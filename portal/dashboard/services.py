"""NetBox-backed data services for the IXP participant portal.

All NetBox data is stored in Django's cache framework, shared across all
gunicorn workers.  A background thread in each worker polls for staleness
and, using a cross-process file lock, ensures only one worker performs the
actual NetBox refresh at a time.

The cache backend is configurable via Django CACHES setting — swap
FileBasedCache for RedisCache or MemcachedCache with no code changes here.

On failure the refresh loop uses exponential backoff (30 s → 1 h cap) so
transient NetBox outages recover quickly without hammering the API.
"""

import fcntl
import logging
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic, time

import httpx
from django.conf import settings
from django.core.cache import cache

from prometheus_client import Counter, Gauge, Histogram, REGISTRY
from prometheus_client.core import GaugeMetricFamily

logger = logging.getLogger(__name__)

# ── Tunables ────────────────────────────────────────────────────────

REFRESH_INTERVAL = getattr(settings, "NETBOX_CACHE_TIMEOUT", 4 * 3600)
BACKOFF_INITIAL = 30                  # first retry delay after failure (seconds)
BACKOFF_MAX = 3600                    # cap retry delay at 1 hour
POLL_INTERVAL = 30                    # seconds between cache-freshness checks

# ── Cache keys ──────────────────────────────────────────────────────

CACHE_KEY_DATA = "netbox:data"
CACHE_KEY_HEALTH = "netbox:health"
CACHE_DATA_TIMEOUT = REFRESH_INTERVAL * 3  # keep stale data available on failure

# ── Prometheus metrics ──────────────────────────────────────────────

PROM_REFRESH_DURATION = Histogram(
    "netbox_refresh_duration_seconds",
    "Time spent fetching data from NetBox",
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120),
)
PROM_REFRESH_SUCCESS = Counter(
    "netbox_refresh_success_total",
    "Number of successful NetBox cache refreshes",
)
PROM_REFRESH_FAILURE = Counter(
    "netbox_refresh_failure_total",
    "Number of failed NetBox cache refreshes",
)
PROM_CACHE_AGE = Gauge(
    "netbox_cache_age_seconds",
    "Seconds since last successful cache refresh",
)
PROM_CACHE_ITEMS = Gauge(
    "netbox_cache_items",
    "Number of cached items by type",
    ["type"],
)

# ── Health state ────────────────────────────────────────────────────


@dataclass
class NetBoxHealth:
    """Observable health state for the NetBox data source."""

    last_success_time: float = 0.0            # time.time() of last success
    last_failure_time: float = 0.0            # time.time() of last failure
    last_error: str = ""                      # str(exception) from last failure
    consecutive_failures: int = 0
    last_refresh_duration: float = 0.0        # seconds
    total_successes: int = 0
    total_failures: int = 0
    item_counts: dict[str, int] = field(default_factory=dict)

    @property
    def cache_age(self) -> float:
        """Seconds since last successful refresh, or -1 if never refreshed."""
        return time() - self.last_success_time if self.last_success_time else -1

    @property
    def healthy(self) -> bool:
        return self.last_success_time > 0 and self.consecutive_failures == 0

    def to_dict(self) -> dict:
        return {
            "last_success_time": self.last_success_time,
            "last_failure_time": self.last_failure_time,
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
            "last_refresh_duration": self.last_refresh_duration,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "item_counts": self.item_counts,
        }

    @classmethod
    def from_dict(cls, d: dict | None) -> "NetBoxHealth":
        if not d:
            return cls()
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Per-process state ───────────────────────────────────────────────

_force_refresh = threading.Event()

# ── Cross-process refresh lock ──────────────────────────────────────


@contextmanager
def _refresh_lock():
    """Try to acquire a non-blocking cross-process file lock.

    Yields True if the lock was acquired, False if another worker holds it.
    When migrating to Redis, replace with django-redis cache.lock().
    """
    lock_path = getattr(settings, "NETBOX_CACHE_LOCK_FILE", "/tmp/.netbox_refresh.lock")
    Path(lock_path).parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
    acquired = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError:
            pass  # another worker holds the lock
        yield acquired
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _cache_is_stale() -> bool:
    """Check whether the shared cache needs a refresh."""
    health_dict = cache.get(CACHE_KEY_HEALTH)
    if not health_dict:
        return True
    last_success = health_dict.get("last_success_time", 0)
    return not last_success or (time() - last_success) >= REFRESH_INTERVAL


# ── NetBox HTTP helpers ─────────────────────────────────────────────

def _netbox_get_all(path, params=None):
    """Fetch all pages from a NetBox list endpoint."""
    base = settings.IXP_NETBOX_URL.rstrip("/")
    url = f"{base}/api/{path.lstrip('/')}/"
    results: list = []
    next_url: str | None = url
    while next_url:
        resp = httpx.get(
            next_url,
            headers={"Authorization": f"Token {settings.IXP_NETBOX_TOKEN}"},
            params=params if next_url == url else None,
            timeout=30,
            follow_redirects=True,
        )
        resp.raise_for_status()
        body = resp.json()
        results.extend(body.get("results", []))
        next_url = body.get("next")
        params = None  # already encoded in next_url
    return results


def _refresh_cache():
    """Pull all participant data from NetBox and write to shared cache.

    Returns True on success, False on failure.
    """
    t0 = monotonic()
    health = get_health()  # read current shared state

    try:
        tenants = _netbox_get_all("tenancy/tenants", {"tag": "ixp_participant", "limit": 200})
        ips = _netbox_get_all("ipam/ip-addresses", {"tag": "ixp_participant", "limit": 500})
        ports = _netbox_get_all("dcim/interfaces", {"tag": "peering_port", "limit": 500})
        # Physical members of the peering LAGs (for per-port participant
        # attribution on the SNMP series — errors, optics DOM, ...).
        lag_ids = [p["id"] for p in ports if (p.get("type") or {}).get("value") == "lag"]
        lag_members = (
            _netbox_get_all("dcim/interfaces", {"lag_id": lag_ids, "limit": 500})
            if lag_ids else []
        )
        duration = monotonic() - t0

        # Write data to shared cache atomically (single key)
        cache.set(CACHE_KEY_DATA, {
            "tenants": tenants,
            "ip_addresses": ips,
            "peering_ports": ports,
            "lag_members": lag_members,
        }, CACHE_DATA_TIMEOUT)

        # Update shared health
        health.last_success_time = time()
        health.last_refresh_duration = duration
        health.consecutive_failures = 0
        health.total_successes += 1
        health.item_counts = {
            "tenants": len(tenants),
            "ip_addresses": len(ips),
            "peering_ports": len(ports),
            "lag_members": len(lag_members),
        }
        cache.set(CACHE_KEY_HEALTH, health.to_dict(), CACHE_DATA_TIMEOUT)

        # Update Prometheus (per-worker counters)
        PROM_REFRESH_DURATION.observe(duration)
        PROM_REFRESH_SUCCESS.inc()
        PROM_CACHE_AGE.set(0)
        for label, count in health.item_counts.items():
            PROM_CACHE_ITEMS.labels(type=label).set(count)

        logger.info(
            "NetBox cache refreshed in %.1fs: %d tenants, %d IPs, %d ports (pid=%d)",
            duration, len(tenants), len(ips), len(ports), os.getpid(),
        )
        return True

    except Exception as exc:
        duration = monotonic() - t0
        health.last_failure_time = time()
        health.last_error = str(exc)
        health.consecutive_failures += 1
        health.total_failures += 1
        health.last_refresh_duration = duration
        cache.set(CACHE_KEY_HEALTH, health.to_dict(), CACHE_DATA_TIMEOUT)

        PROM_REFRESH_DURATION.observe(duration)
        PROM_REFRESH_FAILURE.inc()
        if health.last_success_time:
            PROM_CACHE_AGE.set(time() - health.last_success_time)

        logger.exception("NetBox cache refresh failed — serving stale data (pid=%d)", os.getpid())
        return False


def _backoff_delay(consecutive_failures: int) -> float:
    """Exponential backoff: BACKOFF_INITIAL * 2^(failures-1), capped at BACKOFF_MAX."""
    return min(BACKOFF_INITIAL * (2 ** (consecutive_failures - 1)), BACKOFF_MAX)


# ── Background refresh thread ──────────────────────────────────────

def _refresh_loop():
    """Poll for cache staleness and refresh with cross-process locking.

    Each gunicorn worker runs this loop.  Only the worker that wins the
    file lock actually queries NetBox; the others just read the shared
    cache that the winner populates.
    """
    while True:
        if _cache_is_stale():
            with _refresh_lock() as acquired:
                if acquired:
                    # Double-check after acquiring lock — another worker
                    # may have refreshed while we waited.
                    if _cache_is_stale():
                        success = _refresh_cache()
                        if not success:
                            health = get_health()
                            delay = _backoff_delay(health.consecutive_failures)
                            logger.info(
                                "NetBox refresh backoff: %.0fs (failure #%d, pid=%d)",
                                delay, health.consecutive_failures, os.getpid(),
                            )
                            _force_refresh.wait(timeout=delay)
                            _force_refresh.clear()
                            continue
                else:
                    logger.debug(
                        "Another worker is refreshing NetBox cache (pid=%d)",
                        os.getpid(),
                    )

        # Poll every POLL_INTERVAL, but wake immediately on force refresh
        _force_refresh.wait(timeout=POLL_INTERVAL)
        _force_refresh.clear()


def start_background_refresh():
    """Spawn the daemon refresh thread (safe to call multiple times).

    On first call, performs an eager synchronous fetch if the shared cache
    is empty so the very first request in the worker sees data.
    """
    if getattr(start_background_refresh, "_started", False):
        return
    start_background_refresh._started = True

    # Eager first fetch: if no worker has populated the cache yet, do it
    # synchronously so pages don't render with empty data.
    if _cache_is_stale():
        with _refresh_lock() as acquired:
            if acquired and _cache_is_stale():
                _refresh_cache()

    t = threading.Thread(target=_refresh_loop, daemon=True)
    t.start()
    logger.info(
        "NetBox background refresh thread started "
        "(interval=%ds, poll=%ds, pid=%d)",
        REFRESH_INTERVAL, POLL_INTERVAL, os.getpid(),
    )


# ── Public API (reads from shared cache) ────────────────────────────

def _get_data() -> dict:
    """Read the full data dict from shared cache."""
    return cache.get(CACHE_KEY_DATA) or {
        "tenants": [], "ip_addresses": [], "peering_ports": [], "lag_members": [],
    }


def get_all_participant_tenants():
    """Return cached list of participant tenants."""
    return list(_get_data()["tenants"])


def get_participants_for_asns(asns):
    """Return participant tenants whose as_number is in the given set."""
    return [
        t for t in get_all_participant_tenants()
        if t.get("custom_fields", {}).get("as_number") in asns
    ]


def get_participant_ips(tenant_id):
    """Return cached IP addresses for a specific tenant."""
    return [
        ip for ip in _get_data()["ip_addresses"]
        if (ip.get("tenant") or {}).get("id") == tenant_id
    ]


def get_participant_peering_ports(tenant_id):
    """Return cached peering port interfaces for a specific tenant."""
    return [
        p for p in _get_data()["peering_ports"]
        if ((p.get("custom_fields") or {}).get("participant") or {}).get("id") == tenant_id
    ]


def get_health() -> NetBoxHealth:
    """Return the current NetBox health state from shared cache."""
    return NetBoxHealth.from_dict(cache.get(CACHE_KEY_HEALTH))


def refresh_cache():
    """Perform a synchronous cache refresh from NetBox.

    Blocks until the fresh data is written to the shared cache so the
    subsequent redirect shows up-to-date information immediately.
    The full dataset is overwritten atomically, removing any stale entries.
    """
    logger.info("NetBox cache refresh requested manually (pid=%d)", os.getpid())
    _refresh_cache()


# ── Participant port attribution for Prometheus ─────────────────────

PORT_INFO_DOMAIN = "sfmix.org"   # NetBox device names are bare (switch01.sfo02)


def _port_host_site(port) -> tuple[str, str]:
    dev = ((port.get("device") or {}).get("name") or "").strip()
    host = dev if dev.endswith("." + PORT_INFO_DOMAIN) else f"{dev}.{PORT_INFO_DOMAIN}"
    site = dev.split(".")[1] if "." in dev else ""
    return host, site


class PeeringPortInfoCollector:
    """Export sfmix_peering_port_info for joining participant identity
    (ASN, name, peering IPs) onto per-interface SNMP series in Prometheus.

    Rebuilds the label sets from the NetBox cache at scrape time, so series
    for moved/retired ports disappear on their own — no stale-series cleanup.
    port_role distinguishes peering-LAN-facing interfaces (the Port-Channel
    or a plain Ethernet port) from physical LAG members.
    """

    def collect(self):
        fam = GaugeMetricFamily(
            "sfmix_peering_port_info",
            "Participant attribution for peering switch ports (join on host+ifname)",
            labels=["host", "ifname", "asn", "participant", "site", "port_role",
                    "ipv4", "ipv6"],
        )
        data = _get_data()
        tenants = {t["id"]: t for t in data["tenants"]}

        ips_by_port: dict[int, list] = {}
        ips_by_tenant: dict[int, list] = {}
        for ip in data["ip_addresses"]:
            lag = (ip.get("custom_fields") or {}).get("participant_lag") or {}
            if lag.get("id"):
                ips_by_port.setdefault(lag["id"], []).append(ip)
            tenant = ip.get("tenant") or {}
            if tenant.get("id"):
                ips_by_tenant.setdefault(tenant["id"], []).append(ip)

        ports_by_tenant: dict[int, list] = {}
        participant_by_port: dict[int, dict] = {}
        for port in data["peering_ports"]:
            ref = (port.get("custom_fields") or {}).get("participant") or {}
            tenant = tenants.get(ref.get("id"))
            if not tenant:
                continue
            ports_by_tenant.setdefault(tenant["id"], []).append(port)
            participant_by_port[port["id"]] = tenant

        for port in data["peering_ports"]:
            tenant = participant_by_port.get(port["id"])
            if not tenant:
                continue
            ips = ips_by_port.get(port["id"], [])
            if not ips and len(ports_by_tenant[tenant["id"]]) == 1:
                # participant_lag not set (or mis-set, cf. the PCH swap) —
                # unambiguous only when the participant has a single port
                ips = ips_by_tenant.get(tenant["id"], [])
            v4 = sorted(ip["address"].split("/")[0] for ip in ips
                        if ":" not in ip["address"])
            v6 = sorted(ip["address"].split("/")[0] for ip in ips
                        if ":" in ip["address"])
            host, site = _port_host_site(port)
            asn = str((tenant.get("custom_fields") or {}).get("as_number") or "")
            fam.add_metric(
                [host, port["name"], asn, tenant["name"], site, "peering_port",
                 v4[0] if v4 else "", v6[0] if v6 else ""], 1)

        for member in data.get("lag_members", []):
            tenant = participant_by_port.get(((member.get("lag") or {}).get("id")))
            if not tenant:
                continue
            host, site = _port_host_site(member)
            asn = str((tenant.get("custom_fields") or {}).get("as_number") or "")
            fam.add_metric(
                [host, member["name"], asn, tenant["name"], site, "lag_member",
                 "", ""], 1)

        yield fam


try:
    REGISTRY.register(PeeringPortInfoCollector())
except ValueError:
    pass  # already registered (dev-server autoreload)
