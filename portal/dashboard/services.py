"""NetBox-backed data services for the IXP participant portal.

All NetBox data is pre-fetched into an in-process cache and refreshed
periodically by a background thread.  Request handlers always read from
the cache, so NetBox latency never blocks page loads.

On failure the refresh loop uses exponential backoff (30s → 1h cap) so
transient NetBox outages recover quickly without hammering the API.
"""

import logging
import os
import threading
from dataclasses import dataclass, field
from time import monotonic, time

import httpx
from django.conf import settings
from prometheus_client import Counter, Gauge, Histogram

logger = logging.getLogger(__name__)

# ── Tunables ────────────────────────────────────────────────────────

REFRESH_INTERVAL = 4 * 3600          # 4 hours between successful refreshes
BACKOFF_INITIAL = 30                  # first retry delay after failure (seconds)
BACKOFF_MAX = 3600                    # cap retry delay at 1 hour

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


_health = NetBoxHealth()

# ── In-process cache ────────────────────────────────────────────────
# Populated by _refresh_cache(), read by public helpers.

_lock = threading.Lock()
_data: dict[str, list] = {
    "tenants": [],       # participant tenants (tag=ixp_participant)
    "ip_addresses": [],  # participant IPs   (tag=ixp_participant)
    "peering_ports": [],  # peering ports     (tag=peering_port)
}
_force_refresh = threading.Event()


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
    """Pull all participant data from NetBox and swap it into the cache.

    Returns True on success, False on failure.
    """
    t0 = monotonic()
    try:
        tenants = _netbox_get_all("tenancy/tenants", {"tag": "ixp_participant", "limit": 200})
        ips = _netbox_get_all("ipam/ip-addresses", {"tag": "ixp_participant", "limit": 500})
        ports = _netbox_get_all("dcim/interfaces", {"tag": "peering_port", "limit": 500})
        duration = monotonic() - t0

        with _lock:
            _data["tenants"] = tenants
            _data["ip_addresses"] = ips
            _data["peering_ports"] = ports

        # Update health
        _health.last_success_time = time()
        _health.last_refresh_duration = duration
        _health.consecutive_failures = 0
        _health.total_successes += 1
        _health.item_counts = {
            "tenants": len(tenants),
            "ip_addresses": len(ips),
            "peering_ports": len(ports),
        }

        # Update Prometheus
        PROM_REFRESH_DURATION.observe(duration)
        PROM_REFRESH_SUCCESS.inc()
        PROM_CACHE_AGE.set(0)
        for label, count in _health.item_counts.items():
            PROM_CACHE_ITEMS.labels(type=label).set(count)

        logger.info(
            "NetBox cache refreshed in %.1fs: %d tenants, %d IPs, %d ports",
            duration, len(tenants), len(ips), len(ports),
        )
        return True

    except Exception as exc:
        duration = monotonic() - t0
        _health.last_failure_time = time()
        _health.last_error = str(exc)
        _health.consecutive_failures += 1
        _health.total_failures += 1
        _health.last_refresh_duration = duration

        PROM_REFRESH_DURATION.observe(duration)
        PROM_REFRESH_FAILURE.inc()
        if _health.last_success_time:
            PROM_CACHE_AGE.set(time() - _health.last_success_time)

        logger.exception("NetBox cache refresh failed — serving stale data")
        return False


def _backoff_delay(consecutive_failures: int) -> float:
    """Exponential backoff: BACKOFF_INITIAL * 2^(failures-1), capped at BACKOFF_MAX."""
    return min(BACKOFF_INITIAL * (2 ** (consecutive_failures - 1)), BACKOFF_MAX)


# ── Background refresh thread ──────────────────────────────────────

def _refresh_loop():
    """Run _refresh_cache() on a schedule with exponential backoff on failure."""
    while True:
        success = _refresh_cache()
        if success:
            delay = REFRESH_INTERVAL
        else:
            delay = _backoff_delay(_health.consecutive_failures)
            logger.info(
                "NetBox refresh backoff: next retry in %.0fs (failure #%d)",
                delay, _health.consecutive_failures,
            )
        # Wait for `delay` seconds, but wake immediately on _force_refresh
        _force_refresh.wait(timeout=delay)
        _force_refresh.clear()


def start_background_refresh():
    """Spawn the daemon refresh thread (safe to call multiple times)."""
    if getattr(start_background_refresh, "_started", False):
        return
    start_background_refresh._started = True
    t = threading.Thread(target=_refresh_loop, daemon=True)
    t.start()
    logger.info("NetBox background refresh thread started (interval=%ds, pid=%d)", REFRESH_INTERVAL, os.getpid())


# ── Public API (always reads from cache) ────────────────────────────

def get_all_participant_tenants():
    """Return cached list of participant tenants."""
    with _lock:
        return list(_data["tenants"])


def get_participants_for_asns(asns):
    """Return participant tenants whose as_number is in the given set."""
    return [
        t for t in get_all_participant_tenants()
        if t.get("custom_fields", {}).get("as_number") in asns
    ]


def get_participant_ips(tenant_id):
    """Return cached IP addresses for a specific tenant."""
    with _lock:
        return [
            ip for ip in _data["ip_addresses"]
            if (ip.get("tenant") or {}).get("id") == tenant_id
        ]


def get_participant_peering_ports(tenant_id):
    """Return cached peering port interfaces for a specific tenant."""
    with _lock:
        return [
            p for p in _data["peering_ports"]
            if ((p.get("custom_fields") or {}).get("participant") or {}).get("id") == tenant_id
        ]


def get_health() -> NetBoxHealth:
    """Return the current NetBox health state (read-only snapshot)."""
    return _health


def clear_cache():
    """Clear all cached data and trigger an immediate refresh."""
    with _lock:
        _data["tenants"] = []
        _data["ip_addresses"] = []
        _data["peering_ports"] = []
    _health.item_counts = {}
    logger.info("NetBox cache cleared manually, triggering immediate refresh")
    _force_refresh.set()
