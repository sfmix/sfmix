"""PeeringDB facility + org lookups for the map builder.

Enriches map sites with PUBLIC PeeringDB facility metadata — operator website,
city/state, network + IX counts, and the org logo — keyed by the NetBox
``peeringdb_facility`` custom field on each site. Everything published here is
public PeeringDB data (the map.json it feeds is public by design).

Fetched at build time: the map build already calls out to public NetBox, and
``www.peeringdb.com`` is likewise world-reachable, so this fits the "public
network only" builder model (see network-map/ARCHITECTURE.md). It is strictly
best-effort — any network/parse failure degrades to no enrichment so the build
never breaks on a PeeringDB hiccup. The ``fac``/``org`` endpoints read without
auth (rate-limited); an optional operator API key raises the limit.
"""
import json
import logging
import os
import time

log = logging.getLogger(__name__)

PDB_BASE = "https://www.peeringdb.com/api"
# Anonymous reads are rate-limited. Wait out a 429 briefly, but cap the total
# wait per build: under a longer throttle the build falls back to the last good
# answers in the on-disk cache instead of stalling or dropping enrichment.
RATE_LIMIT_RETRIES = 2
RATE_LIMIT_WAIT_DEFAULT = 60
RATE_LIMIT_WAIT_MAX = 90
RATE_LIMIT_WAIT_BUDGET = 120


class PeeringDBClient:
    """Tiny cached PeeringDB reader. One instance per build; results are memoised
    so shared operators (many SFMIX sites share an org) cost one request each.
    With ``cache_path`` the last good fac/org records persist across builds and
    stand in for any lookup that fails; call ``save()`` after the build."""

    def __init__(self, api_key=None, timeout=10, session=None, sleep=time.sleep, cache_path=None):
        if session is None:
            import requests
            session = requests.Session()
        self._s = session
        self._s.headers.update({"Accept": "application/json"})
        if api_key:
            self._s.headers["Authorization"] = "Api-Key %s" % api_key
        self.timeout = timeout
        self._sleep = sleep
        self._waited = 0
        self._fac = {}
        self._org = {}
        self._cache_path = cache_path
        self._cache = {"fac": {}, "org": {}}
        if cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path) as f:
                    loaded = json.load(f)
                self._cache = {k: dict(loaded.get(k) or {}) for k in ("fac", "org")}
            except Exception as e:
                log.warning("PeeringDB cache %s unreadable: %s", cache_path, e)

    def _get(self, path):
        for attempt in range(RATE_LIMIT_RETRIES + 1):
            r = self._s.get("%s/%s" % (PDB_BASE, path), timeout=self.timeout)
            if r.status_code != 429 or attempt == RATE_LIMIT_RETRIES:
                break
            try:
                wait = int(r.headers.get("Retry-After", RATE_LIMIT_WAIT_DEFAULT))
            except ValueError:
                wait = RATE_LIMIT_WAIT_DEFAULT
            wait = min(max(wait, 1), RATE_LIMIT_WAIT_MAX)
            if self._waited + wait > RATE_LIMIT_WAIT_BUDGET:
                break  # out of patience this build: raise below, caller uses the cache
            log.info("PeeringDB %s rate-limited; retrying in %ds", path, wait)
            self._waited += wait
            self._sleep(wait)
        r.raise_for_status()
        data = (r.json() or {}).get("data") or []
        return data[0] if data else None

    def _lookup(self, kind, memo, oid):
        if oid in memo:
            return memo[oid]
        try:
            rec = self._get("%s/%d" % (kind, oid))
        except Exception:
            cached = self._cache[kind].get(str(oid))
            if cached is None:
                raise
            log.warning("PeeringDB %s/%d unavailable; using cached record", kind, oid)
            rec = cached
        else:
            if rec is not None:
                self._cache[kind][str(oid)] = rec
        memo[oid] = rec
        return rec

    def facility(self, fac_id):
        return self._lookup("fac", self._fac, int(fac_id))

    def org(self, org_id):
        return self._lookup("org", self._org, int(org_id))

    def save(self):
        """Write the fac/org cache (atomically) if this client has a cache path."""
        if not self._cache_path:
            return
        try:
            os.makedirs(os.path.dirname(self._cache_path) or ".", exist_ok=True)
            tmp = self._cache_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._cache, f)
            os.replace(tmp, self._cache_path)
        except Exception as e:
            log.warning("PeeringDB cache %s not saved: %s", self._cache_path, e)

    def facility_meta(self, fac_id):
        """Public display fields for a facility, or ``{}`` on any failure."""
        try:
            fac = self.facility(fac_id)
        except Exception as e:  # network, HTTP, or JSON — all non-fatal
            log.warning("PeeringDB fac/%s fetch failed: %s", fac_id, e)
            return {}
        if not fac:
            return {}
        meta = {
            "pdb_fac": int(fac_id),
            "pdb_url": "https://www.peeringdb.com/fac/%s" % fac_id,
            "operator_website": (fac.get("website") or "").strip(),
            "city": (fac.get("city") or "").strip(),
            "state": (fac.get("state") or "").strip(),
            "country": (fac.get("country") or "").strip(),
            "net_count": int(fac.get("net_count") or 0),
            "ix_count": int(fac.get("ix_count") or 0),
            "logo": "",
        }
        org_id = fac.get("org_id")
        if org_id:
            try:
                org = self.org(org_id)
            except Exception as e:
                log.warning("PeeringDB org/%s fetch failed: %s", org_id, e)
                org = None
            if org:
                meta["logo"] = (org.get("logo") or "").strip()
                if not meta["operator_website"]:
                    meta["operator_website"] = (org.get("website") or "").strip()
        # drop empty values so map.json only carries what we actually have
        return {k: v for k, v in meta.items() if v not in ("", 0, None)}
