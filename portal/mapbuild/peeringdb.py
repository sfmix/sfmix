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
import logging

log = logging.getLogger(__name__)

PDB_BASE = "https://www.peeringdb.com/api"


class PeeringDBClient:
    """Tiny cached PeeringDB reader. One instance per build; results are memoised
    so shared operators (many SFMIX sites share an org) cost one request each."""

    def __init__(self, api_key=None, timeout=10):
        import requests

        self._s = requests.Session()
        self._s.headers.update({"Accept": "application/json"})
        if api_key:
            self._s.headers["Authorization"] = "Api-Key %s" % api_key
        self.timeout = timeout
        self._fac = {}
        self._org = {}

    def _get(self, path):
        r = self._s.get("%s/%s" % (PDB_BASE, path), timeout=self.timeout)
        r.raise_for_status()
        data = (r.json() or {}).get("data") or []
        return data[0] if data else None

    def facility(self, fac_id):
        fid = int(fac_id)
        if fid not in self._fac:
            self._fac[fid] = self._get("fac/%d" % fid)
        return self._fac[fid]

    def org(self, org_id):
        oid = int(org_id)
        if oid not in self._org:
            self._org[oid] = self._get("org/%d" % oid)
        return self._org[oid]

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
