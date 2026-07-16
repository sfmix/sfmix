"""Alice Looking Glass REST API client.

Fetches route-server BGP neighbor data from Alice-LG (alice.sfmix.org).
Used to display route-server session status on the network detail page.
"""

import logging
from typing import Any

import httpx
from django.conf import settings

from .http_pool import get_with_retry, pooled_client

logger = logging.getLogger(__name__)

# Short connect budget + longer read budget (route-server neighbor dumps can be
# large). See http_pool for why a pooled, kept-alive client matters.
_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=10.0, pool=5.0)


class AliceLGClient:
    """Client for the Alice-LG REST API."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0):
        self.base_url = (base_url or getattr(settings, "ALICE_LG_URL", "")).rstrip("/")
        # Retained for API compatibility; the shared pooled client owns the real timeout.
        self.timeout = timeout

    def _get(self, path: str) -> Any:
        """Make a GET request to the Alice API."""
        resp = get_with_retry(pooled_client("alice", _TIMEOUT), f"{self.base_url}{path}")
        resp.raise_for_status()
        return resp.json()

    def get_routeservers(self) -> list[dict[str, Any]]:
        """List configured route servers.

        Returns list of dicts with 'id', 'name', etc.
        """
        data = self._get("/api/v1/routeservers")
        return data.get("routeservers", [])

    def get_neighbors(self, rs_id: str) -> list[dict[str, Any]]:
        """Get all BGP neighbors for a specific route server.

        Returns list of neighbor dicts with 'address', 'asn', 'state',
        'routes_received', 'routes_accepted', 'routes_filtered', etc.

        Alice-LG reports ``uptime`` as a Go ``time.Duration`` — an int64
        count of nanoseconds — so we normalize it to whole seconds here,
        at the single boundary every caller (and the devmock fixtures)
        passes through.
        """
        data = self._get(f"/api/v1/routeservers/{rs_id}/neighbors")
        neighbors = data.get("neighbors", [])
        for neighbor in neighbors:
            neighbor["uptime"] = _uptime_ns_to_seconds(neighbor.get("uptime", 0))
        return neighbors

    def get_all_neighbors(
        self, routeservers: list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        """Aggregate BGP neighbors across all route servers.

        Each returned dict is augmented with 'rs_id' and 'rs_name'. Pass
        ``routeservers`` to avoid re-fetching the route-server list when the
        caller already has it.
        """
        if routeservers is None:
            try:
                routeservers = self.get_routeservers()
            except Exception:
                logger.warning("Failed to fetch Alice route server list", exc_info=True)
                return []

        results = []
        for rs in routeservers:
            rs_id = rs.get("id", "")
            rs_name = rs.get("name", rs_id)
            try:
                neighbors = self.get_neighbors(rs_id)
            except Exception:
                logger.warning("Failed to fetch neighbors from RS %s", rs_id, exc_info=True)
                continue
            for neighbor in neighbors:
                neighbor["rs_name"] = rs_name
                neighbor["rs_id"] = rs_id
                results.append(neighbor)
        return results

    def get_neighbors_for_asn(self, asn: int) -> list[dict[str, Any]]:
        """Aggregate RS neighbors across all route servers, filtered to ASN.

        Returns a list of dicts, each augmented with 'rs_name' and 'rs_id'.
        """
        return [n for n in self.get_all_neighbors() if n.get("asn") == asn]


def _uptime_ns_to_seconds(value: Any) -> int:
    """Convert an Alice-LG ``uptime`` (Go time.Duration, nanoseconds) to seconds."""
    if not isinstance(value, (int, float)):
        return 0
    return int(value // 1_000_000_000)


def get_alice_client() -> AliceLGClient:
    """Get a configured AliceLGClient instance."""
    return AliceLGClient()
