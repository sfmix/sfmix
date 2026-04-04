"""Looking Glass REST API client.

Provides typed access to the Looking Glass REST API for fetching
live network data (interface status, optics, BGP, etc.).
"""

from typing import Any

import httpx
from django.conf import settings


class LookingGlassClient:
    """Client for the Looking Glass REST API."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0):
        self.base_url = (base_url or getattr(settings, "IXP_LOOKING_GLASS_URL", "")).rstrip("/")
        self.timeout = timeout

    def _get(self, path: str, token: str | None = None) -> list[dict[str, Any]]:
        """Make a GET request to the LG API.

        Args:
            path: API path (e.g., "/api/v1/interfaces/status")
            token: Optional OIDC id_token for authenticated requests

        Returns:
            List of device results, each containing device name, success flag, and data.
        """
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}{path}", headers=headers)
            resp.raise_for_status()
            return resp.json()

    def get_interfaces_status(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get interface status summary from all devices."""
        return self._get("/api/v1/interfaces/status", token)

    def get_interface_detail(self, name: str, token: str | None = None) -> list[dict[str, Any]]:
        """Get detailed interface info for a specific port."""
        return self._get(f"/api/v1/interfaces/{name}", token)

    def get_optics(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get transceiver DOM levels for all ports."""
        return self._get("/api/v1/optics", token)

    def get_optics_detail(self, name: str, token: str | None = None) -> list[dict[str, Any]]:
        """Get detailed DOM levels for a specific port."""
        return self._get(f"/api/v1/optics/{name}", token)

    def get_bgp_summary(self, af: str = "ipv4", token: str | None = None) -> list[dict[str, Any]]:
        """Get BGP peer summary.

        Args:
            af: Address family ("ipv4" or "ipv6")
            token: Optional OIDC id_token
        """
        return self._get(f"/api/v1/bgp/summary?af={af}", token)

    def get_lldp_neighbors(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get LLDP neighbor table."""
        return self._get("/api/v1/lldp/neighbors", token)

    def get_arp_table(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get ARP table."""
        return self._get("/api/v1/arp", token)

    def get_nd_table(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get IPv6 neighbor discovery table."""
        return self._get("/api/v1/nd", token)

    def get_participants(self) -> list[dict[str, Any]]:
        """Get IXP participant list (no auth required)."""
        return self._get("/api/v1/participants")


def get_lg_client() -> LookingGlassClient:
    """Get a configured LookingGlassClient instance."""
    return LookingGlassClient()
