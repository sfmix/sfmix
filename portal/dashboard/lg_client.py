"""Looking Glass REST API client.

Provides typed access to the Looking Glass REST API for fetching
live network data (interface status, optics, etc.).
"""

from typing import Any

import httpx
from django.conf import settings


class LookingGlassClient:
    """Client for the Looking Glass REST API."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0):
        self.base_url = (base_url or getattr(settings, "IXP_LOOKING_GLASS_URL", "")).rstrip("/")
        self.timeout = timeout

    def _get(self, path: str, token: str | None = None, params: dict[str, str] | None = None) -> Any:
        """Make a GET request to the LG API.

        Args:
            path: API path (e.g., "/api/v1/interfaces/status")
            token: Optional OIDC id_token for authenticated requests
            params: Optional query parameters

        Returns:
            Parsed JSON response (list or dict depending on endpoint).
        """
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(f"{self.base_url}{path}", headers=headers, params=params)
            resp.raise_for_status()
            return resp.json()

    def get_interfaces_status(self, token: str | None = None, asn: int | None = None) -> list[dict[str, Any]]:
        """Get interface status summary from all devices."""
        params = {}
        if asn is not None:
            params["asn"] = str(asn)
        return self._get("/api/v1/interfaces/status", token, params or None)

    def get_interface_detail(self, name: str, token: str | None = None) -> list[dict[str, Any]]:
        """Get detailed interface info for a specific port."""
        return self._get(f"/api/v1/interfaces/{name}", token)

    def get_optics(self, token: str | None = None, asn: int | None = None) -> list[dict[str, Any]]:
        """Get transceiver DOM levels for all ports."""
        params = {}
        if asn is not None:
            params["asn"] = str(asn)
        return self._get("/api/v1/optics", token, params or None)

    def get_optics_detail(self, name: str, token: str | None = None) -> list[dict[str, Any]]:
        """Get detailed DOM levels for a specific port."""
        return self._get(f"/api/v1/optics/{name}", token)

    def get_lldp_neighbors(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get LLDP neighbor table."""
        return self._get("/api/v1/lldp/neighbors", token)

    def get_mac_address_table(self, token: str | None = None, vlan: str | None = None) -> list[dict[str, Any]]:
        """Get MAC address table."""
        params = {}
        if vlan is not None:
            params["vlan"] = vlan
        return self._get("/api/v1/mac-address-table", token, params or None)

    def get_arp(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get ARP table (IPv4 neighbor-to-MAC mapping)."""
        return self._get("/api/v1/arp", token)

    def get_ipv6_neighbors(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get IPv6 neighbor table (NDP)."""
        return self._get("/api/v1/ipv6/neighbors", token)

    def get_participants(self) -> list[dict[str, Any]]:
        """Get IXP participant list (no auth required)."""
        return self._get("/api/v1/participants")

    def get_participant_ports(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get all participant peering ports as (device, interface, asn, name) tuples."""
        return self._get("/api/v1/participant-ports", token)

    def get_participant_detail(self, asn: int, token: str | None = None) -> dict[str, Any]:
        """Get enriched participant data for a specific ASN."""
        return self._get(f"/api/v1/participants/{asn}", token)

    def get_optics_inventory(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get transceiver hardware inventory (vendor, model, serial number)."""
        return self._get("/api/v1/optics/inventory", token)

    def get_netbox_status(self) -> dict[str, Any]:
        """Get NetBox cache status from the Looking Glass."""
        return self._get("/api/v1/netbox/status")

    def get_device_cache_status(self, token: str | None = None) -> list[dict[str, Any]]:
        """Get per-device background cache freshness."""
        return self._get("/api/v1/device-cache/status", token)

    def get_participants_json(self) -> dict[str, Any]:
        """Get IX-F Member Export (participants.json)."""
        return self._get("/api/v1/participants.json")

    def get_peeringdb_cache(self) -> dict[str, Any]:
        """Get PeeringDB network cache (website URLs, IRR, policy, etc.)."""
        return self._get("/api/v1/peeringdb-cache")

    def get_discovered_neighbors(
        self, token: str | None = None, asn: int | None = None, unassigned: bool = False
    ) -> dict[str, Any]:
        """Get ARP/NDP neighbors heard on the IX fabric (with conflicts).

        ``unassigned=True`` narrows to IPs not in the NetBox assignment set
        (hosts mis-bound to an invalid/disallowed address); it takes precedence
        over ``asn`` since unassigned neighbors carry no ASN.

        Returns {"neighbors": [...], "fetched_at": ..., "last_error": ...}.
        """
        params = {}
        if unassigned:
            params["unassigned"] = "true"
        elif asn is not None:
            params["asn"] = str(asn)
        return self._get("/api/v1/discovered-neighbors", token, params or None)


def get_lg_client() -> LookingGlassClient:
    """Get a configured LookingGlassClient instance."""
    return LookingGlassClient()
