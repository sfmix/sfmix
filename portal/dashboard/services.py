"""Thin clients for IXP data sources (participants JSON, NetBox)."""

import logging
from time import time

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)

_CACHE_TTL = 120  # seconds
_cache = {}


def _cached_get(url, headers=None):
    """Simple TTL cache for HTTP GETs — avoids hammering upstream on every page load."""
    now = time()
    if url in _cache:
        ts, data = _cache[url]
        if now - ts < _CACHE_TTL:
            return data
    try:
        resp = httpx.get(url, headers=headers or {}, timeout=10, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        _cache[url] = (now, data)
        return data
    except httpx.HTTPError:
        logger.exception("Failed to fetch %s", url)
        # Return stale data if available
        if url in _cache:
            return _cache[url][1]
        return None


def get_participants():
    """Fetch the IXF-style participants table from the looking glass."""
    return _cached_get(settings.IXP_PARTICIPANTS_URL)


def get_participants_for_asns(asns):
    """Filter participant data to only networks matching the given ASN set."""
    data = get_participants()
    if not data:
        return []
    members = data.get("member_list", data.get("members", []))
    return [m for m in members if m.get("asnum") in asns]


def get_netbox_participant(asn):
    """Fetch per-ASN detail from NetBox (connections, IPs, etc.)."""
    if not settings.IXP_NETBOX_TOKEN:
        return None
    headers = {"Authorization": f"Token {settings.IXP_NETBOX_TOKEN}"}
    base = settings.IXP_NETBOX_URL.rstrip("/")
    # IP addresses tagged with this ASN's tenant
    url = f"{base}/api/ipam/ip-addresses/?tag=participant&cf_participant_asn={asn}"
    return _cached_get(url, headers=headers)
