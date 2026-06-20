"""Prometheus query client + locked-down query catalogue for traffic charts.

The browser never sends PromQL. It asks the portal for a *named panel* with a
bounded set of params (a range key, and for per-port panels a port index that is
validated against the member's own ports). This module owns the actual PromQL
templates, the allowed time ranges, and the Prometheus HTTP call — so a user can
only ever read the series the portal decided they may see.

Metric notes (verified against the live sFlow-RT exporter):
  * ``sflow_ixp_peering_bps`` is already bits/sec. Labels: src_asn, dst_asn,
    src_name, dst_name. "From peer" = member is the destination (dst_asn);
    "to peer" = member is the source (src_asn).
  * ``sflow_if{in,out}octets`` are *gauges in bytes/sec* (not cumulative
    counters), so they are multiplied by 8 and never wrapped in rate().
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)

# Range key -> (lookback_window_seconds, step_seconds). Both the window and the
# resolution are fixed server-side; the client may only choose a key from here.
RANGES: dict[str, tuple[int, int]] = {
    "1h": (3600, 30),
    "24h": (86400, 300),
    "7d": (604800, 1800),
    "30d": (2592000, 7200),
}
DEFAULT_RANGE = "24h"

# How many named peers to show before the rest are folded into an "Other" band.
TOP_PEERS = 8


class PrometheusClient:
    """Minimal read-only client for the Prometheus HTTP API."""

    def __init__(self, base_url: str | None = None, timeout: float = 15.0):
        self.base_url = (base_url or getattr(settings, "PROMETHEUS_URL", "")).rstrip("/")
        self.timeout = timeout

    def query_range(self, query: str, start: int, end: int, step: int) -> list[dict[str, Any]]:
        """Run a range query and return the raw ``data.result`` list."""
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(
                f"{self.base_url}/api/v1/query_range",
                params={"query": query, "start": start, "end": end, "step": f"{step}s"},
            )
            resp.raise_for_status()
            payload = resp.json()
        if payload.get("status") != "success":
            raise RuntimeError(payload.get("error", "prometheus query failed"))
        return payload["data"]["result"]


# ── PromQL builders (the only place query strings are constructed) ──────────

def _escape(value: str) -> str:
    """Escape a value for use inside a PromQL double-quoted string literal."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def peer_query(asn: int, direction: str, step: int) -> str:
    """Per-peer bps for a member. ``direction`` is "from" (ingress) or "to" (egress)."""
    label = "dst_asn" if direction == "from" else "src_asn"
    # asn is coerced to int by the caller, so it is safe to interpolate.
    return f'avg_over_time(sflow_ixp_peering_bps{{{label}="{int(asn)}"}}[{step}s])'


def ifcounters_query(members: list[tuple[str, str]], direction: str, step: int) -> str:
    """Summed interface throughput (bps) across a port's physical members.

    ``members`` is a validated list of (device, ifname) pairs. Octet gauges are
    bytes/sec, so the sum is multiplied by 8.
    """
    metric = "sflow_ifoutoctets" if direction == "out" else "sflow_ifinoctets"
    terms = [
        f'avg_over_time({metric}{{host="{_escape(dev)}",ifname="{_escape(ifn)}"}}[{step}s])'
        for dev, ifn in members
    ]
    return f"sum({' or '.join(terms)}) * 8"


# ── Reshaping query_range results onto a shared time grid ───────────────────

def build_grid(start: int, end: int, step: int) -> list[int]:
    """The canonical x-axis: integer unix timestamps from start to end by step."""
    return list(range(start, end + 1, step))


def _to_grid(values: list[list], xs: list[int], start: int, step: int) -> list[float | None]:
    """Align one Prometheus series' [ts, val] points onto the xs grid."""
    out: list[float | None] = [None] * len(xs)
    n = len(xs)
    for ts, val in values:
        idx = round((float(ts) - start) / step)
        if 0 <= idx < n:
            try:
                out[idx] = float(val)
            except (TypeError, ValueError):
                pass
    return out


def align_single(result: list[dict], xs: list[int], start: int, step: int) -> list[float | None]:
    """Collapse a (sum) result expected to hold one series into one grid array."""
    if not result:
        return [None] * len(xs)
    return _to_grid(result[0].get("values", []), xs, start, step)


def _clean_name(raw: str) -> str:
    """sFlow-RT names use underscores for spaces (e.g. "Hurricane_Electric")."""
    return (raw or "").replace("_", " ").strip()


def top_peers(result: list[dict], xs: list[int], start: int, step: int, direction: str) -> list[dict]:
    """Rank peer series by mean throughput, keep the top N, fold the rest into "Other".

    The "other" peer's identifying labels are the *opposite* end of the flow:
    for "from peer" (dst_asn=member) the peer is the source; for "to peer" the
    peer is the destination.
    """
    asn_label = "src_asn" if direction == "from" else "dst_asn"
    name_label = "src_name" if direction == "from" else "dst_name"

    series = []
    for s in result:
        vals = _to_grid(s.get("values", []), xs, start, step)
        present = [v for v in vals if v is not None]
        mean = sum(present) / len(present) if present else 0.0
        m = s.get("metric", {})
        series.append({
            "asn": m.get(asn_label, ""),
            "name": _clean_name(m.get(name_label, "")) or f"AS{m.get(asn_label, '?')}",
            "values": vals,
            "_mean": mean,
        })

    series.sort(key=lambda x: x["_mean"], reverse=True)
    top = series[:TOP_PEERS]
    rest = series[TOP_PEERS:]

    if rest:
        folded: list[float | None] = [None] * len(xs)
        for r in rest:
            for i, v in enumerate(r["values"]):
                if v is not None:
                    folded[i] = (folded[i] or 0.0) + v
        top.append({"asn": "", "name": f"Other ({len(rest)})", "values": folded, "_mean": 0.0})

    for s in top:
        s.pop("_mean", None)
    return top
