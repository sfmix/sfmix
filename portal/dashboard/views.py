import ipaddress
import logging
from collections import defaultdict
from datetime import datetime

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils.timesince import timesince
from django.utils.translation import gettext, ngettext

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from .alice_client import AliceLGClient
from .lg_client import LookingGlassClient, get_lg_client

logger = logging.getLogger(__name__)


# ── Helpers ─────────────────────────────────────────────────────────

def _is_ix_admin(request):
    return request.session.get("oidc_is_ix_admin", False)


def _client_ip(request):
    """Return the client IP, respecting X-Forwarded-For from a trusted proxy."""
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def _ip_in_trusted_networks(ip_str):
    """Check if an IP address falls within any configured trusted network."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in getattr(settings, "PROMETHEUS_TRUSTED_NETWORKS", []):
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


# ── Auth views ──────────────────────────────────────────────────────

def login_view(request):
    if request.user.is_authenticated:
        return redirect("/")
    return render(request, "dashboard/login.html", {
        "dev_login_enabled": getattr(settings, "DEV_LOGIN_ENABLED", False),
    })


def logout_view(request):
    auth_logout(request)
    return redirect("/login/")


# ── Dashboard views ─────────────────────────────────────────────────

@login_required
def index(request):
    return redirect("participants_list")


@login_required
def network_mac_table(request, asn):
    """MAC address table for a participant network."""
    asns = request.session.get("oidc_asns", [])
    if asn not in asns:
        return HttpResponseForbidden(gettext("You do not have access to this network."))
    vlan = request.GET.get("vlan")
    token = request.session.get("oidc_id_token")
    entries = []
    lg_error = None
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            allowed_ports: set[tuple[str, str]] = set()
            detail = lg.get_participant_detail(asn, token=token)
            for port in detail.get("enriched_ports", []):
                dev, iface = port.get("device", ""), port.get("interface", "")
                if dev and iface:
                    allowed_ports.add((dev, iface))
                for member_dev, member_iface in port.get("member_interfaces", []):
                    if member_dev and member_iface:
                        allowed_ports.add((member_dev, member_iface))

            results = lg.get_mac_address_table(token=token, vlan=vlan)
            for device_result in results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for entry in device_result["data"]:
                        entry["device"] = dev
                        if (dev, entry.get("interface", "")) in allowed_ports:
                            entries.append(entry)
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/network_mac_table.html", {
        "asn": asn,
        "entries": entries,
        "vlan_filter": vlan or "",
        "lg_error": lg_error,
        "is_ix_admin": _is_ix_admin(request),
    })


@login_required
def lldp_neighbors(request):
    """LLDP neighbor table (admin only)."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden(gettext("IX Administrators only."))
    entries = []
    lg_error = None
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        if not lg.base_url:
            lg_error = gettext("Looking Glass not configured")
        else:
            results = lg.get_lldp_neighbors(token=token)
            for device_result in results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for entry in device_result["data"]:
                        entry["device"] = dev
                        entries.append(entry)

            port_to_participant: dict[tuple[str, str], dict] = {
                (p["device"], p["interface"]): p
                for p in lg.get_participant_ports(token=token)
                if p.get("device") and p.get("interface")
            }

            iface_description: dict[tuple[str, str], str] = {}
            for device_result in lg.get_interfaces_status(token=token):
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for iface in device_result["data"]:
                        iface_description[(dev, iface["name"])] = iface.get("description", "")

            for entry in entries:
                key = (entry.get("device", ""), entry.get("local_interface", ""))
                participant = port_to_participant.get(key)
                entry["participant_asn"] = participant["asn"] if participant else None
                entry["participant_name"] = participant["name"] if participant else ""
                entry["description"] = iface_description.get(key, "")
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/lldp_neighbors.html", {
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": True,
    })


# ── Network detail helpers ─────────────────────────────────────────

# Per-media-type RX power specs: (rx_min_bad, rx_min_warn, rx_max_warn, rx_max_bad)
# Sources: IEEE 802.3 per-lane receiver sensitivity and overload specs.
# warn zone = 1.5 dB inside the bad boundary on each side.
_OPTIC_RX_SPECS: dict[str, tuple[float, float, float, float]] = {
    # 1G
    "1000BASE-T":   (-30.0, -30.0, 30.0, 30.0),   # copper, ignore
    "1000BASE-LX":  (-19.0, -17.5, -0.5, 0.5),     # -19 to 0 dBm
    "1000BASE-SX":  (-17.0, -15.5, -2.0, -0.5),
    # 10G
    "10GBASE-SR":   (-11.1, -9.6, -0.5, 1.0),      # -11.1 to -1 dBm
    "10GBASE-LR":   (-14.4, -12.9, -0.5, 0.5),     # -14.4 to 0.5 dBm
    "10GBASE-ER":   (-15.8, -14.3, -0.5, 1.0),     # -15.8 to -1 dBm
    # 40G
    "40GBASE-SR4":  (-9.5, -8.0, -0.5, 1.0),
    "40GBASE-LR4":  (-13.7, -12.2, 1.5, 2.3),      # per-lane
    "40GBASE-PSM4": (-13.0, -11.5, 1.5, 2.5),
    # 100G
    "100GBASE-SR4":  (-10.3, -8.8, 1.5, 2.4),
    "100GBASE-LR4":  (-10.6, -9.1, 1.5, 2.4),      # per-lane
    "100GBASE-ER4":  (-13.5, -12.0, 1.5, 2.4),
    "100GBASE-LR":   (-10.6, -9.1, 1.5, 2.4),
    "100GBASE-CR4":  (-30.0, -30.0, 30.0, 30.0),   # DAC, ignore
    # 400G
    "400GBASE-SR8":  (-10.3, -8.8, 1.5, 2.4),
    "400GBASE-DR4":  (-10.6, -9.1, 1.5, 2.4),
    "400GBASE-FR4":  (-10.6, -9.1, 1.5, 2.4),
    "400GBASE-LR8":  (-10.6, -9.1, 1.5, 2.4),
    "400GBASE-ZR":   (-18.0, -16.5, 2.0, 3.5),
    "400GBASE-ZRP":  (-18.0, -16.5, 2.0, 3.5),
}
# Fallback for unknown types
_OPTIC_RX_DEFAULT = (-14.0, -12.0, 1.5, 3.0)


def _optic_spec(media_type):
    """Return the (rx_min_bad, rx_min_warn, rx_max_warn, rx_max_bad) tuple for a media type."""
    if not media_type:
        return _OPTIC_RX_DEFAULT
    key = media_type.upper().strip()
    return _OPTIC_RX_SPECS.get(key, _OPTIC_RX_DEFAULT)


def _optic_band(rx_dbm, media_type=""):
    """Classify RX power level against per-optic-type thresholds."""
    if rx_dbm is None:
        return "unknown"
    rx_min_bad, rx_min_warn, rx_max_warn, rx_max_bad = _optic_spec(media_type)
    if rx_dbm < rx_min_bad or rx_dbm > rx_max_bad:
        return "bad"
    if rx_dbm < rx_min_warn or rx_dbm > rx_max_warn:
        return "warn"
    return "good"


def _optic_band_label(band):
    """Human label for an optic band."""
    return {
        "good": gettext("Nominal"),
        "warn": gettext("Marginal"),
        "bad": gettext("Out of range"),
    }.get(band, "—")


def _optic_meter_pos(rx_dbm, media_type=""):
    """Compute meter position (0-100%) using the type-specific RX range."""
    if rx_dbm is None:
        return 50
    rx_min_bad, _, _, rx_max_bad = _optic_spec(media_type)
    span = rx_max_bad - rx_min_bad
    if span <= 0:
        return 50
    return max(2, min(98, ((rx_dbm - rx_min_bad) / span) * 100))


def _format_speed_gbps(speed_mbps):
    """Format port speed in Mbps to Gbps integer or decimal."""
    if not speed_mbps:
        return 0
    return speed_mbps / 1000


def _dqt(device, port):
    """Device-qualified name as plain text (e.g. 'switch01.sfo02:Ethernet22/1')."""
    short = device.split(".sfmix.org")[0] if device else device
    return f"{short}:{port}"


def _rs_session_sort_key(session):
    """Deterministic, human-friendly ordering for route-server sessions.

    Orders by route-server name, then IPv4 before IPv6, then numerically by
    neighbor IP. Alice-LG returns neighbors in non-deterministic order, so
    without this the session list would shuffle between page loads.
    Unparseable addresses sort last but stably.
    """
    try:
        ip = ipaddress.ip_address(session.get("address", ""))
        addr_key = (ip.version, int(ip))
    except ValueError:
        addr_key = (9, 0)
    return (session.get("name", ""), addr_key, session.get("address", ""))


def _build_logical_ports(enriched_ports, iface_by_key, optics_by_key, lldp_by_key, macs_by_key,
                         participant_ips, arp_by_ip, ndp_by_ip, discovered_by_ip,
                         rs_sessions, can_see_admin, peering_vlans):
    """Build the logical port tree from NetBox + live data.

    ``peering_vlans`` is the set of IXP peering-LAN dot1q VIDs (strings); learned
    MACs on other VLANs are excluded from the L2 band. An empty set means the
    peering-LAN list was unavailable, in which case MACs are not filtered.

    Returns a list of logical port dicts ready for the template.
    """
    # Index IPs by participant_lag_id (interface_id of the enriched port)
    ips_by_lag_id: dict[int, list[dict]] = {}
    unmatched_ips: list[dict] = []
    for ip_entry in participant_ips:
        lag_id = ip_entry.get("participant_lag_id")
        if lag_id:
            ips_by_lag_id.setdefault(lag_id, []).append(ip_entry)
        else:
            unmatched_ips.append(ip_entry)

    # Collect all port IPs (bare addresses) for RS session matching
    all_port_ips: dict[str, int] = {}  # ip_addr -> enriched port interface_id

    alice_base = getattr(settings, "ALICE_LG_URL", "").rstrip("/")

    logical_ports = []

    for port in enriched_ports:
        dev = port.get("device", "")
        iface_name = port.get("interface", "")
        speed_mbps = port.get("speed") or 0
        members = port.get("member_interfaces", [])
        is_lag = bool(members)
        port_iface_id = port.get("interface_id", 0)

        # Build physical member list
        physical = []
        if is_lag:
            per_member_speed = speed_mbps // max(len(members), 1)
            for mem_dev, mem_iface in members:
                physical.append(_build_physical_port(
                    mem_dev, mem_iface, iface_by_key, optics_by_key, lldp_by_key,
                    can_see_admin, netbox_speed_mbps=per_member_speed))
        else:
            physical.append(_build_physical_port(
                dev, iface_name, iface_by_key, optics_by_key, lldp_by_key,
                can_see_admin, netbox_speed_mbps=speed_mbps))

        # Derive link state from physical members
        known = [p for p in physical if p["link_status"] != "unknown"]
        up_count = sum(1 for p in known if p["link_status"] in ("up", "connected"))
        total = len(physical)
        if not known:
            # No live data — assume up based on enabled state
            link_state = "up" if port.get("enabled", True) else "down"
            eff_speed = speed_mbps
        elif up_count == 0:
            link_state = "down"
            eff_speed = 0
        else:
            link_state = "degraded" if up_count < len(known) else "up"
            eff_speed = sum(
                p["speed_mbps"] for p in physical
                if p["link_status"] in ("up", "connected")
            )

        # L3: Match IPs to this port via participant_lag_id → interface_id
        port_ips = ips_by_lag_id.get(port_iface_id, [])
        if not port_ips and len(enriched_ports) == 1:
            # Single-port participant: assign all IPs regardless of lag_id
            port_ips = participant_ips

        port_v4 = None
        port_v6 = None
        bound_mac_v4 = None
        bound_mac_v6 = None
        port_ip_addrs: set[str] = set()
        discovered_v4: list[dict] = []
        discovered_v6: list[dict] = []
        for ip_entry in port_ips:
            addr = ip_entry.get("address", "").split("/")[0]
            family = ip_entry.get("family", "")
            port_ip_addrs.add(addr)
            disc = discovered_by_ip.get(addr)
            if family == "IPv4":
                if not port_v4:
                    port_v4 = ip_entry.get("address")
                    bound_mac_v4 = arp_by_ip.get(addr)
                if disc:
                    discovered_v4.append({"ip": addr, **disc})
            elif family == "IPv6":
                if not port_v6:
                    port_v6 = ip_entry.get("address")
                    bound_mac_v6 = ndp_by_ip.get(addr)
                if disc:
                    discovered_v6.append({"ip": addr, **disc})

        # Record IP → port mapping for RS session matching
        for addr in port_ip_addrs:
            all_port_ips[addr] = port_iface_id

        # L4: Route-server sessions matched by neighbor IP → port IP
        port_rs = []
        for session in rs_sessions:
            sess_addr = session.get("address", "")
            # Only include sessions whose neighbor address matches an IP on this port
            if port_ip_addrs and sess_addr not in port_ip_addrs:
                continue
            is_v4 = "." in sess_addr
            is_v6 = ":" in sess_addr
            rs_id = session.get("rs_id", "")
            neighbor_id = session.get("id", "")
            routes_url = (
                f"{alice_base}/routeservers/{rs_id}"
                f"/neighbors/{neighbor_id}/routes"
                if alice_base and rs_id and neighbor_id else ""
            )
            port_rs.append({
                "name": session.get("rs_name", ""),
                "asn": session.get("asn", 0),
                "state": session.get("state", ""),
                "uptime": _format_uptime(session.get("uptime", 0)),
                "description": session.get("description", ""),
                "v4_received": session.get("routes_received", 0) if is_v4 else 0,
                "v4_accepted": session.get("routes_accepted", 0) if is_v4 else 0,
                "v4_rejected": session.get("routes_filtered", 0) if is_v4 else 0,
                "v6_received": session.get("routes_received", 0) if is_v6 else 0,
                "v6_accepted": session.get("routes_accepted", 0) if is_v6 else 0,
                "v6_rejected": session.get("routes_filtered", 0) if is_v6 else 0,
                "address": sess_addr,
                "is_down": (
                    session.get("state", "").lower()
                    not in ("established", "up")
                ),
                "routes_url": routes_url,
            })

        # Stable, human-friendly order: RS name, then IPv4 before IPv6, then IP.
        port_rs.sort(key=_rs_session_sort_key)

        # L2: MACs learned on this logical port. The fabric reports learned
        # MACs on the bundle (Port-Channel) for LAGs and on the interface
        # itself for single ports, so gather from the port's own interface
        # and every member (deduped) to cover both. Restrict to the IXP peering
        # LAN (VID 998 at SFMIX today) — other service VLANs are not relevant
        # here and would otherwise trip the "expected 1" warning. Skip filtering
        # if the peering-LAN list is unavailable.
        mac_keys = {(dev, iface_name)} | {(p["device"], p["name"]) for p in physical}
        port_macs = [m for key in mac_keys for m in macs_by_key.get(key, [])
                     if not peering_vlans or str(m.get("vlan", "")) in peering_vlans]

        logical_ports.append({
            "id": iface_name,
            "device": dev,
            "name": iface_name,
            "kind": "lag" if is_lag else "single",
            "macs": port_macs,
            "speed_mbps": speed_mbps,
            "speed_gbps": _format_speed_gbps(speed_mbps),
            "enabled": port.get("enabled", True),
            "link_state": link_state,
            "members_up": up_count,
            "members_total": total,
            "effective_speed_gbps": _format_speed_gbps(eff_speed),
            "physical": physical,
            "v4": port_v4 or "—",
            "v6": port_v6 or "—",
            "bound_mac_v4": bound_mac_v4 or "—",
            "bound_mac_v6": bound_mac_v6 or "—",
            "discovered": discovered_v4 + discovered_v6,
            "route_servers": port_rs,
        })

    return logical_ports


def _build_physical_port(device, iface_name, iface_by_key, optics_by_key, lldp_by_key,
                         can_see_admin, netbox_speed_mbps=0):
    """Build a single physical port dict from live data lookups."""
    iface = iface_by_key.get((device, iface_name), {})
    link_status = iface.get("link_status", "unknown")
    speed_mbps = iface.get("speed", 0) or 0
    if isinstance(speed_mbps, str):
        try:
            speed_mbps = int(speed_mbps)
        except (ValueError, TypeError):
            speed_mbps = 0
    # Fall back to NetBox speed if live data has no speed
    if not speed_mbps and netbox_speed_mbps:
        speed_mbps = netbox_speed_mbps

    phy = {
        "device": device,
        "name": iface_name,
        "link_status": link_status,
        "speed_mbps": speed_mbps,
        "speed_gbps": _format_speed_gbps(speed_mbps),
    }

    # L1: Optics (admin only)
    if can_see_admin:
        optic = optics_by_key.get((device, iface_name), {})
        if optic.get("dom_supported"):
            lanes_raw = optic.get("lanes", [])
            media_type = optic.get("media_type", "")
            lanes = []
            for i, lane in enumerate(lanes_raw):
                rx = lane.get("rx_power_dbm")
                tx = lane.get("tx_power_dbm")
                band = _optic_band(rx, media_type)
                lanes.append({
                    "index": i,
                    "label": lane.get("label", f"Lane {i+1}"),
                    "rx_dbm": rx,
                    "rx_formatted": f"{rx:.1f}" if rx is not None else "—",
                    "tx_dbm": tx,
                    "tx_formatted": f"{tx:.1f}" if tx is not None else "—",
                    "band": band,
                    "band_label": _optic_band_label(band),
                    "meter_pos": _optic_meter_pos(rx, media_type),
                })
            phy["lanes"] = lanes
            temp = optic.get("temperature_c")
            phy["temperature_c"] = f"{temp:.1f}" if temp is not None else None
            phy["media_type"] = optic.get("media_type", "")
            phy["serial"] = optic.get("serial_number", "") or ""
            phy["tx_bias_ok"] = link_status in ("up", "connected")
        else:
            phy["lanes"] = []
            phy["temperature_c"] = None
            phy["media_type"] = ""
            phy["serial"] = ""
            phy["tx_bias_ok"] = False
    else:
        phy["lanes"] = []

    # L2: LLDP neighbor
    lldp = lldp_by_key.get((device, iface_name))
    if lldp:
        phy["lldp"] = {
            "sys_name": lldp.get("system_name", ""),
            "port_id": lldp.get("neighbor_interface", ""),
            "chassis_id": lldp.get("chassis_id", ""),
        }
    else:
        phy["lldp"] = None

    return phy


def _format_uptime(seconds):
    """Format seconds into a human-readable uptime string."""
    if not seconds or not isinstance(seconds, (int, float)):
        return "—"
    seconds = int(seconds)
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    if days > 0:
        return f"{days}d {hours}h"
    minutes = (seconds % 3600) // 60
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


# ── Route-server parity ─────────────────────────────────────────────
#
# SFMIX requires every participant to peer with BOTH route servers so that a
# single RS failure does not cut them off. We compare a participant's BGP
# sessions across all configured route servers on session state and on
# received-prefix counts, and surface any loss of redundancy (down/missing on
# one RS) or asymmetric filtering (counts disagree). We compare received (not
# accepted) prefixes because OpenBGPD does not report accepted-prefix counts
# through Alice — its accepted count comes back as 0, which would falsely flag
# every participant as mismatched.

_PREFIX_PARITY_MIN_DELTA = 2     # ignore received-count deltas this small …
_PREFIX_PARITY_PCT = 0.10        # … or within this fraction of the larger count

# sort_rank: lower = scarier (sorted to the top of the public parity page).
_RS_PARITY_RANK = {
    "redundancy_broken": 0,   # peered to >=1 RS but down/missing on another
    "not_peered": 1,          # no RS sessions at all (peering is required)
    "prefix_mismatch": 2,     # established everywhere, counts diverge
    "ok": 3,
}
_RS_PARITY_SEVERITY = {
    "redundancy_broken": "crit",
    "not_peered": "crit",
    "prefix_mismatch": "warn",
    "ok": "ok",
}


def _rs_af(addr):
    """Address-family label ('v4'/'v6') for a neighbor address."""
    return "v6" if ":" in (addr or "") else "v4"


def _rs_established(state):
    """True if a BGP session state counts as up."""
    return (state or "").lower() in ("established", "up")


def _af_label(af):
    """Translatable address-family label."""
    return gettext("IPv6") if af == "v6" else gettext("IPv4")


def _rs_result(rs_summary, status, issues, afs):
    """Assemble the parity result dict from a classified status."""
    return {
        "rs": rs_summary,
        "status": status,
        "severity": _RS_PARITY_SEVERITY[status],
        "sort_rank": _RS_PARITY_RANK[status],
        "issues": issues,
        "afs": afs,
    }


def _compute_rs_parity(rs_sessions, routeservers):
    """Compare a participant's BGP sessions across all route servers.

    ``rs_sessions`` is the list of Alice neighbor dicts for one ASN (each with
    ``rs_id`` / ``rs_name`` / ``address`` / ``state`` / ``routes_received``).
    ``routeservers`` is the expected RS set (dicts with ``id`` / ``name``).

    Returns a dict {rs, status, severity, sort_rank, issues, afs}, or ``None``
    when there are no configured route servers to compare against. Only the
    address families the participant actually peers in are compared, so a
    v4-only participant is not faulted for "missing" v6 (symmetric absence is
    not a parity defect).
    """
    if not routeservers:
        return None

    rs_meta = [(rs.get("id", ""), rs.get("name") or rs.get("id", "")) for rs in routeservers]
    rs_names = {rid: name for rid, name in rs_meta}
    real_ids = {rid for rid, _ in rs_meta}

    # by_rs[rs_id][af] = session; afs_used = families seen on any real RS.
    # ``rs_sessions`` may include looking-glass / quarantine collector sessions
    # (they are shown in the participant listing); those are not real route
    # servers, so exclude them here — they must not factor into parity.
    by_rs = {rid: {} for rid, _ in rs_meta}
    afs_used = set()
    for s in rs_sessions:
        rid = s.get("rs_id", "")
        if rid not in real_ids:
            continue
        af = _rs_af(s.get("address", ""))
        afs_used.add(af)
        by_rs.setdefault(rid, {})[af] = s

    afs = sorted(afs_used)

    rs_summary = []
    for rid, name in rs_meta:
        af_cells = []
        for af in afs:
            s = by_rs.get(rid, {}).get(af)
            af_cells.append({
                "af": af,
                "label": _af_label(af),
                "present": s is not None,
                "established": _rs_established(s.get("state")) if s else False,
                "state": s.get("state") if s else None,
                "received": s.get("routes_received") if s else None,
                "address": s.get("address") if s else None,
            })
        rs_summary.append({"rs_id": rid, "name": name, "afs": af_cells})

    # No sessions on any route server at all.
    if not afs:
        return _rs_result(
            rs_summary, "not_peered",
            [gettext("Not peered with any SFMIX route server.")], afs,
        )

    # Redundancy: an AF is only a parity defect when it is established on at
    # least one route server but missing/down on another (true asymmetry). An
    # AF that is missing or down on *every* route server is symmetric absence —
    # e.g. a participant who configures v6 sessions but never brings them up —
    # which is an outage, not a loss of redundancy, so it is not flagged here.
    issues = []
    for af in afs:
        up_rs = {
            rid for rid, _ in rs_meta
            if _rs_established((by_rs.get(rid, {}).get(af) or {}).get("state"))
        }
        if not up_rs:
            continue  # symmetric absence/down across all RS — not a parity defect
        for rid, _ in rs_meta:
            if rid in up_rs:
                continue
            name = rs_names.get(rid, rid)
            entry = by_rs.get(rid, {}).get(af)
            if entry is None:
                issues.append(gettext("No %(af)s session with %(rs)s.") % {
                    "af": _af_label(af), "rs": name})
            else:
                issues.append(gettext("%(af)s session with %(rs)s is %(state)s.") % {
                    "af": _af_label(af), "rs": name,
                    "state": entry.get("state") or gettext("down")})
    if issues:
        return _rs_result(rs_summary, "redundancy_broken", issues, afs)

    # Prefix parity: received counts should agree across route servers per AF.
    # (Received, not accepted — OpenBGPD does not report accepted counts.)
    for af in afs:
        counts = [
            by_rs[rid][af].get("routes_received") or 0
            for rid, _ in rs_meta
            if by_rs.get(rid, {}).get(af)
        ]
        if len(counts) >= 2:
            lo, hi = min(counts), max(counts)
            delta = hi - lo
            if delta > _PREFIX_PARITY_MIN_DELTA and delta > _PREFIX_PARITY_PCT * hi:
                issues.append(gettext(
                    "%(af)s received-prefix counts differ across route servers "
                    "(%(lo)s vs %(hi)s)."
                ) % {"af": _af_label(af), "lo": lo, "hi": hi})

    return _rs_result(rs_summary, "prefix_mismatch" if issues else "ok", issues, afs)


def _parity_applicable(participant, pdb_networks=None):
    """True if the participant is an active peer expected to peer with the RS.

    Networks that declare ``info_never_via_route_servers`` on PeeringDB are
    excluded: they intentionally never use the route servers, so parity findings
    would be noise. ``pdb_networks`` is the PeeringDB cache's ``networks`` map
    (ASN-string keyed); when omitted, the flag is not consulted.
    """
    ptype = (participant.get("participant_type") or "").lower()
    if ptype in ("ixp", "routeserver"):
        return False
    if pdb_networks:
        pdb = pdb_networks.get(str(participant.get("asn"))) or {}
        if pdb.get("info_never_via_route_servers"):
            return False
    return any(
        ip.get("status", "").lower() == "active"
        for ip in participant.get("ip_addresses", [])
    )


# Alice exposes non-RS collectors (looking-glass / quarantine-VLAN) alongside the
# real route servers in its routeservers list. Parity only concerns the two
# production route servers (BIRD + OpenBGPD), so drop the looking-glass sources.
_NON_RS_HINTS = ("looking_glass", "looking glass", "quarantine")


def _real_routeservers(routeservers):
    """Keep only the actual route servers, dropping looking-glass collectors."""
    out = []
    for rs in routeservers:
        ident = f"{rs.get('id', '')} {rs.get('name', '')}".lower()
        if any(hint in ident for hint in _NON_RS_HINTS):
            continue
        out.append(rs)
    return out


def _compute_alerts(logical_ports):
    """Compute health alerts from logical port data (admin only)."""
    alerts = []
    for lp in logical_ports:
        port_label = _dqt(lp["device"], lp["name"])
        # Invalid-IP binding: a MAC on this port is sourcing an IP that is not
        # assigned on the IX. The peering LAN is a shared L2 segment, so a
        # mis-configured address can disrupt other participants.
        invalid = lp.get("invalid_ip_bindings") or []
        if invalid:
            pairs = ", ".join(f"{b['mac']} → {b['ip']}" for b in invalid)
            alerts.append({
                "severity": "crit",
                "icon": "⛔",
                "title": ngettext(
                    "%(port)s is bound to an unassigned IP",
                    "%(port)s is bound to unassigned IPs",
                    len(invalid),
                ) % {"port": port_label},
                "body": gettext(
                    "A MAC learned on this port is sourcing an address that is not "
                    "assigned on the IX (%(pairs)s). Using an unallocated peering-LAN "
                    "IP is disallowed and can disrupt other participants — correct the "
                    "interface configuration."
                ) % {"pairs": pairs},
                "where": f"{port_label} · L3",
            })
        if lp["link_state"] == "down":
            alerts.append({
                "severity": "crit",
                "icon": "⛔",
                "title": gettext("%(port)s is down") % {"port": port_label},
                "body": gettext("All member links are offline. Route-server sessions are idle and no traffic is passing on this logical port."),
                "where": f"{port_label} · L1/L2",
            })
        elif lp["link_state"] == "degraded":
            alerts.append({
                "severity": "warn",
                "icon": "⚠",
                "title": gettext("%(port)s degraded — %(up)s/%(total)s members up") % {
                    "port": port_label,
                    "up": lp["members_up"],
                    "total": lp["members_total"],
                },
                "body": gettext(
                    "A member link is down; the bundle is running at "
                    "%(effective)sG of %(total)sG. "
                    "Redundancy is lost until the link is restored."
                ) % {
                    "effective": f"{lp['effective_speed_gbps']:.0f}",
                    "total": f"{lp['speed_gbps']:.0f}",
                },
                "where": f"{port_label} · L1",
            })
        # Check optics on physical ports
        for phy in lp["physical"]:
            if phy["link_status"] not in ("up", "connected"):
                continue
            for lane in phy.get("lanes", []):
                if lane["band"] in ("warn", "bad"):
                    phy_label = _dqt(phy["device"], phy["name"])
                    alerts.append({
                        "severity": "crit" if lane["band"] == "bad" else "warn",
                        "icon": "⚠",
                        "title": gettext("%(port)s optic %(band)s on %(lane)s") % {
                            "port": phy_label,
                            "band": lane["band_label"].lower(),
                            "lane": lane["label"],
                        },
                        "body": gettext("RX %(rx)s dBm is outside the nominal window. Inspect the fiber / patch or schedule an optic replacement.") % {
                            "rx": lane["rx_formatted"],
                        },
                        "where": f"{phy_label} · L1",
                    })
        # Check route rejections
        total_rejected = sum(
            rs.get("v4_rejected", 0) + rs.get("v6_rejected", 0)
            for rs in lp["route_servers"]
        )
        if total_rejected > 0:
            rs_session_count = sum(
                1 for rs in lp["route_servers"]
                if rs.get("v4_rejected", 0) or rs.get("v6_rejected", 0)
            )
            alerts.append({
                "severity": "warn",
                "icon": "⚠",
                "title": ngettext(
                    "%(count)s route rejected on %(port)s across %(rs_session_count)s %(sessions)s",
                    "%(count)s routes rejected on %(port)s across %(rs_session_count)s %(sessions)s",
                    total_rejected,
                ) % {
                    "count": total_rejected,
                    "port": port_label,
                    "rs_session_count": rs_session_count,
                    "sessions": ngettext("session", "sessions", rs_session_count),
                },
                "body": gettext("Prefixes are being filtered (IRR / RPKI-invalid, bogon, or max-prefix). Advertised routes may not be reaching peers as expected."),
                "where": f"{port_label} · L4",
            })
    return alerts


def _fetch_lldp_by_key(lg, token):
    """Fetch LLDP neighbors and index by (device, local_interface)."""
    lldp_by_key = {}
    try:
        results = lg.get_lldp_neighbors(token=token)
        for device_result in results:
            if device_result.get("success") and device_result.get("data"):
                dev = device_result.get("device", "")
                for entry in device_result["data"]:
                    lldp_by_key[(dev, entry.get("local_interface", ""))] = entry
    except Exception:
        logger.warning("Failed to fetch LLDP neighbors", exc_info=True)
    return lldp_by_key


def _parse_rfc3339(ts):
    """Parse an RFC3339 timestamp into a datetime, or None if blank/invalid."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _seen_display(entry):
    """Attach human-readable first/last-seen strings to a MAC entry dict."""
    first = _parse_rfc3339(entry.get("first_seen"))
    last = _parse_rfc3339(entry.get("last_seen"))
    entry["first_seen_display"] = first.strftime("%Y-%m-%d") if first else ""
    entry["last_seen_ago"] = timesince(last) if last else ""
    return entry


def _fetch_macs_by_key(lg, token):
    """Fetch the MAC table and index by (device, interface) -> list of entries.

    Many MACs can be learned on one port, so values are lists. Each entry is
    enriched with display-ready first/last-seen strings.
    """
    macs_by_key = {}
    try:
        for device_result in lg.get_mac_address_table(token=token):
            if device_result.get("success") and device_result.get("data"):
                dev = device_result.get("device", "")
                for entry in device_result["data"]:
                    macs_by_key.setdefault((dev, entry.get("interface", "")), []).append(
                        _seen_display(entry))
    except Exception:
        logger.warning("Failed to fetch MAC table", exc_info=True)
    return macs_by_key


def _fetch_peering_vlan_ids(lg):
    """Fetch the IXP peering-LAN dot1q VIDs as a set of strings (e.g. {"998"}).

    The looking-glass derives these from the NetBox ``peering_lan`` tag, so the
    set is portable across IXPs (today SFMIX has a single peering LAN, VID 998).
    Returns an empty set on any failure — callers treat that as "don't filter"
    so an older LG without this endpoint degrades to showing all VLANs rather
    than blanking the L2 band.
    """
    try:
        result = lg.get_peering_vlans()
        return {str(v["vid"]) for v in result.get("vlans", []) if v.get("vid") is not None}
    except Exception:
        logger.warning("Failed to fetch peering VLANs", exc_info=True)
        return set()


def _fetch_arp_by_ip(lg, token):
    """Fetch ARP table and index by IP address string."""
    arp_by_ip = {}
    try:
        results = lg.get_arp(token=token)
        for device_result in results:
            if device_result.get("success") and device_result.get("data"):
                for entry in device_result["data"]:
                    addr = entry.get("address", "")
                    mac = entry.get("mac_address", "")
                    if addr and mac:
                        arp_by_ip[addr] = mac
    except Exception:
        logger.warning("Failed to fetch ARP table", exc_info=True)
    return arp_by_ip


def _fetch_ndp_by_ip(lg, token):
    """Fetch IPv6 NDP table and index by IP address string."""
    ndp_by_ip = {}
    try:
        results = lg.get_ipv6_neighbors(token=token)
        for device_result in results:
            if device_result.get("success") and device_result.get("data"):
                for entry in device_result["data"]:
                    addr = entry.get("address", "")
                    mac = entry.get("mac_address", "")
                    if addr and mac:
                        ndp_by_ip[addr] = mac
    except Exception:
        logger.warning("Failed to fetch NDP table", exc_info=True)
    return ndp_by_ip


def _fetch_discovered_by_ip(lg, token, asn):
    """Fetch discovered ARP/NDP neighbors for an ASN, indexed by IP address.

    Returns {ip_str: {"macs": [...], "conflict": bool}} where each MAC entry
    carries display-ready first/last-seen strings. Distinct from ARP/NDP above:
    this is what was passively *heard* on the fabric, so an IP may have several
    MACs (a conflict) rather than the single one the kernel chose.
    """
    discovered_by_ip = {}
    try:
        result = lg.get_discovered_neighbors(token=token, asn=asn)
        for neighbor in result.get("neighbors", []):
            addr = neighbor.get("ip", "")
            if not addr:
                continue
            macs = [_seen_display(dict(m)) for m in neighbor.get("macs", [])]
            discovered_by_ip[addr] = {
                "macs": macs,
                "conflict": bool(neighbor.get("conflict")),
            }
    except Exception:
        logger.warning("Failed to fetch discovered neighbors", exc_info=True)
    return discovered_by_ip


def _norm_mac(s):
    """Normalize a MAC to bare lowercase hex for cross-source matching.

    Switch MAC-table formats vary by vendor (colon-separated vs Cisco-style
    ``aabb.ccdd.eeff``); the fabric sensor emits lowercase-colon. Strip all
    separators and lowercase so both sides compare equal.
    """
    if not s:
        return ""
    return s.replace(":", "").replace(".", "").replace("-", "").replace(" ", "").lower()


def _fetch_unassigned_by_mac(lg, token):
    """Fetch fabric-heard neighbors on *unassigned* IPs, indexed by MAC.

    These are IPs not in the NetBox assignment set — a host claiming one is
    mis-bound to an invalid/disallowed address on the IX. Returns
    ``{normalized_mac: [{ip, family, first_seen_display, last_seen_ago}, ...]}``
    so a participant's learned port MACs can be matched against them.
    """
    by_mac = {}
    try:
        result = lg.get_discovered_neighbors(token=token, unassigned=True)
        for neighbor in result.get("neighbors", []):
            addr = neighbor.get("ip", "")
            if not addr:
                continue
            for m in neighbor.get("macs", []):
                seen = _seen_display(dict(m))
                by_mac.setdefault(_norm_mac(m.get("mac", "")), []).append({
                    "ip": addr,
                    "family": neighbor.get("family", ""),
                    "first_seen_display": seen.get("first_seen_display", ""),
                    "last_seen_ago": seen.get("last_seen_ago", ""),
                })
    except Exception:
        logger.warning("Failed to fetch unassigned discovered neighbors", exc_info=True)
    return by_mac


def _fetch_rs_data(asn):
    """Fetch (sessions, routeservers) for ASN from Alice-LG.

    Returns the participant's RS sessions plus the configured route-server list
    (needed to compute parity against the expected RS set).
    """
    try:
        alice = AliceLGClient()
        if alice.base_url:
            all_sources = alice.get_routeservers()
            # Sessions for display include looking-glass / quarantine collectors
            # so they still appear in the participant listing; parity, however,
            # compares only the real route servers.
            sessions = [
                n for n in alice.get_all_neighbors(all_sources)
                if n.get("asn") == asn
            ]
            return sessions, _real_routeservers(all_sources)
    except Exception:
        logger.warning("Failed to fetch Alice RS data for AS%s", asn, exc_info=True)
    return [], []


def participant_detail(request, asn):
    """Network detail page with layered service-stackup view."""
    user_asns = request.session.get("oidc_asns", []) if request.user.is_authenticated else []
    is_admin = _is_ix_admin(request) if request.user.is_authenticated else False
    can_see_admin = is_admin or (asn in user_asns)
    token = request.session.get("oidc_id_token") if request.user.is_authenticated else None

    member = {}
    ip_addresses = []
    enriched_ports = []
    pdb_entry = {}
    logical_ports = []
    alerts = []
    has_invalid_ip = False
    rs_parity = None
    lg_error = None

    try:
        lg = LookingGlassClient()
        if lg.base_url:
            # 1. NetBox participant data
            detail = lg.get_participant_detail(asn, token=token)
            member = {
                "asn": detail.get("asn"),
                "name": detail.get("name", ""),
                "participant_type": detail.get("participant_type", ""),
            }
            ip_addresses = detail.get("ip_addresses", [])
            enriched_ports = detail.get("enriched_ports", [])

            # 2. PeeringDB cache for website URL
            try:
                pdb_data = lg.get_peeringdb_cache()
                pdb_entry = pdb_data.get("networks", {}).get(str(asn), {})
            except Exception:
                pass

            # 3. Live interface status (indexed by device+name)
            #    ASN filter requires auth; fall back to unfiltered for public
            iface_by_key = {}
            try:
                asn_filter = asn if token else None
                for device_result in lg.get_interfaces_status(token, asn=asn_filter):
                    if device_result.get("success") and device_result.get("data"):
                        dev = device_result.get("device", "")
                        for iface in device_result["data"]:
                            iface_by_key[(dev, iface["name"])] = iface
            except Exception:
                logger.warning("Failed to fetch interface status", exc_info=True)

            # 4. Optics (admin only)
            optics_by_key = {}
            if can_see_admin:
                try:
                    for device_result in lg.get_optics(token, asn=asn):
                        if device_result.get("success") and device_result.get("data"):
                            dev = device_result.get("device", "")
                            for optic in device_result["data"]:
                                optics_by_key[(dev, optic.get("name", ""))] = optic
                except Exception:
                    logger.warning("Failed to fetch optics", exc_info=True)

            # 5. LLDP neighbors + learned MACs (both public, per-port).
            #    Learned MACs are filtered to the IXP peering LAN only; other
            #    service VLANs on participant ports are not yet relevant here.
            lldp_by_key = _fetch_lldp_by_key(lg, token)
            macs_by_key = _fetch_macs_by_key(lg, token)
            peering_vlans = _fetch_peering_vlan_ids(lg)

            # 6. ARP + NDP (kernel-chosen MAC) and passively-heard neighbors
            arp_by_ip = _fetch_arp_by_ip(lg, token)
            ndp_by_ip = _fetch_ndp_by_ip(lg, token)
            discovered_by_ip = _fetch_discovered_by_ip(lg, token, asn)

            # 7. Route-server sessions + configured RS list from Alice-LG
            rs_sessions, routeservers = _fetch_rs_data(asn)

            # 8. Build logical port tree
            logical_ports = _build_logical_ports(
                enriched_ports, iface_by_key, optics_by_key, lldp_by_key, macs_by_key,
                ip_addresses, arp_by_ip, ndp_by_ip, discovered_by_ip, rs_sessions, can_see_admin,
                peering_vlans,
            )

            # 8b. Flag ports whose learned L2 MACs are heard on unassigned IPs:
            #     the participant is mis-bound to an invalid/disallowed address.
            unassigned_by_mac = _fetch_unassigned_by_mac(lg, token)
            if unassigned_by_mac:
                for lp in logical_ports:
                    bindings = []
                    seen = set()
                    for m in lp["macs"]:
                        mac = m.get("mac_address", "")
                        for hit in unassigned_by_mac.get(_norm_mac(mac), []):
                            key = (mac, hit["ip"])
                            if key in seen:
                                continue
                            seen.add(key)
                            bindings.append({"mac": mac, **hit})
                    lp["invalid_ip_bindings"] = bindings
                    if bindings:
                        has_invalid_ip = True

            # 9. Compute alerts (admin only)
            if can_see_admin:
                alerts = _compute_alerts(logical_ports)

            # 10. Route-server parity (public): warn when not redundantly
            #     peered with both route servers, or counts disagree.
            if _parity_applicable(detail, {str(asn): pdb_entry}):
                rs_parity = _compute_rs_parity(rs_sessions, routeservers)

    except Exception as e:
        lg_error = str(e)
        logger.exception("Error loading network detail for AS%s", asn)

    # Derive aggregate network status
    if logical_ports:
        if all(lp["link_state"] == "down" for lp in logical_ports):
            net_status = "down"
        elif any(lp["link_state"] != "up" for lp in logical_ports):
            net_status = "degraded"
        else:
            net_status = "active"
    else:
        net_status = "unknown"

    total_physical = sum(len(lp["physical"]) for lp in logical_ports)
    total_active_gbps = sum(lp["effective_speed_gbps"] for lp in logical_ports)
    total_provisioned_gbps = sum(lp["speed_gbps"] for lp in logical_ports)

    return render(request, "dashboard/participant_detail.html", {
        "asn": asn,
        "member": member,
        "website": pdb_entry.get("website", ""),
        "net_status": net_status,
        "logical_ports": logical_ports,
        "logical_port_count": len(logical_ports),
        "physical_port_count": total_physical,
        "total_active_gbps": total_active_gbps,
        "total_provisioned_gbps": total_provisioned_gbps,
        "alerts": alerts,
        "has_invalid_ip": has_invalid_ip,
        "rs_parity": rs_parity,
        "lg_error": lg_error,
        "can_see_admin": can_see_admin,
        "is_own_network": asn in user_asns,
        "is_ix_admin": is_admin,
    })


def _format_speed(speed_mbps):
    """Format port speed in Mbps to human-readable string."""
    if not speed_mbps:
        return ""
    if speed_mbps >= 1000:
        g = speed_mbps / 1000
        return f"{int(g)}G" if g == int(g) else f"{g:.1f}G"
    return f"{int(speed_mbps)}M"


def _site_from_device(device_fqdn):
    """Extract site code from a device FQDN like 'switch01.sfo02.sfmix.org'."""
    if not device_fqdn:
        return ""
    parts = device_fqdn.split(".")
    return parts[1].upper() if len(parts) >= 2 else ""


def _derive_status(participant):
    """Derive a display status from participant data."""
    ptype = (participant.get("participant_type") or "").lower()
    if ptype in ("ixp", "routeserver"):
        return "infrastructure"
    ips = participant.get("ip_addresses", [])
    ports = participant.get("enriched_ports", [])
    if not ips and not ports:
        return "inactive"
    has_active_ip = any(ip.get("status", "").lower() == "active" for ip in ips)
    has_enabled_port = any(p.get("enabled", False) for p in ports)
    if has_active_ip and has_enabled_port:
        return "active"
    if ips or ports:
        return "provisioning"
    return "inactive"


def _ip_sort_key(ip_str):
    """Convert dotted-quad IPv4 to a sortable integer, or 2^32 for missing."""
    if not ip_str or ip_str == "\u2014":
        return 2**32
    try:
        addr = ip_str.split("/")[0]
        return int(ipaddress.ip_address(addr))
    except (ValueError, TypeError):
        return 2**32


def _flatten_participant(p, pdb_cache):
    """Flatten a NetboxParticipant into a template-ready dict."""
    asn = p.get("asn", 0)
    ips = p.get("ip_addresses", [])
    ports = p.get("enriched_ports", [])
    v4 = next((ip["address"] for ip in ips if ip.get("family") == "IPv4"), "\u2014")
    v6 = next((ip["address"] for ip in ips if ip.get("family") == "IPv6"), "\u2014")
    speed_mbps = ports[0].get("speed") if ports else None
    device = ports[0].get("device", "") if ports else ""
    pdb = pdb_cache.get(str(asn), {})
    return {
        "asn": asn,
        "name": p.get("name", ""),
        "v4": v4,
        "v6": v6,
        "v4_sort": _ip_sort_key(v4),
        "speed_mbps": speed_mbps or 0,
        "speed": _format_speed(speed_mbps),
        "site": _site_from_device(device),
        "status": _derive_status(p),
        "participant_type": p.get("participant_type", ""),
        "website": pdb.get("website", ""),
        "peeringdb_url": f"https://www.peeringdb.com/asn/{asn}",
    }


def participants_list(request):
    """Public IXP participant list (no auth required)."""
    entries = []
    lg_error = None
    my_participants = []
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            all_participants = lg.get_participants()
            pdb_networks = {}
            try:
                pdb_data = lg.get_peeringdb_cache()
                pdb_networks = pdb_data.get("networks", {})
            except Exception:
                pass
            flat = [_flatten_participant(p, pdb_networks) for p in all_participants]
            entries = sorted(flat, key=lambda p: p["v4_sort"])
            if request.user.is_authenticated:
                user_asns = set(request.session.get("oidc_asns", []))
                my_participants = [p for p in flat if p["asn"] in user_asns]
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/participants_list.html", {
        "entries": entries,
        "my_participants": my_participants,
        "lg_error": lg_error,
        "is_ix_admin": _is_ix_admin(request) if request.user.is_authenticated else False,
    })


def route_server_parity(request):
    """Public route-server parity overview across all participants.

    Lists every active peer with a per-route-server status indicator (state +
    received-prefix count) and an overall parity verdict, sorted so the most
    dangerous configs (lost redundancy, then unpeered, then count mismatch)
    appear first.
    """
    entries = []
    routeservers = []
    counts = {"crit": 0, "warn": 0, "ok": 0}
    lg_error = None
    try:
        lg = LookingGlassClient()
        alice = AliceLGClient()
        if lg.base_url and alice.base_url:
            participants = lg.get_participants()
            try:
                pdb_networks = lg.get_peeringdb_cache().get("networks", {})
            except Exception:
                pdb_networks = {}
            routeservers = _real_routeservers(alice.get_routeservers())
            by_asn = defaultdict(list)
            for n in alice.get_all_neighbors(routeservers):
                by_asn[n.get("asn")].append(n)
            for p in participants:
                if not _parity_applicable(p, pdb_networks):
                    continue
                asn = p.get("asn", 0)
                parity = _compute_rs_parity(by_asn.get(asn, []), routeservers)
                if not parity:
                    continue
                counts[parity["severity"]] = counts.get(parity["severity"], 0) + 1
                entries.append({"asn": asn, "name": p.get("name", ""), "parity": parity})
            entries.sort(key=lambda e: (e["parity"]["sort_rank"], e["name"].lower()))
    except Exception as e:
        lg_error = str(e)
        logger.exception("Error loading route-server parity overview")
    return render(request, "dashboard/route_server_parity.html", {
        "entries": entries,
        "routeservers": routeservers,
        "counts": counts,
        "lg_error": lg_error,
        "is_ix_admin": _is_ix_admin(request) if request.user.is_authenticated else False,
    })


# ── Prometheus metrics ──────────────────────────────────────────────

def metrics_view(request):
    """Expose Prometheus metrics, restricted to trusted networks."""
    if not _ip_in_trusted_networks(_client_ip(request)):
        return HttpResponseForbidden("Forbidden")
    return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)


# ── Admin: NetBox status ────────────────────────────────────────────

@login_required
def netbox_status_view(request):
    """Show NetBox cache health and freshness to IX administrators."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden(gettext("IX Administrators only."))
    health = {}
    try:
        lg = get_lg_client()
        health = lg.get_netbox_status()
    except Exception as e:
        health = {"error": str(e)}
    return render(request, "dashboard/netbox_status.html", {
        "health": health,
        "is_ix_admin": True,
    })


# ── Admin: Optics (status + inventory) ─────────────────────────────

@login_required
def optics_view(request):
    """Transceiver DOM status and hardware inventory across all devices (admin only)."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden(gettext("IX Administrators only."))
    entries = []
    lg_error = None
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        if not lg.base_url:
            lg_error = gettext("Looking Glass not configured")
        else:
            status_by_key = {}
            for device_result in lg.get_optics(token=token):
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for optic in device_result["data"]:
                        status_by_key[(dev, optic.get("name", ""))] = optic

            for device_result in lg.get_optics_inventory(token=token):
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for inv in device_result["data"]:
                        key = (dev, inv.get("name", ""))
                        entry = status_by_key.pop(key, {})
                        entry.update({k: v for k, v in inv.items() if k not in entry})
                        entry["device"] = dev
                        entries.append(entry)

            # status entries with no matching inventory record
            for (dev, _), optic in status_by_key.items():
                optic["device"] = dev
                entries.append(optic)
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/optics.html", {
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": True,
    })


# ── Admin: Device cache status ──────────────────────────────────────

@login_required
def device_cache_status_view(request):
    """Show background device cache freshness to IX administrators."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden(gettext("IX Administrators only."))
    devices = []
    lg_error = None
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        devices = lg.get_device_cache_status(token=token)
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/device_cache_status.html", {
        "devices": devices,
        "lg_error": lg_error,
        "is_ix_admin": True,
    })
