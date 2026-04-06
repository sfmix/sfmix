import ipaddress

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from .lg_client import LookingGlassClient, get_lg_client


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
    return render(request, "dashboard/login.html")


def logout_view(request):
    auth_logout(request)
    return redirect("/login/")


# ── Dashboard views ─────────────────────────────────────────────────

@login_required
def index(request):
    asns = request.session.get("oidc_asns", [])
    participants = []
    if asns:
        try:
            lg = get_lg_client()
            all_participants = lg.get_participants()
            asn_set = set(asns)
            participants = [p for p in all_participants if p.get("asn") in asn_set]
        except Exception:
            pass
    return render(request, "dashboard/index.html", {
        "asns": asns,
        "participants": participants,
        "is_ix_admin": _is_ix_admin(request),
    })


@login_required
def network_detail(request, asn):
    asns = request.session.get("oidc_asns", [])
    if asn not in asns:
        return HttpResponseForbidden("You do not have access to this network.")

    # Fetch participant detail (with IPs and ports) from Looking Glass
    member = {}
    ip_addresses = []
    peering_ports = []
    try:
        lg = get_lg_client()
        detail = lg.get_participant_detail(asn)
        member = {"asn": detail.get("asn"), "name": detail.get("name"), "participant_type": detail.get("participant_type")}
        ip_addresses = detail.get("ip_addresses", [])
        peering_ports = detail.get("enriched_ports", [])
    except Exception:
        pass

    # Fetch live interface status (with optics merged in) from Looking Glass
    live_interfaces = []
    lg_error = None
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            # Use server-side ASN filtering
            iface_results = lg.get_interfaces_status(token, asn=asn)
            for device_result in iface_results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for iface in device_result["data"]:
                        iface["device"] = dev
                        live_interfaces.append(iface)

            # Discover LAG member interfaces from status data
            all_ifaces_by_key = {}
            for iface in live_interfaces:
                all_ifaces_by_key[(iface.get("device", ""), iface["name"])] = iface

            for iface in list(live_interfaces):
                name = iface["name"]
                device = iface.get("device", "")
                base_pc = name.split(".")[0] if "Port-Channel" in name and "." in name else name
                if not base_pc.startswith("Port-Channel"):
                    continue
                base_entry = all_ifaces_by_key.get((device, base_pc))
                if not base_entry:
                    continue
                for member_name in base_entry.get("member_interfaces", []):
                    member_iface = all_ifaces_by_key.get((device, member_name))
                    if member_iface:
                        entry = dict(member_iface)
                        entry["is_lag_member"] = True
                        entry["parent_lag"] = name
                        live_interfaces.append(entry)

            # Get optics filtered by ASN and merge
            optics_results = lg.get_optics(token, asn=asn)
            optics_by_key = {}
            for device_result in optics_results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for optic in device_result["data"]:
                        optics_by_key[(dev, optic.get("name", ""))] = optic
            for iface in live_interfaces:
                optic = optics_by_key.get((iface.get("device", ""), iface["name"]))
                if optic and optic.get("dom_supported"):
                    lanes = optic.get("lanes", [])
                    if lanes:
                        lane = lanes[0]
                        tx = lane.get("tx_power_dbm")
                        rx = lane.get("rx_power_dbm")
                        iface["tx_power"] = f"{tx:.2f} dBm" if tx is not None else None
                        iface["rx_power"] = f"{rx:.2f} dBm" if rx is not None else None
                    temp = optic.get("temperature_c")
                    iface["temperature"] = f"{temp:.1f}°C" if temp is not None else None
                    iface["media_type"] = optic.get("media_type", "")
    except Exception as e:
        lg_error = str(e)

    return render(request, "dashboard/network_detail.html", {
        "asn": asn,
        "member": member,
        "ip_addresses": ip_addresses,
        "peering_ports": peering_ports,
        "live_interfaces": live_interfaces,
        "lg_error": lg_error,
        "is_ix_admin": _is_ix_admin(request),
    })


# ── Looking Glass feature views ────────────────────────────────────

def _lg_call(request, method, *args, **kwargs):
    """Call a LookingGlassClient method, returning (data, error)."""
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        if not lg.base_url:
            return [], "Looking Glass not configured"
        results = getattr(lg, method)(token=token, *args, **kwargs)
        data = []
        for device_result in results:
            if device_result.get("success") and device_result.get("data"):
                dev = device_result.get("device", "")
                item = device_result["data"]
                if isinstance(item, list):
                    for entry in item:
                        if isinstance(entry, dict):
                            entry["device"] = dev
                        data.append(entry)
                elif isinstance(item, dict):
                    item["device"] = dev
                    data.append(item)
        return data, None
    except Exception as e:
        return [], str(e)


def _check_asn_access(request, asn):
    """Return HttpResponseForbidden if user doesn't own this ASN."""
    asns = request.session.get("oidc_asns", [])
    if asn not in asns:
        return HttpResponseForbidden("You do not have access to this network.")
    return None


@login_required
def network_bgp(request, asn):
    """BGP summary for a participant network."""
    denied = _check_asn_access(request, asn)
    if denied:
        return denied
    token = request.session.get("oidc_id_token")
    peers_v4 = []
    peers_v6 = []
    lg_error = None
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            for af, dest in [("ipv4", peers_v4), ("ipv6", peers_v6)]:
                results = lg.get_bgp_summary(af=af, token=token)
                for device_result in results:
                    if device_result.get("success") and device_result.get("data"):
                        summary = device_result["data"]
                        dev = device_result.get("device", "")
                        for peer in summary.get("peers", []):
                            if peer.get("remote_as") == asn:
                                peer["device"] = dev
                                peer["router_id"] = summary.get("router_id", "")
                                peer["local_as"] = summary.get("local_as", 0)
                                dest.append(peer)
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/network_bgp.html", {
        "asn": asn,
        "peers_v4": peers_v4,
        "peers_v6": peers_v6,
        "lg_error": lg_error,
        "is_ix_admin": _is_ix_admin(request),
    })


@login_required
def network_bgp_neighbor(request, asn, address):
    """BGP neighbor detail for a specific peer."""
    denied = _check_asn_access(request, asn)
    if denied:
        return denied
    af = request.GET.get("af", "ipv4")
    token = request.session.get("oidc_id_token")
    neighbor = None
    lg_error = None
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            results = lg.get_bgp_neighbor(address, af=af, token=token)
            for device_result in results:
                if device_result.get("success") and device_result.get("data"):
                    neighbor = device_result["data"]
                    neighbor["device"] = device_result.get("device", "")
                    break
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/network_bgp_neighbor.html", {
        "asn": asn,
        "address": address,
        "af": af,
        "neighbor": neighbor,
        "lg_error": lg_error,
        "is_ix_admin": _is_ix_admin(request),
    })


@login_required
def network_mac_table(request, asn):
    """MAC address table for a participant network."""
    denied = _check_asn_access(request, asn)
    if denied:
        return denied
    vlan = request.GET.get("vlan")
    token = request.session.get("oidc_id_token")
    entries = []
    lg_error = None
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            results = lg.get_mac_address_table(token=token, vlan=vlan)
            for device_result in results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for entry in device_result["data"]:
                        entry["device"] = dev
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
def network_arp(request, asn):
    """ARP table view for a participant network."""
    denied = _check_asn_access(request, asn)
    if denied:
        return denied
    entries, lg_error = _lg_call(request, "get_arp_table")
    return render(request, "dashboard/network_arp.html", {
        "asn": asn,
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": _is_ix_admin(request),
    })


@login_required
def network_nd(request, asn):
    """IPv6 neighbor discovery table for a participant network."""
    denied = _check_asn_access(request, asn)
    if denied:
        return denied
    entries, lg_error = _lg_call(request, "get_nd_table")
    return render(request, "dashboard/network_nd.html", {
        "asn": asn,
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": _is_ix_admin(request),
    })


@login_required
def lldp_neighbors(request):
    """LLDP neighbor table (admin only)."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden("IX Administrators only.")
    entries, lg_error = _lg_call(request, "get_lldp_neighbors")
    return render(request, "dashboard/lldp_neighbors.html", {
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": True,
    })


@login_required
def vxlan_vtep(request):
    """VXLAN VTEP table (admin only)."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden("IX Administrators only.")
    entries, lg_error = _lg_call(request, "get_vxlan_vtep")
    return render(request, "dashboard/vxlan_vtep.html", {
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": True,
    })


def participants_list(request):
    """Public IXP participant list (no auth required)."""
    entries = []
    lg_error = None
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            entries = lg.get_participants()
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/participants_list.html", {
        "entries": entries,
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
        return HttpResponseForbidden("IX Administrators only.")
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
