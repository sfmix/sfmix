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


@login_required
def network_mac_table(request, asn):
    """MAC address table for a participant network."""
    asns = request.session.get("oidc_asns", [])
    if asn not in asns:
        return HttpResponseForbidden("You do not have access to this network.")
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
def lldp_neighbors(request):
    """LLDP neighbor table (admin only)."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden("IX Administrators only.")
    entries = []
    lg_error = None
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        if not lg.base_url:
            lg_error = "Looking Glass not configured"
        else:
            results = lg.get_lldp_neighbors(token=token)
            for device_result in results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for entry in device_result["data"]:
                        entry["device"] = dev
                        entries.append(entry)
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/lldp_neighbors.html", {
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": True,
    })


def participant_detail(request, asn):
    """Participant info page; live optics shown to IXP admins and own-network users."""
    user_asns = request.session.get("oidc_asns", []) if request.user.is_authenticated else []
    is_admin = _is_ix_admin(request) if request.user.is_authenticated else False
    can_see_live = is_admin or (asn in user_asns)
    token = request.session.get("oidc_id_token") if request.user.is_authenticated else None

    member = {}
    ip_addresses = []
    peering_ports = []
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            detail = lg.get_participant_detail(asn, token=token)
            member = {
                "asn": detail.get("asn"),
                "name": detail.get("name"),
                "participant_type": detail.get("participant_type"),
            }
            ip_addresses = detail.get("ip_addresses", [])
            peering_ports = detail.get("enriched_ports", [])
    except Exception:
        pass

    live_interfaces = []
    lg_error = None
    if can_see_live:
        try:
            lg = LookingGlassClient()
            if lg.base_url:
                iface_results = lg.get_interfaces_status(token, asn=asn)
                for device_result in iface_results:
                    if device_result.get("success") and device_result.get("data"):
                        dev = device_result.get("device", "")
                        for iface in device_result["data"]:
                            iface["device"] = dev
                            live_interfaces.append(iface)

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

    return render(request, "dashboard/participant_detail.html", {
        "asn": asn,
        "member": member,
        "ip_addresses": ip_addresses,
        "peering_ports": peering_ports,
        "live_interfaces": live_interfaces,
        "lg_error": lg_error,
        "can_see_live": can_see_live,
        "is_own_network": asn in user_asns,
        "is_ix_admin": is_admin,
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


# ── Admin: Optics status ────────────────────────────────────────────

@login_required
def optics_status_view(request):
    """Transceiver DOM status across all devices (admin only)."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden("IX Administrators only.")
    entries = []
    lg_error = None
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        if not lg.base_url:
            lg_error = "Looking Glass not configured"
        else:
            results = lg.get_optics(token=token)
            for device_result in results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for optic in device_result["data"]:
                        optic["device"] = dev
                        entries.append(optic)
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/optics_status.html", {
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": True,
    })


# ── Admin: Optics inventory ─────────────────────────────────────────

@login_required
def optics_inventory_view(request):
    """Transceiver hardware inventory across all devices (admin only)."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden("IX Administrators only.")
    entries = []
    lg_error = None
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        if not lg.base_url:
            lg_error = "Looking Glass not configured"
        else:
            results = lg.get_optics_inventory(token=token)
            for device_result in results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for entry in device_result["data"]:
                        entry["device"] = dev
                        entries.append(entry)
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/optics_inventory.html", {
        "entries": entries,
        "lg_error": lg_error,
        "is_ix_admin": True,
    })


# ── Admin: Device cache status ──────────────────────────────────────

@login_required
def device_cache_status_view(request):
    """Show background device cache freshness to IX administrators."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden("IX Administrators only.")
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
