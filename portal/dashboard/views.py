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
    return redirect("participants_list")



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

            port_to_participant: dict[tuple[str, str], dict] = {
                (p["device"], p["interface"]): p
                for p in lg.get_participant_ports(token=token)
                if p.get("device") and p.get("interface")
            }

            for entry in entries:
                key = (entry.get("device", ""), entry.get("local_interface", ""))
                participant = port_to_participant.get(key)
                entry["participant_asn"] = participant["asn"] if participant else None
                entry["participant_name"] = participant["name"] if participant else ""
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

                # Mark LAG members and reorder so each parent is immediately
                # followed by its children (sorted by name).
                for iface in live_interfaces:
                    parent = iface.get("port_channel")
                    if parent:
                        iface["is_lag_member"] = True
                        iface["parent_lag"] = parent

                members_by_parent: dict = {}
                for iface in live_interfaces:
                    if iface.get("is_lag_member"):
                        members_by_parent.setdefault(iface["parent_lag"], []).append(iface)
                for v in members_by_parent.values():
                    v.sort(key=lambda i: i["name"])
                ordered = []
                seen_members: set = set()
                for iface in live_interfaces:
                    if iface.get("is_lag_member"):
                        continue
                    ordered.append(iface)
                    for child in members_by_parent.get(iface["name"], []):
                        ordered.append(child)
                        seen_members.add(id(child))
                for iface in live_interfaces:
                    if iface.get("is_lag_member") and id(iface) not in seen_members:
                        ordered.append(iface)
                live_interfaces = ordered

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
    my_participants = []
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            all_participants = lg.get_participants()
            entries = sorted(all_participants, key=lambda p: p.get("asn", 0))
            if request.user.is_authenticated:
                user_asns = set(request.session.get("oidc_asns", []))
                my_participants = [p for p in all_participants if p.get("asn") in user_asns]
    except Exception as e:
        lg_error = str(e)
    return render(request, "dashboard/participants_list.html", {
        "entries": entries,
        "my_participants": my_participants,
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


# ── Admin: Optics (status + inventory) ─────────────────────────────

@login_required
def optics_view(request):
    """Transceiver DOM status and hardware inventory across all devices (admin only)."""
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
