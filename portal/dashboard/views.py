import ipaddress

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from . import services
from .lg_client import LookingGlassClient


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
    participants = services.get_participants_for_asns(set(asns)) if asns else []
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
    participants = services.get_participants_for_asns({asn})
    member = participants[0] if participants else {}
    tenant_id = member.get("id")
    ip_addresses = services.get_participant_ips(tenant_id) if tenant_id else []
    peering_ports = services.get_participant_peering_ports(tenant_id) if tenant_id else []

    # Fetch live interface status (with optics merged in) from Looking Glass
    live_interfaces = []
    lg_error = None
    token = request.session.get("oidc_id_token")
    try:
        lg = LookingGlassClient()
        if lg.base_url:
            # Get interface status - LG filters by user's ASN via token
            iface_results = lg.get_interfaces_status(token)
            for device_result in iface_results:
                if device_result.get("success") and device_result.get("data"):
                    for iface in device_result["data"]:
                        # Filter to interfaces matching this ASN
                        desc = iface.get("description", "")
                        if f"AS{asn}" in desc or f"(AS{asn})" in desc:
                            iface["device"] = device_result.get("device", "")
                            live_interfaces.append(iface)

            # Discover LAG member interfaces from status data
            # Build full interface lookup: (device, name) -> iface dict
            all_ifaces_by_key = {}
            for device_result in iface_results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for iface in device_result["data"]:
                        all_ifaces_by_key[(dev, iface["name"])] = iface

            for iface in list(live_interfaces):
                name = iface["name"]
                device = iface.get("device", "")
                # Extract base Port-Channel name (strip .VLAN suffix)
                base_pc = name.split(".")[0] if "Port-Channel" in name and "." in name else name
                if not base_pc.startswith("Port-Channel"):
                    continue
                # Look up member_interfaces from the base Port-Channel's status entry
                base_entry = all_ifaces_by_key.get((device, base_pc))
                if not base_entry:
                    continue
                for member_name in base_entry.get("member_interfaces", []):
                    member = all_ifaces_by_key.get((device, member_name))
                    if member:
                        entry = dict(member)
                        entry["device"] = device
                        entry["is_lag_member"] = True
                        entry["parent_lag"] = name
                        live_interfaces.append(entry)

            # Get optics and merge into matching interfaces
            optics_results = lg.get_optics(token)
            # Build lookup: (device, interface_name) -> optics data
            optics_by_key = {}
            for device_result in optics_results:
                if device_result.get("success") and device_result.get("data"):
                    dev = device_result.get("device", "")
                    for optic in device_result["data"]:
                        optics_by_key[(dev, optic.get("name", ""))] = optic
            # Merge optics fields into each live interface
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
    health = services.get_health()
    return render(request, "dashboard/netbox_status.html", {
        "health": health,
        "is_ix_admin": True,
    })


@login_required
@require_POST
def netbox_refresh_cache_view(request):
    """Force an immediate synchronous refresh of the NetBox cache."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden("IX Administrators only.")
    services.refresh_cache()
    return redirect("netbox_status")
