import ipaddress

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from . import services


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
    return render(request, "dashboard/network_detail.html", {
        "asn": asn,
        "member": member,
        "ip_addresses": ip_addresses,
        "peering_ports": peering_ports,
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
def netbox_clear_cache_view(request):
    """Clear all cached NetBox data and trigger an immediate refresh."""
    if not _is_ix_admin(request):
        return HttpResponseForbidden("IX Administrators only.")
    services.clear_cache()
    return redirect("netbox_status")
