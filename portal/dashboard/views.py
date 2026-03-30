from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render

from . import services


def login_view(request):
    if request.user.is_authenticated:
        return redirect("/")
    return render(request, "dashboard/login.html")


@login_required
def index(request):
    asns = request.session.get("oidc_asns", [])
    participants = services.get_participants_for_asns(set(asns)) if asns else []
    return render(request, "dashboard/index.html", {
        "asns": asns,
        "participants": participants,
        "is_ix_admin": request.session.get("oidc_is_ix_admin", False),
    })


@login_required
def network_detail(request, asn):
    asns = request.session.get("oidc_asns", [])
    if asn not in asns:
        return HttpResponseForbidden("You do not have access to this network.")
    participants = services.get_participants_for_asns({asn})
    member = participants[0] if participants else {}
    netbox_data = services.get_netbox_participant(asn)
    return render(request, "dashboard/network_detail.html", {
        "asn": asn,
        "member": member,
        "netbox_data": netbox_data,
        "is_ix_admin": request.session.get("oidc_is_ix_admin", False),
    })
