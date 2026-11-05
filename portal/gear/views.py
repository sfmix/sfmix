"""peering-gear.sfmix.org: the SFMIX hardware fleet and where donations go.

IX Administrators only while it's being built up (OIDC via login.sfmix.org,
same `oidc_is_ix_admin` session flag the portal's admin pages use).
"""

from __future__ import annotations

import functools
import logging
from datetime import date

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import analysis, data

logger = logging.getLogger(__name__)


def admin_only(view):
    @login_required
    @functools.wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.session.get("oidc_is_ix_admin", False):
            return HttpResponseForbidden(render(request, "gear/forbidden.html").content)
        return view(request, *args, **kwargs)

    return wrapped


def _load(request, refresh: bool = False):
    try:
        fleet = data.get_fleet(refresh=refresh)
        error = None
    except Exception as exc:  # NetBox down: render the page with the error
        logger.exception("peering-gear: NetBox fetch failed")
        fleet, error = [], f"Couldn't load hardware from NetBox: {exc}"
    today = date.today()
    analysis.enrich(fleet, today)
    ns = analysis.needs(fleet, today)
    return fleet, ns, error


def _ctx(request, nav, **kw):
    return {"nav": nav, "user_email": getattr(request.user, "email", ""), **kw}


@admin_only
def fleet(request):
    fleet, ns, error = _load(request)
    return render(request, "gear/fleet.html", _ctx(
        request, "fleet",
        error=error,
        stats=analysis.stats(fleet, ns),
        roles=analysis.by_role(fleet),
        need_summary=analysis.need_summary(ns),
        flow=analysis.needs_flow(ns),
        top_needs=[n for n in ns if n.severity >= 2][:8],
    ))


@admin_only
def device(request, name):
    fleet, ns, error = _load(request)
    dev = next((d for d in fleet if d["name"] == name), None)
    if dev is None:
        raise Http404("No such device")
    return render(request, "gear/device.html", _ctx(
        request, "fleet",
        error=error,
        dev=dev,
        needs=[n for n in ns if n.device == name],
    ))


@admin_only
def needs(request):
    fleet, ns, error = _load(request)
    groups = []
    for cat in analysis.CATEGORY_LABELS:
        items = [n for n in ns if n.category == cat]
        if items:
            groups.append({"category": cat, "label": analysis.CATEGORY_LABELS[cat], "items": items,
                           "units": sum(n.units for n in items)})
    return render(request, "gear/needs.html", _ctx(
        request, "needs",
        error=error,
        stats=analysis.stats(fleet, ns),
        need_summary=analysis.need_summary(ns),
        groups=groups,
        flow=analysis.needs_flow(ns, include_optics=True),
        spares=analysis.spares(fleet),
    ))


@admin_only
def donations(request):
    fleet, ns, error = _load(request)
    rows = analysis.donations(fleet)
    return render(request, "gear/donations.html", _ctx(
        request, "donations",
        error=error,
        rows=rows,
        donors=sorted({r["donor"] for r in rows}),
        flow=analysis.donations_flow(rows),
        could_flow=analysis.needs_flow(ns),
    ))


@require_POST
@admin_only
def refresh(request):
    data.get_fleet(refresh=True)
    nxt = request.POST.get("next") or "/"
    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        nxt = "/"
    return redirect(nxt)
