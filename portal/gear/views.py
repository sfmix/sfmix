"""peering-gear.sfmix.org: the SFMIX hardware fleet and where donations go.

IX Administrators only while it's being built up (OIDC via login.sfmix.org,
same `oidc_is_ix_admin` session flag the portal's admin pages use).
"""

from __future__ import annotations

import functools
import logging
from datetime import date, datetime, timezone

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseForbidden
from django.db.models import Sum
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import analysis, data
from .forms import PledgeForm
from .models import Pledge

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
        snap = data.get_snapshot(refresh=refresh)
        fleet, error = snap["fleet"], None
        request.gear_fetched_at = datetime.fromtimestamp(snap["fetched_at"], tz=timezone.utc)
    except Exception as exc:  # NetBox down and no snapshot yet: render the error
        logger.exception("peering-gear: NetBox fetch failed")
        fleet, error = [], f"Couldn't load hardware from NetBox: {exc}"
    today = date.today()
    analysis.enrich(fleet, today)
    ns = analysis.needs(fleet, today)
    return fleet, ns, error


def _wishlist(fleet):
    open_pledges = (Pledge.objects.filter(status__in=[Pledge.Status.NEW, Pledge.Status.CONFIRMED])
                    .exclude(item_slug="").values("item_slug").annotate(n=Sum("quantity")))
    return analysis.wishlist(fleet, {r["item_slug"]: r["n"] for r in open_pledges})


def _supporters():
    """Opted-in pledges an admin has confirmed, for the donor wall."""
    return [{"name": p.display_name, "url": p.url, "item": p.item_title or "hardware"}
            for p in Pledge.objects.filter(show_as_donor=True, status__in=[Pledge.Status.CONFIRMED, Pledge.Status.RECEIVED])]


def _ctx(request, nav, **kw):
    return {"nav": nav, "user_email": getattr(request.user, "email", ""),
            "fetched_at": getattr(request, "gear_fetched_at", None), **kw}


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
        wishlist=_wishlist(fleet),
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
        wishlist=_wishlist(fleet),
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
        wall=analysis.donor_wall(rows, _supporters()),
        pledges=Pledge.objects.all()[:200],
        statuses=Pledge.Status.choices,
    ))


@admin_only
def pledge(request):
    fleet, ns, error = _load(request)
    wishlist = _wishlist(fleet)
    if request.method == "POST":
        form = PledgeForm(request.POST, wishlist=wishlist)
        if form.is_valid():
            p = form.save(commit=False)
            p.submitted_by = getattr(request.user, "email", "") or ""
            p.save()
            logger.info("peering-gear: new pledge #%d (%s × %s)", p.pk, p.quantity, p.item_slug or "other")
            return redirect("gear_pledge_thanks", pk=p.pk)
    else:
        item = request.GET.get("item", "")
        hit = next((w for w in wishlist if w["slug"] == item), None)
        form = PledgeForm(wishlist=wishlist, initial={
            "item_slug": item if hit else (wishlist[0]["slug"] if wishlist else ""),
            "quantity": 1,
            "name": request.user.get_full_name() if request.user.is_authenticated else "",
            "email": getattr(request.user, "email", ""),
        })
    return render(request, "gear/pledge.html", _ctx(request, "pledge", error=error, form=form, wishlist=wishlist))


@admin_only
def pledge_thanks(request, pk):
    return render(request, "gear/pledge_thanks.html", _ctx(request, "pledge", pledge=get_object_or_404(Pledge, pk=pk)))


@require_POST
@admin_only
def pledge_status(request, pk):
    p = get_object_or_404(Pledge, pk=pk)
    if request.POST.get("status") in Pledge.Status.values:
        p.status = request.POST["status"]
        p.save(update_fields=["status", "updated_at"])
    return redirect("/donations/#pledges")


@require_POST
@admin_only
def refresh(request):
    data.get_snapshot(refresh=True)
    nxt = request.POST.get("next") or "/"
    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        nxt = "/"
    return redirect(nxt)
