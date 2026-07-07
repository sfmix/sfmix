"""Admin-gated build-status viewer for the network map.

Reuses the portal's IX-administrator session gate (the "IX Administrators" OIDC
group). Reads Django-Q2's own tables for run history/queue depth — no Django
admin site needed — and offers an on-demand rebuild.
"""
import json
import os

from django.conf import settings
from django.http import FileResponse
from django.http import Http404
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext
from django.views.decorators.http import require_POST

from .tasks import SCHEDULE_NAME

TASK_FUNC = "mapbuild.tasks.build_map_task"


def map_json(request):
    """Serve the PUBLIC map.json the builder writes. Opaque ids only — no circuit
    ids/providers — so it's safe to serve cross-origin to the website frontend.
    (map-links.json is never served; the traffic feed keys off it server-side.)"""
    try:
        resp = FileResponse(open(settings.MAP_OUTPUT, "rb"), content_type="application/json")
    except OSError:
        raise Http404("map.json not built yet")
    resp["Access-Control-Allow-Origin"] = "*"
    resp["Cache-Control"] = "public, max-age=300"
    return resp


def _is_ix_admin(request):
    return request.session.get("oidc_is_ix_admin", False)


def _current_map():
    try:
        d = json.load(open(settings.MAP_OUTPUT))
    except (OSError, ValueError):
        return None
    return {
        "generation": d.get("generation"),
        "generated_at": d.get("generated_at"),
        "cables": len(d.get("cables", [])),
        "sites": len(d.get("sites", {})),
        "mtime": os.path.getmtime(settings.MAP_OUTPUT),
        "path": settings.MAP_OUTPUT,
    }


def status(request):
    if not _is_ix_admin(request):
        return HttpResponseForbidden(gettext("IX Administrators only."))
    ctx = {"is_ix_admin": True, "current": _current_map(),
           "schedule": None, "successes": [], "failures": [], "queued": 0, "q_error": None}
    try:
        from django_q.models import Failure, OrmQ, Schedule, Success
        ctx["successes"] = list(Success.objects.filter(func=TASK_FUNC).order_by("-stopped")[:10])
        ctx["failures"] = list(Failure.objects.filter(func=TASK_FUNC).order_by("-stopped")[:10])
        ctx["schedule"] = Schedule.objects.filter(name=SCHEDULE_NAME).first()
        ctx["queued"] = OrmQ.objects.count()
    except Exception as e:
        ctx["q_error"] = str(e)
    return render(request, "mapbuild/status.html", ctx)


@require_POST
def rebuild(request):
    if not _is_ix_admin(request):
        return HttpResponseForbidden(gettext("IX Administrators only."))
    from django_q.tasks import async_task
    async_task(TASK_FUNC, group="map-build")
    return redirect(reverse("mapbuild:status"))
