"""Django-Q2 tasks for the network-map build.

build_map_task() is the unit of work Q2 runs — on the daily schedule and on
demand from the admin status page. It returns a small summary dict (Q2 stores it
as the task result, surfaced in the status viewer) and raises on failure so Q2
records a Failure with the traceback.
"""
import datetime
import logging

from django.conf import settings

from . import builder

log = logging.getLogger("mapbuild")

SCHEDULE_NAME = "map-build-daily"


def build_map_task():
    """Build map.json + map-links.json from NetBox + committed geometry and write
    them to the configured outputs. Returns a run summary."""
    mapjson, links, drift = builder.build()
    builder.write_outputs(mapjson, links, settings.MAP_OUTPUT, settings.MAP_LINKS_OUTPUT)
    result = {
        "generation": mapjson["generation"],
        "generated_at": mapjson["generated_at"],
        "cables": len(mapjson["cables"]),
        "sites": len(mapjson["sites"]),
        "metros": len(mapjson["metros"]),
        "drift": {k: len(v) for k, v in drift.items()},
        "out": settings.MAP_OUTPUT,
    }
    log.info("map build ok: %s", result)
    return result


def ensure_schedule():
    """Idempotently register the daily map-build schedule. Safe to call from
    AppConfig.ready(): tolerant of the django_q tables not existing yet (e.g.
    during migrate) — it just no-ops and the next boot creates it."""
    try:
        from django_q.models import Schedule
    except Exception:
        return
    try:
        from django.utils import timezone
        hh, mm = (settings.MAP_BUILD_CRON_UTC.split(":") + ["0"])[:2]
        now = timezone.now()
        run_at = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
        if run_at <= now:
            run_at += datetime.timedelta(days=1)
        Schedule.objects.get_or_create(
            name=SCHEDULE_NAME,
            defaults=dict(
                func="mapbuild.tasks.build_map_task",
                schedule_type=Schedule.DAILY,
                next_run=run_at,
                repeats=-1,  # forever
            ),
        )
    except Exception:
        # django_q not migrated yet, or DB not ready — the next ready() recreates it.
        log.debug("ensure_schedule skipped (django_q not ready)")
