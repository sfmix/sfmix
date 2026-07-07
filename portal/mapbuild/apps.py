import sys

from django.apps import AppConfig


class MapbuildConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "mapbuild"
    verbose_name = "Network map builder"

    def ready(self):
        # Register the daily build schedule idempotently on startup. Skip during
        # schema-management commands (the django_q tables may not exist yet); a
        # normal server/qcluster boot after migrate creates it.
        if any(c in sys.argv for c in ("migrate", "makemigrations", "collectstatic",
                                       "compilemessages", "test")):
            return
        from .tasks import ensure_schedule
        ensure_schedule()
