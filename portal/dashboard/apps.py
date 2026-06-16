from django.apps import AppConfig
from django.conf import settings


class DashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "dashboard"

    def ready(self):
        # Local-dev only: serve pages from JSON fixtures instead of the real
        # Looking Glass / Alice APIs. LG_USE_FIXTURES is itself DEBUG-gated in
        # settings, and install() re-checks DEBUG, so this never fires in prod.
        if getattr(settings, "LG_USE_FIXTURES", False):
            from . import devmock
            devmock.install()
