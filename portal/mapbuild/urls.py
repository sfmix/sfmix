from django.urls import path

from . import views

app_name = "mapbuild"

urlpatterns = [
    # NOTE: the public map.json + operator logos (/statistics/map/map.json and
    # /statistics/map/logos/) are served directly from disk by nginx now, not by
    # Django — see the ixp_portal nginx template. No route here for them.
    # admin: build status + on-demand rebuild
    path("admin/map-build/", views.status, name="status"),
    path("admin/map-build/rebuild/", views.rebuild, name="rebuild"),
]
