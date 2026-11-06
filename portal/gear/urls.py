"""URLconf for peering-gear.sfmix.org (selected per request by GearHostMiddleware)."""

from django.conf import settings
from django.urls import include, path

from dashboard import views as portal_views

from . import views

urlpatterns = [
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("login/", portal_views.login_view, name="login"),
    path("logout/", portal_views.logout_view, name="logout"),
    path("", views.fleet, name="index"),
    path("device/<str:name>/", views.device, name="gear_device"),
    path("needs/", views.needs, name="gear_needs"),
    path("donations/", views.donations, name="gear_donations"),
    path("pledge/", views.pledge, name="gear_pledge"),
    path("pledge/<int:pk>/thanks/", views.pledge_thanks, name="gear_pledge_thanks"),
    path("pledges/<int:pk>/status/", views.pledge_status, name="gear_pledge_status"),
    path("refresh/", views.refresh, name="gear_refresh"),
]

if getattr(settings, "DEV_LOGIN_ENABLED", False):
    from dashboard import devauth

    urlpatterns.append(path("dev/login/", devauth.dev_login, name="dev_login"))
