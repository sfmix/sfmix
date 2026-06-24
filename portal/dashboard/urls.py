from django.conf import settings
from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("network/<int:asn>/mac-table/", views.network_mac_table, name="network_mac_table"),
    path("participants/", views.participants_list, name="participants_list"),
    path("statistics/", views.ix_statistics, name="ix_statistics"),
    path("statistics/metrics/", views.ix_metrics, name="ix_metrics"),
    path("route-servers/", views.route_server_parity, name="route_server_parity"),
    path("participants/<int:asn>/", views.participant_detail, name="participant_detail"),
    path("participants/<int:asn>/metrics/", views.participant_metrics, name="participant_metrics"),
    path("admin/lldp/", views.lldp_neighbors, name="lldp_neighbors"),
    path("admin/nd-events/", views.nd_events, name="nd_events"),
    path("admin/nd-events/<str:event_id>/pcap/", views.nd_event_pcap, name="nd_event_pcap"),
    path("metrics/", views.metrics_view, name="metrics"),
    path("admin/netbox-status/", views.netbox_status_view, name="netbox_status"),
    path("admin/optics/", views.optics_view, name="optics"),
    path("admin/device-cache/", views.device_cache_status_view, name="device_cache_status"),
]

# DEBUG-only dev login bypass (gated; absent / 404 in production).
if getattr(settings, "DEV_LOGIN_ENABLED", False):
    from . import devauth
    urlpatterns.append(path("dev/login/", devauth.dev_login, name="dev_login"))
