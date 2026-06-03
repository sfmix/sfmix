from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("network/<int:asn>/mac-table/", views.network_mac_table, name="network_mac_table"),
    path("participants/", views.participants_list, name="participants_list"),
    path("participants/<int:asn>/", views.participant_detail, name="participant_detail"),
    path("admin/lldp/", views.lldp_neighbors, name="lldp_neighbors"),
    path("metrics/", views.metrics_view, name="metrics"),
    path("admin/netbox-status/", views.netbox_status_view, name="netbox_status"),
    path("admin/optics/", views.optics_status_view, name="optics_status"),
    path("admin/optics-inventory/", views.optics_inventory_view, name="optics_inventory"),
    path("admin/device-cache/", views.device_cache_status_view, name="device_cache_status"),
]
