from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("network/<int:asn>/", views.network_detail, name="network_detail"),
    path("network/<int:asn>/bgp/", views.network_bgp, name="network_bgp"),
    path("network/<int:asn>/bgp/neighbor/<str:address>/", views.network_bgp_neighbor, name="network_bgp_neighbor"),
    path("network/<int:asn>/mac-table/", views.network_mac_table, name="network_mac_table"),
    path("network/<int:asn>/arp/", views.network_arp, name="network_arp"),
    path("network/<int:asn>/nd/", views.network_nd, name="network_nd"),
    path("participants/", views.participants_list, name="participants_list"),
    path("admin/lldp/", views.lldp_neighbors, name="lldp_neighbors"),
    path("admin/vxlan-vtep/", views.vxlan_vtep, name="vxlan_vtep"),
    path("metrics/", views.metrics_view, name="metrics"),
    path("admin/netbox-status/", views.netbox_status_view, name="netbox_status"),
]
