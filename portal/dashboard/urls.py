from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("network/<int:asn>/", views.network_detail, name="network_detail"),
    path("metrics/", views.metrics_view, name="metrics"),
    path("admin/netbox-status/", views.netbox_status_view, name="netbox_status"),
    path("admin/netbox-clear/", views.netbox_clear_cache_view, name="netbox_clear_cache"),
]
