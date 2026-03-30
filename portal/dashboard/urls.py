from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login_view, name="login"),
    path("network/<int:asn>/", views.network_detail, name="network_detail"),
]
