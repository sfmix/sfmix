from django.urls import include, path

urlpatterns = [
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("", include("dashboard.urls")),
]
