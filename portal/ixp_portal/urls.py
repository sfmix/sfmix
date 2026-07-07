from django.urls import include, path

urlpatterns = [
    path("oidc/", include("mozilla_django_oidc.urls")),
    # Built-in set_language view: validates the posted code against LANGUAGES,
    # stores it in the django_language cookie, and redirects back. Powers the
    # in-nav language picker.
    path("i18n/", include("django.conf.urls.i18n")),
    path("", include("mapbuild.urls")),
    path("", include("dashboard.urls")),
]
