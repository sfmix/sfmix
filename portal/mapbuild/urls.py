from django.urls import path

from . import views

app_name = "mapbuild"

urlpatterns = [
    # public: the built structure the frontend draws (opaque ids, safe cross-origin)
    path("statistics/map/map.json", views.map_json, name="map_json"),
    # admin: build status + on-demand rebuild
    path("admin/map-build/", views.status, name="status"),
    path("admin/map-build/rebuild/", views.rebuild, name="rebuild"),
]
