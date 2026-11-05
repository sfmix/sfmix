from django.conf import settings


class GearHostMiddleware:
    """Serve the peering-gear site from this same Django project by Host header.

    Requests for a host in settings.GEAR_HOSTS (peering-gear.sfmix.org) get
    gear.urls as their URLconf; everything else keeps the portal's. Must run
    before CommonMiddleware (APPEND_SLASH resolves against the URLconf).
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.hosts = {h.strip().lower() for h in getattr(settings, "GEAR_HOSTS", []) if h.strip()}

    def __call__(self, request):
        host = request.get_host().split(":")[0].lower()
        if host in self.hosts:
            request.urlconf = "gear.urls"
            request.is_gear_site = True
        return self.get_response(request)
