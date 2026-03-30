from . import services


class NetBoxCacheMiddleware:
    """Start the background NetBox refresh thread on first request in each worker."""

    def __init__(self, get_response):
        self.get_response = get_response
        services.start_background_refresh()

    def __call__(self, request):
        return self.get_response(request)
