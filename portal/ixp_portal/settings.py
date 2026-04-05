import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ── Cache backend (swap to RedisCache / MemcachedCache via env) ──
_cache_dir = os.environ.get("CACHE_DIR", str(BASE_DIR / "cache" / "django_cache"))
os.makedirs(_cache_dir, exist_ok=True)

CACHES = {
    "default": {
        "BACKEND": os.environ.get(
            "CACHE_BACKEND",
            "django.core.cache.backends.filebased.FileBasedCache",
        ),
        "LOCATION": _cache_dir,
    }
}

# NetBox cache refresh interval and cross-worker lock file
NETBOX_CACHE_TIMEOUT = int(os.environ.get("NETBOX_CACHE_TIMEOUT", str(4 * 3600)))
NETBOX_CACHE_LOCK_FILE = os.environ.get(
    "NETBOX_CACHE_LOCK_FILE",
    str(BASE_DIR / "cache" / ".netbox_refresh.lock"),
)

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "insecure-dev-key-change-me")
DEBUG = os.environ.get("DJANGO_DEBUG", "true").lower() in ("true", "1", "yes")
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "mozilla_django_oidc",
    "dashboard.apps.DashboardConfig",
]

MIDDLEWARE = [
    "dashboard.middleware.NetBoxCacheMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "mozilla_django_oidc.middleware.SessionRefresh",
]

ROOT_URLCONF = "ixp_portal.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
            ],
        },
    },
]

WSGI_APPLICATION = "ixp_portal.wsgi.application"

# Trust X-Forwarded-Proto from nginx reverse proxy
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# --- Static files ---
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# --- Auth ---
AUTHENTICATION_BACKENDS = [
    "dashboard.backends.SFMIXOIDCBackend",
]

LOGIN_URL = "/oidc/authenticate/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

# --- OIDC (Authentik at login.sfmix.org) ---
OIDC_RP_CLIENT_ID = os.environ.get("OIDC_RP_CLIENT_ID", "portal")
OIDC_RP_CLIENT_SECRET = os.environ.get("OIDC_RP_CLIENT_SECRET", "")
OIDC_RP_SIGN_ALGO = "RS256"
OIDC_RP_SCOPES = "openid profile email groups"

_OIDC_ISSUER = os.environ.get("OIDC_PROVIDER_URL", "https://login.sfmix.org/application/o/portal")
_OIDC_BASE = _OIDC_ISSUER.rsplit("/", 1)[0]  # https://login.sfmix.org/application/o
OIDC_OP_AUTHORIZATION_ENDPOINT = f"{_OIDC_BASE}/authorize/"
OIDC_OP_TOKEN_ENDPOINT = f"{_OIDC_BASE}/token/"
OIDC_OP_USER_ENDPOINT = f"{_OIDC_BASE}/userinfo/"
OIDC_OP_JWKS_ENDPOINT = f"{_OIDC_ISSUER}/jwks/"

# Re-check OIDC claims every 15 minutes
OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS = 900

# --- IXP data source (NetBox) ---
IXP_NETBOX_URL = os.environ.get("IXP_NETBOX_URL", "https://netbox.sfmix.org")
IXP_NETBOX_TOKEN = os.environ.get("IXP_NETBOX_TOKEN", "")

# --- Looking Glass REST API ---
IXP_LOOKING_GLASS_URL = os.environ.get("IXP_LOOKING_GLASS_URL", "https://lg.sfmix.org:8081")

# --- Prometheus metrics ---
# Networks allowed to scrape /metrics/.  Accepts CIDR notation.
_trusted_nets = os.environ.get("PROMETHEUS_TRUSTED_NETWORKS", "127.0.0.0/8,::1/128")
PROMETHEUS_TRUSTED_NETWORKS = [n.strip() for n in _trusted_nets.split(",") if n.strip()]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Ensure lock file parent directory exists
os.makedirs(os.path.dirname(NETBOX_CACHE_LOCK_FILE), exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "root": {"handlers": ["console"], "level": "WARNING"},
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "ERROR", "propagate": False},
        "mozilla_django_oidc": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "dashboard": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
