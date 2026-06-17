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

# ── Local-dev affordances — HARD-GATED on DEBUG ──
# Both flags AND with DEBUG, so setting the env var in production (where
# DJANGO_DEBUG=false) can never enable them. See dashboard/devmock and
# dashboard/devauth. Off by default even in DEBUG, so live mode still works.
LG_USE_FIXTURES = DEBUG and os.environ.get("LG_USE_FIXTURES", "false").lower() in ("true", "1", "yes")
DEV_LOGIN_ENABLED = DEBUG and os.environ.get("DEV_LOGIN", "true").lower() in ("true", "1", "yes")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "mozilla_django_oidc",
    "dashboard.apps.DashboardConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # LocaleMiddleware must sit after SessionMiddleware (it can read the
    # language from the session) and before CommonMiddleware. It resolves the
    # active language per request from the django_language cookie → session →
    # Accept-Language header → LANGUAGE_CODE.
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "mozilla_django_oidc.middleware.SessionRefresh",
]

# DEBUG-only: auto-login a dev persona on every request so `runserver` comes up
# already authenticated (mirrors the prod SSO experience). Set e.g.
# DEV_AUTOLOGIN=admin_member. The middleware self-disables unless DEBUG +
# DEV_LOGIN_ENABLED, but we only even add it when the env var is present.
if DEV_LOGIN_ENABLED and os.environ.get("DEV_AUTOLOGIN", "").strip():
    MIDDLEWARE.append("dashboard.devauth.DevAutologinMiddleware")

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
                "django.template.context_processors.i18n",
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
        "NAME": BASE_DIR / "db" / "db.sqlite3",
    }
}

# --- Internationalization ---
# LTR string translation only (for now). Active language is resolved by
# LocaleMiddleware: django_language cookie (set by the in-nav picker via the
# set_language view) → session → Accept-Language header → LANGUAGE_CODE.
USE_I18N = True
LANGUAGE_CODE = "en"

# Custom/novelty locales. Django only ships LANG_INFO metadata (display name,
# text direction, plural rule) for real languages, so a made-up code would make
# get_language_info() — used by the picker — raise KeyError. Register the metadata
# here. These are English-based variants, so they use en-<variant> codes (locale
# dirs en_Pirate / en_Genz) and the standard 2-form English plural rule.
from django.conf.locale import LANG_INFO  # noqa: E402

for _code, _name in (("en-pirate", "Pirate"), ("en-genz", "Gen Z")):
    LANG_INFO[_code] = {
        "bidi": False,
        "code": _code,
        "name": _name,
        "name_local": _name,
    }

# Names are intentionally plain (not gettext-wrapped) native names: the picker
# always displays each language's own local name (get_language_info name_local),
# never a name translated into the active language — so "Español" stays "Español"
# even when the UI is in German. Keeping these untranslatable prevents that rule
# from being accidentally broken and keeps the names out of the .po catalogs.
LANGUAGES = [
    ("en", "English"),
    ("es", "Español"),
    ("de", "Deutsch"),
    ("en-pirate", "Pirate"),
    ("en-genz", "Gen Z"),
]
LOCALE_PATHS = [BASE_DIR / "locale"]

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

# The dev-login bypass authenticates a plain Django user, which needs a backend
# present in AUTHENTICATION_BACKENDS so get_user() can rehydrate the session on
# subsequent requests. Only added when the dev login is enabled (DEBUG-gated).
if DEV_LOGIN_ENABLED:
    AUTHENTICATION_BACKENDS.append("django.contrib.auth.backends.ModelBackend")

# Send unauthenticated users to the local login page (a safe public placeholder
# with the SSO button — and the dev-login link in DEBUG), rather than bouncing
# straight into the Authentik OIDC flow. This keeps gated pages usable in local
# dev and gives prod a normal login landing instead of an auto-redirect.
LOGIN_URL = "/login/"
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

# --- Looking Glass REST API ---
IXP_LOOKING_GLASS_URL = os.environ.get("IXP_LOOKING_GLASS_URL", "https://lg.sfmix.org:8081")

# --- Alice Looking Glass (route-server session data) ---
ALICE_LG_URL = os.environ.get("ALICE_LG_URL", "https://alice.sfmix.org")

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
        "django.security.DisallowedHost": {"handlers": [], "level": "CRITICAL", "propagate": False},
        "mozilla_django_oidc": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "dashboard": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
