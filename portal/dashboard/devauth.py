"""DEBUG-only dev login bypass + optional auto-login.

Lets you work on the pages locally without the real Authentik OIDC flow. It logs
in a throwaway Django user and seeds the session with the same keys the real
OIDC backend writes (see ``SFMIXOIDCBackend._write_session``), so the
``@login_required`` and admin/ASN gating in the views behave identically.

Two entry points, both DEBUG-gated (``settings.DEV_LOGIN_ENABLED``):
  * ``/dev/login/`` — interactive persona picker (this module's view).
  * ``DevAutologinMiddleware`` — when ``DEV_AUTOLOGIN`` is set, seeds a persona
    on every request so ``runserver`` comes up already logged in, like prod.
"""

import os
import time

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.core.exceptions import MiddlewareNotUsed
from django.http import Http404, HttpResponse
from django.shortcuts import redirect

from .backends import extract_asns

# Placeholder ASNs (RFC 5398 documentation range) used by the personas; they
# match the synthetic fixtures so the network detail / mac-table pages populate.
DEV_OWN_ASN = 64496
DEV_SECOND_ASN = 64497

_PERSONAS = {
    "admin": {
        "label": "IX admin only (no networks)",
        "groups": ["IX Administrators"],
    },
    "admin_member": {
        "label": f"IX admin + network admin for AS{DEV_OWN_ASN} & AS{DEV_SECOND_ASN}",
        "groups": ["IX Administrators", f"as{DEV_OWN_ASN}", f"as{DEV_SECOND_ASN}"],
    },
    "member": {
        "label": f"AS{DEV_OWN_ASN} member (no admin)",
        "groups": [f"as{DEV_OWN_ASN}"],
    },
    "public": {
        "label": "no networks (plain logged-in user)",
        "groups": [],
    },
}


def groups_for_spec(spec):
    """Resolve a persona key or a comma-spec to a list of OIDC group names.

    Accepts a persona key ("admin", "admin_member", …) or a free-form spec like
    "admin,64496,64497" where "admin" → "IX Administrators", a number N → "asN",
    and anything else is treated as a raw group name.
    """
    spec = (spec or "").strip()
    if spec in _PERSONAS:
        return list(_PERSONAS[spec]["groups"])
    groups = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if tok.lower() in ("admin", "ix_admin", "ixadmin"):
            groups.append("IX Administrators")
        elif tok.isdigit():
            groups.append(f"as{tok}")
        else:
            groups.append(tok)
    return groups


def seed_session(request, groups):
    """Log in the dev user and write OIDC-equivalent session keys."""
    User = get_user_model()
    user, _ = User.objects.get_or_create(
        username="dev@sfmix.local",
        defaults={"email": "dev@sfmix.local", "first_name": "Dev", "last_name": "User"},
    )
    # ModelBackend is added to AUTHENTICATION_BACKENDS in dev (settings.py).
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")

    # Mirror SFMIXOIDCBackend._write_session so view gating works unchanged.
    request.session["oidc_groups"] = groups
    request.session["oidc_asns"] = extract_asns(groups)
    request.session["oidc_is_ix_admin"] = "IX Administrators" in groups
    request.session["oidc_id_token"] = "devmock-dummy-id-token"
    # Keep mozilla-django-oidc's SessionRefresh from bouncing the dev session
    # back into the real OIDC flow.
    request.session["oidc_id_token_expiration"] = time.time() + 30 * 86400


def _ensure_enabled():
    if not getattr(settings, "DEV_LOGIN_ENABLED", False):
        raise Http404("dev login is disabled")


def dev_login(request):
    """Log in as a chosen persona, seeding OIDC-equivalent session keys.

    Query params:
      ?as=admin|admin_member|member|public   pick a predefined persona, or
      ?admin=1&asns=64496,64497               build a custom one.
    With no params, render a small landing page of quick-login links.
    """
    _ensure_enabled()

    has_params = any(k in request.GET for k in ("as", "admin", "asns"))
    if not has_params:
        return _landing_page()

    persona = request.GET.get("as")
    if persona in _PERSONAS:
        groups = list(_PERSONAS[persona]["groups"])
    else:
        groups = []
        if request.GET.get("admin", "").lower() in ("1", "true", "yes"):
            groups.append("IX Administrators")
        raw_asns = request.GET.get("asns", "")
        groups += [f"as{a.strip()}" for a in raw_asns.split(",") if a.strip()]

    seed_session(request, groups)
    return redirect("/")


def _landing_page():
    links = "".join(
        f'<li style="margin:.4rem 0"><a href="?as={key}">{p["label"]}</a></li>'
        for key, p in _PERSONAS.items()
    )
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Dev login</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem}}
a{{color:#1a6070}} code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px}}</style></head>
<body>
<h1>Dev login</h1>
<p><strong>DEBUG-only.</strong> Pick a persona to seed your session:</p>
<ul>{links}</ul>
<p style="color:#888">Custom: <code>?admin=1&amp;asns=64496,64497</code><br>
Auto-login on startup: <code>DEV_AUTOLOGIN=admin_member python manage.py runserver</code></p>
</body></html>"""
    return HttpResponse(html)


class DevAutologinMiddleware:
    """Seed a dev persona on every anonymous request (DEBUG-only).

    Enabled by setting ``DEV_AUTOLOGIN`` (a persona key or comma-spec). Makes the
    dev server come up already logged in, mirroring the prod SSO experience. The
    middleware is only added to ``MIDDLEWARE`` when the env var is set
    (settings.py), and refuses to load unless DEBUG + DEV_LOGIN_ENABLED.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.spec = os.environ.get("DEV_AUTOLOGIN", "").strip()
        if not (settings.DEBUG and getattr(settings, "DEV_LOGIN_ENABLED", False) and self.spec):
            raise MiddlewareNotUsed
        self.groups = groups_for_spec(self.spec)

    def __call__(self, request):
        if not request.user.is_authenticated:
            seed_session(request, self.groups)
        return self.get_response(request)
