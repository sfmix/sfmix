import re

from mozilla_django_oidc.auth import OIDCAuthenticationBackend


_ASN_RE = re.compile(r"^as(\d+)$", re.IGNORECASE)


def extract_asns(groups):
    return sorted({int(m.group(1)) for g in groups if (m := _ASN_RE.match(g))})


class SFMIXOIDCBackend(OIDCAuthenticationBackend):
    """OIDC backend that stores Authentik ASN-groups on the user profile.

    Claims-derived data (ASNs, groups, admin flag) are persisted to the
    Django session so they survive across requests without a custom user model.
    """

    def _sync_user(self, user, claims):
        user.first_name = claims.get("given_name", "")
        user.last_name = claims.get("family_name", "")
        user.email = claims.get("email", user.email)
        user.save()
        # Stash claims-derived data on request.session (set in get_or_create_user)
        self._pending_claims = claims
        return user

    def _write_session(self, request, claims, id_token=None):
        groups = claims.get("groups", [])
        request.session["oidc_groups"] = groups
        request.session["oidc_asns"] = extract_asns(groups)
        request.session["oidc_is_ix_admin"] = "IX Administrators" in groups
        # Store id_token for cross-service API calls (e.g., to looking-glass)
        if id_token:
            request.session["oidc_id_token"] = id_token

    def get_token(self, payload):
        """Override to capture the raw id_token JWT string before the
        parent class decodes and discards it."""
        token_info = super().get_token(payload)
        self._raw_id_token = token_info.get("id_token")
        return token_info

    def authenticate(self, request, **kwargs):
        user = super().authenticate(request, **kwargs)
        if user and request and hasattr(self, "_pending_claims"):
            self._write_session(
                request,
                self._pending_claims,
                getattr(self, "_raw_id_token", None),
            )
            del self._pending_claims
        return user

    def create_user(self, claims):
        email = claims.get("email")
        user = self.UserModel.objects.create_user(username=email, email=email)
        return self._sync_user(user, claims)

    def update_user(self, user, claims):
        return self._sync_user(user, claims)

    def filter_users_by_claims(self, claims):
        email = claims.get("email")
        if not email:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(email=email)
