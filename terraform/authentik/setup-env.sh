#!/usr/bin/env bash
# -------------------------------------------------------------------
# Source this script to set up ephemeral Terraform credentials for
# the Authentik workspace. Creates a short-lived API token and
# fetches the OAuth client secrets from the running instance.
#
# Usage:
#   source setup-env.sh [authentik-username]
#
# The argument is your *Authentik* username, which is NOT necessarily
# your local login name — SSO accounts (PeeringDB/GitHub) get their own
# usernames. It defaults to $(whoami) only as a convenience; pass it
# explicitly if that differs. You must have SSH access to
# login.sfmix.org and IX Administrator privileges in Authentik.
# -------------------------------------------------------------------

set -euo pipefail

AUTHENTIK_HOST="login.sfmix.org"
AUTHENTIK_CONTAINER="authentik-server-1"
AK_USER="${1:-$(whoami)}"
TOKEN_ID="terraform-$(date +%s)"

echo "==> Creating ephemeral API token for user '${AK_USER}' on ${AUTHENTIK_HOST}..."
# Capture stderr so a remote failure (e.g. unknown user) can be reported
# instead of silently aborting. The `|| true` keeps `set -e` from killing the
# script on a failed command-substitution *before* the guard below can run.
_ak_err=$(mktemp)
AUTHENTIK_TOKEN=$(ssh "${AUTHENTIK_HOST}" \
  "docker exec ${AUTHENTIK_CONTAINER} ak shell -c \"
from authentik.core.models import Token, TokenIntents, User
from django.utils import timezone
from datetime import timedelta
u = User.objects.get(username='${AK_USER}')
t = Token.objects.create(
    identifier='${TOKEN_ID}',
    user=u,
    intent=TokenIntents.INTENT_API,
    expiring=True,
    expires=timezone.now() + timedelta(hours=1),
    description='Ephemeral Terraform token',
)
print(t.key)
\"" 2>"${_ak_err}" | tail -1) || true

if [[ -z "${AUTHENTIK_TOKEN}" ]]; then
  echo "ERROR: Failed to create API token for Authentik user '${AK_USER}'." >&2
  if grep -q "User matching query does not exist" "${_ak_err}"; then
    echo "       No Authentik user named '${AK_USER}'. Your local login is not" >&2
    echo "       necessarily your Authentik username (SSO accounts differ)." >&2
    echo "       Pass it explicitly:  source setup-env.sh <authentik-username>" >&2
  else
    echo "       Remote error (last lines):" >&2
    grep -vE '"logger": "authentik' "${_ak_err}" | tail -5 | sed 's/^/         /' >&2
  fi
  rm -f "${_ak_err}"
  return 1 2>/dev/null || exit 1
fi
rm -f "${_ak_err}"

echo "==> Fetching OAuth client secrets..."
TF_VAR_github_consumer_secret=$(ssh "${AUTHENTIK_HOST}" \
  "docker exec ${AUTHENTIK_CONTAINER} ak shell -c \
    \"from authentik.sources.oauth.models import OAuthSource; print(OAuthSource.objects.get(slug='github').consumer_secret)\"" 2>/dev/null | tail -1)

TF_VAR_peeringdb_consumer_secret=$(ssh "${AUTHENTIK_HOST}" \
  "docker exec ${AUTHENTIK_CONTAINER} ak shell -c \
    \"from authentik.sources.oauth.models import OAuthSource; print(OAuthSource.objects.get(slug='peeringdb').consumer_secret)\"" 2>/dev/null | tail -1)

TF_VAR_grafana_client_secret=$(ssh "${AUTHENTIK_HOST}" \
  "docker exec ${AUTHENTIK_CONTAINER} ak shell -c \
    \"from authentik.providers.oauth2.models import OAuth2Provider; print(OAuth2Provider.objects.get(name='Grafana').client_secret)\"" 2>/dev/null | tail -1)

TF_VAR_portal_client_secret=$(ssh "${AUTHENTIK_HOST}" \
  "docker exec ${AUTHENTIK_CONTAINER} ak shell -c \
    \"from authentik.providers.oauth2.models import OAuth2Provider; print(OAuth2Provider.objects.get(name='portal').client_secret)\"" 2>/dev/null | tail -1)

TF_VAR_looking_glass_api_client_secret=$(ssh "${AUTHENTIK_HOST}" \
  "docker exec ${AUTHENTIK_CONTAINER} ak shell -c \
    \"from authentik.providers.oauth2.models import OAuth2Provider; print(OAuth2Provider.objects.get(name='Looking Glass API').client_secret)\"" 2>/dev/null | tail -1)

export AUTHENTIK_URL="https://${AUTHENTIK_HOST}/"
export AUTHENTIK_TOKEN
export TF_VAR_github_consumer_secret
export TF_VAR_peeringdb_consumer_secret
export TF_VAR_grafana_client_secret
export TF_VAR_portal_client_secret
export TF_VAR_looking_glass_api_client_secret

echo "==> Ready. Token: ${TOKEN_ID} (user: ${AK_USER})"
echo "    AUTHENTIK_URL=${AUTHENTIK_URL}"
echo "    Run: terraform plan"
