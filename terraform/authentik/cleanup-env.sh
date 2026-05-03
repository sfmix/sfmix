#!/usr/bin/env bash
# -------------------------------------------------------------------
# Cleanup ephemeral Terraform tokens from Authentik.
# Deletes all expired tokens and optionally the current session token.
#
# Usage:
#   ./cleanup-env.sh           # Delete expired tokens only
#   ./cleanup-env.sh --all     # Also delete current session token
# -------------------------------------------------------------------

set -euo pipefail

AUTHENTIK_HOST="login.sfmix.org"
AUTHENTIK_CONTAINER="authentik-server-1"
DELETE_ALL="${1:-}"

echo "==> Cleaning up expired Terraform tokens on ${AUTHENTIK_HOST}..."

DELETED=$(ssh "${AUTHENTIK_HOST}" \
  "docker exec ${AUTHENTIK_CONTAINER} ak shell -c \"
from authentik.core.models import Token, TokenIntents
from django.utils import timezone
expired = Token.objects.filter(
    identifier__startswith='terraform-',
    intent=TokenIntents.INTENT_API,
    expiring=True,
    expires__lt=timezone.now(),
)
count = expired.count()
expired.delete()
print(count)
\"" 2>/dev/null | tail -1)

echo "    Deleted ${DELETED} expired token(s)."

if [[ "${DELETE_ALL}" == "--all" ]]; then
  echo "==> Deleting all Terraform tokens (including unexpired)..."
  DELETED_ALL=$(ssh "${AUTHENTIK_HOST}" \
    "docker exec ${AUTHENTIK_CONTAINER} ak shell -c \"
from authentik.core.models import Token, TokenIntents
tokens = Token.objects.filter(
    identifier__startswith='terraform-',
    intent=TokenIntents.INTENT_API,
)
count = tokens.count()
tokens.delete()
print(count)
\"" 2>/dev/null | tail -1)
  echo "    Deleted ${DELETED_ALL} token(s) total."
fi

echo "==> Done."
