# -------------------------------------------------------------------
# Custom property mappings — source (OAuth) and provider (scope)
# -------------------------------------------------------------------

# --- GitHub source mappings ---

resource "authentik_property_mapping_source_oauth" "github_user" {
  name       = "GitHub Admin User Mapping"
  expression = <<-EOT
import requests

gh_login = info.get("login", "")
gh_email = info.get("email", "")
gh_name = info.get("name", "") or gh_login

headers = {
    "Authorization": f"Bearer {token['access_token']}",
    "Accept": "application/vnd.github+json",
}

# GitHub omits email from profile if the user has it set to private.
# Fetch from /user/emails API to get the primary verified address.
if not gh_email:
    try:
        emails_resp = requests.get("https://api.github.com/user/emails", headers=headers, timeout=10)
        emails_resp.raise_for_status()
        for entry in emails_resp.json():
            if entry.get("primary") and entry.get("verified"):
                gh_email = entry["email"]
                break
    except Exception:
        pass

# Fetch org teams using the OAuth token
teams_url = "https://api.github.com/user/teams"
try:
    resp = requests.get(teams_url, headers=headers, timeout=10)
    resp.raise_for_status()
    teams = resp.json()
except Exception:
    teams = []

# Check for sfmix/ix-administrators team membership
is_ix_admin = any(
    t.get("slug") == "ix-administrators"
    and t.get("organization", {}).get("login", "").lower() == "sfmix"
    for t in teams
)

# Preserve manually-assigned groups not managed by OAuth sources
try:
    from authentik.core.models import User
    existing = User.objects.filter(email=gh_email, is_active=True).first()
    groups = [g.name for g in existing.groups.all() if g.name in {"authentik Admins"}] if existing else []
except Exception:
    groups = []

if is_ix_admin and "${var.admin_group_name}" not in groups:
    groups.append("${var.admin_group_name}")

return {
    "username": gh_email,
    "email": gh_email,
    "name": gh_name,
    "groups": groups,
    "attributes": {
        "github_login": gh_login,
        "github_teams": [
            {"org": t["organization"]["login"], "slug": t["slug"]}
            for t in teams
        ],
        "sfmix_ix_admin": is_ix_admin,
    },
}
EOT
}

resource "authentik_property_mapping_source_oauth" "github_group" {
  name       = "GitHub Group Mapping"
  expression = "return {\"name\": group_id}"
}

# --- PeeringDB source mappings ---

resource "authentik_property_mapping_source_oauth" "peeringdb_user" {
  name       = "PeeringDB User Mapping"
  expression = <<-EOT
pdb_name = info.get("name", "")
pdb_email = info.get("email", "")
pdb_sub = info.get("sub", str(info.get("id", "")))
networks = info.get("networks", [])

# PeeringDB may nest networks under a "data" key depending on scope version
if isinstance(networks, dict):
    networks = networks.get("data", [])
if not isinstance(networks, list):
    networks = []

# Build ASN group list for GroupUpdateStage
asn_groups = []
for n in networks:
    if not isinstance(n, dict):
        continue
    asn = n.get("asn")
    if asn:
        asn_groups.append("as" + str(asn))

# SFMIX IX Administrator path via PeeringDB:
# Users who admin AS12276 (SFMIX) get the admin group
sfmix_asns = {12276}
is_ix_admin = any(
    isinstance(n, dict) and n.get("asn") in sfmix_asns
    for n in networks
)
# Preserve manually-assigned groups not managed by OAuth sources
try:
    from authentik.core.models import User
    existing = User.objects.filter(email=pdb_email, is_active=True).first()
    preserved = [g.name for g in existing.groups.all() if g.name in {"authentik Admins"}] if existing else []
    asn_groups = preserved + asn_groups
except Exception:
    pass

if is_ix_admin and "${var.admin_group_name}" not in asn_groups:
    asn_groups.append("${var.admin_group_name}")

return {
    "username": pdb_email,
    "name": pdb_name,
    "email": pdb_email,
    "groups": asn_groups,
    "attributes": {
        "peeringdb_id": pdb_sub,
        "peeringdb_name": pdb_name,
        "peeringdb_networks": [
            {"asn": n.get("asn"), "name": n.get("name", "")}
            for n in networks if isinstance(n, dict) and n.get("asn")
        ],
    },
}
EOT
}

resource "authentik_property_mapping_source_oauth" "peeringdb_group" {
  name       = "PeeringDB ASN Group Mapping"
  expression = "return {\"name\": group_id}"
}

# --- Custom scope mapping for OIDC providers ---

resource "authentik_property_mapping_provider_scope" "groups" {
  name        = "SFMIX: OpenID 'groups'"
  scope_name  = "groups"
  description = "Include ASN groups and ${var.admin_group_name}"
  expression  = <<-EOT
import re
groups = [g.name for g in request.user.ak_groups.all()]
# Filter to asNNNN pattern or admin group
return {"groups": [g for g in groups if re.match(r'^as\d+$', g, re.I) or g == "${var.admin_group_name}"]}
EOT
}
