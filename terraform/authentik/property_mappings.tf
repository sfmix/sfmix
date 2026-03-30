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

# Fetch org teams using the OAuth token
teams_url = "https://api.github.com/user/teams"
headers = {
    "Authorization": f"Bearer {token['access_token']}",
    "Accept": "application/vnd.github+json",
}
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

groups = []
if is_ix_admin:
    groups.append("IX Administrators")

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

# Build ASN group list for GroupUpdateStage
asn_groups = []
for n in networks:
    asn = n.get("asn")
    if asn:
        asn_groups.append("as" + str(asn))

# SFMIX IX Administrator path via PeeringDB:
# Users who admin AS12276 (SFMIX) are IX Administrators
sfmix_asns = {12276}
is_ix_admin = any(
    n.get("asn") in sfmix_asns
    for n in networks
)
if is_ix_admin:
    asn_groups.append("IX Administrators")

return {
    "username": pdb_email,
    "name": pdb_name,
    "email": pdb_email,
    "groups": asn_groups,
    "attributes": {
        "peeringdb_id": pdb_sub,
        "peeringdb_name": pdb_name,
        "peeringdb_networks": [
            {"asn": n["asn"], "name": n["name"]}
            for n in networks if "asn" in n
        ],
    },
}
EOT
}

resource "authentik_property_mapping_source_oauth" "peeringdb_group" {
  name       = "PeeringDB ASN Group Mapping"
  expression = <<-EOT
networks = info.get("networks", [])
result = []
for n in networks:
    asn = n.get("asn")
    if asn:
        result.append("as" + str(asn))
return result
EOT
}

# --- Custom scope mapping for OIDC providers ---

resource "authentik_property_mapping_provider_scope" "groups" {
  name        = "SFMIX: OpenID 'groups'"
  scope_name  = "groups"
  description = "Include user group memberships"
  expression  = "return {\"groups\": [group.name for group in request.user.ak_groups.all()]}"
}
