# -------------------------------------------------------------------
# OAuth Sources — federated login via GitHub and PeeringDB
# -------------------------------------------------------------------

resource "authentik_source_oauth" "github" {
  name                = "GitHub"
  slug                = "github"
  enabled             = true
  provider_type       = "github"
  consumer_key        = "Ov23liaNukEQ6zEzsem9"
  consumer_secret     = var.github_consumer_secret
  additional_scopes   = "read:org"
  user_matching_mode  = "email_link"
  group_matching_mode = "name_link"
  pkce                = "S256"

  authentication_flow = data.authentik_flow.default_source_authentication.id
  enrollment_flow     = data.authentik_flow.default_source_enrollment.id
  user_path_template  = "users"

  property_mappings       = [authentik_property_mapping_source_oauth.github_user.id]
  property_mappings_group = [authentik_property_mapping_source_oauth.github_group.id]
}

resource "authentik_source_oauth" "peeringdb" {
  name                = "PeeringDB"
  slug                = "peeringdb"
  enabled             = true
  provider_type       = "openidconnect"
  consumer_key        = "1yl8JKUEMKL6JQ8sYRwiVUzi4CsjoBUUCzXei84K"
  consumer_secret     = var.peeringdb_consumer_secret
  additional_scopes   = "networks"
  user_matching_mode  = "email_link"
  group_matching_mode = "name_link" # Was "identifier" — caused IntegrityError on "IX Administrators"
  pkce                = "S256"

  # PeeringDB's client_secret_basic (HTTP Basic) returns 401 with argon2-hashed
  # secrets. Must use client_secret_post (POST body) instead.
  authorization_code_auth_method = "post_body"

  authentication_flow = data.authentik_flow.default_source_authentication.id
  enrollment_flow     = data.authentik_flow.default_source_enrollment.id
  user_path_template  = "users"

  oidc_well_known_url = "https://auth.peeringdb.com/.well-known/openid-configuration"
  oidc_jwks_url       = "https://auth.peeringdb.com/oauth2/.well-known/jwks.json"

  property_mappings       = [authentik_property_mapping_source_oauth.peeringdb_user.id]
  property_mappings_group = [authentik_property_mapping_source_oauth.peeringdb_group.id]
}
