# -------------------------------------------------------------------
# OAuth2/OIDC Providers
# -------------------------------------------------------------------

resource "authentik_provider_oauth2" "grafana" {
  name               = "Grafana"
  client_id          = "grafana"
  client_secret      = var.grafana_client_secret
  client_type        = "confidential"
  authorization_flow = data.authentik_flow.default_implicit_consent.id
  invalidation_flow  = data.authentik_flow.default_invalidation.id
  signing_key        = data.authentik_certificate_key_pair.self_signed.id

  allowed_redirect_uris = [
    {
      matching_mode = "strict"
      url           = "https://grafana.sfmix.org/login/generic_oauth"
    },
  ]

  access_code_validity   = "minutes=1"
  access_token_validity  = "hours=1"
  refresh_token_validity = "days=30"
  sub_mode               = "hashed_user_id"
  issuer_mode            = "per_provider"
  include_claims_in_id_token = true

  property_mappings = [
    data.authentik_property_mapping_provider_scope.openid.id,
    data.authentik_property_mapping_provider_scope.email.id,
    data.authentik_property_mapping_provider_scope.profile.id,
    data.authentik_property_mapping_provider_scope.offline_access.id,
    data.authentik_property_mapping_provider_scope.entitlements.id,
    data.authentik_property_mapping_provider_scope.authentik_api.id,
    authentik_property_mapping_provider_scope.groups.id,
  ]
}

resource "authentik_provider_oauth2" "looking_glass" {
  name               = "Looking Glass"
  client_id          = "looking-glass"
  client_type        = "public"
  authorization_flow = data.authentik_flow.default_implicit_consent.id
  invalidation_flow  = data.authentik_flow.default_invalidation.id
  signing_key        = data.authentik_certificate_key_pair.self_signed.id

  access_code_validity   = "minutes=10"
  access_token_validity  = "hours=1"
  refresh_token_validity = "days=30"
  sub_mode               = "hashed_user_id"
  issuer_mode            = "per_provider"
  include_claims_in_id_token = true

  property_mappings = [
    data.authentik_property_mapping_provider_scope.openid.id,
    data.authentik_property_mapping_provider_scope.email.id,
    data.authentik_property_mapping_provider_scope.profile.id,
    authentik_property_mapping_provider_scope.groups.id,
  ]
}

resource "authentik_provider_oauth2" "portal" {
  name               = "portal"
  client_id          = "portal"
  client_secret      = var.portal_client_secret
  client_type        = "confidential"
  authorization_flow = data.authentik_flow.default_implicit_consent.id
  invalidation_flow  = data.authentik_flow.default_invalidation.id
  signing_key        = data.authentik_certificate_key_pair.self_signed.id

  allowed_redirect_uris = [
    {
      matching_mode = "strict"
      url           = "https://portal.sfmix.org/oidc/callback/"
    },
  ]

  access_code_validity   = "minutes=1"
  access_token_validity  = "hours=1"
  refresh_token_validity = "days=30"
  sub_mode               = "hashed_user_id"
  issuer_mode            = "per_provider"
  include_claims_in_id_token = true

  property_mappings = [
    data.authentik_property_mapping_provider_scope.openid.id,
    data.authentik_property_mapping_provider_scope.email.id,
    data.authentik_property_mapping_provider_scope.profile.id,
    authentik_property_mapping_provider_scope.groups.id,
  ]
}
