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
      # Set redirect_uri_type explicitly: the 2026.5 server reports it as
      # "authorization", so omitting it produces perpetual "-> null" plan drift.
      matching_mode     = "strict"
      url               = "https://grafana.sfmix.org/login/generic_oauth"
      redirect_uri_type = "authorization"
    },
  ]

  access_code_validity       = "minutes=1"
  access_token_validity      = "hours=1"
  refresh_token_validity     = "days=30"
  sub_mode                   = "hashed_user_id"
  issuer_mode                = "per_provider"
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

  allowed_redirect_uris = [
    {
      matching_mode     = "regex"
      url               = "http://127\\.0\\.0\\.1:\\d+/auth/callback"
      redirect_uri_type = "authorization"
    },
    {
      matching_mode     = "regex"
      url               = "http://localhost:\\d+/callback"
      redirect_uri_type = "authorization"
    },
  ]

  access_code_validity       = "minutes=10"
  access_token_validity      = "hours=1"
  refresh_token_validity     = "days=30"
  sub_mode                   = "hashed_user_id"
  issuer_mode                = "per_provider"
  include_claims_in_id_token = true

  property_mappings = [
    data.authentik_property_mapping_provider_scope.openid.id,
    data.authentik_property_mapping_provider_scope.email.id,
    data.authentik_property_mapping_provider_scope.profile.id,
    authentik_property_mapping_provider_scope.groups.id,
  ]
}

resource "authentik_provider_oauth2" "looking_glass_api" {
  name               = "Looking Glass API"
  client_id          = "looking-glass-api"
  client_secret      = var.looking_glass_api_client_secret
  client_type        = "confidential"
  authorization_flow = data.authentik_flow.default_implicit_consent.id
  invalidation_flow  = data.authentik_flow.default_invalidation.id
  signing_key        = data.authentik_certificate_key_pair.self_signed.id

  allowed_redirect_uris = [
    {
      matching_mode     = "regex"
      url               = "https://lg-ng\\.sfmix\\.org/.*"
      redirect_uri_type = "authorization"
    },
  ]

  access_code_validity       = "minutes=5"
  access_token_validity      = "hours=1"
  refresh_token_validity     = "days=30"
  sub_mode                   = "hashed_user_id"
  issuer_mode                = "per_provider"
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

  # Order matters: the authentik provider models allowed_redirect_uris as an
  # ordered list and the server returns them logout-first, so we list the logout
  # URI first here to match. Listing it second produced perpetual plan drift that
  # swapped the two entries on every apply without ever converging.
  allowed_redirect_uris = [
    {
      # RP-initiated logout: the portal sends post_logout_redirect_uri=<the page
      # the user signed out from> so Authentik returns the browser there after
      # ending the SSO session. Regex (not strict) so any portal page validates,
      # not just the home. Anchored to the portal origin via fullmatch, so it
      # can't be abused to redirect off-site. Must be redirect_uri_type=logout —
      # Authentik's end_session only honors post_logout_redirect_uri against
      # LOGOUT-typed URIs. Requires provider >= 2026.x for redirect_uri_type.
      matching_mode     = "regex"
      url               = "https://portal\\.sfmix\\.org/.*"
      redirect_uri_type = "logout"
    },
    {
      # Explicit redirect_uri_type avoids the same "-> null" drift as the others.
      matching_mode     = "strict"
      url               = "https://portal.sfmix.org/oidc/callback/"
      redirect_uri_type = "authorization"
    },
  ]

  access_code_validity       = "minutes=1"
  access_token_validity      = "hours=1"
  refresh_token_validity     = "days=30"
  sub_mode                   = "hashed_user_id"
  issuer_mode                = "per_provider"
  include_claims_in_id_token = true

  property_mappings = [
    data.authentik_property_mapping_provider_scope.openid.id,
    data.authentik_property_mapping_provider_scope.email.id,
    data.authentik_property_mapping_provider_scope.profile.id,
    authentik_property_mapping_provider_scope.groups.id,
  ]
}
