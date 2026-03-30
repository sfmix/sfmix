# -------------------------------------------------------------------
# Data sources for managed (default) objects created by authentik
# blueprints. These are referenced by custom resources but not managed
# by Terraform.
# -------------------------------------------------------------------

# --- Default flows ---

data "authentik_flow" "default_authentication" {
  slug = "default-authentication-flow"
}

data "authentik_flow" "default_source_enrollment" {
  slug = "default-source-enrollment"
}

data "authentik_flow" "default_source_authentication" {
  slug = "default-source-authentication"
}

data "authentik_flow" "default_implicit_consent" {
  slug = "default-provider-authorization-implicit-consent"
}

data "authentik_flow" "default_invalidation" {
  slug = "default-invalidation-flow"
}

# --- Default scope mappings (for OAuth2 providers) ---

data "authentik_property_mapping_provider_scope" "openid" {
  managed = "goauthentik.io/providers/oauth2/scope-openid"
}

data "authentik_property_mapping_provider_scope" "email" {
  managed = "goauthentik.io/providers/oauth2/scope-email"
}

data "authentik_property_mapping_provider_scope" "profile" {
  managed = "goauthentik.io/providers/oauth2/scope-profile"
}

data "authentik_property_mapping_provider_scope" "offline_access" {
  managed = "goauthentik.io/providers/oauth2/scope-offline_access"
}

data "authentik_property_mapping_provider_scope" "entitlements" {
  managed = "goauthentik.io/providers/oauth2/scope-entitlements"
}

data "authentik_property_mapping_provider_scope" "authentik_api" {
  managed = "goauthentik.io/providers/oauth2/scope-authentik_api"
}

# --- Certificate ---

data "authentik_certificate_key_pair" "self_signed" {
  name = "authentik Self-signed Certificate"
}
