# -------------------------------------------------------------------
# Custom authentication flow — OAuth sources only (no username/password)
#
# Shows only "Sign in with GitHub" and "Sign in with PeeringDB"
# buttons. No username or password fields are presented.
# -------------------------------------------------------------------

resource "authentik_flow" "sfmix_authentication" {
  name               = "SFMIX Authentication"
  title              = "Sign in to SFMIX"
  slug               = "sfmix-authentication"
  designation        = "authentication"
  policy_engine_mode = "any"
  layout             = "stacked"
}

resource "authentik_stage_identification" "sfmix_source_select" {
  name               = "SFMIX Source Selection"
  user_fields        = []
  show_matched_user  = true
  show_source_labels = true

  sources = [
    authentik_source_oauth.github.uuid,
    authentik_source_oauth.peeringdb.uuid,
  ]
}

resource "authentik_flow_stage_binding" "sfmix_auth_source_select" {
  target = authentik_flow.sfmix_authentication.uuid
  stage  = authentik_stage_identification.sfmix_source_select.id
  order  = 10
}
