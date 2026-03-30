# -------------------------------------------------------------------
# Applications
# -------------------------------------------------------------------

resource "authentik_application" "grafana" {
  name              = "Grafana"
  slug              = "grafana"
  protocol_provider = authentik_provider_oauth2.grafana.id
  open_in_new_tab   = false
  meta_launch_url   = "https://grafana.sfmix.org"
  policy_engine_mode = "any"
}

resource "authentik_application" "portal" {
  name              = "IXP Participant Portal"
  slug              = "portal"
  protocol_provider = authentik_provider_oauth2.portal.id
  open_in_new_tab   = false
  meta_launch_url   = "https://portal.sfmix.org"
  policy_engine_mode = "any"
}
