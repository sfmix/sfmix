# -------------------------------------------------------------------
# Applications
# -------------------------------------------------------------------

resource "authentik_application" "grafana" {
  name               = "Grafana"
  slug               = "grafana"
  protocol_provider  = authentik_provider_oauth2.grafana.id
  open_in_new_tab    = false
  meta_launch_url    = "https://grafana.sfmix.org"
  policy_engine_mode = "any"
}

resource "authentik_application" "looking_glass" {
  name               = "Looking Glass"
  slug               = "looking-glass"
  protocol_provider  = authentik_provider_oauth2.looking_glass.id
  open_in_new_tab    = false
  policy_engine_mode = "any"
}

resource "authentik_application" "looking_glass_api" {
  name               = "Looking Glass API"
  slug               = "looking-glass-api"
  protocol_provider  = authentik_provider_oauth2.looking_glass_api.id
  open_in_new_tab    = false
  meta_launch_url    = "https://lg-ng.sfmix.org"
  policy_engine_mode = "any"
}

resource "authentik_application" "portal" {
  name               = "IXP Participant Portal"
  slug               = "portal"
  protocol_provider  = authentik_provider_oauth2.portal.id
  open_in_new_tab    = false
  meta_launch_url    = "https://portal.sfmix.org"
  policy_engine_mode = "any"
}

# Admin-only tools behind the embedded outpost (see var.proxied_apps).
resource "authentik_application" "proxied" {
  for_each = var.proxied_apps

  name               = each.value.name
  slug               = each.key
  protocol_provider  = authentik_provider_proxy.proxied[each.key].id
  open_in_new_tab    = false
  meta_launch_url    = authentik_provider_proxy.proxied[each.key].external_host
  policy_engine_mode = "any"
}
