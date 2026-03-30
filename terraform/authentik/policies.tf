# -------------------------------------------------------------------
# Custom expression policies and bindings
# -------------------------------------------------------------------

resource "authentik_policy_expression" "grafana_require_admin_group" {
  name       = "Grafana: Require Admin Group"
  expression = "return ak_is_group_member(request.user, name=\"IX Administrators\")"
}

resource "authentik_policy_binding" "grafana_require_admin_group" {
  target = authentik_application.grafana.uuid
  policy = authentik_policy_expression.grafana_require_admin_group.id
  order  = 0
}
