# -------------------------------------------------------------------
# Custom expression policies and bindings
# -------------------------------------------------------------------

# One shared "must be an IX Administrator" policy, bound to every
# operator-only application. When exposing another internal tool, add a
# binding here rather than a per-app copy of the expression.
resource "authentik_policy_expression" "require_admin_group" {
  name       = "Require Admin Group"
  expression = "return ak_is_group_member(request.user, name=\"${var.admin_group_name}\")"
}

resource "authentik_policy_binding" "grafana_require_admin_group" {
  target = authentik_application.grafana.uuid
  policy = authentik_policy_expression.require_admin_group.id
  order  = 0
}

resource "authentik_policy_binding" "alertmanager_require_admin_group" {
  target = authentik_application.alertmanager.uuid
  policy = authentik_policy_expression.require_admin_group.id
  order  = 0
}
