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

# Every embedded-outpost app is admin-only, without exception.
resource "authentik_policy_binding" "proxied_require_admin_group" {
  for_each = var.proxied_apps

  target = authentik_application.proxied[each.key].uuid
  policy = authentik_policy_expression.require_admin_group.id
  order  = 0
}
