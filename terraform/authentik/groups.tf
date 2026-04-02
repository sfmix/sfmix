# -------------------------------------------------------------------
# Groups
# -------------------------------------------------------------------

resource "authentik_group" "ix_administrators" {
  name         = var.admin_group_name
  is_superuser = false
}

resource "authentik_group" "authentik_admins" {
  name         = "authentik Admins"
  is_superuser = true
}

# ASN-based groups (e.g. as12276, as40271) are created dynamically by
# PeeringDB source enrollment and are NOT managed by Terraform.
