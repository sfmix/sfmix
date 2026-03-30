# -------------------------------------------------------------------
# Import blocks — map existing Authentik resources to Terraform state
#
# These allow `terraform plan` to work without a pre-existing .tfstate.
# Each operator starts fresh: init → plan → apply.
# -------------------------------------------------------------------

# --- Groups ---

import {
  to = authentik_group.ix_administrators
  id = "251bfffb-5a05-466c-b1d9-5fd394154d38"
}

import {
  to = authentik_group.authentik_admins
  id = "bb9786e1-707e-4c2e-adc0-bea0f42af51b"
}

# --- Property mappings (source) ---

import {
  to = authentik_property_mapping_source_oauth.github_user
  id = "005bc14a-e7a0-4d67-9b9e-2b75b03222c3"
}

import {
  to = authentik_property_mapping_source_oauth.github_group
  id = "0fc222ce-ef66-41e6-b574-0c23359a0ac2"
}

import {
  to = authentik_property_mapping_source_oauth.peeringdb_user
  id = "aab52190-3feb-4752-9bc9-cadd9662c8dd"
}

import {
  to = authentik_property_mapping_source_oauth.peeringdb_group
  id = "6e4d2887-e84b-4938-9484-032c126bf649"
}

# --- Property mappings (provider scope) ---

import {
  to = authentik_property_mapping_provider_scope.groups
  id = "c174b1b6-91d2-4bb0-a6c9-7c8ed4d73ae1"
}

# --- Sources ---

import {
  to = authentik_source_oauth.github
  id = "github"
}

import {
  to = authentik_source_oauth.peeringdb
  id = "peeringdb"
}

# --- Providers ---

import {
  to = authentik_provider_oauth2.grafana
  id = "1"
}

import {
  to = authentik_provider_oauth2.portal
  id = "2"
}

# --- Applications ---

import {
  to = authentik_application.grafana
  id = "grafana"
}

import {
  to = authentik_application.portal
  id = "portal"
}

# --- Policies ---

import {
  to = authentik_policy_expression.grafana_require_admin_group
  id = "59f6e34e-8e70-48b6-8a0e-5f816b53256e"
}

import {
  to = authentik_policy_binding.grafana_require_admin_group
  id = "f34bca09-ba43-4dce-b0fd-416eaec7896d"
}

# --- Brand ---

import {
  to = authentik_brand.sfmix
  id = "e290f11e-2416-470e-9dd1-47807837fecf"
}

# --- Custom authentication flow ---

import {
  to = authentik_flow.sfmix_authentication
  id = "sfmix-authentication"
}

import {
  to = authentik_stage_identification.sfmix_source_select
  id = "c2a63956-6547-4cb3-a9c7-fee9755fe002"
}

import {
  to = authentik_flow_stage_binding.sfmix_auth_source_select
  id = "9f984a3b-7f97-42d7-91d7-d7b51fa250a0"
}
