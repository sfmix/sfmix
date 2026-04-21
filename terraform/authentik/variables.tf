# Secrets — set via environment variables (TF_VAR_*) or a .tfvars file.
# Do NOT commit secret values to version control.

variable "github_consumer_secret" {
  description = "GitHub OAuth app client secret"
  type        = string
  sensitive   = true
}

variable "peeringdb_consumer_secret" {
  description = "PeeringDB OAuth app client secret"
  type        = string
  sensitive   = true
}

variable "grafana_client_secret" {
  description = "Grafana OIDC provider client secret"
  type        = string
  sensitive   = true
}

variable "portal_client_secret" {
  description = "IXP Participant Portal OIDC provider client secret"
  type        = string
  sensitive   = true
}

variable "looking_glass_api_client_secret" {
  description = "Looking Glass HTTP API OIDC provider client secret"
  type        = string
  sensitive   = true
}

variable "admin_group_name" {
  description = "Name of the administrative group in Authentik (e.g. IX Administrators)"
  type        = string
  default     = "IX Administrators"
}
