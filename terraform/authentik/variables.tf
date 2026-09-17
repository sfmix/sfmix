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

# Internal tools with no auth of their own, exposed through the embedded
# outpost on login.sfmix.org and restricted to the admin group. The key is
# the application slug and the public hostname's first label
# (<key>.sfmix.org); it must also appear in ansible `authentik_proxied_hosts`
# and as a CNAME to login in the sfmix_dns zone. Upstreams are on the metrics
# host, whose ufw allows login's /27.
variable "proxied_apps" {
  description = "Admin-only apps served by the embedded outpost: slug => {name, internal_host}"
  type = map(object({
    name          = string
    internal_host = string
  }))
  default = {
    alertmanager = {
      name          = "Alertmanager"
      internal_host = "http://metrics.sfo02.sfmix.org:9093"
    }
    prometheus = {
      name          = "Prometheus"
      internal_host = "http://metrics.sfo02.sfmix.org:9090"
    }
    sflow-rt = {
      name          = "sFlow-RT"
      internal_host = "http://metrics.sfo02.sfmix.org:8008"
    }
  }
}
