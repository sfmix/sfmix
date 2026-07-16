terraform {
  required_version = ">= 1.5"

  required_providers {
    authentik = {
      source  = "goauthentik/authentik"
      version = "~> 2026.5"
    }
  }
}

# Configured via environment variables:
#   AUTHENTIK_URL   = "https://login.sfmix.org/"
#   AUTHENTIK_TOKEN = "<api-token>"
provider "authentik" {}
