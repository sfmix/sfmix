# -------------------------------------------------------------------
# Outposts
# -------------------------------------------------------------------

# The embedded outpost runs inside the authentik server container and answers
# on the same :9000 listener that nginx on login.sfmix.org already proxies to.
# A proxy provider attached here is served by matching the request Host header
# against the provider's external_host. Exposing another internal tool needs:
#   1. a DNS name pointing at login (ansible sfmix_dns, zones/sfmix.org.j2)
#   2. an nginx vhost + cert on login (ansible role authentik,
#      `authentik_proxied_hosts`)
#   3. a provider + application + policy binding here, listed below.
resource "authentik_outpost" "embedded" {
  name = "authentik Embedded Outpost"
  type = "proxy"

  protocol_providers = [
    authentik_provider_proxy.alertmanager.id,
  ]

  # `config` is deliberately left computed: authentik fills the embedded
  # outpost's config (authentik_host = https://login.sfmix.org plus ~20
  # defaults) itself, and declaring only the keys we care about would strip
  # the rest on every apply.
}
