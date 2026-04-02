# -------------------------------------------------------------------
# Brand — SFMIX styling for login.sfmix.org
#
# NOTE: branding_custom_css requires authentik >= 2025.4 and a
# matching provider version. If running an older version, remove the
# branding_custom_css block and mount the CSS at
# /web/dist/custom.css in the authentik server container instead.
# -------------------------------------------------------------------

resource "authentik_brand" "sfmix" {
  domain           = "login.sfmix.org"
  default          = true
  branding_title   = "SFMIX"
  branding_logo    = "https://sfmix.org/wp-content/uploads/2022/10/SFMIX-logo.png"
  branding_favicon = "https://sfmix.org/wp-content/uploads/2022/10/SFMIX-logo.png"

  flow_authentication = authentik_flow.sfmix_authentication.uuid
  flow_invalidation   = data.authentik_flow.default_invalidation.id
  flow_device_code    = authentik_flow.device_code.uuid

  branding_custom_css = <<-CSS
    /*
     * SFMIX Brand — login.sfmix.org
     * Colors from documentation/sfmix-brand-style-guide.md
     *
     * CSS custom properties cascade through shadow DOM boundaries,
     * so overriding PatternFly / authentik variables here themes
     * the entire login UI.
     */

    :root {
      /* SFMIX primary palette */
      --ak-accent: #1a3a5c;
      --pf-global--primary-color--100: #1a3a5c;
      --pf-global--primary-color--200: #2a5a8c;
      --pf-global--active-color--100: #1a3a5c;
      --pf-global--link--Color: #2a5a8c;
      --pf-global--link--Color--hover: #e8913a;
      --pf-global--link--Color--dark: #89b4f8;
      --pf-global--link--Color--dark--hover: #e8913a;

      /* SFMIX system font stack */
      --pf-global--FontFamily--sans-serif:
        -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        "Helvetica Neue", Arial, sans-serif;
    }

    /* Dark gradient background matching SFMIX hero style */
    body {
      background: linear-gradient(135deg, #0d2137 0%, #1a3a5c 100%) !important;
      min-height: 100vh;
    }

    /* Hide the locale selector — single-language deployment */
    ak-flow-executor::part(locale-select) {
      display: none;
    }
  CSS
}
