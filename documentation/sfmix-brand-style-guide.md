# SFMIX Brand & Style Guide

Reference for maintaining visual and verbal consistency across SFMIX web properties, tools, and generated materials.

---

## Identity

- **Full name**: San Francisco Metropolitan Internet eXchange
- **Abbreviation**: SFMIX (all caps, no periods)
- **Tagline**: *Local, sustainable, organic … bits.*
- **Domain**: sfmix.org
- **ASNs**: AS 12276 (SFMIX infrastructure), AS 63055 (route servers), AS 40271 (SFMIX Transit)
- **PeeringDB**:
  - [net/8123](https://www.peeringdb.com/net/8123) (AS 12276)
  - [net/12016](https://www.peeringdb.com/net/12016) (AS 63055)
  - [net/37534](https://www.peeringdb.com/net/37534) (AS 40271, SFMIX Transit)

When referring to the organization in running text, use "SFMIX" on first and subsequent references. The full name should appear in page titles, legal/copyright lines, and metadata.

---

## Logo

The primary logo is an origami / folded-paper wordmark spelling **SFMIX**. Each letter is a distinct color that together form a rainbow spectrum left-to-right:

| Letter | Primary Color | Approximate Hex                    |
|--------|---------------|------------------------------------|
| S      | Purple        | `#8B2FC9` / `#C084E8` (light face) |
| F      | Blue          | `#3B7DD8` / `#89B4F8` (light face) |
| M      | Green-Yellow  | `#A0C814` / `#C8E03C` (light face) |
| I      | Yellow-Orange | `#E8B000` / `#F0D040` (light face) |
| X      | Red-Orange    | `#D42020` / `#E85830` (light face) |

### Logo files

| Asset                      | Path                                      | Usage                        |
|----------------------------|-------------------------------------------|------------------------------|
| Full wordmark (large, PNG) | `website/static/img/sfmix-logo-large.png` | Hero sections, presentations |
| Favicon 32×32              | `website/static/img/favicon-32x32.png`    | Browser tab                  |
| Favicon 192×192            | `website/static/img/favicon-192x192.png`  | Android home screen          |
| Apple touch icon           | `website/static/img/apple-touch-icon.png` | iOS home screen              |

### Logo usage rules

- Always display on a dark or transparent background; the folded-paper style has no built-in background.
- Maintain clear space equal to at least the height of the "I" on all sides.
- Do not rotate, skew, recolor, or add effects (outlines, glows) to the logo.
- On dark backgrounds, apply a subtle `drop-shadow(0 2px 8px rgba(0,0,0,0.4))` for legibility if needed.

---

## Color Palette

### Primary palette (from CSS custom properties)

| Name              | Variable                | Hex       | Usage                                                         |
|-------------------|-------------------------|-----------|---------------------------------------------------------------|
| **Primary**       | `--color-primary`       | `#1a3a5c` | Header, footer, headings, table headers, page-header gradient |
| **Primary Light** | `--color-primary-light` | `#2a5a8c` | Links, interactive elements                                   |
| **Accent**        | `--color-accent`        | `#e8913a` | Hover states, emphasis borders, call-to-action highlights     |
| **Hero Dark**     | —                       | `#0d2137` | Hero background, page-header gradient end                     |

### Neutral palette

| Name               | Variable             | Hex       | Usage                                               |
|--------------------|----------------------|-----------|-----------------------------------------------------|
| **Background**     | `--color-bg`         | `#ffffff` | Page background                                     |
| **Background Alt** | `--color-bg-alt`     | `#f5f7fa` | Alternating rows, card backgrounds, subtle sections |
| **Text**           | `--color-text`       | `#333333` | Body text                                           |
| **Text Light**     | `--color-text-light` | `#666666` | Secondary text, captions, metadata                  |
| **Border**         | `--color-border`     | `#dee2e6` | Dividers, card borders, table rules                 |
| **White**          | `--color-white`      | `#ffffff` | Text on dark backgrounds                            |

### Portal accent (Tailwind)

The participant portal uses Tailwind's **indigo** scale as its primary accent:

| Token      | Tailwind Class    | Usage                   |
|------------|-------------------|-------------------------|
| Indigo 700 | `text-indigo-700` | Nav brand, admin badges |
| Indigo 600 | `text-indigo-600` | Links                   |
| Indigo 100 | `bg-indigo-100`   | Badge backgrounds       |

When building new portal UI, prefer the indigo scale for consistency. When building public-facing pages (website, landing pages), use the CSS custom property palette above.

### Logo rainbow (decorative)

The logo's rainbow spectrum (purple → blue → green → yellow → orange → red) may be used as a decorative gradient in banners, loading animations, or accent stripes. Reference implementation: the snappy speed-test landing page uses a rainbow gradient inspired by fiber-optic light.

---

## Typography

### Font stack

```css
--font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
```

System font stack — no web font dependencies. Fast, native-feeling, and consistent across platforms.

### Type scale (website)

| Element        | Size               | Weight      | Notes                               |
|----------------|--------------------|-------------|-------------------------------------|
| Hero h1        | `2.5rem` (40px)    | 300 (light) | Text shadow on dark backgrounds     |
| Page header h1 | `2rem` (32px)      | 600         | White on gradient background        |
| Content h2     | `1.5rem` (24px)    | 600         | Primary color, bottom border accent |
| Content h3     | `1.2rem` (19.2px)  | 600         | Primary color                       |
| Body text      | `1rem` (16px)      | 400         | Line-height 1.6                     |
| Small / meta   | `0.85rem` (13.6px) | 400         | Light text color                    |
| Nav links      | `0.9rem` (14.4px)  | 400         | —                                   |

### Monospace

Use the browser default `monospace` for code snippets, IP addresses, ASNs, and technical values.

---

## Layout

- **Max content width**: `1100px` (`--container-width`)
- **Container padding**: `0 1.5rem`
- **Header height**: `64px` (`--header-height`), sticky
- **Card border-radius**: `8px`
- **Card grid**: `repeat(auto-fill, minmax(300px, 1fr))`, `1.5rem` gap
- **Mobile breakpoint**: `768px`

---

## Imagery & Media

### Hero

- **Desktop**: Looping background video (`video/hero-bg.mp4`), dark overlay at `rgba(0,0,0,0.45)`
- **Mobile**: Static image fallback (Sutro Tower by Marc Liyanage, CC BY-SA 2.0)
- Inner pages use gradient or video page headers with the same overlay treatment

### Photography style

- San Francisco landmarks and skyline (Golden Gate Bridge, Sutro Tower, Bay Bridge at night)
- Data center / fiber optic imagery (fiber cables, network racks, fiber light)
- Tone: professional but approachable; not overly corporate

### Social sharing image

`sfmix-fiber-spray.png` — used for OpenGraph / Twitter Card metadata on ancillary services.

---

## Voice & Tone

- **Professional but approachable** — SFMIX is community-operated, not a large corporation.
- **Technical audience** — Assume readers understand networking concepts (BGP, peering, ASN). No need to over-explain.
- **Concise** — Prefer short, direct sentences. Avoid marketing fluff.
- **Tagline spirit** — "Local, sustainable, organic … bits." reflects a sense of humor and locality. Maintain that personality where appropriate, especially on landing pages and About content.

---

## Component Patterns

### Buttons & Links

- Links: `color: var(--color-primary-light)`; on hover → `color: var(--color-accent)` with underline.
- No explicit button component on the public site; portal uses Tailwind utility classes.

### Tables

- Header row: `background: var(--color-primary)`, white text, `font-weight: 600`
- Rows: hover highlights with `var(--color-bg-alt)`
- Border: bottom only, `1px solid var(--color-border)`

### Cards

- White background, `1px solid var(--color-border)`, `border-radius: 8px`, `padding: 1.5rem`
- Hover: `box-shadow: 0 4px 12px rgba(0,0,0,0.08)`

### Participant table accents

- **Fee-exempt** participants: left border `3px solid var(--color-accent)` (orange)
- **Infrastructure** rows: left border `3px solid var(--color-primary)` (navy)

---

## Sub-brands & Services

| Service            | URL               | Notes                                   |
|--------------------|-------------------|-----------------------------------------|
| Main website       | sfmix.org         | Hugo static site                        |
| Participant portal | web.sfmix.org     | Django + Tailwind                       |
| SSO / Login        | login.sfmix.org   | Authentik                               |
| Monitoring         | grafana.sfmix.org | Grafana (OIDC via Authentik)            |
| Looking Glass      | lg.sfmix.org      | Rust binary (telnet/SSH/MCP)            |
| Speed Test         | snappy.sfmix.org  | Multi-tool speed test with landing page |

All sub-services should use the SFMIX favicon and reference the primary color palette. Navigation back to sfmix.org should be available.

---

## File & Asset Locations

```
website/static/css/style.css          — canonical CSS with all custom properties
website/static/img/sfmix-logo-large.png — primary logo
website/static/img/favicon-*.png      — favicons
website/static/img/hero-mobile-*.jpg  — mobile hero fallback images
website/layouts/_default/baseof.html  — HTML boilerplate & meta tags
portal/templates/base.html            — portal base template (Tailwind)
```

---

## Quick Reference: CSS Custom Properties

```css
:root {
  --color-primary: #1a3a5c;
  --color-primary-light: #2a5a8c;
  --color-accent: #e8913a;
  --color-bg: #ffffff;
  --color-bg-alt: #f5f7fa;
  --color-text: #333333;
  --color-text-light: #666666;
  --color-border: #dee2e6;
  --color-white: #ffffff;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, sans-serif;
  --container-width: 1100px;
  --header-height: 64px;
}
```
