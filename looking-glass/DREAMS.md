# DREAMS.md — Looking Glass Feature Wishlist

A brainstorm of feature ideas and enhancements for the SFMIX Looking Glass. These are aspirational — not all will be implemented, but they capture the vision.

---

## Visual & UX

### ANSI Color Indicators
- **Red/green status** — link up/down, session state, threshold violations
- **Orange for warnings** — distinguish warning vs critical thresholds
- **Blinking red for link down** — attention-grabbing for critical states
- Color-coded optics: green (good), orange (warning), red (alarm/critical)

### Terminal Handling
- **psql `\X` mode** — expanded/vertical display when terminal width is narrow
- **Command history** — up-arrow to recall previous commands
- **Prompt with context** — show username, authenticated ASNs, or timestamp

### Topology Visualization
- **ASCII/ANSI weathermap** — parse LLDP neighbors to show topology diagram
- Line thickness and colors to indicate traffic levels (weathermap style)
- Bay Area ASCII map with anchored site coordinates
- LOC DNS records for geographic positioning (half-joking, half-serious)

---

## Health & Diagnostics

### `show healthcheck [AS]`
A summary view for a participant (default: own ASN), showing:
- Number of ports connected and speed
- Recent interface errors
- dBm levels vs thresholds (flag out-of-spec)
- MAC addresses learned
- Route server session status (up/down)
- Route collector session status
- Recent port security triggers (if any)

### `show optics thresholds`
Explain *why* a port is flagged red or orange — show the actual thresholds and current values side-by-side.

### `show version`
- Git commit hash
- Build timestamp
- Uptime
- Config file path

---

## Participant Features

### MAC Address Intelligence
- **MAC learn status** — is the expected MAC learned on the port?
- **Manufacturer lookup** — OUI-based vendor identification (e.g., "Arista Networks")
- Known vs unknown MAC reporting

### Optical Monitoring
- dBm within appropriate levels (per transceiver type)
- Threshold source: transceiver DOM thresholds or configured overrides

### Route Visibility
- Routes advertised to route servers
- Routes visible on route collector
- Prefix count summary

### Participants List Enhancements
- **RS session status** — green dot for up, red for down
- Optional orange indicator for route server (vs direct peer)

---

## Infrastructure & Backend

### Logs Integration
Mix relevant device logs into output — e.g., recent syslog entries for a port when showing interface details.

### Admin-Only Commands
Some commands are more "behind the scenes" — e.g., `show arp` for the full table vs participant-focused views that filter to relevant entries.

### EOS API vs SSH
Currently using SSH CLI. Consider eAPI (JSON-RPC) for structured output where beneficial, but SSH keeps the codebase simpler and more portable.

### NetBox Plugin
Replace the Ansible dict/list participant inventory with a proper NetBox plugin — cleaner data model, single source of truth.

### Additional Targets
- AS 40271 as a looking glass target

---

## Meta

### Self-Help CLI
The looking glass as a "self-help" tool — participants can diagnose their own connectivity without opening a ticket.
