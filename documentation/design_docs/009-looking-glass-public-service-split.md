# 009 - Looking Glass: public service VM + management-only route collector

## Status: DEPLOYED 2026-11-04 (lg-web live, collector mgmt-only; all 164 established sessions returned)

As-built notes: lg-web is VM 115 on **pve01**-paulave200-sfo (pve02 had 10 GiB free with load 5,
so anti-affinity lost to headroom), Debian 13 cloud image + cloud-init, 4 vCPU / 4 GiB (bump when
Alice moves in). The re-plumb ran as a detached script with a 15-minute auto-revert watchdog
(no guest agent or serial console on the OpenBSD VM); BGP bracket 01:06:26 down → 01:07:30 up,
161/164 back after 45 s, 164/164 within ten minutes, the only state changes being two peers that
were not established before either. The geerlingguy.certbot role does not expand an existing
lineage, so the lg/lg-ng SANs were added once by hand with `certbot certonly --expand`; renewals
carry them. Loki labels hosts by FQDN (`host="lg.sfmix.org"`, `host="lg-web.sfmix.org"`).

## Overview

`lg.sfmix.org` is a single OpenBSD VM (Proxmox VM 111 "lg" on `pve01-paulave200-sfo`,
OpenBSD 7.8, 2 vCPU / 2 GiB, e1000 NICs) doing two unrelated jobs:

1. **Route collector.** OpenBGPD (`fib-update no`, AS 12276, router-id 206.197.187.1) holding
   ~220 passive participant sessions on the peering LAN (`em1` → `vmbr2`, 206.197.187.1 /
   2001:504:30::ba01:2276:1). This is the load-bearing part.
2. **Public web service.** OpenBSD httpd on :80/:443 serving the `bgplg` CGI, the `bgplgd`
   JSON API under `/api/`, `participants*.json` for sfmix.org, and the arouteserver
   `rs-*.summary.html` pages, with acme-client for TLS. Its "public" NIC (`em0` → `vmbr5`,
   VLAN 101 PUBLIC-SFO02, 192.33.255.7/28 + 2620:11a:b000::7/64, default route via .1) sits on
   the sfo02 server VLAN next to monitor, netbox and metrics. It is not a DMZ.

Meanwhile the new looking glass (design doc 004: `lg-server`/`lg-cli`/`lg-http`, "lg-ng") and
Alice-LG both run on `alice.sfmix.org` at fmt01, and Alice reads the collector through
`https://lg.sfmix.org/api/`.

This doc splits the two jobs: a new Linux VM becomes the single public looking-glass host at
`lg.sfmix.org`, and the OpenBSD VM keeps only its peering-LAN leg plus a management leg, with no
public address at all.

### Why

- **Exposure.** `sshd` on the OpenBSD VM listens on every address, including the public one,
  with OpenBSD's default `PasswordAuthentication yes`. In the four days after the 2026-09-15
  log rotation the authlog held ~19k "Invalid user" and ~32k "Failed password" lines from 267
  sources against 8 real logins. That is the `SshBruteForce` Loki rule firing. `pf` is enabled
  but `/etc/pf.conf` is not managed by Ansible, and the Linux `ufw` role is skipped for
  `looking_glass` (and would not run on OpenBSD anyway).
- **Shared fate.** A web-tier problem (crawler storm, httpd bug, OOM) lands on the same VM as
  220 BGP sessions.
- **One front door.** `lg.sfmix.org`, `lg-ng.sfmix.org` and `alice.sfmix.org` are three names
  for one function. The new VM is where that converges; Alice stays where it is for now and is
  absorbed later.

### Decisions

- **New Linux VM in sfo02** (`lg-web.sfmix.org`), on `pve02-paulave200-sfo` for anti-affinity
  with the collector on pve01. Same site as rs-linux and the collector, so every internal hop
  stays on 10.1.1.0/24.
- **Alice stays on `alice.sfmix.org` unchanged** (apart from losing lg-ng). The new VM takes over
  Alice's role over time (see Follow-ups). Because Alice is not on the new VM, there is no
  `/api/v1` clash and lg-http owns the root of `lg.sfmix.org`; `lg-ng.sfmix.org` becomes an alias.
- **Management name for the collector: `mgmt.lg.sfmix.org`**, matching `mgmt.rs-linux`,
  `mgmt.rs-openbsd` and `mgmt.quarantine-lg`.
- **No SLA**, so no TTL pre-lowering or staged DNS: records are replaced in one push.
- **BGP sessions are bracketed by explicit administrative shutdown** (RFC 8203 shutdown
  communication) before anything can drop a socket, and brought back deliberately. Minimising
  downtime is secondary to avoiding session-state hysteresis on the far end.

## Target architecture

```
Internet ──► lg.sfmix.org = lg-ng.sfmix.org = lg-web.sfmix.org
             Linux VM "lg-web", sfo02: net0 vmbr5 (VLAN101) 192.33.255.8 / 2620:11a:b000::8  (default route)
                                      net1 vmbr0 (mgmt)    10.1.1.17                          (10/8, 100.64/10 via 10.1.1.1)
             nginx :443  (roles/looking_glass_web)
               ├─ ^~ /api/v1/, ^~ /mcp, /      → lg-http 127.0.0.1:8080            (lg-ng REST + MCP)
               ├─ ^~ /api/                     → http://mgmt.lg.sfmix.org/api/      (bgplgd, legacy + Alice source)
               ├─ ^~ /cgi-bin/, = /sfmix.png   → http://mgmt.lg.sfmix.org/...       (bgplg CGI)
               └─ /participants*.json, /*.summary.html → /var/www/lg-web            (participants_json, arouteserver)
             lg-cli telnet :2023 / ssh :2222 bound to 10.1.1.17 (admin-only, as on alice today)
             lg-server RPC 10.1.1.17:9090 ← lg-neighborhood-watch on rs-linux (10.1.1.18)

alice.sfmix.org (fmt01, unchanged VM): Alice-LG only; source [looking_glass] → http://mgmt.lg.sfmix.org/api/

Peering LAN ──► OpenBSD VM 111 "lg" (BGP untouched: 206.197.187.1 / …ba01:2276:1, ~220 neighbors)
             em1 vmbr2 peering        (unchanged)
             em0 vmbr5 → vmbr0 mgmt   10.1.1.21/24, default 10.1.1.1, no public address
             httpd :80 on mgmt only (bgplgd + bgplg), TLS + acme removed; sshd ListenAddress 10.1.1.21, key-only
             syslog → metrics.oob.sfo02 (already), snmpd on mgmt
```

This is the layout rs-linux already uses (net0 vmbr0 = 10.1.1.18 with the default route, net1
vmbr2 peering).

lg-ng has only Arista EOS and Nokia SR-OS drivers, so nothing in lg-server talks to the
collector today. The nginx proxy of the legacy paths is what keeps the collector's routes
visible to the public and to Alice. A native bgplgd backend in lg-server is the intended
replacement, after which the proxy locations can go.

## Addresses

| Host | Leg | Address | Source |
|---|---|---|---|
| lg-web | public VLAN 101 | 192.33.255.8 / 2620:11a:b000::8 | free in NetBox and the zone file on 2026-11-03 (.9 is sentry in DNS, not NetBox: avoided) |
| lg-web | mgmt sfo02 | 10.1.1.17 (`mgmt.lg-web`) | free in both |
| lg (OpenBSD) | mgmt sfo02 | 10.1.1.21 (`mgmt.lg`) | free in both |
| lg (OpenBSD) | peering | 206.197.187.1 / 2001:504:30::ba01:2276:1 | unchanged |
| released after Phase 3 | public VLAN 101 | 192.33.255.7 / 2620:11a:b000::7 | free in NetBox + DNS |

## What landed in the repo (2026-11-03)

Safe to deploy at any time; nothing here changes what the public sees until the cutover edits
below are made.

- **Phase 0, sshd**: `roles/sfmix_route_server_openbsd/tasks/sshd_hardening.yml` +
  `deploy_openbsd_sshd.playbook.yml` (hosts `rs_openbsd:looking_glass:quarantine_looking_glass`).
  Key-only auth. Removes the "Failed password" lines the alert keys on; "Invalid user" noise
  remains until the NIC moves.
- **New role `looking_glass_web`**: nginx + certbot (one lineage for all names in
  `looking_glass_web_domains`) + static root; vhost template as in the diagram. Rate-limit zone
  `lg_ip` with the same admin-subnet exemptions as Alice's.
- **Inventory**: `lg-web.sfmix.org` in `looking_glass_rust`, `looking_glass_web` (new) and
  `log_agent`; alice removed from `looking_glass_rust`. `group_vars/looking_glass_web.yml`
  points `participants_json` and the arouteserver summary publish at the static root.
- **lg-ng addresses**: `looking_glass_bind_address` / `looking_glass_rpc_bind` → 10.1.1.17;
  rs_linux `…lg_neighborhood_watch_lg_rpc_url` → `http://10.1.1.17:9090`.
- **push_servers**: summary-HTML and participants.json plays now target `looking_glass_web`;
  new "nginx front door" play; alice's duplicate participants.json play dropped.
- **DNS**: `lg-web` A/AAAA, `mgmt.lg-web`, `mgmt.lg` added. `lg` / `lg-ng` untouched until cutover.
- **sfmix_looking_glass (OpenBSD)**: acme cron is removed when `sfmix_looking_glass_web_tls`
  is false; bgplg header logo is a relative `/sfmix.png` so it survives the proxy.
- Portal default `IXP_LOOKING_GLASS_URL` → `https://lg-ng.sfmix.org`; design doc 004 deployment
  section corrected.

## Operator runbook

Every `ansible-playbook` below takes `--vault-password-file ~/.sfmix_ansible_vault`.

### Phase 0 — key-only sshd on the OpenBSD hosts (now)

```
ansible-playbook deploy_openbsd_sshd.playbook.yml
```

### Phase 1 — build lg-web

1. Proxmox (no VM automation exists): on `pve02-paulave200-sfo`, Debian/Ubuntu like the fleet,
   4 vCPU / 8 GiB (headroom for absorbing Alice later; Alice needed 8 GiB), virtio NICs:
   `net0 bridge=vmbr5` (VLAN 101), `net1 bridge=vmbr0` (sfo02 mgmt). Hostname `lg-web`.
2. Netplan: net0 192.33.255.8/28 + 2620:11a:b000::8/64, default via 192.33.255.1 and
   2620:11a:b000::1; net1 10.1.1.17/24 with static routes 10.0.0.0/8 and 100.64.0.0/10 via
   10.1.1.1. The fleet sysctl sets `accept_ra=0`, so everything is static.
3. NetBox: VM, two interfaces, the three addresses (`scripts/vm_discovery.py --netbox` shows gaps).
4. DNS: `ansible-playbook push_servers.playbook.yml --tags dns` (publishes `lg-web`, `mgmt.lg-web`,
   `mgmt.lg`).
5. Baseline + front door + logs:
   ```
   ansible-playbook push_servers.playbook.yml --limit lg-web.sfmix.org --tags sfmix_server
   ansible-playbook push_servers.playbook.yml --limit lg-web.sfmix.org --tags looking_glass_web,participants_json,route_server_html_summary
   ansible-playbook deploy_looking_glass_rust.playbook.yml
   ansible-playbook deploy_log_agent.playbook.yml --limit lg-web.sfmix.org
   ansible-playbook push_servers.playbook.yml --limit rs-linux.sfmix.org --tags bird   # sensor → new RPC address
   ```
   Alice's lg-ng units keep running until its next alice push; harmless.
6. Smoke test on the temp name: `https://lg-web.sfmix.org/api/v1/participants`, `/mcp`,
   `/participants.json`, `/rs-linux.sfmix.org.summary.html`. The `/api/` and `/cgi-bin/`
   locations return 502 until Phase 3 (mgmt.lg does not answer yet); that is expected.

### Phase 2 + 3 — one window: collector re-plumb, then DNS

Do these in one sitting. Between the collector losing its public leg and the DNS push the
public LG is down for a few minutes; there is no SLA and no TTL dance.

**Cutover edits (commit together, deploy in the order below):**

| File | Change |
|---|---|
| `group_vars/looking_glass.yml` | `sfmix_looking_glass_web_tls: false`, `sfmix_looking_glass_web_hostname: mgmt.lg.sfmix.org`, drop `participants_json_output_directory` |
| `inventory/servers.yml` | `lg.sfmix.org: {ansible_host: mgmt.lg.sfmix.org}` under `looking_glass` |
| `group_vars/looking_glass_web.yml` | `looking_glass_web_domains: [lg-web.sfmix.org, lg.sfmix.org, lg-ng.sfmix.org]` |
| `roles/sfmix_dns/templates/zones/sfmix.org.j2` | `lg` A/AAAA → `lg IN CNAME lg-web`; `lg-ng IN CNAME alice` → `lg-ng IN CNAME lg-web` |
| `roles/alice/templates/alice.conf.j2` | `[source.looking_glass.openbgpd-bgplgd] api = http://mgmt.lg.sfmix.org/api/` |
| `group_vars/alice.yml` | `alice_additional_vhosts: []` (lg-ng leaves alice) |

**Collector re-plumb (OpenBSD VM 111):**

1. Pre-checks: `10.1.1.1` is `eth2.mgmt-gw.sfo02`; rs-linux (default via 10.1.1.1) proves the
   mgmt LAN has NAT egress and reaches the resolver 192.33.255.3. Back up `/etc/hostname.em0`,
   `/etc/mygate`, `/etc/ssh/sshd_config`, `/etc/httpd.conf`, `/etc/pf.conf`.
2. Over the still-public SSH, push the web changes (httpd on plain :80, acme cron removed):
   `ansible-playbook push_servers.playbook.yml --limit lg.sfmix.org --tags looking_glass`.
   `listen on egress port 80` follows the default route, so httpd lands on the mgmt NIC once
   the route moves. That is the intent.
3. Stage the network files, do **not** apply yet: `/etc/hostname.em0` →
   `description "SFMIX Management"` / `inet 10.1.1.21 255.255.255.0`; `/etc/mygate` → `10.1.1.1`
   only; sshd `ListenAddress 10.1.1.21`.
4. **BGP bracket.** Open the Proxmox console (not SSH; the address is about to go away).
   ```
   bgpctl show summary > /root/pre-$(date +%F).txt
   bgpctl show neighbor > /root/pre-neighbors-$(date +%F).txt
   for n in $(bgpctl -j show summary | python3 -c 'import json,sys; print(" ".join(p["remote_addr"] for p in json.load(sys.stdin)["neighbors"]))'); do
     bgpctl neighbor "$n" down "SFMIX LG maintenance: NIC re-plumb, back in ~5 min"
   done
   ```
   Every neighbor is now `Idle` with the admin-down latched in bgpd, and the far side logged a
   Cease / Administrative Shutdown with that text instead of a TCP reset. (Same bracket as the
   graceful RS reboot on 2026-10-20.)
5. On the Proxmox node: `qm set 111 --net0 e1000=BC:24:11:D9:2F:D5,bridge=vmbr0`.
6. Apply without rebooting so bgpd and its em1 bindings never move:
   `sh /etc/netstart em0 && route -n flush && sh /etc/netstart && rcctl restart sshd`.
   e1000 hot-reparent is unreliable on OpenBSD; if em0 does not come up clean, `reboot`
   (bgpd state is already clean because of step 4).
7. From the tailnet: `ssh mgmt.lg.sfmix.org`, `curl http://mgmt.lg.sfmix.org/api/neighbors`.
8. Bring sessions back deliberately: `bgpctl neighbor group "<grp>" up` per group, or per
   address. After a reboot bgpd starts with all neighbors enabled and the participants
   reconnect on their own (the collector is the passive side).
9. `diff <(awk '{print $1,$NF}' /root/pre-*.txt) <(bgpctl show summary | awk '{print $1,$NF}')`.
   A peer that was Established and is still not back after ~10 minutes is in hysteresis on
   its side (ConnectRetry backoff, their damping, an admin-down their automation latched).
   `bgpctl neighbor <addr> clear` once, then contact the participant rather than flap it.

**DNS + front door + Alice:**

```
ansible-playbook push_servers.playbook.yml --tags dns
ansible-playbook push_servers.playbook.yml --limit lg-web.sfmix.org --tags looking_glass_web   # certbot adds lg + lg-ng
ansible-playbook push_servers.playbook.yml --limit alice.sfmix.org --tags alice
```

**Verify:** from outside, `https://lg.sfmix.org/api/v1/participants`, `/mcp`,
`/api/neighbors`, `/cgi-bin/bgplg`, `/participants.json`, `/rs-linux.sfmix.org.summary.html`
all 200; `lg-ng.sfmix.org` identical; portal `/route-servers/` renders; Alice shows the
`looking_glass` source green; `scripts/route_server_parity.py` runs; Loki still has
`{host="lg"}` syslog and `{host="lg-web"}` journal; blackbox-tls green for `lg.sfmix.org`;
`SshBruteForce` silent for `lg`.

**Cleanup:** release 192.33.255.7 / 2620:11a:b000::7 in NetBox; `lg.sfo01` peering records stay.

**Rollback (collector):** `qm set 111 --net0 …bridge=vmbr5`, restore the backed-up files,
`sh /etc/netstart` (or reboot). About two minutes. BGP needs no separate rollback: em1 is never
touched and the down/up bracket is the same either way.

## Follow-ups

- **Absorb Alice.** Either base-path support in lg-http so Alice can sit under a prefix on
  `lg.sfmix.org`, or lg-ng grows the route-browser features; then retire `alice.sfmix.org`,
  its blackbox target, and move the authentik `meta_launch_url` / redirect regex from
  `lg-ng.sfmix.org` to `lg.sfmix.org` (`terraform/authentik`, `looking_glass_oidc_resource_url`).
- **OpenBGPD backend in lg-server** talking to bgplgd over mgmt, replacing the nginx compat
  proxy.
- **Summary page (done 2026-11-04).** `/` on lg.sfmix.org is a static page from the role
  (`files/index.html`): headline figures, a peering board with one tile per participant and a
  lamp per address family, a sortable session table, and the tools hub. It reads `/api/summary`,
  `/api/memory`, `/api/neighbors` and `/api/v1/participants` client-side and refreshes every minute.
  Its markup is the starting point for a native lg-http landing page.
- **Public lg-cli.** Telnet/SSH stay bound to the mgmt address as on alice. Exposing them on
  192.33.255.8 (design doc 004 intent) is a one-line `looking_glass_bind_address` change plus
  ufw allows, once the policy engine's rate limits have been exercised.
- **Manage `pf` via Ansible** on the three OpenBSD hosts (unmanaged today).
