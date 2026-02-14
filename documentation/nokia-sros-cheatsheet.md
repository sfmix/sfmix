# Nokia SR-OS MD-CLI Cheat Sheet for SFMIX

A quick-reference guide for operators working with the Nokia 7750 SR routers in the SFMIX transit network. These routers run SR-OS with the MD-CLI (model-driven CLI).

## Connecting

```bash
ssh management.cr1.sjc01.transit.sfmix.org
```

You land in **operational mode** (prompt: `A:user@cr1.sjc01.transit#`).

## Key Concepts

### Router Instances

| Instance | Service ID | Description |
|----------|-----------|-------------|
| Base | — | IGP, MPLS, MP-BGP core |
| VPRN "FREE" | 200 | Free-user and free-peer BGP sessions |
| VPRN "PAID" | 100 | Paid-user and transit BGP sessions |

- **Show commands** use the numeric service-id: `show router 200 bgp summary`
- **Operational commands** (e.g., `ping`) use the VPRN name: `ping router-instance "FREE" ...`

### Configuration Hierarchy

SR-OS MD-CLI uses a tree structure. Full-context paths look like:
```
/configure service vprn "FREE" bgp group "AS<ASXXXXX>" peer-as <ASXXXXX>
```

## Viewing Configuration

```bash
# Show full running config (flat, one line per leaf)
admin show configuration full-context | no-more

# Filter config to a specific topic
admin show configuration full-context | match AS<ASXXXXX> | no-more

# Show a specific config subtree interactively
edit-config read-only
info /configure service vprn "FREE" bgp group "AS<ASXXXXX>"
quit-config
```

> **Tip:** Always append `| no-more` to disable paging on long output.

> **Tip:** `| match` works in operational mode. Use it for simple string filtering.
> Nokia `| match` does **not** support `\|` for OR — use multiple `match` invocations
> or grep from an SSH pipe instead.

## BGP Operations

### Session Summary

```bash
# All BGP sessions in FREE VPRN
show router 200 bgp summary | no-more

# All BGP sessions in PAID VPRN
show router 100 bgp summary | no-more
```

### Neighbor Detail

```bash
# Full neighbor info (state, counters, policies, address families)
show router 200 bgp neighbor <PEER-IP> | no-more

# Received routes (IPv4)
show router 200 bgp neighbor <PEER-IPv4> received-routes ipv4 | no-more

# Received routes (IPv6)
show router 200 bgp neighbor <PEER-IPv6> received-routes ipv6 | no-more

# Advertised routes (IPv4)
show router 200 bgp neighbor <PEER-IPv4> advertised-routes ipv4 | no-more

# Advertised routes (IPv6)
show router 200 bgp neighbor <PEER-IPv6> advertised-routes ipv6 | no-more
```

### Route Detail

```bash
# Detailed view of a specific IPv4 prefix
show router 200 bgp routes <PREFIX>/<LEN> ipv4 detail | no-more

# Detailed view of a specific IPv6 prefix
show router 200 bgp routes <PREFIX>/<LEN> ipv6 detail | no-more

# All RIB-in and RIB-out entries for a prefix
show router 200 bgp routes <PREFIX>/<LEN> ipv4 hunt | no-more
show router 200 bgp routes <PREFIX>/<LEN> ipv6 hunt | no-more
```

### Key Fields in Neighbor Output

| Field | Meaning |
|-------|---------|
| `IPv4 received` / `IPv6 received` | Total prefixes received from peer |
| `IPv4 active` / `IPv6 active` | Prefixes installed as best path |
| `IPv4 rejected` / `IPv6 rejected` | Prefixes rejected by import policy **or** not best (longer AS-path, etc.) |
| `IPv4 suppressed` / `IPv6 suppressed` | Prefixes suppressed (e.g., dampening) |
| `DB Orig Val` | RPKI validation state: `Valid`, `Invalid`, `NotFound` |

> **Important:** The `rejected` counter includes routes that are valid but lost
> best-path selection (e.g., longer AS-path from this peer vs. a shorter path from
> another peer). A high rejected count doesn't necessarily mean a policy problem.

## Making Configuration Changes

```bash
# Enter private candidate config
edit-config private

# Make changes (example: replacing a prefix-list)
delete /configure policy-options prefix-list "IRR-AS<ASXXXXX>-V6"
/configure policy-options prefix-list "IRR-AS<ASXXXXX>-V6" {
    prefix <PREFIX>/<LEN> type exact {
    }
}

# Review pending changes
compare

# Apply
commit

# Exit config mode
quit-config
```

> **Tip:** After committing, the prompt changes from `*(pr)` (uncommitted changes)
> to `(pr)` (clean candidate).

### Saving to Persistent Storage

```bash
admin save
```

This writes to `cf3:\config.cfg`. **Always do this after committing changes** —
without `admin save`, changes survive a soft reboot but not a power cycle.

## Policy Architecture

SFMIX uses a chained policy model. Policies are evaluated left-to-right:

### Import Chain (example: free user)
```
AS<ASXXXXX>-IN → INTERNET-IN → ACCEPT-TAG-FREE-USER → REJECT-ALL
```

1. **AS<ASXXXXX>-IN** — IRR prefix-list filter. Matching prefixes get `next-policy`; default action is `reject`.
2. **INTERNET-IN** — Hygiene filter: rejects RPKI invalid, bogon ASNs, bogon prefixes, too-small prefixes, IXP nets, AS-path > 100.
3. **ACCEPT-TAG-FREE-USER** — Tags accepted routes with the `sfmix-transit-peer-type-free-user` community.
4. **REJECT-ALL** — Catch-all reject.

### Export Chain (example: free user)
```
NOPROP-PEER-AS<ASXXXXX> → FREE-USER-OUT → REJECT-ALL
```

1. **NOPROP-PEER-AS<ASXXXXX>** — Rejects routes tagged with the no-propagate community for this peer; otherwise `next-policy`.
2. **FREE-USER-OUT** — Accepts routes tagged with free-user, free-peer, hosted-cache, paid-user, or infra communities. Also advertises SFMIX internal prefixes.
3. **REJECT-ALL** — Catch-all reject.

### INTERNET-IN Reject Reasons

| Entry | Rejects |
|-------|---------|
| 20 | RPKI origin-validation-state `invalid` |
| 50 | Bogon ASNs in AS-path |
| 60 | Bogon IPv4 prefixes |
| 70 | Bogon IPv6 prefixes |
| 80 | Too-small IPv4 prefixes |
| 90 | Too-small IPv6 prefixes |
| 100 | AS-path length ≥ 100 |
| 110 | IXP IPv4 prefixes |
| 120 | IXP IPv6 prefixes |

## IRR Prefix-List Management

Prefix-lists are generated from IRR using `bgpq4`. Use the **AS-SET** (e.g., `AS-EXAMPLE`), not the bare ASN (e.g., `AS<ASXXXXX>`), to include downstream customer prefixes.

### Generating Prefix-Lists

```bash
# Nokia MD-CLI format (-n), IPv4 and IPv6
bgpq4 -n -4 -l "IRR-AS<ASXXXXX>-V4" <AS-SET> > /tmp/irr-as<ASXXXXX>-v4.txt
bgpq4 -n -6 -l "IRR-AS<ASXXXXX>-V6" <AS-SET> > /tmp/irr-as<ASXXXXX>-v6.txt

# Junos format (-J)
bgpq4 -J -4 -l IRR-AS<ASXXXXX>-V4 <AS-SET>
bgpq4 -J -6 -l IRR-AS<ASXXXXX>-V6 <AS-SET>
```

### bgpq4 Vendor Flags

| Flag | Vendor |
|------|--------|
| `-n` | Nokia SR-OS MD-CLI |
| `-N` | Nokia SR-OS Classic CLI |
| `-J` | Juniper Junos |
| `-j` | JSON |
| `-e` | Arista EOS |

### Applying to Router via SSH

```bash
# Replace a single prefix-list (e.g., IPv6)
{
  echo 'edit-config private'
  echo 'delete /configure policy-options prefix-list "IRR-AS<ASXXXXX>-V6"'
  cat /tmp/irr-as<ASXXXXX>-v6.txt
  echo 'commit'
  echo 'quit-config'
} | ssh -tt management.<ROUTER>.sfmix.org

# Replace both IPv4 and IPv6 in one shot
{
  echo 'edit-config private'
  echo 'delete /configure policy-options prefix-list "IRR-AS<ASXXXXX>-V4"'
  echo 'delete /configure policy-options prefix-list "IRR-AS<ASXXXXX>-V6"'
  cat /tmp/irr-as<ASXXXXX>-v4.txt
  cat /tmp/irr-as<ASXXXXX>-v6.txt
  echo 'commit'
  echo 'quit-config'
} | ssh -tt management.<ROUTER>.sfmix.org
```

## Routing Table & Reachability

```bash
# Route table lookup (IPv4)
show router 200 route-table <PREFIX>/<LEN> ipv4 | no-more

# Route table lookup (IPv6)
show router 200 route-table <PREFIX>/<LEN> ipv6 | no-more

# Ping from a VPRN
ping router-instance "FREE" <PEER-IP>

# Traceroute from a VPRN
traceroute router-instance "FREE" <PEER-IP>
```

## Common Gotchas

1. **`| match` with regex OR:** Nokia `| match` does not support `\|` for alternation. Pipe through SSH and use `grep` on the local side instead.

2. **`| head` doesn't exist:** There is no `head` command in the Nokia CLI pipe. Use `| count` for counting or just `| no-more` and let it scroll.

3. **`hunt` keyword:** `hunt` is supported on `show router X bgp routes ... hunt` but **not** on `received-routes` or `advertised-routes`.

4. **`longest-match` not available:** Unlike Junos `show route ... longest-match`, Nokia doesn't support this on all commands. Use the covering prefix directly.

5. **`quit-config` context:** You must be at the top level (`/`) or in operational mode to run `quit-config`. If you're deep in a config subtree after a commit, the CLI stays in that subtree — navigate up with `/` or `exit all` first.

6. **`enforce-first-as`:** Cannot be set at the BGP group level on some SR-OS versions. Set it globally or omit it.

7. **Rejected ≠ filtered:** The `rejected` counter in BGP neighbor output includes routes that passed policy but lost best-path selection. Don't assume a high rejected count means your import policy is wrong — check `active` count and route detail.

8. **Service-id vs. name:** Show commands use the numeric service-id (`show router 200 ...`). Config and some operational commands use the name (`router-instance "FREE"`).

## Quick Debugging Workflow

When a peer reports route exchange issues:

1. **Check session state:**
   ```
   show router 200 bgp summary | no-more
   ```

2. **Check received/active/rejected counts:**
   ```
   show router 200 bgp neighbor <PEER-IP> | no-more
   ```

3. **Look at what they're sending:**
   ```
   show router 200 bgp neighbor <PEER-IP> received-routes ipv4 | no-more
   show router 200 bgp neighbor <PEER-IP> received-routes ipv6 | no-more
   ```

4. **Look at what we're sending:**
   ```
   show router 200 bgp neighbor <PEER-IP> advertised-routes ipv4 | no-more
   show router 200 bgp neighbor <PEER-IP> advertised-routes ipv6 | no-more
   ```

5. **Check a specific prefix in detail:**
   ```
   show router 200 bgp routes <PREFIX>/<LEN> ipv4 detail | no-more
   show router 200 bgp routes <PREFIX>/<LEN> ipv6 detail | no-more
   ```

6. **Check the import policy chain:**
   ```
   admin show configuration full-context | match <POLICY-NAME> | no-more
   ```

7. **If prefix-lists are stale, regenerate from IRR:**
   ```bash
   bgpq4 -n -4 -l "IRR-AS<ASXXXXX>-V4" <AS-SET>
   bgpq4 -n -6 -l "IRR-AS<ASXXXXX>-V6" <AS-SET>
   ```
