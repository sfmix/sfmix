# BGP Migration Debugging Guide - JunOS to Nokia SR-OS

## Overview
This guide documents debugging techniques and commands used during the migration of BGP peers from JunOS (Juniper MX150) to Nokia SR-OS routers.

## Capturing Configuration Output

### JunOS Configuration Extraction

**Show full configuration:**
```bash
ssh router.example.com "show configuration | display set | no-more"
```

**Show specific routing instance:**
```bash
ssh router.example.com "show configuration routing-instances PAID | display set"
ssh router.example.com "show configuration routing-instances FREE | display set"
```

**Show BGP configuration:**
```bash
ssh router.example.com "show configuration protocols bgp | display set"
```

**Show policy configuration:**
```bash
ssh router.example.com "show configuration policy-options | display set"
```

**Show interfaces:**
```bash
ssh router.example.com "show configuration interfaces | display set"
```

### Nokia SR-OS Configuration Extraction

**Show full configuration with context:**
```bash
echo 'admin show configuration full-context | no-more' | ssh -tt management.router.example.com
```

**Show specific service VPRN:**
```bash
echo 'admin show configuration full-context | match "vprn \"PAID\"" | no-more' | ssh -tt management.router.example.com
echo 'admin show configuration full-context | match "vprn \"FREE\"" | no-more' | ssh -tt management.router.example.com
```

**Show BGP configuration:**
```bash
echo 'admin show configuration full-context | match bgp | no-more' | ssh -tt management.router.example.com
```

**Show policy configuration:**
```bash
echo 'admin show configuration full-context | match policy-options | no-more' | ssh -tt management.router.example.com
```

**Important:** Nokia SR-OS commands via SSH require the `echo 'command' | ssh -tt` pattern to work properly.

## BGP Session Verification

### JunOS BGP Status

**Show BGP summary:**
```bash
ssh router.example.com "show bgp summary"
```

**Show specific routing instance BGP:**
```bash
ssh router.example.com "show bgp summary instance PAID"
ssh router.example.com "show bgp summary instance FREE"
```

**Show BGP neighbor details:**
```bash
ssh router.example.com "show bgp neighbor 149.112.115.16"
```

**Show received routes:**
```bash
ssh router.example.com "show route receive-protocol bgp 149.112.115.16"
```

**Show advertised routes:**
```bash
ssh router.example.com "show route advertising-protocol bgp 149.112.115.16"
```

### Nokia SR-OS BGP Status

**Show BGP summary for VPRN:**
```bash
echo 'show router 100 bgp summary | no-more' | ssh -tt management.router.example.com
echo 'show router 200 bgp summary | no-more' | ssh -tt management.router.example.com
```

**Show specific neighbor:**
```bash
echo 'show router 100 bgp neighbor 149.112.115.16 | no-more' | ssh -tt management.router.example.com
```

**Show neighbor detail (includes rejected routes count):**
```bash
echo 'show router 100 bgp neighbor 149.112.115.16 detail | no-more' | ssh -tt management.router.example.com
```

**Show received routes:**
```bash
echo 'show router 100 bgp neighbor 149.112.115.16 received-routes | no-more' | ssh -tt management.router.example.com
```

**Show advertised routes:**
```bash
echo 'show router 100 bgp neighbor 149.112.115.16 advertised-routes | no-more' | ssh -tt management.router.example.com
```

**Filter output with match:**
```bash
echo 'show router 100 bgp summary | match 31128 | no-more' | ssh -tt management.router.example.com
```

## Layer 2 Connectivity Verification

### JunOS

**Show ARP table:**
```bash
ssh router.example.com "show arp | match 149.112.115"
```

**Show interface status:**
```bash
ssh router.example.com "show interfaces ae0.1406"
```

**Show MAC address:**
```bash
ssh router.example.com "show interfaces ae0 | match \"Current address\""
```

### Nokia SR-OS

**Show ARP table:**
```bash
echo 'show router 100 arp | no-more' | ssh -tt management.router.example.com
echo 'show router 100 arp | match 149.112.115.16 | no-more' | ssh -tt management.router.example.com
```

**Show interface status:**
```bash
echo 'show router 100 interface | match peering | no-more' | ssh -tt management.router.example.com
```

**Show interface detail:**
```bash
echo 'show service id 100 interface "as31128-peering" detail | no-more' | ssh -tt management.router.example.com
```

**Show MAC address:**
```bash
echo 'show router 100 interface "as31128-peering" detail | match MAC | no-more' | ssh -tt management.router.example.com
```

## Route Table Verification

### JunOS

**Show route table:**
```bash
ssh router.example.com "show route table PAID.inet.0 149.112.115.160/27"
```

**Show route detail:**
```bash
ssh router.example.com "show route table PAID.inet.0 149.112.115.160/27 detail"
```

### Nokia SR-OS

**Show route table:**
```bash
echo 'show router 100 route-table 149.112.115.160/27 | no-more' | ssh -tt management.router.example.com
```

**Show BGP routes:**
```bash
echo 'show router 100 bgp routes 149.112.115.160/27 hunt | no-more' | ssh -tt management.router.example.com
```

## Authentication Issues

### MD5 Authentication Failures

**Symptoms:**
- BGP sessions stuck in Connect/Active state
- Log messages showing MD5 digest mismatch

**Nokia SR-OS - Check for MD5 errors:**
```bash
# Look for authentication failure logs
# Error message format:
# "TCP MD5 digest match Failure: Incoming packet from source address X.X.X.X 
#  virtual router N (service id NNN) dropped due to MD5 authentication failure 
#  and possible reason is digestMismatch"
```

**Verify authentication configuration:**
```bash
echo 'admin show configuration full-context | match authentication | no-more' | ssh -tt management.router.example.com
```

**Check if authentication is configured on BGP group:**
```bash
echo 'show router 200 bgp neighbor 173.194.120.204 detail | no-more' | ssh -tt management.router.example.com
# Look for "Authentication : MD5" or "Authentication : None"
```

**Resolution:**
1. Get correct MD5 key from working router (e.g., cr1.sjc01.transit)
2. Update authentication key on Nokia router:
   ```
   /configure service vprn "FREE" bgp group "AS15169" authentication-key "correct-key-here"
   ```
3. Or remove authentication temporarily:
   ```
   /configure service vprn "FREE" bgp group "AS15169" { authentication-key }
   delete authentication-key
   ```

## Common BGP Session Issues

### Issue: Sessions in Active/Connect State

**Possible causes:**
1. Missing local-address configuration
2. MD5 authentication mismatch
3. Remote side not configured yet
4. Layer 2 connectivity issue

**Debugging steps:**

1. **Check local-address is configured:**
   ```bash
   echo 'show router 200 bgp neighbor 173.194.120.204 detail | no-more' | ssh -tt management.router.example.com
   # Look for "Local Address" field - should NOT be 0.0.0.0
   ```

2. **Verify Layer 2 connectivity:**
   ```bash
   echo 'show router 200 arp | match 173.194.120.204 | no-more' | ssh -tt management.router.example.com
   # Should show ARP entry with MAC address
   ```

3. **Check interface status:**
   ```bash
   echo 'show router 200 interface | match peering | no-more' | ssh -tt management.router.example.com
   # All interfaces should show "Up/Up"
   ```

4. **Check for authentication errors in logs**

### Issue: Routes Being Rejected

**Check rejected route count:**
```bash
echo 'show router 100 bgp neighbor 149.112.115.16 detail | no-more' | ssh -tt management.router.example.com
# Look for "IPv4 rejected : N" in the output
```

**If routes are rejected:**
1. Check import policy configuration
2. Verify prefix-lists match expected routes
3. Check community filters
4. Verify route-filter ranges (e.g., /9-/24 for IPv4, /19-/48 for IPv6)

**Example - No routes rejected:**
```
IPv4 received        : 8
IPv4 active          : 8
IPv4 suppressed      : 0
IPv4 rejected        : 0    ✅
```

## Route Leaking Between VPRNs

### JunOS - Using rib-groups

**Check rib-group configuration:**
```bash
ssh router.example.com "show configuration routing-options rib-groups"
```

**Example:**
```
set routing-options rib-groups PAID-ACCESS-V4 import-rib FREE.inet.0
set routing-options rib-groups FREE-ACCESS-V4 import-rib PAID.inet.0
```

### Nokia SR-OS - Using MP-BGP and Route Targets

**Check vrf-import/export policies:**
```bash
echo 'admin show configuration full-context | match vrf-import | no-more' | ssh -tt management.router.example.com
echo 'admin show configuration full-context | match vrf-export | no-more' | ssh -tt management.router.example.com
```

**Check route-target communities:**
```bash
echo 'admin show configuration full-context | match rt-free | no-more' | ssh -tt management.router.example.com
echo 'admin show configuration full-context | match rt-paid | no-more' | ssh -tt management.router.example.com
```

**Verify routes are being leaked:**
```bash
# Check if cache prefix from PAID VPRN appears in FREE VPRN
echo 'show router 200 route-table 149.112.115.160/27 | no-more' | ssh -tt management.router.example.com
# Should show "Remote  BGP VPN" with source from PAID VPRN
```

## Interface Configuration

### Nokia SR-OS SAP Naming

**Important:** Nokia uses colon notation for SAPs, not dot notation:
- ✅ Correct: `lag-core-1:1406`
- ❌ Wrong: `lag-core-1.1406`

**Show all SAPs:**
```bash
echo 'show service sap-using | no-more' | ssh -tt management.router.example.com
```

**Show specific interface:**
```bash
echo 'show router 100 interface "as31128-peering" | no-more' | ssh -tt management.router.example.com
```

## Configuration Changes

### Nokia SR-OS Configuration Mode

**Enter configuration mode:**
```bash
# Via SSH session:
ssh management.router.example.com
# Then:
configure
```

**Apply changes:**
```
commit
admin save
```

**View pending changes:**
```
info diff
```

**Discard changes:**
```
discard
```

### Deleting and Recreating BGP Configuration

**Important:** Nokia SR-OS does not support renaming BGP groups. You must delete and recreate.

**Delete BGP neighbor:**
```
/configure service vprn "PAID" bgp { neighbor "149.112.115.16" }
delete neighbor "149.112.115.16"
```

**Delete BGP group:**
```
/configure service vprn "PAID" bgp { group "AS31128" }
delete group "AS31128"
```

**Then recreate with new configuration.**

## Useful Filtering and Parsing

### Using grep with context:
```bash
ssh router.example.com "show configuration | display set | grep -A 5 -B 5 'AS31128'"
```

### Using match in Nokia:
```bash
echo 'show router 100 bgp summary | match 31128 | no-more' | ssh -tt management.router.example.com
```

### Counting routes:
```bash
echo 'show router 100 bgp neighbor 149.112.115.16 advertised-routes | match "Routes :" | no-more' | ssh -tt management.router.example.com
```

## Migration Verification Checklist

1. **BGP Sessions:**
   - [ ] All sessions show "Established" state
   - [ ] Session uptime is stable (not flapping)
   - [ ] Routes being received match expected count
   - [ ] Routes being advertised match expected count

2. **Layer 2:**
   - [ ] ARP entries present for all neighbors
   - [ ] Interfaces show "Up/Up" status
   - [ ] MAC addresses correct (if using MAC spoofing)

3. **Route Exchange:**
   - [ ] No routes rejected (check detail output)
   - [ ] Cache prefixes visible in routing table
   - [ ] Route leaking working between VPRNs
   - [ ] Communities being applied correctly

4. **Policies:**
   - [ ] Import policies accepting expected routes
   - [ ] Export policies advertising correct routes
   - [ ] Prefix-lists match expected ranges
   - [ ] Communities configured and applied

5. **Authentication:**
   - [ ] MD5 keys match on both sides (if used)
   - [ ] No authentication errors in logs
   - [ ] Sessions establish successfully

## Common Pitfalls

1. **Missing local-address on BGP neighbors** - Sessions will show local address 0.0.0.0 and fail to establish
2. **MD5 key mismatch** - Check logs for "MD5 digest match Failure" messages
3. **Incorrect SAP notation** - Use colon (`:`) not dot (`.`) for VLAN IDs
4. **Forgetting to commit and save** - Changes are not persistent without `admin save`
5. **Route leaking not configured** - Cache prefixes won't reach free peers without proper vrf-import/export
6. **Prefix-list ranges too restrictive** - e.g., /24 exact won't match /27 cache prefixes
7. **Missing VALID-INTERNET prefix-lists** - Required for accepting general internet routes

## Performance Notes

- Nokia SR-OS can handle large route tables efficiently
- MP-BGP route leaking adds minimal overhead
- Use `| no-more` to prevent pagination in automated scripts
- Use `| match` to filter output instead of piping to grep when possible
