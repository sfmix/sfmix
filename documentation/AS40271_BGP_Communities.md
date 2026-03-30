# AS40271 BGP Communities for SFMIX Transit Service

Since we pretty much only have modern routers internally, we just use BGP Large Communities.

## Informational (tagged as they are ingested)

These are used for informational purposes and are not accepted from outside.

### Internal Routes
- `40271:1500:1` -- SFMIX Transit Internal Infrastructure Routes

### Peer Type ID: 40271:1900

- `40271:1900:0` -- SFMIX (Transit) Infrastructure
- `40271:1900:1` -- SFMIX Transit - Free - User
- `40271:1900:2` -- SFMIX Transit - Paid - Upstream Transit
- `40271:1900:3` -- SFMIX Transit - Free - Peers
- `40271:1900:4` -- SFMIX Transit - Paid - User
- `40271:1900:5` -- SFMIX Transit - Hosted Cache
 
### Peer ASN: 40271:1901

- `40271:1901:[peer ASN]` -- Peer ASN

### PRKI state: 40271:1902

- `40271:1902:0` -- RPKI Valid
- `40271:1902:1` -- RPKI Unknown
- `40271:1902:2` -- RPKI Invalid (guess we'd expose this on a seperate looking glass?)

### Location ID: 40271:1984

Our [SFMIX Site Code from our public list of locations](https://sfmix.org/locations/)

- `40271:1984:[site code]`

## Traffic engineering (externally-signallable flags to control propagation)

These are used for propagation control and are accepted from downstream users to control propagation scope.

### Don't Propagate to ASN XXX: 40271:2000

- `40271:2000:[peer ASN]` -- Don't propagate to ASN `peer ASN`

### Don't Propagate to peer type: 40271:2001

- `40271:2001:0` -- Don't propagate to SFMIX Transit Infrastructure
- `40271:2001:1` -- Don't propagate to SFMIX Transit Free Users
- `40271:2001:2` -- Don't propagate to SFMIX Transit Paid Upstream Transits
- `40271:2001:3` -- Don't propagate to SFMIX Transit Free Peers
- `40271:2001:4` -- Don't propagate to SFMIX Transit Paid Users
- `40271:2001:5` -- Don't propagate to SFMIX Transit Hosted Caches

### Edge Blackhole: 40271:2666

- `40271:2666:666` -- Blackhole at edge
