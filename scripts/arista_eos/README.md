# Arista EOS Scripts

## LldpDomAgent

An [EOS SDK](https://aristanetworks.github.io/EosSdk/) agent that reads optical
RX power (DOM) from every transceiver and advertises it via LLDP so the remote
device can see how well its transmit light is being received.

### How it works

The agent polls `show interfaces transceiver detail` every 30 seconds and
injects two [LLDP-MED](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#LLDP-MED)
TLVs (OUI `00:12:BB` / TIA) on every interface that has DOM data:

| Subtype | Name         | Payload |
|---------|--------------|---------|
| 1       | Capabilities | Inventory bit set, device type Network Connectivity |
| 11      | Asset ID     | `Optical RX dBm: -2.05` or `/`-separated multi-lane |

The Capabilities TLV is required so that remote `lldpd` implementations
recognise the device as LLDP-MED capable and parse the Asset ID.

On the remote side (e.g. VyOS, any Linux running `lldpd`), the value shows up
as a standard LLDP-MED Inventory field:

```
$ lldpcli show neighbors details ports eth4
  LLDP-MED:
    Inventory:
      Asset ID:     Optical RX dBm: -2.04
```

### Deployment

Copy the script to the switch and configure it as a daemon:

```
switch# copy scp://user@host/path/to/LldpDomAgent flash:
switch# configure
switch(config)# daemon LldpDomAgent
switch(config-daemon)# exec /mnt/flash/LldpDomAgent
switch(config-daemon)# no shutdown
```

The poll interval defaults to 30 seconds (matching the LLDP tx-interval).
To change it at runtime:

```
switch(config-daemon)# option POLL_INTERVAL value 60
```

### Verification

```
! Count interfaces with Asset ID TLVs:
switch# show lldp local-info | grep 'OUI 00-12-BB, subtype 11' | wc -l

! View TLVs on a specific interface:
switch# show lldp local-info Ethernet1/1
```

### Logs

The agent logs to syslog (facility `LOCAL4`, ident `LldpDomAgent`):

```
switch# bash grep LldpDomAgent /var/log/messages | tail
```

### Caveats

- **TLVs are scoped per SDK agent name.** If you rename the daemon or change
  the `eossdk.Sdk()` name, orphaned TLVs from the old name will persist.
  To clean them up, create a temporary agent with the old name and call
  `tx_tlv_del` for each interface/subtype.
- **Do not inject IEEE 802.1 TLVs** (OUI `00:80:C2`). EOS manages those
  natively and the SDK will SIGABRT.
- The executable must be `chmod +x`.
