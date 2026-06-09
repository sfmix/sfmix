# Arista EOS Scripts

## LldpDomAgent

An [EOS SDK](https://aristanetworks.github.io/EosSdk/) agent that reads optical
RX power (DOM) from every transceiver and advertises it via LLDP so the remote
device can see how well its transmit light is being received.

### How it works

The agent polls `show interfaces transceiver dom` every 30 seconds (via the
eAPI Unix socket if available, otherwise FastCli subprocess) and injects the
full [LLDP-MED](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#LLDP-MED)
Inventory TLV set (OUI `00:12:BB` / TIA) on every LLDP-enabled interface that
has a transceiver with valid RX power data:

| Subtype | Name              | Payload                                                    |
|---------|-------------------|------------------------------------------------------------|
| 1       | Capabilities      | Inventory bit set, device type Network Connectivity        |
| 5       | Hardware Revision | `Photons`                                                  |
| 6       | Firmware Revision | `v1`                                                       |
| 7       | Software Revision | `LldpDomAgent`                                             |
| 8       | Serial Number     | `AS12276`                                                  |
| 9       | Manufacturer Name | `SFMIX`                                                    |
| 10      | Model Name        | `Internet Exchange`                                        |
| 11      | Asset ID          | `dBm:-2.05` or `dBm:-0.01/-0.87/-0.73/0.28` (multi-lane)   |

EOS receivers require the **complete set** of subtypes 1 + 5–11 to render any
of them in `show lldp neighbors detail`.  Omitting any subtype causes EOS to
silently drop all inventory data from the CLI output.

The Asset ID string uses the compact `dBm:` prefix (4 chars) to stay within
the 32-character TIA-1057 limit.  Worst-case 4-lane: 31 chars.

On a remote Arista switch:

```
switch# show lldp neighbors Ethernet1/1 detail
  - LLDP-MED Inventory Manufacturer Name TLV: "SFMIX"
  - LLDP-MED Inventory Model Name TLV: "Internet Exchange"
  - LLDP-MED Inventory Asset ID TLV: "dBm:-7.60/-8.20/-6.79/-6.52"
```

On VyOS / lldpd:

```
$ lldpcli show neighbors details ports eth4
  LLDP-MED:
    Inventory:
      Asset ID:     dBm:-2.04
```

### Deployment

Use the Ansible playbook (automatically scoped to Arista devices):

```
ansible-playbook deploy_lldp_dom_agent.playbook.yml --diff --vault-password-file ~/.sfmix_ansible_vault
```

Or manually copy the script to the switch and configure it as a daemon:

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
! Check agent status:
switch# show daemon LldpDomAgent

! Count interfaces with Asset ID TLVs:
switch# show lldp local-info | grep 'OUI 00-12-BB, subtype 11' | wc -l

! View TLVs on a specific interface (sender side):
switch# show lldp local-info Ethernet1/1 | tail -15

! View received Asset ID on remote switch:
switch# show lldp neighbors Ethernet1/1 detail | grep 'Asset ID'
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
- **switch01.sfo02** has corrupted SDK state from an earlier crash loop.
  The agent is disabled there and needs a full switch reboot to clear it.
- Dark ports (RX power ≤ −30 dBm) and interfaces without DOM data are
  automatically skipped.  TLVs are cleaned up when a port goes dark.
- The executable must be `chmod +x`.
