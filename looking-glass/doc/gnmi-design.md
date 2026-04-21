# gNMI Backend Design

## Overview

Replace platform-specific backends (Arista eAPI, Nokia NETCONF) with a unified gNMI backend for state queries. This provides:

- **Unified protocol** - same gRPC/gNMI client for all vendors
- **OpenConfig models** - vendor-neutral YANG models where available
- **Better performance** - binary protobuf vs XML/JSON text
- **Streaming subscriptions** - future capability for real-time updates

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     DevicePool                               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ GnmiDriver  │  │ GnmiDriver  │  │ GnmiDriver  │  ...    │
│  │ (Nokia)     │  │ (Arista)    │  │ (Juniper?)  │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│         └────────────────┼────────────────┘                 │
│                          │                                  │
│                   ┌──────▼──────┐                           │
│                   │ GnmiClient  │                           │
│                   │ (tonic)     │                           │
│                   └─────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

## gNMI Paths by Resource

### Interfaces Status

| Vendor | gNMI Path | Model |
|--------|-----------|-------|
| OpenConfig | `/interfaces/interface[name=*]/state` | openconfig-interfaces |
| Nokia native | `/state/port` | nokia-state |
| Arista native | `/Sysdb/interface/status/eth/phy/slice/1/intfStatus/*` | Arista EOS |

**Recommendation**: Use OpenConfig paths where supported, fall back to native.

### BGP Summary

| Vendor | gNMI Path | Model |
|--------|-----------|-------|
| OpenConfig | `/network-instances/network-instance[name=default]/protocols/protocol[name=BGP]/bgp/neighbors/neighbor[*]/state` | openconfig-bgp |
| Nokia native | `/state/router[router-name=Base]/bgp/neighbor` | nokia-state |
| Arista native | `/Sysdb/routing/bgp/export/vrfBgpPeerInfoStatusV2/default/*` | Arista EOS |

### LLDP Neighbors

| Vendor | gNMI Path | Model |
|--------|-----------|-------|
| OpenConfig | `/lldp/interfaces/interface[name=*]/neighbors/neighbor[*]/state` | openconfig-lldp |

### MAC Address Table

| Vendor | gNMI Path | Model |
|--------|-----------|-------|
| OpenConfig | `/network-instances/network-instance[name=*]/fdb/mac-table/entries/entry[*]` | openconfig-network-instance |

### Optics/Transceivers

| Vendor | gNMI Path | Model |
|--------|-----------|-------|
| OpenConfig | `/components/component[name=*]/transceiver/state` | openconfig-platform-transceiver |

## Rust Implementation

### Dependencies

```toml
[dependencies]
tonic = "0.12"
prost = "0.13"
prost-types = "0.13"
tokio = { version = "1", features = ["full"] }

[build-dependencies]
tonic-build = "0.12"
```

### Proto Files

Need gNMI proto definitions:
- `gnmi.proto` - core gNMI service
- `gnmi_ext.proto` - extensions

Source: https://github.com/openconfig/gnmi/tree/master/proto/gnmi

### Client Structure

```rust
pub struct GnmiClient {
    inner: gnmi::g_nmi_client::GNmiClient<tonic::transport::Channel>,
    target: String,
}

impl GnmiClient {
    pub async fn connect(host: &str, port: u16, insecure: bool) -> Result<Self> {
        let endpoint = if insecure {
            format!("http://{}:{}", host, port)
        } else {
            format!("https://{}:{}", host, port)
        };
        let channel = tonic::transport::Channel::from_shared(endpoint)?
            .connect()
            .await?;
        let inner = gnmi::g_nmi_client::GNmiClient::new(channel);
        Ok(Self { inner, target: host.to_string() })
    }

    pub async fn get(&mut self, paths: &[&str]) -> Result<gnmi::GetResponse> {
        let path_elems: Vec<gnmi::Path> = paths.iter()
            .map(|p| parse_gnmi_path(p))
            .collect();
        
        let request = gnmi::GetRequest {
            path: path_elems,
            r#type: gnmi::get_request::DataType::State as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            ..Default::default()
        };
        
        let response = self.inner.get(request).await?;
        Ok(response.into_inner())
    }

    pub async fn capabilities(&mut self) -> Result<gnmi::CapabilityResponse> {
        let request = gnmi::CapabilityRequest::default();
        let response = self.inner.capabilities(request).await?;
        Ok(response.into_inner())
    }
}
```

### Driver Interface

```rust
pub struct GnmiDriver {
    config: DeviceConfig,
    vendor: Vendor,
}

#[derive(Clone, Copy)]
pub enum Vendor {
    Nokia,
    Arista,
    // Future: Juniper, Cisco, etc.
}

impl GnmiDriver {
    fn interfaces_path(&self) -> &str {
        match self.vendor {
            Vendor::Nokia => "/state/port",
            Vendor::Arista => "/interfaces/interface/state",
        }
    }
    
    fn parse_interfaces(&self, response: &gnmi::GetResponse) -> Vec<InterfaceStatus> {
        match self.vendor {
            Vendor::Nokia => self.parse_nokia_interfaces(response),
            Vendor::Arista => self.parse_arista_interfaces(response),
        }
    }
}

#[async_trait]
impl DeviceDriver for GnmiDriver {
    async fn execute(&self, command: &Command) -> Result<CommandResult> {
        let mut client = GnmiClient::connect(
            &self.config.host,
            self.config.gnmi_port.unwrap_or(57400),
            self.config.gnmi_insecure.unwrap_or(false),
        ).await?;
        
        let output = match (&command.verb, &command.resource) {
            (Verb::Show, Resource::InterfacesStatus) => {
                let response = client.get(&[self.interfaces_path()]).await?;
                CommandOutput::InterfacesStatus(self.parse_interfaces(&response))
            }
            // ... other resources
        };
        
        Ok(CommandResult { output, cached_until: None })
    }
}
```

## Configuration Changes

```yaml
devices:
  - name: cr1.sjc01.transit.sfmix.org
    platform: nokia_sros
    host: management.cr1.sjc01.transit.sfmix.org
    # New gNMI options:
    gnmi_port: 57400          # default: 57400
    gnmi_insecure: true       # default: false (use TLS)
    gnmi_skip_verify: false   # default: false (verify TLS cert)
    
  - name: switch01.sfo02.sfmix.org
    platform: arista_eos
    host: switch01.sfo02.sfmix.org
    gnmi_port: 6030           # Arista default
    gnmi_insecure: false
```

## Migration Path

1. **Phase 1**: Add gNMI client library and proto generation
2. **Phase 2**: Implement GnmiDriver with Nokia support
3. **Phase 3**: Test on cr1.scl02.transit (verify it bypasses NETCONF bug)
4. **Phase 4**: Add Arista gNMI support
5. **Phase 5**: Deprecate NETCONF/eAPI backends (keep as fallback)

## Device Configuration

### Nokia SR-OS

```
configure system grpc admin-state enable
configure system grpc allow-unsecure-connection  # or configure TLS
configure system grpc gnmi admin-state enable
configure system grpc gnmi auto-config-save true
configure system security user-params local-user user "looking-glass" access grpc true
configure system security aaa local-profiles profile "default" grpc rpc-authorization gnmi-capabilities-request true
configure system security aaa local-profiles profile "default" grpc rpc-authorization gnmi-get-request true
configure system security aaa local-profiles profile "default" grpc rpc-authorization gnmi-subscribe-request true
```

### Arista EOS

```
management api gnmi
   transport grpc default
      port 6030
   provider eos-native
```

Or with OpenConfig:

```
management api gnmi
   transport grpc default
   provider eos-native
   provider openconfig
```

## Testing

```bash
# Test with gnmic CLI tool
gnmic -a cr1.sjc01.transit.sfmix.org:57400 \
      -u looking-glass -p "$PASSWORD" \
      --insecure \
      get --path /state/port

gnmic -a switch01.sfo02.sfmix.org:6030 \
      -u looking-glass -p "$PASSWORD" \
      --insecure \
      get --path /interfaces/interface/state
```

## Estimated Effort

| Task | Estimate |
|------|----------|
| Proto generation setup | 2 hours |
| GnmiClient implementation | 4 hours |
| Nokia GnmiDriver | 4 hours |
| Arista GnmiDriver | 4 hours |
| Config schema updates | 1 hour |
| Testing & debugging | 4 hours |
| **Total** | **~19 hours** |

## References

- [gNMI Specification](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md)
- [OpenConfig YANG Models](https://github.com/openconfig/public)
- [Nokia gNMI Documentation](https://documentation.nokia.com/sr/25-3/sr-cli-reference/gnmi-commands.html)
- [Arista gNMI Guide](https://aristanetworks.github.io/openmgmt/configuration/gnmi/)
- [gnmic CLI tool](https://gnmic.openconfig.net/)
