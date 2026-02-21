# btest-rs Role

Deploys [btest-rs](https://github.com/jof/btest-rs) server as a systemd service. btest-rs implements the MikroTik bandwidth-test protocol, supporting TCP and UDP modes with multi-connection support.

## Requirements

- Debian/Ubuntu target host (x86_64)

## Role Variables

```yaml
btest_rs_port: 2000                                # TCP control port and UDP port start
btest_rs_max_sessions: 100                         # Maximum concurrent sessions
btest_rs_version: "v0.1.0"                         # GitHub release tag
btest_rs_arch: "x86_64-unknown-linux-gnu"          # Binary architecture
```

## Dependencies

None

## Example Playbook

```yaml
- hosts: speedtest_servers
  roles:
    - btest_rs
```

## Usage

Test from a MikroTik device:

```
/tool bandwidth-test snappy.sfmix.org protocol=tcp direction=receive duration=10s
/tool bandwidth-test snappy.sfmix.org protocol=udp direction=receive duration=10s remote-udp-tx-size=1500
```

## Firewall

The following ports must be open:

- **TCP 2000**: Control/handshake and TCP data
- **UDP 2000-2356**: UDP data ports (port range = udp-port-start through udp-port-start + max-sessions + 256)

## Notes

- Downloads prebuilt binary from GitHub releases
- Service automatically restarts on failure
- Listens on all interfaces (0.0.0.0)
- For best performance, ensure network tuning is applied (see snappy role)
