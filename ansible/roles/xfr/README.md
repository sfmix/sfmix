# xfr Role

Deploys [xfr](https://github.com/lance0/xfr) server as a systemd service for network performance testing. xfr is a modern iperf3 alternative with multi-client server support, QUIC, and UDP modes.

## Requirements

- Debian/Ubuntu target host (x86_64)

## Role Variables

```yaml
xfr_port: "5202"                              # Port for xfr server to listen on
xfr_version: "latest"                         # GitHub release tag (e.g. "latest" or "download/v0.8.0")
xfr_arch: "x86_64-unknown-linux-musl"         # Binary architecture
```

## Dependencies

None

## Example Playbook

```yaml
- hosts: speedtest_servers
  roles:
    - xfr
```

## Usage

Test from a client:

```bash
# TCP test (client -> server)
xfr snappy.sfmix.org -p 5202

# Reverse / download test
xfr snappy.sfmix.org -p 5202 -R

# Parallel streams (4x)
xfr snappy.sfmix.org -p 5202 -P 4

# UDP test
xfr snappy.sfmix.org -p 5202 -u -b 1G

# QUIC test
xfr snappy.sfmix.org -p 5202 --quic
```

## Notes

- xfr runs as a systemd service
- Service automatically restarts on failure
- Supports multiple simultaneous clients (unlike iperf3)
- For best performance, ensure network tuning is applied (see snappy role)
