# iperf3 Role

Deploys iperf3 server as a systemd service for network performance testing.

## Requirements

- Debian/Ubuntu target host
- iperf3 package available in apt repositories

## Role Variables

```yaml
iperf3_port: 5201                         # Port for iperf3 server to listen on
```

## Dependencies

None

## Example Playbook

```yaml
- hosts: speedtest_servers
  roles:
    - iperf3
```

## Usage

Test from a client:

```bash
# Download test (server -> client)
iperf3 -c snappy.sfmix.org -R -t 30

# Upload test (client -> server)
iperf3 -c snappy.sfmix.org -t 30

# Parallel streams (4x)
iperf3 -c snappy.sfmix.org -R -P 4 -t 30
```

## Notes

- iperf3 runs as a systemd service
- Service automatically restarts on failure
- Listens on all interfaces (0.0.0.0)
- For best performance, ensure network tuning is applied (see snappy role)
