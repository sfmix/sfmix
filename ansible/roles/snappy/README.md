# Snappy Speed Test Server Role

Ansible role providing common infrastructure for the snappy.sfmix.org speed test server. This role orchestrates network tuning, BGP peering, nginx reverse proxy, and multiple speed test implementations.

## Features

- **Network Tuning**: Optimized TCP/IP stack for gigabit+ throughput
- **BGP Peering**: BIRD BGP daemon for route exchange with IXP fabric
- **Nginx**: TLS-enabled reverse proxy with path-based routing
- **Firewall**: UFW configuration for speed test services
- **Speed Test Orchestration**: Imports and configures multiple speed test roles:
  - iperf3 (network performance testing)
  - xfr (modern iperf3 alternative with multi-client, QUIC, and UDP support)
  - LibreSpeed (web-based speed test)
  - TAUC Speed Test (alternative web speed test)
  - OpenSpeedTest (another web speed test option)

## Network Performance Optimizations

The role applies the following network tuning settings to achieve optimal throughput:

### TCP Buffer Sizes
- **rmem_max/wmem_max**: 64 MB (increased from default 208 KB)
- **tcp_rmem/tcp_wmem**: 4KB min, 1MB default, 64MB max
- Enables high-bandwidth WAN connections to utilize full link capacity

### Congestion Control
- **Algorithm**: BBR (Bottleneck Bandwidth and RTT)
- **Queue Discipline**: fq (Fair Queue)
- Provides superior throughput on high-latency and variable-latency networks
- Reduces retransmissions compared to traditional CUBIC

### Interface Tuning
- **TX Queue Length**: 10,000 (increased from 1,000)
- Prevents packet drops during traffic bursts on the virtio interface

### Performance Results
With these optimizations, snappy achieves:
- **Single stream**: ~730 Mbps (73% of 1 Gbps client link)
- **4 parallel streams**: ~840 Mbps (84% of 1 Gbps client link)
- **Improvement**: +75% over baseline configuration

## Variables

See `defaults/main.yml` for configurable variables:

```yaml
# BGP Configuration
snappy_bgp_local_asn: 64512
snappy_bgp_remote_asn: 40271
snappy_bgp_router_id: "149.112.115.26"
snappy_bgp_neighbor_v4: "149.112.115.27"
snappy_bgp_neighbor_v6: "2620:11a:b002::27"
snappy_bgp_interface: "ens18"

# Nginx/TLS Configuration
snappy_speedtest_domain: "snappy.sfmix.org"
```

## Speed Test Services

The snappy role orchestrates multiple speed test implementations by importing their respective roles:

- **iperf3** (port 5201): Command-line network performance testing
- **xfr** (port 5202): Modern iperf3 alternative with multi-client server, QUIC, and UDP
- **LibreSpeed** (`/librespeed/`): Rust-based web speed test
- **TAUC Speed Test** (`/tauc/`): Alternative web speed test
- **OpenSpeedTest** (`/openspeedtest/`): Another web speed test option

### Architecture

- Each speed test is implemented as a separate Ansible role
- Web-based tests run in Docker containers on localhost-only ports (8080, 8081, 8082)
- Nginx reverse proxy provides TLS termination and path-based routing
- iperf3 and xfr run as systemd services on ports 5201 and 5202 respectively

### Speed Test Configuration

Each speed test has its own role with independent configuration:
- `iperf3` role: See `roles/iperf3/defaults/main.yml`
- `xfr` role: See `roles/xfr/defaults/main.yml`
- `librespeed` role: See `roles/librespeed/defaults/main.yml`
- `tauc_speedtest` role: See `roles/tauc_speedtest/defaults/main.yml`
- `openspeedtest` role: See `roles/openspeedtest/defaults/main.yml`

**Note**: Web-based speed tests (JavaScript/HTTP) typically achieve 70-90% of iperf3 performance due to browser overhead. For maximum accuracy, use iperf3 directly.

## Tags

Run specific components:

```bash
# Apply only network tuning
ansible-playbook push_servers.playbook.yml --tags network,tuning

# Configure iperf3 only
ansible-playbook push_servers.playbook.yml --tags iperf3

# Configure xfr only
ansible-playbook push_servers.playbook.yml --tags xfr

# Deploy all speed tests
ansible-playbook push_servers.playbook.yml --tags speedtest

# Deploy specific speed test
ansible-playbook push_servers.playbook.yml --tags librespeed
ansible-playbook push_servers.playbook.yml --tags tauc
ansible-playbook push_servers.playbook.yml --tags openspeedtest

# Full snappy configuration
ansible-playbook push_servers.playbook.yml --tags snappy
```

## Requirements

- Debian/Ubuntu target host
- Kernel with BBR support (4.9+)
- Docker installed on target host
- Ansible collections:
  - `community.general`
  - `ansible.posix`
  - `community.docker`

## Role Dependencies

The snappy role imports the following roles:
- `iperf3` - iperf3 server deployment
- `xfr` - xfr speed test server
- `librespeed` - LibreSpeed web speed test
- `tauc_speedtest` - TAUC Speed Test
- `openspeedtest` - OpenSpeedTest

These roles must be present in your `roles/` directory.

## Network Tuning Technical Details

### Why BBR?
BBR (developed by Google) measures the actual delivery rate and RTT of the connection to find the optimal sending rate, rather than relying on packet loss as a congestion signal. This results in:
- Higher throughput on lossy networks
- Lower latency
- Better fairness between flows

### Sysctl Settings Applied
```
net.core.rmem_max = 67108864          # 64 MB RX buffer
net.core.wmem_max = 67108864          # 64 MB TX buffer
net.core.default_qdisc = fq           # Fair Queue
net.ipv4.tcp_congestion_control = bbr # BBR algorithm
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
```

Settings are persistent across reboots via:
- `/etc/sysctl.d/99-snappy-network-tuning.conf`
- `/etc/systemd/system/snappy-txqueuelen.service`

## Testing Performance

```bash
# Single stream upload test
iperf3 -c snappy.sfmix.org -R -t 30

# Parallel streams (4x)
iperf3 -c snappy.sfmix.org -R -P 4 -t 30

# Download test
iperf3 -c snappy.sfmix.org -t 30
```

## Troubleshooting

Check applied settings:
```bash
# Verify BBR is active
cat /proc/sys/net/ipv4/tcp_congestion_control

# Check buffer sizes
sysctl net.core.rmem_max net.core.wmem_max

# Verify TX queue length
ip link show ens18 | grep qlen
```

## References

- [BBR Congestion Control](https://queue.acm.org/detail.cfm?id=3022184)
- [Linux TCP Tuning](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
- [iperf3 Documentation](https://iperf.fr/)
