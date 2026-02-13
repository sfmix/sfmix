# Snappy Speed Test Server Role

Ansible role to configure the snappy.sfmix.org speed test server with optimized network performance settings.

## Features

- **Network Tuning**: Optimized TCP/IP stack for gigabit+ throughput
- **iperf3 Server**: Network performance testing
- **LibreSpeed**: Web-based speed test
- **BGP Peering**: BIRD BGP daemon for route exchange
- **Nginx**: TLS-enabled web server

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
snappy_bgp_interface: "ens18"        # Network interface for BGP peering
snappy_iperf3_port: 5201             # iperf3 server port

# LibreSpeed web speed test
snappy_speedtest_listen_port: 8080   # LibreSpeed port
snappy_speedtest_domain: "snappy.sfmix.org"

# LibreSpeed performance tuning (optimized for gigabit+ connections)
snappy_speedtest_dl_duration: "30"   # Download test duration (seconds)
snappy_speedtest_ul_duration: "30"   # Upload test duration (seconds)
snappy_speedtest_dl_streams: "10"    # Parallel download streams (default: 6)
snappy_speedtest_ul_streams: "8"     # Parallel upload streams (default: 3)
snappy_speedtest_stream_delay: "200" # Delay between streams (ms)
snappy_speedtest_chunk_size: "250"   # Download chunk size (KB)
```

### LibreSpeed Performance Notes

The default LibreSpeed configuration (6 download streams, 3 upload streams, 15s duration) is optimized for typical home connections (100-500 Mbps). For gigabit+ speeds, the optimized settings above provide:

- **More parallel streams**: 10 download / 8 upload streams saturate high-bandwidth links
- **Longer test duration**: 30 seconds allows TCP to fully ramp up on WAN links
- **Larger chunks**: 250 KB chunks reduce HTTP overhead on fast connections
- **Lower stream delay**: 200ms starts streams faster for quicker saturation

**Note**: Web-based speed tests (JavaScript/HTTP) typically achieve 70-90% of iperf3 performance due to browser overhead. For maximum accuracy, use iperf3 directly.

## Tags

Run specific components:

```bash
# Apply only network tuning
ansible-playbook push_servers.playbook.yml --tags network,tuning

# Configure iperf3 only
ansible-playbook push_servers.playbook.yml --tags iperf3

# Full snappy configuration
ansible-playbook push_servers.playbook.yml --tags snappy
```

## Requirements

- Debian/Ubuntu target host
- Kernel with BBR support (4.9+)
- `community.general` and `ansible.posix` collections

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
