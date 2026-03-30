# Akvorado Ansible Role

This Ansible role deploys [Akvorado](https://github.com/akvorado/akvorado), a flow collector, enricher, and visualizer for network flow data (NetFlow v9, IPFIX, and sFlow).

## Overview

Akvorado receives network flows from routers, enriches them with interface names (via SNMP) and GeoIP information, and stores them in ClickHouse for analysis. It provides a web interface for querying and visualizing flow data.

The role deploys Akvorado using Docker Compose with the following components:
- **Akvorado**: Flow collector, enricher, and web console
- **ClickHouse**: Column-oriented database for flow storage
- **Apache Kafka**: Message queue for flow buffering
- **Zookeeper**: Coordination service for Kafka

## Requirements

- Debian/Ubuntu-based system
- Ansible 2.9+
- Python 3
- Docker support
- Minimum 8GB RAM (16GB+ recommended)
- 100GB+ disk space for flow data

### Ansible Collections

```bash
ansible-galaxy collection install community.docker
ansible-galaxy collection install community.general
```

## Role Variables

### Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `akvorado_version` | `latest` | Akvorado Docker image version |
| `akvorado_install_dir` | `/opt/akvorado` | Installation directory |
| `akvorado_data_dir` | `/var/lib/akvorado` | Data directory |
| `akvorado_config_dir` | `/etc/akvorado` | Configuration directory |

### HTTP Interface

| Variable | Default | Description |
|----------|---------|-------------|
| `akvorado_http_listen` | `0.0.0.0:8080` | HTTP listen address |
| `akvorado_http_external_url` | `http://{{ ansible_fqdn }}:8080` | External URL |

### Flow Collection

| Variable | Default | Description |
|----------|---------|-------------|
| `akvorado_flow_listen` | `0.0.0.0:2055` | Flow collector listen address (UDP) |
| `akvorado_flow_workers` | `4` | Number of flow processing workers |

### SNMP Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `akvorado_snmp_communities` | See defaults | SNMP communities for device polling |

Example:
```yaml
akvorado_snmp_communities:
  - community: "public"
    version: 2
  - community: "private"
    version: 3
```

### ClickHouse Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `akvorado_clickhouse_host` | `localhost` | ClickHouse host |
| `akvorado_clickhouse_port` | `9000` | ClickHouse native port |
| `akvorado_clickhouse_database` | `akvorado` | Database name |
| `akvorado_clickhouse_username` | `default` | Username |
| `akvorado_clickhouse_password` | `""` | Password (empty for no auth) |
| `clickhouse_version` | `24.1` | ClickHouse Docker image version |
| `clickhouse_memory_limit` | `16G` | Memory limit |

### Kafka Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `akvorado_kafka_brokers` | `["localhost:9092"]` | Kafka broker addresses |
| `akvorado_kafka_topic` | `akvorado-flows` | Kafka topic name |
| `kafka_version` | `3.6` | Kafka Docker image version |
| `kafka_heap_opts` | `-Xmx2G -Xms2G` | Kafka JVM heap settings |

### GeoIP Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `akvorado_enable_geoip` | `true` | Enable GeoIP enrichment |
| `akvorado_geoip_asn_database` | `""` | URL to ASN database (MaxMind format) |
| `akvorado_geoip_country_database` | `""` | URL to Country database |

### Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `akvorado_enable_orchestrator` | `true` | Enable orchestrator component |
| `akvorado_enable_console` | `true` | Enable web console |
| `akvorado_enable_inlet` | `true` | Enable flow inlet |
| `akvorado_docker_compose` | `true` | Deploy using Docker Compose |

## Dependencies

None.

## Example Playbook

### Basic Deployment

```yaml
---
- hosts: flow_collectors
  become: true
  roles:
    - role: akvorado
      vars:
        akvorado_http_external_url: "http://flows.example.com:8080"
        akvorado_snmp_communities:
          - community: "mysnmp"
            version: 2
```

### Production Deployment with GeoIP

```yaml
---
- hosts: flow_collectors
  become: true
  roles:
    - role: akvorado
      vars:
        akvorado_version: "1.11.2"
        akvorado_http_external_url: "https://flows.sfmix.org"
        akvorado_flow_listen: "0.0.0.0:2055"
        akvorado_flow_workers: 8
        
        akvorado_snmp_communities:
          - community: "{{ vault_snmp_community }}"
            version: 2
        
        clickhouse_memory_limit: "32G"
        kafka_heap_opts: "-Xmx4G -Xms4G"
        
        akvorado_enable_geoip: true
        akvorado_geoip_asn_database: "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&suffix=tar.gz"
        akvorado_geoip_country_database: "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&suffix=tar.gz"
```

### Multiple Kafka Brokers

```yaml
---
- hosts: flow_collectors
  become: true
  roles:
    - role: akvorado
      vars:
        akvorado_kafka_brokers:
          - "kafka1.example.com:9092"
          - "kafka2.example.com:9092"
          - "kafka3.example.com:9092"
```

## Router Configuration

### Cisco IOS/IOS-XE (NetFlow v9)

```
flow exporter AKVORADO
 destination <akvorado-ip>
 transport udp 2055
 template data timeout 60

flow monitor AKVORADO-MONITOR
 exporter AKVORADO
 record netflow ipv4 original-input

interface GigabitEthernet0/0
 ip flow monitor AKVORADO-MONITOR input
 ip flow monitor AKVORADO-MONITOR output
```

### Juniper (IPFIX)

```
set services flow-monitoring version-ipfix template AKVORADO flow-active-timeout 60
set services flow-monitoring version-ipfix template AKVORADO flow-inactive-timeout 30
set chassis fpc 0 sampling-instance AKVORADO
set forwarding-options sampling instance AKVORADO input rate 1000
set forwarding-options sampling instance AKVORADO family inet output flow-server <akvorado-ip> port 2055
set forwarding-options sampling instance AKVORADO family inet output flow-server <akvorado-ip> version-ipfix template AKVORADO
```

### Arista (sFlow)

```
sflow sample 10000
sflow destination <akvorado-ip>
sflow source-interface Management1
sflow run
```

## Accessing Akvorado

After deployment, access the web interface at:
- `http://<server-ip>:8080` (or your configured external URL)

The interface provides:
- Flow visualization and analysis
- Custom queries using ClickHouse SQL
- Traffic graphs and statistics
- Top talkers, protocols, ASNs, etc.

## Firewall Ports

The role automatically configures UFW if present:
- **TCP 8080**: Web interface
- **UDP 2055**: Flow collector (NetFlow/IPFIX/sFlow)

Additional ports used internally by Docker:
- **TCP 9000**: ClickHouse native protocol
- **TCP 9092**: Kafka
- **TCP 2181**: Zookeeper

## Maintenance

### View Logs

```bash
cd /opt/akvorado
docker compose logs -f akvorado
docker compose logs -f clickhouse
docker compose logs -f kafka
```

### Restart Services

```bash
cd /opt/akvorado
docker compose restart akvorado
docker compose restart
```

### Backup ClickHouse Data

```bash
tar -czf akvorado-backup-$(date +%Y%m%d).tar.gz /var/lib/akvorado/clickhouse
```

## Tags

- `akvorado`: Run all tasks
- `prerequisites`: Install dependencies only
- `directories`: Create directories only
- `configure`: Update configuration only
- `docker`: Deploy/update Docker containers
- `firewall`: Configure firewall only

Example:
```bash
ansible-playbook playbook.yml --tags configure
```

## Troubleshooting

### Check Service Status

```bash
cd /opt/akvorado
docker compose ps
```

### Verify Flow Reception

```bash
docker compose logs akvorado | grep -i "received flows"
```

### Check ClickHouse Tables

```bash
docker exec -it akvorado-clickhouse clickhouse-client
SELECT count() FROM akvorado.flows;
```

### Performance Tuning

For high flow rates (>50k flows/sec):
- Increase `akvorado_flow_workers` to 8-16
- Allocate more memory to ClickHouse (`clickhouse_memory_limit`)
- Use faster storage (SSD/NVMe)
- Increase Kafka heap (`kafka_heap_opts`)

## License

AGPLv3 (same as Akvorado)

## Author

SFMIX Network Operations
