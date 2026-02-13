# TAUC Speed Test Role

Deploys TAUC Speed Test (roadrunnerspeed/tauc-speedtest) using docker-compose.

## Requirements

- Docker and docker-compose must be installed on the target host
- `community.docker` Ansible collection
- Git installed on target host

## Role Variables

```yaml
tauc_listen_port: 8081                    # Port the container listens on (localhost only)
tauc_url_path: "/tauc"                    # URL path for nginx routing
```

## Dependencies

None

## Example Playbook

```yaml
- hosts: speedtest_servers
  roles:
    - tauc_speedtest
```

## Notes

- Container runs on localhost only (127.0.0.1)
- Requires nginx reverse proxy for external access
- Clones repository to `/opt/tauc-speedtest` and builds locally using docker-compose
- No pre-built Docker image is available, so the role builds from source
