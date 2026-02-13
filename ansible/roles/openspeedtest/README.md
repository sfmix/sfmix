# OpenSpeedTest Role

Deploys OpenSpeedTest as a Docker container for network speed testing.

## Requirements

- Docker must be installed on the target host
- `community.docker` Ansible collection

## Role Variables

```yaml
openspeedtest_listen_port: 8082           # Port the container listens on (localhost only)
openspeedtest_url_path: "/openspeedtest" # URL path for nginx routing
```

## Dependencies

None

## Example Playbook

```yaml
- hosts: speedtest_servers
  roles:
    - openspeedtest
```

## Notes

- Container runs on localhost only (127.0.0.1)
- Requires nginx reverse proxy for external access
- Uses official image from Docker Hub (openspeedtest/latest)
- Container exposes port 3000 internally
