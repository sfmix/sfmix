# LibreSpeed Role

Deploys LibreSpeed (speedtest-rust) as a Docker container for network speed testing.

## Requirements

- Docker must be installed on the target host
- `community.docker` Ansible collection

## Role Variables

```yaml
librespeed_listen_port: 8080              # Port the container listens on (localhost only)
librespeed_server_name: "SFMIX - San Francisco, CA"  # Server name displayed in UI
librespeed_url_path: "/librespeed"        # URL path for nginx routing

# Performance tuning (balanced for BBR)
librespeed_dl_duration: "20"              # Download test duration in seconds
librespeed_ul_duration: "20"              # Upload test duration in seconds
librespeed_dl_streams: "8"                # Parallel download streams
librespeed_ul_streams: "4"                # Parallel upload streams
librespeed_stream_delay: "200"            # Delay between streams in ms
librespeed_chunk_size: "150"              # Download chunk size in KB
```

## Dependencies

None

## Example Playbook

```yaml
- hosts: speedtest_servers
  roles:
    - librespeed
```

## Notes

- Container runs on localhost only (127.0.0.1)
- Requires nginx reverse proxy for external access
- Assets are stored in `/var/lib/librespeed/assets`
- Configuration stored in `/etc/librespeed.toml`
