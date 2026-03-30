# Deploy Portal

See `portal/README.md` for full architecture, secrets, verification, and troubleshooting docs.

## Steps

1. Run the Ansible playbook:
```bash
cd /home/jof/src/sfmix/sfmix/ansible && pipenv run ansible-playbook deploy_portal.playbook.yml --vault-password-file ~/.sfmix_ansible_vault
```

2. Verify NetBox cache is populating:
```bash
ssh web.sfmix.org "sudo docker-compose -f /opt/ixp_portal/docker-compose.yml logs --tail 20 2>&1 | grep -iE 'netbox|error'"
```
Expected: `NetBox cache refreshed: NN tenants, NN IPs, NN ports`

3. Smoke test:
```bash
ssh web.sfmix.org "curl -s -o /dev/null -w '%{http_code}' -H 'Host: portal.sfmix.org' http://localhost:8000/login/"
```
Expected: `200`
