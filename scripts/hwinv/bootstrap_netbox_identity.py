#!/usr/bin/env python3
"""One-time: create the scoped NetBox identity for the nightly inventory job.

  cd scripts && pipenv run python hwinv/bootstrap_netbox_identity.py /tmp/hwinv-token

Needs an admin-capable NETBOX_API_TOKEN (scripts/.env). Creates (idempotently)
user `hardware-inventory`, adds it to `view_all`, grants add/change/delete on
module/modulebay/moduletype/manufacturer and change on device, then mints a new
token and writes it to the given file (0600) -- it is never printed. Vault it:

  ansible-vault encrypt_string --vault-password-file ~/.sfmix_ansible_vault \\
    --stdin-name hardware_inventory_netbox_api_token < /tmp/hwinv-token
"""
import os
import secrets
import sys

import pynetbox

USER = "hardware-inventory"


def main() -> None:
    out = sys.argv[1]
    nb = pynetbox.api(os.environ["NETBOX_API_ENDPOINT"], token=os.environ["NETBOX_API_TOKEN"])

    u = nb.users.users.get(username=USER)
    if not u:
        u = nb.users.users.create(username=USER, password=secrets.token_urlsafe(32), is_active=True,
                                  first_name="Hardware", last_name="Inventory")
        print("created user", USER)

    view_all = nb.users.permissions.get(name="view_all")
    ids = [x.id for x in (view_all.users or [])]
    if u.id not in ids:
        view_all.update({"users": ids + [u.id]})
        print("added to view_all")

    for name, actions, types, desc in (
        ("hardware-inventory", ["add", "change", "delete"],
         ["dcim.module", "dcim.modulebay", "dcim.moduletype", "dcim.manufacturer"],
         "scripts/hardware_inventory.py: slots (module bays) and FRUs (modules)"),
        ("hardware-inventory-device", ["change"], ["dcim.device"],
         "scripts/hardware_inventory.py: chassis serial + hw custom fields"),
    ):
        if nb.users.permissions.get(name=name) is None:
            nb.users.permissions.create(name=name, actions=actions, object_types=types,
                                        users=[u.id], enabled=True, description=desc)
            print("created permission", name)

    # This NetBox doesn't return a generated key, so POST an explicit one.
    key = secrets.token_hex(20)
    nb.users.tokens.create(user=u.id, key=key, write_enabled=True,
                           description="nightly hardware_inventory job (netbox.sfo02)")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, key.encode())
    os.close(fd)

    check = pynetbox.api(os.environ["NETBOX_API_ENDPOINT"], token=key)
    print("token written to", out, "- modules visible:", check.dcim.modules.count())


if __name__ == "__main__":
    main()
