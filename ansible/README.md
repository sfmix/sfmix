# SFMIX Ansible

SFMIX-related deploy configuration and tools.
Mostly Ansible.

## Use

Most major workflows should be added into the `Makefile`.

Many aspects of the inventory refer to access paths towards servers and devices
that assume that this code will run on an [Ansible Control
Node](https://docs.ansible.com/ansible/latest/network/getting_started/basic_concepts.html#control-node)
which is located on a trusted SFMIX management network.
