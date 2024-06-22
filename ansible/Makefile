all: pipenv install

pipenv:
	pipenv sync

install:
	pipenv run ansible-galaxy install -r requirements.yml

net_build:
	pipenv run ansible-playbook -i inventory --vault-password-file /opt/sfmix/ansible_vault_secret sfmix_network_devices.build.playbook.yml

net_diff:
	pipenv run ansible-playbook -i inventory --vault-password-file /opt/sfmix/ansible_vault_secret sfmix_network_devices.push.playbook.yml --check --diff

net_push:
	pipenv run ansible-playbook -i inventory --vault-password-file /opt/sfmix/ansible_vault_secret sfmix_network_devices.push.playbook.yml --diff

dns:
	pipenv run ansible-playbook -i inventory --vault-password-file /opt/sfmix/ansible_vault_secret push_servers.playbook.yml --diff --limit localhost,dns --tags dns

servers:
	pipenv run ansible-playbook -i inventory push_servers.playbook.yml --vault-password-file /opt/sfmix/ansible_vault_secret --diff

clean:
	rm -rf .github_ssh_keys
	rm -rf sfmix_network_devices.configs
