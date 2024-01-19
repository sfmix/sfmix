all: pipenv install

pipenv:
	pipenv sync

install:
	pipenv run ansible-galaxy install -r requirements.yml

build:
	pipenv run ansible-playbook -i inventory --vault-password-file /opt/sfmix/ansible_vault_secret sfmix_network_devices.build.playbook.yml

diff:
	pipenv run ansible-playbook -i inventory --vault-password-file /opt/sfmix/ansible_vault_secret sfmix_network_devices.push.playbook.yml --check --diff

push:
	pipenv run ansible-playbook -i inventory --vault-password-file /opt/sfmix/ansible_vault_secret sfmix_network_devices.push.playbook.yml --diff

servers:
	pipenv run ansible-playbook -i inventory push_servers.playbook.yml --vault-password-file /opt/sfmix/ansible_vault_secret --diff

clean:
	rm -rf .github_ssh_keys
	rm -rf sfmix_network_devices.configs
