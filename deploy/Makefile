install:
	ansible-galaxy install -r requirements.yml

build:
	pipenv run ansible-playbook -i inventory network_devices/build_switch_configs.playbook.yml

diff:
	pipenv run ansible-playbook -i inventory network_devices/push_switch_configs.playbook.yml --diff --check

push:
	pipenv run ansible-playbook -i inventory network_devices/push_switch_configs.playbook.yml --diff

servers:
	pipenv run ansible-playbook -i inventory push_servers.playbook.yml --diff --ask-vault-pass

clean:
	rm -rf configs
	rm -rf .github_ssh_keys
