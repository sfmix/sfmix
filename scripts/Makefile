.PHONY: help
.DEFAULT_GOAL := help

help:
	@echo "Available Makefile targets: "
	@echo "  setup"
	@echo "  new_participant"

setup:
	pipenv sync

new_participant:
	pipenv run ./new_participant.py

route_server_parity:
	pipenv run ./route_server_parity.py

mac_discovery:
	@echo "Please input or set NETBOX_API_TOKEN token for the mac_discovery user."
	@echo ""
	@echo "Copy from here: https://netbox.sfmix.org/users/tokens/10/"
	@echo ""
	@if [ -z "$${NETBOX_API_TOKEN}" ]; then \
		read -p "Netbox API Token for mac_discovery: " NETBOX_API_TOKEN; \
	fi; \
	NETBOX_API_TOKEN=$$NETBOX_API_TOKEN \
		NETBOX_API_ENDPOINT=https://netbox.sfmix.org/ \
		pipenv run ./mac_discovery.py
