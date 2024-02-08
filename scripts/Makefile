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
