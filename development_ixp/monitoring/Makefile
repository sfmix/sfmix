up:
	docker compose pull
	docker compose up -d
	sudo iptables -t filter -F DOCKER-ISOLATION-STAGE-2
	@while [ "$$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/api/v0/)" != "401" ]; do \
		echo "Waiting for LibreNMS API..."; \
		sleep 1; \
	done
	-docker compose exec librenms lnms user:add admin --password=admin --role=admin
	-docker compose exec librenms lnms user:add grafana --password=grafana --role=global-read \
		&& GRAFANA_API_TOKEN=`openssl rand -hex 16` \
		&& USER_ID=`docker compose exec db mysql -uroot -D librenms -Bse "SELECT user_id FROM users WHERE username='grafana';"` \
		&& docker compose exec db mysql -uroot -D librenms -e \
			"INSERT INTO api_tokens \
				(user_id, token_hash, description) \
				VALUES ($$USER_ID, '$$GRAFANA_API_TOKEN', 'API Key for grafana');" \
		&& echo "GRAFANA_API_TOKEN=$$GRAFANA_API_TOKEN" \
		&& echo $$GRAFANA_API_TOKEN | tee librenms_grafana.api_key
	docker compose run bootstrap_grafana
	-docker compose exec librenms lnms scan 10.10.0.0/24
	-docker compose exec librenms lnms poller:discovery all
	-docker compose exec librenms lnms poller:poll all

down:
	docker compose down --volumes
