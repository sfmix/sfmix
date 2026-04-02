import os
import requests

GRAFANA_URL = "http://grafana:3000/"
GRAFANA_DATASOURCES_API = GRAFANA_URL + "api/datasources"
GRAFANA_USER = "admin"
GRAFANA_PASSWORD = "admin"

API_KEY_FILE = "/monitoring/librenms_grafana.api_key"
if not os.path.exists(API_KEY_FILE):
    raise Exception(f"No {API_KEY_FILE} file found")
else:
    with open(API_KEY_FILE) as f:
        LIBRENMS_GRAFANA_API_KEY = f.read().strip()

existing_datasources = requests.get(
    GRAFANA_DATASOURCES_API, auth=(GRAFANA_USER, GRAFANA_PASSWORD)
).json()
existing_datasource_names = [datasource["name"] for datasource in existing_datasources]

if "RRD" not in existing_datasource_names:
    requests.post(
        GRAFANA_DATASOURCES_API,
        auth=(GRAFANA_USER, GRAFANA_PASSWORD),
        json={
            "name": "RRD",
            "type": "grafana-simple-json-datasource",
            "url": "http://grafana_rrd_server:9000/",
            "access": "proxy",
            "basicAuth": False,
        },
    ).raise_for_status()
    print("Created Datasource: RRD API")
else:
    print("Datasource exists: RRD API")

if "LibreNMS API" not in existing_datasource_names:
    requests.post(
        GRAFANA_DATASOURCES_API,
        auth=(GRAFANA_USER, GRAFANA_PASSWORD),
        json={
            "name": "LibreNMS API",
            "type": "marcusolsson-json-datasource",
            "url": "http://librenms:8000/api/v0/",
            "access": "proxy",
            "basicAuth": False,
            "jsonData": {
                "httpHeaderName1": "X-Auth-Token",
            },
            "secureJsonData": {
                "httpHeaderValue1": LIBRENMS_GRAFANA_API_KEY,
            },
        },
    ).raise_for_status()
    print("Created Datasource: LibreNMS API")
else:
    print("Datasource exists: LibreNMS API")
