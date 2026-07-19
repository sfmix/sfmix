# alertmanager role

Deploys Prometheus Alertmanager as a Docker container on the metrics host and
routes firing alerts to Slack in a colour-coded, per-severity format.

Prometheus (`:9090`) only *evaluates* alert rules — it shows their state on its
`/alerts` page and pushes firing alerts to an Alertmanager. Alertmanager
(`:9093`) is the separate service that groups, dedups, silences, and delivers
those alerts. This role provides that second half; the `alerting:` block in the
`prometheus` role points Prometheus at it.

## Alert metadata it relies on

The Prometheus rules already carry the labels/annotations this role routes and
renders on:

- `severity` label — `critical` | `warning` | `info` → per-channel routing + colour
- `component` label — `traffic` | `optics` | `power` → shown in the title, used for grouping
- `summary` / `description` annotations → Slack message body
- `dashboard` annotation → the "Dashboard" button link (falls back to Grafana home)

## One-time operator setup

Already done:

- The **SFMIX Alertmanager** Slack app is created and installed into the SFMIX
  workspace with the `chat:write` bot scope.
- Its bot token is vaulted as `alertmanager_slack_bot_token` in
  `inventory/group_vars/all.yml`.
- All severities currently route to a single channel, `#networkalerts`
  (`alertmanager_slack_channels`).

Still required before the first deploy:

- **Invite the bot to `#networkalerts`** — it can only post to channels it is a
  member of: `/invite @SFMIX Alertmanager` in that channel.

To split severities onto separate channels later, edit
`alertmanager_slack_channels` and invite the bot to each. To rotate the token,
re-encrypt and replace the vault block:

```
ansible-vault encrypt_string --vault-password-file ~/.sfmix_ansible_vault \
  'xoxb-new-token' --name 'alertmanager_slack_bot_token'
```

## Deploy

```
ansible-playbook --vault-password-file ~/.sfmix_ansible_vault \
  push_servers.playbook.yml --tags alertmanager
```

This runs the `prometheus` role too (same play), which picks up the new
`alerting:` block. Config, templates, and the token file all reload live via
SIGHUP — no metrics gap.

## Verify

- Alertmanager UI: `http://metrics.sfo02.sfmix.org:9093`
- Prometheus → Status → Runtime should list the Alertmanager as a discovered peer.
- Fire a test: `IXPTrafficAllTimeHigh` (severity `info`) is the easiest real one,
  or push a synthetic alert with `amtool`:

  ```
  amtool alert add test severity=warning component=optics \
    --alertmanager.url=http://metrics.sfo02.sfmix.org:9093 \
    --annotation=summary='test alert' --annotation=description='ignore me'
  ```

## Notes

- Delivery uses the Slack **Web API** (`chat.postMessage`) with the bot token,
  not a single-channel incoming webhook — that is what lets one app fan out to
  multiple channels. The token is rendered to `/opt/alertmanager/slack_bot_token`
  (mode 0600) and referenced via `credentials_file`, so it never lands in the
  world-readable `alertmanager.yml`.
- Message layout lives in `templates/slack.tmpl.j2`. Edit there and re-run the
  role to restyle notifications.
