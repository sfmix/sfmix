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

1. **Create a dedicated Slack app** (https://api.slack.com/apps → *Create New App* →
   *From scratch*). Name it e.g. `SFMIX Alertmanager`.
2. Under **OAuth & Permissions**, add the `chat:write` bot scope, then
   *Install to Workspace*. Copy the **Bot User OAuth Token** (`xoxb-…`).
3. **Create the channels** and invite the bot to each (it can only post where it
   is a member): `/invite @SFMIX Alertmanager` in each of
   `#sfmix-alerts-critical`, `#sfmix-alerts`, `#sfmix-alerts-info`
   (or repoint `alertmanager_slack_channels` at whatever channels you prefer —
   set all three the same to collapse the split into one channel).
4. **Store the token in the vault** — in `inventory/group_vars/all.yml`:

   ```
   ansible-vault encrypt_string --vault-password-file ~/.sfmix_ansible_vault \
     'xoxb-your-token-here' --name 'alertmanager_slack_bot_token'
   ```

   Paste the resulting `alertmanager_slack_bot_token: !vault | …` block in.

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
