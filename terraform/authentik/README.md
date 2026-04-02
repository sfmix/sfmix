# Authentik Terraform Configuration

Infrastructure-as-code for the SFMIX Authentik SSO instance at `login.sfmix.org`.

## What's managed

- **Sources**: GitHub and PeeringDB OAuth federation
- **Groups**: Admin group (default: IX Administrators), authentik Admins, ASN-based groups
- **Property mappings**: Custom user/group mappings for both sources, custom `groups` scope
- **Providers**: Grafana and IXP Participant Portal (OIDC)
- **Applications**: Grafana, Portal
- **Policies**: Grafana access restriction (admin group membership)

Default flows, stages, and built-in scope mappings are referenced as **data sources** (read-only) — they remain managed by authentik's internal blueprints.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- SSH access to `login.sfmix.org` (for retrieving secrets during initial setup)
- Membership in the admin group (default: **IX Administrators**) in Authentik

## Usage

There is no persistent state file or long-lived API token. Each session creates
an ephemeral token, fetches secrets from the running instance, and imports
everything fresh via `imports.tf`.

### 1. Set up credentials

`setup-env.sh` SSHs to `login.sfmix.org`, creates a short-lived API token
for your Authentik user, and fetches the four OAuth client secrets:

```bash
cd terraform/authentik/
source setup-env.sh            # uses $(whoami) as Authentik username
source setup-env.sh jof        # or pass an explicit username
```

You must have SSH access to `login.sfmix.org` and IX Administrator privileges.

### 2. Initialize (first time or after provider changes)

```bash
terraform init
```

### 3. Plan and apply

Existing resources are automatically imported via `import` blocks in
`imports.tf` — no separate import step is needed.

```bash
terraform plan
terraform apply
```

## Common tasks

### Adding a new OIDC application

1. Add a `variable` for the new client secret in `variables.tf`
2. Add an `authentik_provider_oauth2` resource in `providers.tf`
3. Add an `authentik_application` resource in `applications.tf`
4. Add any custom scope mappings in `property_mappings.tf`
5. Add any access policies in `policies.tf`
6. `terraform apply`

### Importing a resource created in the UI

If someone creates a resource in the Authentik admin UI and you want to bring it under Terraform management:

1. Find the resource's UUID/slug in the Authentik admin UI (or via the API)
2. Write the corresponding `.tf` resource block
3. Add an `import` block in `imports.tf`:
   ```hcl
   import {
     to = authentik_group.new_group
     id = "<uuid>"
   }
   ```
4. Run: `terraform plan` to verify it matches

> **Note**: Sources and applications use **slug** as the import ID. Groups, property mappings, providers, policies, and bindings use **UUID**. Providers use their **numeric ID**.

### ASN groups

ASN groups (e.g. `as12276`, `as64500`) are created dynamically by PeeringDB source enrollment and are **not managed by Terraform**. They won't appear in `terraform plan` and won't be affected by `terraform apply`.

## File layout

| File                   | Purpose                                                        |
|------------------------|----------------------------------------------------------------|
| `setup-env.sh`         | Source to create ephemeral API token and fetch secrets          |
| `versions.tf`          | Provider version constraint                                    |
| `variables.tf`         | Sensitive input variables (secrets)                            |
| `data.tf`              | Read-only references to default/managed objects                |
| `groups.tf`            | User groups                                                    |
| `property_mappings.tf` | Custom source and scope mappings                               |
| `flows.tf`             | Custom authentication flow (source-only, no username/password) |
| `brands.tf`            | SFMIX brand styling for login.sfmix.org                        |
| `sources.tf`           | GitHub + PeeringDB OAuth sources                               |
| `providers.tf`         | OIDC providers (Grafana, Portal)                               |
| `applications.tf`      | Application definitions                                        |
| `policies.tf`          | Access policies and bindings                                   |
| `imports.tf`           | Declarative import blocks (maps live resources to TF state)    |

## Security notes

- **No persistent credentials**: `setup-env.sh` creates an ephemeral API token per session. Secrets are held only in shell environment variables.
- **No persistent state**: The `.tfstate` file is gitignored and ephemeral. Each run imports fresh via `imports.tf`.
- **Secrets** are passed via `TF_VAR_*` environment variables — never committed to git.
- ASN groups (e.g. `as12276`) are created dynamically by PeeringDB enrollment and are **not** managed by Terraform.
