## Command Grammar

The CLI command tree is defined declaratively in `config/grammar.yml`. A single tree-walking engine in `src/grammar.rs` uses this file to:

- **Parse** user input into structured `Command` values (with abbreviation support)
- **Generate completions** for Tab and `?` help in the interactive Telnet CLI

`build.rs` validates the grammar at compile time — invalid verbs, resources, or address families cause a build failure with a clear error message.

### Grammar YAML Structure

```yaml
commands:
  show:                              # keyword
    help: Display device information  # shown in ? help
    children:
      interfaces:
        help: Interface status summary
        command: { verb: show, resource: interfaces_status }  # leaf → Command
        children:
          status:
            help: Interface status summary (default)
            command: { verb: show, resource: interfaces_status }
          _arg:                      # positional argument slot
            name: "<name>"           # display name for help
            help: Specific interface (e.g. Ethernet1)
            command: { verb: show, resource: interface_detail, target: "$arg" }
```

Key concepts:
- **`children`**: nested keywords forming the command tree
- **`command`**: a leaf that produces a `Command` struct with `verb`, `resource`, optional `target` and `address_family`
- **`_arg`**: a special child that matches any user input as a positional argument; `target: "$arg"` substitutes the captured value
- **`builtin`**: for commands handled by the frontend directly (e.g. `help`, `quit`)
- **`optional: true`**: documentation hint that a keyword is optional in the path (e.g. `unicast` in `show bgp ipv6 unicast summary`)

Nodes can have both a `command` (making them a valid endpoint) and `children` (allowing further refinement). For example, `show interfaces` resolves to `interfaces_status` but also accepts `show interfaces status` or `show interfaces Ethernet1`.

## Adding a New Command

### Walkthrough: adding `show route-summary`

#### 1. Add the `Resource` variant

In `src/command.rs`, add the new variant to the `Resource` enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    // ... existing variants ...
    RouteSummary,       // ← new
}
```

The `serde(rename_all = "snake_case")` attribute means this variant maps to the string `"route_summary"` in YAML automatically.

#### 2. Mirror the variant in `build.rs`

`build.rs` has its own copy of the enum (build scripts can't import crate types). Add the same variant:

```rust
enum Resource {
    // ... existing variants ...
    RouteSummary,       // ← new
}
```

If you forget this step, `cargo build` fails immediately with a clear error listing all valid resource names.

#### 3. Add the grammar entry in `config/grammar.yml`

Add the new keyword under the `show` command tree:

```yaml
commands:
  show:
    children:
      # ... existing children ...
      route-summary:
        help: IP routing table summary
        command: { verb: show, resource: route_summary }
```

This single YAML stanza gives you:
- **Parsing**: `show route-summary` (and abbreviations like `sh ro`) resolves to the command
- **Tab completion**: pressing Tab after `show r` completes to `route-summary`
- **`?` help**: shows `route-summary    IP routing table summary` in context

For commands that take an argument, use `_arg`:

```yaml
      route-summary:
        help: IP routing table summary
        command: { verb: show, resource: route_summary }
        children:
          _arg:
            name: "<vrf>"
            help: Show routes for a specific VRF
            command: { verb: show, resource: route_summary, target: "$arg" }
```

#### 4. Add platform driver translations

Each backend driver must translate the new resource into platform-native CLI.

**`src/backend/arista_eos.rs`** — add a match arm in `translate()`:

```rust
(Verb::Show, Resource::RouteSummary) => match &command.target {
    Some(vrf) => format!("show ip route vrf {vrf} summary"),
    None => "show ip route summary".to_string(),
},
```

**`src/backend/nokia_sros.rs`** — same pattern:

```rust
(Verb::Show, Resource::RouteSummary) => "show router route-table summary".to_string(),
```

If a driver doesn't support the resource, return an error:

```rust
(Verb::Show, Resource::RouteSummary) => {
    anyhow::bail!("route-summary not supported on SR-OS")
}
```

#### 5. (Optional) Update policy rules

If the new command should be restricted, update your policy file. The default policy allows all `show` commands for authenticated users, so most new `show` resources work without policy changes.

If the new resource is port-scoped (requires ownership checks), add it to `Resource::is_port_scoped()` in `src/command.rs`.

#### Summary of files to touch

| File | Change |
|------|--------|
| `src/command.rs` | Add `Resource` variant (one line) |
| `build.rs` | Mirror the variant (one line) |
| `config/grammar.yml` | Add keyword + help + command template |
| `src/backend/arista_eos.rs` | Add `translate()` match arm |
| `src/backend/nokia_sros.rs` | Add `translate()` match arm |
| `src/command.rs` (optional) | Update `is_port_scoped()` if port-scoped |
| Policy file (optional) | Add rules if access should be restricted |

No changes are needed to the parser, completion engine, telnet/SSH/MCP frontends, or any test infrastructure — the grammar engine handles all of that.

## Testing

### Unit Tests

```bash
cargo test
```

47 tests covering:
- Grammar parsing and abbreviation (17 tests)
- Completion and tab-completion (5 tests)
- Policy evaluation with port ownership (10 tests)
- Rate limiting — per-user CPM, user independence, global concurrency (3 tests)
- IP-to-prefix rate key grouping — IPv4 /24, IPv6 /56 (4 tests)
- Device driver command translation (2 tests)
- Public policy defaults (6 tests)

### Integration Testing with Containerlab

A containerlab topology is provided for testing against real Arista EOS devices:

```bash
cd test/clab
sudo containerlab deploy -t lg-test.clab.yml
```

## Tech Stack

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `russh` | SSH client (device backend) and server (SSH frontend) |
| `ssh-key` | SSH key types, certificate parsing |
| `rmcp` | MCP server SDK (streamable HTTP) |
| `axum` | HTTP framework (MCP transport, middleware) |
| `clap` | CLI argument parsing |
| `serde` / `serde_yaml` | Configuration and grammar file parsing |
| `dashmap` | Concurrent per-user rate limit state |
| `tracing` | Structured logging |
| `thiserror` | Error type derivation |
