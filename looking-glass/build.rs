use std::collections::BTreeMap;
use serde::Deserialize;

/// Verb/Resource/AddressFamily are duplicated from command.rs so that build.rs
/// can validate grammar.yml at compile time (build scripts can't import crate types).
/// serde(rename_all) keeps them in sync — a YAML typo like "bogus_resource"
/// causes a serde deserialization failure here at build time.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Verb { Show, Ping, Traceroute }

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum Resource {
    InterfacesStatus, InterfaceDetail, BgpSummary, BgpNeighbor,
    MacAddressTable, ArpTable, NdTable, LldpNeighbors,
    Optics, OpticsDetail, Participants, VxlanVtep,
    NetworkReachability, Help,
}

#[derive(Deserialize)]
#[allow(dead_code)]
enum AddressFamily {
    #[serde(rename = "ipv4")] IPv4,
    #[serde(rename = "ipv6")] IPv6,
}

#[derive(Deserialize)]
struct GrammarFile {
    commands: BTreeMap<String, GrammarNode>,
}

#[derive(Deserialize)]
struct GrammarNode {
    #[serde(default)]
    help: Option<String>,
    #[serde(default)]
    children: Option<BTreeMap<String, GrammarNode>>,
    #[serde(default)]
    command: Option<CommandTemplate>,
    #[serde(default)]
    builtin: Option<String>,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct CommandTemplate {
    verb: Verb,
    resource: Resource,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    address_family: Option<AddressFamily>,
}

fn validate_node(path: &str, node: &GrammarNode) {
    if node.help.is_none() && !path.ends_with("._arg") {
        eprintln!("  warning: {path} has no help text");
    }

    // A node must have at least one of: command, builtin, or children
    if node.command.is_none() && node.builtin.is_none() && node.children.is_none() {
        panic!("{path}: node has no command, builtin, or children (unreachable leaf)");
    }

    if let Some(ref tpl) = node.command {
        if let Some(ref target) = tpl.target {
            assert!(
                target == "$arg",
                "{path}: target must be \"$arg\", got \"{target}\""
            );
        }
    }

    if let Some(ref children) = node.children {
        for (key, child) in children {
            validate_node(&format!("{path}.{key}"), child);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=config/grammar.yml");

    let yaml = std::fs::read_to_string("config/grammar.yml")
        .expect("could not read config/grammar.yml");
    let grammar: GrammarFile =
        serde_yaml::from_str(&yaml).expect("config/grammar.yml failed to parse");

    let mut node_count = 0;
    for (key, node) in &grammar.commands {
        validate_node(key, node);
        node_count += count_nodes(node);
    }

    eprintln!("grammar.yml validated: {} top-level commands, {node_count} total nodes", grammar.commands.len());
}

fn count_nodes(node: &GrammarNode) -> usize {
    let mut count = 1;
    if let Some(ref children) = node.children {
        for child in children.values() {
            count += count_nodes(child);
        }
    }
    count
}
