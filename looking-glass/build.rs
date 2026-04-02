use std::collections::BTreeMap;
use serde::Deserialize;

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
struct CommandTemplate {
    verb: String,
    resource: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    address_family: Option<String>,
}

const VALID_VERBS: &[&str] = &["show", "ping", "traceroute"];
const VALID_RESOURCES: &[&str] = &[
    "interfaces_status",
    "interface_detail",
    "bgp_summary",
    "bgp_neighbor",
    "mac_address_table",
    "arp_table",
    "nd_table",
    "lldp_neighbors",
    "optics",
    "optics_detail",
    "participants",
    "vxlan_vtep",
    "network_reachability",
    "help",
];
const VALID_AF: &[&str] = &["ipv4", "ipv6"];

fn validate_node(path: &str, node: &GrammarNode) {
    // Every non-_arg node should have help text
    if node.help.is_none() && !path.ends_with("._arg") {
        eprintln!("  warning: {path} has no help text");
    }

    // A node must have at least one of: command, builtin, or children
    if node.command.is_none() && node.builtin.is_none() && node.children.is_none() {
        panic!("{path}: node has no command, builtin, or children (unreachable leaf)");
    }

    if let Some(ref tpl) = node.command {
        assert!(
            VALID_VERBS.contains(&tpl.verb.as_str()),
            "{path}: invalid verb '{}'",
            tpl.verb
        );
        assert!(
            VALID_RESOURCES.contains(&tpl.resource.as_str()),
            "{path}: invalid resource '{}'",
            tpl.resource
        );
        if let Some(ref af) = tpl.address_family {
            assert!(
                VALID_AF.contains(&af.as_str()),
                "{path}: invalid address_family '{af}'"
            );
        }
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
