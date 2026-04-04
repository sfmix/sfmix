use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::command::{AddressFamily, Command, ParseError, Resource, Verb};

const GRAMMAR_YAML: &str = include_str!("../config/grammar.yml");

static GRAMMAR: OnceLock<GrammarFile> = OnceLock::new();

fn grammar() -> &'static GrammarFile {
    GRAMMAR.get_or_init(|| {
        serde_yaml::from_str(GRAMMAR_YAML)
            .expect("grammar.yml is invalid (should have been caught by build.rs)")
    })
}

// --- YAML schema types ---

#[derive(Debug, Deserialize)]
pub struct GrammarFile {
    pub commands: BTreeMap<String, GrammarNode>,
}

#[derive(Debug, Deserialize)]
pub struct GrammarNode {
    pub help: Option<String>,
    #[serde(default)]
    pub children: Option<BTreeMap<String, GrammarNode>>,
    pub command: Option<CommandTemplate>,
    pub builtin: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // documentation-only field; not used by the tree walker
    pub optional: bool,
    /// Display name for _arg nodes (e.g. "<name>", "<address>")
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CommandTemplate {
    pub verb: Verb,
    pub resource: Resource,
    pub target: Option<String>,
    #[serde(default)]
    pub address_family: Option<AddressFamily>,
    #[serde(default)]
    pub filter_asn: Option<String>,
    #[serde(default)]
    pub filter_vlan: Option<String>,
}

// --- Completion ---

#[derive(Debug, Clone)]
pub struct Completion {
    pub keyword: String,
    pub help: String,
}

/// Get completions for the current input state.
///
/// `tokens` — fully entered words (followed by a space).
/// `partial` — the incomplete word being typed (empty if cursor follows a space).
pub fn get_completions(tokens: &[&str], partial: &str) -> Vec<Completion> {
    let g = grammar();
    let candidates = resolve_completions(&g.commands, tokens, false);
    filter_candidates(&candidates, partial)
}

/// Attempt tab-completion. Returns the suffix to append, or None if ambiguous.
pub fn tab_complete(tokens: &[&str], partial: &str) -> Option<String> {
    let candidates = get_completions(tokens, partial);
    let real: Vec<&Completion> = candidates
        .iter()
        .filter(|c| !c.keyword.starts_with('<'))
        .collect();
    if real.len() == 1 {
        let full = &real[0].keyword;
        if full.len() > partial.len() {
            Some(format!("{} ", &full[partial.len()..]))
        } else {
            Some(" ".to_string())
        }
    } else {
        None
    }
}

fn filter_candidates(candidates: &[(String, String)], partial: &str) -> Vec<Completion> {
    let lower = partial.to_lowercase();
    candidates
        .iter()
        .filter(|(k, _)| partial.is_empty() || k.starts_with('<') || k.starts_with(&lower))
        .map(|(k, h)| Completion {
            keyword: k.clone(),
            help: h.clone(),
        })
        .collect()
}

/// Walk `tokens` through the grammar tree and return completions at the landing position.
fn resolve_completions(
    children: &BTreeMap<String, GrammarNode>,
    tokens: &[&str],
    parent_has_command: bool,
) -> Vec<(String, String)> {
    if tokens.is_empty() {
        let mut result = node_completion_list(children);
        if parent_has_command {
            result.push(("<cr>".to_string(), "Execute command".to_string()));
        }
        return result;
    }

    let keywords: Vec<&str> = children
        .keys()
        .filter(|k| k.as_str() != "_arg")
        .map(|k| k.as_str())
        .collect();

    match try_abbrev(tokens[0], &keywords) {
        Some(matched) => {
            let node = &children[matched];
            if let Some(ref ch) = node.children {
                resolve_completions(ch, &tokens[1..], node.command.is_some())
            } else {
                vec![("<cr>".to_string(), "Execute command".to_string())]
            }
        }
        None => vec![],
    }
}

/// Build the list of completion candidates from a children map.
fn node_completion_list(children: &BTreeMap<String, GrammarNode>) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for (key, node) in children {
        if key == "_arg" {
            let display = node.name.as_deref().unwrap_or("<value>");
            let help = node.help.as_deref().unwrap_or("");
            result.push((display.to_string(), help.to_string()));
        } else {
            let help = node.help.as_deref().unwrap_or("");
            result.push((key.clone(), help.to_string()));
        }
    }
    result
}

// --- Parsing ---

/// Parse user input into a structured Command using the grammar tree.
pub fn parse_command(input: &str) -> Result<Command, ParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ParseError::Empty);
    }
    if input == "?" {
        return Ok(Command {
            verb: Verb::Show,
            resource: Resource::Help,
            target: None,
            device: None,
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
        });
    }

    let g = grammar();
    let tokens: Vec<&str> = input.split_whitespace().collect();
    walk_parse(&g.commands, &tokens, None)
}

fn walk_parse(
    children: &BTreeMap<String, GrammarNode>,
    tokens: &[&str],
    captured_arg: Option<&str>,
) -> Result<Command, ParseError> {
    if tokens.is_empty() {
        return Err(ParseError::MissingArgument("command"));
    }

    let token = tokens[0];
    let rest = &tokens[1..];

    // Collect keyword children (everything except _arg)
    let keyword_entries: Vec<(&str, &GrammarNode)> = children
        .iter()
        .filter(|(k, _)| k.as_str() != "_arg")
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let keywords: Vec<&str> = keyword_entries.iter().map(|(k, _)| *k).collect();

    match abbrev(token, &keywords) {
        Ok(matched) => {
            let node = keyword_entries
                .iter()
                .find(|(k, _)| *k == matched)
                .unwrap()
                .1;
            resolve_node(node, rest, captured_arg)
        }
        Err(e) => {
            // No keyword match — try _arg
            if let Some(arg_node) = children.get("_arg") {
                resolve_node(arg_node, rest, Some(token))
            } else {
                Err(e)
            }
        }
    }
}

/// After matching a node, either return its command or descend into children.
fn resolve_node(
    node: &GrammarNode,
    rest: &[&str],
    captured_arg: Option<&str>,
) -> Result<Command, ParseError> {
    if rest.is_empty() {
        // All tokens consumed — try to produce a command from this node
        if let Some(ref tpl) = node.command {
            build_command(tpl, captured_arg)
        } else if node.builtin.is_some() {
            Err(ParseError::UnknownCommand(
                node.builtin.as_deref().unwrap_or("builtin").to_string(),
            ))
        } else {
            Err(ParseError::MissingArgument("subcommand"))
        }
    } else if let Some(ref ch) = node.children {
        walk_parse(ch, rest, captured_arg)
    } else {
        // Leaf node but extra tokens remain
        Err(ParseError::UnknownCommand(rest[0].to_string()))
    }
}

fn build_command(tpl: &CommandTemplate, captured_arg: Option<&str>) -> Result<Command, ParseError> {
    let target = match tpl.target.as_deref() {
        Some("$arg") => captured_arg.map(|s| s.to_string()),
        Some(other) => Some(other.to_string()),
        None => None,
    };

    let filter_asn = match tpl.filter_asn.as_deref() {
        Some("$arg") => captured_arg
            .and_then(|s| s.parse::<u32>().ok()),
        _ => None,
    };

    let filter_vlan = match tpl.filter_vlan.as_deref() {
        Some("$arg") => captured_arg.map(|s| s.to_string()),
        _ => None,
    };

    Ok(Command {
        verb: tpl.verb,
        resource: tpl.resource,
        target,
        device: None,
        address_family: tpl.address_family.unwrap_or_default(),
        filter_asn,
        filter_vlan,
    })
}

// --- Abbreviation helpers ---

fn try_abbrev<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let lower = input.to_lowercase();
    for &c in candidates {
        if c == lower {
            return Some(c);
        }
    }
    let matches: Vec<&str> = candidates
        .iter()
        .copied()
        .filter(|c| c.starts_with(&lower) || lower.starts_with(c))
        .collect();
    if matches.len() == 1 {
        Some(matches[0])
    } else {
        None
    }
}

fn abbrev<'a>(input: &str, candidates: &[&'a str]) -> Result<&'a str, ParseError> {
    let lower = input.to_lowercase();
    for &c in candidates {
        if c == lower {
            return Ok(c);
        }
    }
    let matches: Vec<&str> = candidates
        .iter()
        .copied()
        .filter(|c| c.starts_with(&lower) || lower.starts_with(c))
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(ParseError::UnknownCommand(input.to_string())),
        _ => Err(ParseError::AmbiguousCommand(
            input.to_string(),
            matches.iter().map(|s| s.to_string()).collect(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grammar_loads() {
        let g = grammar();
        assert!(g.commands.contains_key("show"));
        assert!(g.commands.contains_key("ping"));
    }

    // --- Parser tests (same as command.rs had) ---

    #[test]
    fn test_parse_show_interfaces_status() {
        let cmd = parse_command("show interfaces status").unwrap();
        assert_eq!(cmd.verb, Verb::Show);
        assert_eq!(cmd.resource, Resource::InterfacesStatus);
        assert!(cmd.target.is_none());
    }

    #[test]
    fn test_parse_show_interfaces_filter_asn() {
        let cmd = parse_command("show interfaces 13335").unwrap();
        assert_eq!(cmd.resource, Resource::InterfacesStatus);
        assert_eq!(cmd.filter_asn, Some(13335));
        assert!(cmd.target.is_none());
    }

    #[test]
    fn test_parse_show_optics() {
        let cmd = parse_command("show optics").unwrap();
        assert_eq!(cmd.resource, Resource::Optics);

        let cmd = parse_command("show optics 13335").unwrap();
        assert_eq!(cmd.resource, Resource::Optics);
        assert_eq!(cmd.filter_asn, Some(13335));
    }

    #[test]
    fn test_parse_bgp_summary() {
        let cmd = parse_command("show ip bgp summary").unwrap();
        assert_eq!(cmd.resource, Resource::BgpSummary);
        assert_eq!(cmd.address_family, AddressFamily::IPv4);

        let cmd = parse_command("show bgp ipv6 unicast summary").unwrap();
        assert_eq!(cmd.resource, Resource::BgpSummary);
        assert_eq!(cmd.address_family, AddressFamily::IPv6);
    }

    #[test]
    fn test_parse_ping() {
        let cmd = parse_command("ping 8.8.8.8").unwrap();
        assert_eq!(cmd.verb, Verb::Ping);
        assert_eq!(cmd.target.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn test_parse_help() {
        let cmd = parse_command("help").unwrap();
        assert_eq!(cmd.resource, Resource::Help);
    }

    #[test]
    fn test_parse_empty() {
        assert!(matches!(parse_command(""), Err(ParseError::Empty)));
        assert!(matches!(parse_command("   "), Err(ParseError::Empty)));
    }

    #[test]
    fn test_parse_unknown() {
        assert!(matches!(
            parse_command("configure terminal"),
            Err(ParseError::UnknownCommand(_))
        ));
    }

    // --- Abbreviation tests ---

    #[test]
    fn test_abbrev_sh_int_st() {
        let cmd = parse_command("sh int st").unwrap();
        assert_eq!(cmd.resource, Resource::InterfacesStatus);
    }

    #[test]
    fn test_abbrev_sh_int() {
        let cmd = parse_command("sh int").unwrap();
        assert_eq!(cmd.resource, Resource::InterfacesStatus);
    }

    #[test]
    fn test_abbrev_sh_int_asn() {
        let cmd = parse_command("sh int 13335").unwrap();
        assert_eq!(cmd.resource, Resource::InterfacesStatus);
        assert_eq!(cmd.filter_asn, Some(13335));
    }

    #[test]
    fn test_abbrev_sh_ip_bgp_sum() {
        let cmd = parse_command("sh ip b sum").unwrap();
        assert_eq!(cmd.resource, Resource::BgpSummary);
        assert_eq!(cmd.address_family, AddressFamily::IPv4);
    }

    #[test]
    fn test_abbrev_sh_bgp_ipv6_sum() {
        let cmd = parse_command("sh bgp ipv6 sum").unwrap();
        assert_eq!(cmd.resource, Resource::BgpSummary);
        assert_eq!(cmd.address_family, AddressFamily::IPv6);
    }

    #[test]
    fn test_abbrev_sh_l() {
        let cmd = parse_command("sh l").unwrap();
        assert_eq!(cmd.resource, Resource::LldpNeighbors);
    }

    #[test]
    fn test_abbrev_sh_a() {
        let cmd = parse_command("sh a").unwrap();
        assert_eq!(cmd.resource, Resource::ArpTable);
    }

    #[test]
    fn test_abbrev_pi() {
        let cmd = parse_command("pi 8.8.8.8").unwrap();
        assert_eq!(cmd.verb, Verb::Ping);
    }

    #[test]
    fn test_abbrev_tr() {
        let cmd = parse_command("tr 8.8.8.8").unwrap();
        assert_eq!(cmd.verb, Verb::Traceroute);
    }

    #[test]
    fn test_abbrev_ambiguous_i() {
        assert!(matches!(
            parse_command("sh i"),
            Err(ParseError::AmbiguousCommand(_, _))
        ));
    }

    #[test]
    fn test_abbrev_show_bgp_neighbors_spelling() {
        let cmd = parse_command("show bgp neighbors 10.0.0.1").unwrap();
        assert_eq!(cmd.resource, Resource::BgpNeighbor);
    }

    // --- Completion tests ---

    #[test]
    fn test_empty_input_shows_verbs() {
        let c = get_completions(&[], "");
        assert!(c.iter().any(|x| x.keyword == "show"));
        assert!(c.iter().any(|x| x.keyword == "ping"));
        assert!(c.iter().any(|x| x.keyword == "quit"));
    }

    #[test]
    fn test_partial_verb() {
        let c = get_completions(&[], "sh");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].keyword, "show");
    }

    #[test]
    fn test_show_completions() {
        let c = get_completions(&["show"], "");
        assert!(c.iter().any(|x| x.keyword == "interfaces"));
        assert!(c.iter().any(|x| x.keyword == "bgp"));
    }

    #[test]
    fn test_show_int_completions() {
        let c = get_completions(&["show"], "int");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].keyword, "interfaces");
    }

    #[test]
    fn test_show_interfaces_completions() {
        let c = get_completions(&["show", "interfaces"], "");
        assert!(c.iter().any(|x| x.keyword == "status"));
        assert!(c.iter().any(|x| x.keyword == "<cr>"));
    }

    #[test]
    fn test_tab_complete_unambiguous() {
        let result = tab_complete(&["show"], "int");
        assert_eq!(result, Some("erfaces ".to_string()));
    }

    #[test]
    fn test_tab_complete_ambiguous() {
        let result = tab_complete(&["show"], "i");
        assert!(result.is_none());
    }

    #[test]
    fn test_show_ip_bgp_completions() {
        let c = get_completions(&["show", "ip", "bgp"], "");
        assert!(c.iter().any(|x| x.keyword == "summary"));
        assert!(c.iter().any(|x| x.keyword == "neighbor"));
    }
}
