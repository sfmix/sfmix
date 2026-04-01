/// A single completion candidate with keyword and help text.
#[derive(Debug, Clone)]
pub struct Completion {
    pub keyword: String,
    pub help: String,
}

fn make(items: &[(&str, &str)]) -> Vec<Completion> {
    items
        .iter()
        .map(|(k, h)| Completion {
            keyword: k.to_string(),
            help: h.to_string(),
        })
        .collect()
}

const VERBS: &[(&str, &str)] = &[
    ("show", "Display device information"),
    ("ping", "Send ICMP echo to a destination"),
    ("traceroute", "Trace route to a destination"),
    ("help", "Show available commands"),
    ("quit", "Disconnect"),
    ("exit", "Disconnect"),
];

const SHOW_RESOURCES: &[(&str, &str)] = &[
    ("interfaces", "Interface status summary"),
    ("optics", "Transceiver/DOM information"),
    ("ip", "IP protocol information"),
    ("bgp", "BGP routing information"),
    ("mac", "MAC address table"),
    ("arp", "ARP table"),
    ("ipv6", "IPv6 protocol information"),
    ("lldp", "LLDP neighbor information"),
    ("participants", "IXP participant list"),
    ("vxlan", "VXLAN VTEP information"),
];

const SHOW_INTERFACES_NEXT: &[(&str, &str)] = &[
    ("status", "Interface status summary (default)"),
    ("<name>", "Specific interface (e.g. Ethernet1)"),
];

const SHOW_IP_NEXT: &[(&str, &str)] = &[("bgp", "BGP routing information")];

const SHOW_BGP_NEXT: &[(&str, &str)] = &[
    ("ipv6", "IPv6 address family"),
    ("summary", "BGP neighbor summary"),
    ("neighbor", "BGP neighbor detail"),
];

const SHOW_BGP_AF_NEXT: &[(&str, &str)] = &[
    ("summary", "BGP neighbor summary"),
    ("neighbor", "BGP neighbor detail"),
];

const SHOW_MAC_NEXT: &[(&str, &str)] = &[
    ("address-table", "MAC address table"),
];

const SHOW_IPV6_NEXT: &[(&str, &str)] = &[("neighbors", "IPv6 neighbor discovery table")];

const DEST_ARG: &[(&str, &str)] = &[("<destination>", "IP address or hostname")];
const NEIGHBOR_ARG: &[(&str, &str)] = &[("<address>", "Neighbor IP address")];
const CR: &[(&str, &str)] = &[("<cr>", "Execute command")];

/// Silently try to match an abbreviation. Returns None on failure.
fn try_abbrev<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    // Reuse the logic from command::abbrev but don't propagate errors
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

/// Get completions for the current input state.
///
/// `tokens` are the fully-entered tokens (words before the cursor that are
/// followed by a space). `partial` is the incomplete token being typed
/// (empty string if the cursor follows a space or the input is empty).
pub fn get_completions(tokens: &[&str], partial: &str) -> Vec<Completion> {
    let candidates = resolve_position(tokens);
    filter_candidates(&candidates, partial)
}

fn filter_candidates(candidates: &[(&str, &str)], partial: &str) -> Vec<Completion> {
    if partial.is_empty() {
        return make(candidates);
    }
    let lower = partial.to_lowercase();
    make(candidates)
        .into_iter()
        .filter(|c| c.keyword.starts_with('<') || c.keyword.starts_with(&lower))
        .collect()
}

fn resolve_position(tokens: &[&str]) -> Vec<(&'static str, &'static str)> {
    if tokens.is_empty() {
        return VERBS.to_vec();
    }

    let verb_candidates: Vec<&str> = VERBS.iter().map(|(k, _)| *k).collect();
    let verb = match try_abbrev(tokens[0], &verb_candidates) {
        Some(v) => v,
        None => return vec![],
    };

    match verb {
        "show" => resolve_show(&tokens[1..]),
        "ping" | "traceroute" => {
            if tokens.len() == 1 {
                DEST_ARG.to_vec()
            } else {
                CR.to_vec()
            }
        }
        "help" | "quit" | "exit" => CR.to_vec(),
        _ => vec![],
    }
}

fn resolve_show(tokens: &[&str]) -> Vec<(&'static str, &'static str)> {
    if tokens.is_empty() {
        return SHOW_RESOURCES.to_vec();
    }

    let res_keywords: Vec<&str> = SHOW_RESOURCES.iter().map(|(k, _)| *k).collect();
    let resource = match try_abbrev(tokens[0], &res_keywords) {
        Some(r) => r,
        None => return vec![],
    };

    match resource {
        "interfaces" => {
            if tokens.len() == 1 {
                let mut v = SHOW_INTERFACES_NEXT.to_vec();
                v.push(("<cr>", "Execute command (shows status)"));
                v
            } else {
                CR.to_vec()
            }
        }
        "optics" => {
            if tokens.len() == 1 {
                let mut v = vec![("<name>", "Specific interface (e.g. Ethernet1)")];
                v.push(("<cr>", "Execute command (all optics)"));
                v
            } else {
                CR.to_vec()
            }
        }
        "ip" => {
            if tokens.len() == 1 {
                return SHOW_IP_NEXT.to_vec();
            }
            let ip_keywords: Vec<&str> = SHOW_IP_NEXT.iter().map(|(k, _)| *k).collect();
            match try_abbrev(tokens[1], &ip_keywords) {
                Some("bgp") => resolve_show_bgp(&tokens[2..]),
                _ => vec![],
            }
        }
        "bgp" => {
            if tokens.len() == 1 {
                return SHOW_BGP_NEXT.to_vec();
            }
            let bgp_keywords: Vec<&str> = SHOW_BGP_NEXT.iter().map(|(k, _)| *k).collect();
            match try_abbrev(tokens[1], &bgp_keywords) {
                Some("ipv6") => {
                    // After "ipv6", optionally "unicast", then bgp sub-commands
                    if tokens.len() == 2 {
                        let mut v = vec![("unicast", "Unicast address family")];
                        // Also allow going straight to summary/neighbor
                        v.extend_from_slice(SHOW_BGP_AF_NEXT);
                        return v;
                    }
                    if try_abbrev(tokens[2], &["unicast"]).is_some() {
                        resolve_show_bgp(&tokens[3..])
                    } else {
                        resolve_show_bgp(&tokens[2..])
                    }
                }
                Some("summary") => CR.to_vec(),
                Some("neighbor") => {
                    if tokens.len() == 2 {
                        NEIGHBOR_ARG.to_vec()
                    } else {
                        CR.to_vec()
                    }
                }
                _ => vec![],
            }
        }
        "mac" => {
            if tokens.len() == 1 {
                let mut v = SHOW_MAC_NEXT.to_vec();
                v.push(("<cr>", "Execute command"));
                return v;
            }
            // After "address-table"
            if tokens.len() == 2 {
                let mut v = vec![("interface", "Filter by interface")];
                v.push(("<cr>", "Execute command"));
                return v;
            }
            if tokens.len() == 3 {
                return vec![("<name>", "Interface name")];
            }
            CR.to_vec()
        }
        "arp" => {
            if tokens.len() == 1 {
                let mut v = vec![("interface", "Filter by interface")];
                v.push(("<cr>", "Execute command"));
                return v;
            }
            if tokens.len() == 2 {
                return vec![("<name>", "Interface name")];
            }
            CR.to_vec()
        }
        "ipv6" => {
            if tokens.len() == 1 {
                return SHOW_IPV6_NEXT.to_vec();
            }
            if tokens.len() == 2 {
                let mut v = vec![("interface", "Filter by interface")];
                v.push(("<cr>", "Execute command"));
                return v;
            }
            if tokens.len() == 3 {
                return vec![("<name>", "Interface name")];
            }
            CR.to_vec()
        }
        "lldp" | "participants" | "vxlan" => CR.to_vec(),
        _ => vec![],
    }
}

fn resolve_show_bgp(tokens: &[&str]) -> Vec<(&'static str, &'static str)> {
    if tokens.is_empty() {
        let mut v = SHOW_BGP_AF_NEXT.to_vec();
        v.push(("<cr>", "Execute command (shows summary)"));
        return v;
    }
    let keywords: Vec<&str> = SHOW_BGP_AF_NEXT.iter().map(|(k, _)| *k).collect();
    match try_abbrev(tokens[0], &keywords) {
        Some("summary") => CR.to_vec(),
        Some("neighbor") => {
            if tokens.len() == 1 {
                NEIGHBOR_ARG.to_vec()
            } else {
                CR.to_vec()
            }
        }
        _ => vec![],
    }
}

/// Attempt tab-completion. Returns the completed suffix to append, or None.
/// If multiple matches, returns None (caller should display options).
pub fn tab_complete(tokens: &[&str], partial: &str) -> Option<String> {
    let candidates = get_completions(tokens, partial);
    // Filter out placeholder entries like <name>, <cr>, <destination>
    let real: Vec<&Completion> = candidates.iter().filter(|c| !c.keyword.starts_with('<')).collect();
    if real.len() == 1 {
        // Return the suffix needed to complete the partial + a trailing space
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // "i" matches interfaces, ip, ipv6
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
