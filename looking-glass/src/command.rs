use std::fmt;

/// Structured command representation.
///
/// Commands are parsed from user input into this structured form before
/// policy evaluation and device dispatch. This prevents injection and
/// enables platform-independent policy checks.
#[derive(Debug, Clone)]
pub struct Command {
    pub verb: Verb,
    pub resource: Resource,
    pub target: Option<String>,
    pub device: Option<String>,
    pub address_family: AddressFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Show,
    Ping,
    Traceroute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    InterfacesStatus,
    InterfaceDetail,
    BgpSummary,
    BgpNeighbor,
    MacAddressTable,
    ArpTable,
    NdTable,
    LldpNeighbors,
    Optics,
    OpticsDetail,
    Participants,
    VxlanVtep,
    /// Ping/traceroute destination (resource is the destination address)
    NetworkReachability,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressFamily {
    #[default]
    IPv4,
    IPv6,
}

/// Result of executing a command against a device.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// The device that was queried
    pub device: String,
    /// Raw text output from the device
    pub output: String,
    /// Whether the command executed successfully
    pub success: bool,
}

/// Whether a resource targets a specific participant port (and thus
/// requires ownership checks for non-admin authenticated users).
impl Resource {
    pub fn is_port_scoped(&self) -> bool {
        matches!(
            self,
            Resource::InterfaceDetail
                | Resource::OpticsDetail
                | Resource::MacAddressTable
                | Resource::ArpTable
                | Resource::NdTable
        )
    }
}

#[allow(dead_code)]
impl Command {
    /// Whether this command requires authentication to access participant ports.
    /// Core/infrastructure ports are always accessible; participant ports need auth.
    pub fn requires_auth_for_participant_port(&self) -> bool {
        self.resource.is_port_scoped() && self.target.is_some()
    }
}

/// Parse user input text into a structured Command.
///
/// Returns None for empty input, Err for unrecognized commands.
pub fn parse_command(input: &str) -> Result<Command, ParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let tokens: Vec<&str> = input.split_whitespace().collect();

    // "?" is a special case
    if tokens[0] == "?" {
        return Ok(Command {
            verb: Verb::Show,
            resource: Resource::Help,
            target: None,
            device: None,
            address_family: AddressFamily::IPv4,
        });
    }

    match abbrev(tokens[0], &["show", "ping", "traceroute", "help"])? {
        "show" => parse_show(&tokens[1..]),
        "ping" => {
            let dest = tokens.get(1).ok_or(ParseError::MissingArgument("destination"))?;
            Ok(Command {
                verb: Verb::Ping,
                resource: Resource::NetworkReachability,
                target: Some(dest.to_string()),
                device: None,
                address_family: AddressFamily::IPv4,
            })
        }
        "traceroute" => {
            let dest = tokens.get(1).ok_or(ParseError::MissingArgument("destination"))?;
            Ok(Command {
                verb: Verb::Traceroute,
                resource: Resource::NetworkReachability,
                target: Some(dest.to_string()),
                device: None,
                address_family: AddressFamily::IPv4,
            })
        }
        "help" => Ok(Command {
            verb: Verb::Show,
            resource: Resource::Help,
            target: None,
            device: None,
            address_family: AddressFamily::IPv4,
        }),
        _ => unreachable!(),
    }
}

fn parse_show(tokens: &[&str]) -> Result<Command, ParseError> {
    if tokens.is_empty() {
        return Err(ParseError::MissingArgument("resource"));
    }

    // Candidates for "show <resource>". "interfaces" covers both "interface" and "interfaces".
    // "ip" and "ipv6" are both present; exact-match of "ip" takes priority over prefix.
    match abbrev(tokens[0], &[
        "interfaces", "optics", "ip", "bgp", "mac", "arp", "ipv6",
        "lldp", "participants", "vxlan",
    ]) {
        Ok("interfaces") => {
            // "show interfaces [status]" or "show interface(s) <port>"
            // If next token matches "status" (or abbreviation), it's InterfacesStatus.
            // If next token exists but isn't "status", it's an interface name.
            // If no next token, default to InterfacesStatus.
            match tokens.get(1) {
                None => Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::InterfacesStatus,
                    target: None,
                    device: None,
                    address_family: AddressFamily::IPv4,
                }),
                Some(t) if abbrev(t, &["status"]).is_ok() => Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::InterfacesStatus,
                    target: None,
                    device: None,
                    address_family: AddressFamily::IPv4,
                }),
                Some(intf) => Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::InterfaceDetail,
                    target: Some(intf.to_string()),
                    device: None,
                    address_family: AddressFamily::IPv4,
                }),
            }
        }
        Ok("optics") => {
            match tokens.get(1) {
                Some(intf) => Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::OpticsDetail,
                    target: Some(intf.to_string()),
                    device: None,
                    address_family: AddressFamily::IPv4,
                }),
                None => Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::Optics,
                    target: None,
                    device: None,
                    address_family: AddressFamily::IPv4,
                }),
            }
        }
        Ok("ip") => {
            // "show ip bgp ..."
            match tokens.get(1) {
                Some(t) if abbrev(t, &["bgp"]).is_ok() => parse_show_bgp(&tokens[2..], AddressFamily::IPv4),
                _ => Err(ParseError::UnknownCommand(format!("show ip {}", tokens.get(1).unwrap_or(&"")))),
            }
        }
        Ok("bgp") => {
            // "show bgp [ipv6 [unicast]] summary|neighbor ..."
            match tokens.get(1) {
                Some(t) if abbrev(t, &["ipv6"]).is_ok() => {
                    // Skip optional "unicast" token
                    let rest_start = if tokens.get(2).map(|s| abbrev(s, &["unicast"]).is_ok()).unwrap_or(false) {
                        3
                    } else {
                        2
                    };
                    parse_show_bgp(&tokens[rest_start..], AddressFamily::IPv6)
                }
                Some(t) if abbrev(t, &["summary", "neighbor"]).is_ok() => {
                    parse_show_bgp(&tokens[1..], AddressFamily::IPv4)
                }
                None => parse_show_bgp(&[], AddressFamily::IPv4),
                _ => Err(ParseError::UnknownCommand("show bgp ...".to_string())),
            }
        }
        Ok("mac") => {
            // "show mac [address-table] [interface <intf>]"
            let mut idx = 1;
            // Skip optional "address-table"
            if tokens.get(idx).map(|t| abbrev(t, &["address-table"]).is_ok()).unwrap_or(false) {
                idx += 1;
            }
            let target = if tokens.get(idx).map(|t| abbrev(t, &["interface"]).is_ok()).unwrap_or(false) {
                tokens.get(idx + 1).map(|s| s.to_string())
            } else {
                None
            };
            Ok(Command {
                verb: Verb::Show,
                resource: Resource::MacAddressTable,
                target,
                device: None,
                address_family: AddressFamily::IPv4,
            })
        }
        Ok("arp") => {
            let target = if tokens.get(1).map(|t| abbrev(t, &["interface"]).is_ok()).unwrap_or(false) {
                tokens.get(2).map(|s| s.to_string())
            } else {
                None
            };
            Ok(Command {
                verb: Verb::Show,
                resource: Resource::ArpTable,
                target,
                device: None,
                address_family: AddressFamily::IPv4,
            })
        }
        Ok("ipv6") => {
            // "show ipv6 neighbors [interface <intf>]"
            match tokens.get(1) {
                Some(t) if abbrev(t, &["neighbors"]).is_ok() => {
                    let target = if tokens.get(2).map(|t2| abbrev(t2, &["interface"]).is_ok()).unwrap_or(false) {
                        tokens.get(3).map(|s| s.to_string())
                    } else {
                        None
                    };
                    Ok(Command {
                        verb: Verb::Show,
                        resource: Resource::NdTable,
                        target,
                        device: None,
                        address_family: AddressFamily::IPv6,
                    })
                }
                _ => Err(ParseError::UnknownCommand("show ipv6 ...".to_string())),
            }
        }
        Ok("lldp") => Ok(Command {
            verb: Verb::Show,
            resource: Resource::LldpNeighbors,
            target: None,
            device: None,
            address_family: AddressFamily::IPv4,
        }),
        Ok("participants") => Ok(Command {
            verb: Verb::Show,
            resource: Resource::Participants,
            target: None,
            device: None,
            address_family: AddressFamily::IPv4,
        }),
        Ok("vxlan") => Ok(Command {
            verb: Verb::Show,
            resource: Resource::VxlanVtep,
            target: None,
            device: None,
            address_family: AddressFamily::IPv4,
        }),
        Ok(_) => unreachable!(),
        Err(e) => Err(e),
    }
}

fn parse_show_bgp(tokens: &[&str], af: AddressFamily) -> Result<Command, ParseError> {
    match tokens.first() {
        None => Ok(Command {
            verb: Verb::Show,
            resource: Resource::BgpSummary,
            target: None,
            device: None,
            address_family: af,
        }),
        Some(t) => match abbrev(t, &["summary", "neighbor"])? {
            "summary" => Ok(Command {
                verb: Verb::Show,
                resource: Resource::BgpSummary,
                target: None,
                device: None,
                address_family: af,
            }),
            "neighbor" => {
                let addr = tokens.get(1).ok_or(ParseError::MissingArgument("neighbor address"))?;
                Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::BgpNeighbor,
                    target: Some(addr.to_string()),
                    device: None,
                    address_family: af,
                })
            }
            _ => unreachable!(),
        },
    }
}

#[derive(Debug)]
pub enum ParseError {
    Empty,
    UnknownCommand(String),
    AmbiguousCommand(String, Vec<String>),
    MissingArgument(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, ""),
            ParseError::UnknownCommand(cmd) => write!(f, "Unknown command: {cmd}"),
            ParseError::AmbiguousCommand(input, candidates) => {
                write!(f, "Ambiguous command '{}': could be {}", input, candidates.join(", "))
            }
            ParseError::MissingArgument(what) => write!(f, "Missing argument: {what}"),
        }
    }
}

/// Match `input` as an unambiguous prefix of one of `candidates`.
/// Exact matches take priority. Returns the matched candidate or a ParseError.
fn abbrev<'a>(input: &str, candidates: &[&'a str]) -> Result<&'a str, ParseError> {
    let lower = input.to_lowercase();
    // Exact match first
    for &c in candidates {
        if c == lower {
            return Ok(c);
        }
    }
    // Prefix match: input is a prefix of candidate (abbreviation)
    // OR candidate is a prefix of input (over-typing, e.g. "neighbors" matches "neighbor")
    let matches: Vec<&str> = candidates.iter().copied()
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

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_show_interfaces_status() {
        let cmd = parse_command("show interfaces status").unwrap();
        assert_eq!(cmd.verb, Verb::Show);
        assert_eq!(cmd.resource, Resource::InterfacesStatus);
        assert!(cmd.target.is_none());
    }

    #[test]
    fn test_parse_show_interface_detail() {
        let cmd = parse_command("show interface Ethernet3/1").unwrap();
        assert_eq!(cmd.resource, Resource::InterfaceDetail);
        assert_eq!(cmd.target.as_deref(), Some("Ethernet3/1"));
    }

    #[test]
    fn test_parse_show_optics() {
        let cmd = parse_command("show optics").unwrap();
        assert_eq!(cmd.resource, Resource::Optics);

        let cmd = parse_command("show optics Ethernet3/1").unwrap();
        assert_eq!(cmd.resource, Resource::OpticsDetail);
        assert_eq!(cmd.target.as_deref(), Some("Ethernet3/1"));
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
        assert!(matches!(parse_command("configure terminal"), Err(ParseError::UnknownCommand(_))));
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
    fn test_abbrev_sh_int_ethernet() {
        let cmd = parse_command("sh int Ethernet1").unwrap();
        assert_eq!(cmd.resource, Resource::InterfaceDetail);
        assert_eq!(cmd.target.as_deref(), Some("Ethernet1"));
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
        // "i" matches interfaces, ip, ipv6 — should be ambiguous
        assert!(matches!(parse_command("sh i"), Err(ParseError::AmbiguousCommand(_, _))));
    }

    #[test]
    fn test_abbrev_show_bgp_neighbors_spelling() {
        // "neighbors" still works (prefix of "neighbor" candidate? No — "neighbors" starts with "neighbor")
        let cmd = parse_command("show bgp neighbors 10.0.0.1").unwrap();
        assert_eq!(cmd.resource, Resource::BgpNeighbor);
    }
}
