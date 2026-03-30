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

    match tokens[0].to_lowercase().as_str() {
        "help" | "?" => Ok(Command {
            verb: Verb::Show,
            resource: Resource::Help,
            target: None,
            device: None,
            address_family: AddressFamily::IPv4,
        }),
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
        other => Err(ParseError::UnknownCommand(other.to_string())),
    }
}

fn parse_show(tokens: &[&str]) -> Result<Command, ParseError> {
    if tokens.is_empty() {
        return Err(ParseError::MissingArgument("resource"));
    }

    match tokens[0].to_lowercase().as_str() {
        "interfaces" => {
            // "show interfaces status" or "show interfaces transceiver" or "show interfaces <intf>"
            match tokens.get(1).map(|s| s.to_lowercase()).as_deref() {
                Some("status") | None => Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::InterfacesStatus,
                    target: None,
                    device: None,
                    address_family: AddressFamily::IPv4,
                }),
                Some(_) => Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::InterfaceDetail,
                    target: Some(tokens[1].to_string()),
                    device: None,
                    address_family: AddressFamily::IPv4,
                }),
            }
        }
        "interface" => {
            // "show interface <intf>"
            let intf = tokens.get(1).ok_or(ParseError::MissingArgument("interface name"))?;
            Ok(Command {
                verb: Verb::Show,
                resource: Resource::InterfaceDetail,
                target: Some(intf.to_string()),
                device: None,
                address_family: AddressFamily::IPv4,
            })
        }
        "optics" => {
            // "show optics" or "show optics <intf>"
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
        "ip" => {
            // "show ip bgp summary" or "show ip bgp neighbor <addr>"
            match tokens.get(1).map(|s| s.to_lowercase()).as_deref() {
                Some("bgp") => parse_show_bgp(&tokens[2..], AddressFamily::IPv4),
                _ => Err(ParseError::UnknownCommand(format!("show ip {}", tokens.get(1).unwrap_or(&"")))),
            }
        }
        "bgp" => {
            // "show bgp ipv6 unicast summary"
            match tokens.get(1).map(|s| s.to_lowercase()).as_deref() {
                Some("ipv6") => parse_show_bgp(&tokens[3..], AddressFamily::IPv6), // skip "ipv6 unicast"
                Some("summary") => Ok(Command {
                    verb: Verb::Show,
                    resource: Resource::BgpSummary,
                    target: None,
                    device: None,
                    address_family: AddressFamily::IPv4,
                }),
                _ => Err(ParseError::UnknownCommand("show bgp ...".to_string())),
            }
        }
        "mac" => {
            // "show mac address-table [interface <intf>]"
            let target = if tokens.len() >= 3 && tokens[1].eq_ignore_ascii_case("address-table") {
                if tokens.len() >= 5 && tokens[2].eq_ignore_ascii_case("interface") {
                    Some(tokens[3].to_string())
                } else {
                    None
                }
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
        "arp" => {
            // "show arp [interface <intf>]"
            let target = if tokens.len() >= 3 && tokens[1].eq_ignore_ascii_case("interface") {
                Some(tokens[2].to_string())
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
        "ipv6" => {
            // "show ipv6 neighbors [interface <intf>]"
            if tokens.get(1).map(|s| s.to_lowercase()).as_deref() == Some("neighbors") {
                let target = if tokens.len() >= 4 && tokens[2].eq_ignore_ascii_case("interface") {
                    Some(tokens[3].to_string())
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
            } else {
                Err(ParseError::UnknownCommand("show ipv6 ...".to_string()))
            }
        }
        "lldp" => {
            // "show lldp neighbors"
            Ok(Command {
                verb: Verb::Show,
                resource: Resource::LldpNeighbors,
                target: None,
                device: None,
                address_family: AddressFamily::IPv4,
            })
        }
        "participants" => Ok(Command {
            verb: Verb::Show,
            resource: Resource::Participants,
            target: None,
            device: None,
            address_family: AddressFamily::IPv4,
        }),
        "vxlan" => {
            // "show vxlan vtep"
            Ok(Command {
                verb: Verb::Show,
                resource: Resource::VxlanVtep,
                target: None,
                device: None,
                address_family: AddressFamily::IPv4,
            })
        }
        other => Err(ParseError::UnknownCommand(format!("show {other}"))),
    }
}

fn parse_show_bgp(tokens: &[&str], af: AddressFamily) -> Result<Command, ParseError> {
    match tokens.first().map(|s| s.to_lowercase()).as_deref() {
        Some("summary") | None => Ok(Command {
            verb: Verb::Show,
            resource: Resource::BgpSummary,
            target: None,
            device: None,
            address_family: af,
        }),
        Some("neighbor") | Some("neighbors") => {
            let addr = tokens.get(1).ok_or(ParseError::MissingArgument("neighbor address"))?;
            Ok(Command {
                verb: Verb::Show,
                resource: Resource::BgpNeighbor,
                target: Some(addr.to_string()),
                device: None,
                address_family: af,
            })
        }
        Some(other) => Err(ParseError::UnknownCommand(format!("show bgp {other}"))),
    }
}

#[derive(Debug)]
pub enum ParseError {
    Empty,
    UnknownCommand(String),
    MissingArgument(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, ""),
            ParseError::UnknownCommand(cmd) => write!(f, "Unknown command: {cmd}"),
            ParseError::MissingArgument(what) => write!(f, "Missing argument: {what}"),
        }
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
}
