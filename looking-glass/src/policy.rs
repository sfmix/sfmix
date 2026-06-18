use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use tracing::debug;

use crate::command::{Command, Resource, Verb};
use crate::config::DEFAULT_ADMIN_GROUP;
use crate::identity::Identity;
use crate::participants::ParticipantMap;

/// Policy evaluation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
}

/// Policy engine that evaluates commands against caller identity.
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    admin_group: String,
}

#[derive(Debug, Deserialize)]
pub struct PolicyFile {
    pub policies: Vec<PolicyRule>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    #[serde(rename = "match")]
    pub match_criteria: Option<MatchCriteria>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: bool,
}

#[derive(Debug, Deserialize)]
pub struct MatchCriteria {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub authenticated: Option<bool>,
}

impl PolicyEngine {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let policy_file: PolicyFile = serde_yaml::from_str(&contents)?;
        Ok(Self {
            rules: policy_file.policies,
            admin_group: DEFAULT_ADMIN_GROUP.to_string(),
        })
    }

    pub fn with_admin_group(mut self, group: &str) -> Self {
        self.admin_group = group.to_string();
        self
    }

    /// Build a default policy with both public and authenticated tiers.
    ///
    /// - Public: show commands, ping, traceroute (port-scoped commands
    ///   targeting participant ports are blocked by the ownership check above)
    /// - Authenticated: same as public, plus port-scoped commands for own ports
    pub fn default_public() -> Self {
        Self {
            rules: vec![
                // Authenticated users get all show commands (port ownership
                // is enforced separately in evaluate())
                PolicyRule {
                    name: "authenticated".to_string(),
                    match_criteria: Some(MatchCriteria {
                        groups: vec![],
                        authenticated: Some(true),
                    }),
                    allow: vec![
                        "show *".to_string(),
                        "ping *".to_string(),
                        "traceroute *".to_string(),
                    ],
                    deny: false,
                },
                // Public: broad show access (participant port ownership
                // check blocks unauthenticated port-scoped queries)
                PolicyRule {
                    name: "public".to_string(),
                    match_criteria: Some(MatchCriteria {
                        groups: vec![],
                        authenticated: Some(false),
                    }),
                    allow: vec![
                        "show interfaces status".to_string(),
                        "show optics".to_string(),
                        "show lldp neighbors".to_string(),
                        "show mac address-table".to_string(),
                        "show participants".to_string(),
                        "show arp".to_string(),
                        "show ipv6 neighbors".to_string(),
                        "ping *".to_string(),
                        "traceroute *".to_string(),
                    ],
                    deny: false,
                },
                PolicyRule {
                    name: "default-deny".to_string(),
                    match_criteria: None,
                    allow: vec![],
                    deny: true,
                },
            ],
            admin_group: DEFAULT_ADMIN_GROUP.to_string(),
        }
    }

    /// Evaluate whether the given command is allowed for the given identity.
    ///
    /// Port-scoped commands (InterfaceDetail, OpticsDetail) target a participant
    /// ASN and require authentication + ASN ownership (or admin).
    ///
    /// BGP neighbor commands targeting a participant session address require
    /// authentication + ASN ownership (or admin).
    pub fn evaluate(
        &self,
        command: &Command,
        identity: &Identity,
        participants: &ParticipantMap,
    ) -> PolicyDecision {
        // Help, Whoami, and Logout are always allowed
        if matches!(command.resource, Resource::Help | Resource::Whoami | Resource::Logout | Resource::NetboxCache | Resource::DeviceCache | Resource::IxIpAssignments | Resource::DiscoveredNeighbors) {
            return PolicyDecision::Allow;
        }

        // OpticsInventory is admin-only
        if command.resource == Resource::OpticsInventory {
            if !identity.is_admin(self.admin_group()) {
                return PolicyDecision::Deny {
                    reason: "optics inventory requires admin access".to_string(),
                };
            }
            return PolicyDecision::Allow;
        }

        // Port-scoped commands require auth + ownership.
        //
        // Two calling conventions:
        //   ASN target ("64500")        — participant queries; check ownership
        //   Interface-name target       — direct interface queries (MCP/admin); admin-only
        if command.resource.is_port_scoped() {
            if let Some(ref target) = command.target {
                match crate::command::parse_asn(target) {
                    Some(asn) => {
                        if participants.get(asn).is_none() {
                            return PolicyDecision::Deny {
                                reason: format!("unknown participant AS{asn}"),
                            };
                        }
                        if !identity.authenticated {
                            return PolicyDecision::Deny {
                                reason: "authentication required for participant port queries".to_string(),
                            };
                        }
                        if !identity.is_admin(self.admin_group()) && !identity.asns.contains(&asn) {
                            return PolicyDecision::Deny {
                                reason: "you do not administer this ASN".to_string(),
                            };
                        }
                    }
                    None => {
                        // Interface-name target — resolve owning ASN via port map
                        match participants.port_owner_by_interface(target) {
                            Some(owner_asn) => {
                                if !identity.authenticated {
                                    return PolicyDecision::Deny {
                                        reason: "authentication required for participant port queries".to_string(),
                                    };
                                }
                                if !identity.is_admin(self.admin_group()) && !identity.asns.contains(&owner_asn) {
                                    return PolicyDecision::Deny {
                                        reason: "you do not administer this port".to_string(),
                                    };
                                }
                            }
                            None => {
                                // Not a participant port (core/infrastructure) — admin only
                                if !identity.authenticated || !identity.is_admin(self.admin_group()) {
                                    return PolicyDecision::Deny {
                                        reason: "interface queries for non-participant ports require admin access".to_string(),
                                    };
                                }
                            }
                        }
                    }
                }
            }
        }

        // ASN-filtered commands (show interfaces <asn>, show optics <asn>)
        // require auth + ownership, same as port-scoped commands.
        if let Some(asn) = command.filter_asn {
            if participants.get(asn).is_none() {
                return PolicyDecision::Deny {
                    reason: format!("unknown participant AS{asn}"),
                };
            }
            if !identity.authenticated {
                return PolicyDecision::Deny {
                    reason: "authentication required for participant port queries".to_string(),
                };
            }
            if !identity.is_admin(self.admin_group()) && !identity.asns.contains(&asn) {
                return PolicyDecision::Deny {
                    reason: "you do not administer this ASN".to_string(),
                };
            }
        }

        // First-match rule evaluation
        for rule in &self.rules {
            if self.rule_matches(rule, identity) {
                if rule.deny {
                    debug!(rule = rule.name, "policy deny");
                    return PolicyDecision::Deny {
                        reason: format!("denied by policy rule: {}", rule.name),
                    };
                }
                if self.command_matches_allow_list(command, &rule.allow) {
                    debug!(rule = rule.name, "policy allow");
                    return PolicyDecision::Allow;
                }
            }
        }

        PolicyDecision::Deny {
            reason: "no matching policy rule".to_string(),
        }
    }

    pub fn admin_group(&self) -> &str {
        &self.admin_group
    }

    fn rule_matches(&self, rule: &PolicyRule, identity: &Identity) -> bool {
        match &rule.match_criteria {
            None => true, // no criteria = matches everything (e.g. default-deny)
            Some(criteria) => {
                // Check authentication requirement
                if let Some(require_auth) = criteria.authenticated {
                    if require_auth != identity.authenticated {
                        return false;
                    }
                }
                // Check group membership (if groups specified, user must have at least one)
                if !criteria.groups.is_empty()
                    && !criteria.groups.iter().any(|g| identity.groups.contains(g))
                {
                    return false;
                }
                true
            }
        }
    }

    fn command_matches_allow_list(&self, command: &Command, allow: &[String]) -> bool {
        let command_str = command_to_match_string(command);
        for pattern in allow {
            if pattern_matches(&command_str, pattern) {
                return true;
            }
        }
        false
    }
}

/// Convert a command to a string suitable for policy pattern matching.
fn command_to_match_string(command: &Command) -> String {
    let verb = match command.verb {
        Verb::Show => "show",
        Verb::Ping => "ping",
        Verb::Traceroute => "traceroute",
    };
    let resource = match command.resource {
        Resource::InterfacesStatus => "interfaces status",
        Resource::InterfaceDetail => {
            return format!("show interface {}", command.target.as_deref().unwrap_or("*"));
        }
        Resource::MacAddressTable => "mac address-table",
        Resource::LldpNeighbors => "lldp neighbors",
        Resource::Optics => return format!("{verb} optics"),
        Resource::OpticsDetail => {
            return format!("show optics {}", command.target.as_deref().unwrap_or("*"));
        }
        Resource::OpticsInventory => return "show optics inventory".to_string(),
        Resource::Participants => "participants",
        Resource::IxIpAssignments => return "show ix-ip-assignments".to_string(),
        Resource::DiscoveredNeighbors => return "show discovered-neighbors".to_string(),
        Resource::ParticipantDetail => {
            return format!("show participant {}", command.target.as_deref().unwrap_or("*"));
        }
        Resource::NetworkReachability => {
            return format!("{verb} {}", command.target.as_deref().unwrap_or(""));
        }
        Resource::Help => "help",
        Resource::Login => return "login".to_string(),
        Resource::Whoami => return "whoami".to_string(),
        Resource::Logout => return "logout".to_string(),
        Resource::NetboxCache => return "show netbox".to_string(),
        Resource::DeviceCache => return "show device-cache".to_string(),
        Resource::Arp => "arp",
        Resource::IPv6Neighbors => "ipv6 neighbors",
    };
    format!("{verb} {resource}")
}

/// Simple glob-style pattern matching (only supports trailing `*`).
fn pattern_matches(input: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        input.starts_with(prefix.trim_end())
    } else {
        input == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{AddressFamily, Verb};
    use crate::grammar::parse_command;
    use crate::participants::{Participant, ParticipantPort, ParticipantSession};

    fn test_participants() -> ParticipantMap {
        let mut map = ParticipantMap::empty();
        map.insert(Participant {
            asn: 64500,
            name: "Test Peer A".to_string(),
            participant_type: Some("Member".to_string()),
            ports: vec![ParticipantPort {
                device: "switch01.sfo02".to_string(),
                interface: "Ethernet3/1".to_string(),
            }],
            sessions: vec![ParticipantSession {
                device: "switch01.sfo02".to_string(),
                neighbor: Some("198.51.100.1".to_string()),
                neighbor_v6: Some("2001:db8::1".to_string()),
            }],
        });
        map.insert(Participant {
            asn: 64501,
            name: "Test Peer B".to_string(),
            participant_type: None,
            ports: vec![ParticipantPort {
                device: "switch01.sfo02".to_string(),
                interface: "Ethernet3/2".to_string(),
            }],
            sessions: vec![],
        });
        map
    }

    #[test]
    fn test_public_policy_allows_show_interfaces() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = ParticipantMap::empty();

        let command = parse_command("show interfaces status").unwrap();
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_public_policy_allows_ping() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = ParticipantMap::empty();

        let command = parse_command("ping 8.8.8.8").unwrap();
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_public_policy_allows_help() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = ParticipantMap::empty();

        let command = parse_command("help").unwrap();
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_public_policy_allows_optics_global() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let command = parse_command("show optics").unwrap();
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    // --- ASN-targeted port-scoped commands ---

    #[test]
    fn test_anon_denied_interface_detail_by_asn() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let command = parse_command("show interface 64500").unwrap();
        assert!(matches!(
            engine.evaluate(&command, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_auth_owner_allowed_own_asn() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "user@peer-a.net".to_string(),
            vec!["as64500".to_string()],
            "as",
        );
        let command = parse_command("show interface 64500").unwrap();
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_auth_non_owner_denied_other_asn() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "user@peer-b.net".to_string(),
            vec!["as64501".to_string()],
            "as",
        );
        let command = parse_command("show interface 64500").unwrap();
        assert!(matches!(
            engine.evaluate(&command, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_admin_allowed_any_asn() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "admin@sfmix.org".to_string(),
            vec![DEFAULT_ADMIN_GROUP.to_string()],
            "as",
        );
        let command = parse_command("show interface 64500").unwrap();
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_unknown_asn_denied() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "user@example.com".to_string(),
            vec!["as99999".to_string()],
            "as",
        );
        let command = parse_command("show interface 99999").unwrap();
        assert!(matches!(
            engine.evaluate(&command, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    fn interface_name_command(interface: &str) -> Command {
        // InterfaceDetail with an interface-name target is constructed by the MCP/REST
        // layer directly — the grammar doesn't have a path for this.
        Command {
            verb: Verb::Show,
            resource: Resource::InterfaceDetail,
            target: Some(interface.to_string()),
            device: None,
            address_family: AddressFamily::IPv4,
            filter_asn: None,
            filter_vlan: None,
            filter_source: None,
        }
    }

    #[test]
    fn test_admin_allowed_interface_name_query() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "admin@sfmix.org".to_string(),
            vec![DEFAULT_ADMIN_GROUP.to_string()],
            "as",
        );
        let command = interface_name_command("Ethernet3/1");
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_owner_allowed_own_interface_name_query() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        // AS64500 owns Ethernet3/1 — querying own port by interface name is allowed
        let identity = Identity::from_oidc_claims(
            "user@peer-a.net".to_string(),
            vec!["as64500".to_string()],
            "as",
        );
        let command = interface_name_command("Ethernet3/1");
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_non_owner_denied_interface_name_query() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        // AS64501 does not own Ethernet3/1 (belongs to AS64500)
        let identity = Identity::from_oidc_claims(
            "user@peer-b.net".to_string(),
            vec!["as64501".to_string()],
            "as",
        );
        let command = interface_name_command("Ethernet3/1");
        assert!(matches!(
            engine.evaluate(&command, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_anon_denied_interface_name_query() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let command = interface_name_command("Ethernet3/1");
        assert!(matches!(
            engine.evaluate(&command, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_anon_denied_optics_detail_by_asn() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let command = parse_command("show optics 64500").unwrap();
        assert!(matches!(
            engine.evaluate(&command, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_auth_owner_allowed_optics_detail_own_asn() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "user@peer-a.net".to_string(),
            vec!["as64500".to_string()],
            "as",
        );
        let command = parse_command("show optics 64500").unwrap();
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_anon_denied_optics_inventory() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let command = parse_command("show optics inventory").unwrap();
        assert!(matches!(
            engine.evaluate(&command, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_admin_allowed_optics_inventory() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "admin@sfmix.org".to_string(),
            vec![DEFAULT_ADMIN_GROUP.to_string()],
            "as",
        );
        let command = parse_command("show optics inventory").unwrap();
        assert_eq!(engine.evaluate(&command, &identity, &participants), PolicyDecision::Allow);
    }

}
