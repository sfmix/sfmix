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
                        "show ip bgp summary".to_string(),
                        "show bgp *".to_string(),
                        "show lldp neighbors".to_string(),
                        "show arp".to_string(),
                        "show mac address-table".to_string(),
                        "show ipv6 neighbors".to_string(),
                        "show participants".to_string(),
                        "show vxlan vtep".to_string(),
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
        if matches!(command.resource, Resource::Help | Resource::Whoami | Resource::Logout | Resource::NetboxCache) {
            return PolicyDecision::Allow;
        }

        // Port-scoped commands target a participant ASN — require auth + ownership
        if command.resource.is_port_scoped() {
            if let Some(ref target) = command.target {
                let asn: u32 = match target.parse() {
                    Ok(a) => a,
                    Err(_) => {
                        return PolicyDecision::Deny {
                            reason: format!("invalid ASN: {target}"),
                        };
                    }
                };
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
                if !identity.is_admin(&self.admin_group()) && !identity.asns.contains(&asn) {
                    return PolicyDecision::Deny {
                        reason: "you do not administer this ASN".to_string(),
                    };
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
            if !identity.is_admin(&self.admin_group()) && !identity.asns.contains(&asn) {
                return PolicyDecision::Deny {
                    reason: "you do not administer this ASN".to_string(),
                };
            }
        }

        // BGP neighbor commands: if the address belongs to a participant, check ownership
        if command.resource == Resource::BgpNeighbor {
            if let Some(ref addr) = command.target {
                if let Some(owner_asn) = participants.session_owner(addr) {
                    if !identity.authenticated {
                        return PolicyDecision::Deny {
                            reason: "authentication required for participant BGP neighbor queries".to_string(),
                        };
                    }
                    if !identity.is_admin(&self.admin_group()) && !identity.asns.contains(&owner_asn) {
                        return PolicyDecision::Deny {
                            reason: "you do not administer this BGP session".to_string(),
                        };
                    }
                }
                // Non-participant sessions (infrastructure BGP) fall through to rule matching
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
                if !criteria.groups.is_empty() {
                    if !criteria.groups.iter().any(|g| identity.groups.contains(g)) {
                        return false;
                    }
                }
                true
            }
        }
    }

    fn command_matches_allow_list(&self, command: &Command, allow: &[String]) -> bool {
        let cmd_str = command_to_match_string(command);
        for pattern in allow {
            if pattern_matches(&cmd_str, pattern) {
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
        Resource::BgpSummary => match command.address_family {
            crate::command::AddressFamily::IPv4 => "ip bgp summary",
            crate::command::AddressFamily::IPv6 => "bgp ipv6 unicast summary",
        },
        Resource::BgpNeighbor => {
            return format!("show bgp neighbor {}", command.target.as_deref().unwrap_or("*"));
        }
        Resource::MacAddressTable => "mac address-table",
        Resource::ArpTable => "arp",
        Resource::NdTable => "ipv6 neighbors",
        Resource::LldpNeighbors => "lldp neighbors",
        Resource::Optics => return format!("{verb} optics"),
        Resource::OpticsDetail => {
            return format!("show optics {}", command.target.as_deref().unwrap_or("*"));
        }
        Resource::Participants => "participants",
        Resource::VxlanVtep => "vxlan vtep",
        Resource::NetworkReachability => {
            return format!("{verb} {}", command.target.as_deref().unwrap_or(""));
        }
        Resource::Help => "help",
        Resource::Login => return "login".to_string(),
        Resource::Whoami => return "whoami".to_string(),
        Resource::Logout => return "logout".to_string(),
        Resource::NetboxCache => return "show netbox".to_string(),
    };
    format!("{verb} {resource}")
}

/// Simple glob-style pattern matching (only supports trailing `*`).
fn pattern_matches(input: &str, pattern: &str) -> bool {
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        input.starts_with(prefix.trim_end())
    } else {
        input == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let cmd = parse_command("show interfaces status").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_public_policy_allows_ping() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = ParticipantMap::empty();

        let cmd = parse_command("ping 8.8.8.8").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_public_policy_allows_help() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = ParticipantMap::empty();

        let cmd = parse_command("help").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_public_policy_allows_optics_global() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let cmd = parse_command("show optics").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    // --- ASN-targeted port-scoped commands ---

    #[test]
    fn test_anon_denied_interface_detail_by_asn() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let cmd = parse_command("show interface 64500").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
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
        let cmd = parse_command("show interface 64500").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
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
        let cmd = parse_command("show interface 64500").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
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
        let cmd = parse_command("show interface 64500").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
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
        let cmd = parse_command("show interface 99999").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_anon_denied_optics_detail_by_asn() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let cmd = parse_command("show optics 64500").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
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
        let cmd = parse_command("show optics 64500").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    // --- BGP neighbor ownership ---

    #[test]
    fn test_anon_denied_bgp_neighbor_participant_session() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        let cmd = parse_command("show bgp neighbor 198.51.100.1").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_auth_owner_allowed_bgp_neighbor_own_session() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "user@peer-a.net".to_string(),
            vec!["as64500".to_string()],
            "as",
        );
        let cmd = parse_command("show bgp neighbor 198.51.100.1").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_auth_non_owner_denied_bgp_neighbor_other_session() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "user@peer-b.net".to_string(),
            vec!["as64501".to_string()],
            "as",
        );
        let cmd = parse_command("show bgp neighbor 198.51.100.1").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_anon_allowed_bgp_neighbor_infrastructure() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        // 10.0.0.1 is not a participant session — infrastructure BGP, allowed
        let cmd = parse_command("show bgp neighbor 10.0.0.1").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }
}
