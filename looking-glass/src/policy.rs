use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use tracing::debug;

use crate::command::{Command, Resource, Verb};
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
            admin_group: "IX Administrators".to_string(),
        })
    }

    #[allow(dead_code)]
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
                        "show interface *".to_string(),
                        "show optics".to_string(),
                        "show optics *".to_string(),
                        "show ip bgp summary".to_string(),
                        "show bgp *".to_string(),
                        "show lldp neighbors".to_string(),
                        "show arp".to_string(),
                        "show ipv6 neighbors".to_string(),
                        "show participants".to_string(),
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
            admin_group: "IX Administrators".to_string(),
        }
    }

    /// Evaluate whether the given command is allowed for the given identity.
    ///
    /// For Phase 1 (public/telnet), this primarily checks whether the command
    /// is in the public command set. Port-scoped commands against participant
    /// ports require authentication and ASN ownership (or admin).
    pub fn evaluate(
        &self,
        command: &Command,
        identity: &Identity,
        participants: &ParticipantMap,
    ) -> PolicyDecision {
        // Help is always allowed
        if command.resource == Resource::Help {
            return PolicyDecision::Allow;
        }

        // Port-scoped commands targeting a specific interface need ownership check
        if command.resource.is_port_scoped() {
            if let Some(ref target) = command.target {
                // Check if this is a participant port
                if is_participant_port(target, participants) {
                    if !identity.authenticated {
                        return PolicyDecision::Deny {
                            reason: "authentication required for participant port queries".to_string(),
                        };
                    }
                    // Authenticated: check ASN ownership (or admin)
                    if !identity.is_admin(&self.admin_group()) {
                        let owns_port = identity.asns.iter().any(|asn| {
                            // Check all devices — target is just the interface name
                            participants.port_belongs_to_any_device(target, *asn)
                        });
                        if !owns_port {
                            return PolicyDecision::Deny {
                                reason: "you do not own this port".to_string(),
                            };
                        }
                    }
                }
                // Core/infrastructure ports fall through to normal rule matching
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

    fn admin_group(&self) -> &str {
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

/// Check if an interface name belongs to any participant across all devices.
fn is_participant_port(interface: &str, participants: &ParticipantMap) -> bool {
    participants.interface_is_participant_port(interface)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar::parse_command;
    use crate::participants::{Participant, ParticipantPort};

    fn test_participants() -> ParticipantMap {
        // AS64500 owns Ethernet3/1, AS64501 owns Ethernet3/2
        let mut map = ParticipantMap::empty();
        map.insert(Participant {
            asn: 64500,
            name: "Test Peer A".to_string(),
            ports: vec![ParticipantPort {
                device: "switch01.sfo02".to_string(),
                interface: "Ethernet3/1".to_string(),
            }],
            sessions: vec![],
        });
        map.insert(Participant {
            asn: 64501,
            name: "Test Peer B".to_string(),
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
    fn test_public_policy_allows_optics() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = ParticipantMap::empty();

        let cmd = parse_command("show optics").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    // --- Per-ASN enforcement tests ---

    #[test]
    fn test_anon_denied_participant_port_interface_detail() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        // Ethernet3/1 is a participant port — anon should be denied
        let cmd = parse_command("show interface Ethernet3/1").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_anon_allowed_infrastructure_port() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        // Ethernet49/1 is NOT a participant port — anon should be allowed
        let cmd = parse_command("show interface Ethernet49/1").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_auth_owner_allowed_own_port() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        // AS64500 user querying their own port Ethernet3/1
        let identity = Identity::from_oidc_claims(
            "user@peer-a.net".to_string(),
            vec!["as64500".to_string()],
            "as",
        );
        let cmd = parse_command("show interface Ethernet3/1").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_auth_non_owner_denied_other_port() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        // AS64501 user querying AS64500's port Ethernet3/1
        let identity = Identity::from_oidc_claims(
            "user@peer-b.net".to_string(),
            vec!["as64501".to_string()],
            "as",
        );
        let cmd = parse_command("show interface Ethernet3/1").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_admin_allowed_any_port() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        // Admin user (no ASN ownership) can see any participant port
        let identity = Identity::from_oidc_claims(
            "admin@sfmix.org".to_string(),
            vec!["IX Administrators".to_string()],
            "as",
        );
        let cmd = parse_command("show interface Ethernet3/1").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_anon_denied_optics_detail_participant_port() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        // OpticsDetail for a participant port should be denied for anon
        let cmd = parse_command("show optics Ethernet3/1").unwrap();
        assert!(matches!(
            engine.evaluate(&cmd, &identity, &participants),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_auth_owner_allowed_optics_detail_own_port() {
        let engine = PolicyEngine::default_public();
        let participants = test_participants();

        let identity = Identity::from_oidc_claims(
            "user@peer-a.net".to_string(),
            vec!["as64500".to_string()],
            "as",
        );
        let cmd = parse_command("show optics Ethernet3/1").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }

    #[test]
    fn test_anon_allowed_optics_global() {
        let engine = PolicyEngine::default_public();
        let identity = Identity::anonymous();
        let participants = test_participants();

        // Global optics (no target) is public
        let cmd = parse_command("show optics").unwrap();
        assert_eq!(engine.evaluate(&cmd, &identity, &participants), PolicyDecision::Allow);
    }
}
