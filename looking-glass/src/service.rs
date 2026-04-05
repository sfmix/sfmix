use arc_swap::ArcSwap;
use thiserror::Error;

use crate::backend::pool::DevicePool;
use crate::command::{Command, Resource};
use crate::format::ColorMode;
use crate::identity::Identity;
use crate::oidc::OidcClient;
use crate::participants::{ParticipantMap, PortMap, PortClass};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::ratelimit::{ConnectionTracker, DeviceRateLimiter, RateLimiter};
use crate::structured::CommandOutput;

// ---------------------------------------------------------------------------
// RPC types
// ---------------------------------------------------------------------------

/// A request to the looking glass service.
pub struct Request {
    pub command: Command,
    pub identity: Identity,
    pub rate_key: String,
}

/// A single device's contribution to a response.
#[derive(Debug)]
pub struct DeviceResult {
    pub device: String,
    pub success: bool,
    pub output: CommandOutput,
}

/// Service-level errors returned from `execute()`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("denied: {0}")]
    PolicyDenied(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("device error: {0}")]
    DeviceError(String),
    #[error("bad request: {0}")]
    BadRequest(String),
}

// ---------------------------------------------------------------------------
// LookingGlass — the unified service core
// ---------------------------------------------------------------------------

/// The central looking glass service.
///
/// All frontends (CLI, HTTP/REST, HTTP/MCP) call `execute()` to run
/// commands through the unified policy → rate-limit → device dispatch
/// → output filter pipeline.
pub struct LookingGlass {
    pub service_name: String,
    pub policy: PolicyEngine,
    pub rate_limiter: RateLimiter,
    pub device_rate_limiter: DeviceRateLimiter,
    pub connection_tracker: ConnectionTracker,
    pub participants: ArcSwap<ParticipantMap>,
    pub port_map: ArcSwap<PortMap>,
    pub device_pool: DevicePool,
    pub group_prefix: String,
    pub oidc_client: Option<OidcClient>,
    pub public_vlans: Vec<String>,
}

impl LookingGlass {
    /// Execute a command through the full pipeline.
    ///
    /// Returns a vec of per-device results. For local resources like
    /// Participants, returns a single synthetic result.
    pub async fn execute(&self, req: Request) -> Result<Vec<DeviceResult>, Error> {
        let command = &req.command;
        let identity = &req.identity;

        // Local resources — no device dispatch needed
        if command.resource == Resource::Participants {
            let pmap = self.participants.load();
            let text = crate::format::format_participants(&pmap, ColorMode::Plain);
            return Ok(vec![DeviceResult {
                device: "local".to_string(),
                success: true,
                output: CommandOutput::Participants(text),
            }]);
        }

        // Validate targets before touching any device
        if let Some(ref target) = command.target {
            match command.resource {
                Resource::NetworkReachability => {
                    if !is_valid_destination(target) {
                        return Err(Error::BadRequest(format!(
                            "invalid destination: {target}"
                        )));
                    }
                }
                Resource::BgpNeighbor => {
                    if target.parse::<std::net::IpAddr>().is_err() {
                        return Err(Error::BadRequest(format!(
                            "invalid IP address: {target}"
                        )));
                    }
                }
                Resource::InterfaceDetail | Resource::OpticsDetail => {
                    let pmap = self.port_map.load();
                    if pmap.len() > 0 && !pmap.known_interface(target) {
                        return Err(Error::BadRequest(format!(
                            "unknown interface: {target}"
                        )));
                    }
                }
                _ => {}
            }
        }

        // Policy check
        match self.policy.evaluate(command, identity, &self.participants.load()) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny { reason } => {
                return Err(Error::PolicyDenied(reason));
            }
        }

        // Rate limit
        let _guard = self
            .rate_limiter
            .acquire(&req.rate_key)
            .await
            .map_err(|e| Error::RateLimited(e.to_string()))?;

        // Device dispatch
        let mut rx = self
            .device_pool
            .execute(
                command,
                identity,
                &self.device_rate_limiter,
                self.policy.admin_group(),
                &self.port_map.load(),
                &self.public_vlans,
            )
            .await
            .map_err(|e| Error::DeviceError(e.to_string()))?;

        // Collect results, applying post-filters
        let mut results = Vec::new();
        while let Some(mut r) = rx.recv().await {
            // ASN post-filter
            if let Some(asn) = command.filter_asn {
                let pmap = self.port_map.load();
                r.output = apply_asn_filter(r.output, &r.device, asn, &pmap);
            }
            // VLAN post-filter
            if let Some(ref vlan) = command.filter_vlan {
                r.output = apply_vlan_filter(r.output, vlan);
            }
            results.push(DeviceResult {
                device: r.device,
                success: r.success,
                output: r.output,
            });
        }

        Ok(results)
    }

    /// Number of configured devices.
    pub fn device_count(&self) -> usize {
        self.device_pool.device_count()
    }

    /// Load a snapshot of the current participant map.
    pub fn participants(&self) -> arc_swap::Guard<std::sync::Arc<ParticipantMap>> {
        self.participants.load()
    }

    /// The admin group name from the policy engine.
    pub fn admin_group(&self) -> &str {
        self.policy.admin_group()
    }
}

// ---------------------------------------------------------------------------
// Target validation
// ---------------------------------------------------------------------------

/// Check if a string is a valid IP address or DNS hostname (RFC 1123).
/// Rejects CLI metacharacters, pipes, semicolons, etc.
fn is_valid_destination(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // DNS hostname: labels separated by dots
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

// ---------------------------------------------------------------------------
// Post-filters (moved from frontend/common.rs)
// ---------------------------------------------------------------------------

/// Filter interfaces/optics output to only ports belonging to the given ASN.
fn apply_asn_filter(
    output: CommandOutput,
    device: &str,
    asn: u32,
    pmap: &PortMap,
) -> CommandOutput {
    let matches_asn = |name: &str| -> bool {
        matches!(pmap.classify(device, name), Some(PortClass::Participant { asn: a }) if *a == asn)
    };

    match output {
        CommandOutput::InterfacesStatus(mut entries) => {
            // First pass: find Port-Channels (including subinterfaces) that match the ASN.
            // Collect both the full name and the base name (without .VLAN suffix) so that
            // member interfaces referencing "Port-Channel114" are found when the PortMap
            // entry is "Port-Channel114.998".
            let mut matched_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for e in entries.iter() {
                if e.name.starts_with("Port-Channel") && matches_asn(&e.name) {
                    matched_pcs.insert(e.name.clone());
                    // Also insert base name (strip .VLAN suffix)
                    if let Some(base) = e.name.split('.').next() {
                        matched_pcs.insert(base.to_string());
                    }
                }
            }

            // Keep entries that match the ASN directly OR are members of a matched PC
            entries.retain(|e| {
                matches_asn(&e.name)
                    || e.port_channel.as_ref().is_some_and(|pc| matched_pcs.contains(pc))
            });
            CommandOutput::InterfacesStatus(entries)
        }
        CommandOutput::Optics(mut entries) => {
            // Same Port-Channel member logic as InterfacesStatus
            let mut matched_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for e in entries.iter() {
                if let Some(ref pc) = e.port_channel {
                    if matches_asn(pc) {
                        matched_pcs.insert(pc.clone());
                        if let Some(base) = pc.split('.').next() {
                            matched_pcs.insert(base.to_string());
                        }
                    }
                }
            }
            // Also check the PortMap directly for Port-Channels belonging to this ASN
            for (key, class) in pmap.iter() {
                if key.0 == device {
                    if let PortClass::Participant { asn: a } = *class {
                        if a == asn && key.1.starts_with("Port-Channel") {
                            matched_pcs.insert(key.1.clone());
                            if let Some(base) = key.1.split('.').next() {
                                matched_pcs.insert(base.to_string());
                            }
                        }
                    }
                }
            }
            entries.retain(|e| {
                matches_asn(&e.name)
                    || e.port_channel.as_ref().is_some_and(|pc| matched_pcs.contains(pc))
            });
            CommandOutput::Optics(entries)
        }
        CommandOutput::OpticsDetail(mut entries) => {
            // Same logic for OpticsDetail
            let mut matched_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for (key, class) in pmap.iter() {
                if key.0 == device {
                    if let PortClass::Participant { asn: a } = *class {
                        if a == asn && key.1.starts_with("Port-Channel") {
                            matched_pcs.insert(key.1.clone());
                            if let Some(base) = key.1.split('.').next() {
                                matched_pcs.insert(base.to_string());
                            }
                        }
                    }
                }
            }
            entries.retain(|e| {
                matches_asn(&e.name)
                    || e.port_channel.as_ref().is_some_and(|pc| matched_pcs.contains(pc))
            });
            CommandOutput::OpticsDetail(entries)
        }
        other => other,
    }
}

/// Filter MAC table output to only entries matching the given VLAN.
fn apply_vlan_filter(output: CommandOutput, vlan: &str) -> CommandOutput {
    match output {
        CommandOutput::MacAddressTable(mut entries) => {
            entries.retain(|e| e.vlan == vlan);
            CommandOutput::MacAddressTable(entries)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netbox::NetboxParticipant;
    use crate::structured::*;

    const DEVICE: &str = "switch03.fmt01.sfmix.org";

    fn test_port_map() -> PortMap {
        let participants = vec![
            NetboxParticipant {
                asn: 6939,
                name: "Hurricane Electric".to_string(),
                participant_type: Some("Member".to_string()),
                ports: vec![
                    (DEVICE.to_string(), "Port-Channel101".to_string()),
                ],
            },
            NetboxParticipant {
                asn: 6140,
                name: "Two P".to_string(),
                participant_type: Some("Member".to_string()),
                ports: vec![
                    ("switch01.fmt01.sfmix.org".to_string(), "Port-Channel114.998".to_string()),
                ],
            },
            NetboxParticipant {
                asn: 13335,
                name: "Cloudflare".to_string(),
                participant_type: Some("Member".to_string()),
                ports: vec![
                    (DEVICE.to_string(), "Ethernet5/1".to_string()),
                ],
            },
        ];
        let core_ports = vec![
            (DEVICE.to_string(), "Ethernet50/1".to_string()),
            (DEVICE.to_string(), "Ethernet51/1".to_string()),
        ];
        PortMap::build(&participants, &core_ports)
    }

    fn iface(name: &str, desc: &str, port_channel: Option<&str>) -> InterfaceStatus {
        InterfaceStatus {
            name: name.to_string(),
            description: desc.to_string(),
            link_status: "connected".to_string(),
            protocol_status: "up".to_string(),
            speed: "100Gbps".to_string(),
            interface_type: "100GBASE-LR".to_string(),
            vlan: String::new(),
            auto_negotiate: false,
            member_interfaces: vec![],
            port_channel: port_channel.map(|s| s.to_string()),
        }
    }

    fn mac_entry(vlan: &str, mac: &str, iface: &str) -> MacEntry {
        MacEntry {
            vlan: vlan.to_string(),
            mac_address: mac.to_string(),
            entry_type: "Dynamic".to_string(),
            interface: iface.to_string(),
        }
    }

    fn optic(name: &str) -> InterfaceOptics {
        optic_with_pc(name, None)
    }

    fn optic_with_pc(name: &str, port_channel: Option<&str>) -> InterfaceOptics {
        InterfaceOptics {
            name: name.to_string(),
            description: String::new(),
            link_status: "connected".to_string(),
            media_type: "100GBASE-LR".to_string(),
            temperature_c: None,
            voltage_v: None,
            lanes: vec![],
            dom_supported: false,
            port_channel: port_channel.map(|s| s.to_string()),
        }
    }

    #[test]
    fn asn_filter_keeps_matching_port() {
        let pmap = test_port_map();
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet5/1", "Peer: Cloudflare (AS13335)", None),
            iface("Ethernet50/1", "Core: transport", None),
            iface("Ethernet6/1", "Peer: Someone else", None),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 13335, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].name, "Ethernet5/1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_empty_when_no_match() {
        let pmap = test_port_map();
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet50/1", "Core: transport", None),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 13335, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => assert!(v.is_empty()),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_includes_port_channel_and_members() {
        let pmap = test_port_map();
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet1/1", "LAG: Hurricane Electric (AS6939)", Some("Port-Channel101")),
            iface("Ethernet2/1", "LAG: Hurricane Electric (AS6939)", Some("Port-Channel101")),
            iface("Port-Channel101", "Peer: Hurricane Electric (AS6939)", None),
            iface("Ethernet50/1", "Core: transport", None),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 6939, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => {
                let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, &["Ethernet1/1", "Ethernet2/1", "Port-Channel101"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_includes_members_of_subinterface_port_channel() {
        let pmap = test_port_map();
        let device = "switch01.fmt01.sfmix.org";
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet7", "LAG: Two P (AS6140)", Some("Port-Channel114")),
            iface("Ethernet8", "LAG: Two P (AS6140)", Some("Port-Channel114")),
            iface("Port-Channel114.998", "Peer: Two P (AS6140)", None),
            iface("Ethernet50/1", "Core: transport", None),
        ]);
        let filtered = apply_asn_filter(output, device, 6140, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => {
                let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, &["Ethernet7", "Ethernet8", "Port-Channel114.998"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_subinterface_no_false_positives() {
        let pmap = test_port_map();
        let device = "switch01.fmt01.sfmix.org";
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet7", "LAG: Two P", Some("Port-Channel114")),
            iface("Port-Channel114.998", "Peer: Two P (AS6140)", None),
            iface("Ethernet9", "LAG: Other", Some("Port-Channel200")),
            iface("Port-Channel200", "Other peer", None),
        ]);
        let filtered = apply_asn_filter(output, device, 6140, &pmap);
        match filtered {
            CommandOutput::InterfacesStatus(v) => {
                let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, &["Ethernet7", "Port-Channel114.998"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_optics() {
        let pmap = test_port_map();
        let output = CommandOutput::Optics(vec![
            optic("Ethernet5/1"),
            optic("Ethernet50/1"),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 13335, &pmap);
        match filtered {
            CommandOutput::Optics(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].name, "Ethernet5/1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_optics_includes_lag_members() {
        let pmap = test_port_map();
        let output = CommandOutput::Optics(vec![
            optic_with_pc("Ethernet1/1", Some("Port-Channel101")),
            optic_with_pc("Ethernet2/1", Some("Port-Channel101")),
            optic("Ethernet50/1"),
            optic("Ethernet6/1"),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 6939, &pmap);
        match filtered {
            CommandOutput::Optics(v) => {
                let names: Vec<&str> = v.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, vec!["Ethernet1/1", "Ethernet2/1"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn vlan_filter_keeps_matching() {
        let output = CommandOutput::MacAddressTable(vec![
            mac_entry("998", "aa:bb:cc:dd:ee:01", "Ethernet1"),
            mac_entry("999", "aa:bb:cc:dd:ee:02", "Ethernet2"),
            mac_entry("998", "aa:bb:cc:dd:ee:03", "Ethernet3"),
        ]);
        let filtered = apply_vlan_filter(output, "998");
        match filtered {
            CommandOutput::MacAddressTable(v) => {
                assert_eq!(v.len(), 2);
                assert!(v.iter().all(|e| e.vlan == "998"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn vlan_filter_empty_when_no_match() {
        let output = CommandOutput::MacAddressTable(vec![
            mac_entry("999", "aa:bb:cc:dd:ee:01", "Ethernet1"),
        ]);
        let filtered = apply_vlan_filter(output, "100");
        match filtered {
            CommandOutput::MacAddressTable(v) => assert!(v.is_empty()),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn asn_filter_passes_through_mac_table() {
        let pmap = test_port_map();
        let output = CommandOutput::MacAddressTable(vec![
            mac_entry("998", "aa:bb:cc:dd:ee:01", "Ethernet1"),
        ]);
        let filtered = apply_asn_filter(output, DEVICE, 13335, &pmap);
        match filtered {
            CommandOutput::MacAddressTable(v) => assert_eq!(v.len(), 1),
            _ => panic!("wrong variant"),
        }
    }

    // ── Target validation tests ──────────────────────────────────────

    #[test]
    fn valid_ipv4() {
        assert!(is_valid_destination("192.0.2.1"));
        assert!(is_valid_destination("10.0.0.1"));
    }

    #[test]
    fn valid_ipv6() {
        assert!(is_valid_destination("2001:db8::1"));
        assert!(is_valid_destination("::1"));
    }

    #[test]
    fn valid_hostname() {
        assert!(is_valid_destination("example.com"));
        assert!(is_valid_destination("a-b.example.com"));
        assert!(is_valid_destination("host"));
    }

    #[test]
    fn rejects_cli_injection() {
        assert!(!is_valid_destination("8.8.8.8 | show run"));
        assert!(!is_valid_destination("8.8.8.8; show run"));
        assert!(!is_valid_destination("$(reboot)"));
        assert!(!is_valid_destination("foo`reboot`"));
        assert!(!is_valid_destination(""));
    }

    #[test]
    fn rejects_bad_hostname() {
        assert!(!is_valid_destination("-leading.com"));
        assert!(!is_valid_destination("trailing-.com"));
        assert!(!is_valid_destination(".leading-dot.com"));
        assert!(!is_valid_destination("double..dot.com"));
    }

    #[test]
    fn known_interface_lookup() {
        let pmap = test_port_map();
        assert!(pmap.known_interface("Ethernet5/1"));
        assert!(pmap.known_interface("Ethernet50/1"));
        assert!(!pmap.known_interface("Ethernet99/1"));
        assert!(!pmap.known_interface("Ethernet5/1 | show run"));
    }

    #[test]
    fn vlan_filter_passes_through_interfaces() {
        let output = CommandOutput::InterfacesStatus(vec![
            iface("Ethernet1", "test", None),
        ]);
        let filtered = apply_vlan_filter(output, "998");
        match filtered {
            CommandOutput::InterfacesStatus(v) => assert_eq!(v.len(), 1),
            _ => panic!("wrong variant"),
        }
    }
}
