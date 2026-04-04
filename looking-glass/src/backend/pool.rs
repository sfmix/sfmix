use std::collections::HashMap;

use anyhow::{Result, anyhow};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::ratelimit::{DeviceRateLimiter, DeviceRateLimitError};

use crate::command::{Command, CommandResult, Resource};
use crate::config::{DeviceConfig, Platform};
use crate::identity::Identity;
use crate::participants::{PortClass, PortMap};
use crate::structured::CommandOutput;

use super::arista_eos::AristaEosDriver;
use super::nokia_sros::NokiaSrosDriver;
use super::driver::DeviceDriver;

/// Manages a pool of device configurations and dispatches commands.
///
/// Device-level rate limiting (concurrency + CPM) is enforced via
/// `DeviceRateLimiter`, which is passed to `execute()`. This keeps
/// the pool focused on dispatch and the rate limiter focused on limits.
pub struct DevicePool {
    devices: HashMap<String, DeviceConfig>,
}

impl DevicePool {
    pub fn new(devices: Vec<DeviceConfig>) -> Self {
        let map: HashMap<String, DeviceConfig> = devices
            .into_iter()
            .map(|d| (d.name.clone(), d))
            .collect();
        Self {
            devices: map,
        }
    }

    /// Execute a command, dispatching to one or all devices.
    ///
    /// Returns an `mpsc::Receiver<CommandResult>` that yields results as
    /// each device completes — frontends can render incrementally instead
    /// of waiting for the slowest device.
    ///
    /// When `command.device` is `Some`, targets that specific device.
    /// When `None`, fans out to **all** configured devices concurrently.
    ///
    /// Output is always filtered through the `PortMap` allowlist.
    pub async fn execute(
        &self,
        command: &Command,
        identity: &Identity,
        device_rl: &DeviceRateLimiter,
        admin_group: &str,
        port_map: &PortMap,
        public_vlans: &[String],
    ) -> Result<mpsc::Receiver<CommandResult>> {
        // Commands that don't need a device
        if matches!(command.resource, Resource::Help | Resource::Participants) {
            return Err(anyhow!(
                "command should be handled locally, not dispatched to device"
            ));
        }

        if let Some(ref name) = command.device {
            let config = self
                .devices
                .get(name)
                .ok_or_else(|| anyhow!("unknown device: {name}"))?
                .clone();
            let cmd = command.clone();
            let id = identity.clone();
            let ag = admin_group.to_string();
            let (tx, rx) = mpsc::channel(1);

            // Acquire per-device permit (concurrency + CPM) — rejects immediately
            let device_permit = device_rl
                .try_acquire(name)
                .await
                .map_err(|e| anyhow!("{e}"))?;

            let pmap = port_map.clone();
            let pvlans: Vec<String> = public_vlans.to_vec();

            tokio::spawn(async move {
                let _permit = device_permit;
                debug!(
                    device = config.name,
                    "dispatching command to device"
                );
                match execute_on_device_inner(&config, &cmd, &id, &ag, &pmap, &pvlans).await {
                    Ok(r) => { let _ = tx.send(r).await; }
                    Err(e) => {
                        warn!(device = config.name, error = %e, "device command failed");
                    }
                }
            });
            return Ok(rx);
        }

        // Fan out to all devices concurrently
        if self.devices.is_empty() {
            return Err(anyhow!("no devices configured"));
        }

        let ag = admin_group.to_string();
        let (tx, rx) = mpsc::channel(self.devices.len());

        // Pre-acquire all device permits before spawning tasks.
        // Collect (config, permit) pairs; skip devices that are busy/rate-limited.
        let mut dispatches = Vec::new();
        for name in self.devices.keys() {
            match device_rl.try_acquire(name).await {
                Ok(permit) => {
                    dispatches.push((self.devices[name].clone(), permit));
                }
                Err(DeviceRateLimitError::UnknownDevice(_)) => {
                    warn!(device = name, "device not in rate limiter, skipping");
                }
                Err(e) => {
                    warn!(device = name, error = %e, "device rate limited, skipping in fan-out");
                }
            }
        }

        if dispatches.is_empty() {
            return Err(anyhow!("all devices are currently rate limited"));
        }

        let pmap = port_map.clone();

        for (config, device_permit) in dispatches {
            let cmd = command.clone();
            let id = identity.clone();
            let tx = tx.clone();
            let ag = ag.clone();
            let pmap = pmap.clone();
            let pvlans: Vec<String> = public_vlans.to_vec();
            tokio::spawn(async move {
                let _permit = device_permit;
                match execute_on_device_inner(&config, &cmd, &id, &ag, &pmap, &pvlans).await {
                    Ok(r) => { let _ = tx.send(r).await; }
                    Err(e) => {
                        warn!(device = config.name, error = %e, "device command failed");
                    }
                }
            });
        }
        // Drop our copy so rx closes when all tasks finish
        drop(tx);

        Ok(rx)
    }

    /// Number of configured devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// List configured device names.
    pub fn device_names(&self) -> Vec<&str> {
        self.devices.keys().map(|s| s.as_str()).collect()
    }
}

/// Execute a command on a device and apply output filtering.
async fn execute_on_device_inner(
    config: &DeviceConfig,
    command: &Command,
    identity: &Identity,
    admin_group: &str,
    pmap: &PortMap,
    public_vlans: &[String],
) -> Result<CommandResult> {
    let driver: Box<dyn DeviceDriver> = match config.platform {
        Platform::AristaEos => Box::new(AristaEosDriver::new(config.clone())),
        Platform::NokiaSros => Box::new(NokiaSrosDriver::new(config.clone())),
    };

    let mut result = driver.execute(command).await?;

    result.output = filter_output_with_lookup(result.output, &config.name, identity, pmap, admin_group, public_vlans);

    Ok(result)
}

/// Allowlist filter: only ports classified in the PortMap are visible.
///
/// - Loopback: always visible (safety net)
/// - Not in map: hidden
/// - Core: visible to everyone
/// - Participant(asn): visible to owning ASN or admin
fn filter_output_with_lookup(
    output: CommandOutput,
    device: &str,
    identity: &Identity,
    pmap: &PortMap,
    admin_group: &str,
    public_vlans: &[String],
) -> CommandOutput {
    let is_admin = identity.is_admin(admin_group);
    match output {
        CommandOutput::InterfacesStatus(mut entries) => {
            // First pass: determine which Port-Channels are visible.
            // Also insert the base name (without .VLAN suffix) so that member
            // interfaces referencing "Port-Channel114" are found when the PortMap
            // entry is "Port-Channel114.998".
            let mut visible_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for e in entries.iter() {
                if e.name.starts_with("Port-Channel")
                    && port_visible(device, &e.name, identity, pmap, is_admin)
                {
                    visible_pcs.insert(e.name.clone());
                    if let Some(base) = e.name.split('.').next() {
                        visible_pcs.insert(base.to_string());
                    }
                }
            }

            // Retain ports that are directly visible OR are members of a visible Port-Channel
            entries.retain(|e| {
                port_visible(device, &e.name, identity, pmap, is_admin)
                    || e.port_channel.as_ref().is_some_and(|pc| visible_pcs.contains(pc))
            });
            CommandOutput::InterfacesStatus(entries)
        }
        CommandOutput::Optics(mut entries) => {
            // Same Port-Channel member logic as InterfacesStatus: physical
            // member interfaces (e.g. Ethernet7) aren't in the PortMap but
            // should be visible when their parent Port-Channel is.
            let mut visible_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for (key, class) in pmap.iter() {
                if key.0 == device
                    && key.1.starts_with("Port-Channel")
                    && match class {
                        PortClass::Core => true,
                        PortClass::Participant { asn } => is_admin || identity.asns.contains(asn),
                    }
                {
                    visible_pcs.insert(key.1.clone());
                    if let Some(base) = key.1.split('.').next() {
                        visible_pcs.insert(base.to_string());
                    }
                }
            }
            entries.retain(|e| {
                port_visible(device, &e.name, identity, pmap, is_admin)
                    || e.port_channel.as_ref().is_some_and(|pc| visible_pcs.contains(pc))
            });
            CommandOutput::Optics(entries)
        }
        CommandOutput::OpticsDetail(mut entries) => {
            let mut visible_pcs: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for (key, class) in pmap.iter() {
                if key.0 == device
                    && key.1.starts_with("Port-Channel")
                    && match class {
                        PortClass::Core => true,
                        PortClass::Participant { asn } => is_admin || identity.asns.contains(asn),
                    }
                {
                    visible_pcs.insert(key.1.clone());
                    if let Some(base) = key.1.split('.').next() {
                        visible_pcs.insert(base.to_string());
                    }
                }
            }
            entries.retain(|e| {
                port_visible(device, &e.name, identity, pmap, is_admin)
                    || e.port_channel.as_ref().is_some_and(|pc| visible_pcs.contains(pc))
            });
            CommandOutput::OpticsDetail(entries)
        }
        CommandOutput::MacAddressTable(mut entries) => {
            // Filter out VXLAN-learned entries
            entries.retain(|e| !e.interface.eq_ignore_ascii_case("Vxlan1"));
            // VLAN visibility: public VLANs visible to all, private only to admins
            if !is_admin {
                entries.retain(|e| public_vlans.contains(&e.vlan));
            }
            CommandOutput::MacAddressTable(entries)
        }
        CommandOutput::ArpTable(entries) => CommandOutput::ArpTable(entries),
        CommandOutput::NdTable(entries) => CommandOutput::NdTable(entries),
        CommandOutput::LldpNeighbors(entries) => CommandOutput::LldpNeighbors(entries),
        CommandOutput::BgpSummary(summary) => CommandOutput::BgpSummary(summary),
        CommandOutput::BgpNeighborDetail(detail) => CommandOutput::BgpNeighborDetail(detail),
        CommandOutput::InterfaceDetail(detail) => CommandOutput::InterfaceDetail(detail),
        CommandOutput::VxlanVtep(entries) => CommandOutput::VxlanVtep(entries),
        CommandOutput::Stream(rx) => CommandOutput::Stream(rx),
    }
}

/// Determine if a port is visible to the given identity under the allowlist model.
fn port_visible(
    device: &str,
    interface: &str,
    identity: &Identity,
    pmap: &PortMap,
    is_admin: bool,
) -> bool {
    // Loopback always visible (safety net)
    if interface.starts_with("Loopback") || interface.starts_with("Lo") {
        return true;
    }
    match pmap.classify(device, interface) {
        None => false, // not in map → hidden
        Some(PortClass::Core) => true,
        Some(PortClass::Participant { asn }) => {
            is_admin || identity.asns.contains(asn)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use crate::netbox::NetboxParticipant;
    use crate::structured::{InterfaceStatus, MacEntry};

    use crate::config::DEFAULT_ADMIN_GROUP as ADMIN_GROUP;
    const DEVICE: &str = "switch01.sfo02";
    const PUBLIC_VLANS: &[&str] = &["998", "999"];

    fn public_vlans() -> Vec<String> {
        PUBLIC_VLANS.iter().map(|s| s.to_string()).collect()
    }

    fn anonymous() -> Identity {
        Identity::anonymous()
    }

    fn user_with_asn(asn: u32) -> Identity {
        let mut asns = HashSet::new();
        asns.insert(asn);
        Identity {
            authenticated: true,
            email: Some("user@example.com".to_string()),
            asns,
            groups: HashSet::new(),
        }
    }

    fn admin() -> Identity {
        let mut groups = HashSet::new();
        groups.insert(ADMIN_GROUP.to_string());
        Identity {
            authenticated: true,
            email: Some("admin@example.com".to_string()),
            asns: HashSet::new(),
            groups,
        }
    }

    fn test_pmap() -> PortMap {
        let participants = vec![
            NetboxParticipant {
                asn: 13335,
                name: "Cloudflare".to_string(),
                participant_type: None,
                ports: vec![(DEVICE.to_string(), "Ethernet3/1".to_string())],
            },
            NetboxParticipant {
                asn: 15169,
                name: "Google".to_string(),
                participant_type: None,
                ports: vec![(DEVICE.to_string(), "Ethernet3/2".to_string())],
            },
        ];
        let core_ports = vec![
            (DEVICE.to_string(), "Ethernet49/1".to_string()),
            (DEVICE.to_string(), "Ethernet50/1".to_string()),
        ];
        PortMap::build(&participants, &core_ports)
    }

    fn iface_status(name: &str) -> InterfaceStatus {
        InterfaceStatus {
            name: name.to_string(),
            description: String::new(),
            link_status: "up".to_string(),
            protocol_status: "up".to_string(),
            speed: "10G".to_string(),
            interface_type: "EthernetCsmacd".to_string(),
            vlan: String::new(),
            auto_negotiate: false,
            member_interfaces: vec![],
            port_channel: None,
        }
    }

    #[test]
    fn loopback_always_visible() {
        let pmap = test_pmap();
        let entries = vec![iface_status("Loopback0")];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &anonymous(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => assert_eq!(e.len(), 1),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unclassified_port_hidden() {
        let pmap = test_pmap();
        // Ethernet99 is not in pmap → hidden from everyone
        let entries = vec![iface_status("Ethernet99")];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &anonymous(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => assert_eq!(e.len(), 0),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn unclassified_port_hidden_from_admin() {
        let pmap = test_pmap();
        let entries = vec![iface_status("Ethernet99")];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &admin(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => assert_eq!(e.len(), 0),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn core_port_visible_to_all() {
        let pmap = test_pmap();
        let entries = vec![iface_status("Ethernet49/1")];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &anonymous(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => assert_eq!(e.len(), 1),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn participant_port_hidden_from_anon() {
        let pmap = test_pmap();
        let entries = vec![iface_status("Ethernet3/1"), iface_status("Ethernet49/1")];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &anonymous(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                assert_eq!(e.len(), 1);
                assert_eq!(e[0].name, "Ethernet49/1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn participant_port_visible_to_owner() {
        let pmap = test_pmap();
        let id = user_with_asn(13335);
        let entries = vec![iface_status("Ethernet3/1"), iface_status("Ethernet3/2")];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &id, &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                assert_eq!(e.len(), 1);
                assert_eq!(e[0].name, "Ethernet3/1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn admin_sees_classified_ports_only() {
        let pmap = test_pmap();
        let id = admin();
        // Ethernet3/1 (participant), Ethernet49/1 (core), Ethernet99 (unclassified)
        let entries = vec![
            iface_status("Ethernet3/1"),
            iface_status("Ethernet49/1"),
            iface_status("Ethernet99"),
        ];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &id, &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                assert_eq!(e.len(), 2);
                let names: Vec<_> = e.iter().map(|i| i.name.as_str()).collect();
                assert!(names.contains(&"Ethernet3/1"));
                assert!(names.contains(&"Ethernet49/1"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn port_channel_members_included_when_pc_visible() {
        // Port-Channel1 is a core port → visible to everyone.
        // Its members (Ethernet3/1, Ethernet3/2) are NOT in the PortMap
        // but should be included because their parent PC is visible.
        let participants = vec![];
        let core_ports = vec![
            (DEVICE.to_string(), "Port-Channel1".to_string()),
            (DEVICE.to_string(), "Ethernet49/1".to_string()),
        ];
        let pmap = PortMap::build(&participants, &core_ports);

        let mut eth1 = iface_status("Ethernet3/1");
        eth1.port_channel = Some("Port-Channel1".to_string());
        let mut eth2 = iface_status("Ethernet3/2");
        eth2.port_channel = Some("Port-Channel1".to_string());
        let pc1 = InterfaceStatus {
            name: "Port-Channel1".to_string(),
            member_interfaces: vec!["Ethernet3/1".to_string(), "Ethernet3/2".to_string()],
            ..iface_status("Port-Channel1")
        };
        let unrelated = iface_status("Ethernet99"); // not in map, no PC

        let entries = vec![eth1, eth2, pc1, unrelated];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &anonymous(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                let names: Vec<_> = e.iter().map(|i| i.name.as_str()).collect();
                assert!(names.contains(&"Port-Channel1"), "PC itself should be visible");
                assert!(names.contains(&"Ethernet3/1"), "member should be visible");
                assert!(names.contains(&"Ethernet3/2"), "member should be visible");
                assert!(!names.contains(&"Ethernet99"), "unrelated should be hidden");
                assert_eq!(e.len(), 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn port_channel_members_hidden_when_pc_not_visible() {
        // Port-Channel1 is a participant port for AS 13335.
        // Anonymous user should not see it or its members.
        let participants = vec![
            NetboxParticipant {
                asn: 13335,
                name: "Cloudflare".to_string(),
                participant_type: None,
                ports: vec![(DEVICE.to_string(), "Port-Channel1".to_string())],
            },
        ];
        let core_ports = vec![];
        let pmap = PortMap::build(&participants, &core_ports);

        let mut eth1 = iface_status("Ethernet3/1");
        eth1.port_channel = Some("Port-Channel1".to_string());
        let pc1 = InterfaceStatus {
            name: "Port-Channel1".to_string(),
            member_interfaces: vec!["Ethernet3/1".to_string()],
            ..iface_status("Port-Channel1")
        };

        let entries = vec![eth1, pc1];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &anonymous(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                assert_eq!(e.len(), 0, "anon should see neither PC nor members");
            }
            _ => panic!("wrong variant"),
        }

        // But the owning ASN should see both
        let mut eth1 = iface_status("Ethernet3/1");
        eth1.port_channel = Some("Port-Channel1".to_string());
        let pc1 = InterfaceStatus {
            name: "Port-Channel1".to_string(),
            member_interfaces: vec!["Ethernet3/1".to_string()],
            ..iface_status("Port-Channel1")
        };
        let entries = vec![eth1, pc1];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &user_with_asn(13335), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                assert_eq!(e.len(), 2, "owner should see PC and member");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn subinterface_port_channel_members_visible() {
        // Port-Channel114.998 is a participant port — member interfaces
        // reference "Port-Channel114" (base name without .VLAN suffix).
        // Members should still be included.
        let participants = vec![
            NetboxParticipant {
                asn: 6140,
                name: "Two P".to_string(),
                participant_type: None,
                ports: vec![(DEVICE.to_string(), "Port-Channel114.998".to_string())],
            },
        ];
        let core_ports = vec![];
        let pmap = PortMap::build(&participants, &core_ports);

        let mut eth7 = iface_status("Ethernet7");
        eth7.port_channel = Some("Port-Channel114".to_string());
        let mut eth8 = iface_status("Ethernet8");
        eth8.port_channel = Some("Port-Channel114".to_string());
        let pc_sub = InterfaceStatus {
            name: "Port-Channel114.998".to_string(),
            member_interfaces: vec![],
            ..iface_status("Port-Channel114.998")
        };
        let unrelated = iface_status("Ethernet99");

        // Admin should see PC subinterface + its members
        let entries = vec![eth7.clone(), eth8.clone(), pc_sub.clone(), unrelated.clone()];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &admin(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                let names: Vec<_> = e.iter().map(|i| i.name.as_str()).collect();
                assert!(names.contains(&"Port-Channel114.998"), "subinterface PC should be visible");
                assert!(names.contains(&"Ethernet7"), "member should be visible via base PC name");
                assert!(names.contains(&"Ethernet8"), "member should be visible via base PC name");
                assert!(!names.contains(&"Ethernet99"), "unrelated should be hidden");
                assert_eq!(e.len(), 3);
            }
            _ => panic!("wrong variant"),
        }

        // Owner should also see them
        let entries = vec![eth7, eth8, pc_sub, unrelated];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &user_with_asn(6140), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                assert_eq!(e.len(), 3, "owner should see PC subinterface and both members");
            }
            _ => panic!("wrong variant"),
        }

        // Anonymous should see neither
        let mut eth7 = iface_status("Ethernet7");
        eth7.port_channel = Some("Port-Channel114".to_string());
        let pc_sub = InterfaceStatus {
            name: "Port-Channel114.998".to_string(),
            ..iface_status("Port-Channel114.998")
        };
        let entries = vec![eth7, pc_sub];
        let out = filter_output_with_lookup(
            CommandOutput::InterfacesStatus(entries), DEVICE, &anonymous(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::InterfacesStatus(e) => {
                assert_eq!(e.len(), 0, "anon should see nothing");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn mac_table_filtered_to_peering_vlans() {
        let pmap = test_pmap();
        let entries = vec![
            MacEntry { vlan: "998".to_string(), mac_address: "aa:bb:cc:dd:ee:01".to_string(), entry_type: "dynamic".to_string(), interface: "Ethernet3/1".to_string() },
            MacEntry { vlan: "999".to_string(), mac_address: "aa:bb:cc:dd:ee:02".to_string(), entry_type: "dynamic".to_string(), interface: "Ethernet3/2".to_string() },
            MacEntry { vlan: "100".to_string(), mac_address: "aa:bb:cc:dd:ee:03".to_string(), entry_type: "dynamic".to_string(), interface: "Ethernet1".to_string() },
            MacEntry { vlan: "998".to_string(), mac_address: "aa:bb:cc:dd:ee:04".to_string(), entry_type: "dynamic".to_string(), interface: "Vxlan1".to_string() },
        ];
        let out = filter_output_with_lookup(
            CommandOutput::MacAddressTable(entries), DEVICE, &anonymous(), &pmap, ADMIN_GROUP, &public_vlans(),
        );
        match out {
            CommandOutput::MacAddressTable(e) => {
                assert_eq!(e.len(), 2);
                assert!(e.iter().all(|m| m.vlan == "998" || m.vlan == "999"));
                assert!(e.iter().all(|m| m.interface != "Vxlan1"));
            }
            _ => panic!("wrong variant"),
        }
    }
}
