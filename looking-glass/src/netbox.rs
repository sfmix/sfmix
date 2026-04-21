use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde::de::{self, Deserializer};
use std::collections::HashMap;
use std::time::Instant;
use tracing::info;

/// Tracks the status of the NetBox cache for diagnostic display.
#[derive(Debug, Clone, Serialize)]
pub struct NetboxStatus {
    /// Whether NetBox is configured as the participant source.
    pub configured: bool,
    /// Number of participants in the current cache.
    pub participant_count: usize,
    /// Number of peering ports in the current cache.
    pub peering_port_count: usize,
    /// Number of core ports in the current cache.
    pub core_port_count: usize,
    /// Total classified ports in the PortMap.
    pub port_map_size: usize,
    /// Seconds since the last successful fetch, or None if never fetched.
    #[serde(skip)]
    pub last_success: Option<Instant>,
    /// Error message from the last failed fetch, if any.
    pub last_error: Option<String>,
    /// Configured refresh interval in seconds (0 = disabled).
    pub refresh_interval_secs: u64,
    /// NetBox URL (for diagnostics).
    pub url: Option<String>,
}

impl NetboxStatus {
    pub fn unconfigured() -> Self {
        Self {
            configured: false,
            participant_count: 0,
            peering_port_count: 0,
            core_port_count: 0,
            port_map_size: 0,
            last_success: None,
            last_error: None,
            refresh_interval_secs: 0,
            url: None,
        }
    }

    /// Seconds since the last successful fetch.
    pub fn age_secs(&self) -> Option<u64> {
        self.last_success.map(|t| t.elapsed().as_secs())
    }
}

/// A participant entry fetched from NetBox, ready for `ParticipantMap::build_from_netbox()`.
#[derive(Debug, Clone, Serialize)]
pub struct NetboxParticipant {
    pub asn: u32,
    pub name: String,
    pub participant_type: Option<String>,
    /// (device_name, interface_name) pairs — used by PortMap/ParticipantMap.
    #[serde(skip)]
    pub ports: Vec<(String, String)>,
    /// Enriched port details for REST API / IX-F export.
    pub enriched_ports: Vec<EnrichedPort>,
    /// IP addresses assigned to this participant.
    pub ip_addresses: Vec<ParticipantIp>,
}

/// Enriched peering port with speed and device info.
#[derive(Debug, Clone, Serialize)]
pub struct EnrichedPort {
    pub device: String,
    pub interface: String,
    /// NetBox device ID (used for IX-F switch_id).
    pub device_id: u64,
    /// Interface ID in NetBox (used to match IP addresses via participant_lag).
    #[serde(skip)]
    pub interface_id: u64,
    /// Speed in Mbps (converted from NetBox kbps), e.g. 10000 = 10G.
    pub speed: Option<u64>,
    /// Rate limit in bps from custom field, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_bps: Option<u64>,
    pub enabled: bool,
}

/// A participant's IP address from NetBox.
#[derive(Debug, Clone, Serialize)]
pub struct ParticipantIp {
    /// IP address without prefix length (e.g. "206.197.187.62").
    pub address: String,
    /// "IPv4" or "IPv6".
    pub family: String,
    /// MAC address from custom field, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    pub status: String,
    /// The peering port interface ID this IP is linked to (via participant_lag).
    #[serde(skip)]
    pub participant_lag_id: Option<u64>,
}

/// A peering switch for IX-F export.
#[derive(Debug, Clone, Serialize)]
pub struct IxpSwitch {
    pub id: u64,
    pub name: String,
    pub colo: String,
    pub pdb_facility_id: Option<u64>,
    pub city: String,
    pub country: String,
    pub manufacturer: String,
    pub model: String,
}

/// A peering VLAN for IX-F export.
#[derive(Debug, Clone, Serialize)]
pub struct IxpVlan {
    pub id: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_mask_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_mask_length: Option<u32>,
}

/// IXP infrastructure data needed for IX-F Member Export.
#[derive(Debug, Clone, Serialize)]
pub struct NetboxIxpData {
    pub switches: Vec<IxpSwitch>,
    pub vlans: Vec<IxpVlan>,
}

/// Result of a NetBox fetch: participants + core port list + IXP data.
pub struct NetboxFetchResult {
    pub participants: Vec<NetboxParticipant>,
    /// Core/infrastructure ports visible to everyone: (device_fqdn, interface_name)
    pub core_ports: Vec<(String, String)>,
    /// Admin-only ports visible only to IX Administrators: (device_fqdn, interface_name)
    pub admin_ports: Vec<(String, String)>,
    /// IXP infrastructure data for IX-F export.
    pub ixp_data: NetboxIxpData,
}

/// Fetch participant→port mapping, core port list, and IXP infrastructure data
/// from NetBox in a single GraphQL query.
pub async fn fetch_port_map(
    url: &str,
    token: &str,
    domain_suffix: Option<&str>,
) -> Result<NetboxFetchResult> {
    let graphql_url = format!("{}/graphql/", url.trim_end_matches('/'));

    let query = r#"{
        tenant_list {
            id
            name
            description
            custom_fields
        }
        peering_ports: interface_list(filters: { tags: { slug: { exact: "peering_port" } } }) {
            id
            name
            speed
            enabled
            device { id name }
            custom_fields
        }
        core_ports: interface_list(filters: { tags: { slug: { exact: "core_port" } } }) {
            name
            device { name }
        }
        admin_ports: interface_list(filters: { tags: { slug: { exact: "admin_port" } } }) {
            name
            device { name }
        }
        transit_peers: interface_list(filters: { tags: { slug: { exact: "transit_peer" } } }) {
            id
            name
            speed
            enabled
            device { id name }
            custom_fields
        }
        ip_addresses: ip_address_list(filters: { tags: { slug: { exact: "ixp_participant" } } }) {
            address
            family { value label }
            status
            tenant { id }
            custom_fields
        }
        peering_switches: device_list(filters: { role: { slug: { exact: "peering_switch" } }, status: STATUS_ACTIVE }) {
            id
            name
            site { id name facility custom_fields region { name } }
            device_type { manufacturer { name } model }
        }
        peering_vlans: vlan_list(filters: { group: { slug: { exact: "exchange_fabric_vlans" } } }) {
            id
            name
            tags { slug }
        }
        prefix_list {
            prefix
            family { value }
            vlan { id }
        }
    }"#;

    let client = reqwest::Client::new();
    let resp = client
        .post(&graphql_url)
        .header("Authorization", format!("Token {}", token))
        .json(&serde_json::json!({ "query": query }))
        .send()
        .await
        .context("NetBox GraphQL request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("NetBox GraphQL returned {status}: {body}");
    }

    let body: GraphQlResponse = resp
        .json()
        .await
        .context("failed to parse NetBox GraphQL response")?;

    if let Some(errors) = body.errors {
        if !errors.is_empty() {
            let msgs: Vec<_> = errors.iter().map(|e| e.message.as_str()).collect();
            anyhow::bail!("NetBox GraphQL errors: {}", msgs.join("; "));
        }
    }

    let data = body.data.context("NetBox GraphQL response has no data")?;

    // Build tenant_id → (asn, name, participant_type) lookup
    let mut tenants_by_id: HashMap<String, (u32, String, Option<String>)> = HashMap::new();
    for tenant in &data.tenant_list {
        if let Some(asn) = tenant.custom_fields.as_number {
            if asn > 0 {
                // Prefer description (e.g. "Cloudflare") over name (e.g. "AS13335")
                let label = if tenant.description.is_empty() {
                    tenant.name.clone()
                } else {
                    tenant.description.clone()
                };
                tenants_by_id.insert(
                    tenant.id.clone(),
                    (asn, label, tenant.custom_fields.participant_type.clone()),
                );
            }
        }
    }

    // Group peering interfaces by ASN → (simple ports + enriched ports)
    let mut ports_by_asn: HashMap<u32, Vec<(String, String)>> = HashMap::new();
    let mut enriched_by_asn: HashMap<u32, Vec<EnrichedPort>> = HashMap::new();

    // Process transit peer SAPs (participant custom field, no peering_port tag).
    // These go into ports_by_asn for PortMap classification but NOT enriched ports.
    for iface in &data.transit_peers {
        if let Some(tenant_id) = iface.custom_fields.participant {
            let tid = tenant_id.to_string();
            if let Some((asn, _, _)) = tenants_by_id.get(&tid) {
                let device_name = normalize_device_name(&iface.device.name, domain_suffix);
                ports_by_asn
                    .entry(*asn)
                    .or_default()
                    .push((device_name, iface.name.clone()));
            }
        }
    }

    for iface in &data.peering_ports {
        if let Some(tenant_id) = iface.custom_fields.participant {
            let tid = tenant_id.to_string();
            if let Some((asn, _, _)) = tenants_by_id.get(&tid) {
                let device_name = normalize_device_name(&iface.device.name, domain_suffix);
                ports_by_asn
                    .entry(*asn)
                    .or_default()
                    .push((device_name.clone(), iface.name.clone()));
                enriched_by_asn
                    .entry(*asn)
                    .or_default()
                    .push(EnrichedPort {
                        device: device_name,
                        interface: iface.name.clone(),
                        device_id: iface.device.id,
                        interface_id: iface.id,
                        speed: iface.speed.map(|s| s / 1000),
                        rate_limit_bps: iface.custom_fields.rate_limit_bps,
                        enabled: iface.enabled,
                    });
            }
        }
    }

    // Group IP addresses by tenant → ASN
    let mut ips_by_asn: HashMap<u32, Vec<ParticipantIp>> = HashMap::new();
    for ip in &data.ip_addresses {
        if let Some(ref tenant) = ip.tenant {
            if let Some((asn, _, _)) = tenants_by_id.get(&tenant.id) {
                // Strip prefix length from address (e.g. "206.197.187.62/32" → "206.197.187.62")
                let addr = ip.address.split('/').next().unwrap_or(&ip.address).to_string();
                let family = match ip.family.value {
                    4 => "IPv4".to_string(),
                    6 => "IPv6".to_string(),
                    v => format!("AF{v}"),
                };
                ips_by_asn.entry(*asn).or_default().push(ParticipantIp {
                    address: addr,
                    family,
                    mac_address: ip.custom_fields.participant_mac_address.clone(),
                    status: ip.status.clone(),
                    participant_lag_id: ip.custom_fields.participant_lag_id,
                });
            }
        }
    }

    // Assemble participants
    let mut participants: Vec<NetboxParticipant> = Vec::new();
    for (_tid, (asn, name, ptype)) in &tenants_by_id {
        participants.push(NetboxParticipant {
            asn: *asn,
            name: name.clone(),
            participant_type: ptype.clone(),
            ports: ports_by_asn.remove(asn).unwrap_or_default(),
            enriched_ports: enriched_by_asn.remove(asn).unwrap_or_default(),
            ip_addresses: ips_by_asn.remove(asn).unwrap_or_default(),
        });
    }

    // Collect core ports
    let core_ports: Vec<(String, String)> = data
        .core_ports
        .iter()
        .map(|e| (normalize_device_name(&e.device.name, domain_suffix), e.name.clone()))
        .collect();

    // Collect admin-only ports
    let admin_ports: Vec<(String, String)> = data
        .admin_ports
        .iter()
        .map(|e| (normalize_device_name(&e.device.name, domain_suffix), e.name.clone()))
        .collect();

    // Build IXP switch list
    let switches: Vec<IxpSwitch> = data.peering_switches.iter().map(|d| {
        let site = &d.site;
        IxpSwitch {
            id: d.id,
            name: d.name.clone(),
            colo: site.facility.clone().unwrap_or_default(),
            pdb_facility_id: site.custom_fields.peeringdb_facility,
            city: site.region.as_ref().map(|r| r.name.clone()).unwrap_or_default(),
            country: "US".to_string(),
            manufacturer: d.device_type.manufacturer.name.clone(),
            model: d.device_type.model.clone(),
        }
    }).collect();

    // Build IXP VLAN list (only peering_lan tagged VLANs)
    let peering_vlan_ids: Vec<u64> = data.peering_vlans.iter()
        .filter(|v| v.tags.iter().any(|t| t.slug == "peering_lan"))
        .map(|v| v.id)
        .collect();

    let vlans: Vec<IxpVlan> = data.peering_vlans.iter()
        .filter(|v| peering_vlan_ids.contains(&v.id))
        .map(|v| {
            // Find prefixes for this VLAN
            let mut ipv4_prefix = None;
            let mut ipv4_mask = None;
            let mut ipv6_prefix = None;
            let mut ipv6_mask = None;
            for pfx in &data.prefix_list {
                if pfx.vlan.as_ref().map(|pv| pv.id) == Some(v.id) {
                    if let Some((network, mask_len)) = parse_prefix(&pfx.prefix) {
                        match pfx.family.value {
                            4 => { ipv4_prefix = Some(network); ipv4_mask = Some(mask_len); }
                            6 => { ipv6_prefix = Some(network); ipv6_mask = Some(mask_len); }
                            _ => {}
                        }
                    }
                }
            }
            IxpVlan {
                id: v.id,
                name: v.name.clone(),
                ipv4_prefix,
                ipv4_mask_length: ipv4_mask,
                ipv6_prefix,
                ipv6_mask_length: ipv6_mask,
            }
        })
        .collect();

    let ixp_data = NetboxIxpData { switches, vlans };

    info!(
        "NetBox: {} participants ({} peering ports), {} core ports, {} admin ports, {} switches, {} vlans, {} IPs",
        participants.len(),
        participants.iter().map(|p| p.ports.len()).sum::<usize>(),
        core_ports.len(),
        admin_ports.len(),
        ixp_data.switches.len(),
        ixp_data.vlans.len(),
        participants.iter().map(|p| p.ip_addresses.len()).sum::<usize>(),
    );
    Ok(NetboxFetchResult { participants, core_ports, admin_ports, ixp_data })
}

/// Parse a CIDR prefix string into (network_address, mask_length).
fn parse_prefix(prefix: &str) -> Option<(String, u32)> {
    let mut parts = prefix.splitn(2, '/');
    let network = parts.next()?;
    let mask: u32 = parts.next()?.parse().ok()?;
    Some((network.to_string(), mask))
}

/// Normalize a NetBox device name to FQDN.
///
/// NetBox stores short names like `switch01.fmt01` or `cr1.sjc01.transit`.
/// If a `domain_suffix` is provided and the name doesn't already end with it,
/// append the suffix. Otherwise the name passes through unchanged.
fn normalize_device_name(name: &str, domain_suffix: Option<&str>) -> String {
    if let Some(suffix) = domain_suffix {
        if !name.ends_with(suffix) {
            return format!("{name}.{suffix}");
        }
    }
    name.to_string()
}

// ── GraphQL response types ──────────────────────────────────────────

#[derive(Deserialize)]
struct GraphQlResponse {
    data: Option<GraphQlData>,
    errors: Option<Vec<GraphQlError>>,
}

#[derive(Deserialize)]
struct GraphQlError {
    message: String,
}

#[derive(Deserialize)]
struct GraphQlData {
    tenant_list: Vec<TenantEntry>,
    peering_ports: Vec<InterfaceEntry>,
    core_ports: Vec<CorePortEntry>,
    admin_ports: Vec<CorePortEntry>,
    transit_peers: Vec<InterfaceEntry>,
    ip_addresses: Vec<IpAddressEntry>,
    peering_switches: Vec<DeviceEntry>,
    peering_vlans: Vec<VlanEntry>,
    prefix_list: Vec<PrefixEntry>,
}

#[derive(Deserialize)]
struct CorePortEntry {
    name: String,
    device: CorePortDevice,
}

#[derive(Deserialize)]
struct CorePortDevice {
    name: String,
}

#[derive(Deserialize)]
struct TenantEntry {
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    custom_fields: TenantCustomFields,
}

#[derive(Deserialize)]
struct TenantCustomFields {
    as_number: Option<u32>,
    participant_type: Option<String>,
}

#[derive(Deserialize)]
struct InterfaceEntry {
    #[serde(deserialize_with = "deserialize_string_id")]
    id: u64,
    name: String,
    speed: Option<u64>,
    enabled: bool,
    device: InterfaceDevice,
    custom_fields: InterfaceCustomFields,
}

#[derive(Deserialize)]
struct InterfaceDevice {
    #[serde(deserialize_with = "deserialize_string_id")]
    id: u64,
    name: String,
}

#[derive(Deserialize)]
struct InterfaceCustomFields {
    /// Tenant ID of the participant that owns this port (plain integer or null).
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    participant: Option<u64>,
    /// Rate limit in bps, if configured.
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    rate_limit_bps: Option<u64>,
}

// ── IP address types ────────────────────────────────────────────────

#[derive(Deserialize)]
struct FamilyType {
    value: u8,
    #[allow(dead_code)]
    label: Option<String>,
}

#[derive(Deserialize)]
struct IpAddressEntry {
    address: String,
    family: FamilyType,
    status: String,
    tenant: Option<IpTenantRef>,
    custom_fields: IpCustomFields,
}

#[derive(Deserialize)]
struct IpTenantRef {
    id: String,
}

#[derive(Deserialize)]
struct IpCustomFields {
    participant_mac_address: Option<String>,
    /// The interface ID this IP is linked to (via participant_lag custom field).
    /// May be a nested object with an "id" field, or a plain integer, or null.
    #[serde(default, deserialize_with = "deserialize_nested_id", alias = "participant_lag")]
    participant_lag_id: Option<u64>,
}

// ── Device / site / VLAN / prefix types ─────────────────────────────

#[derive(Deserialize)]
struct DeviceEntry {
    #[serde(deserialize_with = "deserialize_string_id")]
    id: u64,
    name: String,
    site: SiteEntry,
    device_type: DeviceTypeEntry,
}

#[derive(Deserialize)]
struct SiteEntry {
    #[allow(dead_code)]
    #[serde(deserialize_with = "deserialize_string_id")]
    id: u64,
    #[allow(dead_code)]
    name: String,
    facility: Option<String>,
    custom_fields: SiteCustomFields,
    region: Option<RegionEntry>,
}

#[derive(Deserialize)]
struct SiteCustomFields {
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    peeringdb_facility: Option<u64>,
}

#[derive(Deserialize)]
struct RegionEntry {
    name: String,
}

#[derive(Deserialize)]
struct DeviceTypeEntry {
    manufacturer: ManufacturerEntry,
    model: String,
}

#[derive(Deserialize)]
struct ManufacturerEntry {
    name: String,
}

#[derive(Deserialize)]
struct VlanEntry {
    #[serde(deserialize_with = "deserialize_string_id")]
    id: u64,
    name: String,
    tags: Vec<TagEntry>,
}

#[derive(Deserialize)]
struct TagEntry {
    slug: String,
}

#[derive(Deserialize)]
struct PrefixEntry {
    prefix: String,
    family: FamilyType,
    vlan: Option<PrefixVlanRef>,
}

#[derive(Deserialize)]
struct PrefixVlanRef {
    #[serde(deserialize_with = "deserialize_string_id")]
    id: u64,
}

// ── Custom deserializers ────────────────────────────────────────────

/// Deserialize a NetBox GraphQL ID field (always a string like "123") into u64.
fn deserialize_string_id<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde_json::Value;
    let v = Value::deserialize(deserializer)?;
    match v {
        Value::String(s) => s.parse::<u64>().map_err(de::Error::custom),
        Value::Number(n) => n.as_u64().ok_or_else(|| de::Error::custom("invalid number")),
        _ => Err(de::Error::custom("expected string or number for ID")),
    }
}

/// Deserialize a JSON value that may be a number, string-encoded number, or null.
fn deserialize_optional_u64<'de, D>(deserializer: D) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde_json::Value;
    let v = Option::<Value>::deserialize(deserializer)?;
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| de::Error::custom("invalid number")),
        Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(de::Error::custom),
        _ => Err(de::Error::custom("expected number or null")),
    }
}

/// Deserialize a NetBox custom field that may be a nested object `{"id": 123}`,
/// a plain integer, or null.
fn deserialize_nested_id<'de, D>(deserializer: D) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde_json::Value;
    let v = Option::<Value>::deserialize(deserializer)?;
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| de::Error::custom("invalid number")),
        Some(Value::Object(map)) => {
            if let Some(Value::Number(n)) = map.get("id") {
                n.as_u64().map(Some).ok_or_else(|| de::Error::custom("invalid nested id"))
            } else {
                Ok(None)
            }
        }
        Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(de::Error::custom),
        _ => Err(de::Error::custom("expected object with id, number, or null")),
    }
}
