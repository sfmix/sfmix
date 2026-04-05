use anyhow::{Context, Result};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::collections::HashMap;
use tracing::info;

/// A participant entry fetched from NetBox, ready for `ParticipantMap::build_from_netbox()`.
#[derive(Debug, Clone)]
pub struct NetboxParticipant {
    pub asn: u32,
    pub name: String,
    pub participant_type: Option<String>,
    pub ports: Vec<(String, String)>, // (device_name, interface_name)
}

/// Result of a NetBox fetch: participants + core port list.
pub struct NetboxFetchResult {
    pub participants: Vec<NetboxParticipant>,
    /// Core/infrastructure ports visible to everyone: (device_fqdn, interface_name)
    pub core_ports: Vec<(String, String)>,
}

/// Fetch participant→port mapping and core port list from NetBox in a single GraphQL query.
///
/// Queries `tenant_list` (participants), `peering_ports` (peering_port tag),
/// and `core_ports` (core_port tag).
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
            name
            device { name }
            custom_fields
        }
        core_ports: interface_list(filters: { tags: { slug: { exact: "core_port" } } }) {
            name
            device { name }
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

    // Group peering interfaces by tenant_id → ports
    let mut ports_by_asn: HashMap<u32, Vec<(String, String)>> = HashMap::new();
    for iface in &data.peering_ports {
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

    // Assemble participants
    let mut participants: Vec<NetboxParticipant> = Vec::new();
    for (_tid, (asn, name, ptype)) in &tenants_by_id {
        participants.push(NetboxParticipant {
            asn: *asn,
            name: name.clone(),
            participant_type: ptype.clone(),
            ports: ports_by_asn.remove(asn).unwrap_or_default(),
        });
    }

    // Collect core ports
    let core_ports: Vec<(String, String)> = data
        .core_ports
        .iter()
        .map(|e| (normalize_device_name(&e.device.name, domain_suffix), e.name.clone()))
        .collect();

    info!(
        "NetBox: {} participants ({} peering ports), {} core ports",
        participants.len(),
        participants.iter().map(|p| p.ports.len()).sum::<usize>(),
        core_ports.len(),
    );
    Ok(NetboxFetchResult { participants, core_ports })
}

/// Normalize a NetBox device name to FQDN.
///
/// NetBox stores short names like `switch01.fmt01`. If a `domain_suffix` is
/// provided and the name has fewer than 3 dot-separated components, append
/// the suffix. Otherwise the name passes through unchanged.
fn normalize_device_name(name: &str, domain_suffix: Option<&str>) -> String {
    if let Some(suffix) = domain_suffix {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 3 {
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
}

#[derive(Deserialize)]
struct CorePortEntry {
    name: String,
    device: InterfaceDevice,
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
    name: String,
    device: InterfaceDevice,
    custom_fields: InterfaceCustomFields,
}

#[derive(Deserialize)]
struct InterfaceDevice {
    name: String,
}

#[derive(Deserialize)]
struct InterfaceCustomFields {
    /// Tenant ID of the participant that owns this port (plain integer or null).
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    participant: Option<u64>,
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
        _ => Err(de::Error::custom("expected number or null for participant")),
    }
}
