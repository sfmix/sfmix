//! Render the public NetBox-derived exports offline, exactly as lg-server
//! serves them: IX-F (`participants.json`), the participants table and sites.
//!
//!   NETBOX_URL=https://netbox.sfmix.org NETBOX_TOKEN=... \
//!     cargo run --example netbox_exports -- <out-dir>
//!
//! Handy for diffing a change against the live endpoints before deploying.

use std::path::PathBuf;

use looking_glass::{ixf, netbox, participants_table};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("NETBOX_URL")?;
    let token = std::env::var("NETBOX_TOKEN")?;
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| ".".into()));
    std::fs::create_dir_all(&out)?;

    let result = netbox::fetch_port_map(&url, &token, None).await?;
    let ixp = &result.ixp_data;
    let write = |name: &str, v: serde_json::Value| -> anyhow::Result<()> {
        std::fs::write(out.join(name), serde_json::to_string_pretty(&v)?)?;
        Ok(())
    };
    write("participants.json", ixf::build_ixf_export(ixp, &result.participants))?;
    write(
        "participants_table.json",
        serde_json::to_value(participants_table::build_participants_table(ixp, &result.participants))?,
    )?;
    write("sites.json", serde_json::json!({ "sites": ixp.sites }))?;
    eprintln!("wrote {}", out.display());
    Ok(())
}
