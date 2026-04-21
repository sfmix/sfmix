//! RPC-based command dispatch for the CLI frontends.
//!
//! This replaces `looking_glass::frontend::common::dispatch_command` with a
//! version that routes commands through the lg-server RPC endpoint instead of
//! calling `LookingGlass::execute()` directly.

use anyhow::Result;

use lg_client::client::{ExecuteEvent, RpcClient};
use lg_types::rpc::ServiceInfo;
use looking_glass::command::{ParseError, Resource};
use looking_glass::format::ColorMode;
use looking_glass::frontend::common::{CommandAction, SessionWriter, HELP_TEXT, is_quit};
use looking_glass::grammar::parse_command;
use looking_glass::identity::Identity;
use looking_glass::structured::CommandOutput;

/// Cached service metadata fetched from lg-server at startup.
pub struct ServiceContext {
    pub info: ServiceInfo,
    pub rpc: RpcClient,
}

impl ServiceContext {
    pub async fn connect(rpc_url: &str, rpc_secret: &str) -> Result<Self> {
        let rpc = RpcClient::new(rpc_url, rpc_secret);
        let info = rpc.service_info().await?;
        Ok(Self { info, rpc })
    }
}

/// RPC-based command dispatch.
///
/// Same interface as `looking_glass::frontend::common::dispatch_command` but
/// sends commands to lg-server via RPC instead of calling execute() in-process.
pub async fn dispatch_command<W: SessionWriter>(
    line: &str,
    ctx: &ServiceContext,
    identity: &Identity,
    rate_key: &str,
    color: ColorMode,
    writer: &mut W,
) -> Result<CommandAction> {
    let line = line.trim();

    if line.is_empty() {
        return Ok(CommandAction::Continue);
    }

    if is_quit(line) {
        writer.write_bytes(b"Goodbye.\n").await?;
        return Ok(CommandAction::Quit);
    }

    let command = match parse_command(line) {
        Ok(cmd) => cmd,
        Err(ParseError::Empty) => {
            return Ok(CommandAction::Continue);
        }
        Err(e) => {
            let msg = format!("{e}\n");
            writer.write_bytes(msg.as_bytes()).await?;
            return Ok(CommandAction::Continue);
        }
    };

    // Login — delegate to frontend
    if command.resource == Resource::Login {
        return Ok(CommandAction::Login);
    }

    // Logout — delegate to frontend
    if command.resource == Resource::Logout {
        return Ok(CommandAction::Logout);
    }

    // Whoami — show current identity (local, no RPC needed)
    if command.resource == Resource::Whoami {
        if identity.authenticated {
            let banner = looking_glass::format::format_auth_banner(
                identity,
                None,
                &ctx.info.admin_group,
            );
            writer.write_bytes(banner.as_bytes()).await?;
        } else {
            writer
                .write_bytes(b"Not authenticated. Use 'login' to authenticate.\n")
                .await?;
        }
        return Ok(CommandAction::Continue);
    }

    // Help
    if command.resource == Resource::Help {
        writer.write_bytes(HELP_TEXT.as_bytes()).await?;
        return Ok(CommandAction::Continue);
    }

    // Everything else goes through RPC
    let multi_device = command.device.is_none() && ctx.info.device_count > 1;
    let has_filter = command.filter_asn.is_some() || command.filter_vlan.is_some();

    let mut rx = ctx
        .rpc
        .execute(command, identity.clone(), rate_key.to_string())
        .await?;

    // Track which device is currently streaming (for headers)
    let mut current_stream_device: Option<String> = None;

    while let Some(event) = rx.recv().await {
        match event {
            ExecuteEvent::Result(r) => {
                let output = CommandOutput::from_rpc(r.output);
                if has_filter && output.is_empty() {
                    continue;
                }
                if multi_device {
                    let header =
                        looking_glass::format::format_device_header(&r.device, color);
                    writer.write_bytes(header.as_bytes()).await?;
                }
                let text = looking_glass::format::render(&output, color);
                if text.is_empty() || text.trim().is_empty() {
                    writer.write_bytes(b"  [No data]\n").await?;
                } else {
                    writer.write_bytes(text.as_bytes()).await?;
                    if !text.ends_with('\n') {
                        writer.write_bytes(b"\n").await?;
                    }
                }
            }
            ExecuteEvent::StreamLine(sl) => {
                // Print device header on first stream line for this device
                if multi_device
                    && current_stream_device.as_deref() != Some(&sl.device)
                {
                    let header =
                        looking_glass::format::format_device_header(&sl.device, color);
                    writer.write_bytes(header.as_bytes()).await?;
                    current_stream_device = Some(sl.device.clone());
                }
                writer.write_bytes(sl.line.as_bytes()).await?;
                writer.write_bytes(b"\n").await?;
            }
            ExecuteEvent::StreamEnd(_) => {
                current_stream_device = None;
            }
            ExecuteEvent::Error(e) => {
                let msg = match e.code.as_str() {
                    "policy_denied" => format!("Denied: {}\n", e.message),
                    "rate_limited" => format!("Rate limited: {}\n", e.message),
                    _ => format!("Error: {}\n", e.message),
                };
                writer.write_bytes(msg.as_bytes()).await?;
            }
        }
    }

    Ok(CommandAction::Continue)
}
