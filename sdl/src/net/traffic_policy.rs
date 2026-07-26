//! Linux host-side steering for private traffic policies.
//!
//! The private plugin decides which SDL exit node receives packets after they
//! enter the TUN. This module only decides whether a locally-originated IPv4
//! packet must bypass the TUN. It owns one nftables table and one policy route
//! table, making cleanup deterministic and avoiding a route per GeoIP CIDR.
//!
//! The private table contains only `default dev sdl-tun`. Marked bypass
//! traffic looks up the kernel-managed main table before that rule, so DHCP
//! and NetworkManager can replace the physical default gateway without SDL
//! having to mirror or watch it.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

const NFT_TABLE: &str = "sdl_traffic_policy";
const ROUTE_TABLE: &str = "51801";
const BYPASS_RULE_PRIORITY: &str = "11000";
const TUN_RULE_PRIORITY: &str = "11001";
// Reserve the low 24 bits for SDL and preserve the high byte. Other policy
// routing users can retain their own high-byte mark while SDL is enabled.
const LOCAL_MARK: &str = "0x0053444c";
const LOCAL_MARK_RULE: &str = "0x0053444c/0x00ffffff";

#[derive(Debug, Clone)]
pub struct LocalEgressPlan {
    pub tun_name: String,
    pub local_ipv4_cidrs: Vec<String>,
    pub route_excludes: Vec<String>,
}

pub fn enable_local_egress(plan: &LocalEgressPlan) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = plan;
        bail!("traffic policy routing is currently supported only on Linux");
    }
    #[cfg(target_os = "linux")]
    {
        validate_plan(plan)?;
        ensure_command("ip")?;
        ensure_nft_usable()?;
        reject_existing_full_tunnel(&plan.tun_name)?;
        reject_mark_conflict()?;
        reject_route_table_conflict()?;
        install_nft_set(&plan.local_ipv4_cidrs, &plan.route_excludes)?;
        let apply_result = apply_routes(plan);
        if let Err(error) = apply_result {
            let _ = disable_local_egress(plan);
            return Err(error);
        }
        Ok(())
    }
}

pub fn disable_local_egress(_plan: &LocalEgressPlan) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = _plan;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let _ = run(
            "ip",
            &[
                "rule",
                "del",
                "priority",
                BYPASS_RULE_PRIORITY,
                "fwmark",
                LOCAL_MARK_RULE,
                "lookup",
                "main",
            ],
        );
        let _ = run(
            "ip",
            &[
                "rule",
                "del",
                "priority",
                TUN_RULE_PRIORITY,
                "lookup",
                ROUTE_TABLE,
            ],
        );
        let _ = run("ip", &["route", "flush", "table", ROUTE_TABLE]);
        let _ = run("nft", &["delete", "table", "inet", NFT_TABLE]);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn validate_plan(plan: &LocalEgressPlan) -> Result<()> {
    if plan.tun_name.trim().is_empty() {
        bail!("traffic policy TUN name is empty");
    }
    if plan.local_ipv4_cidrs.is_empty() {
        bail!("traffic policy has no local IPv4 CIDRs; refusing to redirect all traffic");
    }
    for cidr in plan.local_ipv4_cidrs.iter().chain(&plan.route_excludes) {
        let Some((address, prefix)) = cidr.split_once('/') else {
            bail!("invalid local CIDR {cidr}");
        };
        address
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| format!("invalid local CIDR {cidr}"))?;
        prefix
            .parse::<u8>()
            .ok()
            .filter(|prefix| *prefix <= 32)
            .context("invalid local CIDR prefix")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_command(command: &str) -> Result<()> {
    run(command, &["--version"])
        .with_context(|| format!("traffic policy requires `{command}` on PATH"))
}

#[cfg(target_os = "linux")]
fn ensure_nft_usable() -> Result<()> {
    ensure_command("nft")?;
    run("nft", &["list", "tables"]).context(
        "traffic policy requires a usable nf_tables kernel subsystem and permission to manage nftables",
    )
}

#[cfg(target_os = "linux")]
fn reject_existing_full_tunnel(tun_name: &str) -> Result<()> {
    let output = output("ip", &["route", "show", "dev", tun_name])?;
    if output.lines().any(|line| {
        line.starts_with("default ")
            || line.starts_with("0.0.0.0/1 ")
            || line.starts_with("128.0.0.0/1 ")
    }) {
        bail!(
            "traffic policy route preflight failed: a full-tunnel route already exists on interface '{tun_name}'; disable the existing VPN or exit-node route first"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_mark_conflict() -> Result<()> {
    let rules = output("ip", &["-4", "rule", "show"])?;
    let marker = LOCAL_MARK.trim_start_matches("0x").to_ascii_lowercase();
    let marker_without_leading_zeros = marker.trim_start_matches('0');
    for rule in rules.lines() {
        let normalized = rule.to_ascii_lowercase();
        if !normalized.contains("fwmark")
            || (!normalized.contains(&marker) && !normalized.contains(marker_without_leading_zeros))
        {
            continue;
        }
        let owned_bypass =
            normalized.contains(BYPASS_RULE_PRIORITY) && normalized.contains("lookup main");
        if !owned_bypass {
            bail!(
                "traffic policy mark preflight failed: SDL mark {LOCAL_MARK_RULE} is already used by policy rule '{rule}'"
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_route_table_conflict() -> Result<()> {
    let routes = output("ip", &["-4", "route", "show", "table", ROUTE_TABLE])?;
    if !routes.trim().is_empty() {
        bail!(
            "traffic policy route-table preflight failed: table {ROUTE_TABLE} is not empty; SDL will not flush routes it does not own"
        );
    }
    let rules = output("ip", &["-4", "rule", "show"])?;
    if rules.lines().any(|rule| {
        rule.split_whitespace().any(|field| field == ROUTE_TABLE)
            && !rule.contains(TUN_RULE_PRIORITY)
    }) {
        bail!(
            "traffic policy route-table preflight failed: table {ROUTE_TABLE} is referenced by another policy rule"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_nft_set(local_cidrs: &[String], route_excludes: &[String]) -> Result<()> {
    let mut cidrs = local_cidrs.to_vec();
    cidrs.extend_from_slice(route_excludes);
    cidrs.sort();
    cidrs.dedup();
    let elements = cidrs.join(", ");
    let script = format!(
        "destroy table inet {NFT_TABLE}\n\
         table inet {NFT_TABLE} {{\n\
           set bypass_v4 {{ type ipv4_addr; flags interval; elements = {{ {elements} }} }}\n\
           chain output {{ type route hook output priority mangle; policy accept; ip daddr @bypass_v4 meta mark set ((meta mark & 0xff000000) | {LOCAL_MARK}) }}\n\
         }}\n"
    );
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start nft")?;
    child
        .stdin
        .take()
        .context("open nft stdin")?
        .write_all(script.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "nft policy install failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

#[cfg(target_os = "linux")]
fn apply_routes(plan: &LocalEgressPlan) -> Result<()> {
    run(
        "ip",
        &[
            "route",
            "replace",
            "default",
            "dev",
            &plan.tun_name,
            "table",
            ROUTE_TABLE,
        ],
    )?;
    run(
        "ip",
        &[
            "rule",
            "add",
            "priority",
            BYPASS_RULE_PRIORITY,
            "fwmark",
            LOCAL_MARK_RULE,
            "lookup",
            "main",
        ],
    )?;
    run(
        "ip",
        &[
            "rule",
            "add",
            "priority",
            TUN_RULE_PRIORITY,
            "lookup",
            ROUTE_TABLE,
        ],
    )
}

#[cfg(target_os = "linux")]
fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "{} {:?} failed: {}",
            program,
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

#[cfg(target_os = "linux")]
fn output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        bail!(
            "{} {:?} failed: {}",
            program,
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}
