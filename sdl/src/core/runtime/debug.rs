use std::env;

use serde_json::{json, Map, Value};

use super::SdlRuntime;
use crate::handle::CurrentDeviceInfo;

impl SdlRuntime {
    pub(crate) fn debug_snapshot_json(&self, sections: &[String]) -> anyhow::Result<String> {
        let include_all = sections.is_empty() || sections.iter().any(|section| section == "all");
        let wants = |name: &str| include_all || sections.iter().any(|section| section == name);
        let mut root = Map::new();
        root.insert(
            "collected_at_unix_ms".into(),
            json!(crate::handle::now_time() as i64),
        );
        root.insert(
            "selected_sections".into(),
            json!(if include_all {
                vec!["all".to_string()]
            } else {
                sections.to_vec()
            }),
        );

        if wants("runtime") {
            root.insert("runtime".into(), self.snapshot_runtime());
        }

        if wants("gateway") {
            root.insert("gateway".into(), self.snapshot_gateway());
        }

        if wants("nat") {
            root.insert("nat".into(), self.snapshot_nat());
        }

        if wants("peers") {
            root.insert("peers".into(), self.snapshot_peers());
        }

        if wants("routes") {
            root.insert(
                "routes".into(),
                self.snapshot_routes(self.state.current_device.load()),
            );
        }

        if wants("traffic") {
            root.insert("traffic".into(), self.snapshot_traffic());
        }

        serde_json::to_string_pretty(&Value::Object(root)).map_err(Into::into)
    }

    fn snapshot_runtime(&self) -> Value {
        let current_device = self.state.current_device.load();
        let dns_profile = self.state.dns.profile.read().clone();
        let auth_request = self.state.auth_request.read().clone();
        json!({
            "name": self.config.name,
            "device_id": self.config.device_id,
            "sdl_version": crate::build_version_string(),
            "server_addr": self.config.server_addr,
            "mtu": self.config.mtu,
            "virtual_ip": current_device.virtual_ip.to_string(),
            "virtual_gateway": current_device.virtual_gateway.to_string(),
            "virtual_netmask": current_device.virtual_netmask.to_string(),
            "virtual_network": current_device.virtual_network.to_string(),
            "broadcast_ip": current_device.broadcast_ip.to_string(),
            "control_server": self.control_session.server_addr().to_string(),
            "connect_status": format!("{:?}", current_device.status),
            "use_channel_type": format!("{:?}", self.routes().use_channel_type()),
            "dns_profile": dns_profile.as_ref().map(|profile| json!({
                "servers": profile.servers,
                "match_domains": profile.match_domains,
                "peer_name_domain": profile.peer_name_domain,
            })).unwrap_or(Value::Null),
            "system": debug_system_info_json(),
            "build": debug_build_info_json(),
            "auth_request": {
                "user_id": auth_request.user_id,
                "group": auth_request.group,
                "ticket_present": auth_request.ticket.as_ref().map(|ticket| !ticket.is_empty()).unwrap_or(false),
            },
        })
    }

    fn snapshot_gateway(&self) -> Value {
        let summary = self.data_plane.gateway_sessions.session_summary();
        let grant = self.data_plane.gateway_sessions.current_grant_snapshot();
        json!({
            "configured": summary.configured,
            "authenticated": summary.authenticated,
            "endpoint": summary.endpoint.map(|endpoint| endpoint.to_string()),
            "channel_name": summary.channel_name,
            "grant_state": summary.grant_state.as_str(),
            "lease_expire_unix_ms": summary.lease_expire_unix_ms,
            "grace_expire_unix_ms": summary.grace_expire_unix_ms,
            "reauth_required": summary.reauth_required,
            "relay_health": summary.relay_health.as_str(),
            "last_probe_unix_ms": summary.last_probe_unix_ms,
            "last_probe_rtt_ms": summary.last_probe_rtt_ms,
            "consecutive_probe_failures": summary.consecutive_probe_failures,
            "grant": grant.as_ref().map(|grant| json!({
                "session_id": grant.session_id,
                "policy_rev": grant.policy_rev,
                "soft_refresh_after_unix_ms": grant.soft_refresh_after_unix_ms,
                "hard_expire_unix_ms": grant.hard_expire_unix_ms,
                "ticket_expire_unix_ms": grant.ticket_expire_unix_ms,
            })).unwrap_or(Value::Null),
        })
    }

    fn snapshot_nat(&self) -> Value {
        let nat_info = self.nat_test.nat_info();
        json!({
            "nat_type": format!("{:?}", nat_info.nat_type),
            "punch_model": format!("{:?}", nat_info.punch_model),
            "public_ips": nat_info.public_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "public_ports": nat_info.public_ports,
            "public_port_range": nat_info.public_port_range,
            "public_udp_endpoints": nat_info.public_udp_endpoints.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "local_udp_ports": nat_info.local_udp_ports,
            "local_udp_endpoints": nat_info.local_udp_endpoints().iter().map(ToString::to_string).collect::<Vec<_>>(),
            "local_ipv4": nat_info.local_ipv4.map(|ip| ip.to_string()),
            "ipv6": nat_info.ipv6.map(|ip| ip.to_string()),
        })
    }

    fn snapshot_peers(&self) -> Value {
        let (peer_epoch, mut peer_items) = {
            let peer_table = self.state.peers.table.read();
            let peers = peer_table
                .values()
                .map(|peer| {
                    let relay_health = self
                        .data_plane
                        .gateway_sessions
                        .peer_relay_health_summary(peer.virtual_ip);
                    json!({
                        "virtual_ip": peer.virtual_ip.to_string(),
                        "name": peer.name,
                        "status": format!("{:?}", peer.status),
                        "device_id": peer.device_id,
                        "device_pub_key_len": peer.device_pub_key.len(),
                        "online_kx_pub_len": peer.online_kx_pub.len(),
                        "last_relay_receive_unix_ms": relay_health.last_relay_receive_unix_ms,
                        "last_relay_probe_unix_ms": relay_health.last_probe_unix_ms,
                        "relay_probe_failures": relay_health.consecutive_probe_failures,
                    })
                })
                .collect::<Vec<_>>();
            (peer_table.epoch(), peers)
        };
        peer_items.sort_by(|a, b| a["virtual_ip"].as_str().cmp(&b["virtual_ip"].as_str()));

        let mut peer_nat_items = self.state
            .peers.nat_info_map
            .read()
            .iter()
            .map(|(peer_ip, info)| {
                json!({
                    "peer_ip": peer_ip.to_string(),
                    "nat_type": format!("{:?}", info.nat_type),
                    "public_ips": info.public_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "public_ports": info.public_ports,
                })
            })
            .collect::<Vec<_>>();
        peer_nat_items.sort_by(|a, b| a["peer_ip"].as_str().cmp(&b["peer_ip"].as_str()));

        let (current_cipher_count, previous_cipher_count, grace_active) =
            self.state.peers.crypto.debug_counts();
        json!({
            "epoch": peer_epoch,
            "peer_count": peer_items.len(),
            "peer_nat_count": peer_nat_items.len(),
            "current_cipher_count": current_cipher_count,
            "previous_cipher_count": previous_cipher_count,
            "cipher_grace_active": grace_active,
            "items": peer_items,
            "nat_items": peer_nat_items,
        })
    }

    fn snapshot_routes(&self, current_device: CurrentDeviceInfo) -> Value {
        let mut route_items = self
            .data_plane
            .route_manager
            .snapshot_route_states(current_device.virtual_gateway)
            .into_iter()
            .flat_map(|(_, states)| states)
            .map(|state| {
                json!({
                    "peer_ip": state.peer_ip.to_string(),
                    "kind": format!("{:?}", state.kind),
                    "transport": format!("{:?}", state.transport),
                    "addr": state.addr.to_string(),
                    "metric": state.metric,
                    "rt": state.rt,
                })
            })
            .collect::<Vec<_>>();
        route_items.sort_by(|a, b| {
            a["peer_ip"]
                .as_str()
                .cmp(&b["peer_ip"].as_str())
                .then_with(|| a["addr"].as_str().cmp(&b["addr"].as_str()))
        });
        json!({
            "count": route_items.len(),
            "items": route_items,
        })
    }

    fn snapshot_traffic(&self) -> Value {
        json!({
            "up_total": self.state.data_plane_stats.up_traffic_total(),
            "up_channels": self.state.data_plane_stats.up_traffic_all().map(|(_, channels)| channels),
            "down_total": self.state.data_plane_stats.down_traffic_total(),
            "down_channels": self.state.data_plane_stats.down_traffic_all().map(|(_, channels)| channels),
        })
    }
}

fn debug_system_info_json() -> Value {
    json!({
        "hostname": gethostname::gethostname().to_string_lossy().into_owned(),
        "os": env::consts::OS,
        "arch": env::consts::ARCH,
        "family": env::consts::FAMILY,
        "target_env": option_env!("CARGO_CFG_TARGET_ENV"),
        "target_vendor": option_env!("CARGO_CFG_TARGET_VENDOR"),
        "process_id": std::process::id(),
        "current_dir": env::current_dir().ok().map(|path| path.display().to_string()),
        "current_exe": env::current_exe().ok().map(|path| path.display().to_string()),
    })
}

fn debug_build_info_json() -> Value {
    let build = crate::BUILD_INFO;
    json!({
        "display_version": crate::build_version_string(),
        "package_name": build.package_name,
        "package_version": build.package_version,
        "git_tag": build.git_tag,
        "git_commit": build.git_commit,
        "serial": build.serial,
        "debug_assertions": cfg!(debug_assertions),
        "features": {
            "quic": cfg!(feature = "quic"),
            "port_mapping": cfg!(feature = "port_mapping"),
            "upnp": cfg!(feature = "upnp"),
            "lz4_compress": cfg!(feature = "lz4_compress"),
            "zstd_compress": cfg!(feature = "zstd_compress"),
            "aes_gcm": cfg!(feature = "aes_gcm"),
            "aes_cbc": cfg!(feature = "aes_cbc"),
            "aes_ecb": cfg!(feature = "aes_ecb"),
            "sm4_cbc": cfg!(feature = "sm4_cbc"),
            "chacha20_poly1305": cfg!(feature = "chacha20_poly1305"),
        },
    })
}
