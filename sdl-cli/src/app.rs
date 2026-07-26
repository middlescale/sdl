use crate::command::entity::{
    DeviceItem, ExitNodeItem, ExitNodeStatus, GatewayItem, Info, RouteItem, TrafficSummary,
};
use crate::command::server::{
    AuthCommand, CommandHandler, CommandServer, ExitNodeDisableCommand, ExitNodeEnableCommand,
    ExitNodeUseCommand, SwitchCommand,
};
use crate::command::service_state::{read_service_state, write_service_state, LocalServiceState};
use crate::config::{
    read_user_config, save_current_user_config, write_saved_config, write_user_config, FileConfig,
    OriginalDnsServiceFileConfig,
};
use crate::service_lock::ServiceInstanceGuard;
use anyhow::Context;
use console::style;
use sdl::core::{Config, ExitNodeLocalState, PeerIdentity, RenameRequestOutcome, Sdl};
use sdl::data_plane::use_channel_type::UseChannelType;
use sdl::net::exit_node;
use sdl::{ConnectInfo, ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, SdlCallback};
use std::collections::BTreeSet;
use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use crate::root_check;

struct ServiceManager {
    config: Mutex<Config>,
    saved_config: Mutex<FileConfig>,
    runtime: Mutex<Option<Arc<Sdl>>>,
    runtime_start_lock: Mutex<()>,
    // Serializes system route/DNS changes with their corresponding persisted state.
    exit_node_client_route_lock: Mutex<()>,
}

#[derive(Clone)]
struct ServiceCommandHandler(Arc<ServiceManager>);

pub(crate) struct RunningService {
    manager: Arc<ServiceManager>,
    _service_lock: ServiceInstanceGuard,
}

struct ExitNodeClientSelection {
    peer_name: String,
    peer_identity: PeerIdentity,
    tun_name: String,
    route_excludes: Vec<String>,
    applied_route_excludes: Vec<String>,
    dns_service_ip: Ipv4Addr,
}

impl ServiceManager {
    fn saved_client_dns_state(saved_config: &FileConfig) -> Option<exit_node::ClientDnsState> {
        if saved_config.exit_node.original_dns.is_empty() {
            return None;
        }
        Some(
            saved_config
                .exit_node
                .original_dns
                .iter()
                .map(|service| exit_node::ClientDnsServiceState {
                    service: service.service.clone(),
                    restore_servers: service.restore_servers.clone(),
                    restore_metric: service.restore_metric,
                    restore_automatic_metric: service.restore_automatic_metric,
                })
                .collect(),
        )
    }

    fn file_client_dns_state(
        state: exit_node::ClientDnsState,
    ) -> Vec<OriginalDnsServiceFileConfig> {
        state
            .into_iter()
            .map(|service| OriginalDnsServiceFileConfig {
                service: service.service,
                restore_servers: service.restore_servers,
                restore_metric: service.restore_metric,
                restore_automatic_metric: service.restore_automatic_metric,
            })
            .collect()
    }

    fn merge_route_exclude_lists(left: &[String], right: &[String]) -> Vec<String> {
        left.iter()
            .chain(right.iter())
            .filter_map(|value| {
                let value = value.trim();
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn exit_node_dns_service_ip(runtime: &Sdl) -> anyhow::Result<Ipv4Addr> {
        runtime.primary_dns_service_ip().ok_or_else(|| {
            anyhow::anyhow!("SDL DNS service IP is not available; reconnect to control and retry")
        })
    }

    /// Prefer the persisted public-key fingerprint. If it is not currently
    /// known, also try the legacy device ID so an old 64-character hexadecimal
    /// device ID is not mistaken permanently for a fingerprint.
    fn selected_exit_node_peer(
        runtime: &Sdl,
        selected_value: &str,
    ) -> anyhow::Result<sdl::core::PeerInfo> {
        if let Some(identity) = PeerIdentity::from_fingerprint_hex(selected_value) {
            if let Some(vip) = runtime.peer_vip_for_identity(&identity) {
                if let Some(peer) = runtime.peer_info(&vip) {
                    return Ok(peer);
                }
            }
        }
        runtime
            .device_list()
            .into_iter()
            .find(|peer| peer.device_id() == selected_value)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "selected exit-node identity or legacy device ID {} is not in the current device list",
                    selected_value
                )
            })
    }

    fn snapshot_exit_node_client_state(&self) -> exit_node::ClientRouteDnsSnapshot {
        let saved_config = self.saved_config.lock().unwrap().clone();
        exit_node::ClientRouteDnsSnapshot {
            client_active: saved_config.exit_node.client_active,
            tun_name: Self::saved_exit_node_tun_name(&saved_config),
            applied_route_excludes: saved_config.exit_node.applied_route_excludes.clone(),
            dns_state: Self::saved_client_dns_state(&saved_config),
        }
    }

    fn build_exit_node_client_selection(
        &self,
        runtime: &Sdl,
        peer_name: String,
        peer_identity: PeerIdentity,
        tun_name: String,
        route_excludes: &[String],
    ) -> anyhow::Result<ExitNodeClientSelection> {
        Ok(ExitNodeClientSelection {
            peer_name,
            peer_identity,
            tun_name,
            route_excludes: route_excludes.to_vec(),
            applied_route_excludes: exit_node::merge_excludes(
                runtime,
                Some(&peer_identity),
                route_excludes,
            )?,
            dns_service_ip: Self::exit_node_dns_service_ip(runtime)?,
        })
    }

    fn mark_exit_node_client_inactive_for_cleanup(
        &self,
        runtime: &Sdl,
        previous: &exit_node::ClientRouteDnsSnapshot,
        next: &ExitNodeClientSelection,
        apply_err: &exit_node::ClientRouteDnsApplyError,
    ) {
        let mut saved_config = self.saved_config.lock().unwrap();
        saved_config.exit_node.client_active = false;
        saved_config.exit_node.applied_route_excludes = Self::merge_route_exclude_lists(
            &previous.applied_route_excludes,
            &next.applied_route_excludes,
        );
        saved_config.exit_node.original_dns = previous
            .dns_state
            .clone()
            .map(Self::file_client_dns_state)
            .unwrap_or_default();
        drop(saved_config);
        self.persist_saved_config();
        runtime.set_exit_node_state(self.exit_node_state_from_saved_config());
        log::warn!("{apply_err}; exit-node was marked inactive for later cleanup");
    }

    fn apply_exit_node_client_selection(
        &self,
        runtime: &Sdl,
        previous: &exit_node::ClientRouteDnsSnapshot,
        next: &ExitNodeClientSelection,
    ) -> anyhow::Result<exit_node::ClientRouteDnsApplyResult> {
        let route_dns_selection = exit_node::ClientRouteDnsSelection {
            tun_name: next.tun_name.clone(),
            applied_route_excludes: next.applied_route_excludes.clone(),
            dns_service_ip: next.dns_service_ip,
        };
        match exit_node::apply_client_route_dns_selection(previous, &route_dns_selection) {
            Ok(result) => {
                runtime.set_exit_node_state(ExitNodeLocalState {
                    enabled: false,
                    local_ready: false,
                    egress_interface: None,
                    selected_identity: Some(next.peer_identity),
                });
                Ok(result)
            }
            Err(err) => {
                if err.rollback_failed() {
                    self.mark_exit_node_client_inactive_for_cleanup(runtime, previous, next, &err);
                } else {
                    runtime.set_exit_node_state(self.exit_node_state_from_saved_config());
                }
                Err(anyhow::Error::new(err))
            }
        }
    }

    fn persist_exit_node_client_selection(
        &self,
        selection: &ExitNodeClientSelection,
        dns_state: Option<exit_node::ClientDnsState>,
    ) {
        let mut saved_config = self.saved_config.lock().unwrap();
        saved_config.exit_node.client_active = true;
        saved_config.exit_node.selected_identity = Some(selection.peer_identity.fingerprint_hex());
        saved_config.exit_node.tun_name = Some(selection.tun_name.clone());
        saved_config.exit_node.route_excludes = selection.route_excludes.clone();
        saved_config.exit_node.applied_route_excludes = selection.applied_route_excludes.clone();
        saved_config.exit_node.original_dns = dns_state
            .map(Self::file_client_dns_state)
            .unwrap_or_default();
        drop(saved_config);
        self.persist_saved_config();
    }

    fn reapply_exit_node_client_routes(&self) -> anyhow::Result<Option<String>> {
        let _route_guard = self.exit_node_client_route_lock.lock().unwrap();
        let saved_config = self.saved_config.lock().unwrap().clone();
        if !saved_config.exit_node.client_active {
            return Ok(None);
        }
        let Some(selected_value) = saved_config.exit_node.selected_identity.as_deref() else {
            return Ok(None);
        };
        let runtime = self.current_runtime()?;
        let tun_name = self.resolve_exit_node_tun_name(None)?;
        let peer = Self::selected_exit_node_peer(&runtime, selected_value)?;
        if !peer.exit_node_usable() {
            anyhow::bail!(
                "selected exit node '{}' is not currently usable; advertised={}, approved={}, online={}",
                peer.device_id(),
                peer.exit_node_advertised(),
                peer.exit_node_approved(),
                peer.status().is_online()
            );
        }
        let previous = self.snapshot_exit_node_client_state();
        let peer_identity = peer.identity();
        let selection = self.build_exit_node_client_selection(
            &runtime,
            peer.name().to_string(),
            peer_identity,
            tun_name,
            &saved_config.exit_node.route_excludes,
        )?;
        let apply_result =
            self.apply_exit_node_client_selection(&runtime, &previous, &selection)?;
        self.persist_exit_node_client_selection(&selection, apply_result.dns_state);
        runtime.set_exit_node_state(self.exit_node_state_from_saved_config());
        Ok(Some(format!(
            "exit-node client routes reapplied after TUN recreate: {}; {}",
            apply_result.route_note, apply_result.dns_note
        )))
    }

    fn refresh_exit_node_client_route_excludes(&self) -> anyhow::Result<Option<String>> {
        let _route_guard = self.exit_node_client_route_lock.lock().unwrap();
        let saved_config = self.saved_config.lock().unwrap().clone();
        if !saved_config.exit_node.client_active {
            return Ok(None);
        }
        let Some(selected_value) = saved_config.exit_node.selected_identity.as_deref() else {
            return Ok(None);
        };
        let runtime = self.current_runtime()?;
        let tun_name = Self::saved_exit_node_tun_name(&saved_config);
        let selected_identity = Self::selected_exit_node_peer(&runtime, selected_value)?.identity();
        let next_excludes = exit_node::merge_excludes(
            &runtime,
            Some(&selected_identity),
            &saved_config.exit_node.route_excludes,
        )?;
        if next_excludes == saved_config.exit_node.applied_route_excludes {
            return Ok(None);
        }
        match exit_node::refresh_client_route_excludes(
            &tun_name,
            &saved_config.exit_node.applied_route_excludes,
            &next_excludes,
        ) {
            Ok(note) => {
                {
                    let mut saved_config = self.saved_config.lock().unwrap();
                    saved_config.exit_node.applied_route_excludes = next_excludes;
                }
                self.persist_saved_config();
                Ok(Some(note))
            }
            Err(err) => {
                if err.rollback_failed() {
                    let mut saved_config = self.saved_config.lock().unwrap();
                    saved_config.exit_node.client_active = false;
                    saved_config.exit_node.applied_route_excludes = Self::merge_route_exclude_lists(
                        &saved_config.exit_node.applied_route_excludes,
                        &next_excludes,
                    );
                    drop(saved_config);
                    self.persist_saved_config();
                    runtime.set_exit_node_state(self.exit_node_state_from_saved_config());
                }
                Err(anyhow::Error::new(err))
            }
        }
    }

    fn persist_device_name(self: &Arc<Self>, applied_name: String) {
        {
            let mut config = self.config.lock().unwrap();
            let mut saved_config = self.saved_config.lock().unwrap();
            if config.name == applied_name && saved_config.name == applied_name {
                return;
            }
            config.name = applied_name.clone();
            saved_config.name = applied_name;
        }
        self.persist_saved_config();
    }

    fn rename_device(self: &Arc<Self>, new_name: &str) -> anyhow::Result<String> {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            anyhow::bail!("name cannot be empty");
        }
        if trimmed.len() > 128 {
            anyhow::bail!("name too long");
        }
        let current_name = self.current_config().name;
        if current_name == trimmed {
            return Ok(format!("device name already set to {}", trimmed));
        }
        let runtime = self.current_runtime()?;
        match runtime.request_device_rename(trimmed.to_string(), Duration::from_secs(10))? {
            RenameRequestOutcome::Applied(applied_name) => {
                let applied_name = if applied_name.is_empty() {
                    trimmed.to_string()
                } else {
                    applied_name
                };
                self.persist_device_name(applied_name.clone());
                Ok(format!(
                    "device rename saved as {}; restart sdl-service to apply",
                    applied_name
                ))
            }
            RenameRequestOutcome::RestartRequired(applied_name) => {
                let applied_name = if applied_name.is_empty() {
                    trimmed.to_string()
                } else {
                    applied_name
                };
                self.persist_device_name(applied_name.clone());
                Ok(format!(
                    "device rename saved as {}; restart sdl-service to apply",
                    applied_name
                ))
            }
        }
    }

    fn new(config: Config, saved_config: FileConfig) -> Self {
        Self {
            config: Mutex::new(config),
            saved_config: Mutex::new(saved_config),
            runtime: Mutex::new(None),
            runtime_start_lock: Mutex::new(()),
            exit_node_client_route_lock: Mutex::new(()),
        }
    }

    fn mutate_state<F>(&self, f: F)
    where
        F: FnOnce(&mut LocalServiceState),
    {
        let mut state = read_service_state().unwrap_or_default();
        f(&mut state);
        if let Err(e) = write_service_state(&state) {
            log::warn!("write service state failed: {:?}", e);
        }
    }

    fn current_config(&self) -> Config {
        self.config.lock().unwrap().clone()
    }

    fn persist_saved_config(&self) {
        let saved_config = self.saved_config.lock().unwrap().clone();
        if let Err(e) = write_saved_config(&saved_config) {
            log::warn!("write saved config failed: {:?}", e);
        }
    }

    fn current_runtime(&self) -> io::Result<Arc<Sdl>> {
        let runtime = self.runtime.lock().unwrap().clone();
        match runtime {
            Some(vnt) if !vnt.is_stopped() => Ok(vnt),
            _ => Err(io::Error::other(
                "service runtime is unavailable, run `sdl up` or restart `sdl-service`",
            )),
        }
    }

    fn stopped_info(&self) -> Info {
        let config = self.current_config();
        let state = read_service_state().unwrap_or_default();
        let (auth_status, auth_detail) = crate::command::describe_auth_state(&state);
        let channel_policy = match config.use_channel_type {
            UseChannelType::Relay => "relay".to_string(),
            UseChannelType::P2p => "p2p".to_string(),
            UseChannelType::Auto => "auto".to_string(),
        };
        #[cfg(feature = "port_mapping")]
        let port_mapping_list = config.port_mapping_list.clone();
        #[cfg(not(feature = "port_mapping"))]
        let port_mapping_list = vec![];
        Info {
            name: config.name,
            runtime_name: String::new(),
            runtime_status: crate::command::runtime_status_label(&state),
            restart_required: false,
            device_id: config.device_id.clone(),
            virtual_ip: String::new(),
            virtual_gateway: String::new(),
            virtual_netmask: String::new(),
            gateway_session_status: "stopped".to_string(),
            gateway_grant_state: "not-configured".to_string(),
            gateway_endpoint: String::new(),
            gateway_channel: String::new(),
            connect_status: "Stopped".to_string(),
            data_plane_status: "stopped".to_string(),
            auth_pending: state.auth_pending,
            auth_status,
            auth_detail,
            channel_policy,
            last_error: state.last_error,
            nat_type: String::new(),
            public_ips: String::new(),
            local_addr: String::new(),
            ipv6_addr: String::new(),
            port_mapping_list,
            udp_listen_addr: vec![],
        }
    }

    fn spawn_service_runtime(self: &Arc<Self>) -> anyhow::Result<Arc<Sdl>> {
        if let Some(runtime) = self.runtime.lock().unwrap().clone() {
            if !runtime.is_stopped() {
                self.mutate_state(|state| {
                    state.runtime_starting = false;
                    state.runtime_running = true;
                    state.runtime_suspended = runtime.is_suspended();
                });
                return Ok(runtime);
            }
        }
        let _start_guard = self.runtime_start_lock.lock().unwrap();
        if let Some(runtime) = self.runtime.lock().unwrap().clone() {
            if !runtime.is_stopped() {
                self.mutate_state(|state| {
                    state.runtime_starting = false;
                    state.runtime_running = true;
                    state.runtime_suspended = runtime.is_suspended();
                });
                return Ok(runtime);
            }
        }
        self.mutate_state(|state| {
            state.runtime_starting = true;
            state.runtime_running = false;
            state.runtime_suspended = false;
            state.last_error = None;
        });
        let result = (|| {
            let config = self.current_config();
            let callback = ServiceCallback::new(Arc::downgrade(self));
            match self.cleanup_exit_node_client_state() {
                Ok(Some(note)) => log::info!(
                    "reset exit-node client state before runtime start: {}",
                    note
                ),
                Ok(None) => {}
                Err(err) => log::warn!(
                    "failed to reset exit-node client state before runtime start: {:?}",
                    err
                ),
            }
            let sdl = Arc::new(Sdl::new(config, callback)?);
            if let Err(err) = self.reapply_exit_node_server_state() {
                log::warn!("failed to reapply exit-node system state: {err:?}");
            }
            sdl.set_exit_node_state(self.exit_node_state_from_saved_config());
            *self.runtime.lock().unwrap() = Some(sdl.clone());
            Ok::<Arc<Sdl>, anyhow::Error>(sdl)
        })();
        match result {
            Ok(sdl) => {
                self.mutate_state(|state| {
                    state.runtime_starting = false;
                    state.runtime_running = true;
                    state.runtime_suspended = false;
                });
                Ok(sdl)
            }
            Err(err) => {
                let message = format!("{err:?}");
                self.mutate_state(|state| {
                    state.runtime_starting = false;
                    state.runtime_running = false;
                    state.runtime_suspended = false;
                    state.last_error = Some(message);
                });
                Err(err)
            }
        }
    }

    fn exit_node_state_from_saved_config(&self) -> ExitNodeLocalState {
        let saved_config = self.saved_config.lock().unwrap();
        let enabled = saved_config.exit_node.enabled;
        ExitNodeLocalState {
            enabled,
            local_ready: exit_node::local_ready(enabled, &saved_config.exit_node.egress_interface),
            egress_interface: saved_config.exit_node.egress_interface.clone(),
            selected_identity: saved_config
                .exit_node
                .client_active
                .then(|| saved_config.exit_node.selected_identity.as_deref())
                .flatten()
                .and_then(PeerIdentity::from_fingerprint_hex),
        }
    }

    fn saved_exit_node_tun_name(saved_config: &FileConfig) -> String {
        saved_config
            .exit_node
            .tun_name
            .as_deref()
            .unwrap_or("sdl-tun")
            .trim()
            .to_string()
    }

    fn resolve_exit_node_tun_name(&self, requested: Option<&str>) -> anyhow::Result<String> {
        if let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) {
            return Ok(requested.to_string());
        }
        if let Ok(runtime) = self.current_runtime() {
            if let Some(name) = runtime
                .tun_device_name()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            {
                return Ok(name);
            }
        }
        Ok("sdl-tun".to_string())
    }

    fn reapply_exit_node_server_state(&self) -> anyhow::Result<()> {
        let saved_config = self.saved_config.lock().unwrap().clone();
        let tun_name = Self::saved_exit_node_tun_name(&saved_config);
        if saved_config.exit_node.enabled {
            let egress_interface = saved_config
                .exit_node
                .egress_interface
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("exit-node enabled but egress_interface is not configured")
                })?;
            exit_node::setup_server_routing(egress_interface, &tun_name)?;
        }
        Ok(())
    }

    fn cleanup_exit_node_client_state(&self) -> anyhow::Result<Option<String>> {
        let _route_guard = self.exit_node_client_route_lock.lock().unwrap();
        let saved_config = self.saved_config.lock().unwrap().clone();
        if !saved_config.exit_node.client_active
            && saved_config.exit_node.applied_route_excludes.is_empty()
            && saved_config.exit_node.original_dns.is_empty()
        {
            return Ok(None);
        }
        let tun_name = Self::saved_exit_node_tun_name(&saved_config);
        let dns_state = Self::saved_client_dns_state(&saved_config);
        let dns_result = exit_node::teardown_client_dns(dns_state.as_ref())?;
        let setup_result = exit_node::teardown_client_routing(
            &tun_name,
            &saved_config.exit_node.applied_route_excludes,
        )?;
        {
            let mut saved_config = self.saved_config.lock().unwrap();
            saved_config.exit_node.client_active = false;
            saved_config.exit_node.applied_route_excludes.clear();
            saved_config.exit_node.original_dns.clear();
        }
        self.persist_saved_config();
        Ok(Some(format!("{}; {}", setup_result, dns_result)))
    }

    fn block_data_plane_for_auth_pending(&self, message: &str) {
        match self.cleanup_exit_node_client_state() {
            Ok(Some(note)) => log::info!(
                "reset exit-node client state while auth is pending: {}",
                note
            ),
            Ok(None) => {}
            Err(err) => log::warn!(
                "failed to reset exit-node client state while auth is pending: {:?}",
                err
            ),
        }
        match self.current_runtime() {
            Ok(runtime) => {
                runtime.block_data_plane_for_auth_pending();
                log::warn!("blocked SDL data plane while auth is pending: {}", message);
            }
            Err(err) => log::warn!(
                "failed to block SDL data plane while auth is pending: {:?}",
                err
            ),
        }
    }

    fn reapply_exit_node_state_after_auth(&self) {
        if let Err(err) = self.reapply_exit_node_server_state() {
            log::warn!("failed to reapply exit-node system state after auth: {err:?}");
        }
        match self.current_runtime() {
            Ok(runtime) => runtime.set_exit_node_state(self.exit_node_state_from_saved_config()),
            Err(err) => log::warn!("failed to reapply exit-node runtime state after auth: {err:?}"),
        }
    }

    fn exit_node_status(&self) -> ExitNodeStatus {
        let saved = self.saved_config.lock().unwrap().clone();
        let runtime_state = self
            .runtime
            .lock()
            .unwrap()
            .as_ref()
            .filter(|runtime| !runtime.is_stopped())
            .map(|runtime| runtime.exit_node_state());
        let enabled = runtime_state
            .as_ref()
            .map(|state| state.enabled)
            .unwrap_or(saved.exit_node.enabled);
        let local_ready = runtime_state
            .as_ref()
            .map(|state| state.local_ready)
            .unwrap_or(false);
        let egress_interface = runtime_state
            .as_ref()
            .and_then(|state| state.egress_interface.clone())
            .or_else(|| saved.exit_node.egress_interface.clone())
            .unwrap_or_default();
        let client_active = saved.exit_node.client_active
            && runtime_state
                .as_ref()
                .and_then(|state| state.selected_identity)
                .is_some();
        let selected_identity = runtime_state
            .as_ref()
            .and_then(|state| state.selected_identity)
            .map(|identity| identity.fingerprint_hex())
            .or_else(|| saved.exit_node.selected_identity.clone())
            .unwrap_or_default();
        let mut selected_name = String::new();
        let mut selected_virtual_ip = String::new();
        let mut selected_usable = false;
        if !selected_identity.is_empty() {
            if let Ok(runtime) = self.current_runtime() {
                if let Ok(peer) = Self::selected_exit_node_peer(&runtime, &selected_identity) {
                    selected_name = peer.name().to_string();
                    selected_virtual_ip = peer.virtual_ip().to_string();
                    selected_usable = peer.exit_node_usable();
                }
            }
        }
        let note = if client_active && selected_usable {
            "using selected exit node".to_string()
        } else if !selected_identity.is_empty() && selected_usable {
            "last selected exit node is usable but not active; run `sdl exit-node use <target>` to enable it".to_string()
        } else if !selected_identity.is_empty() {
            "last selected exit node is not currently usable".to_string()
        } else if enabled && local_ready {
            "advertising exit-node capability".to_string()
        } else if enabled {
            "exit-node is enabled, but this platform is not ready to advertise it".to_string()
        } else {
            "exit-node is disabled".to_string()
        };
        ExitNodeStatus {
            enabled,
            advertised: enabled,
            local_ready,
            egress_interface,
            client_active,
            selected_identity,
            selected_name,
            selected_virtual_ip,
            selected_usable,
            note,
        }
    }

    fn enable_exit_node(
        &self,
        egress_interface: &str,
        tun_name: Option<&str>,
    ) -> anyhow::Result<String> {
        let egress_interface = egress_interface.trim();
        if egress_interface.is_empty() {
            anyhow::bail!("egress_interface cannot be empty");
        }
        if egress_interface.len() > 64 {
            anyhow::bail!("egress_interface too long");
        }
        {
            let saved_config = self.saved_config.lock().unwrap();
            if saved_config.exit_node.client_active {
                anyhow::bail!(
                    "cannot enable this node as an exit node while it is using another exit node; run `sdl exit-node clear` first"
                );
            }
        }
        let tun_name = self.resolve_exit_node_tun_name(tun_name)?;
        let setup_result = exit_node::setup_server_routing(egress_interface, &tun_name)?;
        {
            let mut saved_config = self.saved_config.lock().unwrap();
            saved_config.exit_node.enabled = true;
            saved_config.exit_node.egress_interface = Some(egress_interface.to_string());
            saved_config.exit_node.tun_name = Some(tun_name.to_string());
        }
        self.persist_saved_config();
        let state = self.exit_node_state_from_saved_config();
        if let Ok(runtime) = self.current_runtime() {
            runtime.set_exit_node_state(state);
        }
        Ok(format!(
            "exit-node enabled on {}; waiting for control approval; {}",
            egress_interface, setup_result
        ))
    }

    fn disable_exit_node(&self, tun_name: Option<&str>) -> anyhow::Result<String> {
        let tun_name = self.resolve_exit_node_tun_name(tun_name)?;
        let egress_interface = {
            let saved_config = self.saved_config.lock().unwrap();
            saved_config.exit_node.egress_interface.clone()
        };
        let setup_result = match egress_interface.as_deref() {
            Some(egress_interface) if !egress_interface.trim().is_empty() => {
                exit_node::teardown_server_routing(egress_interface.trim(), &tun_name)?
            }
            _ => "exit-node routing was not configured".to_string(),
        };
        {
            let mut saved_config = self.saved_config.lock().unwrap();
            saved_config.exit_node.enabled = false;
        }
        self.persist_saved_config();
        if let Ok(runtime) = self.current_runtime() {
            runtime.set_exit_node_state(ExitNodeLocalState::default());
        }
        Ok(format!("exit-node disabled; {}", setup_result))
    }

    fn use_exit_node(
        &self,
        target: &str,
        tun_name: Option<&str>,
        excludes: &[String],
    ) -> anyhow::Result<String> {
        let _route_guard = self.exit_node_client_route_lock.lock().unwrap();
        let target = target.trim();
        if target.is_empty() {
            anyhow::bail!("exit-node target cannot be empty");
        }
        {
            let saved_config = self.saved_config.lock().unwrap();
            if saved_config.exit_node.enabled {
                anyhow::bail!(
                    "cannot use another exit node while this node is enabled as an exit node; run `sdl exit-node disable` first"
                );
            }
        }
        let tun_name = self.resolve_exit_node_tun_name(tun_name)?;
        let runtime = self.current_runtime()?;
        let peers = runtime.device_list();
        let target_ip = target.parse::<Ipv4Addr>().ok();
        let matches: Vec<_> = peers
            .into_iter()
            .filter(|peer| {
                peer.device_id() == target
                    || peer.name() == target
                    || target_ip
                        .map(|target_ip| peer.virtual_ip() == target_ip)
                        .unwrap_or(false)
            })
            .collect();
        if matches.is_empty() {
            anyhow::bail!(
                "exit node '{}' not found in current SDL device list",
                target
            );
        }
        if matches.len() > 1 {
            anyhow::bail!(
                "exit node target '{}' is ambiguous; use device id or virtual ip",
                target
            );
        }
        let peer = matches.into_iter().next().unwrap();
        if !peer.exit_node_usable() {
            anyhow::bail!(
                "device '{}' is not a usable exit node; advertised={}, approved={}, online={}",
                peer.device_id(),
                peer.exit_node_advertised(),
                peer.exit_node_approved(),
                peer.status().is_online()
            );
        }
        let previous = self.snapshot_exit_node_client_state();
        let peer_identity = peer.identity();
        let selection = self.build_exit_node_client_selection(
            &runtime,
            peer.name().to_string(),
            peer_identity,
            tun_name,
            excludes,
        )?;
        let apply_result =
            self.apply_exit_node_client_selection(&runtime, &previous, &selection)?;
        self.persist_exit_node_client_selection(&selection, apply_result.dns_state);
        runtime.set_exit_node_state(self.exit_node_state_from_saved_config());
        Ok(format!(
            "exit-node selection changed to {} ({}); {}; {}",
            selection.peer_name,
            selection.peer_identity.fingerprint_hex(),
            apply_result.route_note,
            apply_result.dns_note
        ))
    }

    fn clear_exit_node(&self, tun_name: Option<&str>) -> anyhow::Result<String> {
        let _route_guard = self.exit_node_client_route_lock.lock().unwrap();
        let tun_name = self.resolve_exit_node_tun_name(tun_name)?;
        let saved_config = self.saved_config.lock().unwrap().clone();
        let dns_state = Self::saved_client_dns_state(&saved_config);
        let current_effective_excludes =
            if let Some(selected_value) = saved_config.exit_node.selected_identity.as_deref() {
                match self.current_runtime() {
                    Ok(runtime) => {
                        let selected_identity =
                            Self::selected_exit_node_peer(&runtime, selected_value)?.identity();
                        exit_node::merge_excludes(
                            &runtime,
                            Some(&selected_identity),
                            &saved_config.exit_node.route_excludes,
                        )?
                    }
                    Err(_) => saved_config.exit_node.route_excludes.clone(),
                }
            } else {
                saved_config.exit_node.route_excludes.clone()
            };
        let effective_excludes = Self::merge_route_exclude_lists(
            &saved_config.exit_node.applied_route_excludes,
            &current_effective_excludes,
        );
        let dns_result = exit_node::teardown_client_dns(dns_state.as_ref())?;
        let setup_result = exit_node::teardown_client_routing(&tun_name, &effective_excludes)?;
        {
            let mut saved_config = self.saved_config.lock().unwrap();
            saved_config.exit_node.client_active = false;
            saved_config.exit_node.selected_identity = None;
            saved_config.exit_node.route_excludes.clear();
            saved_config.exit_node.applied_route_excludes.clear();
            saved_config.exit_node.original_dns.clear();
        }
        self.persist_saved_config();
        if let Ok(runtime) = self.current_runtime() {
            runtime.set_exit_node_state(self.exit_node_state_from_saved_config());
        }
        Ok(format!(
            "exit-node selection cleared; {}; {}",
            setup_result, dns_result
        ))
    }

    fn resume_service_runtime(self: &Arc<Self>) -> anyhow::Result<String> {
        let runtime = self.spawn_service_runtime()?;
        if runtime.is_suspended() {
            runtime.resume()?;
            self.mutate_state(|state| {
                state.runtime_starting = false;
                state.runtime_running = true;
                state.runtime_suspended = false;
            });
            self.persist_saved_config();
            Ok("service resumed".to_string())
        } else {
            self.mutate_state(|state| {
                state.runtime_starting = false;
                state.runtime_running = true;
                state.runtime_suspended = false;
            });
            self.persist_saved_config();
            Ok("service already resumed".to_string())
        }
    }

    fn suspend_service_runtime(&self) -> anyhow::Result<String> {
        let runtime = self.current_runtime()?;
        if runtime.is_suspended() {
            self.mutate_state(|state| {
                state.runtime_starting = false;
                state.runtime_running = true;
                state.runtime_suspended = true;
            });
            return Ok("service already suspended".to_string());
        }
        runtime.suspend()?;
        self.mutate_state(|state| {
            state.runtime_starting = false;
            state.runtime_running = true;
            state.runtime_suspended = true;
        });
        Ok("service suspended".to_string())
    }

    fn stop_service_runtime(&self) -> anyhow::Result<String> {
        match self.cleanup_exit_node_client_state() {
            Ok(Some(note)) => {
                log::info!("reset exit-node client state before runtime stop: {}", note)
            }
            Ok(None) => {}
            Err(err) => log::warn!(
                "failed to reset exit-node client state before runtime stop: {:?}",
                err
            ),
        }
        let runtime = self.runtime.lock().unwrap().take();
        if let Some(vnt) = runtime {
            vnt.stop();
            let _ = vnt.wait_timeout(Duration::from_secs(10));
            self.mutate_state(|state| {
                state.runtime_starting = false;
                state.runtime_running = false;
                state.runtime_suspended = false;
            });
            Ok("service stopped".to_string())
        } else {
            self.mutate_state(|state| {
                state.runtime_starting = false;
                state.runtime_running = false;
                state.runtime_suspended = false;
            });
            Ok("service already stopped".to_string())
        }
    }

    fn switch_user(&self, user_id: &str) -> anyhow::Result<String> {
        let user_id = user_id.trim();
        if user_id.is_empty() {
            anyhow::bail!("user_id cannot be empty");
        }
        if user_id.len() > 128 {
            anyhow::bail!("user_id too long");
        }

        let _ = self.stop_service_runtime();

        let current_saved_config = self.saved_config.lock().unwrap().clone();
        save_current_user_config(&current_saved_config)?;

        let mut next_saved_config = match read_user_config(user_id)? {
            Some((_, saved)) => saved,
            None => FileConfig::default(),
        };
        next_saved_config.user_id = Some(user_id.to_string());
        write_user_config(user_id, &next_saved_config)?;
        write_saved_config(&next_saved_config)?;
        let mut next_config = next_saved_config.clone().into_runtime_config()?;
        next_config.auth_user_id = None;
        next_config.auth_group = None;
        next_config.auth_ticket = None;
        {
            let mut config = self.config.lock().unwrap();
            *config = next_config;
        }
        {
            let mut saved_config = self.saved_config.lock().unwrap();
            *saved_config = next_saved_config;
        }

        self.mutate_state(|state| {
            state.runtime_starting = false;
            state.runtime_running = false;
            state.runtime_suspended = false;
            state.auth_pending = true;
            state.auth_message = Some(format!("reauth_required: switched to user_id={user_id}"));
            state.last_error = None;
            state.authenticated_user_id = None;
            state.authenticated_group = None;
        });

        Ok(format!(
            "switched to user_id={}; run `sdl auth --userId {} <ticket>` to authenticate",
            user_id, user_id
        ))
    }

    fn shutdown(&self) {
        if let Err(e) = self.stop_service_runtime() {
            log::warn!("shutdown stop failed: {:?}", e);
        }
    }

    fn record_auth_success(&self) {
        let mut config = self.config.lock().unwrap();
        let saved = self.saved_config.lock().unwrap();
        let authenticated_user_id = config.auth_user_id.clone();
        let authenticated_group = config.auth_group.clone();
        config.auth_ticket = None;
        self.mutate_state(|state| {
            state.runtime_starting = false;
            state.runtime_running = true;
            state.runtime_suspended = false;
            state.auth_pending = false;
            state.auth_message = None;
            state.last_error = None;
            state.authenticated_user_id = authenticated_user_id.clone();
            state.authenticated_group = authenticated_group.clone();
        });
        if let Some(user_id) = authenticated_user_id {
            log::info!("persisting authenticated user_id={}", user_id);
        }
        if let Err(e) = write_saved_config(&saved) {
            log::warn!("write saved config after auth failed: {:?}", e);
        }
    }
}

impl CommandHandler for ServiceCommandHandler {
    fn route(&self) -> io::Result<Vec<RouteItem>> {
        Ok(crate::command::command_route(
            self.0.current_runtime()?.as_ref(),
        ))
    }

    fn list(&self) -> io::Result<Vec<DeviceItem>> {
        Ok(crate::command::command_list(
            self.0.current_runtime()?.as_ref(),
        ))
    }

    fn info(&self) -> io::Result<Info> {
        match self.0.current_runtime() {
            Ok(vnt) => {
                let mut info = crate::command::command_info(vnt.as_ref());
                let desired_name = self.0.current_config().name;
                if info.name != desired_name {
                    info.restart_required = true;
                    info.name = desired_name;
                }
                if vnt.is_suspended() {
                    info.connect_status = "Suspended".to_string();
                }
                Ok(info)
            }
            Err(_) => Ok(self.0.stopped_info()),
        }
    }

    fn gateway(&self) -> io::Result<Vec<GatewayItem>> {
        match self.0.current_runtime() {
            Ok(vnt) => Ok(crate::command::command_gateway(vnt.as_ref())),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn gateway_set(&self, gateway: Option<&str>) -> io::Result<String> {
        let vnt = self.0.current_runtime()?;
        let Some(gateway) = gateway else {
            vnt.set_gateway_selection(None)
                .map_err(|e| io::Error::other(format!("gateway selection failed: {e:?}")))?;
            return Ok("gateway selection changed to auto".to_string());
        };
        if gateway.eq_ignore_ascii_case("auto") {
            vnt.set_gateway_selection(None)
                .map_err(|e| io::Error::other(format!("gateway selection failed: {e:?}")))?;
            return Ok("gateway selection changed to auto".to_string());
        }
        let gateways = crate::command::command_gateway(vnt.as_ref());
        let endpoint = gateways
            .iter()
            .find(|item| item.gateway_id == gateway || item.endpoint == gateway)
            .map(|item| item.endpoint.clone())
            .filter(|endpoint| !endpoint.is_empty())
            .ok_or_else(|| io::Error::other(format!("gateway '{}' not found", gateway)))?;
        let endpoint = endpoint.parse().map_err(|e| {
            io::Error::other(format!("invalid gateway endpoint '{}': {e}", endpoint))
        })?;
        vnt.set_gateway_selection(Some(endpoint))
            .map_err(|e| io::Error::other(format!("gateway selection failed: {e:?}")))?;
        Ok(format!("gateway selection changed to {}", gateway))
    }

    fn exit_node_status(&self) -> io::Result<ExitNodeStatus> {
        Ok(self.0.exit_node_status())
    }

    fn exit_node_list(&self) -> io::Result<Vec<ExitNodeItem>> {
        let runtime = self.0.current_runtime()?;
        let mut items: Vec<ExitNodeItem> = runtime
            .device_list()
            .into_iter()
            .filter(|peer| peer.exit_node_usable())
            .map(|peer| ExitNodeItem {
                name: peer.name().to_string(),
                device_id: peer.device_id().to_string(),
                virtual_ip: peer.virtual_ip().to_string(),
                status: format!("{:?}", peer.status()),
                approved: peer.exit_node_approved(),
                usable: peer.exit_node_usable(),
            })
            .collect();
        items.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.virtual_ip.cmp(&b.virtual_ip))
                .then_with(|| a.device_id.cmp(&b.device_id))
        });
        Ok(items)
    }

    fn exit_node_enable(&self, enable: ExitNodeEnableCommand) -> io::Result<String> {
        self.0
            .enable_exit_node(&enable.egress_interface, enable.tun_name.as_deref())
            .map_err(|e| io::Error::other(format!("exit-node enable failed: {e}")))
    }

    fn exit_node_disable(&self, disable: ExitNodeDisableCommand) -> io::Result<String> {
        self.0
            .disable_exit_node(disable.tun_name.as_deref())
            .map_err(|e| io::Error::other(format!("exit-node disable failed: {e:?}")))
    }

    fn exit_node_use(&self, use_command: ExitNodeUseCommand) -> io::Result<String> {
        self.0
            .use_exit_node(
                &use_command.target,
                use_command.tun_name.as_deref(),
                &use_command.excludes,
            )
            .map_err(|e| io::Error::other(format!("exit-node use failed: {e}")))
    }

    fn exit_node_clear(&self, clear: ExitNodeDisableCommand) -> io::Result<String> {
        self.0
            .clear_exit_node(clear.tun_name.as_deref())
            .map_err(|e| io::Error::other(format!("exit-node clear failed: {e:?}")))
    }

    fn traffic(&self) -> io::Result<TrafficSummary> {
        match self.0.current_runtime() {
            Ok(vnt) => Ok(crate::command::command_traffic(vnt.as_ref())),
            Err(_) => Ok(TrafficSummary::default()),
        }
    }

    fn resume_runtime(&self) -> io::Result<String> {
        self.0
            .resume_service_runtime()
            .map_err(|e| io::Error::other(format!("up runtime failed: {e:?}")))
    }

    fn down_runtime(&self) -> io::Result<String> {
        self.0
            .stop_service_runtime()
            .map_err(|e| io::Error::other(format!("down runtime failed: {e:?}")))
    }

    fn suspend_runtime(&self) -> io::Result<String> {
        self.0
            .suspend_service_runtime()
            .map_err(|e| io::Error::other(format!("suspend runtime failed: {e:?}")))
    }

    fn channel_change(&self, use_channel_type: UseChannelType) -> io::Result<String> {
        self.0.config.lock().unwrap().use_channel_type = use_channel_type;
        self.0.saved_config.lock().unwrap().use_channel = match use_channel_type {
            UseChannelType::Relay => "relay".to_string(),
            UseChannelType::P2p => "p2p".to_string(),
            UseChannelType::Auto => "auto".to_string(),
        };
        if let Ok(vnt) = self.0.current_runtime() {
            vnt.set_use_channel_type(use_channel_type);
        }
        self.0.persist_saved_config();
        Ok(format!(
            "channel policy changed to {}",
            match use_channel_type {
                UseChannelType::Relay => "relay",
                UseChannelType::P2p => "p2p",
                UseChannelType::Auto => "auto",
            }
        ))
    }

    fn rename(&self, new_name: &str) -> io::Result<String> {
        self.0
            .rename_device(new_name)
            .map_err(|e| io::Error::other(format!("rename failed: {e:?}")))
    }

    fn auth(&self, auth: AuthCommand) -> io::Result<String> {
        {
            let mut config = self.0.config.lock().unwrap();
            config.auth_user_id = Some(auth.user_id.clone());
            config.auth_group = Some(auth.group.clone());
            config.auth_ticket = Some(auth.ticket.clone());
        }
        {
            let mut saved_config = self.0.saved_config.lock().unwrap();
            saved_config.user_id = Some(auth.user_id.clone());
        }
        self.0.persist_saved_config();
        let vnt = self.0.current_runtime()?;
        vnt.request_device_auth(auth.user_id, auth.group, auth.ticket)
            .map(|_| "device auth request submitted to local service".to_string())
            .map_err(|e| io::Error::other(format!("auth failed: {e:?}")))
    }

    fn switch_user(&self, switch: SwitchCommand) -> io::Result<String> {
        self.0
            .switch_user(&switch.user_id)
            .map_err(|e| io::Error::other(format!("switch failed: {e:?}")))
    }
}

#[derive(Clone)]
struct ServiceCallback {
    manager: Weak<ServiceManager>,
}

impl ServiceCallback {
    fn new(manager: Weak<ServiceManager>) -> Self {
        Self { manager }
    }

    fn mutate_state<F>(&self, f: F)
    where
        F: FnOnce(&mut LocalServiceState),
    {
        if let Some(manager) = self.manager.upgrade() {
            manager.mutate_state(f);
        }
    }

    fn clear_error_state(&self) {
        self.mutate_state(|state| {
            state.runtime_starting = false;
            state.runtime_running = true;
            state.runtime_suspended = false;
            state.auth_pending = false;
            state.auth_message = None;
            state.last_error = None;
        });
    }

    fn is_auth_pending_error(info: &ErrorInfo) -> bool {
        info.code == ErrorType::AuthPending
    }

    fn request_runtime_stop(&self) {
        if let Some(manager) = self.manager.upgrade() {
            std::thread::spawn(move || {
                if let Err(e) = manager.stop_service_runtime() {
                    log::warn!("stop runtime after callback error failed: {:?}", e);
                }
            });
        }
    }

    fn request_data_plane_auth_block(&self, message: String) {
        if let Some(manager) = self.manager.upgrade() {
            std::thread::spawn(move || {
                manager.block_data_plane_for_auth_pending(&message);
            });
        }
    }

    fn request_exit_node_state_after_auth_reapply(&self) {
        if let Some(manager) = self.manager.upgrade() {
            std::thread::spawn(move || {
                manager.reapply_exit_node_state_after_auth();
            });
        }
    }

    fn request_persisted_name_refresh(&self, new_name: String) {
        if let Some(manager) = self.manager.upgrade() {
            std::thread::spawn(move || {
                manager.persist_device_name(new_name);
            });
        }
    }

    fn request_exit_node_client_state_reapply(&self) {
        if let Some(manager) = self.manager.upgrade() {
            std::thread::spawn(move || match manager.reapply_exit_node_client_routes() {
                Ok(Some(note)) => log::info!("{}", note),
                Ok(None) => {}
                Err(err) => log::warn!(
                    "failed to reapply exit-node client routes after TUN recreate: {:?}",
                    err
                ),
            });
        }
    }

    fn request_exit_node_client_exclude_refresh(&self, peer_ip: Ipv4Addr) {
        if let Some(manager) = self.manager.upgrade() {
            std::thread::spawn(move || {
                match manager.refresh_exit_node_client_route_excludes() {
                Ok(Some(note)) => log::info!(
                    "exit-node route excludes refreshed after direct route update for {}: {}",
                    peer_ip,
                    note
                ),
                Ok(None) => {}
                Err(err) => log::warn!(
                    "failed to refresh exit-node route excludes after direct route update for {}: {:?}",
                    peer_ip,
                    err
                ),
            }
            });
        }
    }
}

impl SdlCallback for ServiceCallback {
    fn success(&self) {
        self.clear_error_state();
        if let Some(manager) = self.manager.upgrade() {
            let current = manager.current_config();
            if current.auth_user_id.is_some() && current.auth_group.is_some() {
                manager.record_auth_success();
            }
        }
        println!(" {} ", style("====== Connect Successfully ======").green())
    }

    fn create_tun(&self, info: sdl::DeviceInfo) {
        self.request_exit_node_client_state_reapply();
        println!("create_tun {}", info)
    }

    fn connect(&self, info: ConnectInfo) {
        println!("connect {}", info)
    }

    fn handshake(&self, info: HandshakeInfo) -> bool {
        println!("handshake {}", info);
        true
    }

    fn register(&self, info: RegisterInfo) -> bool {
        self.clear_error_state();
        self.request_exit_node_state_after_auth_reapply();
        println!("register {}", style(info).green());
        true
    }

    fn direct_route_changed(&self, peer_ip: Ipv4Addr) {
        self.request_exit_node_client_exclude_refresh(peer_ip);
    }

    fn device_renamed(&self, new_name: String) {
        println!(
            "{}",
            style(format!(
                "device rename saved as {}; restart sdl-service to apply",
                new_name
            ))
            .green()
        );
        self.request_persisted_name_refresh(new_name);
    }

    fn error(&self, info: ErrorInfo) {
        let message = format!("{}", info);
        let auth_pending = Self::is_auth_pending_error(&info);
        if auth_pending {
            log::warn!("auth pending {:?}", info);
        } else {
            log::error!("error {:?}", info);
        }
        self.mutate_state(|state| {
            state.runtime_starting = false;
            state.runtime_running = true;
            state.runtime_suspended = false;
            state.auth_pending = auth_pending;
            state.auth_message = auth_pending.then_some(message.clone());
            state.last_error = (!auth_pending).then_some(message.clone());
        });
        if auth_pending {
            self.request_data_plane_auth_block(message.clone());
            println!(
                "{}",
                style(format!(
                    "auth pending: {}. run `sdl auth ...` to authenticate this device",
                    message
                ))
                .yellow()
            );
            return;
        }
        println!("{}", style(format!("error {}", info)).red());
        match info.code {
            ErrorType::TokenError
            | ErrorType::AddressExhausted
            | ErrorType::IpAlreadyExists
            | ErrorType::InvalidIp
            | ErrorType::LocalIpExists
            | ErrorType::FailedToCreateDevice => {
                self.request_runtime_stop();
            }
            _ => {}
        }
    }

    fn stop(&self) {
        self.mutate_state(|state| {
            state.runtime_starting = false;
            state.runtime_running = false;
            state.runtime_suspended = false;
        });
        println!("stopped");
    }
}

impl RunningService {
    pub(crate) fn start(config: Config, saved_config: FileConfig) -> Result<Self, i32> {
        if !root_check::is_app_elevated() {
            println!("Please run sdl-service with administrator or root privileges");
            return Err(1);
        }
        let service_lock = match crate::service_lock::acquire_service_lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::error!("failed to acquire service instance lock: {:?}", e);
                println!("{}", style(format!("Error {}", e)).red());
                return Err(1);
            }
        };
        let build_version = crate::build_version_string();
        println!("sdl-service version {}", build_version);
        log::info!("sdl-service version {}", build_version);
        log::info!(
            "acquired service instance lock at {}",
            service_lock.path().display()
        );
        let manager = Arc::new(ServiceManager::new(config.clone(), saved_config));
        manager.mutate_state(|state| {
            state.runtime_starting = true;
            state.runtime_running = false;
            state.runtime_suspended = false;
            state.auth_pending = false;
            state.auth_message = None;
            state.last_error = None;
        });
        #[cfg(feature = "port_mapping")]
        for (is_tcp, addr, dest) in config.port_mapping_list.iter() {
            if *is_tcp {
                println!("TCP port mapping {}->{}", addr, dest)
            } else {
                println!("UDP port mapping {}->{}", addr, dest)
            }
        }
        #[cfg(feature = "command")]
        {
            let manager_c = manager.clone();
            std::thread::Builder::new()
                .name("CommandServer".into())
                .spawn(move || {
                    if let Err(e) = CommandServer::new().start(ServiceCommandHandler(manager_c)) {
                        log::warn!("cmd:{:?}", e);
                    }
                })
                .expect("CommandServer");
        }

        {
            let manager_c = manager.clone();
            std::thread::Builder::new()
                .name("RuntimeStart".into())
                .spawn(move || {
                    // Keep the command server alive if runtime startup fails, so
                    // `sdl status` can surface the error and `sdl up` can retry.
                    if let Err(e) = manager_c
                        .clone()
                        .resume_service_runtime()
                        .context("initial service start failed")
                    {
                        log::error!("sdl create error {:?}", e);
                        println!("error: {:?}", e);
                        manager_c.mutate_state(|state| {
                            state.runtime_starting = false;
                            state.runtime_running = false;
                            state.runtime_suspended = false;
                            state.last_error = Some(format!("{e:?}"));
                        });
                    }
                })
                .expect("RuntimeStart");
        }

        Ok(Self {
            manager,
            _service_lock: service_lock,
        })
    }

    pub(crate) fn shutdown(self) {
        self.manager.shutdown();
    }
}

pub fn run_service_process(args: Vec<String>) -> i32 {
    #[cfg(target_os = "windows")]
    {
        return crate::windows_service::run_service_process(args);
    }
    #[cfg(not(target_os = "windows"))]
    {
        run_service_from_args(args)
    }
}

pub fn run_service_from_args(args: Vec<String>) -> i32 {
    if let Err(e) = crate::cli::ensure_service_device_key_path() {
        log::error!("prepare device key path failed: {:?}", e);
        println!("{}", style(format!("Error {:?}", e)).red());
        return 1;
    }
    let (config, saved_config) = match crate::cli::parse_args_config_from(args) {
        Ok(rs) => match rs {
            Some(rs) => rs,
            None => return 0,
        },
        Err(e) => {
            log::error!("parse error={:?}", e);
            println!("{}", style(format!("Error {:?}", e)).red());
            return 1;
        }
    };
    run_service(config, saved_config)
}

pub(crate) fn run_service_with_shutdown(
    config: Config,
    saved_config: FileConfig,
    shutdown_receiver: std::sync::mpsc::Receiver<()>,
) -> i32 {
    if let Err(e) = write_saved_config(&saved_config) {
        log::warn!("write saved config at service start failed: {:?}", e);
    }
    let running_service = match RunningService::start(config, saved_config) {
        Ok(running_service) => running_service,
        Err(code) => return code,
    };
    let _ = shutdown_receiver.recv();
    running_service.shutdown();
    0
}

pub fn run_service(config: Config, saved_config: FileConfig) -> i32 {
    let (_shutdown_sender, shutdown_receiver) = std::sync::mpsc::channel::<()>();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let shutdown_sender = _shutdown_sender.clone();
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ])
        .unwrap();
        let handle = signals.handle();
        std::thread::spawn(move || {
            for sig in signals.forever() {
                match sig {
                    signal_hook::consts::SIGINT | signal_hook::consts::SIGTERM => {
                        println!("Received SIGINT, {}", sig);
                        let _ = shutdown_sender.send(());
                        handle.close();
                        break;
                    }
                    _ => {}
                }
            }
        });
    }

    run_service_with_shutdown(config, saved_config, shutdown_receiver)
}
