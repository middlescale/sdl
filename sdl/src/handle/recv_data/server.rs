use anyhow::anyhow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;
use sdl_packet::icmp::{icmp, Kind};
use sdl_packet::ip::ipv4;
use sdl_packet::ip::ipv4::packet::IpV4Packet;

use crate::core::SdlRuntime;
use crate::data_plane::route::{Route, RouteKey};
use crate::handle::callback::{ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, SdlCallback};
use crate::handle::recv_data::PacketHandler;
use crate::handle::{ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::punch::{NatInfo, NatType, PunchModel};
use crate::proto::message::{
    DebugCollectRequest, DebugCollectResponse, DebugWatchStartRequest, DebugWatchStartResponse,
    DebugWatchStopRequest, DebugWatchStopResponse, DeviceAuthAck, DeviceAuthChallenge,
    DeviceAuthErrorReason, DeviceList, DeviceRenameResponse, DnsQueryResponse, GatewayConnectAck,
    HandshakeResponse, PunchAck, PunchEndpoint, PunchResult, PunchResultCode, PunchSessionPhase,
    PunchStart, RefreshGatewayGrantResponse, RefreshGatewayGrantResult, RegistrationErrorReason,
    RegistrationResponse,
};
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::{ip_turn_packet, service_packet, NetPacket, Protocol};
use crate::tun_tap_device::vnt_device::write_full_device;
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::icmp_debug::parse_icmp_echo_meta;
use crate::{proto, DnsProfile, PeerClientInfo};

const CAPABILITY_UDP_ENDPOINT_REPORT_V1: &str = "udp_endpoint_report_v1";
static UNAUTHORIZED_SERVER_SOURCE_DROP_COUNT: AtomicU64 = AtomicU64::new(0);
static UNAUTHORIZED_SERVER_SOURCE_DROP_LOG_LIMITER: OnceLock<
    crate::util::limit::ConcurrentRateLimiter,
> = OnceLock::new();

fn log_sampled_unauthorized_server_source_drop(route_key: RouteKey, control_addr: SocketAddr) {
    let count = UNAUTHORIZED_SERVER_SOURCE_DROP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if UNAUTHORIZED_SERVER_SOURCE_DROP_LOG_LIMITER
        .get_or_init(|| crate::util::limit::ConcurrentRateLimiter::new(1, 1))
        .try_acquire()
    {
        let sampled = UNAUTHORIZED_SERVER_SOURCE_DROP_COUNT.swap(0, Ordering::Relaxed);
        let total = sampled.max(count);
        log::debug!(
            "dropping packets from unauthorized control/gateway source (sample route_key={:?}, control_addr={}, count={})",
            route_key,
            control_addr,
            total
        );
    }
}

/// 处理来源于服务端的包
#[derive(Clone)]
pub struct ServerPacketHandler<Call, Device> {
    runtime: Arc<SdlRuntime>,
    device: Device,
    callback: Call,
    punch_active_sessions: Arc<Mutex<HashMap<Ipv4Addr, ActivePunchState>>>,
    // Keep device-list commit/apply in order with other peer_state epoch mutators.
    device_list_update_lock: Arc<Mutex<()>>,
    device_auth_ok: Arc<AtomicCell<bool>>,
}

#[derive(Copy, Clone)]
struct ActivePunchSession {
    session_id: u64,
    source: u32,
    target: u32,
    attempt: u32,
    deadline_unix_ms: i64,
}

#[derive(Clone)]
struct ActivePunchState {
    active: ActivePunchSession,
    coalesced: Vec<ActivePunchSession>,
}

struct DeviceListUpdate {
    previous_peers: HashMap<Ipv4Addr, PeerDeviceInfo>,
    ip_list: Vec<PeerDeviceInfo>,
}

impl ActivePunchState {
    fn new(active: ActivePunchSession) -> Self {
        Self {
            active,
            coalesced: Vec::new(),
        }
    }

    fn contains(&self, session_id: u64, attempt: u32) -> bool {
        self.active.session_id == session_id && self.active.attempt == attempt
            || self
                .coalesced
                .iter()
                .any(|session| session.session_id == session_id && session.attempt == attempt)
    }

    fn coalesce(&mut self, session: ActivePunchSession) {
        if self.contains(session.session_id, session.attempt) {
            self.active.deadline_unix_ms =
                self.active.deadline_unix_ms.max(session.deadline_unix_ms);
            return;
        }
        self.active.deadline_unix_ms = self.active.deadline_unix_ms.max(session.deadline_unix_ms);
        self.coalesced.push(session);
    }

    fn sessions(&self) -> Vec<ActivePunchSession> {
        let mut sessions = Vec::with_capacity(1 + self.coalesced.len());
        sessions.push(self.active);
        sessions.extend(self.coalesced.iter().copied());
        sessions
    }

    fn deadline_unix_ms(&self) -> i64 {
        self.active.deadline_unix_ms
    }
}

impl<Call, Device> ServerPacketHandler<Call, Device> {
    pub fn new(runtime: Arc<SdlRuntime>, device: Device, callback: Call) -> Self {
        Self {
            runtime,
            device,
            callback,
            punch_active_sessions: Arc::new(Mutex::new(HashMap::new())),
            device_list_update_lock: Arc::new(Mutex::new(())),
            device_auth_ok: Arc::new(AtomicCell::new(false)),
        }
    }
}

impl<Call: SdlCallback, Device: DeviceWrite> PacketHandler for ServerPacketHandler<Call, Device> {
    fn handle(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        _extend: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        if !self.runtime.control_session.is_control_addr(route_key.addr)
            && !self
                .runtime
                .gateway_sessions
                .is_gateway_addr(route_key.addr)
        {
            log_sampled_unauthorized_server_source_drop(
                route_key,
                self.runtime.control_session.server_addr(),
            );
            return Ok(());
        }
        self.runtime
            .route_manager()
            .touch_path(&net_packet.source(), &route_key);
        self.reconcile_punch_sessions(current_device)?;
        if net_packet.protocol() == Protocol::Error
            && net_packet.transport_protocol()
                == Into::<u8>::into(crate::protocol::error_packet::Protocol::NoKey)
        {
            return Ok(());
        } else if net_packet.protocol() == Protocol::Service
            && net_packet.transport_protocol()
                == Into::<u8>::into(service_packet::Protocol::HandshakeResponse)
        {
            let response = HandshakeResponse::parse_from_bytes(net_packet.payload())
                .map_err(|e| anyhow!("HandshakeResponse {:?}", e))?;
            log::info!("握手响应:{:?},{}", route_key, response);
            if !response
                .capabilities
                .iter()
                .any(|item| item == CAPABILITY_UDP_ENDPOINT_REPORT_V1)
            {
                return Err(anyhow!(
                    "control missing required capability {}",
                    CAPABILITY_UDP_ENDPOINT_REPORT_V1
                ));
            }
            self.runtime
                .control_session
                .set_negotiated_capabilities(&response.capabilities);
            let handshake_info =
                HandshakeInfo::new_no_secret(response.version, response.capabilities);
            if self.callback.handshake(handshake_info) {
                //没有加密，则发送注册请求
                self.register(current_device, route_key, false)?;
            }

            return Ok(());
        }
        match net_packet.protocol() {
            Protocol::Service => {
                self.service(current_device, net_packet, route_key)?;
            }
            Protocol::Error => {
                self.error(current_device, net_packet, route_key)?;
            }
            Protocol::Control => {
                self.control(current_device, net_packet, route_key)?;
            }
            Protocol::IpTurn => {
                match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                    ip_turn_packet::Protocol::Ipv4 => {
                        let source = net_packet.source();
                        let destination = net_packet.destination();
                        let from_gateway = self
                            .runtime
                            .gateway_sessions
                            .is_gateway_addr(route_key.addr);
                        let from_gateway_peer =
                            is_gateway_peer_ipturn_source(source, current_device, from_gateway);
                        let mut gateway_echo_reply = None;
                        let mut peer_echo_reply = None;
                        let mut echo_meta = None;
                        {
                            let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
                            if ipv4.protocol() == ipv4::protocol::Protocol::Icmp
                                && ipv4.destination_ip() == destination
                            {
                                let icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
                                echo_meta = parse_icmp_echo_meta(&icmp_packet);
                                if from_gateway_peer && icmp_packet.kind() == Kind::EchoRequest {
                                    drop(icmp_packet);
                                    drop(ipv4);
                                    rewrite_peer_echo_request_as_reply(
                                        &mut net_packet,
                                        source,
                                        destination,
                                    )?;
                                    self.send_gateway_reply(&net_packet, current_device)?;
                                    return Ok(());
                                }
                                if icmp_packet.kind() == Kind::EchoReply {
                                    if source == current_device.virtual_gateway {
                                        gateway_echo_reply =
                                            Some((ipv4.source_ip(), ipv4.destination_ip()));
                                    } else if from_gateway_peer {
                                        peer_echo_reply =
                                            Some((ipv4.source_ip(), ipv4.destination_ip()));
                                    }
                                }
                            }
                        }
                        if let Some((icmp_source, icmp_destination)) = gateway_echo_reply {
                            self.runtime.debug_watch.emit(
                                "icmp",
                                "gateway_echo_reply_received",
                                serde_json::json!({
                                    "src": icmp_source.to_string(),
                                    "dst": icmp_destination.to_string(),
                                    "via": route_key.addr.to_string(),
                                    "bytes": net_packet.payload().len(),
                                    "icmp_kind": echo_meta.map(|meta| meta.kind_label()),
                                    "icmp_id": echo_meta.map(|meta| meta.identifier),
                                    "icmp_seq": echo_meta.map(|meta| meta.sequence),
                                    "icmp_checksum_valid": echo_meta.map(|meta| meta.checksum_valid),
                                }),
                            );
                            let written = write_full_device(
                                &self.device,
                                net_packet.payload(),
                                "gateway ip packet inject",
                            )?;
                            self.runtime.debug_watch.emit(
                                "icmp",
                                "gateway_echo_reply_injected",
                                serde_json::json!({
                                    "src": icmp_source.to_string(),
                                    "dst": icmp_destination.to_string(),
                                    "written_bytes": written,
                                    "icmp_kind": echo_meta.map(|meta| meta.kind_label()),
                                    "icmp_id": echo_meta.map(|meta| meta.identifier),
                                    "icmp_seq": echo_meta.map(|meta| meta.sequence),
                                    "icmp_checksum_valid": echo_meta.map(|meta| meta.checksum_valid),
                                }),
                            );
                            return Ok(());
                        }
                        if from_gateway_peer {
                            if let Some((icmp_source, icmp_destination)) = peer_echo_reply {
                                self.runtime.debug_watch.emit(
                                    "icmp",
                                    "peer_echo_reply_received",
                                    serde_json::json!({
                                        "src": icmp_source.to_string(),
                                        "dst": icmp_destination.to_string(),
                                        "via": route_key.addr.to_string(),
                                        "bytes": net_packet.payload().len(),
                                        "icmp_kind": echo_meta.map(|meta| meta.kind_label()),
                                        "icmp_id": echo_meta.map(|meta| meta.identifier),
                                        "icmp_seq": echo_meta.map(|meta| meta.sequence),
                                        "icmp_checksum_valid": echo_meta.map(|meta| meta.checksum_valid),
                                    }),
                                );
                            }
                            let written = write_full_device(
                                &self.device,
                                net_packet.payload(),
                                "gateway peer ip packet inject",
                            )?;
                            if let Some((icmp_source, icmp_destination)) = peer_echo_reply {
                                self.runtime.debug_watch.emit(
                                    "icmp",
                                    "peer_echo_reply_injected",
                                    serde_json::json!({
                                        "src": icmp_source.to_string(),
                                        "dst": icmp_destination.to_string(),
                                        "written_bytes": written,
                                        "icmp_kind": echo_meta.map(|meta| meta.kind_label()),
                                        "icmp_id": echo_meta.map(|meta| meta.identifier),
                                        "icmp_seq": echo_meta.map(|meta| meta.sequence),
                                        "icmp_checksum_valid": echo_meta.map(|meta| meta.checksum_valid),
                                    }),
                                );
                            }
                            return Ok(());
                        }
                    }
                    ip_turn_packet::Protocol::WGIpv4 => {}
                    ip_turn_packet::Protocol::Ipv4Broadcast => {}
                    ip_turn_packet::Protocol::Unknown(_) => {}
                }
            }
            Protocol::OtherTurn => {}
            Protocol::Unknown(_) => {}
        }
        Ok(())
    }
}

impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    fn send_gateway_reply<B: AsRef<[u8]>>(
        &self,
        packet: &NetPacket<B>,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        let packet_len = packet.buffer().len();
        let destination = packet.destination();
        self.runtime.data_plane_stats.record_logical_up(packet_len);
        self.runtime.gateway_sessions.send_relay(packet)?;
        self.runtime.data_plane_stats.record_gateway_up(packet_len);
        if destination != current_device.virtual_gateway {
            self.runtime
                .data_plane_stats
                .record_peer_up(destination, packet_len);
        }
        Ok(())
    }

    fn peer_identity_key(peer: &PeerDeviceInfo) -> Vec<u8> {
        if !peer.device_id.is_empty() {
            return format!("id:{}", peer.device_id).into_bytes();
        }
        let mut key = Vec::with_capacity(peer.device_pub_key.len() + 3);
        key.extend_from_slice(b"pk:");
        key.extend_from_slice(&peer.device_pub_key);
        key
    }

    fn apply_gateway_grants(
        &self,
        grants: &[proto::message::GatewayAccessGrant],
        legacy_grant: Option<&proto::message::GatewayAccessGrant>,
        gateway_policy_rev: u64,
        virtual_ip: Ipv4Addr,
    ) {
        let effective_grants = collect_gateway_grants(grants, legacy_grant);
        let incoming_policy_rev =
            effective_gateway_policy_rev(gateway_policy_rev, &effective_grants, legacy_grant);
        let current_policy_rev = self
            .runtime
            .gateway_grant_policy_rev
            .load(Ordering::Relaxed);
        if !should_apply_gateway_policy_rev(current_policy_rev, incoming_policy_rev) {
            log::info!(
                "ignore stale gateway grants: current_policy_rev={}, incoming_policy_rev={}",
                current_policy_rev,
                incoming_policy_rev
            );
            return;
        }
        if effective_grants.is_empty() {
            if self
                .runtime
                .gateway_sessions
                .current_grant_snapshot()
                .is_some()
            {
                self.runtime
                    .gateway_grant_policy_rev
                    .store(incoming_policy_rev, Ordering::Relaxed);
                log::warn!(
                    "gateway grant update omitted grants; retaining cached gateway grant policy_rev={}",
                    incoming_policy_rev
                );
                return;
            }
            self.runtime.gateway_sessions.clear_gateway_grant();
            self.runtime
                .gateway_grant_policy_rev
                .store(incoming_policy_rev, Ordering::Relaxed);
            log::info!("gateway grant cleared");
            return;
        }
        self.runtime.gateway_sessions.set_gateway_grants(
            &effective_grants,
            virtual_ip,
            self.runtime.config.device_id.clone(),
        );
        self.runtime
            .gateway_grant_policy_rev
            .store(incoming_policy_rev, Ordering::Relaxed);
        log::info!(
            "gateway grants applied policy_rev={} count={} gateways={:?}",
            incoming_policy_rev,
            effective_grants.len(),
            effective_grants
                .iter()
                .map(|grant| grant.gateway_id.clone())
                .collect::<Vec<_>>()
        );
    }

    fn prepare_device_list_update(
        &self,
        device_info_list: Vec<proto::message::DeviceInfo>,
        epoch: u16,
    ) -> Option<DeviceListUpdate> {
        let ip_list: Vec<PeerDeviceInfo> = device_info_list
            .into_iter()
            .map(|info| {
                PeerDeviceInfo::new(
                    Ipv4Addr::from(info.virtual_ip),
                    info.name,
                    info.device_status as u8,
                    info.device_id,
                    info.device_pub_key,
                    info.online_kx_pub,
                    info.preferred_channel_mode.enum_value_or_default(),
                    info.exit_node_advertised,
                    info.exit_node_approved,
                    info.exit_node_usable,
                )
            })
            .collect();
        let next_devices: HashMap<Ipv4Addr, PeerDeviceInfo> = ip_list
            .iter()
            .cloned()
            .map(|peer| (peer.virtual_ip, peer))
            .collect();
        let previous_peers = {
            let mut peer_state = self.runtime.peer_state.lock();
            let current_epoch = peer_state.epoch;
            let Some(previous_peers) =
                try_commit_device_list_state(&mut peer_state, epoch, next_devices)
            else {
                log::info!(
                    "ignore stale device list: current_epoch={}, incoming_epoch={}",
                    current_epoch,
                    epoch
                );
                return None;
            };
            previous_peers
        };
        Some(DeviceListUpdate {
            previous_peers,
            ip_list,
        })
    }

    fn reconcile_punch_sessions(&self, current_device: &CurrentDeviceInfo) -> anyhow::Result<()> {
        let now_ms = crate::handle::now_time() as i64;
        let mut succeeded = Vec::new();
        let mut expired = Vec::new();
        {
            let mut sessions = self.punch_active_sessions.lock();
            sessions.retain(|peer_ip, state| {
                if self.runtime.route_manager().direct_path_count(peer_ip) > 0 {
                    succeeded.push(state.sessions());
                    return false;
                }
                if state.deadline_unix_ms() > 0 && now_ms > state.deadline_unix_ms() {
                    expired.push(state.sessions());
                    false
                } else {
                    true
                }
            });
        }
        for sessions in succeeded {
            self.send_punch_results(
                current_device,
                &sessions,
                PunchResultCode::PunchResultSuccess,
                "p2p route established",
            )?;
        }
        for sessions in expired {
            self.send_punch_results(
                current_device,
                &sessions,
                PunchResultCode::PunchResultNoResponse,
                "deadline exceeded",
            )?;
        }
        Ok(())
    }

    fn send_service_packet(
        &self,
        _current_device: &CurrentDeviceInfo,
        transport: service_packet::Protocol,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        self.runtime
            .control_session
            .send_service_payload(transport, payload)?;
        Ok(())
    }

    fn send_punch_result(
        &self,
        current_device: &CurrentDeviceInfo,
        session_id: u64,
        source: u32,
        target: u32,
        attempt: u32,
        code: PunchResultCode,
        reason: &str,
    ) -> anyhow::Result<()> {
        let _ = current_device;
        let selected_endpoint = selected_endpoint_for_result(
            code,
            self.runtime
                .route_manager()
                .direct_route(&Ipv4Addr::from(target)),
        );
        log::info!(
            "sending PunchResult session_id={} source={} target={} attempt={} code={:?} reason={} selected_endpoint={}",
            session_id,
            Ipv4Addr::from(source),
            Ipv4Addr::from(target),
            attempt,
            code,
            reason,
            format_punch_endpoint(selected_endpoint.as_ref())
        );
        send_punch_result_via_control(
            &self.runtime.control_session,
            session_id,
            source,
            target,
            attempt,
            code,
            reason,
            selected_endpoint,
        )
    }

    fn send_punch_results(
        &self,
        current_device: &CurrentDeviceInfo,
        sessions: &[ActivePunchSession],
        code: PunchResultCode,
        reason: &str,
    ) -> anyhow::Result<()> {
        for session in sessions {
            self.send_punch_result(
                current_device,
                session.session_id,
                session.source,
                session.target,
                session.attempt,
                code,
                reason,
            )?;
        }
        Ok(())
    }

    fn spawn_punch_session_watchdog(&self, peer_ip: Ipv4Addr, session: ActivePunchSession) {
        let runtime = self.runtime.clone();
        let sessions = self.punch_active_sessions.clone();
        thread::Builder::new()
            .name(format!("punchWatchdog-{peer_ip}"))
            .spawn(move || loop {
                let now_ms = crate::handle::now_time() as i64;
                let outcome = {
                    let mut guard = sessions.lock();
                    let Some(state) = guard.get(&peer_ip) else {
                        return;
                    };
                    if state.active.session_id != session.session_id
                        || state.active.attempt != session.attempt
                    {
                        return;
                    }
                    if runtime.route_manager().direct_path_count(&peer_ip) > 0 {
                        let state = guard.remove(&peer_ip).expect("active punch state");
                        Some((
                            state.sessions(),
                            PunchResultCode::PunchResultSuccess,
                            "p2p route established",
                        ))
                    } else if state.deadline_unix_ms() > 0 && now_ms > state.deadline_unix_ms() {
                        let state = guard.remove(&peer_ip).expect("active punch state");
                        Some((
                            state.sessions(),
                            PunchResultCode::PunchResultNoResponse,
                            "deadline exceeded",
                        ))
                    } else {
                        None
                    }
                };
                if let Some((sessions, code, reason)) = outcome {
                    log::info!(
                        "punch watchdog outcome peer={} session_id={} attempt={} coalesced_sessions={} code={:?} reason={}",
                        peer_ip,
                        session.session_id,
                        session.attempt,
                        sessions.len(),
                        code,
                        reason
                    );
                    runtime.debug_watch.emit(
                        "punch",
                        "watchdog_outcome",
                        serde_json::json!({
                            "peer_ip": peer_ip.to_string(),
                            "session_id": session.session_id,
                            "attempt": session.attempt,
                            "code": format!("{:?}", code),
                            "reason": reason,
                        }),
                    );
                    let selected_endpoint =
                        selected_endpoint_for_result(code, runtime.route_manager().direct_route(&peer_ip));
                    for punch_session in sessions {
                        if let Err(err) = send_punch_result_via_control(
                            &runtime.control_session,
                            punch_session.session_id,
                            punch_session.source,
                            punch_session.target,
                            punch_session.attempt,
                            code,
                            reason,
                            selected_endpoint.clone(),
                        ) {
                            log::warn!(
                                "send punch result from watchdog failed peer={} session_id={} attempt={} err={:?}",
                                peer_ip,
                                punch_session.session_id,
                                punch_session.attempt,
                                err
                            );
                        }
                    }
                    return;
                }
                let sleep = if session.deadline_unix_ms > 0 {
                    let remaining = {
                        let guard = sessions.lock();
                        guard
                            .get(&peer_ip)
                            .map(|state| state.deadline_unix_ms())
                            .unwrap_or(session.deadline_unix_ms)
                    }
                    .saturating_sub(now_ms) as u64;
                    Duration::from_millis(remaining.clamp(1, 200))
                } else {
                    Duration::from_millis(200)
                };
                thread::sleep(sleep);
            })
            .expect("punch watchdog");
    }

    fn service(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        match service_packet::Protocol::from(net_packet.transport_protocol()) {
            service_packet::Protocol::RegistrationResponse => {
                let response = RegistrationResponse::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("RegistrationResponse {:?}", e)))?;
                if response.error_code != 0 {
                    let reason = if response.error_message.is_empty() {
                        "registration rejected by control".to_string()
                    } else {
                        response.error_message.clone()
                    };
                    self.callback.error(ErrorInfo::new_msg(
                        ErrorType::Unknown,
                        format!(
                            "registration rejected: code={}, reason={}",
                            response.error_code, reason
                        ),
                    ));
                    if should_retry_registration_with_fresh_handshake(
                        response.error_code,
                        response.error_reason.enum_value_or_default(),
                        &reason,
                    ) {
                        match self
                            .runtime
                            .control_session
                            .try_send_registration_reject_recovery_handshake()
                        {
                            Ok(true) => {
                                log::warn!(
                                    "registration rejected due to stale/missing handshake state, requesting fresh handshake before retry: code={}, route={:?}, reason={}",
                                    response.error_code,
                                    route_key,
                                    reason
                                );
                            }
                            Ok(false) => {
                                log::debug!(
                                    "registration reject recovery handshake suppressed by cooldown: code={}, route={:?}, reason={}",
                                    response.error_code,
                                    route_key,
                                    reason
                                );
                            }
                            Err(err) => {
                                log::warn!(
                                    "fresh handshake request after registration reject failed: {:?}",
                                    err
                                );
                            }
                        }
                    }
                    return Ok(());
                }
                let virtual_ip = Ipv4Addr::from(response.virtual_ip);
                let virtual_netmask = Ipv4Addr::from(response.virtual_netmask);
                let virtual_gateway = Ipv4Addr::from(response.virtual_gateway);
                #[cfg_attr(feature = "integrated_tun", allow(unused_variables))]
                let virtual_network =
                    Ipv4Addr::from(response.virtual_ip & response.virtual_netmask);
                let register_info = RegisterInfo::new(virtual_ip, virtual_netmask, virtual_gateway);
                log::info!("注册成功：{:?}", register_info);
                let _device_list_update_guard = self.device_list_update_lock.lock();
                let Some(device_list_update) = self.prepare_device_list_update(
                    response.device_info_list.clone(),
                    response.epoch as _,
                ) else {
                    log::info!(
                        "ignore stale registration response: virtual_ip={}, epoch={}",
                        virtual_ip,
                        response.epoch
                    );
                    return Ok(());
                };
                self.apply_gateway_grants(
                    &response.gateway_access_grants,
                    response.gateway_access_grant.as_ref(),
                    response.gateway_policy_rev,
                    virtual_ip,
                );
                let dns_profile = response.dns_profile.as_ref().map(|profile| DnsProfile {
                    servers: profile.servers.clone(),
                    match_domains: profile.match_domains.clone(),
                });
                if self.callback.register(register_info) {
                    let route = Route::from_default_rt(route_key, 1);
                    self.runtime
                        .route_manager()
                        .add_path_if_absent(virtual_gateway, route);
                    let public_ip = response.public_ip.into();
                    let public_port = response.public_port as u16;
                    let observed_udp_port =
                        observed_udp_port_from_registration(route_key.protocol(), public_port);
                    // For QUIC/TCP control, the observed remote port belongs to the control-plane
                    // connection, not the data-plane UDP socket used for punching.
                    self.runtime
                        .nat_test
                        .update_addr(public_ip, observed_udp_port);
                    let old = current_device;
                    let dns_changed = self.runtime.replace_dns_profile(dns_profile);
                    let vip_changed = old.virtual_ip != virtual_ip
                        || old.virtual_gateway != virtual_gateway
                        || old.virtual_netmask != virtual_netmask;
                    let mut cur = *current_device;
                    loop {
                        let mut new_current_device = cur;
                        new_current_device.update(virtual_ip, virtual_netmask, virtual_gateway);
                        new_current_device.virtual_ip = virtual_ip;
                        new_current_device.virtual_netmask = virtual_netmask;
                        new_current_device.virtual_gateway = virtual_gateway;
                        new_current_device.status = ConnectStatus::Connected;
                        if let Err(c) = self
                            .runtime
                            .current_device
                            .compare_exchange(cur, new_current_device)
                        {
                            cur = c;
                        } else {
                            break;
                        }
                    }
                    self.runtime.gateway_sessions.trigger_connect_now();

                    if vip_changed || dns_changed {
                        if old.virtual_ip != Ipv4Addr::UNSPECIFIED {
                            log::info!("ip发生变化,old:{:?},response={:?}", old, response);
                        }
                        #[cfg(not(feature = "integrated_tun"))]
                        {
                            let device_config = crate::handle::callback::DeviceConfig::new(
                                #[cfg(any(
                                    target_os = "windows",
                                    target_os = "linux",
                                    target_os = "macos"
                                ))]
                                self.runtime.config.device_name.clone(),
                                self.runtime.config.mtu,
                                virtual_ip,
                                virtual_netmask,
                                virtual_gateway,
                                virtual_network,
                            );
                            self.callback.create_device(device_config);
                        }
                        #[cfg(feature = "integrated_tun")]
                        {
                            if let Err(e) =
                                self.runtime.sync_tun_with_current_device(&self.callback)
                            {
                                log::error!("{:?}", e);
                                self.callback.error(ErrorInfo::new_msg(
                                    ErrorType::FailedToCreateDevice,
                                    format!("{:?}", e),
                                ));
                            }
                        }
                    } else if old.status.offline() {
                        #[cfg(feature = "integrated_tun")]
                        self.runtime.force_apply_dns_profile(&self.callback);
                    }
                    self.set_device_info_list(device_list_update);
                    if vip_changed {
                        // apply_gateway_grants() may have kicked the gateway session while
                        // current_device still held the old/unspecified VIP; trigger again
                        // only when the virtual addressing actually changed so wake/reconnect
                        // paths use the committed VIP without adding an extra round for
                        // unchanged registrations.
                        self.runtime.gateway_sessions.trigger_connect_now();
                    }
                    self.runtime
                        .control_session
                        .request_punch_status_report_with_nat_ready(if old.status.offline() {
                            crate::proto::message::PunchTriggerReason::PunchTriggerReconnectRecovery
                        } else {
                            crate::proto::message::PunchTriggerReason::PunchTriggerStatusUpdate
                        });
                    if should_refresh_gateway_grant_after_registration(
                        old.status.offline(),
                        has_gateway_grants(
                            &response.gateway_access_grants,
                            response.gateway_access_grant.as_ref(),
                        ),
                    ) {
                        match self
                            .runtime
                            .control_session
                            .send_refresh_gateway_grant_request(
                                &self.runtime.gateway_sessions,
                                false,
                            ) {
                            Ok(_) => {
                                log::info!(
                                    "registration recovered from offline without gateway grant, requested dedicated gateway grant refresh"
                                );
                            }
                            Err(e) => {
                                log::warn!(
                                    "registration recovered from offline but gateway grant refresh failed: {:?}",
                                    e
                                );
                            }
                        }
                    }
                    if old.status.offline() {
                        self.callback.success();
                    }
                }
            }
            service_packet::Protocol::PushDeviceList => {
                let response = DeviceList::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("PushDeviceList {:?}", e)))?;
                let _device_list_update_guard = self.device_list_update_lock.lock();
                let device_list_update =
                    self.prepare_device_list_update(response.device_info_list, response.epoch as _);
                self.apply_gateway_grants(
                    &response.gateway_access_grants,
                    None,
                    response.gateway_policy_rev,
                    current_device.virtual_ip,
                );
                if device_list_update.is_none() {
                    log::info!(
                        "skip stale push device list peer update: epoch={}",
                        response.epoch
                    );
                }
                let Some(device_list_update) = device_list_update else {
                    return Ok(());
                };
                self.set_device_info_list(device_list_update);
                self.runtime.control_session.report_client_status();
            }
            service_packet::Protocol::DeviceAuthAck => {
                let ack = DeviceAuthAck::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("DeviceAuthAck {:?}", e)))?;
                if !ack.ok {
                    println!("auth device failed: {}", ack.reason);
                    self.callback.error(ErrorInfo::new_msg(
                        ErrorType::Unknown,
                        format!("auth device failed: {}", ack.reason),
                    ));
                    if should_retry_device_auth_after_challenge_expired(
                        ack.error_reason.enum_value_or_default(),
                        &ack.reason,
                    ) {
                        match self
                            .runtime
                            .control_session
                            .try_retry_device_auth_after_challenge_expired()
                        {
                            Ok(true) => {
                                log::warn!(
                                    "device auth challenge expired, retrying auth request with cooldown: route={:?}, reason={}",
                                    route_key,
                                    ack.reason
                                );
                            }
                            Ok(false) => {
                                log::debug!(
                                    "device auth retry suppressed by cooldown: route={:?}, reason={}",
                                    route_key,
                                    ack.reason
                                );
                            }
                            Err(err) => {
                                log::warn!(
                                    "device auth retry after challenge_expired failed: {:?}",
                                    err
                                );
                            }
                        }
                    }
                    return Ok(());
                }
                self.device_auth_ok.store(true);
                println!(
                    "auth device success: user={} group={} device={}",
                    ack.user_id, ack.group, ack.device_id
                );
                self.callback.success();
                self.register(current_device, route_key, true)?;
            }
            service_packet::Protocol::DeviceAuthChallenge => {
                let challenge = DeviceAuthChallenge::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("DeviceAuthChallenge {:?}", e)))?;
                self.runtime
                    .control_session
                    .send_device_auth_proof(&challenge)?;
            }
            service_packet::Protocol::DeviceRenameResponse => {
                let response = DeviceRenameResponse::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("DeviceRenameResponse {:?}", e)))?;
                let result = if response.ok {
                    if response.pending_approval {
                        Ok(crate::core::RenameRequestOutcome::RestartRequired(
                            response.applied_name.clone(),
                        ))
                    } else {
                        Ok(crate::core::RenameRequestOutcome::Applied(
                            response.applied_name.clone(),
                        ))
                    }
                } else {
                    Err(response.reason.clone())
                };
                if !self
                    .runtime
                    .complete_rename_request(response.request_id, result)
                {
                    if response.ok
                        && !response.pending_approval
                        && !response.applied_name.is_empty()
                    {
                        log::info!(
                            "apply async device rename request_id={} applied_name={}",
                            response.request_id,
                            response.applied_name
                        );
                        self.callback.device_renamed(response.applied_name.clone());
                    } else {
                        log::debug!(
                            "drop rename response for unknown request_id={}",
                            response.request_id
                        );
                    }
                }
            }
            service_packet::Protocol::DebugCollectRequest => {
                let request = DebugCollectRequest::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("DebugCollectRequest {:?}", e)))?;
                log::info!(
                    "received debug collect request request_id={} sections={:?} reason={}",
                    request.request_id,
                    request.sections,
                    request.reason
                );
                let mut response = DebugCollectResponse::new();
                response.request_id = request.request_id;
                response.collected_at_unix_ms = crate::handle::now_time() as i64;
                match self.runtime.debug_snapshot_json(&request.sections) {
                    Ok(snapshot_json) => {
                        response.ok = true;
                        response.snapshot_json = snapshot_json;
                    }
                    Err(err) => {
                        log::warn!(
                            "debug collect failed request_id={} err={:?}",
                            request.request_id,
                            err
                        );
                        response.ok = false;
                        response.reason = err.to_string();
                    }
                }
                let bytes = response
                    .write_to_bytes()
                    .map_err(|e| io::Error::other(format!("DebugCollectResponse {:?}", e)))?;
                self.send_service_packet(
                    current_device,
                    service_packet::Protocol::DebugCollectResponse,
                    &bytes,
                )?;
            }
            service_packet::Protocol::DebugWatchStartRequest => {
                let request = DebugWatchStartRequest::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("DebugWatchStartRequest {:?}", e)))?;
                let (started_at_unix_ms, expire_at_unix_ms) = self.runtime.debug_watch.start(
                    request.request_id,
                    &request.sections,
                    request.duration_sec.max(1),
                );
                let mut response = DebugWatchStartResponse::new();
                response.request_id = request.request_id;
                response.ok = true;
                response.watch_id = request.request_id;
                response.started_at_unix_ms = started_at_unix_ms;
                response.expire_at_unix_ms = expire_at_unix_ms;
                let bytes = response
                    .write_to_bytes()
                    .map_err(|e| io::Error::other(format!("DebugWatchStartResponse {:?}", e)))?;
                self.send_service_packet(
                    current_device,
                    service_packet::Protocol::DebugWatchStartResponse,
                    &bytes,
                )?;
                self.runtime.debug_watch.emit(
                    "runtime",
                    "watch_started",
                    serde_json::json!({
                        "watch_id": request.request_id,
                        "sections": request.sections,
                        "duration_sec": request.duration_sec,
                        "reason": request.reason,
                    }),
                );
            }
            service_packet::Protocol::DebugWatchStopRequest => {
                let request = DebugWatchStopRequest::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("DebugWatchStopRequest {:?}", e)))?;
                let stopped_watch_id = self.runtime.debug_watch.stop(Some(request.watch_id));
                let mut response = DebugWatchStopResponse::new();
                response.request_id = request.request_id;
                response.watch_id = stopped_watch_id.unwrap_or(request.watch_id);
                response.stopped_at_unix_ms = crate::handle::now_time() as i64;
                if stopped_watch_id.is_some() {
                    response.ok = true;
                } else {
                    response.ok = false;
                    response.reason = "no matching active debug watch".to_string();
                }
                let bytes = response
                    .write_to_bytes()
                    .map_err(|e| io::Error::other(format!("DebugWatchStopResponse {:?}", e)))?;
                self.send_service_packet(
                    current_device,
                    service_packet::Protocol::DebugWatchStopResponse,
                    &bytes,
                )?;
            }
            service_packet::Protocol::DnsQueryResponse => {
                let response = DnsQueryResponse::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("DnsQueryResponse {:?}", e)))?;
                let Some(pending) = self.runtime.take_dns_query(response.request_id) else {
                    log::debug!(
                        "drop dns response for unknown request_id={}",
                        response.request_id
                    );
                    return Ok(());
                };
                if !response.error.is_empty() {
                    log::warn!(
                        "control dns proxy failed request_id={} err={}",
                        response.request_id,
                        response.error
                    );
                    return Ok(());
                }
                if response.response.is_empty() {
                    log::warn!(
                        "control dns proxy returned empty response request_id={}",
                        response.request_id
                    );
                    return Ok(());
                }
                let packet = crate::util::dns_tunnel::build_dns_response_packet(
                    &pending,
                    &response.response,
                )?;
                write_full_device(&self.device, &packet, "dns response inject")?;
            }
            service_packet::Protocol::PunchStart => {
                let punch_start = PunchStart::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("PunchStart {:?}", e)))?;
                let (peer_ip, peer_nat_info) = build_peer_nat_info_from_punch_start(&punch_start);
                log::info!(
                    "PunchStart received peer={} session_id={} attempt={} endpoints={} public_ips={:?} public_ports={:?} local_ipv4={:?}",
                    peer_ip,
                    punch_start.session_id,
                    punch_start.attempt,
                    punch_start.peer_endpoints.len(),
                    peer_nat_info.public_ips,
                    peer_nat_info.public_ports,
                    peer_nat_info.local_ipv4()
                );
                self.runtime.debug_watch.emit(
                    "punch",
                    "start_received",
                        serde_json::json!({
                            "peer_ip": peer_ip.to_string(),
                            "session_id": punch_start.session_id,
                            "attempt": punch_start.attempt,
                            "attempt_budget": punch_start.attempt_budget,
                            "trigger_reason": format!("{:?}", punch_start.trigger_reason.enum_value_or_default()),
                            "selection_policy": format!("{:?}", punch_start.endpoint_selection_policy.enum_value_or_default()),
                            "endpoint_count": punch_start.peer_endpoints.len(),
                            "public_ips": peer_nat_info.public_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                            "public_ports": peer_nat_info.public_ports,
                        "local_ipv4": peer_nat_info.local_ipv4().map(|ip| ip.to_string()),
                    }),
                );
                let deadline_unix_ms = if punch_start.deadline_unix_ms > 0 {
                    punch_start.deadline_unix_ms
                } else {
                    let timeout_ms = if punch_start.timeout_ms == 0 {
                        5000
                    } else {
                        punch_start.timeout_ms
                    };
                    crate::handle::now_time() as i64 + timeout_ms as i64
                };
                let session = ActivePunchSession {
                    session_id: punch_start.session_id,
                    source: u32::from(current_device.virtual_ip),
                    target: punch_start.target,
                    attempt: punch_start.attempt,
                    deadline_unix_ms,
                };
                let coalesced = {
                    let mut sessions = self.punch_active_sessions.lock();
                    match sessions.get_mut(&peer_ip) {
                        Some(state) => {
                            state.coalesce(session);
                            true
                        }
                        None => {
                            sessions.insert(peer_ip, ActivePunchState::new(session));
                            false
                        }
                    }
                };
                let (accepted, phase, reason) =
                    if coalesced {
                        (
                            true,
                            PunchSessionPhase::PunchPhaseWaiting,
                            "coalesced onto active punch session",
                        )
                    } else if self.runtime.peer_state.lock().devices.get(&peer_ip).map_or(
                        false,
                        |p| {
                            p.preferred_channel_mode
                                == crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY
                        },
                    ) {
                        (
                            false,
                            PunchSessionPhase::PunchPhaseFailed,
                            "peer in forced relay mode",
                        )
                    } else {
                        let accepted = self
                            .runtime
                            .punch_coordinator
                            .submit_local(peer_ip, peer_nat_info);
                        (
                            accepted,
                            if accepted {
                                PunchSessionPhase::PunchPhaseSending
                            } else {
                                PunchSessionPhase::PunchPhaseFailed
                            },
                            if accepted { "" } else { "punch queue busy" },
                        )
                    };
                log::info!(
                    "PunchStart ack peer={} session_id={} attempt={} accepted={} phase={:?} coalesced={} reason={}",
                    peer_ip,
                    punch_start.session_id,
                    punch_start.attempt,
                    accepted,
                    phase,
                    coalesced,
                    reason
                );
                let ack = build_punch_ack(
                    punch_start.session_id,
                    u32::from(current_device.virtual_ip),
                    punch_start.attempt,
                    accepted,
                    phase,
                    reason,
                );
                let bytes = ack
                    .write_to_bytes()
                    .map_err(|e| io::Error::other(format!("PunchAck {:?}", e)))?;
                self.send_service_packet(
                    current_device,
                    service_packet::Protocol::PunchAck,
                    &bytes,
                )?;
                if !accepted {
                    self.punch_active_sessions.lock().remove(&peer_ip);
                    self.send_punch_result(
                        current_device,
                        punch_start.session_id,
                        u32::from(current_device.virtual_ip),
                        punch_start.target,
                        punch_start.attempt,
                        PunchResultCode::PunchResultRejected,
                        reason,
                    )?;
                } else if !coalesced {
                    self.spawn_punch_session_watchdog(peer_ip, session);
                }
            }
            service_packet::Protocol::RefreshGatewayGrantResponse => {
                let response = RefreshGatewayGrantResponse::parse_from_bytes(net_packet.payload())
                    .map_err(|e| {
                        io::Error::other(format!("RefreshGatewayGrantResponse {:?}", e))
                    })?;
                if should_clear_gateway_grants_from_refresh_response(&response) {
                    self.runtime.gateway_sessions.clear_gateway_grant();
                    self.runtime
                        .gateway_grant_policy_rev
                        .store(response.gateway_policy_rev, Ordering::Relaxed);
                    log::warn!(
                        "gateway grant revoked by refresh response: {}",
                        response.reason
                    );
                    return Ok(());
                }
                if !response.has_update {
                    if response.result.enum_value_or_default()
                        == RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_NO_CHANGE
                    {
                        let current_policy_rev = self
                            .runtime
                            .gateway_grant_policy_rev
                            .load(Ordering::Relaxed);
                        if should_apply_gateway_policy_rev(
                            current_policy_rev,
                            response.gateway_policy_rev,
                        ) {
                            self.runtime
                                .gateway_grant_policy_rev
                                .store(response.gateway_policy_rev, Ordering::Relaxed);
                        }
                    }
                    log::info!(
                        "gateway grant refresh skipped: {} (result={:?})",
                        response.reason,
                        response.result.enum_value_or_default()
                    );
                    return Ok(());
                }
                self.apply_gateway_grants(
                    &response.gateway_access_grants,
                    response.gateway_access_grant.as_ref(),
                    response.gateway_policy_rev,
                    current_device.virtual_ip,
                );
                log::info!("gateway grant refreshed for {}", current_device.virtual_ip);
            }
            service_packet::Protocol::GatewayConnectAck => {
                let ack = GatewayConnectAck::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("GatewayConnectAck {:?}", e)))?;
                self.runtime
                    .gateway_sessions
                    .handle_connect_ack(route_key.addr, &ack);
            }
            _ => {
                log::warn!(
                    "service_packet::Protocol::Unknown = {:?}",
                    net_packet.head()
                );
            }
        }
        Ok(())
    }
    fn set_device_info_list(&self, device_list_update: DeviceListUpdate) {
        let DeviceListUpdate {
            previous_peers,
            ip_list,
        } = device_list_update;
        let active_vips: HashSet<Ipv4Addr> = ip_list.iter().map(|peer| peer.virtual_ip).collect();
        let previous_by_identity: HashMap<Vec<u8>, Ipv4Addr> = previous_peers
            .values()
            .map(|peer| (Self::peer_identity_key(peer), peer.virtual_ip))
            .collect();
        let current_by_vip: HashMap<Ipv4Addr, Vec<u8>> = ip_list
            .iter()
            .map(|peer| (peer.virtual_ip, Self::peer_identity_key(peer)))
            .collect();
        let mut reset_vips: HashSet<Ipv4Addr> = previous_peers
            .keys()
            .filter(|vip| !active_vips.contains(vip))
            .copied()
            .collect();
        for (vip, previous_peer) in &previous_peers {
            if let Some(next_identity) = current_by_vip.get(vip) {
                let previous_identity = Self::peer_identity_key(previous_peer);
                if &previous_identity != next_identity {
                    reset_vips.insert(*vip);
                }
            }
        }
        for peer in &ip_list {
            let identity = Self::peer_identity_key(peer);
            if let Some(previous_vip) = previous_by_identity.get(&identity) {
                if *previous_vip != peer.virtual_ip {
                    log::info!(
                        "peer {} moved vip {} -> {}",
                        peer.device_id,
                        previous_vip,
                        peer.virtual_ip
                    );
                    reset_vips.insert(*previous_vip);
                }
            }
            if peer.preferred_channel_mode == crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY
            {
                reset_vips.insert(peer.virtual_ip);
            }
        }
        for vip in &reset_vips {
            self.runtime.route_manager.clear_peer(vip);
        }
        self.runtime.route_manager.retain_peers(&active_vips);
        self.runtime
            .peer_nat_info_map
            .write()
            .retain(|vip, _| active_vips.contains(vip) && !reset_vips.contains(vip));
        let mut peer_session_ciphers = std::collections::HashMap::with_capacity(ip_list.len());
        let local_online_session_key = self.runtime.peer_crypto.online_session_key();
        for peer_info in &ip_list {
            let Some(local_online_session_key) = local_online_session_key.as_ref() else {
                log::warn!("missing local online session key, skip deriving peer session ciphers");
                break;
            };
            match crate::util::derive_peer_session_key(
                local_online_session_key,
                &peer_info.online_kx_pub,
                &self.runtime.config.token,
            )
            .and_then(crate::cipher::Cipher::new_key)
            {
                Ok(cipher) => {
                    peer_session_ciphers.insert(peer_info.virtual_ip, cipher);
                }
                Err(err) => {
                    log::warn!(
                        "derive peer session cipher failed peer={} device_id={} err={:?}",
                        peer_info.virtual_ip,
                        peer_info.device_id,
                        err
                    );
                }
            }
        }
        self.runtime
            .peer_crypto
            .rotate_peer_session_ciphers(peer_session_ciphers);
        self.runtime.peer_crypto.retain_peers(&active_vips);
        self.runtime
            .peer_crypto
            .clear_previous_ciphers_for(&reset_vips);
        self.runtime.apply_selected_exit_node_route();
        self.callback.peer_client_list(
            ip_list
                .into_iter()
                .map(|peer_info| {
                    PeerClientInfo::new(peer_info.virtual_ip, peer_info.name, peer_info.status)
                })
                .collect(),
        );
    }
    fn register(
        &self,
        current_device: &CurrentDeviceInfo,
        _route_key: RouteKey,
        allow_ip_change: bool,
    ) -> anyhow::Result<()> {
        if current_device.status.online() {
            log::info!("已连接的不需要注册，{:?}", self.runtime.config);
            return Ok(());
        }
        log::info!("发送注册请求，{:?}", self.runtime.config);
        self.runtime
            .control_session
            .send_registration_request(false, allow_ip_change)?;
        Ok(())
    }
    fn error(
        &self,
        _current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            InErrorPacket::TokenError => {
                // token错误，可能是服务端设置了白名单
                let err = ErrorInfo::new(ErrorType::TokenError);
                self.callback.error(err);
            }
            InErrorPacket::Disconnect => {
                crate::handle::change_status(
                    &self.runtime.current_device,
                    ConnectStatus::Connecting,
                );
                let err = ErrorInfo::new(ErrorType::Disconnect);
                self.callback.error(err);
                let _device_list_update_guard = self.device_list_update_lock.lock();
                //掉线epoch要归零
                {
                    let mut dev = self.runtime.peer_state.lock();
                    dev.epoch = 0;
                    drop(dev);
                }
                self.runtime.peer_crypto.clear_all();
                self.runtime.control_session.send_handshake()?;
                // self.register(current_device, context, route_key)?;
            }
            InErrorPacket::AddressExhausted => {
                // 地址用尽
                let err = ErrorInfo::new(ErrorType::AddressExhausted);
                self.callback.error(err);
            }
            InErrorPacket::OtherError(e) => {
                let err = ErrorInfo::new_msg(ErrorType::Unknown, e.message()?);
                self.callback.error(err);
            }
            InErrorPacket::IpAlreadyExists => {
                let err = ErrorInfo::new(ErrorType::IpAlreadyExists);
                self.callback.error(err);
            }
            InErrorPacket::InvalidIp => {
                let err = ErrorInfo::new(ErrorType::InvalidIp);
                self.callback.error(err);
            }
            InErrorPacket::NoKey => {
                //这个类型最开头已经处理过，这里忽略
            }
        }
        Ok(())
    }
    fn control(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PongPacket(pong_packet) => {
                let current_time = crate::handle::now_time() as u16;
                if current_time < pong_packet.time() {
                    return Ok(());
                }
                let metric = net_packet.origin_ttl() - net_packet.ttl() + 1;
                let from_control_or_gateway =
                    self.runtime.control_session.is_control_addr(route_key.addr)
                        || self
                            .runtime
                            .gateway_sessions
                            .is_gateway_addr(route_key.addr);
                let learned_metric = if from_control_or_gateway {
                    metric.max(2)
                } else {
                    metric
                };
                let rt = (current_time - pong_packet.time()) as i64;
                let route = Route::from(route_key, learned_metric, rt);
                self.runtime
                    .route_manager()
                    .add_path(net_packet.source(), route);
                let epoch = self.runtime.peer_state.lock().epoch;
                if pong_packet.epoch() != epoch {
                    //纪元不一致，可能有新客户端连接，向服务端拉取客户端列表
                    self.runtime
                        .control_session
                        .send_service_header_only(service_packet::Protocol::PullDeviceList)?;
                }
            }
            ControlPacket::AddrResponse(addr_packet) => {
                //更新本地公网ipv4
                self.runtime
                    .nat_test
                    .update_addr(addr_packet.ipv4(), addr_packet.port());
            }
            _ => {}
        }
        Ok(())
    }
}

fn is_stale_epoch(current_epoch: u16, incoming_epoch: u16) -> bool {
    if current_epoch == 0 || current_epoch == incoming_epoch {
        return false;
    }
    current_epoch.wrapping_sub(incoming_epoch) < (u16::MAX / 2)
}

fn try_commit_device_list_state(
    peer_state: &mut crate::handle::PeerState,
    epoch: u16,
    next_devices: HashMap<Ipv4Addr, PeerDeviceInfo>,
) -> Option<HashMap<Ipv4Addr, PeerDeviceInfo>> {
    if is_stale_epoch(peer_state.epoch, epoch) {
        return None;
    }
    let previous_peers = std::mem::replace(&mut peer_state.devices, next_devices);
    peer_state.epoch = epoch;
    Some(previous_peers)
}

fn build_punch_ack(
    session_id: u64,
    source: u32,
    attempt: u32,
    accepted: bool,
    phase: PunchSessionPhase,
    reason: &str,
) -> PunchAck {
    let mut ack = PunchAck::new();
    ack.session_id = session_id;
    ack.source = source;
    ack.attempt = attempt;
    ack.accepted = accepted;
    ack.reason = reason.to_string();
    ack.phase = protobuf::EnumOrUnknown::new(phase);
    ack
}

fn build_punch_result(
    session_id: u64,
    source: u32,
    target: u32,
    attempt: u32,
    code: PunchResultCode,
    reason: &str,
    selected_endpoint: Option<PunchEndpoint>,
) -> PunchResult {
    let mut result = PunchResult::new();
    result.session_id = session_id;
    result.source = source;
    result.target = target;
    result.attempt = attempt;
    result.code = protobuf::EnumOrUnknown::new(code);
    result.reason = reason.to_string();
    result.phase = protobuf::EnumOrUnknown::new(punch_phase_from_result_code(code));
    if let Some(endpoint) = selected_endpoint {
        result.selected_endpoint = protobuf::MessageField::some(endpoint);
    }
    result
}

fn punch_phase_from_result_code(code: PunchResultCode) -> PunchSessionPhase {
    match code {
        PunchResultCode::PunchResultSuccess => PunchSessionPhase::PunchPhaseSuccess,
        PunchResultCode::PunchResultNoResponse | PunchResultCode::PunchResultTimeout => {
            PunchSessionPhase::PunchPhaseTimeout
        }
        PunchResultCode::PunchResultUnknown
        | PunchResultCode::PunchResultFailed
        | PunchResultCode::PunchResultCanceled
        | PunchResultCode::PunchResultRejected
        | PunchResultCode::PunchResultSuperseded => PunchSessionPhase::PunchPhaseFailed,
    }
}

fn send_punch_result_via_control(
    control_session: &crate::control::ControlSession,
    session_id: u64,
    source: u32,
    target: u32,
    attempt: u32,
    code: PunchResultCode,
    reason: &str,
    selected_endpoint: Option<PunchEndpoint>,
) -> anyhow::Result<()> {
    let result = build_punch_result(
        session_id,
        source,
        target,
        attempt,
        code,
        reason,
        selected_endpoint,
    );
    let bytes = result
        .write_to_bytes()
        .map_err(|e| anyhow!("PunchResult {:?}", e))?;
    control_session.send_service_payload(service_packet::Protocol::PunchResult, &bytes)?;
    Ok(())
}

fn selected_endpoint_for_result(
    code: PunchResultCode,
    route: Option<Route>,
) -> Option<PunchEndpoint> {
    if code != PunchResultCode::PunchResultSuccess {
        return None;
    }
    route.map(punch_endpoint_from_route)
}

fn punch_endpoint_from_route(route: Route) -> PunchEndpoint {
    let mut endpoint = PunchEndpoint::new();
    match route.addr {
        SocketAddr::V4(addr) => {
            endpoint.ip = u32::from(*addr.ip());
            endpoint.port = u32::from(addr.port());
        }
        SocketAddr::V6(addr) => {
            endpoint.ipv6 = addr.ip().octets().to_vec();
            endpoint.port = u32::from(addr.port());
        }
    }
    endpoint.tcp = route.protocol.is_base_tcp() && !route.protocol.is_quic();
    endpoint
}

fn format_punch_endpoint(endpoint: Option<&PunchEndpoint>) -> String {
    let Some(endpoint) = endpoint else {
        return "-".to_string();
    };
    let proto = if endpoint.tcp { "tcp" } else { "udp" };
    if endpoint.ip != 0 {
        return format!(
            "{}:{}/{}",
            Ipv4Addr::from(endpoint.ip),
            endpoint.port,
            proto
        );
    }
    if endpoint.ipv6.len() == 16 {
        let mut ipv6 = [0u8; 16];
        ipv6.copy_from_slice(&endpoint.ipv6);
        return format!("[{}]:{}/{}", Ipv6Addr::from(ipv6), endpoint.port, proto);
    }
    format!("-:{}/{}", endpoint.port, proto)
}

fn build_peer_nat_info_from_punch_start(punch_start: &PunchStart) -> (Ipv4Addr, NatInfo) {
    let peer_ip = Ipv4Addr::from(punch_start.target);
    let mut public_ips = Vec::new();
    let mut public_ports = Vec::new();
    let mut local_udp_ports = Vec::new();
    let mut local_ipv4: Option<Ipv4Addr> = None;
    let mut ipv6: Option<Ipv6Addr> = None;
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;
    for ep in &punch_start.peer_endpoints {
        if ep.ip != 0 {
            has_ipv4 = true;
            let ip = Ipv4Addr::from(ep.ip);
            if crate::nat::is_ipv4_global(&ip) {
                public_ips.push(ip);
            } else if local_ipv4.is_none() {
                // Control-triggered PunchStart only carries endpoint ip:port pairs. In private
                // networks (e.g. Docker bridge CI), keep the first non-global IPv4 as the local
                // candidate so punch workers still have a reachable direct target to probe.
                local_ipv4 = Some(ip);
            }
            if !crate::nat::is_ipv4_global(&ip)
                && ep.port <= u16::MAX as u32
                && ep.port > 0
                && !local_udp_ports.contains(&(ep.port as u16))
            {
                local_udp_ports.push(ep.port as u16);
            }
        }
        if ep.port <= u16::MAX as u32 && ep.port > 0 {
            public_ports.push(ep.port as u16);
        }
        if ipv6.is_none() && ep.ipv6.len() == 16 {
            has_ipv6 = true;
            let mut v6 = [0u8; 16];
            v6.copy_from_slice(&ep.ipv6);
            ipv6 = Some(Ipv6Addr::from(v6));
        }
        if ep.ipv6.len() == 16
            && ep.port <= u16::MAX as u32
            && ep.port > 0
            && !local_udp_ports.contains(&(ep.port as u16))
        {
            local_udp_ports.push(ep.port as u16);
        }
    }
    let local_udp_ports = if local_udp_ports.is_empty() {
        public_ports.clone()
    } else {
        local_udp_ports
    };
    let punch_model = if has_ipv4 && has_ipv6 {
        PunchModel::All
    } else if has_ipv6 {
        PunchModel::IPv6Udp
    } else if has_ipv4 {
        PunchModel::IPv4Udp
    } else {
        PunchModel::All
    };
    (
        peer_ip,
        NatInfo::new(
            public_ips,
            public_ports.clone(),
            punch_start
                .peer_endpoints
                .iter()
                .filter_map(|ep| {
                    if ep.port == 0 {
                        return None;
                    }
                    if ep.ip != 0 {
                        return Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                            Ipv4Addr::from(ep.ip),
                            ep.port as u16,
                        )));
                    }
                    if ep.ipv6.len() == 16 {
                        let mut v6 = [0u8; 16];
                        v6.copy_from_slice(&ep.ipv6);
                        return Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                            Ipv6Addr::from(v6),
                            ep.port as u16,
                            0,
                            0,
                        )));
                    }
                    None
                })
                .collect(),
            0,
            local_ipv4,
            ipv6,
            local_udp_ports,
            NatType::Cone,
            punch_model,
        ),
    )
}

fn observed_udp_port_from_registration(
    protocol: crate::transport::connect_protocol::ConnectProtocol,
    public_port: u16,
) -> u16 {
    if protocol.is_udp() {
        public_port
    } else {
        0
    }
}

fn collect_gateway_grants(
    grants: &[proto::message::GatewayAccessGrant],
    legacy_grant: Option<&proto::message::GatewayAccessGrant>,
) -> Vec<proto::message::GatewayAccessGrant> {
    if !grants.is_empty() {
        return grants.to_vec();
    }
    legacy_grant.cloned().into_iter().collect()
}

fn effective_gateway_policy_rev(
    gateway_policy_rev: u64,
    grants: &[proto::message::GatewayAccessGrant],
    legacy_grant: Option<&proto::message::GatewayAccessGrant>,
) -> u64 {
    if gateway_policy_rev != 0 {
        return gateway_policy_rev;
    }
    collect_gateway_grants(grants, legacy_grant)
        .into_iter()
        .map(|grant| grant.policy_rev)
        .max()
        .unwrap_or(0)
}

fn is_gateway_peer_ipturn_source(
    source: Ipv4Addr,
    current_device: &CurrentDeviceInfo,
    from_gateway: bool,
) -> bool {
    from_gateway && source != current_device.virtual_gateway
}

fn rewrite_peer_echo_request_as_reply<B: AsRef<[u8]> + AsMut<[u8]>>(
    net_packet: &mut NetPacket<B>,
    source: Ipv4Addr,
    destination: Ipv4Addr,
) -> io::Result<()> {
    let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
    let mut icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
    icmp_packet.set_kind(Kind::EchoReply);
    icmp_packet.update_checksum();
    ipv4.set_source_ip(destination);
    ipv4.set_destination_ip(source);
    ipv4.update_checksum();
    net_packet.set_source(destination);
    net_packet.set_destination(source);
    Ok(())
}

fn should_apply_gateway_policy_rev(current_policy_rev: u64, incoming_policy_rev: u64) -> bool {
    incoming_policy_rev == 0 || incoming_policy_rev >= current_policy_rev
}

fn has_gateway_grants(
    grants: &[proto::message::GatewayAccessGrant],
    legacy_grant: Option<&proto::message::GatewayAccessGrant>,
) -> bool {
    !grants.is_empty() || legacy_grant.is_some()
}

fn should_refresh_gateway_grant_after_registration(
    was_offline: bool,
    registration_has_gateway_grant: bool,
) -> bool {
    was_offline && !registration_has_gateway_grant
}

fn should_retry_registration_with_fresh_handshake(
    error_code: u32,
    error_reason: RegistrationErrorReason,
    reason: &str,
) -> bool {
    if error_reason
        == RegistrationErrorReason::REGISTRATION_ERROR_REASON_MISSING_HANDSHAKE_CAPABILITY
    {
        return true;
    }
    if error_code == 0 {
        return false;
    }
    reason
        .trim()
        .to_ascii_lowercase()
        .contains("missing required handshake capability")
}

fn should_retry_device_auth_after_challenge_expired(
    error_reason: DeviceAuthErrorReason,
    reason: &str,
) -> bool {
    if error_reason == DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_CHALLENGE_EXPIRED {
        return true;
    }
    reason.trim().eq_ignore_ascii_case("challenge_expired")
}

fn should_clear_gateway_grants_from_refresh_response(
    response: &RefreshGatewayGrantResponse,
) -> bool {
    let result = response.result.enum_value_or_default();
    if result == RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_REVOKED {
        return true;
    }
    response.has_update
        && !has_gateway_grants(
            &response.gateway_access_grants,
            response.gateway_access_grant.as_ref(),
        )
        && response
            .reason
            .trim()
            .eq_ignore_ascii_case("gateway policy cleared")
}

#[cfg(test)]
mod tests {
    use super::{
        build_peer_nat_info_from_punch_start, build_punch_ack, build_punch_result,
        effective_gateway_policy_rev, format_punch_endpoint, is_gateway_peer_ipturn_source,
        is_stale_epoch, log_sampled_unauthorized_server_source_drop,
        observed_udp_port_from_registration, punch_endpoint_from_route,
        rewrite_peer_echo_request_as_reply, selected_endpoint_for_result,
        should_apply_gateway_policy_rev, should_clear_gateway_grants_from_refresh_response,
        should_refresh_gateway_grant_after_registration,
        should_retry_device_auth_after_challenge_expired,
        should_retry_registration_with_fresh_handshake, try_commit_device_list_state,
        ActivePunchSession, ActivePunchState,
    };
    use crate::data_plane::route::Route;
    use crate::handle::CurrentDeviceInfo;
    use crate::handle::PeerDeviceInfo;
    use crate::nat::punch::PunchModel;
    use crate::proto::message::{
        DeviceAuthErrorReason, GatewayAccessGrant, PunchEndpoint, PunchResultCode,
        PunchSessionPhase, PunchStart, RefreshGatewayGrantResponse, RefreshGatewayGrantResult,
        RegistrationErrorReason,
    };
    use crate::protocol::{ip_turn_packet, NetPacket, Protocol};
    use crate::transport::connect_protocol::ConnectProtocol;
    use sdl_packet::icmp::icmp::IcmpPacket;
    use sdl_packet::icmp::Kind;
    use sdl_packet::ip::ipv4::packet::IpV4Packet;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn build_icmp_echo_request_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> NetPacket<Vec<u8>> {
        let mut ipv4_payload = vec![0u8; 28];
        let ipv4_len = ipv4_payload.len() as u16;
        ipv4_payload[0] = 0x45;
        ipv4_payload[2..4].copy_from_slice(&ipv4_len.to_be_bytes());
        ipv4_payload[8] = 64;
        ipv4_payload[9] = 1;
        ipv4_payload[12..16].copy_from_slice(&source.octets());
        ipv4_payload[16..20].copy_from_slice(&destination.octets());
        ipv4_payload[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
        ipv4_payload[26..28].copy_from_slice(&0x0001u16.to_be_bytes());
        {
            let mut ipv4 = IpV4Packet::new(&mut ipv4_payload).expect("ipv4 packet");
            let mut icmp = IcmpPacket::new(ipv4.payload_mut()).expect("icmp packet");
            icmp.set_kind(Kind::EchoRequest);
            icmp.update_checksum();
            ipv4.update_checksum();
        }

        let buffer = vec![0u8; 12 + ipv4_payload.len()];
        let mut packet = NetPacket::new0(buffer.len(), buffer).expect("net packet");
        packet.set_default_version();
        packet.set_protocol(Protocol::IpTurn);
        packet.set_transport_protocol_into(ip_turn_packet::Protocol::Ipv4);
        packet.set_initial_ttl(6);
        packet.set_source(source);
        packet.set_destination(destination);
        packet.set_payload(&ipv4_payload).expect("set payload");
        packet
    }

    #[test]
    fn build_peer_nat_info_from_punch_start_uses_endpoints() {
        let mut start = PunchStart::new();
        start.target = u32::from(Ipv4Addr::new(10, 26, 0, 3));
        let mut ep1 = PunchEndpoint::new();
        ep1.ip = u32::from(Ipv4Addr::new(1, 1, 1, 1));
        ep1.port = 10001;
        let mut ep2 = PunchEndpoint::new();
        ep2.ip = u32::from(Ipv4Addr::new(2, 2, 2, 2));
        ep2.port = 10002;
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        ep2.ipv6 = ipv6.octets().to_vec();
        start.peer_endpoints.push(ep1);
        start.peer_endpoints.push(ep2);

        let (peer_ip, nat_info) = build_peer_nat_info_from_punch_start(&start);
        assert_eq!(peer_ip, Ipv4Addr::new(10, 26, 0, 3));
        assert_eq!(nat_info.public_ips.len(), 2);
        assert_eq!(nat_info.public_ports, vec![10001, 10002]);
        assert_eq!(nat_info.ipv6(), Some(ipv6));
        assert_eq!(nat_info.punch_model, PunchModel::All);
    }

    #[test]
    fn build_peer_nat_info_from_punch_start_keeps_private_ipv4_as_local_candidate() {
        let mut start = PunchStart::new();
        start.target = u32::from(Ipv4Addr::new(10, 26, 0, 3));
        let mut ep = PunchEndpoint::new();
        ep.ip = u32::from(Ipv4Addr::new(172, 18, 0, 7));
        ep.port = 10001;
        start.peer_endpoints.push(ep);

        let (_peer_ip, nat_info) = build_peer_nat_info_from_punch_start(&start);
        assert!(nat_info.public_ips.is_empty());
        assert_eq!(nat_info.local_ipv4(), Some(Ipv4Addr::new(172, 18, 0, 7)));
        assert_eq!(nat_info.public_ports, vec![10001]);
        assert_eq!(nat_info.local_udp_ports, vec![10001]);
    }

    #[test]
    fn build_peer_nat_info_from_punch_start_uses_local_ports_for_local_candidates() {
        let mut start = PunchStart::new();
        start.target = u32::from(Ipv4Addr::new(10, 26, 0, 5));

        let mut public_ep = PunchEndpoint::new();
        public_ep.ip = u32::from(Ipv4Addr::new(223, 74, 148, 126));
        public_ep.port = 1386;

        let mut local_ep = PunchEndpoint::new();
        local_ep.ip = u32::from(Ipv4Addr::new(192, 168, 31, 146));
        local_ep.port = 55979;

        let mut local_v6_ep = PunchEndpoint::new();
        let local_v6 = "2409:8a55:30d6:3fe4:adf7:c3f7:6177:590f"
            .parse::<Ipv6Addr>()
            .unwrap();
        local_v6_ep.ipv6 = local_v6.octets().to_vec();
        local_v6_ep.port = 55979;

        start.peer_endpoints.push(public_ep);
        start.peer_endpoints.push(local_ep);
        start.peer_endpoints.push(local_v6_ep);

        let (_peer_ip, nat_info) = build_peer_nat_info_from_punch_start(&start);

        assert_eq!(
            nat_info.local_ipv4(),
            Some(Ipv4Addr::new(192, 168, 31, 146))
        );
        assert_eq!(nat_info.ipv6(), Some(local_v6));
        assert_eq!(
            nat_info.local_udp_ipv4addr(),
            Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 31, 146),
                55979,
            )))
        );
        assert_eq!(
            nat_info.local_udp_ipv6addr(),
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                local_v6, 55979, 0, 0,
            )))
        );
        assert_eq!(nat_info.public_ports, vec![1386, 55979, 55979]);
        assert_eq!(nat_info.local_udp_ports, vec![55979]);
    }

    #[test]
    fn build_punch_ack_sets_reason() {
        let ack = build_punch_ack(11, 2, 4, false, PunchSessionPhase::PunchPhaseFailed, "busy");
        assert_eq!(ack.session_id, 11);
        assert_eq!(ack.source, 2);
        assert_eq!(ack.attempt, 4);
        assert!(!ack.accepted);
        assert_eq!(ack.reason, "busy");
        assert_eq!(
            ack.phase.enum_value_or_default(),
            PunchSessionPhase::PunchPhaseFailed
        );
    }

    #[test]
    fn gateway_peer_ipturn_source_only_matches_non_gateway_peer_packets() {
        let current_device = CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 26, 0, 1),
        );

        assert!(is_gateway_peer_ipturn_source(
            Ipv4Addr::new(10, 26, 0, 5),
            &current_device,
            true,
        ));
        assert!(!is_gateway_peer_ipturn_source(
            Ipv4Addr::new(10, 26, 0, 1),
            &current_device,
            true,
        ));
        assert!(!is_gateway_peer_ipturn_source(
            Ipv4Addr::new(10, 26, 0, 5),
            &current_device,
            false,
        ));
    }

    #[test]
    fn rewrite_peer_echo_request_as_reply_swaps_inner_and_outer_ips() {
        let source = Ipv4Addr::new(10, 26, 0, 5);
        let destination = Ipv4Addr::new(10, 26, 0, 3);
        let mut packet = build_icmp_echo_request_packet(source, destination);

        rewrite_peer_echo_request_as_reply(&mut packet, source, destination)
            .expect("rewrite echo request");

        assert_eq!(packet.source(), destination);
        assert_eq!(packet.destination(), source);
        let ipv4 = IpV4Packet::new(packet.payload()).expect("ipv4");
        assert_eq!(ipv4.source_ip(), destination);
        assert_eq!(ipv4.destination_ip(), source);
        let icmp = IcmpPacket::new(ipv4.payload()).expect("icmp");
        assert_eq!(icmp.kind(), Kind::EchoReply);
    }

    #[test]
    fn is_stale_epoch_accepts_zero_and_same_epoch() {
        assert!(!is_stale_epoch(0, 10));
        assert!(!is_stale_epoch(10, 10));
    }

    #[test]
    fn is_stale_epoch_rejects_older_epoch_without_wrap() {
        assert!(is_stale_epoch(83, 63));
        assert!(!is_stale_epoch(63, 83));
    }

    #[test]
    fn try_commit_device_list_state_rejects_stale_without_overwriting_state() {
        let existing_peer = PeerDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            "peer-3".to_string(),
            0,
            "peer-3".to_string(),
            vec![1],
            vec![2],
            crate::proto::message::ChannelMode::CHANNEL_MODE_AUTO,
            false,
            false,
            false,
        );
        let mut peer_state = crate::handle::PeerState {
            epoch: 83,
            devices: HashMap::from([(existing_peer.virtual_ip, existing_peer.clone())]),
        };
        let next_peer = PeerDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 4),
            "peer-4".to_string(),
            0,
            "peer-4".to_string(),
            vec![3],
            vec![4],
            crate::proto::message::ChannelMode::CHANNEL_MODE_AUTO,
            false,
            false,
            false,
        );
        let next_devices = HashMap::from([(next_peer.virtual_ip, next_peer)]);

        let previous = try_commit_device_list_state(&mut peer_state, 63, next_devices);

        assert!(previous.is_none());
        assert_eq!(peer_state.epoch, 83);
        assert_eq!(peer_state.devices.len(), 1);
        assert_eq!(
            peer_state.devices.get(&Ipv4Addr::new(10, 26, 0, 3)),
            Some(&existing_peer)
        );
    }

    #[test]
    fn try_commit_device_list_state_updates_epoch_and_returns_previous_peers() {
        let existing_peer = PeerDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 3),
            "peer-3".to_string(),
            0,
            "peer-3".to_string(),
            vec![1],
            vec![2],
            crate::proto::message::ChannelMode::CHANNEL_MODE_AUTO,
            false,
            false,
            false,
        );
        let next_peer = PeerDeviceInfo::new(
            Ipv4Addr::new(10, 26, 0, 4),
            "peer-4".to_string(),
            0,
            "peer-4".to_string(),
            vec![3],
            vec![4],
            crate::proto::message::ChannelMode::CHANNEL_MODE_AUTO,
            false,
            false,
            false,
        );
        let mut peer_state = crate::handle::PeerState {
            epoch: 63,
            devices: HashMap::from([(existing_peer.virtual_ip, existing_peer.clone())]),
        };
        let next_devices = HashMap::from([(next_peer.virtual_ip, next_peer.clone())]);

        let previous = try_commit_device_list_state(&mut peer_state, 83, next_devices)
            .expect("fresh epoch should commit");

        assert_eq!(previous.len(), 1);
        assert_eq!(
            previous.get(&Ipv4Addr::new(10, 26, 0, 3)),
            Some(&existing_peer)
        );
        assert_eq!(peer_state.epoch, 83);
        assert_eq!(peer_state.devices.len(), 1);
        assert_eq!(
            peer_state.devices.get(&Ipv4Addr::new(10, 26, 0, 4)),
            Some(&next_peer)
        );
    }

    #[test]
    fn active_punch_state_coalesces_deadline_and_sessions() {
        let mut state = ActivePunchState::new(ActivePunchSession {
            session_id: 11,
            source: 2,
            target: 3,
            attempt: 1,
            deadline_unix_ms: 100,
        });
        state.coalesce(ActivePunchSession {
            session_id: 12,
            source: 2,
            target: 3,
            attempt: 2,
            deadline_unix_ms: 250,
        });

        assert_eq!(state.deadline_unix_ms(), 250);
        let sessions = state.sessions();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].session_id, 11);
        assert_eq!(sessions[1].session_id, 12);
    }

    #[test]
    fn active_punch_state_ignores_duplicate_session() {
        let active = ActivePunchSession {
            session_id: 11,
            source: 2,
            target: 3,
            attempt: 1,
            deadline_unix_ms: 100,
        };
        let mut state = ActivePunchState::new(active);
        state.coalesce(ActivePunchSession {
            deadline_unix_ms: 200,
            ..active
        });

        let sessions = state.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(state.deadline_unix_ms(), 200);
    }

    #[test]
    fn build_punch_result_sets_code_and_reason() {
        let result = build_punch_result(
            12,
            3,
            4,
            5,
            PunchResultCode::PunchResultNoResponse,
            "timeout",
            None,
        );
        assert_eq!(result.session_id, 12);
        assert_eq!(result.source, 3);
        assert_eq!(result.target, 4);
        assert_eq!(result.attempt, 5);
        assert_eq!(
            result.code.enum_value_or_default(),
            PunchResultCode::PunchResultNoResponse
        );
        assert_eq!(result.reason, "timeout");
        assert_eq!(
            result.phase.enum_value_or_default(),
            PunchSessionPhase::PunchPhaseTimeout
        );
    }

    #[test]
    fn effective_gateway_policy_rev_prefers_message_level_value() {
        let mut grant = GatewayAccessGrant::new();
        grant.policy_rev = 7;

        assert_eq!(effective_gateway_policy_rev(11, &[grant], None), 11);
    }

    #[test]
    fn effective_gateway_policy_rev_falls_back_to_grant_policy_rev() {
        let mut grant1 = GatewayAccessGrant::new();
        grant1.policy_rev = 3;
        let mut grant2 = GatewayAccessGrant::new();
        grant2.policy_rev = 5;

        assert_eq!(effective_gateway_policy_rev(0, &[grant1, grant2], None), 5);
    }

    #[test]
    fn should_apply_gateway_policy_rev_rejects_older_policy() {
        assert!(!should_apply_gateway_policy_rev(9, 8));
        assert!(should_apply_gateway_policy_rev(9, 9));
        assert!(should_apply_gateway_policy_rev(9, 10));
    }

    #[test]
    fn selected_endpoint_for_success_uses_direct_route() {
        let endpoint = selected_endpoint_for_result(
            PunchResultCode::PunchResultSuccess,
            Some(Route::new(
                ConnectProtocol::UDP,
                "1.2.3.4:51820".parse::<SocketAddr>().unwrap(),
                1,
                1,
            )),
        )
        .expect("selected endpoint");
        assert_eq!(endpoint.ip, u32::from(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(endpoint.port, 51820);
        assert!(!endpoint.tcp);
    }

    #[test]
    fn punch_endpoint_from_tcp_route_marks_tcp() {
        let endpoint = punch_endpoint_from_route(Route::new(
            ConnectProtocol::TCP,
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
            1,
            1,
        ));
        assert!(endpoint.tcp);
        assert_eq!(endpoint.ipv6.len(), 16);
    }

    #[test]
    fn format_punch_endpoint_formats_ipv4() {
        let mut endpoint = PunchEndpoint::new();
        endpoint.ip = u32::from(Ipv4Addr::new(1, 2, 3, 4));
        endpoint.port = 51820;
        assert_eq!(format_punch_endpoint(Some(&endpoint)), "1.2.3.4:51820/udp");
    }

    #[test]
    fn observed_udp_port_from_registration_only_trusts_udp_control() {
        assert_eq!(
            observed_udp_port_from_registration(ConnectProtocol::UDP, 29901),
            29901
        );
        assert_eq!(
            observed_udp_port_from_registration(ConnectProtocol::QUIC, 443),
            0
        );
        assert_eq!(
            observed_udp_port_from_registration(ConnectProtocol::TCP, 443),
            0
        );
    }

    #[test]
    fn refresh_gateway_grant_after_registration_only_for_offline_recovery_without_grant() {
        assert!(should_refresh_gateway_grant_after_registration(true, false));
        assert!(!should_refresh_gateway_grant_after_registration(true, true));
        assert!(!should_refresh_gateway_grant_after_registration(
            false, false
        ));
    }

    #[test]
    fn registration_reject_retries_only_for_stale_handshake_state() {
        assert!(should_retry_registration_with_fresh_handshake(
            1999,
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_MISSING_HANDSHAKE_CAPABILITY,
            "client 203.0.113.10:443 missing required handshake capability \"udp_endpoint_report_v1\""
        ));
        assert!(!should_retry_registration_with_fresh_handshake(
            1002,
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_NOT_AUTHED,
            "device auth check failed"
        ));
        assert!(!should_retry_registration_with_fresh_handshake(
            1999,
            RegistrationErrorReason::REGISTRATION_ERROR_REASON_INTERNAL,
            "address exhausted"
        ));
    }

    #[test]
    fn device_auth_retries_only_for_challenge_expired() {
        assert!(should_retry_device_auth_after_challenge_expired(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_CHALLENGE_EXPIRED,
            "challenge_expired"
        ));
        assert!(should_retry_device_auth_after_challenge_expired(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_UNSPECIFIED,
            " CHALLENGE_EXPIRED "
        ));
        assert!(!should_retry_device_auth_after_challenge_expired(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_DEVICE_KEY_MISMATCH,
            "device_key_mismatch"
        ));
        assert!(!should_retry_device_auth_after_challenge_expired(
            DeviceAuthErrorReason::DEVICE_AUTH_ERROR_REASON_INVALID_SIGNATURE,
            "invalid_signature"
        ));
    }

    #[test]
    fn refresh_response_only_clears_gateway_on_revoke() {
        let mut temporary = RefreshGatewayGrantResponse::new();
        temporary.has_update = false;
        temporary.reason = "no gateway available".into();
        temporary.result =
            RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_TEMPORARILY_UNAVAILABLE.into();
        assert!(!should_clear_gateway_grants_from_refresh_response(
            &temporary
        ));

        let mut no_change = RefreshGatewayGrantResponse::new();
        no_change.has_update = false;
        no_change.reason = "gateway grant unchanged".into();
        no_change.result = RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_NO_CHANGE.into();
        assert!(!should_clear_gateway_grants_from_refresh_response(
            &no_change
        ));

        let mut revoked = RefreshGatewayGrantResponse::new();
        revoked.has_update = true;
        revoked.reason = "gateway policy cleared".into();
        revoked.result = RefreshGatewayGrantResult::REFRESH_GATEWAY_GRANT_RESULT_REVOKED.into();
        assert!(should_clear_gateway_grants_from_refresh_response(&revoked));
    }

    #[test]
    fn unauthorized_server_source_drop_logger_is_callable() {
        log_sampled_unauthorized_server_source_drop(
            crate::data_plane::route::RouteKey::new(
                ConnectProtocol::UDP,
                "198.51.100.10:29901".parse().unwrap(),
            ),
            "203.0.113.10:4242".parse().unwrap(),
        );
    }
}
