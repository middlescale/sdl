use anyhow::anyhow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;
use rand::RngCore;
use sdl_packet::icmp::{icmp, Kind};
use sdl_packet::ip::ipv4;
use sdl_packet::ip::ipv4::packet::IpV4Packet;

use crate::core::SdlRuntime;
use crate::data_plane::route::{Route, RoutePath};
use crate::handle::callback::{ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, SdlCallback};
use crate::handle::recv_data::PacketHandler;
use crate::handle::{ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::punch::{NatInfo, NatType, PunchModel};
use crate::proto::message::{
    DebugCollectRequest, DebugCollectResponse, DebugWatchStartRequest, DebugWatchStartResponse,
    DebugWatchStopRequest, DebugWatchStopResponse, DeviceAuthAck, DeviceAuthChallenge, DeviceList,
    DeviceRenameResponse, DnsQueryResponse, GatewayConnectAck, HandshakeResponse, PunchAck,
    PunchEndpoint, PunchResult, PunchResultCode, PunchSessionPhase, PunchStart,
    RefreshGatewayGrantResponse, RegistrationResponse,
};
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::peer_discovery_packet::DiscoverySessionId;
use crate::protocol::{ip_turn_packet, service_packet, NetPacket, Protocol};
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::{proto, DnsProfile, PeerClientInfo};

const CAPABILITY_UDP_ENDPOINT_REPORT_V1: &str = "udp_endpoint_report_v1";

/// 处理来源于服务端的包
#[derive(Clone)]
pub struct ServerPacketHandler<Call, Device> {
    runtime: Arc<SdlRuntime>,
    device: Device,
    callback: Call,
    punch_active_sessions: Arc<Mutex<HashMap<Ipv4Addr, ActivePunchSession>>>,
    device_auth_ok: Arc<AtomicCell<bool>>,
}

#[derive(Copy, Clone)]
struct ActivePunchSession {
    session_id: u64,
    source: u32,
    target: u32,
    source_owner: u64,
    target_owner: u64,
    attempt: u32,
    deadline_unix_ms: i64,
}

impl<Call, Device> ServerPacketHandler<Call, Device> {
    pub fn new(runtime: Arc<SdlRuntime>, device: Device, callback: Call) -> Self {
        Self {
            runtime,
            device,
            callback,
            punch_active_sessions: Arc::new(Mutex::new(HashMap::new())),
            device_auth_ok: Arc::new(AtomicCell::new(false)),
        }
    }
}

impl<Call: SdlCallback, Device: DeviceWrite> PacketHandler for ServerPacketHandler<Call, Device> {
    fn handle(
        &self,
        net_packet: NetPacket<&mut [u8]>,
        _extend: NetPacket<&mut [u8]>,
        route_key: RoutePath,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
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
                self.register(current_device, route_key)?;
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
                        let ipv4 = IpV4Packet::new(net_packet.payload())?;
                        if ipv4.protocol() == ipv4::protocol::Protocol::Icmp
                            && ipv4.destination_ip() == current_device.virtual_ip
                        {
                            let icmp_packet = icmp::IcmpPacket::new(ipv4.payload())?;
                            if icmp_packet.kind() == Kind::EchoReply {
                                //网关ip ping的回应
                                log::debug!(
                                    "gateway icmp echo reply received src={} dst={} via={} bytes={}",
                                    ipv4.source_ip(),
                                    ipv4.destination_ip(),
                                    route_key.addr(),
                                    net_packet.payload().len()
                                );
                                self.runtime.debug_watch.emit(
                                    "icmp",
                                    "gateway_echo_reply_received",
                                    serde_json::json!({
                                        "src": ipv4.source_ip().to_string(),
                                        "dst": ipv4.destination_ip().to_string(),
                                        "via": route_key.addr().to_string(),
                                        "bytes": net_packet.payload().len(),
                                    }),
                                );
                                let written = self.device.write(net_packet.payload())?;
                                log::debug!(
                                    "gateway icmp echo reply injected into tun src={} dst={} written_bytes={}",
                                    ipv4.source_ip(),
                                    ipv4.destination_ip(),
                                    written
                                );
                                self.runtime.debug_watch.emit(
                                    "icmp",
                                    "gateway_echo_reply_injected",
                                    serde_json::json!({
                                        "src": ipv4.source_ip().to_string(),
                                        "dst": ipv4.destination_ip().to_string(),
                                        "written_bytes": written,
                                    }),
                                );
                                return Ok(());
                            }
                        }
                    }
                    ip_turn_packet::Protocol::WGIpv4 => {}
                    ip_turn_packet::Protocol::Ipv4Broadcast => {}
                    ip_turn_packet::Protocol::Unknown(_) => {}
                }
            }
            Protocol::OtherTurn => {}
            Protocol::PeerDiscovery => {}
            Protocol::Unknown(_) => {}
        }
        Ok(())
    }
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

impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    fn apply_gateway_grant(
        &self,
        grant: Option<&proto::message::GatewayAccessGrant>,
        virtual_ip: Ipv4Addr,
    ) {
        if let Some(grant) = grant {
            self.runtime.gateway_sessions.set_gateway_grant(
                grant,
                virtual_ip,
                self.runtime.config.device_id.clone(),
            );
            log::info!(
                "gateway grant: channels={:?} default={:?} session_id={} policy_rev={} expire={} caps={:?}",
                grant.gateway_channels,
                grant.default_gateway_channel.enum_value_or_default(),
                grant.session_id,
                grant.policy_rev,
                grant.ticket_expire_unix_ms,
                grant.gateway_capabilities
            );
        } else {
            self.runtime.gateway_sessions.clear_gateway_grant();
            log::info!("gateway grant cleared");
        }
    }

    fn reconcile_punch_sessions(&self, current_device: &CurrentDeviceInfo) -> anyhow::Result<()> {
        let now_ms = crate::handle::now_time() as i64;
        let mut succeeded = Vec::new();
        let mut expired = Vec::new();
        {
            let mut sessions = self.punch_active_sessions.lock();
            sessions.retain(|peer_ip, session| {
                let session_ready = self
                    .runtime
                    .peer_sessions
                    .state(peer_ip)
                    .map(|state| state.is_ready())
                    .unwrap_or(false);
                if session_ready {
                    if let Some(_peer_session) = self.runtime.peer_sessions.state(peer_ip) {
                        self.runtime.debug_watch.emit(
                            "peer_session",
                            "ready",
                            serde_json::json!({"peer_ip": peer_ip.to_string()}),
                        );
                    }
                    succeeded.push((*peer_ip, *session));
                    return false;
                }
                if session.deadline_unix_ms > 0 && now_ms > session.deadline_unix_ms {
                    expired.push((*peer_ip, *session));
                    false
                } else {
                    true
                }
            });
        }
        for (peer_ip, session) in succeeded {
            self.runtime.clear_peer_discovery_session(&peer_ip);
            let reason = if self
                .runtime
                .peer_sessions
                .state(&peer_ip)
                .map(|state| state.preferred_transport == crate::util::PeerSessionTransport::Direct)
                .unwrap_or(false)
            {
                "p2p route established"
            } else {
                "peer session ready"
            };
            self.send_punch_result(
                current_device,
                session.session_id,
                session.source,
                session.target,
                session.source_owner,
                session.target_owner,
                session.attempt,
                PunchResultCode::PunchResultSuccess,
                reason,
            )?;
        }
        for (peer_ip, session) in expired {
            self.runtime.clear_peer_discovery_session(&peer_ip);
            self.send_punch_result(
                current_device,
                session.session_id,
                session.source,
                session.target,
                session.source_owner,
                session.target_owner,
                session.attempt,
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
        source_owner: u64,
        target_owner: u64,
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
            source_owner,
            target_owner,
            attempt,
            code,
            reason,
            selected_endpoint,
        )
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
                    let Some(active) = guard.get(&peer_ip).copied() else {
                        return;
                    };
                    if active.session_id != session.session_id || active.attempt != session.attempt
                    {
                        return;
                    }
                    let session_ready = runtime
                        .peer_sessions
                        .state(&peer_ip)
                        .map(|state| state.is_ready())
                        .unwrap_or(false);
                    if session_ready {
                        guard.remove(&peer_ip);
                        if runtime
                            .peer_sessions
                            .state(&peer_ip)
                            .map(|state| {
                                state.preferred_transport
                                    == crate::util::PeerSessionTransport::Direct
                            })
                            .unwrap_or(false)
                        {
                            Some((PunchResultCode::PunchResultSuccess, "p2p route established"))
                        } else {
                            Some((PunchResultCode::PunchResultSuccess, "peer session ready"))
                        }
                    } else if session.deadline_unix_ms > 0 && now_ms > session.deadline_unix_ms {
                        guard.remove(&peer_ip);
                        Some((PunchResultCode::PunchResultNoResponse, "deadline exceeded"))
                    } else {
                        None
                    }
                };
                if let Some((code, reason)) = outcome {
                    runtime.clear_peer_discovery_session(&peer_ip);
                    log::info!(
                        "punch watchdog outcome peer={} session_id={} attempt={} code={:?} reason={}",
                        peer_ip,
                        session.session_id,
                        session.attempt,
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
                    if let Err(err) = send_punch_result_via_control(
                        &runtime.control_session,
                        session.session_id,
                        session.source,
                        session.target,
                        session.source_owner,
                        session.target_owner,
                        session.attempt,
                        code,
                        reason,
                        selected_endpoint,
                    ) {
                        log::warn!(
                            "send punch result from watchdog failed peer={} session_id={} attempt={} err={:?}",
                            peer_ip,
                            session.session_id,
                            session.attempt,
                            err
                        );
                    }
                    return;
                }
                // Retry any pending probes whose first send was dropped (e.g. the
                // responder's initial probe arrives before the initiator has
                // installed its cipher).  Retrying here ensures both sides can
                // reach is_ready() without waiting for the next GatewayConnectAck.
                runtime.retry_pending_peer_session_probes();
                let sleep = if session.deadline_unix_ms > 0 {
                    let remaining = session.deadline_unix_ms.saturating_sub(now_ms) as u64;
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
        route_key: RoutePath,
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
                self.runtime
                    .control_registration_epoch
                    .store(response.registration_epoch, std::sync::atomic::Ordering::Relaxed);
                self.apply_gateway_grant(response.gateway_access_grant.as_ref(), virtual_ip);
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

                    if old.virtual_ip != virtual_ip
                        || old.virtual_gateway != virtual_gateway
                        || old.virtual_netmask != virtual_netmask
                        || dns_changed
                    {
                        if old.virtual_ip != Ipv4Addr::UNSPECIFIED {
                            log::info!("ip发生变化,old:{:?},response={:?}", old, response);
                        }
                        #[cfg(not(feature = "integrated_tun"))]
                        {
                            let device_config = crate::handle::callback::DeviceConfig::new(
                                self.runtime.config.mtu,
                                virtual_ip,
                                virtual_netmask,
                                virtual_gateway,
                                virtual_network,
                                self.runtime.external_route.to_route(),
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
                    }
                    self.set_device_info_list(response.device_info_list, response.epoch as _);
                    self.runtime
                        .control_session
                        .trigger_status_report_with_nat_ready(if old.status.offline() {
                            crate::proto::message::PunchTriggerReason::PunchTriggerReconnectRecovery
                        } else {
                            crate::proto::message::PunchTriggerReason::PunchTriggerStatusUpdate
                        });
                    if should_refresh_gateway_grant_after_registration(
                        old.status.offline(),
                        response.gateway_access_grant.as_ref().is_some(),
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
                self.set_device_info_list(response.device_info_list, response.epoch as _);
                self.runtime
                    .control_session
                    .trigger_status_report_with_nat_ready(
                        crate::proto::message::PunchTriggerReason::PunchTriggerStatusUpdate,
                    );
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
                    return Ok(());
                }
                self.device_auth_ok.store(true);
                println!(
                    "auth device success: user={} group={} device={}",
                    ack.user_id, ack.group, ack.device_id
                );
                self.callback.success();
                self.register(current_device, route_key)?;
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
                        Ok(crate::core::RenameRequestOutcome::PendingApproval)
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
                self.device.write(&packet)?;
            }
            service_packet::Protocol::PunchStart => {
                let punch_start = PunchStart::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("PunchStart {:?}", e)))?;
                let local_registration_epoch = self
                    .runtime
                    .control_registration_epoch
                    .load(std::sync::atomic::Ordering::Relaxed);
                if !punch_start_matches_local_owner(local_registration_epoch, &punch_start) {
                    log::warn!(
                        "drop punch start with stale local owner peer={} session_id={} attempt={} local_owner={} packet_source_owner={}",
                        Ipv4Addr::from(punch_start.target),
                        punch_start.session_id,
                        punch_start.attempt,
                        local_registration_epoch,
                        punch_start.source_owner
                    );
                    return Ok(());
                }
                let (peer_ip, peer_nat_info) = build_peer_nat_info_from_punch_start(&punch_start);
                log::info!(
                    "PunchStart received peer={} session_id={} attempt={} endpoints={} public_ips={:?} public_ports={:?} local_ipv4={:?}",
                    peer_ip,
                    punch_start.session_id,
                    punch_start.attempt,
                    punch_start.peer_endpoints.len(),
                    peer_nat_info.public_ips(),
                    peer_nat_info.public_ports(),
                    peer_nat_info.local_ipv4()
                );
                self.runtime.peer_sessions.clear_pending_ciphers_for(&HashSet::from([peer_ip]));
                self.runtime.clear_peer_discovery_session(&peer_ip);
                self.runtime.route_manager.clear_direct_paths(&peer_ip);
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
                            "public_ips": peer_nat_info.public_ips().iter().map(ToString::to_string).collect::<Vec<_>>(),
                            "public_ports": peer_nat_info.public_ports(),
                        "local_ipv4": peer_nat_info.local_ipv4().map(|ip| ip.to_string()),
                    }),
                );
                self.runtime
                    .peer_nat_info_map
                    .write()
                    .insert(peer_ip, peer_nat_info.clone());
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
                    source_owner: punch_start.source_owner,
                    target_owner: punch_start.target_owner,
                    attempt: punch_start.attempt,
                    deadline_unix_ms,
                };
                let session_id = DiscoverySessionId::new(
                    punch_start.session_id,
                    punch_start.attempt,
                    rand::thread_rng().next_u64(),
                );
                let (setup_session, failure_reason) = match self.runtime.peer_info(&peer_ip) {
                    Some(peer_info) => {
                        match crate::util::build_peer_discovery_noise_initiator(
                            &self.runtime.device_signing_key,
                            &peer_info.device_pub_key,
                            session_id,
                            current_device.virtual_ip,
                            peer_ip,
                        ) {
                            Ok(mut initiator) => match initiator.write_hello(&[]) {
                                Ok(hello_payload) => {
                                    self.runtime
                                        .remember_peer_discovery_initiator(peer_ip, initiator);
                                    (
                                        Some(crate::core::PeerDiscoverySession {
                                            session_id,
                                            deadline_unix_ms,
                                            hello_payload,
                                            local_owner: punch_start.source_owner,
                                            remote_owner: punch_start.target_owner,
                                        }),
                                        None,
                                    )
                                }
                                Err(err) => {
                                    log::warn!(
                                        "encode peer discovery hello failed peer={} device_id={} err={:?}",
                                        peer_ip,
                                        peer_info.device_id,
                                        err
                                    );
                                    (
                                        None,
                                        Some(format!("encode discovery hello failed: {}", err)),
                                    )
                                }
                            },
                            Err(err) => {
                                log::warn!(
                                    "init peer discovery noise failed peer={} device_id={} err={:?}",
                                    peer_ip,
                                    peer_info.device_id,
                                    err
                                );
                                (
                                    None,
                                    Some(format!("init discovery handshake failed: {}", err)),
                                )
                            }
                        }
                    }
                    None => (None, Some("missing peer identity".to_string())),
                };
                if let Some(setup_session) = setup_session.clone() {
                    self.runtime
                        .peer_sessions
                        .begin_recovery(peer_ip, setup_session.session_id);
                    self.runtime
                        .remember_peer_discovery_session(peer_ip, setup_session);
                }
                let replaced = {
                    let mut sessions = self.punch_active_sessions.lock();
                    let prev = sessions.insert(peer_ip, session);
                    match prev {
                        Some(prev)
                            if prev.session_id != punch_start.session_id
                                || prev.attempt != punch_start.attempt =>
                        {
                            Some(prev)
                        }
                        _ => None,
                    }
                };
                if let Some(prev) = replaced {
                    self.send_punch_result(
                        current_device,
                        prev.session_id,
                        prev.source,
                        prev.target,
                        prev.source_owner,
                        prev.target_owner,
                        prev.attempt,
                        PunchResultCode::PunchResultSuperseded,
                        "superseded by new attempt",
                    )?;
                }
                let accepted = setup_session
                    .as_ref()
                    .map(|setup_session| {
                        self.runtime.punch_coordinator.submit_local(
                            peer_ip,
                            peer_nat_info,
                            setup_session.session_id,
                        )
                    })
                    .unwrap_or(false);
                let reason = if accepted {
                    ""
                } else {
                    failure_reason.as_deref().unwrap_or("punch queue busy")
                };
                log::info!(
                    "PunchStart ack peer={} session_id={} attempt={} accepted={} phase={:?} reason={}",
                    peer_ip,
                    punch_start.session_id,
                    punch_start.attempt,
                    accepted,
                    if accepted {
                        PunchSessionPhase::PunchPhaseSending
                    } else {
                        PunchSessionPhase::PunchPhaseFailed
                    },
                    reason
                );
                let ack = build_punch_ack(
                    punch_start.session_id,
                    u32::from(current_device.virtual_ip),
                    punch_start.source_owner,
                    punch_start.target_owner,
                    punch_start.attempt,
                    accepted,
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
                    self.runtime.clear_peer_discovery_session(&peer_ip);
                    self.send_punch_result(
                        current_device,
                        punch_start.session_id,
                        u32::from(current_device.virtual_ip),
                        punch_start.target,
                        punch_start.source_owner,
                        punch_start.target_owner,
                        punch_start.attempt,
                        PunchResultCode::PunchResultRejected,
                        reason,
                    )?;
                } else {
                    self.spawn_punch_session_watchdog(peer_ip, session);
                }
            }
            service_packet::Protocol::RefreshGatewayGrantResponse => {
                let response = RefreshGatewayGrantResponse::parse_from_bytes(net_packet.payload())
                    .map_err(|e| {
                        io::Error::other(format!("RefreshGatewayGrantResponse {:?}", e))
                    })?;
                if !response.has_update {
                    log::info!("gateway grant refresh skipped: {}", response.reason);
                    return Ok(());
                }
                self.apply_gateway_grant(
                    response.gateway_access_grant.as_ref(),
                    current_device.virtual_ip,
                );
                log::info!("gateway grant refreshed for {}", current_device.virtual_ip);
            }
            service_packet::Protocol::GatewayConnectAck => {
                let ack = GatewayConnectAck::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("GatewayConnectAck {:?}", e)))?;
                let became_authenticated = self
                    .runtime
                    .gateway_sessions
                    .handle_connect_ack(route_key.addr(), &ack);
                if became_authenticated {
                    crate::nat::punch_workers::retry_pending_relay_discovery(self.runtime.clone());
                    self.runtime.retry_pending_peer_session_probes();
                }
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
    fn set_device_info_list(&self, device_info_list: Vec<proto::message::DeviceInfo>, epoch: u16) {
        let previous_peers = {
            let peer_state = self.runtime.peer_state.lock();
            let current_epoch = peer_state.epoch;
            if is_stale_epoch(current_epoch, epoch) {
                log::info!(
                    "ignore stale device list: current_epoch={}, incoming_epoch={}",
                    current_epoch,
                    epoch
                );
                return;
            }
            peer_state.devices.clone()
        };
        let ip_list: Vec<PeerDeviceInfo> = device_info_list
            .into_iter()
            .map(|info| {
                PeerDeviceInfo::new(
                    Ipv4Addr::from(info.virtual_ip),
                    info.name,
                    info.device_status as u8,
                    info.device_id,
                    info.device_pub_key,
                    info.registration_epoch,
                )
            })
            .collect();
        let active_vips: HashSet<Ipv4Addr> = ip_list.iter().map(|peer| peer.virtual_ip).collect();
        let previous_by_identity: HashMap<Vec<u8>, Ipv4Addr> = previous_peers
            .values()
            .map(|peer| (peer_identity_key(peer), peer.virtual_ip))
            .collect();
        let current_by_vip: HashMap<Ipv4Addr, Vec<u8>> = ip_list
            .iter()
            .map(|peer| (peer.virtual_ip, peer_identity_key(peer)))
            .collect();
        let hard_reset_vips: HashSet<Ipv4Addr> = HashSet::new();
        let mut soft_reset_vips: HashSet<Ipv4Addr> = previous_peers
            .keys()
            .filter(|vip| !active_vips.contains(vip))
            .copied()
            .collect();
        let mut hard_reset_vips = hard_reset_vips;
        for (vip, previous_peer) in &previous_peers {
            if let Some(next_peer) = ip_list.iter().find(|peer| peer.virtual_ip == *vip) {
                match peer_runtime_reset_kind(previous_peer, next_peer, &current_by_vip) {
                    Some(PeerRuntimeReset::Hard) => {
                        hard_reset_vips.insert(*vip);
                    }
                    Some(PeerRuntimeReset::Soft) => {
                        soft_reset_vips.insert(*vip);
                    }
                    None => {}
                }
            }
        }
        for peer in &ip_list {
            let identity = peer_identity_key(peer);
            if let Some(previous_vip) = previous_by_identity.get(&identity) {
                if *previous_vip != peer.virtual_ip {
                    log::info!(
                        "peer {} moved vip {} -> {}",
                        peer.device_id,
                        previous_vip,
                        peer.virtual_ip
                    );
                    hard_reset_vips.insert(*previous_vip);
                }
            }
        }
        self.runtime.hard_reset_peers(&hard_reset_vips);
        self.runtime.soft_reset_peers(&soft_reset_vips);
        self.runtime.route_manager.retain_peers(&active_vips);
        {
            let mut dev = self.runtime.peer_state.lock();
            //这里可能会收到旧的消息，但是随着时间推移总会收到新的
            dev.epoch = epoch;
            dev.devices.clear();
            for peer_info in ip_list.clone() {
                dev.devices.insert(peer_info.virtual_ip, peer_info);
            }
        }
        self.runtime.retain_peer_discovery_sessions(&active_vips);
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
        _route_key: RoutePath,
    ) -> anyhow::Result<()> {
        if current_device.status.online() {
            log::info!("已连接的不需要注册，{:?}", self.runtime.config);
            return Ok(());
        }
        log::info!("发送注册请求，{:?}", self.runtime.config);
        self.runtime
            .control_session
            .send_registration_request(false, false)?;
        Ok(())
    }
    fn error(
        &self,
        _current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RoutePath,
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
                self.runtime
                    .control_registration_epoch
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                let err = ErrorInfo::new(ErrorType::Disconnect);
                self.callback.error(err);
                //掉线epoch要归零
                {
                    let mut dev = self.runtime.peer_state.lock();
                    dev.epoch = 0;
                    drop(dev);
                }
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
        route_key: RoutePath,
    ) -> anyhow::Result<()> {
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PongPacket(pong_packet) => {
                let current_time = crate::handle::now_time() as u16;
                if current_time < pong_packet.time() {
                    return Ok(());
                }
                let metric = net_packet.origin_ttl() - net_packet.ttl() + 1;
                let learned_metric = if route_key.is_trusted_server_path() {
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

fn build_punch_ack(
    session_id: u64,
    source: u32,
    source_owner: u64,
    target_owner: u64,
    attempt: u32,
    accepted: bool,
    reason: &str,
) -> PunchAck {
    let mut ack = PunchAck::new();
    ack.session_id = session_id;
    ack.source = source;
    ack.source_owner = source_owner;
    ack.target_owner = target_owner;
    ack.attempt = attempt;
    ack.accepted = accepted;
    ack.reason = reason.to_string();
    ack.phase = protobuf::EnumOrUnknown::new(if accepted {
        PunchSessionPhase::PunchPhaseSending
    } else {
        PunchSessionPhase::PunchPhaseFailed
    });
    ack
}

fn build_punch_result(
    session_id: u64,
    source: u32,
    target: u32,
    source_owner: u64,
    target_owner: u64,
    attempt: u32,
    code: PunchResultCode,
    reason: &str,
    selected_endpoint: Option<PunchEndpoint>,
) -> PunchResult {
    let mut result = PunchResult::new();
    result.session_id = session_id;
    result.source = source;
    result.target = target;
    result.source_owner = source_owner;
    result.target_owner = target_owner;
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
    source_owner: u64,
    target_owner: u64,
    attempt: u32,
    code: PunchResultCode,
    reason: &str,
    selected_endpoint: Option<PunchEndpoint>,
) -> anyhow::Result<()> {
    let result = build_punch_result(
        session_id,
        source,
        target,
        source_owner,
        target_owner,
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
    match route.addr() {
        SocketAddr::V4(addr) => {
            endpoint.ip = u32::from(*addr.ip());
            endpoint.port = u32::from(addr.port());
        }
        SocketAddr::V6(addr) => {
            endpoint.ipv6 = addr.ip().octets().to_vec();
            endpoint.port = u32::from(addr.port());
        }
    }
    endpoint.tcp = route.protocol().is_base_tcp() && !route.protocol().is_quic();
    endpoint
}

fn punch_start_matches_local_owner(local_owner: u64, punch_start: &PunchStart) -> bool {
    if local_owner == 0 || punch_start.source_owner == 0 {
        return true;
    }
    local_owner == punch_start.source_owner
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
    }
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
            public_ports,
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

fn should_refresh_gateway_grant_after_registration(
    was_offline: bool,
    registration_has_gateway_grant: bool,
) -> bool {
    was_offline && !registration_has_gateway_grant
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PeerRuntimeReset {
    Soft,
    Hard,
}

fn peer_runtime_reset_kind(
    previous_peer: &PeerDeviceInfo,
    next_peer: &PeerDeviceInfo,
    current_by_vip: &HashMap<Ipv4Addr, Vec<u8>>,
) -> Option<PeerRuntimeReset> {
    if let Some(next_identity) = current_by_vip.get(&previous_peer.virtual_ip) {
        let previous_identity = peer_identity_key(previous_peer);
        if &previous_identity != next_identity {
            return Some(PeerRuntimeReset::Hard);
        }
    }
    if previous_peer.name != next_peer.name {
        return Some(PeerRuntimeReset::Soft);
    }
    if previous_peer.registration_epoch != next_peer.registration_epoch {
        return Some(PeerRuntimeReset::Soft);
    }
    (previous_peer.status != next_peer.status).then_some(PeerRuntimeReset::Soft)
}

#[cfg(test)]
mod tests {
    use super::{
        build_peer_nat_info_from_punch_start, build_punch_ack, build_punch_result,
        format_punch_endpoint, observed_udp_port_from_registration, punch_endpoint_from_route,
        punch_start_matches_local_owner, peer_runtime_reset_kind, selected_endpoint_for_result,
        should_refresh_gateway_grant_after_registration, PeerRuntimeReset,
    };
    use crate::data_plane::route::Route;
    use crate::handle::{PeerDeviceInfo, PeerDeviceStatus};
    use crate::nat::punch::PunchModel;
    use crate::proto::message::{PunchEndpoint, PunchResultCode, PunchSessionPhase, PunchStart};
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

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
        assert_eq!(nat_info.public_ips().len(), 2);
        assert_eq!(nat_info.public_ports(), &[10001, 10002]);
        assert_eq!(nat_info.ipv6(), Some(ipv6));
        assert_eq!(nat_info.punch_model(), PunchModel::All);
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
        assert!(nat_info.public_ips().is_empty());
        assert_eq!(nat_info.local_ipv4(), Some(Ipv4Addr::new(172, 18, 0, 7)));
        assert_eq!(nat_info.public_ports(), &[10001]);
        assert_eq!(nat_info.udp_ports(), &[10001]);
    }

    #[test]
    fn build_punch_ack_sets_reason() {
        let ack = build_punch_ack(11, 2, 21, 22, 4, false, "busy");
        assert_eq!(ack.session_id, 11);
        assert_eq!(ack.source, 2);
        assert_eq!(ack.source_owner, 21);
        assert_eq!(ack.target_owner, 22);
        assert_eq!(ack.attempt, 4);
        assert!(!ack.accepted);
        assert_eq!(ack.reason, "busy");
        assert_eq!(
            ack.phase.enum_value_or_default(),
            PunchSessionPhase::PunchPhaseFailed
        );
    }

    #[test]
    fn build_punch_result_sets_code_and_reason() {
        let result = build_punch_result(
            12,
            3,
            4,
            31,
            32,
            5,
            PunchResultCode::PunchResultNoResponse,
            "timeout",
            None,
        );
        assert_eq!(result.session_id, 12);
        assert_eq!(result.source, 3);
        assert_eq!(result.target, 4);
        assert_eq!(result.source_owner, 31);
        assert_eq!(result.target_owner, 32);
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
    fn punch_start_local_owner_matches_when_equal() {
        let mut start = PunchStart::new();
        start.source_owner = 42;
        assert!(punch_start_matches_local_owner(42, &start));
        assert!(!punch_start_matches_local_owner(43, &start));
    }

    #[test]
    fn punch_start_local_owner_allows_unknown_owner() {
        let start = PunchStart::new();
        assert!(punch_start_matches_local_owner(0, &start));
        assert!(punch_start_matches_local_owner(42, &start));
    }

    #[test]
    fn selected_endpoint_for_success_uses_direct_route() {
        let endpoint = selected_endpoint_for_result(
            PunchResultCode::PunchResultSuccess,
            Some(Route::new_with_origin(
                ConnectProtocol::UDP,
                crate::data_plane::route::RouteOrigin::PeerUdp,
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
        let endpoint = punch_endpoint_from_route(Route::new_with_origin(
            ConnectProtocol::TCP,
            crate::data_plane::route::RouteOrigin::PeerUdp,
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

    fn test_peer_info(ip: Ipv4Addr, status: PeerDeviceStatus) -> PeerDeviceInfo {
        PeerDeviceInfo {
            virtual_ip: ip,
            name: "peer".to_string(),
            status,
            device_id: "dev-1".to_string(),
            device_pub_key: vec![1, 2, 3],
            registration_epoch: 1,
        }
    }

    #[test]
    fn status_change_uses_soft_reset() {
        let vip = Ipv4Addr::new(10, 26, 0, 2);
        let previous = test_peer_info(vip, PeerDeviceStatus::Online);
        let next = test_peer_info(vip, PeerDeviceStatus::Offline);
        let current_by_vip = HashMap::from([(vip, b"id:dev-1".to_vec())]);

        assert_eq!(
            peer_runtime_reset_kind(&previous, &next, &current_by_vip),
            Some(PeerRuntimeReset::Soft)
        );
    }

    #[test]
    fn keep_peer_runtime_when_identity_and_status_are_stable() {
        let vip = Ipv4Addr::new(10, 26, 0, 2);
        let previous = test_peer_info(vip, PeerDeviceStatus::Online);
        let next = test_peer_info(vip, PeerDeviceStatus::Online);
        let current_by_vip = HashMap::from([(vip, b"id:dev-1".to_vec())]);

        assert_eq!(peer_runtime_reset_kind(&previous, &next, &current_by_vip), None);
    }

    #[test]
    fn name_change_uses_soft_reset() {
        let vip = Ipv4Addr::new(10, 26, 0, 2);
        let previous = test_peer_info(vip, PeerDeviceStatus::Online);
        let mut next = test_peer_info(vip, PeerDeviceStatus::Online);
        next.name = "renamed-peer".to_string();
        let current_by_vip = HashMap::from([(vip, b"id:dev-1".to_vec())]);

        assert_eq!(
            peer_runtime_reset_kind(&previous, &next, &current_by_vip),
            Some(PeerRuntimeReset::Soft)
        );
    }

    #[test]
    fn registration_epoch_change_uses_soft_reset() {
        let vip = Ipv4Addr::new(10, 26, 0, 2);
        let previous = test_peer_info(vip, PeerDeviceStatus::Online);
        let mut next = test_peer_info(vip, PeerDeviceStatus::Online);
        next.registration_epoch = 2;
        let current_by_vip = HashMap::from([(vip, b"id:dev-1".to_vec())]);

        assert_eq!(
            peer_runtime_reset_kind(&previous, &next, &current_by_vip),
            Some(PeerRuntimeReset::Soft)
        );
    }

    #[test]
    fn identity_change_uses_hard_reset() {
        let vip = Ipv4Addr::new(10, 26, 0, 2);
        let previous = test_peer_info(vip, PeerDeviceStatus::Online);
        let mut next = test_peer_info(vip, PeerDeviceStatus::Online);
        next.device_id = "dev-2".to_string();
        next.device_pub_key = vec![9, 9, 9];
        let current_by_vip = HashMap::from([(vip, b"id:dev-2".to_vec())]);

        assert_eq!(
            peer_runtime_reset_kind(&previous, &next, &current_by_vip),
            Some(PeerRuntimeReset::Hard)
        );
    }
}
