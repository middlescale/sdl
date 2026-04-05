use anyhow::anyhow;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
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
    DeviceAuthAck, DeviceAuthChallenge, DeviceList, GatewayConnectAck, HandshakeResponse, PunchAck,
    PunchResult, PunchResultCode, PunchStart, RefreshGatewayGrantResponse, RegistrationResponse,
};
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::{ip_turn_packet, service_packet, NetPacket, Protocol};
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::{proto, PeerClientInfo};

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
        route_key: RouteKey,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        if !current_device.is_server_addr(route_key.addr)
            && !self
                .runtime
                .gateway_sessions
                .is_gateway_addr(route_key.addr)
        {
            // 拦截既不是控制端也不是已授权网关的数据
            log::warn!(
                "route_key={:?}, not from control server {} or gateway endpoint",
                route_key,
                current_device.control_server
            );
        }
        self.runtime
            .route_manager()
            .touch_path(&net_packet.source(), &route_key);
        self.reconcile_punch_sessions(current_device)?;
        if net_packet.protocol() == Protocol::Error
            && net_packet.transport_protocol()
                == crate::protocol::error_packet::Protocol::NoKey.into()
        {
            return Ok(());
        } else if net_packet.protocol() == Protocol::Service
            && net_packet.transport_protocol() == service_packet::Protocol::HandshakeResponse.into()
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
                                self.device.write(net_packet.payload())?;
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
            Protocol::Unknown(_) => {}
        }
        Ok(())
    }
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
                if self.runtime.route_manager().direct_path_count(peer_ip) > 0 {
                    succeeded.push(*session);
                    return false;
                }
                if session.deadline_unix_ms > 0 && now_ms > session.deadline_unix_ms {
                    expired.push(*session);
                    false
                } else {
                    true
                }
            });
        }
        for session in succeeded {
            self.send_punch_result(
                current_device,
                session.session_id,
                session.source,
                session.target,
                session.attempt,
                PunchResultCode::PunchResultSuccess,
                "p2p route established",
            )?;
        }
        for session in expired {
            self.send_punch_result(
                current_device,
                session.session_id,
                session.source,
                session.target,
                session.attempt,
                PunchResultCode::PunchResultTimeout,
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
        send_punch_result_via_control(
            &self.runtime.control_session,
            session_id,
            source,
            target,
            attempt,
            code,
            reason,
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
                    if runtime.route_manager().direct_path_count(&peer_ip) > 0 {
                        guard.remove(&peer_ip);
                        Some((PunchResultCode::PunchResultSuccess, "p2p route established"))
                    } else if session.deadline_unix_ms > 0 && now_ms > session.deadline_unix_ms {
                        guard.remove(&peer_ip);
                        Some((PunchResultCode::PunchResultTimeout, "deadline exceeded"))
                    } else {
                        None
                    }
                };
                if let Some((code, reason)) = outcome {
                    if let Err(err) = send_punch_result_via_control(
                        &runtime.control_session,
                        session.session_id,
                        session.source,
                        session.target,
                        session.attempt,
                        code,
                        reason,
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
                self.apply_gateway_grant(response.gateway_access_grant.as_ref(), virtual_ip);
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
                    if route_key.protocol().is_tcp() {
                        log::info!("更新公网tcp端口 {public_port}");
                        self.runtime.nat_test.update_tcp_port(public_port);
                    }
                    let old = current_device;
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
                        .trigger_status_report_with_nat_ready();
                    if old.status.offline() {
                        self.callback.success();
                    }
                }
            }
            service_packet::Protocol::PushDeviceList => {
                let response = DeviceList::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("PushDeviceList {:?}", e)))?;
                self.set_device_info_list(response.device_info_list, response.epoch as _);
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
            service_packet::Protocol::PunchStart => {
                let punch_start = PunchStart::parse_from_bytes(net_packet.payload())
                    .map_err(|e| io::Error::other(format!("PunchStart {:?}", e)))?;
                let (peer_ip, peer_nat_info) = build_peer_nat_info_from_punch_start(&punch_start);
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
                        prev.attempt,
                        PunchResultCode::PunchResultFailed,
                        "superseded by new attempt",
                    )?;
                }
                let accepted = self
                    .runtime
                    .punch_coordinator
                    .submit_local(peer_ip, peer_nat_info);
                let reason = if accepted { "" } else { "punch queue busy" };
                let ack = build_punch_ack(
                    punch_start.session_id,
                    u32::from(current_device.virtual_ip),
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
                    self.send_punch_result(
                        current_device,
                        punch_start.session_id,
                        u32::from(current_device.virtual_ip),
                        punch_start.target,
                        punch_start.attempt,
                        PunchResultCode::PunchResultFailed,
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
    fn set_device_info_list(&self, device_info_list: Vec<proto::message::DeviceInfo>, epoch: u16) {
        let current_epoch = self.runtime.peer_state.lock().0;
        if is_stale_epoch(current_epoch, epoch) {
            log::info!(
                "ignore stale device list: current_epoch={}, incoming_epoch={}",
                current_epoch,
                epoch
            );
            return;
        }
        let ip_list: Vec<PeerDeviceInfo> = device_info_list
            .into_iter()
            .map(|info| {
                PeerDeviceInfo::new(
                    Ipv4Addr::from(info.virtual_ip),
                    info.name,
                    info.device_status as u8,
                    info.wireguard,
                    info.device_id,
                    info.device_pub_key,
                    info.online_kx_pub,
                )
            })
            .collect();
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
        {
            let mut dev = self.runtime.peer_state.lock();
            //这里可能会收到旧的消息，但是随着时间推移总会收到新的
            dev.0 = epoch;
            dev.1.clear();
            for peer_info in ip_list.clone() {
                dev.1.insert(peer_info.virtual_ip, peer_info);
            }
        }
        self.runtime
            .peer_crypto
            .rotate_peer_session_ciphers(peer_session_ciphers);
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
                //掉线epoch要归零
                {
                    let mut dev = self.runtime.peer_state.lock();
                    dev.0 = 0;
                    drop(dev);
                }
                self.runtime.peer_crypto.clear_all();
                let mut current_device = self.runtime.current_device.load();
                while !current_device.is_server_addr(route_key.addr) {
                    let mut next = current_device;
                    next.control_server = route_key.addr;
                    match self
                        .runtime
                        .current_device
                        .compare_exchange(current_device, next)
                    {
                        Ok(_) => break,
                        Err(latest) => current_device = latest,
                    }
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
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PongPacket(pong_packet) => {
                let current_time = crate::handle::now_time() as u16;
                if current_time < pong_packet.time() {
                    return Ok(());
                }
                let metric = net_packet.origin_ttl() - net_packet.ttl() + 1;
                let from_control_or_gateway = current_device.is_server_addr(route_key.addr)
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
                let epoch = self.runtime.peer_state.lock().0;
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
    attempt: u32,
    accepted: bool,
    reason: &str,
) -> PunchAck {
    let mut ack = PunchAck::new();
    ack.session_id = session_id;
    ack.source = source;
    ack.attempt = attempt;
    ack.accepted = accepted;
    ack.reason = reason.to_string();
    ack
}

fn build_punch_result(
    session_id: u64,
    source: u32,
    target: u32,
    attempt: u32,
    code: PunchResultCode,
    reason: &str,
) -> PunchResult {
    let mut result = PunchResult::new();
    result.session_id = session_id;
    result.source = source;
    result.target = target;
    result.attempt = attempt;
    result.code = protobuf::EnumOrUnknown::new(code);
    result.reason = reason.to_string();
    result
}

fn send_punch_result_via_control(
    control_session: &crate::control::ControlSession,
    session_id: u64,
    source: u32,
    target: u32,
    attempt: u32,
    code: PunchResultCode,
    reason: &str,
) -> anyhow::Result<()> {
    let result = build_punch_result(session_id, source, target, attempt, code, reason);
    let bytes = result
        .write_to_bytes()
        .map_err(|e| anyhow!("PunchResult {:?}", e))?;
    control_session.send_service_payload(service_packet::Protocol::PunchResult, &bytes)?;
    Ok(())
}

fn build_peer_nat_info_from_punch_start(punch_start: &PunchStart) -> (Ipv4Addr, NatInfo) {
    let peer_ip = Ipv4Addr::from(punch_start.target);
    let mut public_ips = Vec::new();
    let mut public_ports = Vec::new();
    let mut local_ipv4: Option<Ipv4Addr> = None;
    let mut ipv6: Option<Ipv6Addr> = None;
    let mut use_tcp = false;
    for ep in &punch_start.peer_endpoints {
        if ep.ip != 0 {
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
            let mut v6 = [0u8; 16];
            v6.copy_from_slice(&ep.ipv6);
            ipv6 = Some(Ipv6Addr::from(v6));
        }
        if ep.tcp {
            use_tcp = true;
        }
    }
    let punch_model = if use_tcp {
        PunchModel::IPv4Tcp
    } else {
        PunchModel::IPv4Udp
    };
    (
        peer_ip,
        NatInfo::new(
            public_ips,
            public_ports.clone(),
            0,
            local_ipv4,
            ipv6,
            public_ports,
            0,
            0,
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

#[cfg(test)]
mod tests {
    use super::{
        build_peer_nat_info_from_punch_start, build_punch_ack, build_punch_result,
        observed_udp_port_from_registration,
    };
    use crate::nat::punch::PunchModel;
    use crate::proto::message::{PunchEndpoint, PunchResultCode, PunchStart};
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn build_peer_nat_info_from_punch_start_uses_endpoints_and_tcp_flag() {
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
        ep2.tcp = true;
        start.peer_endpoints.push(ep1);
        start.peer_endpoints.push(ep2);

        let (peer_ip, nat_info) = build_peer_nat_info_from_punch_start(&start);
        assert_eq!(peer_ip, Ipv4Addr::new(10, 26, 0, 3));
        assert_eq!(nat_info.public_ips.len(), 2);
        assert_eq!(nat_info.public_ports, vec![10001, 10002]);
        assert_eq!(nat_info.ipv6(), Some(ipv6));
        assert_eq!(nat_info.punch_model, PunchModel::IPv4Tcp);
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
        assert_eq!(nat_info.udp_ports, vec![10001]);
    }

    #[test]
    fn build_punch_ack_sets_reason() {
        let ack = build_punch_ack(11, 2, 4, false, "busy");
        assert_eq!(ack.session_id, 11);
        assert_eq!(ack.source, 2);
        assert_eq!(ack.attempt, 4);
        assert!(!ack.accepted);
        assert_eq!(ack.reason, "busy");
    }

    #[test]
    fn build_punch_result_sets_code_and_reason() {
        let result =
            build_punch_result(12, 3, 4, 5, PunchResultCode::PunchResultTimeout, "timeout");
        assert_eq!(result.session_id, 12);
        assert_eq!(result.source, 3);
        assert_eq!(result.target, 4);
        assert_eq!(result.attempt, 5);
        assert_eq!(
            result.code.enum_value_or_default(),
            PunchResultCode::PunchResultTimeout
        );
        assert_eq!(result.reason, "timeout");
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
}
