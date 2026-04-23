use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crossbeam_utils::atomic::AtomicCell;
use protobuf::Message;
use std::collections::HashSet;
use std::sync::Arc;

use crate::core::RuntimeConfig;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::stats::DataPlaneStats;
use crate::handle::callback::{ConnectInfo, ErrorType};
use crate::handle::registrar;
use crate::handle::{ConnectStatus, CurrentDeviceInfo, CONTROL_VIP};
use crate::nat::NatTest;
use crate::proto::message::{
    ClientStatusInfo, DeviceAuthChallenge, HandshakeRequest, PunchEndpoint, PunchNatType,
    PunchTriggerReason, RefreshGatewayGrantRequest, RouteItem,
};
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{service_packet, NetPacket, Protocol, HEAD_LEN, MAX_TTL};
use crate::transport::control_addr::parse_control_address;
use crate::transport::http3_channel::Http3Channel;
use crate::util::{
    address_choose, dns_query_all, sign_device_payload, PeerCryptoManager, StopManager,
};
use crate::{ErrorInfo, SdlCallback};
use parking_lot::{Mutex, RwLock};

const CAPABILITY_UDP_ENDPOINT_REPORT_V1: &str = "udp_endpoint_report_v1";
const CAPABILITY_PUNCH_COORD_V1: &str = "punch_coord_v1";
const CAPABILITY_GATEWAY_TICKET_V1: &str = "gateway_ticket_v1";
const HANDSHAKE_SOURCE_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(0, 0, 0, 2);
const CONTROL_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(15);
const RELAY_REPUNCH_INTERVAL: Duration = Duration::from_secs(60);

/// Shared data-plane objects that are owned jointly by the control session and
/// the packet-handling / routing layer.  Everything here is `Clone` via `Arc`.
#[derive(Clone)]
pub struct SharedDataPlane {
    pub current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    pub peer_crypto: Arc<PeerCryptoManager>,
    pub peer_state: Arc<Mutex<crate::handle::PeerState>>,
    pub gateway_sessions: GatewaySessions,
    pub route_manager: RouteManager,
}

#[derive(Clone)]
pub struct ControlSession {
    channel: Http3Channel,
    config: RuntimeConfig,
    data_plane: SharedDataPlane,
    data_plane_stats: DataPlaneStats,
    nat_test: NatTest,
    negotiated_capabilities: Arc<RwLock<HashSet<String>>>,
    last_control_packet_at_ms: Arc<AtomicU64>,
}

impl ControlSession {
    pub fn new(
        channel: Http3Channel,
        config: RuntimeConfig,
        data_plane: SharedDataPlane,
        data_plane_stats: DataPlaneStats,
        nat_test: NatTest,
        negotiated_capabilities: Arc<RwLock<HashSet<String>>>,
    ) -> Self {
        Self {
            channel,
            config,
            data_plane,
            data_plane_stats,
            nat_test,
            negotiated_capabilities,
            last_control_packet_at_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.data_plane.current_device.load()
    }

    pub fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        if let Ok(control_addr) = parse_control_address(&self.config.server_addr) {
            self.channel
                .update_server_name(control_addr.server_name().to_string());
        }
        self.channel.send_packet(packet)
    }

    pub fn send_handshake(&self) -> io::Result<()> {
        self.clear_negotiated_capabilities();
        let request_packet = handshake_request_packet()?;
        self.send_packet(&request_packet)
    }

    pub fn start<Call: SdlCallback, F>(
        &self,
        stop_manager: StopManager,
        call: Call,
        on_packet: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, crate::data_plane::route::RouteKey) + Send + Sync + 'static,
    {
        // Wrap on_packet so every packet received on the control channel
        // automatically updates the liveness timestamp — no address-based
        // detection needed at the call site.
        let last_ts = self.last_control_packet_at_ms.clone();
        let wrapped = move |data: Vec<u8>, route_key: crate::data_plane::route::RouteKey| {
            last_ts.store(crate::handle::now_time() as u64, Ordering::Relaxed);
            on_packet(data, route_key);
        };
        self.channel.start(stop_manager.clone(), wrapped)?;
        let (stop_sender, stop_receiver) = mpsc::channel::<()>();
        let worker = stop_manager.add_listener("controlSession".into(), move || {
            let _ = stop_sender.send(());
        })?;
        let control_session = self.clone();
        thread::Builder::new()
            .name("controlSession".into())
            .spawn(move || {
                control_session.run(call, stop_receiver);
                drop(worker);
            })?;
        Ok(())
    }

    fn maintain_connection<Call: SdlCallback>(
        &self,
        call: &Call,
        connect_count: &mut usize,
    ) -> io::Result<()> {
        let current_device = self.data_plane.current_device.load();
        if current_device.status.offline() {
            *connect_count += 1;
            self.resolve_and_update_server_addr();
            call.connect(ConnectInfo::new(*connect_count, self.channel.server_addr()));
            log::info!("发送握手请求,{:?}", self.config);
            if let Err(e) = self.send_handshake() {
                log::warn!("{:?}", e);
                return Err(e);
            }
        }
        Ok(())
    }

    fn idle_timed_out(&self) -> bool {
        let last = self.last_control_packet_at_ms.load(Ordering::Relaxed);
        if last == 0 {
            return false;
        }
        (crate::handle::now_time() as u64).saturating_sub(last)
            > CONTROL_SESSION_IDLE_TIMEOUT.as_millis() as u64
    }

    fn mark_control_disconnected<Call: SdlCallback>(&self, call: &Call, reason: String) {
        self.last_control_packet_at_ms.store(0, Ordering::Relaxed);
        crate::handle::change_status(&self.data_plane.current_device, ConnectStatus::Connecting);
        call.error(ErrorInfo::new_msg(
            ErrorType::Disconnect,
            format!("{reason}; existing gateway/p2p data plane is kept"),
        ));
        self.data_plane.route_manager.clear_peer(&CONTROL_VIP);
        log::warn!("{reason}");
    }

    fn run<Call: SdlCallback>(&self, call: Call, stop_receiver: mpsc::Receiver<()>) {
        let mut connect_count = 0usize;
        let mut last_connect_at = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap_or_else(Instant::now);
        let mut last_heartbeat_at = Instant::now()
            .checked_sub(Duration::from_secs(3))
            .unwrap_or_else(Instant::now);
        let mut last_status_report_at = Instant::now();
        let mut status_report_delay = Duration::from_secs(60);
        let mut last_public_addr_at = Instant::now()
            .checked_sub(Duration::from_secs(3))
            .unwrap_or_else(Instant::now);
        let mut public_addr_delay = Duration::from_secs(3);
        let mut last_relay_repunch_at = Instant::now();
        loop {
            if stop_receiver.recv_timeout(Duration::from_secs(1)).is_ok() {
                break;
            }
            let current_device = self.current_device();
            if current_device.status.offline() {
                if last_connect_at.elapsed() < Duration::from_secs(5) {
                    continue;
                }
                last_connect_at = Instant::now();
                if let Err(e) = self.maintain_connection(&call, &mut connect_count) {
                    call.error(ErrorInfo::new_msg(
                        ErrorType::Disconnect,
                        format!("connect:{},error:{:?}", self.channel.server_addr(), e),
                    ));
                }
                continue;
            }
            if self.idle_timed_out() {
                self.mark_control_disconnected(
                    &call,
                    format!(
                        "control session idle for more than {:?}, reconnecting",
                        CONTROL_SESSION_IDLE_TIMEOUT
                    ),
                );
                continue;
            }
            if last_heartbeat_at.elapsed() >= Duration::from_secs(3) {
                last_heartbeat_at = Instant::now();
                match self.send_server_heartbeat(self.data_plane.peer_state.lock().epoch) {
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("heartbeat err={:?}", e);
                    }
                }
                try_refresh_gateway_grant(self, &self.data_plane.gateway_sessions);
            }
            if last_status_report_at.elapsed() >= status_report_delay {
                if let Err(e) =
                    self.send_status_report_packet(PunchTriggerReason::PunchTriggerStatusUpdate)
                {
                    log::warn!("{:?}", e)
                }
                last_status_report_at = Instant::now();
                status_report_delay = Duration::from_secs(10 * 60);
            }
            if !self
                .data_plane
                .route_manager
                .use_channel_type()
                .is_only_relay()
                && last_public_addr_at.elapsed() >= public_addr_delay
            {
                if let Err(e) = self.nat_test.request_public_addr() {
                    log::warn!("{:?}", e);
                }
                last_public_addr_at = Instant::now();
                public_addr_delay = self.nat_test.public_addr_retry_delay();
            }
            if !self
                .data_plane
                .route_manager
                .use_channel_type()
                .is_only_relay()
                && last_relay_repunch_at.elapsed() >= RELAY_REPUNCH_INTERVAL
            {
                let peers_missing_direct_route = self.peers_missing_direct_route();
                if !peers_missing_direct_route.is_empty() {
                    log::info!(
                        "periodic repunch requested for peers without direct route: {:?}",
                        peers_missing_direct_route
                    );
                    self.trigger_status_report_with_nat_ready(
                        PunchTriggerReason::PunchTriggerManualRequest,
                    );
                }
                last_relay_repunch_at = Instant::now();
            }
        }
    }

    fn peers_missing_direct_route(&self) -> Vec<std::net::Ipv4Addr> {
        self.data_plane
            .peer_state
            .lock()
            .devices
            .values()
            .filter(|info| info.status.is_online())
            .filter_map(|info| {
                (self
                    .data_plane
                    .route_manager
                    .direct_path_count(&info.virtual_ip)
                    == 0)
                    .then_some(info.virtual_ip)
            })
            .collect()
    }

    pub fn send_server_heartbeat(&self, epoch: u16) -> anyhow::Result<()> {
        let mut packet = NetPacket::new(vec![0u8; HEAD_LEN + 4])?;
        let current_device = self.current_device();
        packet.set_default_version();
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
        packet.set_initial_ttl(5);
        packet.set_source(current_device.virtual_ip);
        packet.set_destination(CONTROL_VIP);
        let mut ping = PingPacket::new(packet.payload_mut())?;
        ping.set_time(crate::handle::now_time() as u16);
        ping.set_epoch(epoch);
        self.send_packet(&packet)?;
        Ok(())
    }

    pub fn send_service_payload(
        &self,
        transport: service_packet::Protocol,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let mut packet = NetPacket::new(vec![0u8; HEAD_LEN + payload.len()])?;
        let current_device = self.current_device();
        packet.set_source(current_device.virtual_ip);
        packet.set_destination(CONTROL_VIP);
        packet.set_default_version();
        packet.set_initial_ttl(MAX_TTL);
        packet.set_protocol(Protocol::Service);
        packet.set_transport_protocol(transport.into());
        packet.set_payload(payload)?;
        self.send_packet(&packet)?;
        Ok(())
    }

    pub fn send_service_header_only(
        &self,
        transport: service_packet::Protocol,
    ) -> anyhow::Result<()> {
        self.send_service_payload(transport, &[])
    }

    pub fn send_registration_request(
        &self,
        is_fast: bool,
        allow_ip_change: bool,
    ) -> anyhow::Result<()> {
        let mut ip = self.config.ip;
        let current_device = self.current_device();
        if ip.is_none() {
            ip = Some(current_device.virtual_ip);
        }
        let online_kx_pub = self
            .data_plane
            .peer_crypto
            .ensure_online_session_key()
            .public_key()
            .to_vec();
        let packet = registrar::registration_request_packet(
            self.config.token.clone(),
            self.config.device_id.clone(),
            self.config.device_pub_key.clone(),
            online_kx_pub,
            self.config.name.clone(),
            ip,
            is_fast,
            allow_ip_change,
        )?;
        self.send_packet(&packet)?;
        Ok(())
    }

    pub fn send_device_auth_request(&self) -> anyhow::Result<()> {
        let auth_request = self.config.auth_request.read();
        let (Some(user_id), Some(group), Some(ticket)) = (
            auth_request.user_id.as_ref(),
            auth_request.group.as_ref(),
            auth_request.ticket.as_ref(),
        ) else {
            anyhow::bail!("auth-device requires user/group/ticket");
        };
        let packet = registrar::device_auth_request_packet(
            user_id.clone(),
            group.clone(),
            self.config.device_id.clone(),
            ticket.clone(),
            self.config.device_pub_key.clone(),
        )?;
        self.send_packet(&packet)?;
        Ok(())
    }

    pub fn send_device_auth_proof(&self, challenge: &DeviceAuthChallenge) -> anyhow::Result<()> {
        let signature = build_device_auth_signature(
            &self.config.device_id,
            &self.config.device_pub_key,
            &challenge.challenge_id,
            &challenge.nonce,
        )?;
        let packet = registrar::device_auth_proof_packet(
            challenge.challenge_id.clone(),
            self.config.device_id.clone(),
            self.config.device_pub_key.clone(),
            signature,
        )?;
        self.send_packet(&packet)?;
        Ok(())
    }

    pub fn send_device_rename_request(
        &self,
        request_id: u64,
        new_name: String,
    ) -> anyhow::Result<()> {
        let current_device = self.current_device();
        if current_device.virtual_ip.is_unspecified() {
            anyhow::bail!("cannot rename device before registration");
        }
        let packet = registrar::device_rename_request_packet(
            request_id,
            current_device.virtual_ip,
            self.config.device_id.clone(),
            new_name,
        )?;
        self.send_packet(&packet)?;
        Ok(())
    }

    pub fn send_refresh_gateway_grant_request(
        &self,
        gateway_sessions: &GatewaySessions,
        force_reissue: bool,
    ) -> anyhow::Result<()> {
        let current_device = self.current_device();
        let virtual_ip = u32::from(current_device.virtual_ip);
        if virtual_ip == 0 {
            anyhow::bail!("cannot refresh gateway grant before registration");
        }
        let snapshot = gateway_sessions.current_grant_snapshot();
        let request = RefreshGatewayGrantRequest {
            virtual_ip,
            device_id: self.config.device_id.clone(),
            last_session_id: snapshot.as_ref().map(|v| v.session_id).unwrap_or(0),
            last_policy_rev: snapshot.as_ref().map(|v| v.policy_rev).unwrap_or(0),
            force_reissue,
            ..Default::default()
        };
        let payload = request.write_to_bytes()?;
        self.send_service_payload(
            service_packet::Protocol::RefreshGatewayGrantRequest,
            &payload,
        )
    }

    pub fn trigger_status_report(&self, reason: PunchTriggerReason) {
        if let Err(e) = self.send_status_report_packet(reason) {
            log::warn!("{:?}", e)
        }
    }

    pub fn supports_udp_endpoint_report_v1(&self) -> bool {
        self.has_capability(CAPABILITY_UDP_ENDPOINT_REPORT_V1)
    }

    pub fn set_negotiated_capabilities(&self, capabilities: &[String]) {
        let mut negotiated = self.negotiated_capabilities.write();
        negotiated.clear();
        negotiated.extend(capabilities.iter().cloned());
    }

    fn clear_negotiated_capabilities(&self) {
        self.negotiated_capabilities.write().clear();
    }

    fn has_capability(&self, capability: &str) -> bool {
        self.negotiated_capabilities.read().contains(capability)
    }

    pub fn trigger_status_report_with_nat_ready(&self, reason: PunchTriggerReason) {
        let control_session = self.clone();
        thread::Builder::new()
            .name("upStatusEvent".into())
            .spawn(move || {
                if !control_session.nat_test.has_public_udp_endpoints() {
                    if let Err(e) = control_session.nat_test.request_public_addr() {
                        log::warn!("{:?}", e);
                    }
                    thread::sleep(Duration::from_secs(2));
                }
                if let Err(e) = control_session.send_status_report_packet(reason) {
                    log::warn!("{:?}", e)
                }
            })
            .expect("upStatusEvent");
    }

    fn send_status_report_packet(&self, reason: PunchTriggerReason) -> io::Result<()> {
        let device_info = self.current_device();
        if device_info.status.offline() {
            return Ok(());
        }
        let routes = self.data_plane.route_manager.snapshot_direct_routes();
        let mut message = ClientStatusInfo::new();
        message.source = device_info.virtual_ip.into();
        for (ip, _) in routes {
            let mut item = RouteItem::new();
            item.next_ip = ip.into();
            message.p2p_list.push(item);
        }
        message.up_stream = self.data_plane_stats.up_traffic_total();
        message.down_stream = self.data_plane_stats.down_traffic_total();
        message.nat_type =
            protobuf::EnumOrUnknown::new(if self.nat_test.nat_info().nat_type.is_cone() {
                PunchNatType::Cone
            } else {
                PunchNatType::Symmetric
            });
        let nat_info = self.nat_test.nat_info();
        message.public_udp_endpoints = nat_info
            .public_udp_endpoints
            .iter()
            .map(|addr| {
                let mut endpoint = PunchEndpoint::new();
                endpoint.port = u32::from(addr.port());
                match addr {
                    std::net::SocketAddr::V4(addr) => {
                        endpoint.ip = u32::from(*addr.ip());
                    }
                    std::net::SocketAddr::V6(addr) => {
                        endpoint.ipv6 = addr.ip().octets().to_vec();
                    }
                }
                endpoint
            })
            .collect();
        message.local_udp_endpoints = nat_info
            .local_udp_endpoints()
            .into_iter()
            .map(|addr| {
                let mut endpoint = PunchEndpoint::new();
                endpoint.port = u32::from(addr.port());
                match addr {
                    std::net::SocketAddr::V4(addr) => {
                        endpoint.ip = u32::from(*addr.ip());
                    }
                    std::net::SocketAddr::V6(addr) => {
                        endpoint.ipv6 = addr.ip().octets().to_vec();
                    }
                }
                endpoint
            })
            .collect();
        message.punch_trigger_reason = protobuf::EnumOrUnknown::new(reason);
        let buf = message.write_to_bytes().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("up_status_packet {:?}", e))
        })?;
        self.send_service_payload(service_packet::Protocol::ClientStatusInfo, &buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(())
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.channel.server_addr()
    }

    pub fn is_control_addr(&self, addr: SocketAddr) -> bool {
        let server = self.channel.server_addr();
        if server == addr {
            return true;
        }
        // Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
        match (server.ip(), addr.ip()) {
            (IpAddr::V4(s), IpAddr::V6(a)) => {
                if let Some(v4) = a.to_ipv4_mapped() {
                    return s == v4 && server.port() == addr.port();
                }
            }
            (IpAddr::V6(s), IpAddr::V4(a)) => {
                if let Some(v4) = s.to_ipv4_mapped() {
                    return v4 == a && server.port() == addr.port();
                }
            }
            _ => {}
        }
        false
    }

    fn resolve_and_update_server_addr(&self) {
        let control_addr = match parse_control_address(&self.config.server_addr) {
            Ok(control_addr) => control_addr,
            Err(e) => {
                log::error!("控制地址解析失败:{:?},addr={}", e, self.config.server_addr);
                return;
            }
        };
        match dns_query_all(control_addr.authority()) {
            Ok(addrs) => {
                log::info!("domain {} addr {:?}", control_addr.authority(), addrs);
                match address_choose(addrs) {
                    Ok(addr) => {
                        let old = self.channel.server_addr();
                        if addr != old {
                            log::info!("服务端地址变化,旧地址:{}，新地址:{}", old, addr);
                            self.channel.update_server_addr(addr);
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "域名地址选择失败:{:?},domain={}",
                            e,
                            control_addr.authority()
                        );
                    }
                }
            }
            Err(e) => {
                log::error!("域名解析失败:{:?},domain={}", e, control_addr.authority());
            }
        }
    }
}

fn build_device_auth_signature(
    device_id: &str,
    device_pub_key: &[u8],
    challenge_id: &str,
    nonce: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(
        challenge_id.len() + device_id.len() + nonce.len() + device_pub_key.len() + 16,
    );
    append_len_prefixed(&mut payload, challenge_id.as_bytes());
    append_len_prefixed(&mut payload, nonce);
    append_len_prefixed(&mut payload, device_id.as_bytes());
    append_len_prefixed(&mut payload, device_pub_key);
    sign_device_payload(device_id, &payload)
}

fn append_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn handshake_request_packet() -> io::Result<NetPacket<Vec<u8>>> {
    let mut request = HandshakeRequest::new();
    request.version = crate::SDL_VERSION.to_string();
    request
        .capabilities
        .push(CAPABILITY_UDP_ENDPOINT_REPORT_V1.to_string());
    request
        .capabilities
        .push(CAPABILITY_PUNCH_COORD_V1.to_string());
    request
        .capabilities
        .push(CAPABILITY_GATEWAY_TICKET_V1.to_string());
    let bytes = request
        .write_to_bytes()
        .map_err(|e| io::Error::other(format!("handshake_request_packet {:?}", e)))?;
    let buf = vec![0u8; HEAD_LEN + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_default_version();
    net_packet.set_destination(CONTROL_VIP);
    net_packet.set_source(HANDSHAKE_SOURCE_IP);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::HandshakeRequest.into());
    net_packet.set_initial_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    Ok(net_packet)
}

fn try_refresh_gateway_grant(control_session: &ControlSession, gateway_sessions: &GatewaySessions) {
    let current_device = control_session.current_device();
    if !current_device.status.online() {
        return;
    }
    let expire_unix_ms = gateway_sessions.ticket_expire_unix_ms();
    if expire_unix_ms <= 0 {
        return;
    }
    let now_ms = crate::handle::now_time() as i64;
    if expire_unix_ms - now_ms > 30_000 {
        return;
    }
    match control_session.send_refresh_gateway_grant_request(gateway_sessions, false) {
        Err(e) => {
            log::warn!("gateway grant refresh send failed: {:?}", e);
        }
        Ok(_) => {
            gateway_sessions.mark_refresh_requested();
            log::info!("gateway grant nearing expiration, requested dedicated refresh");
        }
    }
}
