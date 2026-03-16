use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crossbeam_utils::atomic::AtomicCell;
use protobuf::Message;
use std::sync::Arc;

use crate::channel::context::ChannelContext;
use crate::core::RuntimeConfig;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::handle::callback::{ConnectInfo, ErrorType};
use crate::handle::handshaker::Handshake;
use crate::handle::registrar;
use crate::handle::PeerDeviceInfo;
use crate::handle::{CurrentDeviceInfo, CONTROL_VIP};
use crate::nat::NatTest;
use crate::proto::message::{
    ClientStatusInfo, PunchNatType, RefreshGatewayGrantRequest, RouteItem,
};
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{service_packet, NetPacket, Protocol, HEAD_LEN, MAX_TTL};
use crate::transport::quic_channel::QuicChannel;
use crate::util::{address_choose, dns_query_all, Scheduler, StopManager};
use crate::{ErrorInfo, VntCallback};
use parking_lot::Mutex;

#[derive(Clone)]
pub struct ControlSession {
    channel: QuicChannel,
    config: RuntimeConfig,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
}

impl ControlSession {
    pub fn new(
        channel: QuicChannel,
        config: RuntimeConfig,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ) -> Self {
        Self {
            channel,
            config,
            current_device,
        }
    }

    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.current_device.load()
    }

    pub fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        let current_device = self.current_device();
        self.channel
            .update_server_addr(current_device.control_server);
        self.channel.send_packet(packet)
    }

    pub fn send_handshake(&self) -> io::Result<()> {
        let request_packet = Handshake::new().handshake_request_packet(false)?;
        self.send_packet(&request_packet)
    }

    pub fn start<Call: VntCallback, F>(
        &self,
        stop_manager: StopManager,
        device_map: Arc<
            Mutex<(
                u16,
                std::collections::HashMap<std::net::Ipv4Addr, PeerDeviceInfo>,
            )>,
        >,
        gateway_sessions: GatewaySessions,
        call: Call,
        on_packet: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, crate::channel::RouteKey) + Send + Sync + 'static,
    {
        self.channel.start(stop_manager.clone(), on_packet)?;
        let (stop_sender, stop_receiver) = mpsc::channel::<()>();
        let worker = stop_manager.add_listener("controlSession".into(), move || {
            let _ = stop_sender.send(());
        })?;
        let control_session = self.clone();
        thread::Builder::new()
            .name("controlSession".into())
            .spawn(move || {
                control_session.run(device_map, gateway_sessions, call, stop_receiver);
                drop(worker);
            })?;
        Ok(())
    }

    fn maintain_connection<Call: VntCallback>(
        &self,
        call: &Call,
        connect_count: &mut usize,
    ) -> io::Result<()> {
        let current_device_info = &self.current_device;
        let mut current_device = current_device_info.load();
        if current_device.status.offline() {
            *connect_count += 1;
            current_device = resolve_control_addr(current_device_info, &self.config);
            call.connect(ConnectInfo::new(
                *connect_count,
                current_device.control_server,
            ));
            log::info!("发送握手请求,{:?}", self.config);
            if let Err(e) = self.send_handshake() {
                log::warn!("{:?}", e);
                return Err(e);
            }
        }
        Ok(())
    }

    fn run<Call: VntCallback>(
        &self,
        device_map: Arc<
            Mutex<(
                u16,
                std::collections::HashMap<std::net::Ipv4Addr, PeerDeviceInfo>,
            )>,
        >,
        gateway_sessions: GatewaySessions,
        call: Call,
        stop_receiver: mpsc::Receiver<()>,
    ) {
        let mut connect_count = 0usize;
        let mut last_connect_at = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .unwrap_or_else(Instant::now);
        let mut last_heartbeat_at = Instant::now()
            .checked_sub(Duration::from_secs(3))
            .unwrap_or_else(Instant::now);
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
                    let cur = self.current_device();
                    call.error(ErrorInfo::new_msg(
                        ErrorType::Disconnect,
                        format!("connect:{},error:{:?}", cur.control_server, e),
                    ));
                }
                continue;
            }
            if last_heartbeat_at.elapsed() < Duration::from_secs(3) {
                continue;
            }
            last_heartbeat_at = Instant::now();
            match self.send_server_heartbeat(device_map.lock().0) {
                Ok(_) => {}
                Err(e) => {
                    log::warn!("heartbeat err={:?}", e);
                }
            }
            try_refresh_gateway_grant(self, &gateway_sessions);
        }
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
        let packet = registrar::registration_request_packet(
            self.config.token.clone(),
            self.config.device_id.clone(),
            self.config.device_pub_key.clone(),
            self.config.device_pub_key_alg.clone(),
            self.config.name.clone(),
            ip,
            is_fast,
            allow_ip_change,
            self.config.client_secret_hash.as_ref().map(|v| v.as_ref()),
        )?;
        self.send_packet(&packet)?;
        Ok(())
    }

    pub fn send_device_auth_request(&self) -> anyhow::Result<()> {
        let (Some(user_id), Some(group), Some(ticket)) = (
            self.config.auth_user_id.as_ref(),
            self.config.auth_group.as_ref(),
            self.config.auth_ticket.as_ref(),
        ) else {
            anyhow::bail!("auth-device requires user/group/ticket");
        };
        let packet = registrar::device_auth_request_packet(
            user_id.clone(),
            group.clone(),
            self.config.device_id.clone(),
            ticket.clone(),
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

    pub fn start_status_reporter(
        &self,
        scheduler: &Scheduler,
        context: ChannelContext,
        nat_test: NatTest,
    ) {
        let control_session = self.clone();
        let _ = scheduler.timeout(Duration::from_secs(60), move |x| {
            control_session.status_report_tick(x, context, nat_test)
        });
    }

    pub fn trigger_status_report(&self, context: &ChannelContext, nat_test: &NatTest) {
        if let Err(e) = self.send_status_report_packet(context, nat_test) {
            log::warn!("{:?}", e)
        }
    }

    pub fn trigger_status_report_with_nat_ready(&self, context: ChannelContext, nat_test: NatTest) {
        let control_session = self.clone();
        thread::Builder::new()
            .name("upStatusEvent".into())
            .spawn(move || {
                let nat_info = nat_test.nat_info();
                if !has_public_endpoints(&nat_info.public_ips, &nat_info.public_ports) {
                    if let Ok((data, addr)) = nat_test.send_data() {
                        let _ = context.send_main_udp(0, &data, addr);
                    }
                    thread::sleep(Duration::from_secs(2));
                }
                if let Err(e) = control_session.send_status_report_packet(&context, &nat_test) {
                    log::warn!("{:?}", e)
                }
            })
            .expect("upStatusEvent");
    }

    fn status_report_tick(
        &self,
        scheduler: &Scheduler,
        context: ChannelContext,
        nat_test: NatTest,
    ) {
        if let Err(e) = self.send_status_report_packet(&context, &nat_test) {
            log::warn!("{:?}", e)
        }
        let control_session = self.clone();
        let rs = scheduler.timeout(Duration::from_secs(10 * 60), move |x| {
            control_session.status_report_tick(x, context, nat_test)
        });
        if !rs {
            log::info!("定时任务停止");
        }
    }

    fn send_status_report_packet(
        &self,
        context: &ChannelContext,
        nat_test: &NatTest,
    ) -> io::Result<()> {
        let device_info = self.current_device();
        if device_info.status.offline() {
            return Ok(());
        }
        let routes = context.route_manager().snapshot_direct_routes();
        let mut message = ClientStatusInfo::new();
        message.source = device_info.virtual_ip.into();
        for (ip, _) in routes {
            let mut item = RouteItem::new();
            item.next_ip = ip.into();
            message.p2p_list.push(item);
        }
        message.up_stream = context.up_traffic_meter.as_ref().map_or(0, |v| v.total());
        message.down_stream = context.down_traffic_meter.as_ref().map_or(0, |v| v.total());
        message.nat_type = protobuf::EnumOrUnknown::new(if context.is_cone() {
            PunchNatType::Cone
        } else {
            PunchNatType::Symmetric
        });
        let nat_info = nat_test.nat_info();
        message.public_ip_list = nat_info
            .public_ips
            .iter()
            .map(|ip| u32::from(*ip))
            .collect();
        message.public_udp_ports = nat_info.public_ports.iter().map(|p| *p as u32).collect();
        message.local_udp_ports = nat_info.udp_ports.iter().map(|p| *p as u32).collect();
        let buf = message.write_to_bytes().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("up_status_packet {:?}", e))
        })?;
        self.send_service_payload(service_packet::Protocol::ClientStatusInfo, &buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(())
    }
}

fn has_public_endpoints(public_ips: &[std::net::Ipv4Addr], public_ports: &[u16]) -> bool {
    !public_ips.is_empty() && !public_ports.is_empty()
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

fn resolve_control_addr(
    current_device: &AtomicCell<CurrentDeviceInfo>,
    config: &RuntimeConfig,
) -> CurrentDeviceInfo {
    let mut current_dev = current_device.load();
    let default_interface = &config.default_interface;
    match dns_query_all(
        &config.server_addr,
        config.name_servers.clone(),
        default_interface,
    ) {
        Ok(addrs) => {
            log::info!(
                "domain {} dns {:?} addr {:?}",
                config.server_addr,
                config.name_servers,
                addrs
            );
            match address_choose(addrs) {
                Ok(addr) => {
                    if addr != current_dev.control_server {
                        let mut tmp = current_dev;
                        tmp.control_server = addr;
                        let rs = current_device.compare_exchange(current_dev, tmp);
                        log::info!(
                            "服务端地址变化,旧地址:{}，新地址:{},替换结果:{}",
                            current_dev.control_server,
                            addr,
                            rs.is_ok()
                        );
                        if rs.is_ok() {
                            current_dev.control_server = addr;
                        }
                    }
                }
                Err(e) => {
                    log::error!("域名地址选择失败:{:?},domain={}", e, config.server_addr);
                }
            }
        }
        Err(e) => {
            log::error!("域名解析失败:{:?},domain={}", e, config.server_addr);
        }
    }
    current_dev
}
