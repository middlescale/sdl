use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};

use crate::control::ControlSession;
#[cfg(feature = "integrated_tun")]
use crate::core::context::TunSubsystem;
use crate::core::ExitNodeRoute;
use crate::core::{
    context::{
        AuthRequestConfig, DnsSubsystem, ExitNodeLocalState, ExitNodeSubsystem, GatewaySubsystem,
        PeerSubsystem, PendingRenameRequest, PendingRequestTable, RenameRequestOutcome,
        SdlContextConfig, SdlNodeState, SdlServices, PENDING_REQUEST_TTL_MS,
    },
    Config, SdlContext,
};
use crate::core::{PeerIdentity, PeerInfo};
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::data_plane::route::{Route, RouteKey};
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::route_state::RouteState;
use crate::data_plane::route_table::RouteTable;
use crate::data_plane::stats::DataPlaneStats;
use crate::handle::recv_data::RecvDataHandler;
use crate::handle::{ConnectStatus, CurrentDeviceInfo};
use crate::nat::punch::{NatInfo, Punch};
use crate::nat::punch_workers::{spawn_punch_workers, PunchCoordinator};
use crate::nat::NatTest;
use crate::transport::http3_channel::Http3Channel;
use crate::transport::udp_channel::UdpChannel;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::tun_create_helper::{DeviceAdapter, TunDeviceHelper};
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::{load_or_create_device_signing_key, DebugWatch, StopManager};
use crate::{ensure_rustls_crypto_provider, nat, DnsProfile, SdlCallback};

#[derive(Clone)]
struct NullCallback;

impl SdlCallback for NullCallback {}

pub struct Sdl {
    stop_manager: StopManager,
    config: Config,
    context: Arc<SdlContext>,
    #[cfg(all(
        feature = "integrated_tun",
        any(target_os = "windows", target_os = "linux", target_os = "macos")
    ))]
    _split_dns_stop_worker: crate::util::Worker,
}

impl Sdl {
    #[cfg(feature = "integrated_tun")]
    pub fn new<Call: SdlCallback>(config: Config, callback: Call) -> anyhow::Result<Self> {
        Sdl::init(config, callback, DeviceAdapter::default())
    }
    #[cfg(not(feature = "integrated_tun"))]
    pub fn new_device<Call: SdlCallback, Device: DeviceWrite>(
        config: Config,
        callback: Call,
        device: Device,
    ) -> anyhow::Result<Self> {
        Sdl::init(config, callback, device)
    }
    fn init<Call: SdlCallback, Device: DeviceWrite>(
        config: Config,
        callback: Call,
        device: Device,
    ) -> anyhow::Result<Self> {
        ensure_rustls_crypto_provider();
        log::info!("config: {:?}", config);
        let device_signing_key = load_or_create_device_signing_key(&config.device_id)?;
        let device_pub_key = device_signing_key.verifying_key().to_bytes().to_vec();
        //当前设备信息
        let current_device = Arc::new(AtomicCell::new(CurrentDeviceInfo::new0()));
        //设备列表
        let peer_table: Arc<RwLock<crate::core::PeerTable>> =
            Arc::new(RwLock::new(Default::default()));
        let local_ipv4 = if let Some(local_ipv4) = config.local_ipv4 {
            Some(local_ipv4)
        } else {
            nat::local_ipv4()
        };
        let default_interface = config.local_interface.clone();

        //基础信息
        let auth_request = Arc::new(RwLock::new(AuthRequestConfig {
            user_id: config.auth_user_id.clone(),
            group: config.auth_group.clone(),
            ticket: config.auth_ticket.clone(),
        }));
        let exit_node_state = Arc::new(RwLock::new(ExitNodeLocalState::default()));
        let context_config = SdlContextConfig {
            name: config.name.clone(),
            token: config.token.clone(),
            ip: config.ip,
            cipher_model: config.cipher_model,
            device_id: config.device_id.clone(),
            device_pub_key,
            server_addr: config.server_address_str.clone(),
            mtu: config.mtu.unwrap_or(crate::protocol::DEFAULT_TUN_MTU),
            #[cfg(feature = "integrated_tun")]
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            device_name: config.device_name.clone(),
            default_interface: default_interface.clone(),
        };
        // 服务停止管理器
        let stop_manager = {
            let callback = callback.clone();
            StopManager::new(move || callback.stop())
        };
        #[cfg(feature = "port_mapping")]
        crate::port_mapping::start_port_mapping(
            stop_manager.clone(),
            config.port_mapping_list.clone(),
        )?;
        let data_plane_stats = DataPlaneStats::new(config.enable_traffic);
        let udp_channel = UdpChannel::bind(&config, data_plane_stats.clone())?;
        let local_ipv6 = nat::local_ipv6();
        let udp_ports = vec![udp_channel.local_udp_port()?];
        //nat检测工具
        let nat_test = NatTest::new(
            config.stun_server.clone(),
            config.local_interface.clone(),
            udp_channel.clone(),
            local_ipv4,
            local_ipv6,
            udp_ports,
            config.local_ipv4.is_none(),
            config.punch_model,
        );
        let exit_node_route = ExitNodeRoute::new();
        let punch_coordinator = PunchCoordinator::new();
        let debug_watch = DebugWatch::default();
        let gateway_sessions = GatewaySessions::new(
            current_device.clone(),
            debug_watch.clone(),
            data_plane_stats.clone(),
        );
        let peer_crypto = Arc::new(PeerCryptoManager::new(16));
        let peer_probe_tracker = Arc::new(crate::util::PeerProbeTracker::new(16));
        let peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>> =
            Arc::new(RwLock::new(HashMap::with_capacity(16)));
        let negotiated_capabilities = Arc::new(RwLock::new(HashSet::new()));
        let gateway_grant_policy_rev = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let route_table = Arc::new(RouteTable::new(
            config.use_channel_type,
            config.latency_first,
        ));
        let route_manager = RouteManager::new(
            route_table.clone(),
            udp_channel.clone(),
            stop_manager.clone(),
            current_device.clone(),
            peer_crypto.clone(),
            peer_probe_tracker.clone(),
            true,
            std::time::Duration::from_secs(config.p2p_heartbeat_interval_sec),
            std::time::Duration::from_secs(config.p2p_route_idle_timeout_sec),
            peer_table.clone(),
        )?;
        let control_session = ControlSession::new(
            Http3Channel::new(config.server_address, &config.server_address_str)?,
            context_config.clone(),
            auth_request.clone(),
            exit_node_state.clone(),
            crate::control::SharedDataPlane {
                current_device: current_device.clone(),
                peer_crypto: peer_crypto.clone(),
                peer_table: peer_table.clone(),
                gateway_sessions: gateway_sessions.clone(),
                gateway_grant_policy_rev: gateway_grant_policy_rev.clone(),
                route_manager: route_manager.clone(),
            },
            data_plane_stats.clone(),
            nat_test.clone(),
            negotiated_capabilities.clone(),
        );
        {
            let control_session = control_session.clone();
            debug_watch.set_sender(move |event| {
                use protobuf::Message;

                let mut message = crate::proto::message::DebugWatchEvent::new();
                message.watch_id = event.watch_id;
                message.section = event.section;
                message.event_type = event.event_type;
                message.event_unix_ms = event.event_unix_ms;
                message.payload_json = event.payload_json;
                match message.write_to_bytes() {
                    Ok(bytes) => {
                        if let Err(err) = control_session.send_service_payload(
                            crate::protocol::service_packet::Protocol::DebugWatchEvent,
                            &bytes,
                        ) {
                            log::debug!("send debug watch event failed: {:?}", err);
                        }
                    }
                    Err(err) => {
                        log::debug!("encode debug watch event failed: {:?}", err);
                    }
                }
            });
        }
        {
            let control_session = control_session.clone();
            let debug_watch = debug_watch.clone();
            route_manager.set_direct_route_timeout_handler(Arc::new(move |peer_ip| {
                log::info!(
                    "last direct route expired for {}, triggering repunch",
                    peer_ip
                );
                debug_watch.emit(
                    "route",
                    "direct_route_expired",
                    serde_json::json!({
                        "peer_ip": peer_ip.to_string(),
                    }),
                );
                control_session.request_punch_status_report_with_nat_ready(
                    crate::proto::message::PunchTriggerReason::PunchTriggerRouteTimeout,
                );
            }));
        }
        {
            let callback = callback.clone();
            route_manager.set_direct_route_update_handler(Arc::new(move |peer_ip| {
                callback.direct_route_changed(peer_ip);
            }));
        }
        let context = Arc::new_cyclic(|weak_context| {
            let data_channel = DataChannel::new(weak_context.clone());
            #[cfg(feature = "integrated_tun")]
            let suspended = Arc::new(AtomicCell::new(false));
            #[cfg(feature = "integrated_tun")]
            let tun_device_helper = {
                TunDeviceHelper::new(
                    stop_manager.clone(),
                    data_channel.clone(),
                    current_device.clone(),
                    gateway_sessions.clone(),
                    exit_node_route.clone(),
                    peer_table.clone(),
                    peer_crypto.clone(),
                    config.compressor,
                    device.clone().into_device_adapter(),
                )
            };

            SdlContext {
                config: context_config.clone(),
                state: SdlNodeState {
                    auth_request: auth_request.clone(),
                    peers: PeerSubsystem {
                        table: peer_table.clone(),
                        nat_info_map: peer_nat_info_map.clone(),
                        crypto: peer_crypto.clone(),
                        probe_tracker: peer_probe_tracker.clone(),
                    },
                    gateway: GatewaySubsystem {
                        sessions: gateway_sessions.clone(),
                        grant_policy_rev: gateway_grant_policy_rev.clone(),
                    },
                    dns: DnsSubsystem {
                        profile: Arc::new(RwLock::new(None::<DnsProfile>)),
                        pending_queries: Arc::new(PendingRequestTable::new(PENDING_REQUEST_TTL_MS)),
                        #[cfg(all(
                            feature = "integrated_tun",
                            any(target_os = "windows", target_os = "linux", target_os = "macos")
                        ))]
                        last_interface: Arc::new(Mutex::new(None)),
                        #[cfg(all(
                            feature = "integrated_tun",
                            any(target_os = "windows", target_os = "linux", target_os = "macos")
                        ))]
                        applied_interface: Arc::new(Mutex::new(None)),
                        #[cfg(all(
                            feature = "integrated_tun",
                            any(target_os = "windows", target_os = "linux", target_os = "macos")
                        ))]
                        applied_profile: Arc::new(Mutex::new(None)),
                    },
                    exit_node: ExitNodeSubsystem {
                        state: exit_node_state.clone(),
                        route: exit_node_route.clone(),
                    },
                    auth_pending_block_applied: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    pending_rename_requests: Arc::new(PendingRequestTable::new(
                        PENDING_REQUEST_TTL_MS,
                    )),
                    current_device: current_device.clone(),
                    data_plane_stats: data_plane_stats.clone(),
                    debug_watch: debug_watch.clone(),
                    #[cfg(feature = "integrated_tun")]
                    tun: TunSubsystem {
                        suspended,
                        lifecycle: Arc::new(Mutex::new(())),
                        device_helper: tun_device_helper,
                    },
                },
                services: SdlServices {
                    nat_test: nat_test.clone(),
                    control_session: control_session.clone(),
                    route_manager: route_manager.clone(),
                    udp_channel: udp_channel.clone(),
                    punch_coordinator: punch_coordinator.clone(),
                },
            }
        });
        #[cfg(all(
            feature = "integrated_tun",
            any(target_os = "windows", target_os = "linux", target_os = "macos")
        ))]
        let split_dns_stop_worker = {
            let context = context.clone();
            stop_manager.add_listener("splitDns".into(), move || {
                context.revert_dns_on_shutdown();
            })?
        };
        let handler = RecvDataHandler::new(context.clone(), device, callback.clone());
        let control_handler = handler.clone();
        {
            let handler = handler.clone();
            gateway_sessions.start(stop_manager.clone(), move |mut packet, route_key| {
                let mut extend = [0u8; crate::protocol::BUFFER_SIZE];
                handler.handle(&mut packet, &mut extend, route_key);
            })?;
        }

        //初始化网络数据通道
        udp_channel.start(
            stop_manager.clone(),
            {
                let handler = handler.clone();
                move |buf, extend, route_key| handler.handle(buf, extend, route_key)
            },
            {
                let context = context.clone();
                move |addr| context.is_known_udp_source(addr)
            },
        )?;
        {
            let route_manager = route_manager.clone();
            let peer_probe_tracker = peer_probe_tracker.clone();
            let control_session = control_session.clone();
            let gateway_sessions = gateway_sessions.clone();
            let udp_channel = udp_channel.clone();
            crate::net::underlay_monitor::start_underlay_monitor(
                stop_manager.clone(),
                move || {
                    // Direct endpoints can no longer be trusted after a
                    // suspend/resume, so discard them before refreshing NAT.
                    let removed = route_manager.clear_direct_paths();
                    peer_probe_tracker.clear();
                    match udp_channel.rebind() {
                        Ok(port) => log::info!("rebound main UDP socket on port {}", port),
                        Err(err) => {
                            log::warn!("main UDP rebind after underlay change failed: {:?}", err)
                        }
                    }
                    gateway_sessions.rebuild_udp_sessions_after_underlay_change();
                    log::info!(
                        "underlay recovery invalidated {} direct P2P routes; refreshing NAT",
                        removed
                    );
                    // Refresh the control-plane NAT view without proactively
                    // coordinating peers. The next payload requests direct
                    // recovery on demand while relay remains available.
                    control_session.refresh_nat_and_report_punch_status(
                        crate::proto::message::PunchTriggerReason::StatusReportOnly,
                    );
                },
            )?;
        }
        // 打洞逻辑
        let punch = Punch::new(
            udp_channel.clone(),
            route_manager.clone(),
            config.punch_model,
            nat_test.clone(),
            current_device.clone(),
            peer_probe_tracker.clone(),
        );
        spawn_punch_workers(
            current_device.clone(),
            peer_table.clone(),
            peer_crypto.clone(),
            true,
            punch_coordinator.clone(),
            punch.clone(),
        );

        // #[cfg(not(target_os = "android"))]
        // tun_helper.start(device)?;

        context
            .services
            .control_session
            .start(stop_manager.clone(), callback.clone(), {
                let handler = control_handler;
                move |mut packet, route_key| {
                    let mut extend = [0u8; crate::protocol::BUFFER_SIZE];
                    handler.handle(&mut packet, &mut extend, route_key);
                }
            })?;
        {
            let context = context.clone();
            if !config.use_channel_type.is_only_relay() {
                context
                    .services
                    .nat_test
                    .start_refresh_task(stop_manager.clone())?;
            }
        }
        Ok(Self {
            stop_manager,
            config,
            context,
            #[cfg(all(
                feature = "integrated_tun",
                any(target_os = "windows", target_os = "linux", target_os = "macos")
            ))]
            _split_dns_stop_worker: split_dns_stop_worker,
        })
    }
}

impl Sdl {
    pub fn name(&self) -> &str {
        &self.config.name
    }
    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.context.state.current_device.load()
    }
    pub fn primary_dns_service_ip(&self) -> Option<Ipv4Addr> {
        self.context.state.dns.primary_service_ip()
    }
    #[cfg(feature = "integrated_tun")]
    pub fn tun_device_name(&self) -> Option<String> {
        self.context.state.tun.device_helper.device_name()
    }
    pub fn control_server_addr(&self) -> std::net::SocketAddr {
        self.context.services.control_session.server_addr()
    }
    pub fn current_device_info(&self) -> Arc<AtomicCell<CurrentDeviceInfo>> {
        self.context.state.current_device.clone()
    }
    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.context.state.peers.nat_info(ip)
    }
    pub fn connection_status(&self) -> ConnectStatus {
        self.context.state.current_device.load().status
    }
    pub fn nat_info(&self) -> NatInfo {
        self.context.services.nat_test.nat_info()
    }
    pub fn device_list(&self) -> Vec<PeerInfo> {
        self.context.state.peers.list()
    }
    pub fn peer_info(&self, ip: &Ipv4Addr) -> Option<PeerInfo> {
        self.context.state.peers.info(ip)
    }
    pub fn peer_vip_for_identity(&self, identity: &PeerIdentity) -> Option<Ipv4Addr> {
        self.context.state.peers.vip_for_identity(identity)
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Route> {
        self.context.services.route_manager.best_route(ip)
    }
    pub fn is_peer_active(&self, ip: &Ipv4Addr) -> bool {
        self.context.services.route_manager.is_peer_active(ip)
    }
    pub fn is_gateway(&self, ip: &Ipv4Addr) -> bool {
        self.context.state.current_device.load().is_gateway_vip(ip)
    }
    pub fn route_key(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        self.context
            .services
            .route_manager
            .peer_for_direct_route(route_key)
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.context.services.route_manager.snapshot_routes()
    }
    pub fn gateway_session_summary(
        &self,
    ) -> crate::data_plane::gateway_session::GatewaySessionSummary {
        self.context.state.gateway.sessions.session_summary()
    }
    pub fn gateway_session_summaries(
        &self,
    ) -> Vec<crate::data_plane::gateway_session::GatewaySessionSummary> {
        self.context.state.gateway.sessions.session_summaries()
    }

    pub fn peer_relay_health_summary(
        &self,
        ip: Ipv4Addr,
    ) -> crate::data_plane::gateway_session::PeerRelayHealthSummary {
        self.context
            .state
            .gateway
            .sessions
            .peer_relay_health_summary(ip)
    }
    pub fn set_gateway_selection(&self, endpoint: Option<SocketAddr>) -> anyhow::Result<()> {
        self.context
            .state
            .gateway
            .sessions
            .set_manual_endpoint(endpoint)
    }
    pub fn use_channel_type(&self) -> crate::data_plane::use_channel_type::UseChannelType {
        self.context.services.route_manager.use_channel_type()
    }
    pub fn set_use_channel_type(
        &self,
        use_channel_type: crate::data_plane::use_channel_type::UseChannelType,
    ) {
        let previous = self.context.services.route_manager.use_channel_type();
        if previous == use_channel_type {
            return;
        }
        self.context
            .services
            .route_manager
            .set_use_channel_type(use_channel_type);
        if use_channel_type.is_only_relay() {
            if let Err(err) = self
                .context
                .services
                .control_session
                .send_client_status_report_packet()
            {
                log::warn!("failed to report relay channel mode: {:?}", err);
            }
        } else {
            self.context
                .services
                .control_session
                .request_punch_status_report_with_nat_ready(
                    crate::proto::message::PunchTriggerReason::PunchTriggerManualRequest,
                );
        }
    }
    pub fn request_device_auth(
        &self,
        user_id: String,
        group: String,
        ticket: String,
    ) -> anyhow::Result<()> {
        {
            let mut auth_request = self.context.state.auth_request.write();
            auth_request.user_id = Some(user_id);
            auth_request.group = Some(group);
            auth_request.ticket = Some(ticket);
        }
        self.context
            .services
            .control_session
            .send_device_auth_request()
    }
    pub fn block_data_plane_for_auth_pending(&self) {
        self.context.block_data_plane_for_auth_pending();
    }
    pub fn request_device_rename(
        &self,
        new_name: String,
        timeout: Duration,
    ) -> anyhow::Result<RenameRequestOutcome> {
        let (sender, receiver) = mpsc::channel();
        let request_id = self
            .context
            .state
            .pending_rename_requests
            .remember(PendingRenameRequest { responder: sender });
        if let Err(err) = self
            .context
            .services
            .control_session
            .send_device_rename_request(request_id, new_name)
        {
            self.context
                .state
                .pending_rename_requests
                .forget(request_id);
            return Err(err);
        }
        match receiver.recv_timeout(timeout) {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(reason)) => anyhow::bail!("rename rejected: {}", reason),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.context
                    .state
                    .pending_rename_requests
                    .forget(request_id);
                anyhow::bail!("rename request timed out")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.context
                    .state
                    .pending_rename_requests
                    .forget(request_id);
                anyhow::bail!("rename response channel disconnected")
            }
        }
    }
    pub fn set_exit_node_state(&self, state: ExitNodeLocalState) {
        let should_report_status = self.context.set_exit_node_state(state);
        if should_report_status {
            self.context.services.control_session.report_client_status();
        }
    }
    pub fn exit_node_state(&self) -> ExitNodeLocalState {
        self.context.state.exit_node.snapshot()
    }
    pub fn route_states(&self) -> Vec<(Ipv4Addr, Vec<RouteState>)> {
        let current_device = self.context.state.current_device.load();
        self.context
            .services
            .route_manager
            .snapshot_route_states(current_device.virtual_gateway)
    }
    pub fn up_stream(&self) -> u64 {
        self.context.state.data_plane_stats.up_traffic_total()
    }
    pub fn up_stream_all(&self) -> Option<(u64, HashMap<usize, u64>)> {
        self.context.state.data_plane_stats.up_traffic_all()
    }
    pub fn up_stream_history(&self) -> Option<(u64, HashMap<usize, (u64, Vec<usize>)>)> {
        self.context.state.data_plane_stats.up_traffic_history()
    }
    pub fn down_stream(&self) -> u64 {
        self.context.state.data_plane_stats.down_traffic_total()
    }
    pub fn down_stream_all(&self) -> Option<(u64, HashMap<usize, u64>)> {
        self.context.state.data_plane_stats.down_traffic_all()
    }
    pub fn down_stream_history(&self) -> Option<(u64, HashMap<usize, (u64, Vec<usize>)>)> {
        self.context.state.data_plane_stats.down_traffic_history()
    }
    pub fn up_stream_by_peer(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.context.state.data_plane_stats.up_peer_traffic_all()
    }
    pub fn down_stream_by_peer(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.context.state.data_plane_stats.down_peer_traffic_all()
    }
    pub fn up_rate_by_peer(&self, window_secs: usize) -> Option<HashMap<Ipv4Addr, u64>> {
        self.context
            .state
            .data_plane_stats
            .up_peer_traffic_rates(window_secs)
    }
    pub fn down_rate_by_peer(&self, window_secs: usize) -> Option<HashMap<Ipv4Addr, u64>> {
        self.context
            .state
            .data_plane_stats
            .down_peer_traffic_rates(window_secs)
    }
    pub fn up_active_speed_by_peer(&self) -> Option<HashMap<Ipv4Addr, u64>> {
        self.context.state.data_plane_stats.up_peer_active_speeds()
    }
    pub fn down_active_speed_by_peer(&self) -> Option<HashMap<Ipv4Addr, u64>> {
        self.context
            .state
            .data_plane_stats
            .down_peer_active_speeds()
    }
    pub fn up_stream_by_transport(&self) -> Option<(u64, HashMap<std::net::IpAddr, u64>)> {
        self.context
            .state
            .data_plane_stats
            .up_transport_traffic_all()
    }
    pub fn down_stream_by_transport(&self) -> Option<(u64, HashMap<std::net::IpAddr, u64>)> {
        self.context
            .state
            .data_plane_stats
            .down_transport_traffic_all()
    }
    pub fn up_rate_by_transport(
        &self,
        window_secs: usize,
    ) -> Option<HashMap<std::net::IpAddr, u64>> {
        self.context
            .state
            .data_plane_stats
            .up_transport_traffic_rates(window_secs)
    }
    pub fn down_rate_by_transport(
        &self,
        window_secs: usize,
    ) -> Option<HashMap<std::net::IpAddr, u64>> {
        self.context
            .state
            .data_plane_stats
            .down_transport_traffic_rates(window_secs)
    }
    pub fn up_active_speed_by_transport(&self) -> Option<HashMap<std::net::IpAddr, u64>> {
        self.context
            .state
            .data_plane_stats
            .up_transport_active_speeds()
    }
    pub fn down_active_speed_by_transport(&self) -> Option<HashMap<std::net::IpAddr, u64>> {
        self.context
            .state
            .data_plane_stats
            .down_transport_active_speeds()
    }
    pub fn logical_up_stream(&self) -> u64 {
        self.context.state.data_plane_stats.logical_up_total()
    }
    pub fn logical_down_stream(&self) -> u64 {
        self.context.state.data_plane_stats.logical_down_total()
    }
    pub fn gateway_up_stream(&self) -> u64 {
        self.context.state.data_plane_stats.gateway_up_total()
    }
    pub fn gateway_down_stream(&self) -> u64 {
        self.context.state.data_plane_stats.gateway_down_total()
    }
    pub fn gateway_up_rate(&self, window_secs: usize) -> u64 {
        self.context
            .state
            .data_plane_stats
            .gateway_up_rate(window_secs)
    }
    pub fn gateway_down_rate(&self, window_secs: usize) -> u64 {
        self.context
            .state
            .data_plane_stats
            .gateway_down_rate(window_secs)
    }
    pub fn gateway_up_active_speed(&self) -> u64 {
        self.context
            .state
            .data_plane_stats
            .gateway_up_active_speed()
    }
    pub fn gateway_down_active_speed(&self) -> u64 {
        self.context
            .state
            .data_plane_stats
            .gateway_down_active_speed()
    }
    pub fn transport_up_stream(&self) -> u64 {
        self.context
            .state
            .data_plane_stats
            .up_transport_traffic_all()
            .map(|(total, _)| total)
            .unwrap_or(0)
    }
    pub fn transport_down_stream(&self) -> u64 {
        self.context
            .state
            .data_plane_stats
            .down_transport_traffic_all()
            .map(|(total, _)| total)
            .unwrap_or(0)
    }
    pub fn suspend(&self) -> anyhow::Result<()> {
        #[cfg(feature = "integrated_tun")]
        {
            self.context.suspend();
            return Ok(());
        }
        #[cfg(not(feature = "integrated_tun"))]
        {
            anyhow::bail!("suspend requires integrated_tun support")
        }
    }
    pub fn resume(&self) -> anyhow::Result<()> {
        #[cfg(feature = "integrated_tun")]
        {
            return self.context.resume(&NullCallback);
        }
        #[cfg(not(feature = "integrated_tun"))]
        {
            anyhow::bail!("resume requires integrated_tun support")
        }
    }
    pub fn is_suspended(&self) -> bool {
        #[cfg(feature = "integrated_tun")]
        {
            return self.context.is_suspended();
        }
        #[cfg(not(feature = "integrated_tun"))]
        {
            false
        }
    }
    pub fn stop(&self) {
        self.stop_manager.stop()
    }
    pub fn is_stopped(&self) -> bool {
        self.stop_manager.is_stopped()
    }
    pub fn add_stop_listener<F>(&self, name: String, f: F) -> anyhow::Result<crate::util::Worker>
    where
        F: FnOnce() + Send + 'static,
    {
        self.stop_manager.add_listener(name, f)
    }
    pub fn wait(&self) {
        self.stop_manager.wait()
    }
    pub fn wait_timeout(&self, dur: Duration) -> bool {
        self.stop_manager.wait_timeout(dur)
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl Drop for Sdl {
    fn drop(&mut self) {
        self.stop();
    }
}
