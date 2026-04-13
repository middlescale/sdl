use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};

use crate::control::ControlSession;
use crate::core::{
    runtime::{AuthRequestConfig, RenameRequestOutcome},
    Config, RuntimeConfig, SdlRuntime,
};
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::route::{Route, RoutePath};
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::route_snapshot::RouteSnapshot;
use crate::data_plane::route_table::RouteTable;
use crate::data_plane::stats::DataPlaneStats;
use crate::external_route::{AllowExternalRoute, ExternalRoute};
use crate::handle::recv_data::RecvDataHandler;
use crate::handle::{ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::punch::{NatInfo, Punch};
use crate::nat::punch_workers::{spawn_punch_workers, PunchCoordinator};
use crate::nat::NatTest;
use crate::transport::http3_channel::Http3Channel;
use crate::transport::udp_channel::UdpChannel;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::tun_create_helper::{DeviceAdapter, TunDeviceHelper};
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::{load_or_create_device_signing_key, DebugWatch, PeerCryptoManager, StopManager};
use crate::{nat, DnsProfile, SdlCallback};

#[derive(Clone)]
struct NullCallback;

impl SdlCallback for NullCallback {}

pub struct Sdl {
    stop_manager: StopManager,
    config: Config,
    runtime: Arc<SdlRuntime>,
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
        log::info!("config: {:?}", config);
        let device_signing_key = Arc::new(load_or_create_device_signing_key(&config.device_id)?);
        let device_pub_key = device_signing_key.verifying_key().to_bytes().to_vec();
        //当前设备信息
        let current_device = Arc::new(AtomicCell::new(CurrentDeviceInfo::new0()));
        //设备列表
        let peer_state: Arc<Mutex<crate::handle::PeerState>> =
            Arc::new(Mutex::new(Default::default()));
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
        let runtime_config = RuntimeConfig {
            name: config.name.clone(),
            token: config.token.clone(),
            ip: config.ip,
            cipher_model: config.cipher_model,
            device_id: config.device_id.clone(),
            device_pub_key,
            server_addr: config.server_address_str.clone(),
            mtu: config.mtu.unwrap_or(1420),
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            tap: config.tap,
            #[cfg(feature = "integrated_tun")]
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            device_name: config.device_name.clone(),
            default_interface: default_interface.clone(),
            auth_request: auth_request.clone(),
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
        let external_route = ExternalRoute::new(config.in_ips.clone());
        let out_external_route = AllowExternalRoute::new(config.out_ips.clone());
        let punch_coordinator = PunchCoordinator::new();
        let debug_watch = DebugWatch::default();
        let gateway_sessions = GatewaySessions::new(current_device.clone(), debug_watch.clone());
        let peer_crypto = Arc::new(PeerCryptoManager::new(16));
        let unknown_peer_ingress_limiter = Arc::new(crate::util::PeerIngressLimiter::new(16));
        let peer_replay_guard = Arc::new(crate::util::PeerReplayGuard::new(16));
        let unknown_peer_setup_limiter = Arc::new(crate::util::PeerSetupLimiter::new(16));
        let peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>> =
            Arc::new(RwLock::new(HashMap::with_capacity(16)));
        let pending_peer_discovery_sessions: Arc<
            Mutex<HashMap<Ipv4Addr, crate::core::runtime::PeerDiscoverySession>>,
        > = Arc::new(Mutex::new(HashMap::with_capacity(16)));
        let pending_peer_discovery_initiators = Arc::new(Mutex::new(HashMap::with_capacity(16)));
        let negotiated_capabilities = Arc::new(RwLock::new(HashSet::new()));
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
            true,
            std::time::Duration::from_secs(config.p2p_heartbeat_interval_sec),
            std::time::Duration::from_secs(config.p2p_route_idle_timeout_sec),
        )?;
        let control_session = ControlSession::new(
            Http3Channel::new(config.server_address, &config.server_address_str)?,
            runtime_config.clone(),
            crate::control::SharedDataPlane {
                current_device: current_device.clone(),
                peer_crypto: peer_crypto.clone(),
                peer_state: peer_state.clone(),
                gateway_sessions: gateway_sessions.clone(),
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
                control_session.trigger_status_report_with_nat_ready(
                    crate::proto::message::PunchTriggerReason::PunchTriggerRouteTimeout,
                );
            }));
        }
        let runtime = Arc::new_cyclic(|weak_runtime| {
            let data_channel = DataChannel::new(weak_runtime.clone());
            #[cfg(feature = "integrated_tun")]
            let suspended = Arc::new(AtomicCell::new(false));
            #[cfg(feature = "integrated_tun")]
            let tun_device_helper = {
                TunDeviceHelper::new(
                    stop_manager.clone(),
                    data_channel.clone(),
                    current_device.clone(),
                    gateway_sessions.clone(),
                    external_route.clone(),
                    peer_state.clone(),
                    peer_crypto.clone(),
                    config.compressor,
                    device.clone().into_device_adapter(),
                )
            };

            SdlRuntime {
                config: runtime_config.clone(),
                dns_profile: Arc::new(RwLock::new(None::<DnsProfile>)),
                dns_query_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                pending_dns_queries: Arc::new(Mutex::new(std::collections::HashMap::new())),
                rename_request_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                pending_rename_requests: Arc::new(Mutex::new(std::collections::HashMap::new())),
                current_device: current_device.clone(),
                device_signing_key: device_signing_key.clone(),
                peer_crypto: peer_crypto.clone(),
                unknown_peer_ingress_limiter: unknown_peer_ingress_limiter.clone(),
                peer_replay_guard: peer_replay_guard.clone(),
                unknown_peer_setup_limiter: unknown_peer_setup_limiter.clone(),
                debug_watch: debug_watch.clone(),
                nat_test: nat_test.clone(),
                peer_state: peer_state.clone(),
                peer_nat_info_map: peer_nat_info_map.clone(),
                pending_peer_discovery_sessions: pending_peer_discovery_sessions.clone(),
                pending_peer_discovery_initiators: pending_peer_discovery_initiators.clone(),
                external_route: external_route.clone(),
                out_external_route: out_external_route.clone(),
                control_session: control_session.clone(),
                gateway_sessions: gateway_sessions.clone(),
                route_manager: route_manager.clone(),
                data_plane_stats: data_plane_stats.clone(),
                udp_channel: udp_channel.clone(),
                data_channel,
                punch_coordinator: punch_coordinator.clone(),
                #[cfg(feature = "integrated_tun")]
                suspended,
                #[cfg(feature = "integrated_tun")]
                tun_lifecycle: Arc::new(Mutex::new(())),
                #[cfg(feature = "integrated_tun")]
                tun_device_helper,
                #[cfg(all(feature = "integrated_tun", target_os = "linux"))]
                applied_dns_interface: Arc::new(Mutex::new(None)),
                #[cfg(all(
                    feature = "integrated_tun",
                    any(target_os = "macos", target_os = "windows")
                ))]
                applied_dns_domains: Arc::new(Mutex::new(Vec::new())),
            }
        });
        #[cfg(all(
            feature = "integrated_tun",
            any(target_os = "windows", target_os = "linux", target_os = "macos")
        ))]
        let split_dns_stop_worker = {
            let runtime = runtime.clone();
            stop_manager.add_listener("splitDns".into(), move || {
                runtime.revert_dns_on_shutdown();
            })?
        };
        let handler = RecvDataHandler::new(runtime.clone(), device, callback.clone());
        let control_handler = handler.clone();
        {
            let handler = handler.clone();
            gateway_sessions.start(stop_manager.clone(), move |mut packet, route_key| {
                let mut extend = [0u8; crate::protocol::BUFFER_SIZE];
                handler.handle(&mut packet, &mut extend, route_key);
            })?;
        }

        //初始化网络数据通道
        udp_channel.start(stop_manager.clone(), {
            let handler = handler.clone();
            move |buf, extend, route_key| handler.handle(buf, extend, route_key)
        })?;
        // 打洞逻辑
        let punch = Punch::new(
            udp_channel.clone(),
            route_manager.clone(),
            config.punch_model,
            nat_test.clone(),
            current_device.clone(),
        );
        spawn_punch_workers(runtime.clone(), punch_coordinator.clone(), punch.clone());

        // #[cfg(not(target_os = "android"))]
        // tun_helper.start(device)?;

        runtime
            .control_session
            .start(stop_manager.clone(), callback.clone(), {
                let handler = control_handler;
                move |mut packet, route_key| {
                    let mut extend = [0u8; crate::protocol::BUFFER_SIZE];
                    handler.handle(&mut packet, &mut extend, route_key);
                }
            })?;
        {
            let runtime = runtime.clone();
            if !config.use_channel_type.is_only_relay() {
                runtime.nat_test.start_refresh_task(stop_manager.clone())?;
            }
        }
        Ok(Self {
            stop_manager,
            config,
            runtime,
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
        self.runtime.current_device.load()
    }
    pub fn control_server_addr(&self) -> std::net::SocketAddr {
        self.runtime.control_session.server_addr()
    }
    pub fn current_device_info(&self) -> Arc<AtomicCell<CurrentDeviceInfo>> {
        self.runtime.current_device.clone()
    }
    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.runtime.peer_nat_info_map.read().get(ip).cloned()
    }
    pub fn connection_status(&self) -> ConnectStatus {
        self.runtime.current_device.load().status
    }
    pub fn nat_info(&self) -> NatInfo {
        self.runtime.nat_test.nat_info()
    }
    pub fn device_list(&self) -> Vec<PeerDeviceInfo> {
        let device_list_lock = self.runtime.peer_state.lock();
        let device_list = device_list_lock.devices.clone();
        drop(device_list_lock);
        device_list.into_values().collect::<Vec<_>>()
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Route> {
        self.runtime.route_manager().best_route(ip)
    }
    pub fn is_gateway(&self, ip: &Ipv4Addr) -> bool {
        self.runtime.current_device.load().is_gateway_vip(ip)
    }
    pub fn route_key(&self, route_key: &RoutePath) -> Option<Ipv4Addr> {
        self.runtime
            .route_manager()
            .peer_for_direct_route(route_key)
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.runtime.route_manager().snapshot_routes()
    }
    pub fn gateway_session_summary(
        &self,
    ) -> crate::data_plane::gateway_session::GatewaySessionSummary {
        self.runtime.gateway_sessions.session_summary()
    }
    pub fn use_channel_type(&self) -> crate::data_plane::use_channel_type::UseChannelType {
        self.runtime.route_manager().use_channel_type()
    }
    pub fn set_use_channel_type(
        &self,
        use_channel_type: crate::data_plane::use_channel_type::UseChannelType,
    ) {
        self.runtime
            .route_manager()
            .set_use_channel_type(use_channel_type);
    }
    pub fn request_device_auth(
        &self,
        user_id: String,
        group: String,
        ticket: String,
    ) -> anyhow::Result<()> {
        {
            let mut auth_request = self.runtime.config.auth_request.write();
            auth_request.user_id = Some(user_id);
            auth_request.group = Some(group);
            auth_request.ticket = Some(ticket);
        }
        self.runtime.control_session.send_device_auth_request()
    }
    pub fn request_device_rename(
        &self,
        new_name: String,
        timeout: Duration,
    ) -> anyhow::Result<RenameRequestOutcome> {
        let (sender, receiver) = mpsc::channel();
        let request_id = self.runtime.remember_rename_request(sender);
        if let Err(err) = self
            .runtime
            .control_session
            .send_device_rename_request(request_id, new_name)
        {
            self.runtime.forget_rename_request(request_id);
            return Err(err);
        }
        match receiver.recv_timeout(timeout) {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(reason)) => anyhow::bail!("rename rejected: {}", reason),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.runtime.forget_rename_request(request_id);
                anyhow::bail!("rename request timed out")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.runtime.forget_rename_request(request_id);
                anyhow::bail!("rename response channel disconnected")
            }
        }
    }
    pub fn route_snapshots(&self) -> Vec<RouteSnapshot> {
        self.runtime.route_manager().snapshot_route_snapshots()
    }
    pub fn up_stream(&self) -> u64 {
        self.runtime.data_plane_stats.up_traffic_total()
    }
    pub fn up_stream_all(&self) -> Option<(u64, HashMap<usize, u64>)> {
        self.runtime.data_plane_stats.up_traffic_all()
    }
    pub fn up_stream_history(&self) -> Option<(u64, HashMap<usize, (u64, Vec<usize>)>)> {
        self.runtime.data_plane_stats.up_traffic_history()
    }
    pub fn down_stream(&self) -> u64 {
        self.runtime.data_plane_stats.down_traffic_total()
    }
    pub fn down_stream_all(&self) -> Option<(u64, HashMap<usize, u64>)> {
        self.runtime.data_plane_stats.down_traffic_all()
    }
    pub fn down_stream_history(&self) -> Option<(u64, HashMap<usize, (u64, Vec<usize>)>)> {
        self.runtime.data_plane_stats.down_traffic_history()
    }
    pub fn suspend(&self) -> anyhow::Result<()> {
        #[cfg(feature = "integrated_tun")]
        {
            self.runtime.suspend();
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
            return self.runtime.resume(&NullCallback);
        }
        #[cfg(not(feature = "integrated_tun"))]
        {
            anyhow::bail!("resume requires integrated_tun support")
        }
    }
    pub fn is_suspended(&self) -> bool {
        #[cfg(feature = "integrated_tun")]
        {
            return self.runtime.is_suspended();
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
