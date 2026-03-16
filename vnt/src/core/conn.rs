use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc::channel;

use crate::channel::context::ChannelContext;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::punch::{NatInfo, Punch};
use crate::channel::punch_workers::{spawn_punch_workers, PunchCoordinator};
use crate::channel::sender::IpPacketSender;
use crate::channel::{Route, RouteKey};
use crate::cipher::Cipher;
use crate::compression::Compressor;
use crate::control::ControlSession;
use crate::core::{Config, RuntimeConfig, VntRuntime};
use crate::data_plane::data_channel::DataChannel;
use crate::data_plane::gateway_session::GatewaySessions;
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::route_state::RouteState;
use crate::external_route::{AllowExternalRoute, ExternalRoute};
use crate::handle::recv_data::RecvDataHandler;
use crate::handle::{maintain, ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::NatTest;
#[cfg(feature = "quic")]
use crate::transport::quic_channel::quic_connect_accept;
use crate::transport::quic_channel::QuicChannel;
use crate::transport::udp_channel::UdpChannel;
#[cfg(feature = "integrated_tun")]
use crate::tun_tap_device::tun_create_helper::{DeviceAdapter, TunDeviceHelper};
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::limit::TrafficMeterMultiAddress;
use crate::util::{device_key_alg, load_or_create_device_public_key, Scheduler, StopManager};
use crate::{nat, VntCallback};

#[derive(Clone)]
pub struct Vnt {
    inner: Arc<VntInner>,
}

impl Vnt {
    #[cfg(feature = "integrated_tun")]
    pub fn new<Call: VntCallback>(config: Config, callback: Call) -> anyhow::Result<Self> {
        let inner = Arc::new(VntInner::new(config, callback)?);
        Ok(Self { inner })
    }
    #[cfg(not(feature = "integrated_tun"))]
    pub fn new_device<Call: VntCallback, Device: DeviceWrite>(
        config: Config,
        callback: Call,
        device: Device,
    ) -> anyhow::Result<Self> {
        let inner = Arc::new(VntInner::new_device(config, callback, device)?);
        Ok(Self { inner })
    }
}

impl Deref for Vnt {
    type Target = VntInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct VntInner {
    stop_manager: StopManager,
    config: Config,
    runtime: Arc<VntRuntime>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    context: Arc<Mutex<Option<ChannelContext>>>,
    peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
    client_secret_hash: Option<[u8; 16]>,
    compressor: Compressor,
    client_cipher: Cipher,
    external_route: ExternalRoute,
    up_traffic_meter: Option<TrafficMeterMultiAddress>,
    down_traffic_meter: Option<TrafficMeterMultiAddress>,
}

impl VntInner {
    #[cfg(feature = "integrated_tun")]
    pub fn new<Call: VntCallback>(config: Config, callback: Call) -> anyhow::Result<Self> {
        VntInner::new_device0(config, callback, DeviceAdapter::default())
    }
    #[cfg(not(feature = "integrated_tun"))]
    pub fn new_device<Call: VntCallback, Device: DeviceWrite>(
        config: Config,
        callback: Call,
        device: Device,
    ) -> anyhow::Result<Self> {
        VntInner::new_device0(config, callback, device)
    }
    fn new_device0<Call: VntCallback, Device: DeviceWrite>(
        config: Config,
        callback: Call,
        device: Device,
    ) -> anyhow::Result<Self> {
        log::info!("config: {:?}", config);
        let (up_traffic_meter, down_traffic_meter) = if config.enable_traffic {
            (
                Some(TrafficMeterMultiAddress::default()),
                Some(TrafficMeterMultiAddress::default()),
            )
        } else {
            (None, None)
        };

        let finger = if config.finger {
            Some(config.token.clone())
        } else {
            None
        };
        //客户端对称加密
        let client_cipher =
            Cipher::new_password(config.cipher_model, config.password.clone(), finger)?;
        //当前设备信息
        let current_device = Arc::new(AtomicCell::new(CurrentDeviceInfo::new0(
            config.server_address,
        )));
        //设备列表
        let device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>> =
            Arc::new(Mutex::new((0, HashMap::with_capacity(16))));
        let local_ipv4 = if let Some(local_ipv4) = config.local_ipv4 {
            Some(local_ipv4)
        } else {
            nat::local_ipv4()
        };
        let default_interface = config.local_interface.clone();

        //基础信息
        let runtime_config = RuntimeConfig {
            name: config.name.clone(),
            token: config.token.clone(),
            ip: config.ip,
            client_secret_hash: config.password_hash(),
            server_secret: false,
            device_id: config.device_id.clone(),
            device_pub_key: load_or_create_device_public_key(&config.device_id)?,
            device_pub_key_alg: device_key_alg().to_string(),
            server_addr: config.server_address_str.clone(),
            name_servers: config.name_servers.clone(),
            mtu: config.mtu.unwrap_or(1420),
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            tap: config.tap,
            #[cfg(feature = "integrated_tun")]
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            device_name: config.device_name.clone(),
            default_interface: default_interface.clone(),
            auth_user_id: config.auth_user_id.clone(),
            auth_group: config.auth_group.clone(),
            auth_ticket: config.auth_ticket.clone(),
            auth_only: config.auth_only,
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
        //通道上下文
        let udp_channel = UdpChannel::bind(&config)?;
        let channel_num = udp_channel.channel_num();
        let context = ChannelContext::new(
            udp_channel.clone(),
            channel_num,
            &config,
            up_traffic_meter.clone(),
            down_traffic_meter.clone(),
        );
        let local_ipv6 = nat::local_ipv6();
        let udp_ports = context.main_local_udp_port()?;
        //nat检测工具
        let nat_test = NatTest::new(
            context.channel_num(),
            config.stun_server.clone(),
            local_ipv4,
            local_ipv6,
            udp_ports,
            0,
            config.local_ipv4.is_none(),
            config.punch_model,
        );
        // 定时器
        let scheduler = Scheduler::new(stop_manager.clone())?;
        let external_route = ExternalRoute::new(config.in_ips.clone());
        let out_external_route = AllowExternalRoute::new(config.out_ips.clone());
        let control_session = ControlSession::new(
            QuicChannel::new(config.server_address),
            runtime_config.clone(),
            current_device.clone(),
        );

        #[cfg(feature = "ip_proxy")]
        #[cfg(feature = "integrated_tun")]
        let proxy_map = if !config.out_ips.is_empty() && !config.no_proxy {
            Some(crate::ip_proxy::init_proxy(
                context.clone(),
                stop_manager.clone(),
                current_device.clone(),
                client_cipher.clone(),
            )?)
        } else {
            None
        };
        let punch_coordinator = PunchCoordinator::new();
        let gateway_sessions = GatewaySessions::new(current_device.clone());
        let peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>> =
            Arc::new(RwLock::new(HashMap::with_capacity(16)));
        let route_table = context.route_table();
        let route_manager = RouteManager::new(route_table.clone());
        route_manager.start_maintenance(
            stop_manager.clone(),
            context.clone(),
            current_device.clone(),
            client_cipher.clone(),
        )?;
        let runtime = Arc::new_cyclic(|weak_runtime| {
            let data_channel = DataChannel::new(weak_runtime.clone());
            #[cfg(feature = "integrated_tun")]
            let tun_device_helper = {
                TunDeviceHelper::new(
                    stop_manager.clone(),
                    data_channel.clone(),
                    current_device.clone(),
                    gateway_sessions.clone(),
                    external_route.clone(),
                    #[cfg(feature = "ip_proxy")]
                    proxy_map.clone(),
                    client_cipher.clone(),
                    device_map.clone(),
                    config.compressor,
                    device.clone().into_device_adapter(),
                )
            };

            VntRuntime {
                config: runtime_config.clone(),
                current_device: current_device.clone(),
                nat_test: nat_test.clone(),
                device_map: device_map.clone(),
                peer_nat_info_map: peer_nat_info_map.clone(),
                external_route: external_route.clone(),
                out_external_route: out_external_route.clone(),
                client_cipher: client_cipher.clone(),
                control_session: control_session.clone(),
                gateway_sessions: gateway_sessions.clone(),
                route_manager: route_manager.clone(),
                udp_channel: udp_channel.clone(),
                up_traffic_meter: up_traffic_meter.clone(),
                down_traffic_meter: down_traffic_meter.clone(),
                data_channel,
                punch_coordinator: punch_coordinator.clone(),
                #[cfg(feature = "ip_proxy")]
                #[cfg(feature = "integrated_tun")]
                ip_proxy_map: proxy_map.clone(),
                #[cfg(feature = "integrated_tun")]
                tun_device_helper,
            }
        });
        let handler = RecvDataHandler::new(runtime.clone(), device, callback.clone());
        let control_handler = handler.clone();
        {
            let context = context.clone();
            let handler = handler.clone();
            gateway_sessions.start(stop_manager.clone(), move |mut packet, route_key| {
                let mut extend = [0u8; crate::channel::BUFFER_SIZE];
                handler.handle(&mut packet, &mut extend, route_key, &context);
            })?;
        }

        //初始化网络数据通道
        #[cfg(feature = "quic")]
        let (quic_connect_s, quic_connect_r) = channel(16);
        #[cfg(feature = "quic")]
        let _ = &quic_connect_s;
        context
            .udp_channel
            .start(stop_manager.clone(), handler.clone(), context.clone())?;
        #[cfg(feature = "quic")]
        quic_connect_accept(
            quic_connect_r,
            handler,
            context.clone(),
            stop_manager.clone(),
        )?;
        // 打洞逻辑
        let punch = Punch::new(
            context.clone(),
            config.punch_model,
            nat_test.clone(),
            current_device.clone(),
        );
        spawn_punch_workers(
            current_device.clone(),
            client_cipher.clone(),
            punch_coordinator.clone(),
            punch.clone(),
        );

        // #[cfg(not(target_os = "android"))]
        // tun_helper.start(device)?;

        runtime.control_session.start(
            stop_manager.clone(),
            runtime.device_map.clone(),
            runtime.gateway_sessions.clone(),
            callback.clone(),
            {
                let context = context.clone();
                let handler = control_handler;
                move |mut packet, route_key| {
                    let mut extend = [0u8; crate::channel::BUFFER_SIZE];
                    handler.handle(&mut packet, &mut extend, route_key, &context);
                }
            },
        )?;
        {
            let runtime = runtime.clone();
            if !config.use_channel_type.is_only_relay() {
                // 定时nat探测
                maintain::retrieve_nat_type(&scheduler, runtime.clone());
            }
            //延迟启动
            scheduler.timeout(Duration::from_secs(3), move |scheduler| {
                start(scheduler, runtime.clone());
            });
        }
        let compressor = config.compressor;
        Ok(Self {
            stop_manager,
            config,
            runtime,
            current_device,
            nat_test,
            device_map,
            context: Arc::new(Mutex::new(Some(context))),
            peer_nat_info_map,
            client_secret_hash: runtime_config.client_secret_hash,
            compressor,
            client_cipher,
            external_route,
            up_traffic_meter,
            down_traffic_meter,
        })
    }
}

pub fn start(scheduler: &Scheduler, runtime: Arc<VntRuntime>) {
    // 默认禁用客户端中继探测（client-relay）

    if !runtime.route_manager().use_channel_type().is_only_relay() {
        // 定时地址探测
        maintain::addr_request(&scheduler, runtime.clone());
    }
    runtime
        .control_session
        .start_status_reporter(scheduler, runtime.clone())
}

impl VntInner {
    pub fn name(&self) -> &str {
        &self.config.name
    }
    pub fn client_encrypt(&self) -> bool {
        self.config.password.is_some()
    }
    pub fn client_encrypt_hash(&self) -> Option<&[u8]> {
        self.client_secret_hash.as_ref().map(|v| v.as_ref())
    }
    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.current_device.load()
    }
    pub fn current_device_info(&self) -> Arc<AtomicCell<CurrentDeviceInfo>> {
        self.current_device.clone()
    }
    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.peer_nat_info_map.read().get(ip).cloned()
    }
    pub fn connection_status(&self) -> ConnectStatus {
        self.current_device.load().status
    }
    pub fn nat_info(&self) -> NatInfo {
        self.nat_test.nat_info()
    }
    pub fn device_list(&self) -> Vec<PeerDeviceInfo> {
        let device_list_lock = self.device_map.lock();
        let (_epoch, device_list) = device_list_lock.clone();
        drop(device_list_lock);
        device_list.into_values().collect()
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<Route> {
        self.runtime.route_manager().best_route(ip)
    }
    pub fn is_gateway(&self, ip: &Ipv4Addr) -> bool {
        self.current_device.load().is_gateway_vip(ip)
    }
    pub fn route_key(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        self.runtime
            .route_manager()
            .peer_for_direct_route(route_key)
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.runtime.route_manager().snapshot_routes()
    }
    pub fn route_states(&self) -> Vec<(Ipv4Addr, Vec<RouteState>)> {
        let current_device = self.current_device.load();
        self.runtime
            .route_manager()
            .snapshot_route_states(current_device.virtual_gateway)
    }
    pub fn up_stream(&self) -> u64 {
        self.up_traffic_meter.as_ref().map_or(0, |v| v.total())
    }
    pub fn up_stream_all(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.up_traffic_meter.as_ref().map(|v| v.get_all())
    }
    pub fn up_stream_history(&self) -> Option<(u64, HashMap<Ipv4Addr, (u64, Vec<usize>)>)> {
        self.up_traffic_meter.as_ref().map(|v| v.get_all_history())
    }
    pub fn down_stream(&self) -> u64 {
        self.down_traffic_meter.as_ref().map_or(0, |v| v.total())
    }
    pub fn down_stream_all(&self) -> Option<(u64, HashMap<Ipv4Addr, u64>)> {
        self.down_traffic_meter.as_ref().map(|v| v.get_all())
    }
    pub fn down_stream_history(&self) -> Option<(u64, HashMap<Ipv4Addr, (u64, Vec<usize>)>)> {
        self.down_traffic_meter
            .as_ref()
            .map(|v| v.get_all_history())
    }
    pub fn stop(&self) {
        //退出协助回收资源
        let _ = self.context.lock().take();
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
    pub fn ipv4_packet_sender(&self) -> Option<IpPacketSender> {
        if let Some(c) = self.context.lock().as_ref() {
            Some(IpPacketSender::new(
                c.clone(),
                self.current_device.clone(),
                self.compressor.clone(),
                self.client_cipher.clone(),
                self.external_route.clone(),
            ))
        } else {
            None
        }
    }
}

impl Drop for VntInner {
    fn drop(&mut self) {
        self.stop();
    }
}
