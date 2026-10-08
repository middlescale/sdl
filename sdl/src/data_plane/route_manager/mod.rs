use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::cipher::Cipher;
use crate::core::{runtime::PeerSubsystem, Config};
use crate::data_plane::peer_crypto::PeerCryptoManager;
use crate::data_plane::route::Route;
use crate::data_plane::route_state::RouteState;
use crate::data_plane::route_table::RouteTable;
use crate::data_plane::use_channel_type::UseChannelType;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{NetPacket, Protocol, HEAD_LEN};
use crate::transport::udp_channel::UdpChannel;
use crate::transport::TransportEndpoint;
use crate::util::{PeerProbeTracker, StopManager};
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};

mod maintenance;
use maintenance::RouteMaintenance;

const HEARTBEAT_START_DELAY: Duration = Duration::from_secs(3);

type DirectRouteHandler = Arc<dyn Fn(Ipv4Addr) + Send + Sync>;

#[derive(Clone)]
pub struct RouteManager {
    route_table: Arc<RouteTable>,
    peer_crypto: Arc<PeerCryptoManager>,
    peer_probe_tracker: Arc<PeerProbeTracker>,
    started: Arc<AtomicBool>,
    sender: Option<RouteSender>,
    direct_route_timeout_handler: Arc<Mutex<Option<DirectRouteHandler>>>,
    direct_route_update_handler: Arc<Mutex<Option<DirectRouteHandler>>>,
    heartbeat_interval: Duration,
    stale_direct_timeout: Duration,
    maintenance: Arc<Mutex<RouteMaintenance>>,
    pub(crate) peer_table: Option<Arc<RwLock<crate::core::PeerTable>>>,
}

#[derive(Clone)]
struct RouteSender {
    udp_channel: UdpChannel,
}

impl RouteManager {
    pub(crate) fn new(config: &Config, udp_channel: UdpChannel, peers: &PeerSubsystem) -> Self {
        Self {
            route_table: Arc::new(RouteTable::new(
                config.use_channel_type,
                config.latency_first,
            )),
            peer_crypto: peers.crypto.clone(),
            peer_probe_tracker: peers.probe_tracker.clone(),
            started: Arc::new(AtomicBool::new(false)),
            sender: Some(RouteSender { udp_channel }),
            direct_route_timeout_handler: Arc::new(Mutex::new(None)),
            direct_route_update_handler: Arc::new(Mutex::new(None)),
            heartbeat_interval: Duration::from_secs(config.p2p_heartbeat_interval_sec),
            stale_direct_timeout: Duration::from_secs(config.p2p_route_idle_timeout_sec),
            maintenance: Arc::new(Mutex::new(RouteMaintenance::default())),
            peer_table: Some(peers.table.clone()),
        }
    }

    /// Start once, after installing route handlers. Clones share the claim.
    /// Startup failure is terminal: stop the associated runtime to cancel any
    /// worker already launched, and keep the claim set to prevent partial retry.
    pub(crate) fn start(
        &self,
        stop_manager: StopManager,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "route manager start already attempted"
        );
        let result = self
            .start_heartbeat_loop(stop_manager.clone(), current_device)
            .and_then(|()| self.start_route_maintenance_loop(stop_manager.clone()));
        if result.is_err() {
            stop_manager.stop();
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn new_detached(route_table: Arc<RouteTable>) -> Self {
        Self {
            route_table,
            peer_crypto: Arc::new(PeerCryptoManager::new(0)),
            peer_probe_tracker: Arc::new(PeerProbeTracker::new(0)),
            started: Arc::new(AtomicBool::new(false)),
            sender: None,
            direct_route_timeout_handler: Arc::new(Mutex::new(None)),
            direct_route_update_handler: Arc::new(Mutex::new(None)),
            heartbeat_interval: Duration::from_secs(10),
            stale_direct_timeout: Duration::from_secs(30),
            maintenance: Arc::new(Mutex::new(RouteMaintenance::default())),
            peer_table: None,
        }
    }

    pub fn set_direct_route_timeout_handler(&self, handler: DirectRouteHandler) {
        *self.direct_route_timeout_handler.lock() = Some(handler);
    }

    pub fn set_direct_route_update_handler(&self, handler: DirectRouteHandler) {
        *self.direct_route_update_handler.lock() = Some(handler);
    }

    pub fn use_channel_type(&self) -> UseChannelType {
        self.route_table.use_channel_type()
    }

    pub fn set_use_channel_type(&self, use_channel_type: UseChannelType) {
        self.route_table.set_use_channel_type(use_channel_type);
        self.wake_maintenance();
    }

    pub fn latency_first(&self) -> bool {
        self.route_table.latency_first()
    }

    pub fn add_path_if_absent(&self, vip: Ipv4Addr, route: Route) {
        if self.should_suppress_p2p(&vip, &route) {
            return;
        }
        if self.route_table.add_route_if_absent(vip, route) {
            self.wake_maintenance();
        }
        if route.is_p2p() {
            self.notify_direct_route_update(vip);
        }
    }

    pub fn add_path(&self, vip: Ipv4Addr, route: Route) {
        if self.should_suppress_p2p(&vip, &route) {
            return;
        }
        if self.route_table.add_route(vip, route) {
            self.wake_maintenance();
        }
        if route.is_p2p() {
            self.notify_direct_route_update(vip);
        }
    }

    fn notify_direct_route_update(&self, vip: Ipv4Addr) {
        let handler = self.direct_route_update_handler.lock().clone();
        if let Some(handler) = handler {
            handler(vip);
        }
    }

    fn should_suppress_p2p(&self, vip: &Ipv4Addr, route: &Route) -> bool {
        if !route.is_p2p() {
            return false;
        }
        if let Some(peer_table) = &self.peer_table {
            if let Some(peer) = peer_table.read().get(vip) {
                if peer.preferred_channel_mode
                    == crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY
                {
                    return true;
                }
            }
        }
        false
    }

    fn peer_identity(&self, vip: &Ipv4Addr) -> anyhow::Result<crate::core::PeerIdentity> {
        self.peer_table
            .as_ref()
            .and_then(|peer_table| peer_table.read().identity_for_vip(vip))
            .ok_or_else(|| anyhow::anyhow!("missing peer identity for {}", vip))
    }

    pub fn has_direct_path(&self, vip: &Ipv4Addr, endpoint: &TransportEndpoint) -> bool {
        self.route_table.has_direct_path(vip, endpoint)
    }

    pub fn best_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table
            .get_first_live_route(vip, self.stale_direct_timeout)
    }

    pub fn direct_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table.get_one_p2p_route(vip)
    }

    pub fn measured_direct_route(&self, vip: &Ipv4Addr) -> Option<Route> {
        self.route_table.get_one_measured_p2p_route(vip)
    }

    pub fn payload_route_read(&self, vip: &Ipv4Addr) -> (Option<Route>, bool) {
        self.route_table
            .payload_route_read(vip, self.stale_direct_timeout)
    }

    pub fn peer_for_direct_route(&self, endpoint: &TransportEndpoint) -> Option<Ipv4Addr> {
        self.route_table.get_one_p2p_ip(endpoint)
    }

    pub fn has_direct_endpoint(&self, endpoint: &TransportEndpoint) -> bool {
        self.route_table.has_direct_endpoint(endpoint)
    }

    pub fn direct_path_count(&self, vip: &Ipv4Addr) -> usize {
        self.route_table.p2p_num(vip)
    }

    pub fn has_enough_direct_paths(&self, vip: &Ipv4Addr) -> bool {
        self.route_table.no_need_punch(vip)
    }

    pub fn snapshot_routes(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.route_table.snapshot_routes()
    }

    pub fn snapshot_direct_routes(&self) -> Vec<(Ipv4Addr, Route)> {
        self.route_table.snapshot_direct_routes()
    }

    /// Records application traffic for the peer activity display.
    pub fn activate_peer(&self, vip: &Ipv4Addr) -> bool {
        self.route_table
            .activate_peer(vip, self.stale_direct_timeout)
    }

    pub fn is_peer_active(&self, vip: &Ipv4Addr) -> bool {
        self.route_table
            .is_peer_active(vip, self.stale_direct_timeout)
    }

    pub fn take_direct_recovery_request(&self, vip: &Ipv4Addr, has_direct_route: bool) -> bool {
        self.route_table
            .take_direct_recovery_request(vip, has_direct_route)
    }

    pub fn has_any_route(&self, vip: &Ipv4Addr) -> bool {
        self.best_route(vip).is_some()
    }

    pub fn heartbeat_targets(&self) -> Vec<(Ipv4Addr, Vec<Route>)> {
        self.snapshot_routes()
            .into_iter()
            .filter_map(|(peer_ip, routes)| {
                let routes: Vec<_> = routes
                    .into_iter()
                    // Include unmeasured routes as well: their immediate
                    // punch-time Ping may be lost, and the maintenance loop
                    // must continue probing until liveness expires.
                    .filter(|route| route.is_p2p())
                    .collect();
                if routes.is_empty() {
                    None
                } else {
                    Some((peer_ip, routes))
                }
            })
            .collect()
    }

    pub fn missing_route_peers<'b, I>(&self, peers: I) -> Vec<Ipv4Addr>
    where
        I: IntoIterator<Item = &'b Ipv4Addr>,
    {
        peers
            .into_iter()
            .filter(|peer_ip| !self.has_any_route(peer_ip))
            .copied()
            .collect()
    }

    pub fn snapshot_route_states(
        &self,
        virtual_gateway: Ipv4Addr,
    ) -> Vec<(Ipv4Addr, Vec<RouteState>)> {
        self.route_table
            .snapshot_routes()
            .into_iter()
            .map(|(peer_ip, routes)| {
                let states = routes
                    .into_iter()
                    .map(|route| RouteState::from_route(peer_ip, route, virtual_gateway))
                    .collect();
                (peer_ip, states)
            })
            .collect()
    }

    pub fn remove_path(&self, vip: &Ipv4Addr, endpoint: TransportEndpoint) {
        self.route_table.remove_route(vip, endpoint);
        self.wake_maintenance();
    }

    pub fn clear_all_paths(&self) {
        self.route_table.clear_all();
        self.wake_maintenance();
    }

    /// Invalidates P2P routes after a suspend/resume or local underlay change.
    /// Relay paths remain available while control coordinates fresh punching.
    /// Clearing routes does not rearm an already claimed recovery request;
    /// learning a direct route starts the next recovery cycle.
    pub fn clear_direct_paths(&self) -> usize {
        let affected_peers = self.route_table.clear_direct_routes();
        self.wake_maintenance();
        for peer_ip in &affected_peers {
            self.notify_direct_route_update(*peer_ip);
        }
        affected_peers.len()
    }

    pub fn mark_path_failed(&self, vip: &Ipv4Addr, endpoint: TransportEndpoint) {
        if self.route_table.remove_route(vip, endpoint) {
            self.notify_direct_route_update(*vip);
            self.fire_direct_route_timeout_if_last(*vip);
        }
        self.wake_maintenance();
    }

    pub fn touch_path(&self, vip: &Ipv4Addr, endpoint: &TransportEndpoint) {
        self.route_table.update_read_time(vip, endpoint)
    }

    pub fn clear_peer(&self, vip: &Ipv4Addr) {
        self.route_table.clear_peer(vip);
        self.wake_maintenance();
    }

    pub fn retain_peers(&self, valid_peers: &HashSet<Ipv4Addr>) {
        self.route_table.retain_peers(valid_peers);
        self.wake_maintenance();
    }

    pub fn send_heartbeats(&self, current_device: CurrentDeviceInfo) {
        self.send_heartbeats_to(current_device, self.heartbeat_targets());
    }

    fn send_heartbeats_to(
        &self,
        current_device: CurrentDeviceInfo,
        targets: Vec<(Ipv4Addr, Vec<Route>)>,
    ) {
        let Some(sender) = &self.sender else {
            return;
        };
        let src_ip = current_device.virtual_ip;
        for (dest_ip, routes) in targets {
            if current_device.is_gateway_vip(&dest_ip) {
                continue;
            }
            for route in &routes {
                if !route.is_p2p() {
                    continue;
                }
                let endpoint = route.endpoint;
                let epoch = self.peer_probe_tracker.record_ping_probe(dest_ip, endpoint);
                let net_packets = match self.heartbeat_packets_for_peer(src_ip, dest_ip, epoch) {
                    Ok(net_packets) if !net_packets.is_empty() => net_packets,
                    Ok(_) => continue,
                    Err(e) => {
                        log::error!("heartbeat_packet err={:?}", e);
                        continue;
                    }
                };
                for net_packet in &net_packets {
                    if let Err(e) = self.send_to_endpoint(sender, net_packet, endpoint) {
                        log::warn!("heartbeat err={:?}", e)
                    }
                }
            }
        }
    }

    pub fn send_immediate_heartbeat(
        &self,
        current_device: CurrentDeviceInfo,
        dest_ip: Ipv4Addr,
        endpoint: TransportEndpoint,
    ) -> anyhow::Result<()> {
        let Some(sender) = &self.sender else {
            return Ok(());
        };
        if current_device.is_gateway_vip(&dest_ip) {
            return Ok(());
        }
        let Some(epoch) = self
            .peer_probe_tracker
            .try_record_ping_probe(dest_ip, endpoint)
        else {
            return Ok(());
        };
        let net_packets =
            self.heartbeat_packets_for_peer(current_device.virtual_ip, dest_ip, epoch)?;
        for net_packet in &net_packets {
            self.send_to_endpoint(sender, net_packet, endpoint)?;
        }
        Ok(())
    }

    fn heartbeat_packets_for_peer(
        &self,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        epoch: u16,
    ) -> anyhow::Result<Vec<NetPacket<Vec<u8>>>> {
        let mut packets = Vec::with_capacity(2);
        let peer_identity = match self.peer_identity(&dest_ip) {
            Ok(peer_identity) => peer_identity,
            Err(err) => {
                log::debug!(
                    "skip heartbeat without peer identity for {}: {:?}",
                    dest_ip,
                    err
                );
                return Ok(Vec::new());
            }
        };
        match self.peer_crypto.current_cipher(&peer_identity) {
            Ok(cipher) => packets.push(heartbeat_packet_client(
                Some(cipher),
                src_ip,
                dest_ip,
                epoch,
            )?),
            Err(err) if !self.peer_crypto.is_grace_active() => {
                log::debug!(
                    "skip heartbeat without current peer session cipher for {}: {:?}",
                    dest_ip,
                    err
                );
                return Ok(Vec::new());
            }
            Err(err) => {
                log::debug!(
                    "current heartbeat cipher unavailable during grace for {}: {:?}",
                    dest_ip,
                    err
                );
            }
        }
        if self.peer_crypto.is_grace_active() {
            match self.peer_crypto.previous_cipher(&peer_identity) {
                Ok(cipher) => packets.push(heartbeat_packet_client(
                    Some(cipher),
                    src_ip,
                    dest_ip,
                    epoch,
                )?),
                Err(err) if packets.is_empty() => {
                    log::debug!(
                        "skip heartbeat without grace cipher for {}: {:?}",
                        dest_ip,
                        err
                    );
                    return Ok(Vec::new());
                }
                Err(_) => {}
            }
        }
        Ok(packets)
    }
}

impl RouteManager {
    fn start_heartbeat_loop(
        &self,
        stop_manager: StopManager,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ) -> anyhow::Result<()> {
        let (stop_sender, stop_receiver) = mpsc::channel();
        // Register synchronously so start reports listener failures and stop
        // can interrupt even the initial wait, before the thread has started.
        let worker = stop_manager.add_listener("routeHeartbeat".into(), move || {
            let _ = stop_sender.send(());
        })?;
        let route_manager = self.clone();
        thread::Builder::new()
            .name("routeHeartbeat".into())
            .spawn(move || {
                let mut delay = HEARTBEAT_START_DELAY;
                while matches!(
                    stop_receiver.recv_timeout(delay),
                    Err(RecvTimeoutError::Timeout)
                ) {
                    route_manager.send_heartbeats(current_device.load());
                    delay = route_manager.heartbeat_interval;
                }
                worker.stop_self();
            })?;
        Ok(())
    }

    fn send_to_endpoint<B: AsRef<[u8]>>(
        &self,
        sender: &RouteSender,
        buf: &NetPacket<B>,
        endpoint: TransportEndpoint,
    ) -> io::Result<()> {
        sender.udp_channel.send_to_endpoint(buf.buffer(), endpoint)
    }
}

fn heartbeat_packet(
    src: Ipv4Addr,
    dest: Ipv4Addr,
    epoch: u16,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut net_packet = NetPacket::new(vec![0u8; HEAD_LEN + 4])?;
    net_packet.set_default_version();
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
    net_packet.set_initial_ttl(5);
    net_packet.set_source(src);
    net_packet.set_destination(dest);
    let mut ping = PingPacket::new(net_packet.payload_mut())?;
    ping.set_time(crate::handle::now_time() as u16);
    ping.set_epoch(epoch);
    Ok(net_packet)
}

fn heartbeat_packet_client(
    cipher: Option<Cipher>,
    src: Ipv4Addr,
    dest: Ipv4Addr,
    epoch: u16,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut net_packet = if cipher.is_some() {
        let mut net_packet = NetPacket::new_encrypt(vec![0u8; HEAD_LEN + 4 + ENCRYPTION_RESERVED])?;
        net_packet.set_default_version();
        net_packet.set_protocol(Protocol::Control);
        net_packet.set_transport_protocol(crate::protocol::control_packet::Protocol::Ping.into());
        net_packet.set_initial_ttl(5);
        net_packet.set_source(src);
        net_packet.set_destination(dest);
        let mut ping = PingPacket::new(net_packet.payload_mut())?;
        ping.set_time(crate::handle::now_time() as u16);
        ping.set_epoch(epoch);
        net_packet
    } else {
        heartbeat_packet(src, dest, epoch)?
    };
    if let Some(cipher) = cipher {
        cipher.encrypt_ipv4(&mut net_packet)?;
    }
    Ok(net_packet)
}

#[cfg(test)]
mod tests {
    use super::RouteManager;
    use crate::cipher::Cipher;
    use crate::core::{PeerInfo, PeerTable};
    use crate::data_plane::route::Route;
    use crate::data_plane::route_table::RouteTable;
    use crate::data_plane::use_channel_type::UseChannelType;
    use crate::protocol::Protocol;
    use crate::transport::{ConnectProtocol, TransportEndpoint};
    use parking_lot::Mutex;
    use parking_lot::RwLock;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    fn route(metric: u8, port: u16) -> Route {
        Route::new(
            TransportEndpoint::new(
                ConnectProtocol::UDP,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            ),
            metric,
            10,
        )
    }

    #[test]
    fn heartbeat_packet_client_reserves_room_for_peer_encryption() {
        let cipher = Cipher::new_key([7; 32]).expect("cipher");
        let mut packet = super::heartbeat_packet_client(
            Some(cipher.clone()),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            7,
        )
        .expect("heartbeat packet");
        assert!(packet.is_encrypt());
        cipher.decrypt_ipv4(&mut packet).expect("decrypt heartbeat");
        assert_eq!(packet.protocol(), Protocol::Control);
        assert_eq!(
            packet.transport_protocol(),
            Into::<u8>::into(crate::protocol::control_packet::Protocol::Ping)
        );
    }

    #[test]
    fn mark_path_failed_triggers_handler_when_last_direct_route_is_removed() {
        let table = Arc::new(RouteTable::new(UseChannelType::Auto, false));
        let manager = RouteManager::new_detached(table.clone());
        let peer = Ipv4Addr::new(10, 0, 0, 16);
        let failed_route = route(1, 2016);
        let timeouts = Arc::new(Mutex::new(Vec::new()));
        {
            let timeouts = timeouts.clone();
            manager.set_direct_route_timeout_handler(Arc::new(move |ip| {
                timeouts.lock().push(ip);
            }));
        }
        table.add_route(peer, failed_route);

        manager.mark_path_failed(&peer, failed_route.endpoint);

        assert!(table.get_routes(&peer).is_none());
        assert_eq!(*timeouts.lock(), vec![peer]);
    }

    #[test]
    fn mark_path_failed_keeps_handler_silent_when_other_direct_route_remains() {
        let table = Arc::new(RouteTable::new(UseChannelType::Auto, true));
        let manager = RouteManager::new_detached(table.clone());
        let peer = Ipv4Addr::new(10, 0, 0, 17);
        let first_route = route(1, 2017);
        let second_route = route(1, 2018);
        let timeouts = Arc::new(Mutex::new(Vec::new()));
        {
            let timeouts = timeouts.clone();
            manager.set_direct_route_timeout_handler(Arc::new(move |ip| {
                timeouts.lock().push(ip);
            }));
        }
        table.add_route(peer, first_route);
        table.add_route(peer, second_route);

        manager.mark_path_failed(&peer, first_route.endpoint);

        assert_eq!(manager.direct_path_count(&peer), 1);
        assert!(timeouts.lock().is_empty());
    }

    #[test]
    fn heartbeat_targets_keep_idle_p2p_routes_when_relay_route_sorts_first() {
        let table = Arc::new(RouteTable::new(UseChannelType::Auto, true));
        let manager = RouteManager::new_detached(table.clone());
        let peer = Ipv4Addr::new(10, 0, 0, 9);
        table.add_route(peer, Route::new(route(2, 2010).endpoint, 2, 1));
        table.add_route(peer, route(1, 2011));
        let targets = manager.heartbeat_targets();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, peer);
        assert_eq!(targets[0].1.len(), 1);
        assert!(targets[0].1[0].is_p2p());
    }

    #[test]
    fn heartbeat_targets_retry_unmeasured_direct_routes() {
        let table = Arc::new(RouteTable::new(UseChannelType::Auto, false));
        let manager = RouteManager::new_detached(table.clone());
        let peer = Ipv4Addr::new(10, 0, 0, 20);
        table.add_route(peer, Route::new(route(1, 2021).endpoint, 1, -1));

        let targets = manager.heartbeat_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, peer);
        assert_eq!(targets[0].1.len(), 1);
        assert_eq!(targets[0].1[0].rt, -1);
    }

    #[test]
    fn direct_route_status_snapshot_includes_idle_peers() {
        let table = Arc::new(RouteTable::new(UseChannelType::Auto, false));
        let manager = RouteManager::new_detached(table.clone());
        let peer = Ipv4Addr::new(10, 0, 0, 19);
        table.add_route(peer, route(1, 2020));

        assert_eq!(manager.snapshot_direct_routes().len(), 1);
    }

    #[test]
    fn heartbeat_packets_include_previous_cipher_during_grace_window() {
        let table = Arc::new(RouteTable::new(UseChannelType::Auto, false));
        let mut manager = RouteManager::new_detached(table);
        let peer = Ipv4Addr::new(10, 0, 0, 8);
        let peer_info = PeerInfo::new(
            peer,
            "peer-8".to_string(),
            0,
            "peer-8".to_string(),
            vec![8; 32],
            vec![],
            crate::proto::message::ChannelMode::CHANNEL_MODE_AUTO,
            false,
            false,
            false,
        );
        let peer_identity = peer_info.identity();
        manager.peer_table = Some(Arc::new(RwLock::new(PeerTable::new(
            1,
            std::collections::HashMap::from([(peer, peer_info)]),
        ))));
        manager
            .peer_crypto
            .rotate_peer_session_ciphers(std::collections::HashMap::from([(
                peer_identity.clone(),
                Cipher::new_key([1; 32]).expect("cipher 1"),
            )]));
        manager
            .peer_crypto
            .rotate_peer_session_ciphers(std::collections::HashMap::from([(
                peer_identity,
                Cipher::new_key([2; 32]).expect("cipher 2"),
            )]));

        let packets = manager
            .heartbeat_packets_for_peer(Ipv4Addr::new(10, 0, 0, 1), peer, 9)
            .expect("heartbeat packets");

        assert_eq!(packets.len(), 2);
    }

    #[test]
    fn suppress_p2p_when_peer_is_relay() {
        use crate::core::{PeerInfo, PeerTable};
        let table = Arc::new(RouteTable::new(UseChannelType::Auto, false));
        let mut manager = RouteManager::new_detached(table.clone());
        let peer = Ipv4Addr::new(10, 0, 0, 10);
        let peer_info = PeerInfo::new(
            peer,
            "peer-10".to_string(),
            0,
            "peer-10".to_string(),
            vec![],
            vec![],
            crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY,
            false,
            false,
            false,
        );
        let peer_table = Arc::new(RwLock::new(PeerTable::new(
            1,
            std::collections::HashMap::from([(peer, peer_info)]),
        )));
        manager.peer_table = Some(peer_table);

        // Try to add a p2p route (metric = 1)
        manager.add_path(peer, route(1, 1010));
        assert!(table.get_first_route(&peer).is_none());

        // Try to add a relay route (metric = 2)
        manager.add_path(peer, route(2, 1011));
        assert!(table.get_first_route(&peer).is_some());
    }
}
