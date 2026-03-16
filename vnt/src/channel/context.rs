use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use fnv::FnvHashMap;
use parking_lot::RwLock;
use rand::Rng;

use crate::channel::sender::PacketSender;
use crate::channel::{ConnectProtocol, RouteKey, UseChannelType};
use crate::core::Config;
use crate::data_plane::route_manager::RouteManager;
use crate::data_plane::route_table::RouteTable;
use crate::protocol::NetPacket;
use crate::transport::udp_channel::UdpChannel;
use crate::util::limit::TrafficMeterMultiAddress;

#[derive(Clone)]
pub struct ChannelContext {
    inner: Arc<ContextInner>,
}

impl ChannelContext {
    pub fn new(
        udp_channel: UdpChannel,
        channel_num: usize,
        config: &Config,
        up_traffic_meter: Option<TrafficMeterMultiAddress>,
        down_traffic_meter: Option<TrafficMeterMultiAddress>,
    ) -> Self {
        assert_ne!(channel_num, 0, "not channel");
        let packet_loss_rate = config
            .packet_loss_rate
            .map(|v| {
                let v = (v * PACKET_LOSS_RATE_DENOMINATOR as f64) as u32;
                if v > PACKET_LOSS_RATE_DENOMINATOR {
                    PACKET_LOSS_RATE_DENOMINATOR
                } else {
                    v
                }
            })
            .unwrap_or(0);
        let inner = ContextInner {
            udp_channel,
            channel_num,
            packet_map: RwLock::new(FnvHashMap::default()),
            route_table: Arc::new(RouteTable::new(
                config.use_channel_type,
                config.latency_first,
                channel_num,
            )),
            protocol: config.protocol,
            packet_loss_rate,
            packet_delay: config.packet_delay,
            up_traffic_meter,
            down_traffic_meter,
            default_interface: config.local_interface.clone(),
            default_route_key: AtomicCell::default(),
        };
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl Deref for ChannelContext {
    type Target = ContextInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

const PACKET_LOSS_RATE_DENOMINATOR: u32 = 100_0000;

pub struct ContextInner {
    pub(crate) udp_channel: UdpChannel,
    channel_num: usize,
    pub(crate) packet_map: RwLock<FnvHashMap<RouteKey, PacketSender>>,
    pub route_table: Arc<RouteTable>,
    protocol: ConnectProtocol,
    packet_loss_rate: u32,
    packet_delay: u32,
    pub(crate) up_traffic_meter: Option<TrafficMeterMultiAddress>,
    pub(crate) down_traffic_meter: Option<TrafficMeterMultiAddress>,
    default_interface: crate::transport::socket::LocalInterface,
    default_route_key: AtomicCell<Option<RouteKey>>,
}

impl ContextInner {
    pub fn route_manager(&self) -> RouteManager {
        RouteManager::new(self.route_table.clone())
    }

    pub fn use_channel_type(&self) -> UseChannelType {
        self.route_manager().use_channel_type()
    }

    pub fn default_interface(&self) -> &crate::transport::socket::LocalInterface {
        &self.default_interface
    }

    pub fn set_default_route_key(&self, route_key: RouteKey) {
        self.default_route_key.store(Some(route_key));
    }

    pub fn is_cone(&self) -> bool {
        true
    }

    pub fn main_protocol(&self) -> ConnectProtocol {
        self.protocol
    }

    pub fn is_udp_main(&self, route_key: &RouteKey) -> bool {
        route_key.protocol().is_udp() && route_key.index() < self.udp_channel.main_len()
    }

    pub fn latency_first(&self) -> bool {
        self.route_manager().latency_first()
    }

    #[inline]
    pub fn channel_num(&self) -> usize {
        self.channel_num
    }

    #[inline]
    pub fn main_len(&self) -> usize {
        self.udp_channel.main_len()
    }

    pub fn udp_channel(&self) -> UdpChannel {
        self.udp_channel.clone()
    }

    pub fn route_table(&self) -> Arc<RouteTable> {
        self.route_table.clone()
    }

    pub fn main_local_udp_port(&self) -> io::Result<Vec<u16>> {
        self.udp_channel.main_local_udp_port()
    }

    pub fn packet_loss_rate(&self) -> u32 {
        self.packet_loss_rate
    }

    pub fn packet_delay(&self) -> u32 {
        self.packet_delay
    }

    pub fn send_tcp(&self, buf: &[u8], route_key: &RouteKey) -> io::Result<()> {
        if let Some(tcp) = self.packet_map.read().get(route_key) {
            tcp.try_send(buf)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("dest={:?}", route_key),
            ))
        }
    }

    pub fn send_main_udp(&self, index: usize, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.udp_channel.send_main(index, buf, addr)
    }

    pub fn send_default<B: AsRef<[u8]>>(
        &self,
        buf: &NetPacket<B>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        if self.protocol.is_udp() {
            if addr.is_ipv4() {
                self.send_main_udp(0, buf.buffer(), addr)?
            } else {
                self.send_main_udp(self.channel_num, buf.buffer(), addr)?
            }
        } else if let Some(key) = self.default_route_key.load() {
            self.send_tcp(buf.buffer(), &key)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("dest={:?}", addr),
            ));
        }
        if let Some(up_traffic_meter) = &self.up_traffic_meter {
            up_traffic_meter.add_traffic(buf.destination(), buf.data_len());
        }
        Ok(())
    }

    pub fn try_send_all(&self, buf: &[u8], addr: SocketAddr) {
        self.udp_channel.try_send_all(buf, addr);
    }

    pub fn try_send_all_main(&self, buf: &[u8], addr: SocketAddr) {
        self.udp_channel.try_send_all_main(buf, addr);
    }

    pub fn send_ipv4_by_id<B: AsRef<[u8]>>(
        &self,
        buf: &NetPacket<B>,
        id: &Ipv4Addr,
        server_addr: SocketAddr,
        send_default: bool,
    ) -> io::Result<()> {
        if self.packet_loss_rate > 0
            && rand::thread_rng().gen_ratio(self.packet_loss_rate, PACKET_LOSS_RATE_DENOMINATOR)
        {
            return Ok(());
        }

        if self.packet_delay > 0 {
            thread::sleep(Duration::from_millis(self.packet_delay as _));
        }
        if let Err(e) = self.send_by_id(buf, id) {
            if e.kind() != io::ErrorKind::NotFound {
                log::warn!("{}:{:?}", id, e);
            }
            if !self.route_manager().use_channel_type().is_only_p2p() && send_default {
                self.send_default(buf, server_addr)?;
            }
        }
        Ok(())
    }

    pub fn send_by_id<B: AsRef<[u8]>>(&self, buf: &NetPacket<B>, id: &Ipv4Addr) -> io::Result<()> {
        let mut c = 0;
        loop {
            let route = self.route_manager().select_route(c, id)?;
            return if let Err(e) = self.send_by_key(buf, route.route_key()) {
                if e.kind() == io::ErrorKind::WouldBlock {
                    c += 1;
                    if c < 10 {
                        thread::sleep(Duration::from_micros(200));
                        continue;
                    }
                }
                Err(e)
            } else {
                Ok(())
            };
        }
    }

    pub fn send_by_key<B: AsRef<[u8]>>(
        &self,
        buf: &NetPacket<B>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        match route_key.protocol() {
            ConnectProtocol::UDP => self.udp_channel.send_by_key(buf.buffer(), route_key)?,
            ConnectProtocol::TCP
            | ConnectProtocol::QUIC
            | ConnectProtocol::WS
            | ConnectProtocol::WSS => self.send_tcp(buf.buffer(), &route_key)?,
        }
        if let Some(up_traffic_meter) = &self.up_traffic_meter {
            up_traffic_meter.add_traffic(buf.destination(), buf.data_len());
        }
        Ok(())
    }

    pub fn remove_route(&self, ip: &Ipv4Addr, route_key: RouteKey) {
        self.route_manager().remove_path(ip, route_key)
    }
}
