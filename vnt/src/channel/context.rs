use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use fnv::FnvHashMap;
use parking_lot::RwLock;
use rand::Rng;

use crate::channel::punch::NatType;
use crate::channel::route_table::RouteTable;
use crate::channel::sender::{AcceptSocketSender, PacketSender};
use crate::channel::socket::LocalInterface;
use crate::channel::{ConnectProtocol, RouteKey, UseChannelType};
use crate::core::Config;
use crate::protocol::NetPacket;
use crate::util::limit::TrafficMeterMultiAddress;

/// 传输通道上下文，持有udp socket、tcp socket和路由信息
#[derive(Clone)]
pub struct ChannelContext {
    inner: Arc<ContextInner>,
}

impl ChannelContext {
    pub fn new(
        main_udp_socket: Vec<UdpSocket>,
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
            main_udp_socket,
            channel_num,
            sub_udp_socket: RwLock::new(Vec::new()),
            packet_map: RwLock::new(FnvHashMap::default()),
            route_table: RouteTable::new(
                config.use_channel_type,
                config.latency_first,
                channel_num,
            ),
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

/// 对称网络增加的udp socket数目，有助于增加打洞成功率
pub const SYMMETRIC_CHANNEL_NUM: usize = 84;
const PACKET_LOSS_RATE_DENOMINATOR: u32 = 100_0000;

pub struct ContextInner {
    // 核心udp socket
    pub(crate) main_udp_socket: Vec<UdpSocket>,
    channel_num: usize,
    // 对称网络增加的udp socket
    sub_udp_socket: RwLock<Vec<UdpSocket>>,
    // tcp数据发送器
    pub(crate) packet_map: RwLock<FnvHashMap<RouteKey, PacketSender>>,
    // 路由信息
    pub route_table: RouteTable,
    // 使用什么协议连接服务器
    protocol: ConnectProtocol,
    //控制丢包率，取值v=[0,100_0000] 丢包率r=v/100_0000
    packet_loss_rate: u32,
    //控制延迟
    packet_delay: u32,
    pub(crate) up_traffic_meter: Option<TrafficMeterMultiAddress>,
    pub(crate) down_traffic_meter: Option<TrafficMeterMultiAddress>,
    default_interface: LocalInterface,
    default_route_key: AtomicCell<Option<RouteKey>>,
}

impl ContextInner {
    pub fn use_channel_type(&self) -> UseChannelType {
        self.route_table.use_channel_type
    }
    pub fn default_interface(&self) -> &LocalInterface {
        &self.default_interface
    }
    pub fn set_default_route_key(&self, route_key: RouteKey) {
        self.default_route_key.store(Some(route_key));
    }
    /// 通过sub_udp_socket是否为空来判断是否为锥形网络
    pub fn is_cone(&self) -> bool {
        self.sub_udp_socket.read().is_empty()
    }
    pub fn main_protocol(&self) -> ConnectProtocol {
        self.protocol
    }
    pub fn is_udp_main(&self, route_key: &RouteKey) -> bool {
        route_key.protocol().is_udp() && route_key.index < self.main_udp_socket.len()
    }
    pub fn latency_first(&self) -> bool {
        self.route_table.latency_first
    }
    /// 切换NAT类型，不同的nat打洞模式会有不同
    pub fn switch(
        &self,
        nat_type: NatType,
        udp_socket_sender: &AcceptSocketSender<Option<Vec<mio::net::UdpSocket>>>,
    ) -> anyhow::Result<()> {
        let mut write_guard = self.sub_udp_socket.write();
        match nat_type {
            NatType::Symmetric => {
                if !write_guard.is_empty() {
                    return Ok(());
                }
                let mut vec = Vec::with_capacity(SYMMETRIC_CHANNEL_NUM);
                for _ in 0..SYMMETRIC_CHANNEL_NUM {
                    let udp = crate::channel::socket::bind_udp(
                        "0.0.0.0:0".parse().unwrap(),
                        &self.default_interface,
                    )?;
                    let udp: UdpSocket = udp.into();
                    vec.push(udp);
                }
                let mut mio_vec = Vec::with_capacity(SYMMETRIC_CHANNEL_NUM);
                for udp in vec.iter() {
                    let udp_socket = mio::net::UdpSocket::from_std(udp.try_clone()?);
                    mio_vec.push(udp_socket);
                }
                udp_socket_sender.try_add_socket(Some(mio_vec))?;
                *write_guard = vec;
            }
            NatType::Cone => {
                if write_guard.is_empty() {
                    return Ok(());
                }
                udp_socket_sender.try_add_socket(None)?;
                *write_guard = Vec::new();
            }
        }
        Ok(())
    }
    #[inline]
    pub fn channel_num(&self) -> usize {
        self.channel_num
    }
    #[inline]
    pub fn main_len(&self) -> usize {
        self.main_udp_socket.len()
    }
    /// 获取核心udp监听的端口，用于其他客户端连接
    pub fn main_local_udp_port(&self) -> io::Result<Vec<u16>> {
        let mut ports = Vec::new();
        for udp in self.main_udp_socket[..self.channel_num].iter() {
            ports.push(udp.local_addr()?.port())
        }
        Ok(ports)
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
        if let Some(udp) = self.main_udp_socket.get(index) {
            udp.send_to(buf, addr)?;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "overflow"))
        }
    }
    /// 将数据发送到默认通道，一般发往服务器才用此方法
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
        } else {
            if let Some(key) = self.default_route_key.load() {
                self.send_tcp(buf.buffer(), &key)?
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("dest={:?}", addr),
                ));
            }
        }
        if let Some(up_traffic_meter) = &self.up_traffic_meter {
            up_traffic_meter.add_traffic(buf.destination(), buf.data_len());
        }
        Ok(())
    }

    /// 此方法仅用于对称网络打洞
    pub fn try_send_all(&self, buf: &[u8], addr: SocketAddr) {
        self.try_send_all_main(buf, addr);
        for udp in self.sub_udp_socket.read().iter() {
            if let Err(e) = udp.send_to(buf, addr) {
                log::warn!("{:?},add={:?}", e, addr);
            }
            thread::sleep(Duration::from_millis(3));
        }
    }
    pub fn try_send_all_main(&self, buf: &[u8], addr: SocketAddr) {
        for index in 0..self.channel_num() {
            if let Err(e) = self.send_main_udp(index, buf, addr) {
                log::warn!("{:?},add={:?}", e, addr);
            }
        }
    }
    /// 发送网络数据
    pub fn send_ipv4_by_id<B: AsRef<[u8]>>(
        &self,
        buf: &NetPacket<B>,
        id: &Ipv4Addr,
        server_addr: SocketAddr,
        send_default: bool,
    ) -> io::Result<()> {
        if self.packet_loss_rate > 0 {
            if rand::thread_rng().gen_ratio(self.packet_loss_rate, PACKET_LOSS_RATE_DENOMINATOR) {
                return Ok(());
            }
        }

        if self.packet_delay > 0 {
            thread::sleep(Duration::from_millis(self.packet_delay as _));
        }
        //优先发到直连到地址
        if let Err(e) = self.send_by_id(buf, id) {
            if e.kind() != io::ErrorKind::NotFound {
                log::warn!("{}:{:?}", id, e);
            }
            if !self.route_table.use_channel_type.is_only_p2p() && send_default {
                //符合条件再发到服务器转发
                self.send_default(buf, server_addr)?;
            }
        }
        Ok(())
    }
    /// 将数据发到指定id
    pub fn send_by_id<B: AsRef<[u8]>>(&self, buf: &NetPacket<B>, id: &Ipv4Addr) -> io::Result<()> {
        let mut c = 0;
        loop {
            let route = self.route_table.get_route(c, id)?;
            return if let Err(e) = self.send_by_key(buf, route.route_key()) {
                //降低发送速率
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
    /// 将数据发到指定路由
    pub fn send_by_key<B: AsRef<[u8]>>(
        &self,
        buf: &NetPacket<B>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        match route_key.protocol() {
            ConnectProtocol::UDP => {
                if let Some(main_udp) = self.main_udp_socket.get(route_key.index) {
                    main_udp.send_to(buf.buffer(), route_key.addr)?;
                } else {
                    if let Some(udp) = self
                        .sub_udp_socket
                        .read()
                        .get(route_key.index - self.main_len())
                    {
                        udp.send_to(buf.buffer(), route_key.addr)?;
                    } else {
                        Err(io::Error::from(io::ErrorKind::NotFound))?
                    }
                }
            }
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
        self.route_table.remove_route(ip, route_key)
    }
}
