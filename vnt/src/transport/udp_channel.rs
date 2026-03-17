use mio::net::UdpSocket as MioUdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;

use crate::channel::{ConnectProtocol, RouteKey, BUFFER_SIZE};
use crate::core::Config;
use crate::util::limit::TrafficMeterMultiChannel;
use crate::util::StopManager;

const NOTIFY: Token = Token(0);

#[derive(Clone)]
pub struct UdpChannel {
    main_udp_socket: Arc<Vec<UdpSocket>>,
    channel_num: usize,
    up_traffic_meter: Option<TrafficMeterMultiChannel>,
    down_traffic_meter: Option<TrafficMeterMultiChannel>,
}

impl UdpChannel {
    pub fn bind(config: &Config) -> anyhow::Result<Self> {
        let mut ports = config.ports.as_ref().map_or(vec![0, 0], |v| {
            if v.is_empty() {
                vec![0, 0]
            } else {
                v.clone()
            }
        });
        if config.use_channel_type.is_only_relay() {
            ports.truncate(1);
        }
        assert!(!ports.is_empty(), "not channel");

        let default_interface = config.local_interface.clone();
        let use_ipv6 = match socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)
        {
            Ok(_) => true,
            Err(e) => {
                log::warn!("{:?}", e);
                false
            }
        };

        let mut main_udp_socket_v4 = Vec::with_capacity(ports.len());
        let mut main_udp_socket_v6 = Vec::with_capacity(ports.len());
        for port in &ports {
            let addr_v4: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
            if use_ipv6 {
                let (main_channel_v4, main_channel_v6) =
                    bind_udp_v4_and_v6(*port, &default_interface)?;
                main_udp_socket_v4.push(main_channel_v4);
                main_udp_socket_v6.push(main_channel_v6);
            } else {
                let socket = crate::transport::socket::bind_udp(addr_v4, &default_interface)?;
                let main_channel_v4: UdpSocket = socket.into();
                main_udp_socket_v4.push(main_channel_v4);
            }
        }

        let mut main_udp_socket =
            Vec::with_capacity(main_udp_socket_v4.len() + main_udp_socket_v6.len());
        let channel_num = main_udp_socket_v4.len();
        main_udp_socket.append(&mut main_udp_socket_v4);
        main_udp_socket.append(&mut main_udp_socket_v6);
        Ok(Self {
            main_udp_socket: Arc::new(main_udp_socket),
            channel_num,
            up_traffic_meter: config
                .enable_traffic
                .then(TrafficMeterMultiChannel::default),
            down_traffic_meter: config
                .enable_traffic
                .then(TrafficMeterMultiChannel::default),
        })
    }

    pub fn channel_num(&self) -> usize {
        self.channel_num
    }

    pub fn main_len(&self) -> usize {
        self.main_udp_socket.len()
    }

    pub fn has_ipv6(&self) -> bool {
        self.main_len() > self.channel_num
    }

    pub fn main_local_udp_port(&self) -> io::Result<Vec<u16>> {
        let mut ports = Vec::with_capacity(self.channel_num);
        for udp in self.main_udp_socket[..self.channel_num].iter() {
            ports.push(udp.local_addr()?.port());
        }
        Ok(ports)
    }

    pub fn up_traffic_total(&self) -> u64 {
        self.up_traffic_meter.as_ref().map_or(0, |v| v.total())
    }

    pub fn up_traffic_all(&self) -> Option<(u64, std::collections::HashMap<usize, u64>)> {
        self.up_traffic_meter.as_ref().map(|v| v.get_all())
    }

    pub fn up_traffic_history(
        &self,
    ) -> Option<(u64, std::collections::HashMap<usize, (u64, Vec<usize>)>)> {
        self.up_traffic_meter.as_ref().map(|v| v.get_all_history())
    }

    pub fn down_traffic_total(&self) -> u64 {
        self.down_traffic_meter.as_ref().map_or(0, |v| v.total())
    }

    pub fn down_traffic_all(&self) -> Option<(u64, std::collections::HashMap<usize, u64>)> {
        self.down_traffic_meter.as_ref().map(|v| v.get_all())
    }

    pub fn down_traffic_history(
        &self,
    ) -> Option<(u64, std::collections::HashMap<usize, (u64, Vec<usize>)>)> {
        self.down_traffic_meter
            .as_ref()
            .map(|v| v.get_all_history())
    }

    pub fn send_main(&self, index: usize, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        if let Some(udp) = self.main_udp_socket.get(index) {
            udp.send_to(buf, addr)?;
            self.record_up_traffic(index, buf.len());
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "udp main channel overflow",
            ))
        }
    }

    pub fn try_send_all(&self, buf: &[u8], addr: SocketAddr) {
        self.try_send_all_main(buf, addr);
    }

    pub fn try_send_all_main(&self, buf: &[u8], addr: SocketAddr) {
        for index in 0..self.channel_num {
            if let Err(e) = self.send_main(index, buf, addr) {
                log::warn!("{:?},addr={:?}", e, addr);
            }
        }
    }

    pub fn send_by_key(&self, buf: &[u8], route_key: RouteKey) -> io::Result<()> {
        if !route_key.protocol().is_udp() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not udp route: {:?}", route_key.protocol()),
            ));
        }
        self.send_main(route_key.index(), buf, route_key.addr)
    }

    pub fn start<H>(&self, stop_manager: StopManager, recv_handler: H) -> anyhow::Result<()>
    where
        H: Fn(&mut [u8], &mut [u8], RouteKey) + Clone + Send + Sync + 'static,
    {
        main_udp_listen(self.clone(), stop_manager, recv_handler)
    }

    fn record_up_traffic(&self, index: usize, len: usize) {
        if let Some(up_traffic_meter) = &self.up_traffic_meter {
            up_traffic_meter.add_traffic(index, len);
        }
    }

    fn record_down_traffic(&self, index: usize, len: usize) {
        if let Some(down_traffic_meter) = &self.down_traffic_meter {
            down_traffic_meter.add_traffic(index, len);
        }
    }
}

fn bind_udp_v4_and_v6(
    port: u16,
    default_interface: &crate::transport::socket::LocalInterface,
) -> anyhow::Result<(UdpSocket, UdpSocket)> {
    let mut count = 0;
    loop {
        let addr_v4: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
        let socket = crate::transport::socket::bind_udp(addr_v4, default_interface)?;
        if let Err(e) = socket.set_recv_buffer_size(2 * 1024 * 1024) {
            log::warn!("set_recv_buffer_size {:?}", e);
        }
        let main_channel_v4: UdpSocket = socket.into();
        let addr = main_channel_v4.local_addr()?;
        let addr_v6: SocketAddr = format!("[::]:{}", addr.port()).parse().unwrap();
        let socket = if port == 0 {
            match crate::transport::socket::bind_udp(addr_v6, default_interface) {
                Ok(socket) => socket,
                Err(e) => {
                    if count > 10 {
                        return Err(e);
                    }
                    if let Some(e) = e.downcast_ref::<std::io::Error>() {
                        if e.kind() == std::io::ErrorKind::AddrInUse {
                            count += 1;
                            continue;
                        }
                    }
                    Err(e)?
                }
            }
        } else {
            crate::transport::socket::bind_udp(addr_v6, default_interface)?
        };
        if let Err(e) = socket.set_recv_buffer_size(2 * 1024 * 1024) {
            log::warn!("set_recv_buffer_size {:?}", e);
        }
        let main_channel_v6: UdpSocket = socket.into();
        return Ok((main_channel_v4, main_channel_v6));
    }
}

fn main_udp_listen<H>(
    udp_channel: UdpChannel,
    stop_manager: StopManager,
    recv_handler: H,
) -> anyhow::Result<()>
where
    H: Fn(&mut [u8], &mut [u8], RouteKey) + Clone + Send + Sync + 'static,
{
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), NOTIFY)?);
    let wake = waker.clone();
    let worker = stop_manager.add_listener("main_udp".into(), move || {
        if let Err(e) = wake.wake() {
            log::error!("{:?}", e);
        }
    })?;
    thread::Builder::new()
        .name("mainUdp".into())
        .spawn(move || {
            if let Err(e) = main_udp_listen0(udp_channel, poll, recv_handler) {
                log::error!("{:?}", e);
            }
            drop(waker);
            worker.stop_all();
        })?;
    Ok(())
}

fn main_udp_listen0<H>(udp_channel: UdpChannel, mut poll: Poll, recv_handler: H) -> io::Result<()>
where
    H: Fn(&mut [u8], &mut [u8], RouteKey) + Clone + Send + Sync + 'static,
{
    let mut buf = [0; BUFFER_SIZE];
    let mut udps = Vec::with_capacity(udp_channel.main_len());
    for (index, udp) in udp_channel.main_udp_socket.iter().enumerate() {
        let udp_socket = udp.try_clone()?;
        udp_socket.set_nonblocking(true)?;
        let mut mio_udp = MioUdpSocket::from_std(udp_socket);
        poll.registry()
            .register(&mut mio_udp, Token(index + 1), Interest::READABLE)?;
        udps.push(mio_udp);
    }

    let mut events = Events::with_capacity(udps.len() + 1);
    let mut extend = [0; BUFFER_SIZE];
    loop {
        if let Err(e) = poll.poll(&mut events, None) {
            crate::ignore_io_interrupted(e)?;
            continue;
        }
        for event in events.iter() {
            let index = match event.token() {
                NOTIFY => return Ok(()),
                Token(index) => index - 1,
            };
            let udp = if let Some(udp) = udps.get(index) {
                udp
            } else {
                log::error!("invalid udp token {:?}", event.token());
                continue;
            };
            loop {
                match udp.recv_from(&mut buf) {
                    Ok((len, addr)) => {
                        udp_channel.record_down_traffic(index, len);
                        recv_handler(
                            &mut buf[..len],
                            &mut extend,
                            RouteKey::new(ConnectProtocol::UDP, index, addr),
                        )
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        log::error!("main_udp_listen_{}={:?}", index, e);
                    }
                }
            }
        }
    }
}
