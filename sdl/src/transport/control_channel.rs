use std::io;
use std::net::SocketAddr;

use crate::data_plane::route::RouteKey;
use crate::protocol::NetPacket;
use crate::transport::http2_channel::Http2Channel;
use crate::transport::http3_channel::Http3Channel;
use crate::util::StopManager;

#[derive(Clone)]
pub enum ControlChannel {
    Http2(Http2Channel),
    Http3(Http3Channel),
}

impl ControlChannel {
    pub fn new(server_addr: SocketAddr, server_addr_str: &str) -> anyhow::Result<Self> {
        if server_addr_str.trim().starts_with("quic://") {
            Ok(Self::Http3(Http3Channel::new(
                server_addr,
                server_addr_str,
            )?))
        } else {
            Ok(Self::Http2(Http2Channel::new(
                server_addr,
                server_addr_str,
            )?))
        }
    }

    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
    {
        match self {
            Self::Http2(channel) => channel.start(stop_manager, on_packet),
            Self::Http3(channel) => channel.start(stop_manager, on_packet),
        }
    }

    pub fn update_server_addr(&self, server_addr: SocketAddr) {
        match self {
            Self::Http2(channel) => channel.update_server_addr(server_addr),
            Self::Http3(channel) => channel.update_server_addr(server_addr),
        }
    }

    pub fn server_addr(&self) -> SocketAddr {
        match self {
            Self::Http2(channel) => channel.server_addr(),
            Self::Http3(channel) => channel.server_addr(),
        }
    }

    pub fn update_server_name(&self, server_name: String) {
        match self {
            Self::Http2(channel) => channel.update_server_name(server_name.clone()),
            Self::Http3(channel) => channel.update_server_name(server_name),
        }
    }

    pub fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        match self {
            Self::Http2(channel) => channel.send_packet(packet),
            Self::Http3(channel) => channel.send_packet(packet),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ControlChannel;

    #[test]
    fn defaults_https_to_http2() {
        let channel = ControlChannel::new(
            "127.0.0.1:4433".parse().unwrap(),
            "https://127.0.0.1:4433/control",
        )
        .unwrap();
        assert!(matches!(channel, ControlChannel::Http2(_)));
    }

    #[test]
    fn keeps_quic_scheme_for_http3() {
        let channel =
            ControlChannel::new("127.0.0.1:4433".parse().unwrap(), "quic://127.0.0.1:4433")
                .unwrap();
        assert!(matches!(channel, ControlChannel::Http3(_)));
    }
}
