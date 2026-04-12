use std::sync::Arc;
use std::thread;

use crate::core::SdlRuntime;
use crate::data_plane::route::RouteKey;
use crate::handle::callback::SdlCallback;
use crate::handle::recv_data::client::ClientPacketHandler;
use crate::handle::recv_data::server::ServerPacketHandler;
use crate::handle::recv_data::turn::TurnPacketHandler;
use crate::handle::{CurrentDeviceInfo, SELF_IP};
use crate::protocol::{NetPacket, HEAD_LEN};
use crate::tun_tap_device::vnt_device::DeviceWrite;

mod client;
mod server;
mod turn;

#[derive(Clone)]
pub struct RecvDataHandler<Call, Device> {
    runtime: Arc<SdlRuntime>,
    turn: TurnPacketHandler,
    client: ClientPacketHandler<Device>,
    server: ServerPacketHandler<Call, Device>,
}

impl<Call: SdlCallback, Device: DeviceWrite> RecvDataHandler<Call, Device> {
    pub fn handle(&self, buf: &mut [u8], extend: &mut [u8], route_key: RouteKey) {
        if buf.len() < HEAD_LEN {
            return;
        }
        //判断stun响应包
        if route_key.protocol().is_udp() {
            if let Ok(rs) = self.runtime.nat_test.recv_data(route_key.addr(), buf) {
                if rs {
                    if self
                        .runtime
                        .control_session
                        .supports_udp_endpoint_report_v1()
                    {
                        self.runtime.control_session.trigger_status_report(
                            crate::proto::message::PunchTriggerReason::PunchTriggerStatusUpdate,
                        );
                    }
                    return;
                }
            }
        }
        if let Err(e) = self.handle0(buf, extend, route_key) {
            log::error!(
                "[{}]-{:?}-{:?}",
                thread::current().name().unwrap_or(""),
                route_key.addr(),
                e
            );
        }
    }

    pub fn new(runtime: Arc<SdlRuntime>, device: Device, callback: Call) -> Self {
        let server = ServerPacketHandler::new(runtime.clone(), device.clone(), callback);
        let client = ClientPacketHandler::new(runtime.clone(), device.clone());
        let turn = TurnPacketHandler::new(runtime.clone());
        Self {
            runtime,
            turn,
            client,
            server,
        }
    }

    fn handle0(
        &self,
        buf: &mut [u8],
        extend: &mut [u8],
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        let net_packet = NetPacket::new(buf)?;

        let extend = NetPacket::unchecked(extend);
        if net_packet.ttl() == 0 || net_packet.origin_ttl() < net_packet.ttl() {
            log::warn!("丢弃过时包:{:?} {}", net_packet.head(), route_key.addr());
            return Ok(());
        }
        let current_device = self.runtime.current_device.load();
        let dest = net_packet.destination();
        if dest == current_device.virtual_ip
            || dest.is_broadcast()
            || dest.is_multicast()
            || dest == SELF_IP
            || dest.is_unspecified()
            || dest == current_device.broadcast_ip
        {
            if is_claiming_control_or_service_packet(&net_packet, &current_device) {
                if !route_key.is_trusted_server_path() {
                    log::warn!(
                        "drop untrusted control/service packet source={} route_key={:?}",
                        net_packet.source(),
                        route_key
                    );
                    return Ok(());
                }
                //服务端-客户端包
                self.server
                    .handle(net_packet, extend, route_key, &current_device)
            } else {
                //客户端-客户端包
                self.client
                    .handle(net_packet, extend, route_key, &current_device)
            }
        } else {
            //转发包
            self.turn
                .handle(net_packet, extend, route_key, &current_device)
        }
    }
}

fn is_claiming_control_or_service_packet<B: AsRef<[u8]>>(
    net_packet: &NetPacket<B>,
    current_device: &CurrentDeviceInfo,
) -> bool {
    match net_packet.protocol() {
        crate::protocol::Protocol::Service | crate::protocol::Protocol::Error => true,
        crate::protocol::Protocol::Control => {
            current_device.is_control_vip(&net_packet.source())
                || current_device.is_gateway_vip(&net_packet.source())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_claiming_control_or_service_packet;
    use crate::data_plane::route::{RouteKey, RouteOrigin};
    use crate::handle::{CurrentDeviceInfo, CONTROL_VIP};
    use crate::protocol::{NetPacket, Protocol, HEAD_LEN};
    use crate::transport::connect_protocol::ConnectProtocol;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn route_key(origin: RouteOrigin) -> RouteKey {
        RouteKey::new_with_origin(
            ConnectProtocol::QUIC,
            origin,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 443)),
        )
    }

    fn control_device() -> CurrentDeviceInfo {
        CurrentDeviceInfo::new(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(10, 0, 0, 1),
        )
    }

    fn packet(protocol: Protocol, source: Ipv4Addr) -> NetPacket<Vec<u8>> {
        let mut packet = NetPacket::new(vec![0; HEAD_LEN]).unwrap();
        packet.set_default_version();
        packet.set_protocol(protocol);
        packet.set_transport_protocol(0);
        packet.set_initial_ttl(1);
        packet.set_source(source);
        packet.set_destination(Ipv4Addr::new(10, 0, 0, 2));
        packet
    }

    #[test]
    fn service_packets_claim_server_dispatch() {
        let packet = packet(Protocol::Service, CONTROL_VIP);
        let current_device = control_device();

        assert!(is_claiming_control_or_service_packet(
            &packet,
            &current_device
        ));
        assert!(route_key(RouteOrigin::ControlHttp3).is_trusted_server_path());
        assert!(!RouteKey::new_with_origin(
            ConnectProtocol::UDP,
            RouteOrigin::PeerUdp,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 20000))
        )
        .is_trusted_server_path());
    }

    #[test]
    fn control_packets_to_gateway_claim_server_dispatch() {
        let current_device = control_device();
        let packet = packet(Protocol::Control, current_device.virtual_gateway());

        assert!(is_claiming_control_or_service_packet(
            &packet,
            &current_device
        ));
        assert!(route_key(RouteOrigin::GatewayQuic).is_trusted_server_path());
    }

    #[test]
    fn peer_control_packets_do_not_claim_server_dispatch() {
        let current_device = control_device();
        let packet = packet(Protocol::Control, Ipv4Addr::new(10, 0, 0, 9));

        assert!(!is_claiming_control_or_service_packet(
            &packet,
            &current_device
        ));
    }
}

pub trait PacketHandler {
    fn handle(
        &self,
        net_packet: NetPacket<&mut [u8]>,
        extend: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()>;
}
