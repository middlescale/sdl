use std::io;

use protobuf::Message;
use sdl_packet::ip::ipv4::packet::IpV4Packet;
use sdl_packet::ip::ipv4::protocol::Protocol as IpProtocol;
use sdl_packet::udp::udp::UdpPacket;

use crate::core::PendingDnsQuery;
use crate::proto::message::DnsQueryRequest;

pub(crate) fn build_dns_query_payload(request_id: u64, query: &[u8]) -> io::Result<Vec<u8>> {
    let request = DnsQueryRequest {
        request_id,
        query: query.to_vec(),
        ..Default::default()
    };
    request
        .write_to_bytes()
        .map_err(|err| io::Error::other(format!("DnsQueryRequest {:?}", err)))
}

pub(crate) fn build_dns_response_packet(
    pending: &PendingDnsQuery,
    response: &[u8],
) -> io::Result<Vec<u8>> {
    let udp_len = 8usize
        .checked_add(response.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "dns udp length overflow"))?;
    let total_len = 20usize
        .checked_add(udp_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "dns ip length overflow"))?;
    if udp_len > u16::MAX as usize || total_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns response too large for ipv4/udp",
        ));
    }
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[8] = 64;
    buf[9] = Into::<u8>::into(IpProtocol::Udp);
    buf[12..16].copy_from_slice(&pending.dns_server_ip.octets());
    buf[16..20].copy_from_slice(&pending.client_ip.octets());
    let udp_buf = &mut buf[20..];
    udp_buf[0..2].copy_from_slice(&53u16.to_be_bytes());
    udp_buf[2..4].copy_from_slice(&pending.client_port.to_be_bytes());
    udp_buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp_buf[8..].copy_from_slice(response);

    let mut udp = UdpPacket::new(pending.dns_server_ip, pending.client_ip, udp_buf)?;
    udp.update_checksum();

    let mut ipv4 = IpV4Packet::new(&mut buf)?;
    ipv4.update_checksum();
    Ok(buf)
}

pub(crate) fn build_dns_servfail_packet(
    pending: &PendingDnsQuery,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns query too short for SERVFAIL response",
        ));
    }
    let mut response = query.to_vec();
    // QR=1, preserve RD, and return SERVFAIL. The original question remains.
    response[2] = 0x80 | (query[2] & 0x01);
    response[3] = 0x02;
    response[6..12].fill(0);
    build_dns_response_packet(pending, &response)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use sdl_packet::ip::ipv4::packet::IpV4Packet;
    use sdl_packet::udp::udp::UdpPacket;

    use crate::core::PendingDnsQuery;

    use super::{build_dns_response_packet, build_dns_servfail_packet};

    #[test]
    fn builds_dns_response_packet_with_expected_addrs_and_ports() {
        let pending = PendingDnsQuery {
            client_ip: Ipv4Addr::new(10, 26, 0, 2),
            dns_server_ip: Ipv4Addr::new(10, 26, 0, 53),
            client_port: 40444,
        };
        let payload = [0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0];
        let packet = build_dns_response_packet(&pending, &payload).unwrap();
        let ipv4 = IpV4Packet::new(packet.as_slice()).unwrap();
        assert_eq!(ipv4.source_ip(), pending.dns_server_ip);
        assert_eq!(ipv4.destination_ip(), pending.client_ip);
        let udp = UdpPacket::new(pending.dns_server_ip, pending.client_ip, ipv4.payload()).unwrap();
        assert_eq!(udp.source_port(), 53);
        assert_eq!(udp.destination_port(), pending.client_port);
        assert_eq!(udp.payload(), &payload);
    }

    #[test]
    fn builds_servfail_that_preserves_question() {
        let pending = PendingDnsQuery::new(
            Ipv4Addr::new(10, 26, 0, 2),
            Ipv4Addr::new(10, 26, 0, 53),
            40444,
        );
        let query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let packet = build_dns_servfail_packet(&pending, &query).unwrap();
        let ipv4 = IpV4Packet::new(packet.as_slice()).unwrap();
        let udp = UdpPacket::new(pending.dns_server_ip, pending.client_ip, ipv4.payload()).unwrap();
        assert_eq!(&udp.payload()[0..2], &query[0..2]);
        assert_eq!(udp.payload()[2] & 0x80, 0x80);
        assert_eq!(udp.payload()[3] & 0x0f, 2);
    }
}
