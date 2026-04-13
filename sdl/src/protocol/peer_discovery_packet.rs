use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::{fmt, io};

use crate::nat::punch::{NatInfo, NatType, PunchModel};

const ENDPOINT_INFO_MAGIC: &[u8; 4] = b"SDPD";
const ENDPOINT_INFO_VERSION: u8 = 1;

pub const DISCOVERY_SESSION_LEN: usize = 20;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DiscoverySessionId {
    session_id: u64,
    attempt: u32,
    txid: u64,
}

impl DiscoverySessionId {
    pub fn new(session_id: u64, attempt: u32, txid: u64) -> Self {
        Self {
            session_id,
            attempt,
            txid,
        }
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn txid(&self) -> u64 {
        self.txid
    }

    pub fn same_transaction(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.attempt == other.attempt
            && self.txid == other.txid
    }

    pub fn same_attempt(&self, other: &Self) -> bool {
        self.session_id == other.session_id && self.attempt == other.attempt
    }

    pub fn read(payload: &[u8]) -> io::Result<Self> {
        if payload.len() < DISCOVERY_SESSION_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "len < 20"));
        }
        Ok(Self {
            session_id: u64::from_be_bytes(payload[..8].try_into().unwrap()),
            attempt: u32::from_be_bytes(payload[8..12].try_into().unwrap()),
            txid: u64::from_be_bytes(payload[12..20].try_into().unwrap()),
        })
    }

    pub fn write(&self, payload: &mut [u8]) -> io::Result<()> {
        if payload.len() < DISCOVERY_SESSION_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "len < 20"));
        }
        payload[..8].copy_from_slice(&self.session_id.to_be_bytes());
        payload[8..12].copy_from_slice(&self.attempt.to_be_bytes());
        payload[12..20].copy_from_slice(&self.txid.to_be_bytes());
        Ok(())
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    Hello,
    HelloAck,
    EndpointInfo,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Hello,
            2 => Protocol::HelloAck,
            3 => Protocol::EndpointInfo,
            val => Protocol::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Hello => 1,
            Protocol::HelloAck => 2,
            Protocol::EndpointInfo => 3,
            Protocol::Unknown(val) => val,
        }
    }
}

pub enum PeerDiscoveryPacket<'a> {
    Hello {
        session: DiscoverySessionId,
        payload: &'a [u8],
    },
    HelloAck {
        session: DiscoverySessionId,
        payload: &'a [u8],
    },
    EndpointInfo {
        session: DiscoverySessionId,
        payload: &'a [u8],
    },
}

#[derive(Clone, Debug)]
pub struct EndpointInfoPayload {
    reply: bool,
    public_udp_endpoints: Vec<SocketAddr>,
    local_udp_endpoints: Vec<SocketAddr>,
    public_port_range: u16,
    nat_type: NatType,
    punch_model: PunchModel,
}

impl EndpointInfoPayload {
    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.len() >= 4 && &payload[..4] == ENDPOINT_INFO_MAGIC {
            return Self::decode_native(payload);
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported legacy endpoint info payload",
        ))
    }

    pub fn from_nat_info(reply: bool, nat_info: &NatInfo) -> Self {
        Self {
            reply,
            public_udp_endpoints: nat_info.public_udp_endpoints().to_vec(),
            local_udp_endpoints: nat_info.local_udp_endpoints(),
            public_port_range: nat_info.public_port_range(),
            nat_type: nat_info.nat_type(),
            punch_model: nat_info.punch_model(),
        }
    }

    pub fn reply(&self) -> bool {
        self.reply
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(
            14 + self.public_udp_endpoints.len() * 19 + self.local_udp_endpoints.len() * 19,
        );
        buf.extend_from_slice(ENDPOINT_INFO_MAGIC);
        buf.push(ENDPOINT_INFO_VERSION);
        buf.push(u8::from(self.reply));
        buf.push(match self.nat_type {
            NatType::Symmetric => 0,
            NatType::Cone => 1,
        });
        buf.push(match self.punch_model {
            PunchModel::All => 0,
            PunchModel::IPv4 => 1,
            PunchModel::IPv6 => 2,
            PunchModel::IPv4Udp => 3,
            PunchModel::IPv6Udp => 4,
        });
        buf.extend_from_slice(&self.public_port_range.to_be_bytes());
        buf.extend_from_slice(&(self.public_udp_endpoints.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.local_udp_endpoints.len() as u16).to_be_bytes());
        for endpoint in &self.public_udp_endpoints {
            encode_socket_addr(endpoint, &mut buf);
        }
        for endpoint in &self.local_udp_endpoints {
            encode_socket_addr(endpoint, &mut buf);
        }
        Ok(buf)
    }

    pub fn into_nat_info(self) -> NatInfo {
        let public_ips = self
            .public_udp_endpoints
            .iter()
            .filter_map(|addr| match addr {
                SocketAddr::V4(addr) => Some(*addr.ip()),
                SocketAddr::V6(_) => None,
            })
            .collect();
        let public_ports = self
            .public_udp_endpoints
            .iter()
            .map(|addr| addr.port())
            .collect();
        let local_ipv4 = self.local_udp_endpoints.iter().find_map(|addr| match addr {
            SocketAddr::V4(addr) => Some(*addr.ip()),
            SocketAddr::V6(_) => None,
        });
        let ipv6 = self.local_udp_endpoints.iter().find_map(|addr| match addr {
            SocketAddr::V4(_) => None,
            SocketAddr::V6(addr) => Some(*addr.ip()),
        });
        let udp_ports = self
            .local_udp_endpoints
            .iter()
            .map(|addr| addr.port())
            .collect();
        NatInfo::new(
            public_ips,
            public_ports,
            self.public_udp_endpoints,
            self.public_port_range,
            local_ipv4,
            ipv6,
            udp_ports,
            self.nat_type,
            self.punch_model,
        )
    }

    fn decode_native(payload: &[u8]) -> io::Result<Self> {
        if payload.len() < 14 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "endpoint info native payload too short",
            ));
        }
        if payload[4] != ENDPOINT_INFO_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported endpoint info version",
            ));
        }
        let reply = payload[5] != 0;
        let nat_type = match payload[6] {
            0 => NatType::Symmetric,
            1 => NatType::Cone,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid endpoint info nat type",
                ))
            }
        };
        let punch_model = match payload[7] {
            0 => PunchModel::All,
            1 => PunchModel::IPv4,
            2 => PunchModel::IPv6,
            3 => PunchModel::IPv4Udp,
            4 => PunchModel::IPv6Udp,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid endpoint info punch model",
                ))
            }
        };
        let public_port_range = u16::from_be_bytes(payload[8..10].try_into().unwrap());
        let public_count = u16::from_be_bytes(payload[10..12].try_into().unwrap()) as usize;
        let local_count = u16::from_be_bytes(payload[12..14].try_into().unwrap()) as usize;
        let mut offset = 14;
        let mut public_udp_endpoints = Vec::with_capacity(public_count);
        for _ in 0..public_count {
            let (endpoint, next) = decode_socket_addr(payload, offset)?;
            public_udp_endpoints.push(endpoint);
            offset = next;
        }
        let mut local_udp_endpoints = Vec::with_capacity(local_count);
        for _ in 0..local_count {
            let (endpoint, next) = decode_socket_addr(payload, offset)?;
            local_udp_endpoints.push(endpoint);
            offset = next;
        }
        if offset != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "endpoint info trailing bytes",
            ));
        }
        Ok(Self {
            reply,
            public_udp_endpoints,
            local_udp_endpoints,
            public_port_range,
            nat_type,
            punch_model,
        })
    }
}

fn encode_socket_addr(addr: &SocketAddr, buf: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(addr) => {
            buf.push(4);
            buf.extend_from_slice(&addr.port().to_be_bytes());
            buf.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            buf.push(6);
            buf.extend_from_slice(&addr.port().to_be_bytes());
            buf.extend_from_slice(&addr.ip().octets());
        }
    }
}

fn decode_socket_addr(payload: &[u8], offset: usize) -> io::Result<(SocketAddr, usize)> {
    if offset + 3 > payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "endpoint info socket addr too short",
        ));
    }
    let family = payload[offset];
    let port = u16::from_be_bytes(payload[offset + 1..offset + 3].try_into().unwrap());
    match family {
        4 => {
            if offset + 7 > payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "endpoint info ipv4 too short",
                ));
            }
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&payload[offset + 3..offset + 7]).unwrap());
            Ok((SocketAddr::V4(SocketAddrV4::new(ip, port)), offset + 7))
        }
        6 => {
            if offset + 19 > payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "endpoint info ipv6 too short",
                ));
            }
            let ip =
                Ipv6Addr::from(<[u8; 16]>::try_from(&payload[offset + 3..offset + 19]).unwrap());
            Ok((
                SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
                offset + 19,
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid endpoint info address family",
        )),
    }
}

impl<'a> PeerDiscoveryPacket<'a> {
    pub fn new(protocol: u8, payload: &'a [u8]) -> io::Result<Self> {
        let session = DiscoverySessionId::read(payload)?;
        match Protocol::from(protocol) {
            Protocol::Hello => Ok(PeerDiscoveryPacket::Hello {
                session,
                payload: &payload[DISCOVERY_SESSION_LEN..],
            }),
            Protocol::HelloAck => Ok(PeerDiscoveryPacket::HelloAck {
                session,
                payload: &payload[DISCOVERY_SESSION_LEN..],
            }),
            Protocol::EndpointInfo => Ok(PeerDiscoveryPacket::EndpointInfo {
                session,
                payload: &payload[DISCOVERY_SESSION_LEN..],
            }),
            Protocol::Unknown(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported")),
        }
    }
}

impl fmt::Debug for PeerDiscoveryPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerDiscoveryPacket::Hello { session, .. } => {
                f.debug_tuple("Hello").field(session).finish()
            }
            PeerDiscoveryPacket::HelloAck { session, .. } => {
                f.debug_tuple("HelloAck").field(session).finish()
            }
            PeerDiscoveryPacket::EndpointInfo { session, .. } => {
                f.debug_tuple("EndpointInfo").field(session).finish()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DiscoverySessionId, EndpointInfoPayload, PeerDiscoveryPacket, Protocol,
        DISCOVERY_SESSION_LEN,
    };
    use crate::nat::punch::{NatInfo, NatType, PunchModel};
    use std::io;
    use std::net::Ipv4Addr;
    use std::net::{SocketAddr, SocketAddrV4};

    #[test]
    fn discovery_session_id_round_trips() {
        let session = DiscoverySessionId::new(7, 3, 11);
        let mut payload = [0u8; DISCOVERY_SESSION_LEN];
        session.write(&mut payload).unwrap();

        let parsed = DiscoverySessionId::read(&payload).unwrap();
        assert_eq!(parsed, session);
    }

    #[test]
    fn peer_discovery_packet_splits_session_and_payload() {
        let session = DiscoverySessionId::new(9, 4, 13);
        let mut payload = vec![0u8; DISCOVERY_SESSION_LEN + 3];
        session.write(&mut payload).unwrap();
        payload[DISCOVERY_SESSION_LEN..].copy_from_slice(&[1, 2, 3]);

        match PeerDiscoveryPacket::new(Protocol::Hello.into(), &payload).unwrap() {
            PeerDiscoveryPacket::Hello {
                session: parsed,
                payload,
            } => {
                assert_eq!(parsed, session);
                assert_eq!(payload, &[1, 2, 3]);
            }
            _ => panic!("unexpected packet"),
        }

        match PeerDiscoveryPacket::new(Protocol::HelloAck.into(), &payload).unwrap() {
            PeerDiscoveryPacket::HelloAck {
                session: parsed,
                payload,
            } => {
                assert_eq!(parsed, session);
                assert_eq!(payload, &[1, 2, 3]);
            }
            _ => panic!("unexpected packet"),
        }

        match PeerDiscoveryPacket::new(Protocol::EndpointInfo.into(), &payload).unwrap() {
            PeerDiscoveryPacket::EndpointInfo {
                session: parsed,
                payload,
            } => {
                assert_eq!(parsed, session);
                assert_eq!(payload, &[1, 2, 3]);
            }
            _ => panic!("unexpected packet"),
        }
    }

    #[test]
    fn endpoint_info_native_round_trips() {
        let nat_info = NatInfo::new(
            vec![Ipv4Addr::new(198, 51, 100, 10)],
            vec![4000],
            vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(198, 51, 100, 10),
                4000,
            ))],
            2,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            None,
            vec![4000],
            NatType::Cone,
            PunchModel::IPv4Udp,
        );
        let encoded = EndpointInfoPayload::from_nat_info(true, &nat_info)
            .encode()
            .unwrap();
        let decoded = EndpointInfoPayload::decode(&encoded)
            .unwrap()
            .into_nat_info();

        assert_eq!(decoded.public_port_range(), nat_info.public_port_range());
        assert_eq!(decoded.nat_type(), nat_info.nat_type());
        assert_eq!(decoded.punch_model(), nat_info.punch_model());
        assert_eq!(
            decoded.public_udp_endpoints(),
            nat_info.public_udp_endpoints()
        );
    }

    #[test]
    fn endpoint_info_rejects_legacy_payload() {
        let err = EndpointInfoPayload::decode(&[1, 2, 3]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
