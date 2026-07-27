use crate::protocol::body::ENCRYPTION_RESERVED;
use std::net::Ipv4Addr;
use std::{fmt, io};

/*
   0                                            15                                              31
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |e |s |x |u|   版本(4) |      协议(8)          |      上层协议(8)        | 初始ttl(4) | 生存时间(4) |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                          源ip地址(32)                                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                          目的ip地址(32)                                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                           数据体                                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   注：e为是否加密标志，s为保留位，x扩展标志，u未使用
*/
pub const HEAD_LEN: usize = 12;
pub const BUFFER_SIZE: usize = 1024 * 64;

/// The common underlay MTU used for the default tunnel packet budget.
pub const DEFAULT_UNDERLAY_MTU: usize = 1500;
/// IPv4 and UDP headers added around an SDL packet on a P2P UDP path.
pub const IPV4_UDP_HEADER_LEN: usize = 20 + 8;
/// Bytes added to an inner IP packet before it is sent through P2P UDP.
/// Relay, QUIC, and HTTPS transports apply their MTU limits independently.
pub const P2P_UDP_ENVELOPE_OVERHEAD: usize = IPV4_UDP_HEADER_LEN + HEAD_LEN + ENCRYPTION_RESERVED;
/// Largest inner IP packet that avoids outer IPv4 fragmentation on a 1500-byte path.
pub const MAX_SAFE_TUN_MTU: usize = DEFAULT_UNDERLAY_MTU - P2P_UDP_ENVELOPE_OVERHEAD;
/// Conservative default that also fits common 1492-byte PPPoE paths.
pub const DEFAULT_TUN_MTU: u32 = 1380;

pub mod body;
pub mod control_packet;
pub mod error_packet;
pub mod extension;
pub mod ip_turn_packet;
pub mod other_turn_packet;
pub mod service_packet;

#[cfg(test)]
mod tests {
    use super::{DEFAULT_TUN_MTU, MAX_SAFE_TUN_MTU, P2P_UDP_ENVELOPE_OVERHEAD};

    #[test]
    fn default_tun_mtu_fits_the_p2p_udp_packet_budget() {
        assert!(DEFAULT_TUN_MTU as usize <= MAX_SAFE_TUN_MTU);
        assert_eq!(DEFAULT_TUN_MTU as usize + P2P_UDP_ENVELOPE_OVERHEAD, 1480);
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Version {
    V2,
    V3,
    Unknown(u8),
}

impl From<u8> for Version {
    fn from(value: u8) -> Self {
        match value {
            // 版本从2开始，用于和stun协议的binging响应区分开
            2 => Version::V2,
            3 => Version::V3,
            val => Version::Unknown(val),
        }
    }
}

impl Into<u8> for Version {
    fn into(self) -> u8 {
        match self {
            Version::V2 => 2,
            Version::V3 => 3,
            Version::Unknown(val) => val,
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// 服务包 用于和服务端交互
    Service,
    /// 响应异常
    Error,
    /// 控制协议
    Control,
    /// 转发ip数据
    IpTurn,
    /// 转发其他数据
    OtherTurn,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Service,
            2 => Protocol::Error,
            3 => Protocol::Control,
            4 => Protocol::IpTurn,
            5 => Protocol::OtherTurn,
            val => Protocol::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Service => 1,
            Protocol::Error => 2,
            Protocol::Control => 3,
            Protocol::IpTurn => 4,
            Protocol::OtherTurn => 5,
            Protocol::Unknown(val) => val,
        }
    }
}

pub const MAX_TTL: u8 = 0b1111;
pub const MAX_SOURCE: u8 = 0b11110000;

#[derive(Copy, Clone)]
pub struct NetPacket<B> {
    data_len: usize,
    buffer: B,
}

impl<B: AsRef<[u8]>> NetPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        let data_len = buffer.as_ref().len();
        Self { data_len, buffer }
    }
    pub fn new(buffer: B) -> io::Result<NetPacket<B>> {
        let data_len = buffer.as_ref().len();
        Self::new0(data_len, buffer)
    }
    pub fn new_encrypt(buffer: B) -> io::Result<NetPacket<B>> {
        if 12 + ENCRYPTION_RESERVED > buffer.as_ref().len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "length overflow",
            ));
        }
        //加密需要预留ENCRYPTION_RESERVED字节
        let data_len = buffer.as_ref().len() - ENCRYPTION_RESERVED;
        Self::new0(data_len, buffer)
    }
    pub fn new0(data_len: usize, buffer: B) -> io::Result<NetPacket<B>> {
        if data_len > buffer.as_ref().len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "length overflow",
            ));
        }
        if data_len < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data_len too short",
            ));
        }
        Ok(NetPacket { data_len, buffer })
    }
    #[inline]
    pub fn buffer(&self) -> &[u8] {
        &self.buffer.as_ref()[..self.data_len]
    }
    pub fn raw_buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }
    pub fn data_len(&self) -> usize {
        self.data_len
    }
    pub fn reserve(&self) -> usize {
        self.buffer.as_ref().len() - self.data_len
    }
    pub fn into_buffer(self) -> B {
        self.buffer
    }
}

impl<B: AsRef<[u8]>> NetPacket<B> {
    /// 数据加密
    pub fn is_encrypt(&self) -> bool {
        self.buffer.as_ref()[0] & 0x80 == 0x80
    }
    /// 扩展协议
    pub fn is_extension(&self) -> bool {
        self.buffer.as_ref()[0] & 0x20 == 0x20
    }
    pub fn version(&self) -> Version {
        Version::from(self.buffer.as_ref()[0] & 0x0F)
    }
    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.buffer.as_ref()[1])
    }
    pub fn transport_protocol(&self) -> u8 {
        self.buffer.as_ref()[2]
    }
    pub fn ttl(&self) -> u8 {
        self.buffer.as_ref()[3] & MAX_TTL
    }
    pub fn origin_ttl(&self) -> u8 {
        self.buffer.as_ref()[3] >> 4
    }
    pub fn source_ttl(&self) -> u8 {
        self.origin_ttl()
    }
    pub fn source(&self) -> Ipv4Addr {
        let tmp: [u8; 4] = self.buffer.as_ref()[4..8].try_into().unwrap();
        Ipv4Addr::from(tmp)
    }
    pub fn destination(&self) -> Ipv4Addr {
        let tmp: [u8; 4] = self.buffer.as_ref()[8..12].try_into().unwrap();
        Ipv4Addr::from(tmp)
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[12..self.data_len]
    }
    pub fn head(&self) -> &[u8] {
        &self.buffer.as_ref()[..12]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> NetPacket<B> {
    pub fn head_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..12]
    }
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..self.data_len]
    }
    pub fn set_encrypt_flag(&mut self, is_encrypt: bool) {
        if is_encrypt {
            self.buffer.as_mut()[0] = self.buffer.as_ref()[0] | 0x80
        } else {
            self.buffer.as_mut()[0] = self.buffer.as_ref()[0] & 0x7F
        };
    }
    pub fn set_extension_flag(&mut self, is_extension: bool) {
        if is_extension {
            self.buffer.as_mut()[0] = self.buffer.as_ref()[0] | 0x20
        } else {
            self.buffer.as_mut()[0] = self.buffer.as_ref()[0] & 0xDF
        };
    }
    pub fn set_default_version(&mut self) {
        let v: u8 = Version::V3.into();
        self.buffer.as_mut()[0] = (self.buffer.as_ref()[0] & 0xF0) | (0x0F & v);
    }
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.buffer.as_mut()[1] = protocol.into();
    }
    pub fn set_transport_protocol(&mut self, transport_protocol: u8) {
        self.buffer.as_mut()[2] = transport_protocol;
    }
    pub fn set_transport_protocol_into<P: Into<u8>>(&mut self, transport_protocol: P) {
        self.buffer.as_mut()[2] = transport_protocol.into();
    }
    pub fn set_initial_ttl(&mut self, ttl: u8) {
        self.buffer.as_mut()[3] = ttl << 4 | ttl;
    }
    pub fn set_ttl(&mut self, ttl: u8) {
        self.buffer.as_mut()[3] = (self.buffer.as_mut()[3] & MAX_SOURCE) | (MAX_TTL & ttl);
    }
    pub fn tick_ttl(&mut self) -> u8 {
        let ttl = self.ttl() - 1;
        self.set_ttl(ttl);
        ttl
    }
    pub fn set_origin_ttl(&mut self, origin_ttl: u8) {
        self.buffer.as_mut()[3] = (origin_ttl << 4) | (MAX_TTL & self.buffer.as_ref()[3]);
    }
    pub fn set_source_ttl(&mut self, source_ttl: u8) {
        self.set_origin_ttl(source_ttl);
    }
    pub fn set_source(&mut self, source: Ipv4Addr) {
        self.buffer.as_mut()[4..8].copy_from_slice(&source.octets());
    }
    pub fn set_destination(&mut self, destination: Ipv4Addr) {
        self.buffer.as_mut()[8..12].copy_from_slice(&destination.octets());
    }
    pub fn set_payload(&mut self, payload: &[u8]) -> io::Result<()> {
        if self.data_len - 12 != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data_len - 12 != payload.len",
            ));
        }
        self.buffer.as_mut()[12..self.data_len].copy_from_slice(payload);
        Ok(())
    }
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[12..self.data_len]
    }
    pub fn set_data_len(&mut self, data_len: usize) -> io::Result<()> {
        if data_len > self.buffer.as_ref().len() || data_len < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data_len invalid",
            ));
        }
        self.data_len = data_len;
        Ok(())
    }
    pub fn set_payload_len(&mut self, payload_len: usize) -> io::Result<()> {
        let data_len = HEAD_LEN + payload_len;
        self.set_data_len(data_len)
    }
    pub fn set_data_len_max(&mut self) {
        self.data_len = self.buffer.as_ref().len();
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for NetPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetPacket")
            .field("version", &self.version())
            .field("encrypt", &self.is_encrypt())
            .field("protocol", &self.protocol())
            .field("transport_protocol", &self.transport_protocol())
            .field("ttl", &self.ttl())
            .field("origin_ttl", &self.origin_ttl())
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("payload", &self.payload())
            .finish()
    }
}
