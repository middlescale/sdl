use sdl_packet::icmp::icmp::{HeaderOther, IcmpPacket};
use sdl_packet::icmp::Kind;

#[derive(Clone, Copy, Debug)]
pub(crate) struct IcmpEchoMeta {
    pub kind: Kind,
    pub identifier: u16,
    pub sequence: u16,
    pub checksum_valid: bool,
}

impl IcmpEchoMeta {
    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            Kind::EchoRequest => "echo_request",
            Kind::EchoReply => "echo_reply",
            _ => "other",
        }
    }
}

pub(crate) fn parse_icmp_echo_meta<B: AsRef<[u8]>>(packet: &IcmpPacket<B>) -> Option<IcmpEchoMeta> {
    match (packet.kind(), packet.header_other()) {
        (Kind::EchoRequest, HeaderOther::Identifier(identifier, sequence))
        | (Kind::EchoReply, HeaderOther::Identifier(identifier, sequence)) => Some(IcmpEchoMeta {
            kind: packet.kind(),
            identifier,
            sequence,
            checksum_valid: packet.is_valid(),
        }),
        _ => None,
    }
}
