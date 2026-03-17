#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ConnectProtocol {
    UDP,
    TCP,
    QUIC,
    WS,
    WSS,
}

impl ConnectProtocol {
    #[inline]
    pub fn is_tcp(&self) -> bool {
        self == &ConnectProtocol::TCP
    }
    #[inline]
    pub fn is_quic(&self) -> bool {
        self == &ConnectProtocol::QUIC
    }
    #[inline]
    pub fn is_udp(&self) -> bool {
        self == &ConnectProtocol::UDP
    }
    #[inline]
    pub fn is_ws(&self) -> bool {
        self == &ConnectProtocol::WS
    }
    #[inline]
    pub fn is_wss(&self) -> bool {
        self == &ConnectProtocol::WSS
    }
    pub fn is_transport(&self) -> bool {
        self.is_tcp() || self.is_udp() || self.is_quic()
    }
    pub fn is_base_tcp(&self) -> bool {
        self.is_tcp() || self.is_quic() || self.is_ws() || self.is_wss()
    }
}
