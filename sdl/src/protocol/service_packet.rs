#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// 注册请求
    RegistrationRequest,
    /// 注册响应
    RegistrationResponse,
    /// 拉取设备列表
    PullDeviceList,
    /// 推送设备列表
    PushDeviceList,
    /// 和服务端握手
    HandshakeRequest,
    HandshakeResponse,
    /// 客户端上报状态
    ClientStatusInfo,
    PunchRequest,
    PunchAck,
    PunchStart,
    PunchResult,
    PunchCancel,
    DeviceAuthRequest,
    DeviceAuthAck,
    DeviceAuthChallenge,
    DeviceAuthProof,
    GatewayReportRequest,
    GatewayReportAck,
    GatewayConnectHello,
    GatewayConnectAck,
    RefreshGatewayGrantRequest,
    RefreshGatewayGrantResponse,
    DnsQueryRequest,
    DnsQueryResponse,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::RegistrationRequest,
            2 => Self::RegistrationResponse,
            3 => Self::PullDeviceList,
            4 => Self::PushDeviceList,
            5 => Self::HandshakeRequest,
            6 => Self::HandshakeResponse,
            9 => Self::ClientStatusInfo,
            10 => Self::PunchRequest,
            11 => Self::PunchAck,
            12 => Self::PunchStart,
            13 => Self::PunchResult,
            14 => Self::PunchCancel,
            15 => Self::DeviceAuthRequest,
            16 => Self::DeviceAuthAck,
            23 => Self::DeviceAuthChallenge,
            24 => Self::DeviceAuthProof,
            17 => Self::GatewayReportRequest,
            18 => Self::GatewayReportAck,
            19 => Self::GatewayConnectHello,
            20 => Self::GatewayConnectAck,
            21 => Self::RefreshGatewayGrantRequest,
            22 => Self::RefreshGatewayGrantResponse,
            25 => Self::DnsQueryRequest,
            26 => Self::DnsQueryResponse,
            val => Self::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Self::RegistrationRequest => 1,
            Self::RegistrationResponse => 2,
            Self::PullDeviceList => 3,
            Self::PushDeviceList => 4,
            Self::HandshakeRequest => 5,
            Self::HandshakeResponse => 6,
            Self::ClientStatusInfo => 9,
            Self::PunchRequest => 10,
            Self::PunchAck => 11,
            Self::PunchStart => 12,
            Self::PunchResult => 13,
            Self::PunchCancel => 14,
            Self::DeviceAuthRequest => 15,
            Self::DeviceAuthAck => 16,
            Self::DeviceAuthChallenge => 23,
            Self::DeviceAuthProof => 24,
            Self::GatewayReportRequest => 17,
            Self::GatewayReportAck => 18,
            Self::GatewayConnectHello => 19,
            Self::GatewayConnectAck => 20,
            Self::RefreshGatewayGrantRequest => 21,
            Self::RefreshGatewayGrantResponse => 22,
            Self::DnsQueryRequest => 25,
            Self::DnsQueryResponse => 26,
            Self::Unknown(val) => val,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Protocol;

    #[test]
    fn punch_protocol_mapping_roundtrip() {
        let cases = [
            (10u8, Protocol::PunchRequest),
            (11u8, Protocol::PunchAck),
            (12u8, Protocol::PunchStart),
            (13u8, Protocol::PunchResult),
            (14u8, Protocol::PunchCancel),
            (15u8, Protocol::DeviceAuthRequest),
            (16u8, Protocol::DeviceAuthAck),
            (23u8, Protocol::DeviceAuthChallenge),
            (24u8, Protocol::DeviceAuthProof),
            (17u8, Protocol::GatewayReportRequest),
            (18u8, Protocol::GatewayReportAck),
            (21u8, Protocol::RefreshGatewayGrantRequest),
            (22u8, Protocol::RefreshGatewayGrantResponse),
            (25u8, Protocol::DnsQueryRequest),
            (26u8, Protocol::DnsQueryResponse),
        ];
        for (raw, expect) in cases {
            assert_eq!(Protocol::from(raw), expect);
            let back: u8 = expect.into();
            assert_eq!(back, raw);
        }
    }

    #[test]
    fn unknown_protocol_passthrough() {
        let p = Protocol::from(200);
        assert_eq!(p, Protocol::Unknown(200));
        let back: u8 = p.into();
        assert_eq!(back, 200);
    }
}
