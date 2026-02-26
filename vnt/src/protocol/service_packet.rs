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
    SecretHandshakeRequest,
    SecretHandshakeResponse,
    /// 客户端上报状态
    ClientStatusInfo,
    PunchRequest,
    PunchAck,
    PunchStart,
    PunchResult,
    PunchCancel,
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
            7 => Self::SecretHandshakeRequest,
            8 => Self::SecretHandshakeResponse,
            9 => Self::ClientStatusInfo,
            10 => Self::PunchRequest,
            11 => Self::PunchAck,
            12 => Self::PunchStart,
            13 => Self::PunchResult,
            14 => Self::PunchCancel,
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
            Self::SecretHandshakeRequest => 7,
            Self::SecretHandshakeResponse => 8,
            Self::ClientStatusInfo => 9,
            Self::PunchRequest => 10,
            Self::PunchAck => 11,
            Self::PunchStart => 12,
            Self::PunchResult => 13,
            Self::PunchCancel => 14,
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
