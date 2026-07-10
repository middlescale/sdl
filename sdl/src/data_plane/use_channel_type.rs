use std::str::FromStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum UseChannelType {
    Relay,
    P2p,
    Auto,
}

impl UseChannelType {
    pub fn is_only_relay(&self) -> bool {
        self == &UseChannelType::Relay
    }
    pub fn is_only_p2p(&self) -> bool {
        self == &UseChannelType::P2p
    }
    pub fn is_auto(&self) -> bool {
        self == &UseChannelType::Auto
    }
}

impl FromStr for UseChannelType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "relay" => Ok(UseChannelType::Relay),
            "p2p" => Ok(UseChannelType::P2p),
            "auto" => Ok(UseChannelType::Auto),
            _ => Err(format!("not match '{}', enum: relay/p2p/auto", s)),
        }
    }
}

impl Default for UseChannelType {
    fn default() -> Self {
        UseChannelType::Auto
    }
}
