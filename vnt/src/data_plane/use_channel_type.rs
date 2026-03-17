use std::str::FromStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum UseChannelType {
    Relay,
    P2p,
    All,
}

impl UseChannelType {
    pub fn is_only_relay(&self) -> bool {
        self == &UseChannelType::Relay
    }
    pub fn is_only_p2p(&self) -> bool {
        self == &UseChannelType::P2p
    }
    pub fn is_all(&self) -> bool {
        self == &UseChannelType::All
    }
}

impl FromStr for UseChannelType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "relay" => Ok(UseChannelType::Relay),
            "p2p" => Ok(UseChannelType::P2p),
            "all" => Ok(UseChannelType::All),
            _ => Err(format!("not match '{}', enum: relay/p2p/all", s)),
        }
    }
}

impl Default for UseChannelType {
    fn default() -> Self {
        UseChannelType::All
    }
}
