use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::core::PeerIdentity;

/// Shared peer-device table, protected by a RwLock.
/// `epoch` increments every time the server pushes a new device list so stale updates can be
/// detected and dropped.
#[derive(Debug, Default)]
pub struct PeerTable {
    epoch: u16,
    devices: HashMap<Ipv4Addr, PeerInfo>,
    vip_by_identity: HashMap<PeerIdentity, Ipv4Addr>,
    vip_by_device_id: HashMap<String, Ipv4Addr>,
}

impl PeerTable {
    pub fn new(epoch: u16, devices: HashMap<Ipv4Addr, PeerInfo>) -> Self {
        let mut table = Self {
            epoch,
            devices,
            vip_by_identity: HashMap::new(),
            vip_by_device_id: HashMap::new(),
        };
        table.rebuild_indexes();
        table
    }

    pub fn identity_for_vip(&self, vip: &Ipv4Addr) -> Option<PeerIdentity> {
        self.devices.get(vip).map(PeerInfo::identity)
    }

    pub fn epoch(&self) -> u16 {
        self.epoch
    }

    pub fn bump_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
    }

    pub fn reset_epoch(&mut self) {
        self.epoch = 0;
    }

    pub fn get(&self, vip: &Ipv4Addr) -> Option<&PeerInfo> {
        self.devices.get(vip)
    }

    pub fn values(&self) -> impl Iterator<Item = &PeerInfo> {
        self.devices.values()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn cloned_devices(&self) -> HashMap<Ipv4Addr, PeerInfo> {
        self.devices.clone()
    }

    pub fn devices(&self) -> &HashMap<Ipv4Addr, PeerInfo> {
        &self.devices
    }

    pub fn vip_for_identity(&self, identity: &PeerIdentity) -> Option<Ipv4Addr> {
        self.vip_by_identity.get(identity).copied()
    }

    pub fn vip_for_device_id(&self, device_id: &str) -> Option<Ipv4Addr> {
        self.vip_by_device_id.get(device_id).copied()
    }

    pub fn replace_devices(
        &mut self,
        epoch: u16,
        next_devices: HashMap<Ipv4Addr, PeerInfo>,
    ) -> HashMap<Ipv4Addr, PeerInfo> {
        let previous = std::mem::replace(&mut self.devices, next_devices);
        self.epoch = epoch;
        self.rebuild_indexes();
        previous
    }

    pub fn replace_devices_if_fresh(
        &mut self,
        epoch: u16,
        next_devices: HashMap<Ipv4Addr, PeerInfo>,
    ) -> Result<HashMap<Ipv4Addr, PeerInfo>, u16> {
        let current_epoch = self.epoch;
        if is_stale_epoch(current_epoch, epoch) {
            return Err(current_epoch);
        }
        Ok(self.replace_devices(epoch, next_devices))
    }

    pub fn clear_devices(&mut self) {
        self.devices.clear();
        self.vip_by_identity.clear();
        self.vip_by_device_id.clear();
    }

    fn rebuild_indexes(&mut self) {
        self.vip_by_identity.clear();
        self.vip_by_identity.extend(
            self.devices
                .values()
                .map(|peer| (peer.identity(), peer.virtual_ip)),
        );
        self.vip_by_device_id.clear();
        self.vip_by_device_id.extend(
            self.devices
                .values()
                .map(|peer| (peer.device_id.clone(), peer.virtual_ip)),
        );
    }
}

fn is_stale_epoch(current_epoch: u16, incoming_epoch: u16) -> bool {
    if current_epoch == 0 || incoming_epoch == current_epoch {
        return false;
    }
    current_epoch.wrapping_sub(incoming_epoch) < (u16::MAX / 2)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerInfo {
    pub(crate) virtual_ip: Ipv4Addr,
    pub(crate) name: String,
    pub(crate) status: PeerStatus,
    pub(crate) device_id: String,
    pub(crate) device_pub_key: Vec<u8>,
    identity: PeerIdentity,
    pub(crate) online_kx_pub: Vec<u8>,
    pub(crate) preferred_channel_mode: crate::proto::message::ChannelMode,
    pub(crate) exit_node_advertised: bool,
    pub(crate) exit_node_approved: bool,
    pub(crate) exit_node_usable: bool,
}

impl PeerInfo {
    pub fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn status(&self) -> PeerStatus {
        self.status
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn identity(&self) -> PeerIdentity {
        self.identity.clone()
    }

    pub fn exit_node_advertised(&self) -> bool {
        self.exit_node_advertised
    }

    pub fn exit_node_approved(&self) -> bool {
        self.exit_node_approved
    }

    pub fn exit_node_usable(&self) -> bool {
        self.exit_node_usable
    }

    pub(crate) fn from_control_device(info: crate::proto::message::DeviceInfo) -> Self {
        let identity = PeerIdentity::from_device_public_key(&info.device_pub_key);
        Self {
            virtual_ip: Ipv4Addr::from(info.virtual_ip),
            name: info.name,
            status: PeerStatus::from(info.device_status as u8),
            device_id: info.device_id,
            device_pub_key: info.device_pub_key,
            identity,
            online_kx_pub: info.online_kx_pub,
            preferred_channel_mode: info.preferred_channel_mode.enum_value_or_default(),
            exit_node_advertised: info.exit_node_advertised,
            exit_node_approved: info.exit_node_approved,
            exit_node_usable: info.exit_node_usable,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        virtual_ip: Ipv4Addr,
        name: String,
        status: u8,
        device_id: String,
        device_pub_key: Vec<u8>,
        online_kx_pub: Vec<u8>,
        preferred_channel_mode: crate::proto::message::ChannelMode,
        exit_node_advertised: bool,
        exit_node_approved: bool,
        exit_node_usable: bool,
    ) -> Self {
        let identity = PeerIdentity::from_device_public_key(&device_pub_key);
        Self {
            virtual_ip,
            name,
            status: PeerStatus::from(status),
            device_id,
            device_pub_key,
            identity,
            online_kx_pub,
            preferred_channel_mode,
            exit_node_advertised,
            exit_node_approved,
            exit_node_usable,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PeerStatus {
    Online,
    Offline,
}

impl PeerStatus {
    pub fn is_online(&self) -> bool {
        self == &PeerStatus::Online
    }
    pub fn is_offline(&self) -> bool {
        self == &PeerStatus::Offline
    }
}

impl From<u8> for PeerStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PeerStatus::Online,
            _ => PeerStatus::Offline,
        }
    }
}

impl From<PeerStatus> for u8 {
    fn from(value: PeerStatus) -> Self {
        match value {
            PeerStatus::Online => 0,
            PeerStatus::Offline => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use super::{PeerInfo, PeerTable};
    use crate::proto::message::ChannelMode;

    fn test_peer(vip: Ipv4Addr, device_id: &str) -> PeerInfo {
        PeerInfo::new(
            vip,
            device_id.to_string(),
            0,
            device_id.to_string(),
            vec![vip.octets()[3]],
            vec![],
            ChannelMode::CHANNEL_MODE_AUTO,
            false,
            false,
            false,
        )
    }

    #[test]
    fn device_id_index_tracks_replacement_and_clear() {
        let first_vip = Ipv4Addr::new(10, 26, 0, 4);
        let second_vip = Ipv4Addr::new(10, 26, 0, 10);
        let mut table = PeerTable::new(1, HashMap::from([(first_vip, test_peer(first_vip, "hk"))]));
        assert_eq!(table.vip_for_device_id("hk"), Some(first_vip));

        table.replace_devices(
            2,
            HashMap::from([(second_vip, test_peer(second_vip, "jp"))]),
        );
        assert_eq!(table.vip_for_device_id("hk"), None);
        assert_eq!(table.vip_for_device_id("jp"), Some(second_vip));

        table.clear_devices();
        assert_eq!(table.vip_for_device_id("jp"), None);
    }
}
