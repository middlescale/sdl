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
}

impl PeerTable {
    pub fn new(epoch: u16, devices: HashMap<Ipv4Addr, PeerInfo>) -> Self {
        let mut table = Self {
            epoch,
            devices,
            vip_by_identity: HashMap::new(),
        };
        table.rebuild_identity_index();
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

    pub fn replace_devices(
        &mut self,
        epoch: u16,
        next_devices: HashMap<Ipv4Addr, PeerInfo>,
    ) -> HashMap<Ipv4Addr, PeerInfo> {
        let previous = std::mem::replace(&mut self.devices, next_devices);
        self.epoch = epoch;
        self.rebuild_identity_index();
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
    }

    fn rebuild_identity_index(&mut self) {
        self.vip_by_identity.clear();
        self.vip_by_identity.extend(
            self.devices
                .values()
                .map(|peer| (peer.identity(), peer.virtual_ip)),
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
    pub virtual_ip: Ipv4Addr,
    pub name: String,
    pub status: PeerStatus,
    pub device_id: String,
    pub device_pub_key: Vec<u8>,
    identity: PeerIdentity,
    pub online_kx_pub: Vec<u8>,
    pub preferred_channel_mode: crate::proto::message::ChannelMode,
    pub exit_node_advertised: bool,
    pub exit_node_approved: bool,
    pub exit_node_usable: bool,
}

impl PeerInfo {
    pub fn identity(&self) -> PeerIdentity {
        self.identity.clone()
    }

    pub fn new(
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
