use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use crate::handle::CurrentDeviceInfo;
use crate::nat::punch::{NatInfo, NatType, Punch};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{control_packet, NetPacket, Protocol};
use crate::util::PeerCryptoManager;

struct PunchSenders {
    sender_self: SyncSender<(Ipv4Addr, NatInfo)>,
    sender_peer: SyncSender<(Ipv4Addr, NatInfo)>,
    sender_cone_self: SyncSender<(Ipv4Addr, NatInfo)>,
    sender_cone_peer: SyncSender<(Ipv4Addr, NatInfo)>,
}

impl PunchSenders {
    fn send(&self, src_peer: bool, ip: Ipv4Addr, info: NatInfo) -> bool {
        log::info!(
            "发送打洞协商消息,是否对端发起:{},ip:{},info:{:?}",
            src_peer,
            ip,
            info
        );
        let sender = match info.nat_type {
            NatType::Symmetric => {
                if src_peer {
                    &self.sender_peer
                } else {
                    &self.sender_self
                }
            }
            NatType::Cone => {
                if src_peer {
                    &self.sender_cone_peer
                } else {
                    &self.sender_cone_self
                }
            }
        };
        let queued = sender.try_send((ip, info)).is_ok();
        log::info!(
            "打洞任务入队结果,是否对端发起:{},ip:{},queued:{}",
            src_peer,
            ip,
            queued
        );
        queued
    }
}

struct PunchReceivers {
    receiver_peer: Receiver<(Ipv4Addr, NatInfo)>,
    receiver_self: Receiver<(Ipv4Addr, NatInfo)>,
    receiver_cone_peer: Receiver<(Ipv4Addr, NatInfo)>,
    receiver_cone_self: Receiver<(Ipv4Addr, NatInfo)>,
}

#[derive(Clone)]
pub struct PunchCoordinator {
    inner: Arc<PunchCoordinatorInner>,
}

struct PunchCoordinatorInner {
    senders: PunchSenders,
    receivers: Mutex<Option<PunchReceivers>>,
}

impl PunchCoordinator {
    pub fn new() -> Self {
        let (sender_self, receiver_self) = sync_channel(0);
        let (sender_peer, receiver_peer) = sync_channel(0);
        let (sender_cone_peer, receiver_cone_peer) = sync_channel(0);
        let (sender_cone_self, receiver_cone_self) = sync_channel(0);
        Self {
            inner: Arc::new(PunchCoordinatorInner {
                senders: PunchSenders {
                    sender_self,
                    sender_peer,
                    sender_cone_peer,
                    sender_cone_self,
                },
                receivers: Mutex::new(Some(PunchReceivers {
                    receiver_peer,
                    receiver_self,
                    receiver_cone_peer,
                    receiver_cone_self,
                })),
            }),
        }
    }

    pub fn submit_from_peer(&self, ip: Ipv4Addr, info: NatInfo) -> bool {
        self.inner.senders.send(true, ip, info)
    }

    pub fn submit_local(&self, ip: Ipv4Addr, info: NatInfo) -> bool {
        self.inner.senders.send(false, ip, info)
    }

    fn take_receivers(&self) -> Option<PunchReceivers> {
        self.inner.receivers.lock().take()
    }
}

pub fn spawn_punch_workers(
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    peer_crypto: Arc<PeerCryptoManager>,
    peer_encrypt: bool,
    coordinator: PunchCoordinator,
    punch: Punch,
) {
    log::info!("control-driven punch enabled: starting punch workers");
    let Some(receivers) = coordinator.take_receivers() else {
        log::warn!("punch workers already started");
        return;
    };
    let punch_record = Arc::new(Mutex::new(HashMap::new()));
    let f = |receiver: Receiver<(Ipv4Addr, NatInfo)>| {
        let punch = punch.clone();
        let current_device = current_device.clone();
        let peer_crypto = peer_crypto.clone();
        let peer_encrypt = peer_encrypt;
        let punch_record = punch_record.clone();
        thread::Builder::new()
            .name("punch".into())
            .spawn(move || {
                punch_start(
                    receiver,
                    punch,
                    current_device,
                    peer_crypto,
                    peer_encrypt,
                    punch_record,
                );
            })
            .expect("punch");
    };
    f(receivers.receiver_peer);
    f(receivers.receiver_self);
    f(receivers.receiver_cone_peer);
    f(receivers.receiver_cone_self);
}

fn punch_start(
    receiver: Receiver<(Ipv4Addr, NatInfo)>,
    mut punch: Punch,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    peer_crypto: Arc<PeerCryptoManager>,
    peer_encrypt: bool,
    punch_record: Arc<Mutex<HashMap<Ipv4Addr, usize>>>,
) {
    while let Ok((peer_ip, nat_info)) = receiver.recv() {
        let mut packet = NetPacket::new_encrypt([0u8; 12 + ENCRYPTION_RESERVED]).unwrap();
        packet.set_default_version();
        packet.set_initial_ttl(1);
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(control_packet::Protocol::PunchRequest.into());
        packet.set_source(current_device.load().virtual_ip());
        packet.set_destination(peer_ip);
        let count = {
            let mut guard = punch_record.lock();
            if let Some(v) = guard.get_mut(&peer_ip) {
                *v += 1;
                *v
            } else {
                guard.insert(peer_ip, 0);
                0
            }
        };
        log::info!("第{}次发起打洞,目标:{:?},{:?} ", count, peer_ip, nat_info);

        if peer_encrypt {
            let Ok(cipher) = peer_crypto.current_cipher(&peer_ip) else {
                log::warn!(
                    "skip punch request without peer session cipher for {}",
                    peer_ip
                );
                continue;
            };
            if let Err(e) = cipher.encrypt_ipv4(&mut packet) {
                log::error!("{:?}", e);
                continue;
            }
        }
        log::info!("开始发送 PunchRequest,目标:{},第{}次", peer_ip, count);
        if let Err(e) = punch.punch(packet.buffer(), peer_ip, nat_info, count) {
            log::warn!("{:?}", e)
        } else {
            log::info!("PunchRequest 发送完成,目标:{},第{}次", peer_ip, count);
        }
    }
}
