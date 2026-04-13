use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;

use crate::core::SdlRuntime;
use crate::nat::punch::{NatInfo, NatType, Punch};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::peer_discovery_packet::{DiscoverySessionId, DISCOVERY_SESSION_LEN};
use crate::protocol::{NetPacket, Protocol};

struct PunchSenders {
    sender_self: SyncSender<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
    sender_peer: SyncSender<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
    sender_cone_self: SyncSender<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
    sender_cone_peer: SyncSender<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
}

impl PunchSenders {
    fn send(
        &self,
        src_peer: bool,
        ip: Ipv4Addr,
        info: NatInfo,
        session_id: DiscoverySessionId,
    ) -> bool {
        log::info!(
            "发送打洞协商消息,是否对端发起:{},ip:{},info:{:?},session_id={},attempt={},txid={}",
            src_peer,
            ip,
            info,
            session_id.session_id(),
            session_id.attempt(),
            session_id.txid()
        );
        let sender = match info.nat_type() {
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
        let queued = sender.try_send((ip, info, session_id)).is_ok();
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
    receiver_peer: Receiver<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
    receiver_self: Receiver<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
    receiver_cone_peer: Receiver<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
    receiver_cone_self: Receiver<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
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

    pub fn submit_from_peer(
        &self,
        ip: Ipv4Addr,
        info: NatInfo,
        session_id: DiscoverySessionId,
    ) -> bool {
        self.inner.senders.send(true, ip, info, session_id)
    }

    pub fn submit_local(
        &self,
        ip: Ipv4Addr,
        info: NatInfo,
        session_id: DiscoverySessionId,
    ) -> bool {
        self.inner.senders.send(false, ip, info, session_id)
    }

    fn take_receivers(&self) -> Option<PunchReceivers> {
        self.inner.receivers.lock().take()
    }
}

pub fn spawn_punch_workers(runtime: Arc<SdlRuntime>, coordinator: PunchCoordinator, punch: Punch) {
    log::info!("control-driven punch enabled: starting punch workers");
    let Some(receivers) = coordinator.take_receivers() else {
        log::warn!("punch workers already started");
        return;
    };
    let punch_record = Arc::new(Mutex::new(HashMap::new()));
    let f = |receiver: Receiver<(Ipv4Addr, NatInfo, DiscoverySessionId)>| {
        let punch = punch.clone();
        let runtime = runtime.clone();
        let punch_record = punch_record.clone();
        thread::Builder::new()
            .name("punch".into())
            .spawn(move || {
                punch_start(receiver, punch, runtime, punch_record);
            })
            .expect("punch");
    };
    f(receivers.receiver_peer);
    f(receivers.receiver_self);
    f(receivers.receiver_cone_peer);
    f(receivers.receiver_cone_self);
}

fn punch_start(
    receiver: Receiver<(Ipv4Addr, NatInfo, DiscoverySessionId)>,
    mut punch: Punch,
    runtime: Arc<SdlRuntime>,
    punch_record: Arc<Mutex<HashMap<Ipv4Addr, usize>>>,
) {
    while let Ok((peer_ip, nat_info, session_id)) = receiver.recv() {
        let Some(session) = runtime.peer_discovery_session(&peer_ip) else {
            log::warn!(
                "skip discovery hello without active session for {}",
                peer_ip
            );
            continue;
        };
        let mut packet = NetPacket::new_encrypt(vec![
            0u8;
            12 + DISCOVERY_SESSION_LEN
                + session.hello_payload.len()
                + ENCRYPTION_RESERVED
        ])
        .unwrap();
        let source = runtime.current_device.load().virtual_ip();
        packet.set_default_version();
        packet.set_initial_ttl(1);
        packet.set_protocol(Protocol::PeerDiscovery);
        packet
            .set_transport_protocol(crate::protocol::peer_discovery_packet::Protocol::Hello.into());
        packet.set_source(source);
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

        let Some(peer_info) = runtime.peer_info(&peer_ip) else {
            log::warn!("skip discovery hello without peer identity for {}", peer_ip);
            continue;
        };
        let bootstrap_key = match crate::util::derive_peer_discovery_bootstrap_key(
            &runtime.device_signing_key,
            &peer_info.device_pub_key,
        ) {
            Ok(key) => key,
            Err(err) => {
                log::warn!(
                    "skip discovery hello without bootstrap key for {}: {:?}",
                    peer_ip,
                    err
                );
                continue;
            }
        };
        let Ok(cipher) = crate::cipher::Cipher::new_key(bootstrap_key) else {
            log::warn!(
                "skip discovery hello without bootstrap cipher for {}",
                peer_ip
            );
            continue;
        };
        session_id.write(packet.payload_mut()).unwrap();
        packet.payload_mut()
            [DISCOVERY_SESSION_LEN..DISCOVERY_SESSION_LEN + session.hello_payload.len()]
            .copy_from_slice(&session.hello_payload);
        if let Err(e) = cipher.encrypt_ipv4(&mut packet) {
            log::error!("{:?}", e);
            continue;
        }
        log::info!("开始发送 PeerDiscoveryHello,目标:{},第{}次", peer_ip, count);
        if let Err(e) = punch.punch(packet.buffer(), peer_ip, nat_info, count) {
            log::warn!("{:?}", e)
        } else {
            log::info!("PeerDiscoveryHello 发送完成,目标:{},第{}次", peer_ip, count);
        }
    }
}
