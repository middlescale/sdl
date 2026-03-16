use anyhow::Context;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use rustls::RootCertStore;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::channel::{ConnectProtocol, RouteKey, BUFFER_SIZE};
use crate::protocol::NetPacket;
use crate::util::StopManager;

pub(crate) type PacketCallback = Arc<dyn Fn(Vec<u8>, RouteKey) + Send + Sync + 'static>;

enum QuicCommand {
    Send(Vec<u8>),
}

struct ActiveConnection {
    addr: SocketAddr,
    endpoint: Endpoint,
    send: SendStream,
}

impl ActiveConnection {
    fn close(self) {
        self.endpoint.close(0u32.into(), &[]);
    }
}

#[derive(Clone)]
pub struct QuicChannel {
    server_addr: Arc<AtomicCell<SocketAddr>>,
    sender: Sender<QuicCommand>,
    receiver: Arc<Mutex<Option<Receiver<QuicCommand>>>>,
}

impl QuicChannel {
    pub fn new(server_addr: SocketAddr) -> Self {
        let (sender, receiver) = channel(128);
        Self {
            server_addr: Arc::new(AtomicCell::new(server_addr)),
            sender,
            receiver: Arc::new(Mutex::new(Some(receiver))),
        }
    }

    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
    {
        self.start_named(stop_manager, "controlQuic", on_packet)
    }

    pub fn start_named<F>(
        &self,
        stop_manager: StopManager,
        worker_name: &str,
        on_packet: F,
    ) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
    {
        let Some(receiver) = self.receiver.lock().take() else {
            return Ok(());
        };
        let callback: PacketCallback = Arc::new(on_packet);
        let server_addr = self.server_addr.clone();
        let worker_name = worker_name.to_string();
        let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
        let worker = stop_manager.add_listener(worker_name.clone(), move || {
            let _ = stop_sender.send(());
        })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .with_context(|| format!("{worker_name} runtime build failed"))?;
        thread::Builder::new()
            .name(worker_name.clone())
            .spawn(move || {
                let worker_task = runtime.spawn(async move {
                    run_quic_worker(receiver, server_addr, callback).await;
                });
                runtime.block_on(async {
                    let mut worker_task = worker_task;
                    tokio::select! {
                        _ = stop_receiver => {
                            worker_task.abort();
                            let _ = worker_task.await;
                        }
                        _ = &mut worker_task => {}
                    }
                });
                runtime.shutdown_background();
                drop(worker);
            })
            .with_context(|| format!("{worker_name} thread build failed"))?;
        Ok(())
    }

    pub fn update_server_addr(&self, server_addr: SocketAddr) {
        self.server_addr.store(server_addr);
    }

    pub fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        self.sender
            .try_send(QuicCommand::Send(packet.buffer().to_vec()))
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "control quic queue full")
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::NotConnected, "control quic worker stopped")
                }
            })
    }
}

async fn run_quic_worker(
    mut receiver: Receiver<QuicCommand>,
    server_addr: Arc<AtomicCell<SocketAddr>>,
    on_packet: PacketCallback,
) {
    let mut active: Option<ActiveConnection> = None;
    while let Some(command) = receiver.recv().await {
        match command {
            QuicCommand::Send(data) => {
                let addr = server_addr.load();
                if active.as_ref().map(|v| v.addr) != Some(addr) {
                    if let Some(connection) = active.take() {
                        connection.close();
                    }
                }
                if active.is_none() {
                    match connect(addr, b"vnt-control").await {
                        Ok(connection) => {
                            let QuicClientConnection {
                                addr,
                                route_key,
                                endpoint,
                                send,
                                mut recv,
                            } = connection;
                            let callback = on_packet.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    read_framed_packets(&mut recv, route_key, callback).await
                                {
                                    log::warn!(
                                        "control quic read failed {:?}: {:?}",
                                        route_key.addr,
                                        e
                                    );
                                }
                            });
                            active = Some(ActiveConnection {
                                addr,
                                endpoint,
                                send,
                            });
                        }
                        Err(e) => {
                            log::warn!("control quic connect failed {}: {:?}", addr, e);
                            continue;
                        }
                    }
                }
                let send_result = if let Some(connection) = active.as_mut() {
                    connection.send.write_all(&frame_quic_packet(&data)).await
                } else {
                    continue;
                };
                if let Err(e) = send_result {
                    log::warn!("control quic send failed {}: {:?}", addr, e);
                    if let Some(connection) = active.take() {
                        connection.close();
                    }
                    match connect(addr, b"vnt-control").await {
                        Ok(connection) => {
                            let QuicClientConnection {
                                addr,
                                route_key,
                                endpoint,
                                mut send,
                                mut recv,
                            } = connection;
                            let callback = on_packet.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    read_framed_packets(&mut recv, route_key, callback).await
                                {
                                    log::warn!(
                                        "control quic read failed {:?}: {:?}",
                                        route_key.addr,
                                        e
                                    );
                                }
                            });
                            if let Err(e) = send.write_all(&frame_quic_packet(&data)).await {
                                log::warn!("control quic resend failed {}: {:?}", addr, e);
                                endpoint.close(0u32.into(), &[]);
                            } else {
                                active = Some(ActiveConnection {
                                    addr,
                                    endpoint,
                                    send,
                                });
                            }
                        }
                        Err(e) => {
                            log::warn!("control quic reconnect failed {}: {:?}", addr, e);
                        }
                    }
                }
            }
        }
    }
    if let Some(connection) = active {
        connection.close();
    }
}

pub(crate) struct QuicClientConnection {
    pub addr: SocketAddr,
    pub route_key: RouteKey,
    pub endpoint: Endpoint,
    pub send: SendStream,
    pub recv: RecvStream,
}

pub(crate) async fn connect(addr: SocketAddr, alpn: &[u8]) -> anyhow::Result<QuicClientConnection> {
    let mut roots = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        if let Err(e) = roots.add(cert) {
            log::warn!("skip system cert {:?}", e);
        }
    }
    if roots.is_empty() {
        anyhow::bail!("no valid system root certificates for quic");
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![alpn.to_vec()];
    let quic_crypto = QuicClientConfig::try_from(client_crypto)?;
    let client_config = ClientConfig::new(Arc::new(quic_crypto));

    let bind_addr: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let server_name = addr.ip().to_string();
    let connecting = endpoint.connect(addr, &server_name)?;
    let conn = tokio::time::timeout(Duration::from_secs(5), connecting).await??;
    let route_key = RouteKey::new(ConnectProtocol::QUIC, 0, addr);
    let (send, recv) = conn.open_bi().await?;
    Ok(QuicClientConnection {
        addr,
        route_key,
        endpoint,
        send,
        recv,
    })
}

pub(crate) async fn read_framed_packets(
    recv: &mut RecvStream,
    route_key: RouteKey,
    on_packet: PacketCallback,
) -> anyhow::Result<()> {
    read_framed_packets_with(recv, move |packet| on_packet(packet, route_key)).await
}

pub(crate) async fn read_framed_packets_with<F>(
    recv: &mut RecvStream,
    mut on_packet: F,
) -> anyhow::Result<()>
where
    F: FnMut(Vec<u8>),
{
    let mut buf = [0; BUFFER_SIZE];
    let mut pending = Vec::with_capacity(BUFFER_SIZE * 2);
    loop {
        let len = recv.read(&mut buf).await?;
        let Some(len) = len else {
            return Ok(());
        };
        pending.extend_from_slice(&buf[..len]);
        loop {
            if pending.len() < 4 {
                break;
            }
            let frame_len =
                u32::from_be_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;
            if frame_len == 0 || frame_len > BUFFER_SIZE * 16 {
                anyhow::bail!("invalid quic frame length: {}", frame_len);
            }
            if pending.len() < 4 + frame_len {
                break;
            }
            let packet = pending[4..4 + frame_len].to_vec();
            pending.drain(..4 + frame_len);
            if packet.len() < 12 {
                continue;
            }
            on_packet(packet);
        }
    }
}

pub(crate) fn frame_quic_packet(data: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + data.len());
    framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
    framed.extend_from_slice(data);
    framed
}
