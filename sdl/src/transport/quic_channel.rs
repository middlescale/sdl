use anyhow::Context;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use rustls::RootCertStore;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::data_plane::route::RouteKey;
use crate::protocol::NetPacket;
use crate::protocol::BUFFER_SIZE;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::util::StopManager;

pub(crate) type PacketCallback = Arc<dyn Fn(Vec<u8>, RouteKey) + Send + Sync + 'static>;
type TransportErrorCallback = Arc<dyn Fn(String) + Send + Sync>;

enum QuicCommand {
    Send(Vec<u8>),
}

enum QuicReadEvent {
    Closed { connection_id: u64, reason: String },
}

struct ActiveConnection {
    connection_id: u64,
    addr: SocketAddr,
    config_rev: u64,
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
    server_name: Arc<Mutex<String>>,
    config_rev: Arc<AtomicU64>,
    // The currently usable QUIC connection. Gateway authentication is scoped to
    // this connection on the server, so callers must discard an ACK when this
    // value changes or becomes zero.
    active_generation: Arc<AtomicU64>,
    sender: Sender<QuicCommand>,
    receiver: Arc<Mutex<Option<Receiver<QuicCommand>>>>,
}

impl QuicChannel {
    pub fn new(server_addr: SocketAddr, server_name: String) -> Self {
        let (sender, receiver) = channel(128);
        Self {
            server_addr: Arc::new(AtomicCell::new(server_addr)),
            server_name: Arc::new(Mutex::new(server_name)),
            config_rev: Arc::new(AtomicU64::new(0)),
            active_generation: Arc::new(AtomicU64::new(0)),
            sender,
            receiver: Arc::new(Mutex::new(Some(receiver))),
        }
    }

    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
    {
        self.start_named_with_transport_error(stop_manager, "controlQuic", on_packet, |_| {})
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
        self.start_named_with_transport_error(stop_manager, worker_name, on_packet, |_| {})
    }

    pub fn start_with_transport_error<F, E>(
        &self,
        stop_manager: StopManager,
        on_packet: F,
        on_transport_error: E,
    ) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
        E: Fn(String) + Send + Sync + 'static,
    {
        self.start_named_with_transport_error(
            stop_manager,
            "controlQuic",
            on_packet,
            on_transport_error,
        )
    }

    pub fn start_named_with_transport_error<F, E>(
        &self,
        stop_manager: StopManager,
        worker_name: &str,
        on_packet: F,
        on_transport_error: E,
    ) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
        E: Fn(String) + Send + Sync + 'static,
    {
        let Some(receiver) = self.receiver.lock().take() else {
            return Ok(());
        };
        let callback: PacketCallback = Arc::new(on_packet);
        let on_transport_error: TransportErrorCallback = Arc::new(on_transport_error);
        let server_addr = self.server_addr.clone();
        let server_name = self.server_name.clone();
        let config_rev = self.config_rev.clone();
        let active_generation = self.active_generation.clone();
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
                    run_quic_worker(
                        receiver,
                        server_addr,
                        server_name,
                        config_rev,
                        active_generation,
                        callback,
                        on_transport_error,
                    )
                    .await;
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

    pub fn update_server_addr(&self, server_addr: SocketAddr) -> bool {
        if self.server_addr.load() == server_addr {
            return false;
        }
        self.server_addr.store(server_addr);
        self.config_rev.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr.load()
    }

    pub fn update_server_name(&self, server_name: String) -> bool {
        let mut current = self.server_name.lock();
        if *current == server_name {
            return false;
        }
        *current = server_name;
        self.config_rev.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn connection_generation(&self) -> u64 {
        self.active_generation.load(Ordering::Acquire)
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
    server_name: Arc<Mutex<String>>,
    config_rev: Arc<AtomicU64>,
    active_generation: Arc<AtomicU64>,
    on_packet: PacketCallback,
    on_transport_error: TransportErrorCallback,
) {
    let (read_event_sender, mut read_event_receiver) = channel(16);
    let mut active: Option<ActiveConnection> = None;
    let mut next_connection_id = 1u64;
    loop {
        tokio::select! {
            maybe_event = read_event_receiver.recv() => {
                let Some(event) = maybe_event else {
                    continue;
                };
                handle_read_event(&mut active, event, &active_generation, &on_transport_error);
            }
            maybe_command = receiver.recv() => {
                let Some(command) = maybe_command else {
                    break;
                };
                match command {
                    QuicCommand::Send(data) => {
                        let addr = server_addr.load();
                        let current_rev = config_rev.load(Ordering::Relaxed);
                        if active.as_ref().map(|v| (v.addr, v.config_rev)) != Some((addr, current_rev)) {
                            if let Some(connection) = active.take() {
                                clear_active_generation(&active_generation, connection.connection_id);
                                connection.close();
                            }
                        }
                        if active.is_none() {
                            let name = server_name.lock().clone();
                            match connect(addr, &name, b"sdl-control").await {
                                Ok(connection) => {
                                    let connection = register_active_connection(
                                        connection,
                                        current_rev,
                                        &mut next_connection_id,
                                        on_packet.clone(),
                                        read_event_sender.clone(),
                                        active_generation.clone(),
                                    );
                                    active = Some(connection);
                                }
                                Err(e) => {
                                    log::warn!("control quic connect failed {}: {:?}", addr, e);
                                    on_transport_error(format!(
                                        "control quic connect failed {}: {:?}",
                                        addr, e
                                    ));
                                    continue;
                                }
                            }
                        }
                        let send_result = if let Some(connection) = active.as_mut() {
                            connection.send.write_all(&frame_packet(&data)).await
                        } else {
                            continue;
                        };
                        if let Err(e) = send_result {
                            log::warn!("control quic send failed {}: {:?}", addr, e);
                            if let Some(connection) = active.take() {
                                clear_active_generation(&active_generation, connection.connection_id);
                                connection.close();
                            }
                            let name = server_name.lock().clone();
                            let current_rev = config_rev.load(Ordering::Relaxed);
                            match connect(addr, &name, b"sdl-control").await {
                                Ok(connection) => {
                                    let connection_id = next_connection_id;
                                    next_connection_id = next_connection_id.wrapping_add(1);
                                    let QuicClientConnection {
                                        addr,
                                        route_key,
                                        endpoint,
                                        mut send,
                                        recv,
                                    } = connection;
                                    active_generation.store(connection_id, Ordering::Release);
                                    spawn_quic_reader(
                                        connection_id,
                                        recv,
                                        route_key,
                                        on_packet.clone(),
                                        read_event_sender.clone(),
                                        active_generation.clone(),
                                    );
                                    if let Err(e) = send.write_all(&frame_packet(&data)).await {
                                        log::warn!("control quic resend failed {}: {:?}", addr, e);
                                        on_transport_error(format!(
                                            "control quic resend failed {}: {:?}",
                                            addr, e
                                        ));
                                        clear_active_generation(
                                            &active_generation,
                                            connection_id,
                                        );
                                        endpoint.close(0u32.into(), &[]);
                                    } else {
                                        active = Some(ActiveConnection {
                                            connection_id,
                                            addr,
                                            config_rev: current_rev,
                                            endpoint,
                                            send,
                                        });
                                    }
                                }
                                Err(e) => {
                                    log::warn!("control quic reconnect failed {}: {:?}", addr, e);
                                    on_transport_error(format!(
                                        "control quic reconnect failed {}: {:?}",
                                        addr, e
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(connection) = active {
        clear_active_generation(&active_generation, connection.connection_id);
        connection.close();
    }
}

fn register_active_connection(
    connection: QuicClientConnection,
    config_rev: u64,
    next_connection_id: &mut u64,
    on_packet: PacketCallback,
    read_event_sender: Sender<QuicReadEvent>,
    active_generation: Arc<AtomicU64>,
) -> ActiveConnection {
    let connection_id = *next_connection_id;
    *next_connection_id = next_connection_id.wrapping_add(1);
    let QuicClientConnection {
        addr,
        route_key,
        endpoint,
        send,
        recv,
    } = connection;
    active_generation.store(connection_id, Ordering::Release);
    spawn_quic_reader(
        connection_id,
        recv,
        route_key,
        on_packet,
        read_event_sender,
        active_generation,
    );
    ActiveConnection {
        connection_id,
        addr,
        config_rev,
        endpoint,
        send,
    }
}

fn spawn_quic_reader(
    connection_id: u64,
    mut recv: RecvStream,
    route_key: RouteKey,
    on_packet: PacketCallback,
    read_event_sender: Sender<QuicReadEvent>,
    active_generation: Arc<AtomicU64>,
) {
    tokio::spawn(async move {
        let reason = match read_framed_packets(&mut recv, route_key, on_packet).await {
            Ok(()) => format!(
                "control quic read loop ended unexpectedly {}",
                route_key.addr
            ),
            Err(e) => format!("control quic read failed {}: {:?}", route_key.addr, e),
        };
        clear_active_generation(&active_generation, connection_id);
        let _ = read_event_sender
            .send(QuicReadEvent::Closed {
                connection_id,
                reason,
            })
            .await;
    });
}

fn handle_read_event(
    active: &mut Option<ActiveConnection>,
    event: QuicReadEvent,
    active_generation: &Arc<AtomicU64>,
    on_transport_error: &TransportErrorCallback,
) {
    match event {
        QuicReadEvent::Closed {
            connection_id,
            reason,
        } => {
            if active.as_ref().map(|conn| conn.connection_id) != Some(connection_id) {
                return;
            }
            if let Some(connection) = active.take() {
                clear_active_generation(active_generation, connection.connection_id);
                connection.close();
            }
            on_transport_error(reason);
        }
    }
}

fn clear_active_generation(active_generation: &AtomicU64, generation: u64) {
    let _ = active_generation.compare_exchange(generation, 0, Ordering::AcqRel, Ordering::Acquire);
}

pub(crate) struct QuicClientConnection {
    pub addr: SocketAddr,
    pub route_key: RouteKey,
    pub endpoint: Endpoint,
    pub send: SendStream,
    pub recv: RecvStream,
}

async fn connect(
    addr: SocketAddr,
    server_name: &str,
    alpn: &[u8],
) -> anyhow::Result<QuicClientConnection> {
    let mut client_crypto = build_client_crypto()?;
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

    let connecting = endpoint.connect(addr, &server_name)?;
    let conn = tokio::time::timeout(Duration::from_secs(5), connecting).await??;
    let route_key = RouteKey::new(ConnectProtocol::QUIC, addr);
    let (send, recv) = conn.open_bi().await?;
    Ok(QuicClientConnection {
        addr,
        route_key,
        endpoint,
        send,
        recv,
    })
}

fn build_client_crypto() -> anyhow::Result<rustls::ClientConfig> {
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
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub fn extract_server_name(addr: &str) -> String {
    let raw = addr
        .trim()
        .strip_prefix("quic://")
        .unwrap_or(addr.trim())
        .trim();
    if let Some(host) = raw
        .strip_prefix('[')
        .and_then(|v| v.split_once(']'))
        .map(|v| v.0)
    {
        return host.to_string();
    }
    if raw.parse::<SocketAddr>().is_ok() {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            return addr.ip().to_string();
        }
    }
    raw.rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .unwrap_or_else(|| raw.to_string())
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
        consume_pending_frames(&mut pending, &mut on_packet)?;
    }
}

pub(crate) fn consume_pending_frames<F>(
    pending: &mut Vec<u8>,
    on_packet: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(Vec<u8>),
{
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
    Ok(())
}

pub(crate) fn frame_packet(data: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + data.len());
    framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
    framed.extend_from_slice(data);
    framed
}

#[cfg(test)]
mod tests {
    use super::{consume_pending_frames, frame_packet, QuicChannel};
    use std::net::SocketAddr;

    #[test]
    fn unchanged_gateway_config_does_not_bump_connection_revision() {
        let address: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let channel = QuicChannel::new(address, "gateway.example".into());

        assert!(!channel.update_server_addr(address));
        assert!(!channel.update_server_name("gateway.example".into()));
        assert_eq!(
            channel
                .config_rev
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        assert!(channel.update_server_addr("127.0.0.1:4434".parse().unwrap()));
        assert!(channel.update_server_name("other.example".into()));
        assert_eq!(
            channel
                .config_rev
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn frame_packet_prefixes_big_endian_length() {
        let framed = frame_packet(b"hello");
        assert_eq!(&framed[..4], &(5u32.to_be_bytes()));
        assert_eq!(&framed[4..], b"hello");
    }

    #[test]
    fn consume_pending_frames_drains_multiple_complete_packets() {
        let packet_a = vec![1u8; 12];
        let packet_b = vec![2u8; 20];
        let mut pending = frame_packet(&packet_a);
        pending.extend_from_slice(&frame_packet(&packet_b));

        let mut packets = Vec::new();
        consume_pending_frames(&mut pending, &mut |packet| packets.push(packet)).unwrap();

        assert!(pending.is_empty());
        assert_eq!(packets, vec![packet_a, packet_b]);
    }

    #[test]
    fn consume_pending_frames_keeps_partial_frame_buffered() {
        let packet = vec![7u8; 16];
        let framed = frame_packet(&packet);
        let mut pending = framed[..10].to_vec();

        let mut packets = Vec::new();
        consume_pending_frames(&mut pending, &mut |packet| packets.push(packet)).unwrap();

        assert!(packets.is_empty());
        assert_eq!(pending, framed[..10].to_vec());

        pending.extend_from_slice(&framed[10..]);
        consume_pending_frames(&mut pending, &mut |packet| packets.push(packet)).unwrap();

        assert!(pending.is_empty());
        assert_eq!(packets, vec![packet]);
    }

    #[test]
    fn consume_pending_frames_skips_too_short_packets() {
        let short_packet = vec![9u8; 11];
        let valid_packet = vec![8u8; 12];
        let mut pending = frame_packet(&short_packet);
        pending.extend_from_slice(&frame_packet(&valid_packet));

        let mut packets = Vec::new();
        consume_pending_frames(&mut pending, &mut |packet| packets.push(packet)).unwrap();

        assert!(pending.is_empty());
        assert_eq!(packets, vec![valid_packet]);
    }

    #[test]
    fn consume_pending_frames_rejects_invalid_lengths() {
        let mut pending = 0u32.to_be_bytes().to_vec();
        let err = consume_pending_frames(&mut pending, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("invalid quic frame length"));

        let oversize = ((crate::protocol::BUFFER_SIZE * 16 + 1) as u32).to_be_bytes();
        let mut pending = oversize.to_vec();
        let err = consume_pending_frames(&mut pending, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("invalid quic frame length"));
    }
}
