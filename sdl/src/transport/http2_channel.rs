use anyhow::Context;
use bytes::Bytes;
use h2::client;
use h2::RecvStream;
use h2::SendStream;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::data_plane::route::RouteKey;
use crate::protocol::NetPacket;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::transport::quic_channel::{consume_pending_frames, frame_packet, PacketCallback};
use crate::util::StopManager;

enum Http2Command {
    Send(Bytes),
}

const GATEWAY_HTTP2_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_HTTP2_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const GATEWAY_HTTP2_RECONNECT_INTERVAL: Duration = Duration::from_secs(1);
const GATEWAY_HTTP2_TRANSPORT_PING: &[u8] = b"SDLH2PNG";

struct ActiveConnection {
    addr: SocketAddr,
    config_rev: u64,
    generation: u64,
    healthy: Arc<AtomicBool>,
    active_generation: Arc<AtomicU64>,
    uplink_send: SendStream<Bytes>,
    connection_task: JoinHandle<()>,
    read_task: JoinHandle<()>,
}

impl ActiveConnection {
    fn close(self) {
        self.healthy.store(false, Ordering::Relaxed);
        let _ = self.active_generation.compare_exchange(
            self.generation,
            0,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        self.connection_task.abort();
        self.read_task.abort();
    }
}

#[derive(Clone)]
pub struct Http2Channel {
    server_addr: Arc<AtomicCell<SocketAddr>>,
    server_name: Arc<Mutex<String>>,
    request_uri: Arc<Mutex<String>>,
    idle_timeout_ms: Arc<AtomicU64>,
    config_rev: Arc<AtomicU64>,
    next_generation: Arc<AtomicU64>,
    active_generation: Arc<AtomicU64>,
    sender: Sender<Http2Command>,
    receiver: Arc<Mutex<Option<Receiver<Http2Command>>>>,
}

impl Http2Channel {
    pub fn new(server_addr: SocketAddr, request_uri: String, server_name: String) -> Self {
        let (sender, receiver) = channel(128);
        Self {
            server_addr: Arc::new(AtomicCell::new(server_addr)),
            server_name: Arc::new(Mutex::new(server_name)),
            request_uri: Arc::new(Mutex::new(request_uri)),
            idle_timeout_ms: Arc::new(AtomicU64::new(10_000)),
            config_rev: Arc::new(AtomicU64::new(0)),
            next_generation: Arc::new(AtomicU64::new(1)),
            active_generation: Arc::new(AtomicU64::new(0)),
            sender,
            receiver: Arc::new(Mutex::new(Some(receiver))),
        }
    }

    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
    where
        F: Fn(Vec<u8>, RouteKey) + Send + Sync + 'static,
    {
        self.start_named(stop_manager, "gatewayHttp2", on_packet)
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
        let server_name = self.server_name.clone();
        let request_uri = self.request_uri.clone();
        let idle_timeout_ms = self.idle_timeout_ms.clone();
        let config_rev = self.config_rev.clone();
        let next_generation = self.next_generation.clone();
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
                    run_http2_worker(
                        receiver,
                        server_addr,
                        server_name,
                        request_uri,
                        idle_timeout_ms,
                        config_rev,
                        next_generation,
                        active_generation,
                        callback,
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

    pub fn update_server_name(&self, server_name: String) -> bool {
        let mut current = self.server_name.lock();
        if *current == server_name {
            return false;
        }
        *current = server_name;
        self.config_rev.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn update_request_uri(&self, request_uri: String) -> bool {
        let mut current = self.request_uri.lock();
        if *current == request_uri {
            return false;
        }
        *current = request_uri;
        self.config_rev.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn update_idle_timeout(&self, idle_timeout: Duration) {
        let next = idle_timeout.as_millis().min(u128::from(u64::MAX)).max(1) as u64;
        self.idle_timeout_ms.store(next, Ordering::Relaxed);
    }

    pub fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        self.sender
            .try_send(Http2Command::Send(Bytes::from(frame_packet(
                packet.buffer(),
            ))))
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "gateway http2 queue full")
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::NotConnected, "gateway http2 worker stopped")
                }
            })
    }

    /// Zero means no live HTTP/2 connection. A nonzero value identifies the
    /// current connection and changes on every reconnect.
    pub fn connection_generation(&self) -> u64 {
        self.active_generation.load(Ordering::Relaxed)
    }
}

async fn run_http2_worker(
    mut receiver: Receiver<Http2Command>,
    server_addr: Arc<AtomicCell<SocketAddr>>,
    server_name: Arc<Mutex<String>>,
    request_uri: Arc<Mutex<String>>,
    idle_timeout_ms: Arc<AtomicU64>,
    config_rev: Arc<AtomicU64>,
    next_generation: Arc<AtomicU64>,
    active_generation: Arc<AtomicU64>,
    on_packet: PacketCallback,
) {
    let mut active: Option<ActiveConnection> = None;
    let mut maintain_connection = false;
    loop {
        if active.is_some() {
            let ping_interval = transport_ping_interval(Duration::from_millis(
                idle_timeout_ms.load(Ordering::Relaxed).max(1),
            ));
            tokio::select! {
                command = receiver.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    match command {
                        Http2Command::Send(data) => {
                            handle_send_command(
                                &mut active,
                                &server_addr,
                                &server_name,
                                &request_uri,
                                &idle_timeout_ms,
                                &config_rev,
                                &next_generation,
                                &active_generation,
                                &on_packet,
                                &mut maintain_connection,
                                data,
                            ).await;
                        }
                    }
                }
                _ = tokio::time::sleep(ping_interval) => {
                    let addr = server_addr.load();
                    let current_rev = config_rev.load(Ordering::Relaxed);
                    let active_matches = active_connection_matches(
                        active.as_ref().map(|connection| {
                            (
                                connection.addr,
                                connection.config_rev,
                                connection.healthy.load(Ordering::Relaxed),
                            )
                        }),
                        addr,
                        current_rev,
                    );
                    if !active_matches {
                        drop_active_connection(&mut active);
                        continue;
                    }
                    if let Some(connection) = active.as_mut() {
                        if let Err(err) = send_transport_ping(connection).await {
                            log::warn!("gateway http2 transport ping failed {}: {:?}", addr, err);
                            connection.healthy.store(false, Ordering::Relaxed);
                        }
                    }
                }
            }
        } else {
            if maintain_connection {
                tokio::select! {
                    command = receiver.recv() => {
                        let Some(command) = command else {
                            break;
                        };
                        match command {
                            Http2Command::Send(data) => {
                                handle_send_command(
                                    &mut active,
                                    &server_addr,
                                    &server_name,
                                    &request_uri,
                                &idle_timeout_ms,
                                &config_rev,
                                &next_generation,
                                &active_generation,
                                &on_packet,
                                &mut maintain_connection,
                                data,
                                )
                                .await;
                            }
                        }
                    }
                    _ = tokio::time::sleep(GATEWAY_HTTP2_RECONNECT_INTERVAL) => {
                        let addr = server_addr.load();
                        let current_rev = config_rev.load(Ordering::Relaxed);
                        let uri = request_uri.lock().clone();
                        let name = server_name.lock().clone();
                        match connect_active_connection(
                            addr,
                            &name,
                            &uri,
                            idle_timeout_ms.clone(),
                            on_packet.clone(),
                            current_rev,
                            next_generation.clone(),
                            active_generation.clone(),
                        ).await {
                            Ok(connection) => {
                                active = Some(connection);
                            }
                            Err(err) => {
                                log::warn!("gateway http2 passive reconnect failed {}: {:?}", addr, err);
                            }
                        }
                    }
                }
            } else {
                let Some(command) = receiver.recv().await else {
                    break;
                };
                match command {
                    Http2Command::Send(data) => {
                        handle_send_command(
                            &mut active,
                            &server_addr,
                            &server_name,
                            &request_uri,
                            &idle_timeout_ms,
                            &config_rev,
                            &next_generation,
                            &active_generation,
                            &on_packet,
                            &mut maintain_connection,
                            data,
                        )
                        .await;
                    }
                }
            }
        }
    }
    drop_active_connection(&mut active);
}

async fn handle_send_command(
    active: &mut Option<ActiveConnection>,
    server_addr: &Arc<AtomicCell<SocketAddr>>,
    server_name: &Arc<Mutex<String>>,
    request_uri: &Arc<Mutex<String>>,
    idle_timeout_ms: &Arc<AtomicU64>,
    config_rev: &Arc<AtomicU64>,
    next_generation: &Arc<AtomicU64>,
    active_generation: &Arc<AtomicU64>,
    on_packet: &PacketCallback,
    maintain_connection: &mut bool,
    data: Bytes,
) {
    let addr = server_addr.load();
    let current_rev = config_rev.load(Ordering::Relaxed);
    let active_matches = active_connection_matches(
        active.as_ref().map(|connection| {
            (
                connection.addr,
                connection.config_rev,
                connection.healthy.load(Ordering::Relaxed),
            )
        }),
        addr,
        current_rev,
    );
    if !active_matches {
        drop_active_connection(active);
    }
    if active.is_none() {
        let uri = request_uri.lock().clone();
        let name = server_name.lock().clone();
        match connect_active_connection(
            addr,
            &name,
            &uri,
            idle_timeout_ms.clone(),
            on_packet.clone(),
            current_rev,
            next_generation.clone(),
            active_generation.clone(),
        )
        .await
        {
            Ok(connection) => {
                *active = Some(connection);
                *maintain_connection = true;
            }
            Err(e) => {
                log::warn!("gateway http2 connect failed {}: {:?}", addr, e);
                return;
            }
        }
    }
    let send_result = if let Some(connection) = active.as_mut() {
        send_packet(connection, data.clone()).await
    } else {
        return;
    };
    if let Err(e) = send_result {
        log::warn!("gateway http2 send failed {}: {:?}", addr, e);
        drop_active_connection(active);
        let current_rev = config_rev.load(Ordering::Relaxed);
        let uri = request_uri.lock().clone();
        let name = server_name.lock().clone();
        match connect_active_connection(
            addr,
            &name,
            &uri,
            idle_timeout_ms.clone(),
            on_packet.clone(),
            current_rev,
            next_generation.clone(),
            active_generation.clone(),
        )
        .await
        {
            Ok(mut connection) => {
                if let Err(e) = send_packet(&mut connection, data).await {
                    log::warn!("gateway http2 resend failed {}: {:?}", addr, e);
                    connection.close();
                } else {
                    *active = Some(connection);
                    *maintain_connection = true;
                }
            }
            Err(e) => {
                log::warn!("gateway http2 reconnect failed {}: {:?}", addr, e);
            }
        }
    }
}

struct Http2ClientConnection {
    addr: SocketAddr,
    healthy: Arc<AtomicBool>,
    uplink_send: SendStream<Bytes>,
    connection_task: JoinHandle<()>,
    read_task: JoinHandle<()>,
}

async fn connect(
    addr: SocketAddr,
    server_name: &str,
    request_uri: &str,
    idle_timeout_ms: Arc<AtomicU64>,
    active_generation: Arc<AtomicU64>,
    generation: u64,
    on_packet: PacketCallback,
) -> anyhow::Result<Http2ClientConnection> {
    let stream =
        tokio::time::timeout(GATEWAY_HTTP2_CONNECT_TIMEOUT, TcpStream::connect(addr)).await??;
    stream.set_nodelay(true)?;
    let tls = TlsConnector::from(Arc::new(build_client_crypto()?));
    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("invalid gateway https server name {server_name}"))?;
    let tls_stream = tokio::time::timeout(
        GATEWAY_HTTP2_CONNECT_TIMEOUT,
        tls.connect(server_name, stream),
    )
    .await??;
    let (mut sender, connection) =
        tokio::time::timeout(GATEWAY_HTTP2_CONNECT_TIMEOUT, client::handshake(tls_stream))
            .await??;
    let healthy = Arc::new(AtomicBool::new(true));
    let connection_health = healthy.clone();
    let connection_generation = active_generation.clone();
    let connection_task = tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("gateway http2 connection closed: {:?}", e);
        }
        connection_health.store(false, Ordering::Relaxed);
        let _ = connection_generation.compare_exchange(
            generation,
            0,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(request_uri)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header("x-sdl-http2-role", "downlink")
        .body(())?;
    let (response, _) = match sender.send_request(request, true) {
        Ok(response) => response,
        Err(e) => {
            connection_task.abort();
            return Err(e.into());
        }
    };
    let response = match tokio::time::timeout(GATEWAY_HTTP2_RESPONSE_TIMEOUT, response).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            connection_task.abort();
            return Err(e.into());
        }
        Err(e) => {
            connection_task.abort();
            return Err(e.into());
        }
    };
    if !response.status().is_success() {
        connection_task.abort();
        anyhow::bail!("gateway http2 response status {}", response.status());
    }
    let recv = response.into_body();
    let callback = on_packet.clone();
    let route_key = RouteKey::new(ConnectProtocol::TCP, addr);
    let read_health = healthy.clone();
    let read_generation = active_generation.clone();
    let read_task = tokio::spawn(async move {
        if let Err(e) = read_h2_packets(recv, idle_timeout_ms, route_key, callback).await {
            log::warn!("gateway http2 read failed {:?}: {:?}", route_key.addr, e);
        } else {
            log::debug!("gateway http2 downlink closed {:?}", route_key.addr);
        }
        read_health.store(false, Ordering::Relaxed);
        let _ =
            read_generation.compare_exchange(generation, 0, Ordering::Relaxed, Ordering::Relaxed);
    });
    let uplink_request = http::Request::builder()
        .method(http::Method::POST)
        .uri(request_uri)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header("x-sdl-http2-role", "uplink")
        .body(())?;
    let (uplink_response, uplink_send) = match sender.send_request(uplink_request, false) {
        Ok(value) => value,
        Err(e) => {
            connection_task.abort();
            read_task.abort();
            return Err(e.into());
        }
    };
    let uplink_response =
        match tokio::time::timeout(GATEWAY_HTTP2_RESPONSE_TIMEOUT, uplink_response).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                connection_task.abort();
                read_task.abort();
                return Err(e.into());
            }
            Err(e) => {
                connection_task.abort();
                read_task.abort();
                return Err(e.into());
            }
        };
    if !uplink_response.status().is_success() {
        connection_task.abort();
        read_task.abort();
        anyhow::bail!(
            "gateway http2 uplink response status {}",
            uplink_response.status()
        );
    }
    Ok(Http2ClientConnection {
        addr,
        healthy,
        uplink_send,
        connection_task,
        read_task,
    })
}

async fn connect_active_connection(
    addr: SocketAddr,
    server_name: &str,
    request_uri: &str,
    idle_timeout_ms: Arc<AtomicU64>,
    on_packet: PacketCallback,
    config_rev: u64,
    next_generation: Arc<AtomicU64>,
    active_generation: Arc<AtomicU64>,
) -> anyhow::Result<ActiveConnection> {
    let generation = next_generation.fetch_add(1, Ordering::Relaxed);
    let connection = connect(
        addr,
        server_name,
        request_uri,
        idle_timeout_ms,
        active_generation.clone(),
        generation,
        on_packet,
    )
    .await?;
    active_generation.store(generation, Ordering::Relaxed);
    Ok(ActiveConnection {
        addr: connection.addr,
        config_rev,
        generation,
        healthy: connection.healthy,
        active_generation,
        uplink_send: connection.uplink_send,
        connection_task: connection.connection_task,
        read_task: connection.read_task,
    })
}

async fn send_packet(connection: &mut ActiveConnection, data: Bytes) -> anyhow::Result<()> {
    if !connection.healthy.load(Ordering::Relaxed) {
        anyhow::bail!("gateway http2 connection is unhealthy");
    }
    wait_for_send_capacity(&mut connection.uplink_send, data.len()).await?;
    connection.uplink_send.send_data(data, false)?;
    Ok(())
}

async fn send_transport_ping(connection: &mut ActiveConnection) -> anyhow::Result<()> {
    if !connection.healthy.load(Ordering::Relaxed) {
        anyhow::bail!("gateway http2 connection is unhealthy");
    }
    let payload = Bytes::from(frame_packet(GATEWAY_HTTP2_TRANSPORT_PING));
    wait_for_send_capacity(&mut connection.uplink_send, payload.len()).await?;
    connection.uplink_send.send_data(payload, false)?;
    Ok(())
}

async fn wait_for_send_capacity(
    send: &mut SendStream<Bytes>,
    required: usize,
) -> anyhow::Result<()> {
    if required == 0 {
        return Ok(());
    }
    while send.capacity() < required {
        send.reserve_capacity(required);
        tokio::time::timeout(
            GATEWAY_HTTP2_RESPONSE_TIMEOUT,
            poll_fn(|cx| match send.poll_capacity(cx) {
                std::task::Poll::Ready(Some(Ok(_))) => std::task::Poll::Ready(Ok(())),
                std::task::Poll::Ready(Some(Err(err))) => {
                    std::task::Poll::Ready(Err(anyhow::Error::from(err)))
                }
                std::task::Poll::Ready(None) => {
                    std::task::Poll::Ready(Err(anyhow::anyhow!("gateway http2 uplink closed")))
                }
                std::task::Poll::Pending => std::task::Poll::Pending,
            }),
        )
        .await??;
    }
    Ok(())
}

fn active_connection_matches(
    active: Option<(SocketAddr, u64, bool)>,
    addr: SocketAddr,
    config_rev: u64,
) -> bool {
    matches!(
        active,
        Some((active_addr, active_rev, true)) if active_addr == addr && active_rev == config_rev
    )
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
        anyhow::bail!("no valid system root certificates for gateway http2");
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

fn transport_ping_interval(idle_timeout: Duration) -> Duration {
    let half_idle = idle_timeout.div_f64(2.0);
    half_idle.max(Duration::from_secs(3))
}

fn drop_active_connection(active: &mut Option<ActiveConnection>) {
    if let Some(connection) = active.take() {
        connection.close();
    }
}

async fn read_h2_packets(
    mut recv: RecvStream,
    idle_timeout_ms: Arc<AtomicU64>,
    route_key: RouteKey,
    on_packet: PacketCallback,
) -> anyhow::Result<()> {
    let mut flow_control = recv.flow_control().clone();
    let mut pending = Vec::new();
    loop {
        let idle_timeout = Duration::from_millis(idle_timeout_ms.load(Ordering::Relaxed).max(1));
        let chunk = match tokio::time::timeout(idle_timeout, recv.data()).await {
            Ok(chunk) => chunk,
            Err(_) => {
                anyhow::bail!(
                    "gateway http2 downlink idle timeout after {}ms",
                    idle_timeout.as_millis()
                );
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        let bytes = chunk?;
        log::debug!("gateway http2 recv chunk bytes={}", bytes.len());
        pending.extend_from_slice(bytes.as_ref());
        let _ = flow_control.release_capacity(bytes.len());
        consume_pending_frames(&mut pending, &mut |packet| {
            log::debug!("gateway http2 recv framed packet bytes={}", packet.len());
            on_packet(packet, route_key)
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{active_connection_matches, transport_ping_interval, Http2Channel};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn active_connection_matches_current_config_when_healthy() {
        assert!(active_connection_matches(
            Some((addr(443), 7, true)),
            addr(443),
            7
        ));
    }

    #[test]
    fn active_connection_rejected_when_downlink_unhealthy() {
        assert!(!active_connection_matches(
            Some((addr(443), 7, false)),
            addr(443),
            7
        ));
    }

    #[test]
    fn active_connection_rejected_after_config_change() {
        assert!(!active_connection_matches(
            Some((addr(443), 7, true)),
            addr(443),
            8
        ));
    }

    #[test]
    fn unchanged_gateway_config_does_not_bump_connection_revision() {
        let channel = Http2Channel::new(
            addr(443),
            "https://gateway.example/gateway".into(),
            "gateway.example".into(),
        );

        assert!(!channel.update_server_addr(addr(443)));
        assert!(!channel.update_server_name("gateway.example".into()));
        assert!(!channel.update_request_uri("https://gateway.example/gateway".into()));
        assert_eq!(
            channel
                .config_rev
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        assert!(channel.update_server_name("other.example".into()));
        assert_eq!(
            channel
                .config_rev
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn transport_ping_interval_uses_half_idle_timeout_with_floor() {
        assert_eq!(
            transport_ping_interval(Duration::from_secs(10)),
            Duration::from_secs(5)
        );
        assert_eq!(
            transport_ping_interval(Duration::from_secs(4)),
            Duration::from_secs(3)
        );
    }
}
