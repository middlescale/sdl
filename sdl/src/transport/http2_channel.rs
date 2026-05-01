use anyhow::Context;
use bytes::Bytes;
use h2::client::{self, SendRequest};
use h2::RecvStream;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_rustls::TlsConnector;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::data_plane::route::RouteKey;
use crate::protocol::NetPacket;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::transport::quic_channel::{consume_pending_frames, frame_quic_packet, PacketCallback};
use crate::util::StopManager;

enum Http2Command {
    Send(Vec<u8>),
}

const GATEWAY_HTTP2_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_HTTP2_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

struct ActiveConnection {
    addr: SocketAddr,
    config_rev: u64,
    healthy: Arc<AtomicBool>,
    request_uri: String,
    send_request: SendRequest<Bytes>,
}

#[derive(Clone)]
pub struct Http2Channel {
    server_addr: Arc<AtomicCell<SocketAddr>>,
    server_name: Arc<Mutex<String>>,
    request_uri: Arc<Mutex<String>>,
    idle_timeout_ms: Arc<AtomicU64>,
    config_rev: Arc<AtomicU64>,
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

    pub fn update_server_addr(&self, server_addr: SocketAddr) {
        self.server_addr.store(server_addr);
        self.config_rev.fetch_add(1, Ordering::Relaxed);
    }

    pub fn update_server_name(&self, server_name: String) {
        *self.server_name.lock() = server_name;
        self.config_rev.fetch_add(1, Ordering::Relaxed);
    }

    pub fn update_request_uri(&self, request_uri: String) {
        *self.request_uri.lock() = request_uri;
        self.config_rev.fetch_add(1, Ordering::Relaxed);
    }

    pub fn update_idle_timeout(&self, idle_timeout: Duration) {
        let next = idle_timeout.as_millis().min(u128::from(u64::MAX)).max(1) as u64;
        self.idle_timeout_ms.store(next, Ordering::Relaxed);
    }

    pub fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        self.sender
            .try_send(Http2Command::Send(packet.buffer().to_vec()))
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "gateway http2 queue full")
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::NotConnected, "gateway http2 worker stopped")
                }
            })
    }
}

async fn run_http2_worker(
    mut receiver: Receiver<Http2Command>,
    server_addr: Arc<AtomicCell<SocketAddr>>,
    server_name: Arc<Mutex<String>>,
    request_uri: Arc<Mutex<String>>,
    idle_timeout_ms: Arc<AtomicU64>,
    config_rev: Arc<AtomicU64>,
    on_packet: PacketCallback,
) {
    let mut active: Option<ActiveConnection> = None;
    while let Some(command) = receiver.recv().await {
        match command {
            Http2Command::Send(data) => {
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
                    active = None;
                }
                if active.is_none() {
                    let uri = request_uri.lock().clone();
                    let name = server_name.lock().clone();
                    match connect(
                        addr,
                        &name,
                        &uri,
                        idle_timeout_ms.clone(),
                        on_packet.clone(),
                    )
                    .await
                    {
                        Ok(connection) => {
                            active = Some(ActiveConnection {
                                addr: connection.addr,
                                config_rev: current_rev,
                                healthy: connection.healthy,
                                request_uri: uri,
                                send_request: connection.send_request,
                            });
                        }
                        Err(e) => {
                            log::warn!("gateway http2 connect failed {}: {:?}", addr, e);
                            continue;
                        }
                    }
                }
                let send_result = if let Some(connection) = active.as_mut() {
                    let request_uri = connection.request_uri.clone();
                    send_packet(connection, &request_uri, &data).await
                } else {
                    continue;
                };
                if let Err(e) = send_result {
                    log::warn!("gateway http2 send failed {}: {:?}", addr, e);
                    active = None;
                    let current_rev = config_rev.load(Ordering::Relaxed);
                    let uri = request_uri.lock().clone();
                    let name = server_name.lock().clone();
                    match connect(
                        addr,
                        &name,
                        &uri,
                        idle_timeout_ms.clone(),
                        on_packet.clone(),
                    )
                    .await
                    {
                        Ok(connection) => {
                            let mut connection = ActiveConnection {
                                addr: connection.addr,
                                config_rev: current_rev,
                                healthy: connection.healthy,
                                request_uri: uri.clone(),
                                send_request: connection.send_request,
                            };
                            if let Err(e) = send_packet(&mut connection, &uri, &data).await {
                                log::warn!("gateway http2 resend failed {}: {:?}", addr, e);
                            } else {
                                active = Some(connection);
                                continue;
                            }
                        }
                        Err(e) => {
                            log::warn!("gateway http2 reconnect failed {}: {:?}", addr, e);
                        }
                    }
                }
            }
        }
    }
    drop(active);
}

struct Http2ClientConnection {
    addr: SocketAddr,
    healthy: Arc<AtomicBool>,
    send_request: SendRequest<Bytes>,
}

async fn connect(
    addr: SocketAddr,
    server_name: &str,
    request_uri: &str,
    idle_timeout_ms: Arc<AtomicU64>,
    on_packet: PacketCallback,
) -> anyhow::Result<Http2ClientConnection> {
    let stream =
        tokio::time::timeout(GATEWAY_HTTP2_CONNECT_TIMEOUT, TcpStream::connect(addr)).await??;
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
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("gateway http2 connection closed: {:?}", e);
        }
        connection_health.store(false, Ordering::Relaxed);
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(request_uri)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .header("x-sdl-http2-role", "downlink")
        .body(())?;
    let (response, _) = sender.send_request(request, true)?;
    let response = tokio::time::timeout(GATEWAY_HTTP2_RESPONSE_TIMEOUT, response).await??;
    if !response.status().is_success() {
        anyhow::bail!("gateway http2 response status {}", response.status());
    }
    let recv = response.into_body();
    let callback = on_packet.clone();
    let route_key = RouteKey::new(ConnectProtocol::TCP, addr);
    let read_health = healthy.clone();
    tokio::spawn(async move {
        if let Err(e) = read_h2_packets(recv, idle_timeout_ms, route_key, callback).await {
            log::warn!("gateway http2 read failed {:?}: {:?}", route_key.addr, e);
        } else {
            log::debug!("gateway http2 downlink closed {:?}", route_key.addr);
        }
        read_health.store(false, Ordering::Relaxed);
    });
    Ok(Http2ClientConnection {
        addr,
        healthy,
        send_request: sender,
    })
}

async fn send_packet(
    connection: &mut ActiveConnection,
    request_uri: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(request_uri)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .body(())?;
    let (response, mut send) = connection.send_request.send_request(request, false)?;
    send.send_data(Bytes::from(frame_quic_packet(data)), true)?;
    let response = tokio::time::timeout(GATEWAY_HTTP2_RESPONSE_TIMEOUT, response).await??;
    if !response.status().is_success() {
        anyhow::bail!("gateway http2 uplink response status {}", response.status());
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
    use super::active_connection_matches;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
}
