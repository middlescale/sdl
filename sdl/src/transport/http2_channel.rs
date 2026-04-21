use anyhow::Context;
use bytes::Bytes;
use h2::{client, RecvStream, SendStream};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use std::io;
use std::net::SocketAddr;
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
use crate::transport::control_addr::parse_control_address;
use crate::transport::quic_channel::{consume_pending_frames, frame_quic_packet, PacketCallback};
use crate::util::StopManager;

enum Http2Command {
    Send(Vec<u8>),
}

struct ActiveConnection {
    addr: SocketAddr,
    send: SendStream<Bytes>,
    connection_task: JoinHandle<()>,
    read_task: JoinHandle<()>,
}

impl ActiveConnection {
    fn close(self) {
        self.connection_task.abort();
        self.read_task.abort();
    }
}

#[derive(Clone)]
pub struct Http2Channel {
    server_addr: Arc<AtomicCell<SocketAddr>>,
    server_name: Arc<Mutex<String>>,
    request_uri: String,
    sender: Sender<Http2Command>,
    receiver: Arc<Mutex<Option<Receiver<Http2Command>>>>,
}

impl Http2Channel {
    pub fn new(server_addr: SocketAddr, server_addr_str: &str) -> anyhow::Result<Self> {
        let control_addr = parse_control_address(server_addr_str)?;
        let (sender, receiver) = channel(128);
        Ok(Self {
            server_addr: Arc::new(AtomicCell::new(server_addr)),
            server_name: Arc::new(Mutex::new(control_addr.server_name().to_string())),
            request_uri: control_addr.request_uri().to_string(),
            sender,
            receiver: Arc::new(Mutex::new(Some(receiver))),
        })
    }

    pub fn start<F>(&self, stop_manager: StopManager, on_packet: F) -> anyhow::Result<()>
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
        let worker_name = "controlHttp2".to_string();
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
                    run_http2_worker(receiver, server_addr, server_name, request_uri, callback)
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
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr.load()
    }

    pub fn update_server_name(&self, server_name: String) {
        *self.server_name.lock() = server_name;
    }

    pub fn send_packet<B: AsRef<[u8]>>(&self, packet: &NetPacket<B>) -> io::Result<()> {
        self.sender
            .try_send(Http2Command::Send(packet.buffer().to_vec()))
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "control http2 queue full")
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::NotConnected, "control http2 worker stopped")
                }
            })
    }
}

async fn run_http2_worker(
    mut receiver: Receiver<Http2Command>,
    server_addr: Arc<AtomicCell<SocketAddr>>,
    server_name: Arc<Mutex<String>>,
    request_uri: String,
    on_packet: PacketCallback,
) {
    let mut active: Option<ActiveConnection> = None;
    while let Some(command) = receiver.recv().await {
        match command {
            Http2Command::Send(data) => {
                let addr = server_addr.load();
                if active.as_ref().map(|conn| conn.addr) != Some(addr) {
                    if let Some(connection) = active.take() {
                        connection.close();
                    }
                }
                if active.is_none() {
                    let name = server_name.lock().clone();
                    match connect(addr, &name, &request_uri, on_packet.clone()).await {
                        Ok(connection) => active = Some(connection),
                        Err(e) => {
                            log::warn!("control http2 connect failed {}: {:?}", addr, e);
                            continue;
                        }
                    }
                }
                let frame = Bytes::from(frame_quic_packet(&data));
                let send_result = if let Some(connection) = active.as_mut() {
                    connection.send.send_data(frame, false)
                } else {
                    continue;
                };
                if let Err(e) = send_result {
                    log::warn!("control http2 send failed {}: {:?}", addr, e);
                    if let Some(connection) = active.take() {
                        connection.close();
                    }
                    let name = server_name.lock().clone();
                    match connect(addr, &name, &request_uri, on_packet.clone()).await {
                        Ok(mut connection) => {
                            if let Err(e) = connection
                                .send
                                .send_data(Bytes::from(frame_quic_packet(&data)), false)
                            {
                                log::warn!("control http2 resend failed {}: {:?}", addr, e);
                                connection.close();
                            } else {
                                active = Some(connection);
                            }
                        }
                        Err(e) => {
                            log::warn!("control http2 reconnect failed {}: {:?}", addr, e);
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

async fn connect(
    addr: SocketAddr,
    server_name: &str,
    request_uri: &str,
    on_packet: PacketCallback,
) -> anyhow::Result<ActiveConnection> {
    let mut roots = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        if let Err(e) = roots.add(cert) {
            log::warn!("skip system cert {:?}", e);
        }
    }
    if roots.is_empty() {
        anyhow::bail!("no valid system root certificates for http2");
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_crypto));

    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await??;
    tcp.set_nodelay(true)?;
    let server_name = ServerName::try_from(server_name.to_string())
        .with_context(|| format!("invalid control server name: {server_name}"))?;
    let tls =
        tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp)).await??;

    let (mut sender, connection) = client::handshake(tls).await?;
    let connection_task = tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("control http2 driver closed: {:?}", e);
        }
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(request_uri)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .body(())?;
    let (response, send) = sender.send_request(request, false)?;
    let response = response.await?;
    if !response.status().is_success() {
        anyhow::bail!("control http2 response status {}", response.status());
    }

    let recv = response.into_body();
    let route_key = RouteKey::new(ConnectProtocol::TCP, addr);
    let read_task = tokio::spawn(async move {
        if let Err(e) = read_h2_packets(recv, route_key, on_packet).await {
            log::warn!("control http2 read failed {:?}: {:?}", route_key.addr, e);
        }
    });

    Ok(ActiveConnection {
        addr,
        send,
        connection_task,
        read_task,
    })
}

async fn read_h2_packets(
    mut recv: RecvStream,
    route_key: RouteKey,
    on_packet: PacketCallback,
) -> anyhow::Result<()> {
    let mut pending = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk?;
        pending.extend_from_slice(chunk.as_ref());
        consume_pending_frames(&mut pending, &mut |packet| on_packet(packet, route_key))?;
    }
    Ok(())
}
