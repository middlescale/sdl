use anyhow::Context;
use bytes::{Buf, Bytes};
use futures_util::future;
use h3::client::{RequestStream, SendRequest};
use h3_quinn::quinn::crypto::rustls::QuicClientConfig;
use h3_quinn::{quinn, RecvStream as H3RecvStream, SendStream as H3SendStream};
use rustls::RootCertStore;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::data_plane::route::RouteKey;
use crate::protocol::NetPacket;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::transport::control_addr::parse_control_address;
use crate::transport::quic_channel::{consume_pending_frames, frame_quic_packet, PacketCallback};
use crate::util::StopManager;

enum Http3Command {
    Send(Vec<u8>),
}

struct ActiveConnection {
    addr: SocketAddr,
    endpoint: quinn::Endpoint,
    _request_sender: SendRequest<h3_quinn::OpenStreams, Bytes>,
    send: RequestStream<H3SendStream<Bytes>, Bytes>,
}

impl ActiveConnection {
    fn close(self) {
        self.endpoint.close(0u32.into(), &[]);
    }
}

#[derive(Clone)]
pub struct Http3Channel {
    server_addr: Arc<AtomicCell<SocketAddr>>,
    server_name: Arc<Mutex<String>>,
    request_uri: String,
    sender: Sender<Http3Command>,
    receiver: Arc<Mutex<Option<Receiver<Http3Command>>>>,
}

impl Http3Channel {
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
        let worker_name = "controlHttp3".to_string();
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
                    run_http3_worker(receiver, server_addr, server_name, request_uri, callback)
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
            .try_send(Http3Command::Send(packet.buffer().to_vec()))
            .map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "control http3 queue full")
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::NotConnected, "control http3 worker stopped")
                }
            })
    }
}

async fn run_http3_worker(
    mut receiver: Receiver<Http3Command>,
    server_addr: Arc<AtomicCell<SocketAddr>>,
    server_name: Arc<Mutex<String>>,
    request_uri: String,
    on_packet: PacketCallback,
) {
    let mut active: Option<ActiveConnection> = None;
    while let Some(command) = receiver.recv().await {
        match command {
            Http3Command::Send(data) => {
                let addr = server_addr.load();
                if active.as_ref().map(|conn| conn.addr) != Some(addr) {
                    if let Some(connection) = active.take() {
                        connection.close();
                    }
                }
                if active.is_none() {
                    let name = server_name.lock().clone();
                    match connect(addr, &name, &request_uri).await {
                        Ok(connection) => {
                            let Http3ClientConnection {
                                addr,
                                route_key,
                                endpoint,
                                request_sender,
                                send,
                                recv,
                            } = connection;
                            let callback = on_packet.clone();
                            tokio::spawn(async move {
                                if let Err(e) = read_h3_packets(recv, route_key, callback).await {
                                    log::warn!(
                                        "control http3 read failed {:?}: {:?}",
                                        route_key.addr,
                                        e
                                    );
                                }
                            });
                            active = Some(ActiveConnection {
                                addr,
                                endpoint,
                                _request_sender: request_sender,
                                send,
                            });
                        }
                        Err(e) => {
                            log::warn!("control http3 connect failed {}: {:?}", addr, e);
                            continue;
                        }
                    }
                }
                let frame = Bytes::from(frame_quic_packet(&data));
                let send_result = if let Some(connection) = active.as_mut() {
                    connection.send.send_data(frame).await
                } else {
                    continue;
                };
                if let Err(e) = send_result {
                    log::warn!("control http3 send failed {}: {:?}", addr, e);
                    if let Some(connection) = active.take() {
                        connection.close();
                    }
                    let name = server_name.lock().clone();
                    match connect(addr, &name, &request_uri).await {
                        Ok(connection) => {
                            let Http3ClientConnection {
                                addr,
                                route_key,
                                endpoint,
                                request_sender,
                                mut send,
                                recv,
                            } = connection;
                            let callback = on_packet.clone();
                            tokio::spawn(async move {
                                if let Err(e) = read_h3_packets(recv, route_key, callback).await {
                                    log::warn!(
                                        "control http3 read failed {:?}: {:?}",
                                        route_key.addr,
                                        e
                                    );
                                }
                            });
                            if let Err(e) =
                                send.send_data(Bytes::from(frame_quic_packet(&data))).await
                            {
                                log::warn!("control http3 resend failed {}: {:?}", addr, e);
                                endpoint.close(0u32.into(), &[]);
                            } else {
                                active = Some(ActiveConnection {
                                    addr,
                                    endpoint,
                                    _request_sender: request_sender,
                                    send,
                                });
                            }
                        }
                        Err(e) => {
                            log::warn!("control http3 reconnect failed {}: {:?}", addr, e);
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

struct Http3ClientConnection {
    addr: SocketAddr,
    route_key: RouteKey,
    endpoint: quinn::Endpoint,
    request_sender: SendRequest<h3_quinn::OpenStreams, Bytes>,
    send: RequestStream<H3SendStream<Bytes>, Bytes>,
    recv: RequestStream<H3RecvStream, Bytes>,
}

async fn connect(
    addr: SocketAddr,
    server_name: &str,
    request_uri: &str,
) -> anyhow::Result<Http3ClientConnection> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        if let Err(e) = roots.add(cert) {
            log::warn!("skip system cert {:?}", e);
        }
    }
    if roots.is_empty() {
        anyhow::bail!("no valid system root certificates for http3");
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.enable_early_data = true;
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(client_crypto)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let bind_addr: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint.connect(addr, server_name)?;
    let conn = tokio::time::timeout(Duration::from_secs(5), connecting).await??;
    let route_key = RouteKey::new(ConnectProtocol::QUIC, addr);

    let quinn_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await?;
    tokio::spawn(async move {
        let err = future::poll_fn(|cx| driver.poll_close(cx)).await;
        if !err.is_h3_no_error() {
            log::debug!("control http3 driver closed: {:?}", err);
        }
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(request_uri)
        .header(http::header::CONTENT_TYPE, "application/octet-stream")
        .body(())?;
    let req_stream = send_request.send_request(request).await?;
    let (send, mut recv) = req_stream.split();
    let response = recv.recv_response().await?;
    if !response.status().is_success() {
        anyhow::bail!("control http3 response status {}", response.status());
    }

    Ok(Http3ClientConnection {
        addr,
        route_key,
        endpoint,
        request_sender: send_request,
        send,
        recv,
    })
}

async fn read_h3_packets(
    mut recv: RequestStream<H3RecvStream, Bytes>,
    route_key: RouteKey,
    on_packet: PacketCallback,
) -> anyhow::Result<()> {
    let mut pending = Vec::new();
    loop {
        let Some(mut chunk) = recv.recv_data().await? else {
            return Ok(());
        };
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        pending.extend_from_slice(bytes.as_ref());
        consume_pending_frames(&mut pending, &mut |packet| on_packet(packet, route_key))?;
    }
}
