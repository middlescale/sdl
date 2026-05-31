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
use tokio::sync::mpsc::{channel, unbounded_channel, Receiver, Sender, UnboundedSender};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use crate::data_plane::route::RouteKey;
use crate::protocol::NetPacket;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::transport::control_addr::parse_control_address;
use crate::transport::quic_channel::{consume_pending_frames, frame_packet, PacketCallback};
use crate::util::StopManager;

type TransportErrorCallback = Arc<dyn Fn(String) + Send + Sync>;

enum Http3Command {
    Send(Vec<u8>),
}

enum Http3ReadEvent {
    Closed { connection_id: u64, reason: String },
}

struct ActiveConnection {
    connection_id: u64,
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

    pub fn start<F, E>(
        &self,
        stop_manager: StopManager,
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
                    run_http3_worker(
                        receiver,
                        server_addr,
                        server_name,
                        request_uri,
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
    on_transport_error: TransportErrorCallback,
) {
    let (read_event_sender, mut read_event_receiver) = unbounded_channel();
    let mut active: Option<ActiveConnection> = None;
    let mut next_connection_id = 1u64;
    loop {
        tokio::select! {
            maybe_event = read_event_receiver.recv() => {
                let Some(event) = maybe_event else {
                    continue;
                };
                handle_read_event(&mut active, event, &on_transport_error);
            }
            maybe_command = receiver.recv() => {
                let Some(command) = maybe_command else {
                    break;
                };
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
                                    active = Some(register_active_connection(
                                        connection,
                                        &mut next_connection_id,
                                        on_packet.clone(),
                                        read_event_sender.clone(),
                                    ));
                                }
                                Err(e) => {
                                    log::warn!("control http3 connect failed {}: {:?}", addr, e);
                                    on_transport_error(format!(
                                        "control http3 connect failed {}: {:?}",
                                        addr, e
                                    ));
                                    continue;
                                }
                            }
                        }
                        let frame = Bytes::from(frame_packet(&data));
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
                                    let connection_id = next_connection_id;
                                    next_connection_id = next_connection_id.wrapping_add(1);
                                    let Http3ClientConnection {
                                        addr,
                                        route_key,
                                        endpoint,
                                        request_sender,
                                        mut send,
                                        recv,
                                    } = connection;
                                    spawn_h3_reader(
                                        connection_id,
                                        recv,
                                        route_key,
                                        on_packet.clone(),
                                        read_event_sender.clone(),
                                    );
                                    if let Err(e) =
                                        send.send_data(Bytes::from(frame_packet(&data))).await
                                    {
                                        log::warn!("control http3 resend failed {}: {:?}", addr, e);
                                        on_transport_error(format!(
                                            "control http3 resend failed {}: {:?}",
                                            addr, e
                                        ));
                                        endpoint.close(0u32.into(), &[]);
                                    } else {
                                        active = Some(ActiveConnection {
                                            connection_id,
                                            addr,
                                            endpoint,
                                            _request_sender: request_sender,
                                            send,
                                        });
                                    }
                                }
                                Err(e) => {
                                    log::warn!("control http3 reconnect failed {}: {:?}", addr, e);
                                    on_transport_error(format!(
                                        "control http3 reconnect failed {}: {:?}",
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
        connection.close();
    }
}

fn register_active_connection(
    connection: Http3ClientConnection,
    next_connection_id: &mut u64,
    on_packet: PacketCallback,
    read_event_sender: UnboundedSender<Http3ReadEvent>,
) -> ActiveConnection {
    let connection_id = *next_connection_id;
    *next_connection_id = next_connection_id.wrapping_add(1);
    let Http3ClientConnection {
        addr,
        route_key,
        endpoint,
        request_sender,
        send,
        recv,
    } = connection;
    spawn_h3_reader(connection_id, recv, route_key, on_packet, read_event_sender);
    ActiveConnection {
        connection_id,
        addr,
        endpoint,
        _request_sender: request_sender,
        send,
    }
}

fn spawn_h3_reader(
    connection_id: u64,
    recv: RequestStream<H3RecvStream, Bytes>,
    route_key: RouteKey,
    on_packet: PacketCallback,
    read_event_sender: UnboundedSender<Http3ReadEvent>,
) {
    tokio::spawn(async move {
        let reason = match read_h3_packets(recv, route_key, on_packet).await {
            Ok(()) => format!(
                "control http3 read loop ended unexpectedly {}",
                route_key.addr
            ),
            Err(e) => format!("control http3 read failed {}: {:?}", route_key.addr, e),
        };
        let _ = read_event_sender.send(Http3ReadEvent::Closed {
            connection_id,
            reason,
        });
    });
}

fn handle_read_event(
    active: &mut Option<ActiveConnection>,
    event: Http3ReadEvent,
    on_transport_error: &TransportErrorCallback,
) {
    match event {
        Http3ReadEvent::Closed {
            connection_id,
            reason,
        } => {
            if active.as_ref().map(|conn| conn.connection_id) != Some(connection_id) {
                return;
            }
            if let Some(connection) = active.take() {
                connection.close();
            }
            on_transport_error(reason);
        }
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
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    client_config.transport_config(std::sync::Arc::new(transport));

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
