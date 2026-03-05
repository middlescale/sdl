use anyhow::Context;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;

use crate::channel::context::ChannelContext;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::sender::PacketSender;
use crate::channel::{ConnectProtocol, RouteKey, BUFFER_SIZE};
use crate::util::StopManager;

pub fn quic_connect_accept<H>(
    receiver: Receiver<(Vec<u8>, String, SocketAddr)>,
    recv_handler: H,
    context: ChannelContext,
    stop_manager: StopManager,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let worker = stop_manager.add_listener("quicChannel".into(), move || {
        let _ = stop_sender.send(());
    })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("quic tokio runtime build failed")?;
    thread::Builder::new()
        .name("quicChannel".into())
        .spawn(move || {
            runtime
                .spawn(async move { connect_quic_handle(receiver, recv_handler, context).await });
            runtime.block_on(async {
                let _ = stop_receiver.await;
            });
            runtime.shutdown_background();
            worker.stop_all();
        })
        .context("quic thread build failed")?;
    Ok(())
}

async fn connect_quic_handle<H>(
    mut receiver: Receiver<(Vec<u8>, String, SocketAddr)>,
    recv_handler: H,
    context: ChannelContext,
) where
    H: RecvChannelHandler,
{
    while let Some((data, server_name, addr)) = receiver.recv().await {
        let recv_handler = recv_handler.clone();
        let context = context.clone();
        tokio::spawn(async move {
            if let Err(e) =
                connect_quic(data, server_name, addr, recv_handler, context).await
            {
                log::warn!("quic链接终止:{:?}", e);
            }
        });
    }
}

async fn connect_quic<H>(
    data: Vec<u8>,
    server_name: String,
    addr: SocketAddr,
    recv_handler: H,
    context: ChannelContext,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let mut roots = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for cert in certs.certs {
        if let Err(e) = roots.add(cert) {
            log::warn!("跳过系统证书 {:?}", e);
        }
    }
    if roots.is_empty() {
        return Err(anyhow::anyhow!(
            "no valid system root certificates for quic"
        ));
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"vnt-control".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(client_crypto)?;
    let client_config = ClientConfig::new(Arc::new(quic_crypto));

    let bind_addr: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let server_name = parse_server_name(&server_name, addr);
    let connecting = endpoint.connect(addr, &server_name)?;
    let conn = tokio::time::timeout(Duration::from_secs(5), connecting).await??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&data).await?;

    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let route_key = RouteKey::new(ConnectProtocol::QUIC, 0, addr);
    context
        .packet_map
        .write()
        .insert(route_key, PacketSender::new(sender));
    tokio::spawn(async move {
        while let Some(data) = receiver.recv().await {
            if let Err(e) = send.write_all(&data).await {
                log::warn!("quic发送失败 {:?}", e);
                break;
            }
        }
        let _ = send.finish();
    });
    if let Err(e) = quic_read(&mut recv, recv_handler, &context, route_key).await {
        log::warn!("quic读取失败 {:?}", e);
    }
    context.packet_map.write().remove(&route_key);
    endpoint.close(0u32.into(), &[]);
    Ok(())
}

fn parse_server_name(server_name: &str, addr: SocketAddr) -> String {
    let mut val = server_name.to_lowercase();
    if let Some(v) = val.strip_prefix("quic://") {
        val = v.to_string();
    }
    if let Some(v) = val.strip_prefix("udp://") {
        val = v.to_string();
    }
    if let Some(v) = val.strip_prefix("tcp://") {
        val = v.to_string();
    }
    let host = if let Some(v) = val.strip_prefix('[') {
        v.split(']').next().unwrap_or_default().to_string()
    } else {
        val.split(':').next().unwrap_or_default().to_string()
    };
    if host.is_empty() {
        addr.ip().to_string()
    } else {
        host
    }
}

async fn quic_read<H>(
    recv: &mut quinn::RecvStream,
    recv_handler: H,
    context: &ChannelContext,
    route_key: RouteKey,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let mut buf = [0; BUFFER_SIZE];
    let mut extend = [0; BUFFER_SIZE];
    loop {
        let len = recv.read(&mut buf).await?;
        let Some(len) = len else {
            return Ok(());
        };
        if len < 12 {
            continue;
        }
        recv_handler.handle(&mut buf[..len], &mut extend, route_key, context);
    }
}
