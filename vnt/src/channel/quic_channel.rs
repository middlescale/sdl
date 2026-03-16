use anyhow::Context;
use std::net::SocketAddr;
use std::thread;
use tokio::sync::mpsc::Receiver;

use crate::channel::context::ChannelContext;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::sender::PacketSender;
use crate::channel::{RouteKey, BUFFER_SIZE};
use crate::transport::quic_channel::{connect, frame_quic_packet, read_framed_packets_with};
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
            if let Err(e) = connect_quic(data, server_name, addr, recv_handler, context).await {
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
    let _ = server_name;
    let connection = connect(addr, b"vnt-control").await?;
    let crate::transport::quic_channel::QuicClientConnection {
        endpoint,
        route_key,
        mut send,
        mut recv,
        ..
    } = connection;
    send.write_all(&frame_quic_packet(&data)).await?;

    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    context
        .packet_map
        .write()
        .insert(route_key, PacketSender::new(sender));
    tokio::spawn(async move {
        while let Some(data) = receiver.recv().await {
            if let Err(e) = send.write_all(&frame_quic_packet(&data)).await {
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

async fn quic_read<H>(
    recv: &mut quinn::RecvStream,
    recv_handler: H,
    context: &ChannelContext,
    route_key: RouteKey,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let mut extend = [0; BUFFER_SIZE];
    read_framed_packets_with(recv, |mut packet| {
        recv_handler.handle(&mut packet, &mut extend, route_key, context);
    })
    .await
}
