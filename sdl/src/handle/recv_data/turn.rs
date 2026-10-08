use crate::core::SdlRuntime;
use crate::handle::recv_data::PacketHandler;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::{NetPacket, Protocol};
use crate::transport::TransportEndpoint;
use anyhow::Context;
use std::sync::Arc;

/// 处理客户端中转包
#[derive(Clone)]
pub struct TurnPacketHandler {
    runtime: Arc<SdlRuntime>,
}

impl TurnPacketHandler {
    pub(crate) fn new(runtime: Arc<SdlRuntime>) -> Self {
        Self { runtime }
    }
}

impl PacketHandler for TurnPacketHandler {
    fn handle(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        _extend: NetPacket<&mut [u8]>,
        endpoint: TransportEndpoint,
        _current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        // 增加了一跳
        let ttl = net_packet.tick_ttl();
        if ttl > 0 {
            if matches!(net_packet.protocol(), Protocol::Service | Protocol::Error) {
                // 不转发控制面服务包
                return Ok(());
            }
            let destination = net_packet.destination();
            if let Some(route) = self.runtime.routes().best_route(&destination) {
                if route.endpoint.addr == endpoint.addr {
                    //防止环路
                    log::warn!("来源和目标相同 {:?},{:?}", endpoint, net_packet.head());
                    return Ok(());
                }
                if route.metric <= ttl {
                    return self
                        .runtime
                        .data_plane
                        .send_p2p(&net_packet, route.endpoint)
                        .context("转发失败");
                }
            }
            //其他没有路由的不转发
        }
        log::info!("没有路由 {:?},{:?}", endpoint, net_packet.head());
        Ok(())
    }
}
