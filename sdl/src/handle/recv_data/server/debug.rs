use super::*;
impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    pub(super) fn handle_debug_collect_request(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let request = DebugCollectRequest::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("DebugCollectRequest {:?}", e)))?;
        log::info!(
            "received debug collect request request_id={} sections={:?} reason={}",
            request.request_id,
            request.sections,
            request.reason
        );
        let mut response = DebugCollectResponse::new();
        response.request_id = request.request_id;
        response.collected_at_unix_ms = crate::handle::now_time() as i64;
        match self.context.debug_snapshot_json(&request.sections) {
            Ok(snapshot_json) => {
                response.ok = true;
                response.snapshot_json = snapshot_json;
            }
            Err(err) => {
                log::warn!(
                    "debug collect failed request_id={} err={:?}",
                    request.request_id,
                    err
                );
                response.ok = false;
                response.reason = err.to_string();
            }
        }
        let bytes = response
            .write_to_bytes()
            .map_err(|e| io::Error::other(format!("DebugCollectResponse {:?}", e)))?;
        self.send_service_packet(
            current_device,
            service_packet::Protocol::DebugCollectResponse,
            &bytes,
        )?;
        Ok(())
    }

    pub(super) fn handle_debug_watch_start_request(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let request = DebugWatchStartRequest::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("DebugWatchStartRequest {:?}", e)))?;
        let (started_at_unix_ms, expire_at_unix_ms) = self.context.state.debug_watch.start(
            request.request_id,
            &request.sections,
            request.duration_sec.max(1),
        );
        let mut response = DebugWatchStartResponse::new();
        response.request_id = request.request_id;
        response.ok = true;
        response.watch_id = request.request_id;
        response.started_at_unix_ms = started_at_unix_ms;
        response.expire_at_unix_ms = expire_at_unix_ms;
        let bytes = response
            .write_to_bytes()
            .map_err(|e| io::Error::other(format!("DebugWatchStartResponse {:?}", e)))?;
        self.send_service_packet(
            current_device,
            service_packet::Protocol::DebugWatchStartResponse,
            &bytes,
        )?;
        self.context.state.debug_watch.emit(
            "runtime",
            "watch_started",
            serde_json::json!({
                "watch_id": request.request_id,
                "sections": request.sections,
                "duration_sec": request.duration_sec,
                "reason": request.reason,
            }),
        );
        Ok(())
    }

    pub(super) fn handle_debug_watch_stop_request(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let request = DebugWatchStopRequest::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("DebugWatchStopRequest {:?}", e)))?;
        let stopped_watch_id = self.context.state.debug_watch.stop(Some(request.watch_id));
        let mut response = DebugWatchStopResponse::new();
        response.request_id = request.request_id;
        response.watch_id = stopped_watch_id.unwrap_or(request.watch_id);
        response.stopped_at_unix_ms = crate::handle::now_time() as i64;
        if stopped_watch_id.is_some() {
            response.ok = true;
        } else {
            response.ok = false;
            response.reason = "no matching active debug watch".to_string();
        }
        let bytes = response
            .write_to_bytes()
            .map_err(|e| io::Error::other(format!("DebugWatchStopResponse {:?}", e)))?;
        self.send_service_packet(
            current_device,
            service_packet::Protocol::DebugWatchStopResponse,
            &bytes,
        )?;
        Ok(())
    }
}
