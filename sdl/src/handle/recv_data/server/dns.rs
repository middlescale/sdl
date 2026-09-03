use super::*;
impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    pub(super) fn handle_dns_query_response(
        &self,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let response = DnsQueryResponse::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("DnsQueryResponse {:?}", e)))?;
        let Some(pending) = self.context.state.dns.take_query(response.request_id) else {
            log::debug!(
                "drop dns response for unknown request_id={}",
                response.request_id
            );
            return Ok(());
        };
        if !response.error.is_empty() {
            log::warn!(
                "control dns proxy failed request_id={} err={}",
                response.request_id,
                response.error
            );
            return Ok(());
        }
        if response.response.is_empty() {
            log::warn!(
                "control dns proxy returned empty response request_id={}",
                response.request_id
            );
            return Ok(());
        }
        let packet =
            crate::net::dns::tunnel::build_dns_response_packet(&pending, &response.response)?;
        write_full_device(&self.device, &packet, "dns response inject")?;
        Ok(())
    }
}
