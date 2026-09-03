use super::*;
use std::thread;
use std::time::Duration;

#[derive(Copy, Clone)]
pub(super) struct ActivePunchSession {
    pub(super) session_id: u64,
    pub(super) source: u32,
    pub(super) target: u32,
    pub(super) attempt: u32,
    pub(super) deadline_unix_ms: i64,
}

pub(super) type PunchEndpointFingerprint = Vec<(u32, Vec<u8>, u32, bool)>;

#[derive(Clone)]
pub(super) struct ActivePunchState {
    active: ActivePunchSession,
    coalesced: Vec<ActivePunchSession>,
    endpoint_fingerprint: PunchEndpointFingerprint,
}

pub(super) struct PunchSessionStart {
    pub(super) coalesced: bool,
    pub(super) endpoints_changed: bool,
}

pub(super) struct PunchSessionOutcome {
    pub(super) sessions: Vec<ActivePunchSession>,
    pub(super) code: PunchResultCode,
    pub(super) reason: &'static str,
}

#[derive(Clone, Default)]
pub(super) struct PunchSessionTracker {
    sessions: Arc<Mutex<HashMap<Ipv4Addr, ActivePunchState>>>,
}

impl ActivePunchState {
    pub(super) fn new(
        active: ActivePunchSession,
        endpoint_fingerprint: PunchEndpointFingerprint,
    ) -> Self {
        Self {
            active,
            coalesced: Vec::new(),
            endpoint_fingerprint,
        }
    }

    pub(super) fn contains(&self, session_id: u64, attempt: u32) -> bool {
        self.active.session_id == session_id && self.active.attempt == attempt
            || self
                .coalesced
                .iter()
                .any(|session| session.session_id == session_id && session.attempt == attempt)
    }

    pub(super) fn coalesce(
        &mut self,
        session: ActivePunchSession,
        endpoint_fingerprint: &[(u32, Vec<u8>, u32, bool)],
    ) -> bool {
        let endpoints_changed = self.endpoint_fingerprint != endpoint_fingerprint;
        if self.contains(session.session_id, session.attempt) {
            self.active.deadline_unix_ms =
                self.active.deadline_unix_ms.max(session.deadline_unix_ms);
            return endpoints_changed;
        }
        self.active.deadline_unix_ms = self.active.deadline_unix_ms.max(session.deadline_unix_ms);
        self.coalesced.push(session);
        endpoints_changed
    }

    pub(super) fn update_endpoint_fingerprint(
        &mut self,
        endpoint_fingerprint: PunchEndpointFingerprint,
    ) {
        self.endpoint_fingerprint = endpoint_fingerprint;
    }

    pub(super) fn sessions(&self) -> Vec<ActivePunchSession> {
        let mut sessions = Vec::with_capacity(1 + self.coalesced.len());
        sessions.push(self.active);
        sessions.extend(self.coalesced.iter().copied());
        sessions
    }

    pub(super) fn deadline_unix_ms(&self) -> i64 {
        self.active.deadline_unix_ms
    }
}

impl PunchSessionTracker {
    pub(super) fn on_punch_start(
        &self,
        peer_ip: Ipv4Addr,
        session: ActivePunchSession,
        endpoint_fingerprint: PunchEndpointFingerprint,
    ) -> PunchSessionStart {
        let mut sessions = self.sessions.lock();
        match sessions.get_mut(&peer_ip) {
            Some(state) => PunchSessionStart {
                coalesced: true,
                endpoints_changed: state.coalesce(session, &endpoint_fingerprint),
            },
            None => {
                sessions.insert(
                    peer_ip,
                    ActivePunchState::new(session, endpoint_fingerprint),
                );
                PunchSessionStart {
                    coalesced: false,
                    endpoints_changed: false,
                }
            }
        }
    }

    pub(super) fn mark_endpoint_refresh_completed(
        &self,
        peer_ip: Ipv4Addr,
        endpoint_fingerprint: PunchEndpointFingerprint,
    ) {
        if let Some(state) = self.sessions.lock().get_mut(&peer_ip) {
            state.update_endpoint_fingerprint(endpoint_fingerprint);
        }
    }

    pub(super) fn remove(&self, peer_ip: Ipv4Addr) {
        self.sessions.lock().remove(&peer_ip);
    }

    pub(super) fn reconcile(
        &self,
        route_manager: &crate::data_plane::route_manager::RouteManager,
    ) -> Vec<PunchSessionOutcome> {
        let now_ms = crate::handle::now_time() as i64;
        let mut outcomes = Vec::new();
        self.sessions.lock().retain(|peer_ip, state| {
            let outcome = if route_manager.direct_path_count(peer_ip) > 0 {
                Some((PunchResultCode::PunchResultSuccess, "p2p route established"))
            } else if state.deadline_unix_ms() > 0 && now_ms > state.deadline_unix_ms() {
                Some((PunchResultCode::PunchResultNoResponse, "deadline exceeded"))
            } else {
                None
            };
            if let Some((code, reason)) = outcome {
                outcomes.push(PunchSessionOutcome {
                    sessions: state.sessions(),
                    code,
                    reason,
                });
                false
            } else {
                true
            }
        });
        outcomes
    }
}
impl<Call: SdlCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    pub(super) fn handle_punch_start(
        &self,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
    ) -> anyhow::Result<()> {
        let punch_start = PunchStart::parse_from_bytes(net_packet.payload())
            .map_err(|e| io::Error::other(format!("PunchStart {:?}", e)))?;
        let (peer_ip, peer_nat_info) = build_peer_nat_info_from_punch_start(&punch_start);
        let endpoint_fingerprint = punch_start_endpoint_fingerprint(&punch_start);
        log::info!(
            "PunchStart received peer={} session_id={} attempt={} endpoints={} public_ips={:?} public_ports={:?} local_ipv4={:?}",
            peer_ip,
            punch_start.session_id,
            punch_start.attempt,
            punch_start.peer_endpoints.len(),
            peer_nat_info.public_ips,
            peer_nat_info.public_ports,
            peer_nat_info.local_ipv4()
        );
        self.context.state.debug_watch.emit(
            "punch",
            "start_received",
            serde_json::json!({
                "peer_ip": peer_ip.to_string(),
                "session_id": punch_start.session_id,
                "attempt": punch_start.attempt,
                "attempt_budget": punch_start.attempt_budget,
                "trigger_reason": format!("{:?}", punch_start.trigger_reason.enum_value_or_default()),
                "selection_policy": format!("{:?}", punch_start.endpoint_selection_policy.enum_value_or_default()),
                "endpoint_count": punch_start.peer_endpoints.len(),
                "public_ips": peer_nat_info.public_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "public_ports": peer_nat_info.public_ports,
                "local_ipv4": peer_nat_info.local_ipv4().map(|ip| ip.to_string()),
            }),
        );
        let deadline_unix_ms = if punch_start.deadline_unix_ms > 0 {
            punch_start.deadline_unix_ms
        } else {
            let timeout_ms = if punch_start.timeout_ms == 0 {
                5000
            } else {
                punch_start.timeout_ms
            };
            crate::handle::now_time() as i64 + timeout_ms as i64
        };
        let session = ActivePunchSession {
            session_id: punch_start.session_id,
            source: u32::from(current_device.virtual_ip),
            target: punch_start.target,
            attempt: punch_start.attempt,
            deadline_unix_ms,
        };
        let local_forced_relay = self
            .context
            .services
            .route_manager
            .use_channel_type()
            .is_only_relay();
        let peer_forced_relay = self
            .context
            .state
            .peers
            .table
            .read()
            .get(&peer_ip)
            .map_or(false, |p| {
                p.preferred_channel_mode == crate::proto::message::ChannelMode::CHANNEL_MODE_RELAY
            });
        let (accepted, phase, reason, coalesced) = if local_forced_relay {
            (
                false,
                PunchSessionPhase::PunchPhaseFailed,
                "local node in forced relay mode",
                false,
            )
        } else if peer_forced_relay {
            (
                false,
                PunchSessionPhase::PunchPhaseFailed,
                "peer in forced relay mode",
                false,
            )
        } else {
            let start =
                self.punch_sessions
                    .on_punch_start(peer_ip, session, endpoint_fingerprint.clone());
            if start.coalesced && !start.endpoints_changed {
                (
                    true,
                    PunchSessionPhase::PunchPhaseWaiting,
                    "coalesced onto active punch session",
                    true,
                )
            } else {
                let accepted = self
                    .context
                    .services
                    .punch_coordinator
                    .submit_local(peer_ip, peer_nat_info);
                if accepted && start.coalesced {
                    self.punch_sessions
                        .mark_endpoint_refresh_completed(peer_ip, endpoint_fingerprint);
                }
                (
                    // A coalesced session with newer endpoint candidates needs a
                    // second probe. Keep the original watchdog so every coalesced
                    // control session still receives its eventual result.
                    accepted || start.coalesced,
                    if accepted {
                        PunchSessionPhase::PunchPhaseSending
                    } else if start.coalesced {
                        PunchSessionPhase::PunchPhaseWaiting
                    } else {
                        PunchSessionPhase::PunchPhaseFailed
                    },
                    if accepted {
                        if start.coalesced {
                            "coalesced session refreshed with newer peer endpoints"
                        } else {
                            ""
                        }
                    } else if start.coalesced {
                        "coalesced onto active punch session; endpoint refresh queue busy"
                    } else {
                        "punch queue busy"
                    },
                    start.coalesced,
                )
            }
        };
        log::info!(
            "PunchStart ack peer={} session_id={} attempt={} accepted={} phase={:?} coalesced={} reason={}",
            peer_ip,
            punch_start.session_id,
            punch_start.attempt,
            accepted,
            phase,
            coalesced,
            reason
        );
        let ack = build_punch_ack(
            punch_start.session_id,
            u32::from(current_device.virtual_ip),
            punch_start.attempt,
            accepted,
            phase,
            reason,
        );
        let bytes = ack
            .write_to_bytes()
            .map_err(|e| io::Error::other(format!("PunchAck {:?}", e)))?;
        self.send_service_packet(current_device, service_packet::Protocol::PunchAck, &bytes)?;
        if !accepted {
            self.punch_sessions.remove(peer_ip);
            self.send_punch_result(
                current_device,
                punch_start.session_id,
                u32::from(current_device.virtual_ip),
                punch_start.target,
                punch_start.attempt,
                PunchResultCode::PunchResultRejected,
                reason,
            )?;
        } else if !coalesced {
            self.punch_sessions
                .spawn_watchdog(self.context.clone(), peer_ip, session);
        }
        Ok(())
    }

    pub(super) fn reconcile_punch_sessions(
        &self,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        for outcome in self
            .punch_sessions
            .reconcile(&self.context.services.route_manager)
        {
            self.send_punch_results(
                current_device,
                &outcome.sessions,
                outcome.code,
                outcome.reason,
            )?;
        }
        Ok(())
    }

    pub(super) fn send_service_packet(
        &self,
        _current_device: &CurrentDeviceInfo,
        transport: service_packet::Protocol,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        self.context
            .services
            .control_session
            .send_service_payload(transport, payload)?;
        Ok(())
    }

    pub(super) fn send_punch_result(
        &self,
        current_device: &CurrentDeviceInfo,
        session_id: u64,
        source: u32,
        target: u32,
        attempt: u32,
        code: PunchResultCode,
        reason: &str,
    ) -> anyhow::Result<()> {
        let _ = current_device;
        let selected_endpoint = selected_endpoint_for_result(
            code,
            self.context
                .services
                .route_manager
                .direct_route(&Ipv4Addr::from(target)),
        );
        log::info!(
            "sending PunchResult session_id={} source={} target={} attempt={} code={:?} reason={} selected_endpoint={}",
            session_id,
            Ipv4Addr::from(source),
            Ipv4Addr::from(target),
            attempt,
            code,
            reason,
            format_punch_endpoint(selected_endpoint.as_ref())
        );
        send_punch_result_via_control(
            &self.context.services.control_session,
            session_id,
            source,
            target,
            attempt,
            code,
            reason,
            selected_endpoint,
        )
    }

    pub(super) fn send_punch_results(
        &self,
        current_device: &CurrentDeviceInfo,
        sessions: &[ActivePunchSession],
        code: PunchResultCode,
        reason: &str,
    ) -> anyhow::Result<()> {
        for session in sessions {
            self.send_punch_result(
                current_device,
                session.session_id,
                session.source,
                session.target,
                session.attempt,
                code,
                reason,
            )?;
        }
        Ok(())
    }
}

impl PunchSessionTracker {
    pub(super) fn spawn_watchdog(
        &self,
        context: Arc<SdlContext>,
        peer_ip: Ipv4Addr,
        session: ActivePunchSession,
    ) {
        let tracker = self.clone();
        thread::Builder::new()
            .name(format!("punchWatchdog-{peer_ip}"))
            .spawn(move || loop {
                let now_ms = crate::handle::now_time() as i64;
                let outcome = {
                    let mut guard = tracker.sessions.lock();
                    let Some(state) = guard.get(&peer_ip) else {
                        return;
                    };
                    if state.active.session_id != session.session_id
                        || state.active.attempt != session.attempt
                    {
                        return;
                    }
                    if context.services.route_manager.direct_path_count(&peer_ip) > 0 {
                        let state = guard.remove(&peer_ip).expect("active punch state");
                        Some((
                            state.sessions(),
                            PunchResultCode::PunchResultSuccess,
                            "p2p route established",
                        ))
                    } else if state.deadline_unix_ms() > 0 && now_ms > state.deadline_unix_ms() {
                        let state = guard.remove(&peer_ip).expect("active punch state");
                        Some((
                            state.sessions(),
                            PunchResultCode::PunchResultNoResponse,
                            "deadline exceeded",
                        ))
                    } else {
                        None
                    }
                };
                if let Some((sessions, code, reason)) = outcome {
                    log::info!(
                        "punch watchdog outcome peer={} session_id={} attempt={} coalesced_sessions={} code={:?} reason={}",
                        peer_ip,
                        session.session_id,
                        session.attempt,
                        sessions.len(),
                        code,
                        reason
                    );
                    context.state.debug_watch.emit(
                        "punch",
                        "watchdog_outcome",
                        serde_json::json!({
                            "peer_ip": peer_ip.to_string(),
                            "session_id": session.session_id,
                            "attempt": session.attempt,
                            "code": format!("{:?}", code),
                            "reason": reason,
                        }),
                    );
                    let selected_endpoint = selected_endpoint_for_result(
                        code,
                        context.services.route_manager.direct_route(&peer_ip),
                    );
                    for punch_session in sessions {
                        if let Err(err) = send_punch_result_via_control(
                            &context.services.control_session,
                            punch_session.session_id,
                            punch_session.source,
                            punch_session.target,
                            punch_session.attempt,
                            code,
                            reason,
                            selected_endpoint.clone(),
                        ) {
                            log::warn!(
                                "send punch result from watchdog failed peer={} session_id={} attempt={} err={:?}",
                                peer_ip,
                                punch_session.session_id,
                                punch_session.attempt,
                                err
                            );
                        }
                    }
                    return;
                }
                let sleep = if session.deadline_unix_ms > 0 {
                    let remaining = {
                        let guard = tracker.sessions.lock();
                        guard
                            .get(&peer_ip)
                            .map(|state| state.deadline_unix_ms())
                            .unwrap_or(session.deadline_unix_ms)
                    }
                    .saturating_sub(now_ms) as u64;
                    Duration::from_millis(remaining.clamp(1, 200))
                } else {
                    Duration::from_millis(200)
                };
                thread::sleep(sleep);
            })
            .expect("punch watchdog");
    }
}

pub(super) fn build_punch_ack(
    session_id: u64,
    source: u32,
    attempt: u32,
    accepted: bool,
    phase: PunchSessionPhase,
    reason: &str,
) -> PunchAck {
    let mut ack = PunchAck::new();
    ack.session_id = session_id;
    ack.source = source;
    ack.attempt = attempt;
    ack.accepted = accepted;
    ack.reason = reason.to_string();
    ack.phase = protobuf::EnumOrUnknown::new(phase);
    ack
}

pub(super) fn build_punch_result(
    session_id: u64,
    source: u32,
    target: u32,
    attempt: u32,
    code: PunchResultCode,
    reason: &str,
    selected_endpoint: Option<PunchEndpoint>,
) -> PunchResult {
    let mut result = PunchResult::new();
    result.session_id = session_id;
    result.source = source;
    result.target = target;
    result.attempt = attempt;
    result.code = protobuf::EnumOrUnknown::new(code);
    result.reason = reason.to_string();
    result.phase = protobuf::EnumOrUnknown::new(punch_phase_from_result_code(code));
    if let Some(endpoint) = selected_endpoint {
        result.selected_endpoint = protobuf::MessageField::some(endpoint);
    }
    result
}

pub(super) fn punch_phase_from_result_code(code: PunchResultCode) -> PunchSessionPhase {
    match code {
        PunchResultCode::PunchResultSuccess => PunchSessionPhase::PunchPhaseSuccess,
        PunchResultCode::PunchResultNoResponse | PunchResultCode::PunchResultTimeout => {
            PunchSessionPhase::PunchPhaseTimeout
        }
        PunchResultCode::PunchResultUnknown
        | PunchResultCode::PunchResultFailed
        | PunchResultCode::PunchResultCanceled
        | PunchResultCode::PunchResultRejected
        | PunchResultCode::PunchResultSuperseded => PunchSessionPhase::PunchPhaseFailed,
    }
}

pub(super) fn send_punch_result_via_control(
    control_session: &crate::control::ControlSession,
    session_id: u64,
    source: u32,
    target: u32,
    attempt: u32,
    code: PunchResultCode,
    reason: &str,
    selected_endpoint: Option<PunchEndpoint>,
) -> anyhow::Result<()> {
    let result = build_punch_result(
        session_id,
        source,
        target,
        attempt,
        code,
        reason,
        selected_endpoint,
    );
    let bytes = result
        .write_to_bytes()
        .map_err(|e| anyhow!("PunchResult {:?}", e))?;
    control_session.send_service_payload(service_packet::Protocol::PunchResult, &bytes)?;
    Ok(())
}

pub(super) fn selected_endpoint_for_result(
    code: PunchResultCode,
    route: Option<Route>,
) -> Option<PunchEndpoint> {
    if code != PunchResultCode::PunchResultSuccess {
        return None;
    }
    route.map(punch_endpoint_from_route)
}

pub(super) fn punch_endpoint_from_route(route: Route) -> PunchEndpoint {
    let mut endpoint = PunchEndpoint::new();
    match route.addr {
        SocketAddr::V4(addr) => {
            endpoint.ip = u32::from(*addr.ip());
            endpoint.port = u32::from(addr.port());
        }
        SocketAddr::V6(addr) => {
            endpoint.ipv6 = addr.ip().octets().to_vec();
            endpoint.port = u32::from(addr.port());
        }
    }
    endpoint.tcp = route.protocol.is_base_tcp() && !route.protocol.is_quic();
    endpoint
}

pub(super) fn format_punch_endpoint(endpoint: Option<&PunchEndpoint>) -> String {
    let Some(endpoint) = endpoint else {
        return "-".to_string();
    };
    let proto = if endpoint.tcp { "tcp" } else { "udp" };
    if endpoint.ip != 0 {
        return format!(
            "{}:{}/{}",
            Ipv4Addr::from(endpoint.ip),
            endpoint.port,
            proto
        );
    }
    if endpoint.ipv6.len() == 16 {
        let mut ipv6 = [0u8; 16];
        ipv6.copy_from_slice(&endpoint.ipv6);
        return format!("[{}]:{}/{}", Ipv6Addr::from(ipv6), endpoint.port, proto);
    }
    format!("-:{}/{}", endpoint.port, proto)
}

pub(super) fn build_peer_nat_info_from_punch_start(
    punch_start: &PunchStart,
) -> (Ipv4Addr, NatInfo) {
    let peer_ip = Ipv4Addr::from(punch_start.target);
    let mut public_ips = Vec::new();
    let mut public_ports = Vec::new();
    let mut local_udp_ports = Vec::new();
    let mut local_ipv4: Option<Ipv4Addr> = None;
    let mut ipv6: Option<Ipv6Addr> = None;
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;
    for ep in &punch_start.peer_endpoints {
        if ep.ip != 0 {
            has_ipv4 = true;
            let ip = Ipv4Addr::from(ep.ip);
            if crate::nat::is_ipv4_global(&ip) {
                public_ips.push(ip);
            } else if local_ipv4.is_none() {
                // Control-triggered PunchStart only carries endpoint ip:port pairs. In private
                // networks (e.g. Docker bridge CI), keep the first non-global IPv4 as the local
                // candidate so punch workers still have a reachable direct target to probe.
                local_ipv4 = Some(ip);
            }
            if !crate::nat::is_ipv4_global(&ip)
                && ep.port <= u16::MAX as u32
                && ep.port > 0
                && !local_udp_ports.contains(&(ep.port as u16))
            {
                local_udp_ports.push(ep.port as u16);
            }
        }
        if ep.port <= u16::MAX as u32 && ep.port > 0 {
            public_ports.push(ep.port as u16);
        }
        if ipv6.is_none() && ep.ipv6.len() == 16 {
            has_ipv6 = true;
            let mut v6 = [0u8; 16];
            v6.copy_from_slice(&ep.ipv6);
            ipv6 = Some(Ipv6Addr::from(v6));
        }
        if ep.ipv6.len() == 16
            && ep.port <= u16::MAX as u32
            && ep.port > 0
            && !local_udp_ports.contains(&(ep.port as u16))
        {
            local_udp_ports.push(ep.port as u16);
        }
    }
    let local_udp_ports = if local_udp_ports.is_empty() {
        public_ports.clone()
    } else {
        local_udp_ports
    };
    let punch_model = if has_ipv4 && has_ipv6 {
        PunchModel::All
    } else if has_ipv6 {
        PunchModel::IPv6Udp
    } else if has_ipv4 {
        PunchModel::IPv4Udp
    } else {
        PunchModel::All
    };
    (
        peer_ip,
        NatInfo::new(
            public_ips,
            public_ports.clone(),
            punch_start
                .peer_endpoints
                .iter()
                .filter_map(|ep| {
                    if ep.port == 0 {
                        return None;
                    }
                    if ep.ip != 0 {
                        return Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                            Ipv4Addr::from(ep.ip),
                            ep.port as u16,
                        )));
                    }
                    if ep.ipv6.len() == 16 {
                        let mut v6 = [0u8; 16];
                        v6.copy_from_slice(&ep.ipv6);
                        return Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                            Ipv6Addr::from(v6),
                            ep.port as u16,
                            0,
                            0,
                        )));
                    }
                    None
                })
                .collect(),
            0,
            local_ipv4,
            ipv6,
            local_udp_ports,
            NatType::Cone,
            punch_model,
        ),
    )
}

pub(super) fn punch_start_endpoint_fingerprint(
    punch_start: &PunchStart,
) -> PunchEndpointFingerprint {
    let mut endpoints = punch_start
        .peer_endpoints
        .iter()
        .map(|endpoint| {
            (
                endpoint.ip,
                endpoint.ipv6.clone(),
                endpoint.port,
                endpoint.tcp,
            )
        })
        .collect::<Vec<_>>();
    endpoints.sort_unstable();
    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_plane::route::Route;
    use crate::handle::recv_data::server::test_util::endpoint_fingerprint;
    use crate::transport::connect_protocol::ConnectProtocol;

    #[test]
    fn build_peer_nat_info_from_punch_start_uses_endpoints() {
        let mut start = PunchStart::new();
        start.target = u32::from(Ipv4Addr::new(10, 26, 0, 3));
        let mut ep1 = PunchEndpoint::new();
        ep1.ip = u32::from(Ipv4Addr::new(1, 1, 1, 1));
        ep1.port = 10001;
        let mut ep2 = PunchEndpoint::new();
        ep2.ip = u32::from(Ipv4Addr::new(2, 2, 2, 2));
        ep2.port = 10002;
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        ep2.ipv6 = ipv6.octets().to_vec();
        start.peer_endpoints.extend([ep1, ep2]);

        let (peer_ip, nat_info) = build_peer_nat_info_from_punch_start(&start);
        assert_eq!(peer_ip, Ipv4Addr::new(10, 26, 0, 3));
        assert_eq!(nat_info.public_ips.len(), 2);
        assert_eq!(nat_info.public_ports, vec![10001, 10002]);
        assert_eq!(nat_info.ipv6(), Some(ipv6));
        assert_eq!(nat_info.punch_model, PunchModel::All);
    }

    #[test]
    fn punch_start_endpoint_fingerprint_ignores_endpoint_order() {
        let mut first = PunchStart::new();
        let mut second = PunchStart::new();
        let mut ep1 = PunchEndpoint::new();
        ep1.ip = u32::from(Ipv4Addr::new(1, 1, 1, 1));
        ep1.port = 10001;
        let mut ep2 = PunchEndpoint::new();
        ep2.ip = u32::from(Ipv4Addr::new(2, 2, 2, 2));
        ep2.port = 10002;
        first.peer_endpoints.extend([ep1.clone(), ep2.clone()]);
        second.peer_endpoints.extend([ep2, ep1]);

        assert_eq!(
            punch_start_endpoint_fingerprint(&first),
            punch_start_endpoint_fingerprint(&second)
        );
    }

    #[test]
    fn build_peer_nat_info_from_punch_start_keeps_private_ipv4_as_local_candidate() {
        let mut start = PunchStart::new();
        start.target = u32::from(Ipv4Addr::new(10, 26, 0, 3));
        let mut ep = PunchEndpoint::new();
        ep.ip = u32::from(Ipv4Addr::new(172, 18, 0, 7));
        ep.port = 10001;
        start.peer_endpoints.push(ep);

        let (_, nat_info) = build_peer_nat_info_from_punch_start(&start);
        assert!(nat_info.public_ips.is_empty());
        assert_eq!(nat_info.local_ipv4(), Some(Ipv4Addr::new(172, 18, 0, 7)));
        assert_eq!(nat_info.public_ports, vec![10001]);
        assert_eq!(nat_info.local_udp_ports, vec![10001]);
    }

    #[test]
    fn build_peer_nat_info_from_punch_start_uses_local_ports_for_local_candidates() {
        let mut start = PunchStart::new();
        start.target = u32::from(Ipv4Addr::new(10, 26, 0, 5));
        let mut public_ep = PunchEndpoint::new();
        public_ep.ip = u32::from(Ipv4Addr::new(223, 74, 148, 126));
        public_ep.port = 1386;
        let mut local_ep = PunchEndpoint::new();
        local_ep.ip = u32::from(Ipv4Addr::new(192, 168, 31, 146));
        local_ep.port = 55979;
        let mut local_v6_ep = PunchEndpoint::new();
        let local_v6 = "2409:8a55:30d6:3fe4:adf7:c3f7:6177:590f"
            .parse::<Ipv6Addr>()
            .unwrap();
        local_v6_ep.ipv6 = local_v6.octets().to_vec();
        local_v6_ep.port = 55979;
        start
            .peer_endpoints
            .extend([public_ep, local_ep, local_v6_ep]);

        let (_, nat_info) = build_peer_nat_info_from_punch_start(&start);
        assert_eq!(
            nat_info.local_ipv4(),
            Some(Ipv4Addr::new(192, 168, 31, 146))
        );
        assert_eq!(nat_info.ipv6(), Some(local_v6));
        assert_eq!(
            nat_info.local_udp_ipv4addr(),
            Some(SocketAddr::V4(std::net::SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 31, 146),
                55979
            )))
        );
        assert_eq!(
            nat_info.local_udp_ipv6addr(),
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                local_v6, 55979, 0, 0
            )))
        );
        assert_eq!(nat_info.public_ports, vec![1386, 55979, 55979]);
        assert_eq!(nat_info.local_udp_ports, vec![55979]);
    }

    #[test]
    fn build_punch_ack_sets_reason() {
        let ack = build_punch_ack(11, 2, 4, false, PunchSessionPhase::PunchPhaseFailed, "busy");
        assert_eq!(ack.session_id, 11);
        assert_eq!(ack.source, 2);
        assert_eq!(ack.attempt, 4);
        assert!(!ack.accepted);
        assert_eq!(ack.reason, "busy");
        assert_eq!(
            ack.phase.enum_value_or_default(),
            PunchSessionPhase::PunchPhaseFailed
        );
    }

    fn session(session_id: u64, attempt: u32, deadline_unix_ms: i64) -> ActivePunchSession {
        ActivePunchSession {
            session_id,
            source: 2,
            target: 3,
            attempt,
            deadline_unix_ms,
        }
    }

    #[test]
    fn active_punch_state_coalesces_deadline_and_sessions() {
        let mut state = ActivePunchState::new(
            session(11, 1, 100),
            endpoint_fingerprint(Ipv4Addr::new(1, 1, 1, 1), 10001),
        );
        assert!(!state.coalesce(
            session(12, 2, 250),
            &endpoint_fingerprint(Ipv4Addr::new(1, 1, 1, 1), 10001),
        ));
        assert_eq!(state.deadline_unix_ms(), 250);
        assert_eq!(state.sessions().len(), 2);
    }

    #[test]
    fn active_punch_state_ignores_duplicate_session() {
        let active = session(11, 1, 100);
        let mut state = ActivePunchState::new(
            active,
            endpoint_fingerprint(Ipv4Addr::new(1, 1, 1, 1), 10001),
        );
        assert!(!state.coalesce(
            ActivePunchSession {
                deadline_unix_ms: 200,
                ..active
            },
            &endpoint_fingerprint(Ipv4Addr::new(1, 1, 1, 1), 10001),
        ));
        assert_eq!(state.sessions().len(), 1);
        assert_eq!(state.deadline_unix_ms(), 200);
    }

    #[test]
    fn active_punch_state_refreshes_when_peer_endpoints_change() {
        let mut state = ActivePunchState::new(
            session(11, 1, 100),
            endpoint_fingerprint(Ipv4Addr::new(1, 1, 1, 1), 10001),
        );
        let refreshed = endpoint_fingerprint(Ipv4Addr::new(2, 2, 2, 2), 10002);
        assert!(state.coalesce(session(12, 2, 200), &refreshed));
        state.update_endpoint_fingerprint(refreshed.clone());
        assert!(!state.coalesce(session(13, 3, 300), &refreshed));
    }

    #[test]
    fn punch_session_tracker_reports_coalesced_endpoint_refresh() {
        let tracker = PunchSessionTracker::default();
        let peer_ip = Ipv4Addr::new(10, 26, 0, 4);
        let first = tracker.on_punch_start(
            peer_ip,
            session(11, 1, 100),
            endpoint_fingerprint(Ipv4Addr::new(1, 1, 1, 1), 10001),
        );
        assert!(!first.coalesced);
        assert!(!first.endpoints_changed);
        let refreshed = tracker.on_punch_start(
            peer_ip,
            session(12, 2, 200),
            endpoint_fingerprint(Ipv4Addr::new(2, 2, 2, 2), 10002),
        );
        assert!(refreshed.coalesced);
        assert!(refreshed.endpoints_changed);
    }

    #[test]
    fn build_punch_result_sets_code_and_reason() {
        let result = build_punch_result(
            12,
            3,
            4,
            5,
            PunchResultCode::PunchResultNoResponse,
            "timeout",
            None,
        );
        assert_eq!(result.session_id, 12);
        assert_eq!(result.source, 3);
        assert_eq!(result.target, 4);
        assert_eq!(result.attempt, 5);
        assert_eq!(
            result.code.enum_value_or_default(),
            PunchResultCode::PunchResultNoResponse
        );
        assert_eq!(result.reason, "timeout");
        assert_eq!(
            result.phase.enum_value_or_default(),
            PunchSessionPhase::PunchPhaseTimeout
        );
    }

    #[test]
    fn selected_endpoint_for_success_uses_direct_route() {
        let endpoint = selected_endpoint_for_result(
            PunchResultCode::PunchResultSuccess,
            Some(Route::new(
                ConnectProtocol::UDP,
                "1.2.3.4:51820".parse::<SocketAddr>().unwrap(),
                1,
                1,
            )),
        )
        .expect("selected endpoint");
        assert_eq!(endpoint.ip, u32::from(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(endpoint.port, 51820);
        assert!(!endpoint.tcp);
    }

    #[test]
    fn punch_endpoint_from_tcp_route_marks_tcp() {
        let endpoint = punch_endpoint_from_route(Route::new(
            ConnectProtocol::TCP,
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
            1,
            1,
        ));
        assert!(endpoint.tcp);
        assert_eq!(endpoint.ipv6.len(), 16);
    }

    #[test]
    fn format_punch_endpoint_formats_ipv4() {
        let mut endpoint = PunchEndpoint::new();
        endpoint.ip = u32::from(Ipv4Addr::new(1, 2, 3, 4));
        endpoint.port = 51820;
        assert_eq!(format_punch_endpoint(Some(&endpoint)), "1.2.3.4:51820/udp");
    }
}
