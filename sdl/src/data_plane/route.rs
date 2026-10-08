use crate::transport::TransportEndpoint;

#[derive(Copy, Clone, Debug)]
pub struct Route {
    pub endpoint: TransportEndpoint,
    pub metric: u8,
    pub rt: i64,
    pub loss_rate: Option<f32>,
}

pub(crate) const DEFAULT_RT: i64 = 9999;

impl Route {
    pub fn new(endpoint: TransportEndpoint, metric: u8, rt: i64) -> Self {
        Self {
            endpoint,
            metric,
            rt,
            loss_rate: None,
        }
    }

    pub fn with_default_rt(endpoint: TransportEndpoint, metric: u8) -> Self {
        Self::new(endpoint, metric, DEFAULT_RT)
    }

    pub fn with_loss_rate(mut self, loss_rate: Option<f32>) -> Self {
        self.loss_rate = loss_rate;
        self
    }

    pub fn is_p2p(&self) -> bool {
        self.metric == 1
    }

    pub fn has_measured_rt(&self) -> bool {
        self.rt >= 0 && self.rt != DEFAULT_RT
    }

    pub fn is_udp(&self) -> bool {
        self.endpoint.protocol.is_udp()
    }

    /// Returns a short name for the transport protocol (e.g. "Udp", "Tcp", "Quic").
    pub fn protocol_name(&self) -> String {
        format!("{:?}", self.endpoint.protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ConnectProtocol;

    #[test]
    fn route_constructor_preserves_endpoint_and_measurements() {
        let endpoint = TransportEndpoint::new(ConnectProtocol::UDP, ([127, 0, 0, 1], 29873).into());
        let route = Route::new(endpoint, 1, 42);

        assert_eq!(route.endpoint, endpoint);
        assert_eq!(route.metric, 1);
        assert_eq!(route.rt, 42);
        assert!(route.is_p2p());
        assert!(route.is_udp());
        assert!(route.has_measured_rt());
        assert_eq!(route.loss_rate, None);
        assert_eq!(route.with_loss_rate(Some(0.2)).loss_rate, Some(0.2));
    }

    #[test]
    fn default_rtt_does_not_mark_endpoint_as_measured() {
        let endpoint = TransportEndpoint::new(ConnectProtocol::QUIC, ([127, 0, 0, 1], 443).into());
        let route = Route::with_default_rt(endpoint, 2);

        assert_eq!(route.endpoint, endpoint);
        assert_eq!(route.rt, DEFAULT_RT);
        assert!(!route.has_measured_rt());
        assert!(!route.is_p2p());
        assert!(!route.is_udp());
        assert_eq!(route.protocol_name(), "QUIC");
    }
}
