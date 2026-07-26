use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::RwLock;

pub struct ExitRouteFlow {
    pub destination: Ipv4Addr,
}

/// A DNS request intercepted by SDL's virtual DNS service. DNS routing is a
/// separate decision from IP routing because the domain is only available
/// before resolution.
pub struct DnsRouteFlow<'a> {
    pub domain: &'a str,
    pub query_type: u16,
}

/// DNS answers observed on the client after they have passed through either
/// the control DNS proxy or an exit node resolver.
pub struct DnsRouteObservation<'a> {
    pub domain: &'a str,
    pub ipv4_addresses: &'a [Ipv4Addr],
    pub ttl_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitRouteDecision {
    Local,
    /// Existing exit-node selection, addressed by the currently assigned VIP.
    ExitNodeVip(Ipv4Addr),
    /// Stable private-policy target. SDL resolves it against the live peer
    /// table before forwarding, so a changed VIP does not invalidate policy.
    ExitNodeDeviceId(String),
}

pub trait ExitRoutePolicy: Send + Sync {
    fn decide(&self, flow: &ExitRouteFlow) -> ExitRouteDecision;

    /// `None` leaves DNS handling to SDL's ordinary exit-node selection.
    /// `Some(Local)` sends the query to SDL's local resolver path.
    fn decide_dns(&self, _flow: &DnsRouteFlow<'_>) -> Option<ExitRouteDecision> {
        None
    }

    /// DNS observations are optional. Default routing has no DNS cache.
    fn observe_dns(&self, _observation: &DnsRouteObservation<'_>) {}
}

#[derive(Default)]
struct DefaultExitRoutePolicy {
    default_next_hop: RwLock<Option<Ipv4Addr>>,
}

impl DefaultExitRoutePolicy {
    fn set_default_next_hop(&self, next_hop: Option<Ipv4Addr>) {
        *self.default_next_hop.write() = next_hop;
    }
}

impl ExitRoutePolicy for DefaultExitRoutePolicy {
    fn decide(&self, flow: &ExitRouteFlow) -> ExitRouteDecision {
        let _destination = flow.destination;
        match *self.default_next_hop.read() {
            Some(next_hop) => ExitRouteDecision::ExitNodeVip(next_hop),
            None => ExitRouteDecision::Local,
        }
    }
}

#[derive(Clone)]
pub struct ExitNodeRoute {
    policy: Arc<RwLock<Arc<dyn ExitRoutePolicy>>>,
    default_policy: Arc<DefaultExitRoutePolicy>,
}

impl ExitNodeRoute {
    pub fn new() -> Self {
        let default_policy = Arc::new(DefaultExitRoutePolicy::default());
        Self {
            policy: Arc::new(RwLock::new(default_policy.clone())),
            default_policy,
        }
    }

    pub fn decision_for_external_destination(&self, destination: &Ipv4Addr) -> ExitRouteDecision {
        let flow = ExitRouteFlow {
            destination: *destination,
        };
        self.policy.read().decide(&flow)
    }

    pub fn decision_for_dns_query(
        &self,
        domain: &str,
        query_type: u16,
    ) -> Option<ExitRouteDecision> {
        self.policy
            .read()
            .decide_dns(&DnsRouteFlow { domain, query_type })
    }

    pub fn observe_dns_response(&self, domain: &str, ipv4_addresses: &[Ipv4Addr], ttl_secs: u32) {
        self.policy.read().observe_dns(&DnsRouteObservation {
            domain,
            ipv4_addresses,
            ttl_secs,
        });
    }

    pub fn next_hop_for_external_destination(&self, destination: &Ipv4Addr) -> Option<Ipv4Addr> {
        match self.decision_for_external_destination(destination) {
            ExitRouteDecision::ExitNodeVip(next_hop) => Some(next_hop),
            ExitRouteDecision::Local | ExitRouteDecision::ExitNodeDeviceId(_) => None,
        }
    }

    pub fn set_default_next_hop(&self, next_hop: Option<Ipv4Addr>) {
        self.default_policy.set_default_next_hop(next_hop);
    }

    pub fn set_policy(&self, policy: Arc<dyn ExitRoutePolicy>) {
        *self.policy.write() = policy;
    }

    pub fn reset_policy_to_default(&self) {
        *self.policy.write() = self.default_policy.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::{ExitNodeRoute, ExitRouteDecision, ExitRouteFlow, ExitRoutePolicy};
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    struct GoogleToJapanPolicy;

    impl ExitRoutePolicy for GoogleToJapanPolicy {
        fn decide(&self, flow: &ExitRouteFlow) -> ExitRouteDecision {
            if flow.destination == Ipv4Addr::new(8, 8, 8, 8) {
                return ExitRouteDecision::ExitNodeVip(Ipv4Addr::new(10, 26, 0, 43));
            }
            ExitRouteDecision::Local
        }
    }

    #[test]
    fn default_next_hop_handles_external_destinations() {
        let route = ExitNodeRoute::new();
        assert_eq!(
            route.next_hop_for_external_destination(&Ipv4Addr::new(8, 8, 8, 8)),
            None
        );

        route.set_default_next_hop(Some(Ipv4Addr::new(10, 26, 0, 42)));
        assert_eq!(
            route.next_hop_for_external_destination(&Ipv4Addr::new(8, 8, 8, 8)),
            Some(Ipv4Addr::new(10, 26, 0, 42))
        );

        route.set_default_next_hop(None);
        assert_eq!(
            route.next_hop_for_external_destination(&Ipv4Addr::new(8, 8, 8, 8)),
            None
        );
    }

    #[test]
    fn custom_policy_can_override_default_exit_node_decision() {
        let route = ExitNodeRoute::new();
        route.set_default_next_hop(Some(Ipv4Addr::new(10, 26, 0, 42)));

        route.set_policy(Arc::new(GoogleToJapanPolicy));
        assert_eq!(
            route.next_hop_for_external_destination(&Ipv4Addr::new(8, 8, 8, 8)),
            Some(Ipv4Addr::new(10, 26, 0, 43))
        );
        assert_eq!(
            route.next_hop_for_external_destination(&Ipv4Addr::new(1, 1, 1, 1)),
            None
        );

        route.reset_policy_to_default();
        assert_eq!(
            route.next_hop_for_external_destination(&Ipv4Addr::new(1, 1, 1, 1)),
            Some(Ipv4Addr::new(10, 26, 0, 42))
        );
    }
}
