use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::RwLock;

pub(crate) struct ExitRouteFlow {
    pub destination: Ipv4Addr,
}

pub(crate) enum ExitRouteDecision {
    Local,
    ExitNode(Ipv4Addr),
}

pub(crate) trait ExitRoutePolicy: Send + Sync {
    fn decide(&self, flow: &ExitRouteFlow) -> ExitRouteDecision;
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
            Some(next_hop) => ExitRouteDecision::ExitNode(next_hop),
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

    pub fn next_hop_for_external_destination(&self, destination: &Ipv4Addr) -> Option<Ipv4Addr> {
        let flow = ExitRouteFlow {
            destination: *destination,
        };
        match self.policy.read().decide(&flow) {
            ExitRouteDecision::ExitNode(next_hop) => Some(next_hop),
            ExitRouteDecision::Local => None,
        }
    }

    pub fn set_default_next_hop(&self, next_hop: Option<Ipv4Addr>) {
        self.default_policy.set_default_next_hop(next_hop);
    }

    pub(crate) fn set_policy(&self, policy: Arc<dyn ExitRoutePolicy>) {
        *self.policy.write() = policy;
    }

    pub(crate) fn reset_policy_to_default(&self) {
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
                return ExitRouteDecision::ExitNode(Ipv4Addr::new(10, 26, 0, 43));
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
