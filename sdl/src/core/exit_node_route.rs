use std::net::Ipv4Addr;

use parking_lot::RwLock;

#[derive(Clone)]
pub struct ExitNodeRoute {
    default_next_hop: std::sync::Arc<RwLock<Option<Ipv4Addr>>>,
}

impl ExitNodeRoute {
    pub fn new() -> Self {
        Self {
            default_next_hop: std::sync::Arc::new(RwLock::new(None)),
        }
    }

    pub fn next_hop_for_external_destination(&self, _destination: &Ipv4Addr) -> Option<Ipv4Addr> {
        *self.default_next_hop.read()
    }

    pub fn set_default_next_hop(&self, next_hop: Option<Ipv4Addr>) {
        *self.default_next_hop.write() = next_hop;
    }
}

#[cfg(test)]
mod tests {
    use super::ExitNodeRoute;
    use std::net::Ipv4Addr;

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
}
