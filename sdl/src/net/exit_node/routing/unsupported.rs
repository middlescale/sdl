//! unsupported route operations.

pub fn setup_server_routing(_egress_interface: &str, _tun_name: &str) -> anyhow::Result<String> {
    anyhow::bail!("exit-node routing setup is currently supported only on Linux")
}

pub fn teardown_server_routing(_egress_interface: &str, _tun_name: &str) -> anyhow::Result<String> {
    anyhow::bail!("exit-node routing teardown is currently supported only on Linux")
}

pub fn setup_client_routing(_tun_name: &str, _excludes: &[String]) -> anyhow::Result<String> {
    anyhow::bail!("exit-node client routing setup is supported only on Linux, macOS, and Windows")
}

pub fn teardown_client_routing(_tun_name: &str, _excludes: &[String]) -> anyhow::Result<String> {
    anyhow::bail!(
        "exit-node client routing teardown is supported only on Linux, macOS, and Windows"
    )
}

pub fn refresh_client_routing_excludes(
    _tun_name: &str,
    _previous_excludes: &[String],
    _next_excludes: &[String],
) -> anyhow::Result<String> {
    anyhow::bail!(
        "exit-node client route exclude refresh is supported only on Linux, macOS, and Windows"
    )
}
