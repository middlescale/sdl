use crate::command::entity::{
    DeviceItem, ExitNodeItem, ExitNodeStatus, GatewayItem, Info, RouteItem, TrafficPolicyStatus,
    TrafficSummary,
};
use crate::command::ipc;
use interprocess::local_socket::traits::ListenerExt;
use sdl::data_plane::use_channel_type::UseChannelType;
use serde::Deserialize;
use std::io;
use std::io::{Read, Write};
use std::str::FromStr;

#[derive(Deserialize)]
pub struct AuthCommand {
    pub user_id: String,
    pub group: String,
    pub ticket: String,
}

#[derive(Deserialize)]
pub struct SwitchCommand {
    pub user_id: String,
}

#[derive(Deserialize)]
pub struct ExitNodeEnableCommand {
    pub egress_interface: String,
    pub tun_name: Option<String>,
}

#[derive(Deserialize)]
pub struct ExitNodeDisableCommand {
    #[serde(default)]
    pub tun_name: Option<String>,
}

#[derive(Deserialize)]
pub struct ExitNodeUseCommand {
    pub target: String,
    #[serde(default)]
    pub tun_name: Option<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
}

pub struct CommandServer {}

impl CommandServer {
    pub fn new() -> Self {
        Self {}
    }
}

pub trait CommandHandler: Send + Sync + 'static {
    fn route(&self) -> io::Result<Vec<RouteItem>>;
    fn list(&self) -> io::Result<Vec<DeviceItem>>;
    fn info(&self) -> io::Result<Info>;
    fn gateway(&self) -> io::Result<Vec<GatewayItem>>;
    fn gateway_set(&self, gateway: Option<&str>) -> io::Result<String>;
    fn exit_node_list(&self) -> io::Result<Vec<ExitNodeItem>>;
    fn exit_node_status(&self) -> io::Result<ExitNodeStatus>;
    fn exit_node_enable(&self, enable: ExitNodeEnableCommand) -> io::Result<String>;
    fn exit_node_disable(&self, disable: ExitNodeDisableCommand) -> io::Result<String>;
    fn exit_node_use(&self, use_command: ExitNodeUseCommand) -> io::Result<String>;
    fn exit_node_clear(&self, clear: ExitNodeDisableCommand) -> io::Result<String>;
    fn traffic(&self) -> io::Result<TrafficSummary>;
    fn traffic_policy_status(&self) -> io::Result<TrafficPolicyStatus> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "traffic policy is not configured",
        ))
    }
    fn traffic_policy_up(&self) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "traffic policy is not configured",
        ))
    }
    fn traffic_policy_down(&self) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "traffic policy is not configured",
        ))
    }
    fn resume_runtime(&self) -> io::Result<String>;
    fn down_runtime(&self) -> io::Result<String>;
    fn suspend_runtime(&self) -> io::Result<String>;
    fn channel_change(&self, use_channel_type: UseChannelType) -> io::Result<String>;
    fn rename(&self, new_name: &str) -> io::Result<String>;
    fn auth(&self, auth: AuthCommand) -> io::Result<String>;
    fn switch_user(&self, switch: SwitchCommand) -> io::Result<String>;
}

impl CommandServer {
    pub fn start<H>(self, handler: H) -> io::Result<()>
    where
        H: CommandHandler,
    {
        let listener = ipc::bind_listener()?;
        log::info!("启动后台本地命令socket");

        for conn in listener.incoming() {
            match conn {
                Ok(mut conn) => {
                    if let Err(e) = handle_connection(&mut conn, &handler) {
                        log::warn!("local command socket error: {:?}", e);
                    }
                }
                Err(e) => {
                    log::warn!("local command socket accept failed: {:?}", e);
                }
            }
        }
        Ok(())
    }
}

fn handle_connection<S, H>(conn: &mut S, handler: &H) -> io::Result<()>
where
    S: Read + Write,
    H: CommandHandler,
{
    let frame = ipc::read_frame(conn)?;
    let cmd = std::str::from_utf8(&frame).map_err(io::Error::other)?;
    let out = command(cmd, handler).unwrap_or_else(|e| {
        serde_yaml::to_string(&format!("error {}", e))
            .unwrap_or_else(|ser_err| format!("error {:?}", ser_err))
    });
    ipc::write_frame(conn, out.as_bytes())
}

fn command<H>(cmd: &str, handler: &H) -> io::Result<String>
where
    H: CommandHandler,
{
    let cmd = cmd.trim();
    let out_str = match cmd {
        "route" => {
            serde_yaml::to_string(&handler.route()?).unwrap_or_else(|e| format!("error {:?}", e))
        }
        "list" => {
            serde_yaml::to_string(&handler.list()?).unwrap_or_else(|e| format!("error {:?}", e))
        }
        "status" | "info" => {
            serde_yaml::to_string(&handler.info()?).unwrap_or_else(|e| format!("error {:?}", e))
        }
        "gateway" => {
            serde_yaml::to_string(&handler.gateway()?).unwrap_or_else(|e| format!("error {:?}", e))
        }
        "exit_node:list" => serde_yaml::to_string(&handler.exit_node_list()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "exit_node:status" => serde_yaml::to_string(&handler.exit_node_status()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "exit_node:disable" => serde_yaml::to_string(
            &handler.exit_node_disable(ExitNodeDisableCommand { tun_name: None })?,
        )
        .unwrap_or_else(|e| format!("error {:?}", e)),
        "exit_node:clear" => serde_yaml::to_string(
            &handler.exit_node_clear(ExitNodeDisableCommand { tun_name: None })?,
        )
        .unwrap_or_else(|e| format!("error {:?}", e)),
        "traffic" => {
            serde_yaml::to_string(&handler.traffic()?).unwrap_or_else(|e| format!("error {:?}", e))
        }
        "traffic_policy:status" => serde_yaml::to_string(&handler.traffic_policy_status()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "traffic_policy:up" => serde_yaml::to_string(&handler.traffic_policy_up()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "traffic_policy:down" => serde_yaml::to_string(&handler.traffic_policy_down()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "up" | "resume" => serde_yaml::to_string(&handler.resume_runtime()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "down" => serde_yaml::to_string(&handler.down_runtime()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "suspend" => serde_yaml::to_string(&handler.suspend_runtime()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        _ => {
            if let Some(value) = cmd.strip_prefix("channel_change:") {
                match UseChannelType::from_str(value.trim()) {
                    Ok(use_channel_type) => {
                        serde_yaml::to_string(&handler.channel_change(use_channel_type)?)
                            .unwrap_or_else(|e| format!("error {:?}", e))
                    }
                    Err(err) => serde_yaml::to_string(&format!("error {}", err))
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                }
            } else if let Some(value) = cmd.strip_prefix("rename:") {
                serde_yaml::to_string(&handler.rename(value)?)
                    .unwrap_or_else(|e| format!("error {:?}", e))
            } else if let Some(value) = cmd.strip_prefix("gateway_set:") {
                let gateway = value.trim();
                let gateway = if gateway.is_empty() {
                    None
                } else {
                    Some(gateway)
                };
                serde_yaml::to_string(&handler.gateway_set(gateway)?)
                    .unwrap_or_else(|e| format!("error {:?}", e))
            } else if let Some(value) = cmd.strip_prefix("exit_node:enable:") {
                match serde_json::from_str::<ExitNodeEnableCommand>(value.trim()) {
                    Ok(enable) => serde_yaml::to_string(&handler.exit_node_enable(enable)?)
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                    Err(err) => serde_yaml::to_string(&format!("error {}", err))
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                }
            } else if let Some(value) = cmd.strip_prefix("exit_node:disable:") {
                match serde_json::from_str::<ExitNodeDisableCommand>(value.trim()) {
                    Ok(disable) => serde_yaml::to_string(&handler.exit_node_disable(disable)?)
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                    Err(err) => serde_yaml::to_string(&format!("error {}", err))
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                }
            } else if let Some(value) = cmd.strip_prefix("exit_node:clear:") {
                match serde_json::from_str::<ExitNodeDisableCommand>(value.trim()) {
                    Ok(clear) => serde_yaml::to_string(&handler.exit_node_clear(clear)?)
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                    Err(err) => serde_yaml::to_string(&format!("error {}", err))
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                }
            } else if let Some(value) = cmd.strip_prefix("exit_node:use:") {
                match serde_json::from_str::<ExitNodeUseCommand>(value.trim()) {
                    Ok(use_command) => serde_yaml::to_string(&handler.exit_node_use(use_command)?)
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                    Err(err) => serde_yaml::to_string(&format!("error {}", err))
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                }
            } else if let Some(value) = cmd.strip_prefix("auth:") {
                match serde_json::from_str::<AuthCommand>(value.trim()) {
                    Ok(auth) => {
                        let _ = crate::command::service_state::clear_service_state();
                        serde_yaml::to_string(&handler.auth(auth)?)
                            .unwrap_or_else(|e| format!("error {:?}", e))
                    }
                    Err(err) => serde_yaml::to_string(&format!("error {}", err))
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                }
            } else if let Some(value) = cmd.strip_prefix("switch:") {
                match serde_json::from_str::<SwitchCommand>(value.trim()) {
                    Ok(switch) => {
                        let _ = crate::command::service_state::clear_service_state();
                        serde_yaml::to_string(&handler.switch_user(switch)?)
                            .unwrap_or_else(|e| format!("error {:?}", e))
                    }
                    Err(err) => serde_yaml::to_string(&format!("error {}", err))
                        .unwrap_or_else(|e| format!("error {:?}", e)),
                }
            } else {
                format!(
                    "command '{}' not found.  Try to enter: 'route'/'list'/'up'/'down' \n",
                    cmd
                )
            }
        }
    };
    Ok(out_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubHandler;

    impl CommandHandler for StubHandler {
        fn route(&self) -> io::Result<Vec<RouteItem>> {
            Ok(Vec::new())
        }
        fn list(&self) -> io::Result<Vec<DeviceItem>> {
            Ok(Vec::new())
        }
        fn info(&self) -> io::Result<Info> {
            Err(io::Error::other("unused"))
        }
        fn gateway(&self) -> io::Result<Vec<GatewayItem>> {
            Ok(Vec::new())
        }
        fn gateway_set(&self, gateway: Option<&str>) -> io::Result<String> {
            Ok(gateway.unwrap_or("auto").to_string())
        }
        fn exit_node_list(&self) -> io::Result<Vec<ExitNodeItem>> {
            Ok(vec![ExitNodeItem {
                name: "node-b".to_string(),
                device_id: "dev-b".to_string(),
                virtual_ip: "10.26.0.4".to_string(),
                status: "Online".to_string(),
                approved: true,
                usable: true,
            }])
        }
        fn exit_node_status(&self) -> io::Result<ExitNodeStatus> {
            Ok(ExitNodeStatus::default())
        }
        fn exit_node_enable(&self, enable: ExitNodeEnableCommand) -> io::Result<String> {
            Ok(format!("exit-node:{}", enable.egress_interface))
        }
        fn exit_node_disable(&self, _disable: ExitNodeDisableCommand) -> io::Result<String> {
            Ok("exit-node disabled".to_string())
        }
        fn exit_node_use(&self, use_command: ExitNodeUseCommand) -> io::Result<String> {
            Ok(format!("exit-node use {}", use_command.target))
        }
        fn exit_node_clear(&self, _clear: ExitNodeDisableCommand) -> io::Result<String> {
            Ok("exit-node selection cleared".to_string())
        }
        fn traffic(&self) -> io::Result<TrafficSummary> {
            Ok(TrafficSummary::default())
        }
        fn resume_runtime(&self) -> io::Result<String> {
            Ok("up".to_string())
        }
        fn down_runtime(&self) -> io::Result<String> {
            Ok("down".to_string())
        }
        fn suspend_runtime(&self) -> io::Result<String> {
            Ok("suspend".to_string())
        }
        fn channel_change(&self, _use_channel_type: UseChannelType) -> io::Result<String> {
            Ok("ok".to_string())
        }
        fn rename(&self, new_name: &str) -> io::Result<String> {
            Ok(new_name.to_string())
        }
        fn auth(&self, auth: AuthCommand) -> io::Result<String> {
            Ok(format!(
                "{}:{}:{}",
                auth.user_id,
                auth.group,
                auth.ticket.len()
            ))
        }
        fn switch_user(&self, switch: SwitchCommand) -> io::Result<String> {
            Ok(format!("switch:{}", switch.user_id))
        }
    }

    #[test]
    fn auth_command_parses_long_json_payload() {
        let handler = StubHandler;
        let long_ticket = "x".repeat(256);
        let payload = serde_json::json!({
            "user_id": "user-1",
            "group": "sales.ms.net",
            "ticket": long_ticket,
        });
        let cmd = format!("auth:{}", serde_json::to_string(&payload).unwrap());

        let out = command(&cmd, &handler).unwrap();
        let parsed: String = serde_yaml::from_str(&out).unwrap();

        assert_eq!(parsed, "user-1:sales.ms.net:256");
        assert!(cmd.len() > 64);
    }

    #[test]
    fn rename_command_passes_raw_name() {
        let handler = StubHandler;
        let out = command("rename:desktop windows", &handler).unwrap();
        let parsed: String = serde_yaml::from_str(&out).unwrap();
        assert_eq!(parsed, "desktop windows");
    }

    #[test]
    fn switch_command_parses_json_payload() {
        let handler = StubHandler;
        let payload = serde_json::json!({
            "user_id": "sdl-user-1",
        });
        let cmd = format!("switch:{}", serde_json::to_string(&payload).unwrap());

        let out = command(&cmd, &handler).unwrap();
        let parsed: String = serde_yaml::from_str(&out).unwrap();

        assert_eq!(parsed, "switch:sdl-user-1");
    }

    #[test]
    fn gateway_set_command_passes_raw_value() {
        let handler = StubHandler;
        let out = command("gateway_set:gateway-west", &handler).unwrap();
        let parsed: String = serde_yaml::from_str(&out).unwrap();
        assert_eq!(parsed, "gateway-west");
    }

    #[test]
    fn exit_node_use_command_parses_json_payload() {
        let handler = StubHandler;
        let payload = serde_json::json!({
            "target": "node-b",
        });
        let cmd = format!("exit_node:use:{}", serde_json::to_string(&payload).unwrap());

        let out = command(&cmd, &handler).unwrap();
        let parsed: String = serde_yaml::from_str(&out).unwrap();

        assert_eq!(parsed, "exit-node use node-b");
    }

    #[test]
    fn exit_node_list_command_returns_items() {
        let handler = StubHandler;
        let out = command("exit_node:list", &handler).unwrap();
        let parsed: Vec<ExitNodeItem> = serde_yaml::from_str(&out).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].device_id, "dev-b");
        assert!(parsed[0].usable);
    }

    #[test]
    fn lifecycle_commands_route_to_expected_runtime_actions() {
        let handler = StubHandler;

        let up: String = serde_yaml::from_str(&command("up", &handler).unwrap()).unwrap();
        let resume: String = serde_yaml::from_str(&command("resume", &handler).unwrap()).unwrap();
        let down: String = serde_yaml::from_str(&command("down", &handler).unwrap()).unwrap();
        let suspend: String = serde_yaml::from_str(&command("suspend", &handler).unwrap()).unwrap();

        assert_eq!(up, "up");
        assert_eq!(resume, "up");
        assert_eq!(down, "down");
        assert_eq!(suspend, "suspend");
    }

    #[test]
    fn status_command_reuses_info_handler() {
        struct StatusHandler;

        impl CommandHandler for StatusHandler {
            fn route(&self) -> io::Result<Vec<RouteItem>> {
                Err(io::Error::other("unused"))
            }
            fn list(&self) -> io::Result<Vec<DeviceItem>> {
                Err(io::Error::other("unused"))
            }
            fn info(&self) -> io::Result<Info> {
                Ok(Info {
                    name: "status-ok".to_string(),
                    runtime_name: String::new(),
                    runtime_status: String::new(),
                    restart_required: false,
                    device_id: String::new(),
                    virtual_ip: String::new(),
                    virtual_gateway: String::new(),
                    virtual_netmask: String::new(),
                    gateway_session_status: String::new(),
                    gateway_grant_state: String::new(),
                    gateway_endpoint: String::new(),
                    gateway_channel: String::new(),
                    connect_status: String::new(),
                    data_plane_status: String::new(),
                    auth_pending: false,
                    auth_status: String::new(),
                    auth_detail: None,
                    channel_policy: String::new(),
                    last_error: None,
                    nat_type: String::new(),
                    public_ips: String::new(),
                    local_addr: String::new(),
                    ipv6_addr: String::new(),
                    port_mapping_list: Vec::new(),
                    udp_listen_addr: Vec::new(),
                })
            }
            fn gateway(&self) -> io::Result<Vec<GatewayItem>> {
                Err(io::Error::other("unused"))
            }
            fn gateway_set(&self, _gateway: Option<&str>) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn exit_node_list(&self) -> io::Result<Vec<ExitNodeItem>> {
                Err(io::Error::other("unused"))
            }
            fn exit_node_status(&self) -> io::Result<ExitNodeStatus> {
                Err(io::Error::other("unused"))
            }
            fn exit_node_enable(&self, _enable: ExitNodeEnableCommand) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn exit_node_disable(&self, _disable: ExitNodeDisableCommand) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn exit_node_use(&self, _use_command: ExitNodeUseCommand) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn exit_node_clear(&self, _clear: ExitNodeDisableCommand) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn traffic(&self) -> io::Result<TrafficSummary> {
                Err(io::Error::other("unused"))
            }
            fn resume_runtime(&self) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn down_runtime(&self) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn suspend_runtime(&self) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn channel_change(&self, _use_channel_type: UseChannelType) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn rename(&self, _new_name: &str) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn auth(&self, _auth: AuthCommand) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
            fn switch_user(&self, _switch: SwitchCommand) -> io::Result<String> {
                Err(io::Error::other("unused"))
            }
        }

        let handler = StatusHandler;
        let out = command("status", &handler).unwrap();
        let parsed: Info = serde_yaml::from_str(&out).unwrap();
        assert_eq!(parsed.name, "status-ok");
    }

    struct FailingRenameHandler;

    impl CommandHandler for FailingRenameHandler {
        fn route(&self) -> io::Result<Vec<RouteItem>> {
            Err(io::Error::other("unused"))
        }
        fn list(&self) -> io::Result<Vec<DeviceItem>> {
            Err(io::Error::other("unused"))
        }
        fn info(&self) -> io::Result<Info> {
            Err(io::Error::other("unused"))
        }
        fn gateway(&self) -> io::Result<Vec<GatewayItem>> {
            Err(io::Error::other("unused"))
        }
        fn gateway_set(&self, _gateway: Option<&str>) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn exit_node_list(&self) -> io::Result<Vec<ExitNodeItem>> {
            Err(io::Error::other("unused"))
        }
        fn exit_node_status(&self) -> io::Result<ExitNodeStatus> {
            Err(io::Error::other("unused"))
        }
        fn exit_node_enable(&self, _enable: ExitNodeEnableCommand) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn exit_node_disable(&self, _disable: ExitNodeDisableCommand) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn exit_node_use(&self, _use_command: ExitNodeUseCommand) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn exit_node_clear(&self, _clear: ExitNodeDisableCommand) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn traffic(&self) -> io::Result<TrafficSummary> {
            Err(io::Error::other("unused"))
        }
        fn resume_runtime(&self) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn down_runtime(&self) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn suspend_runtime(&self) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn channel_change(&self, _use_channel_type: UseChannelType) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn rename(&self, _new_name: &str) -> io::Result<String> {
            Err(io::Error::other("rename failed: timed out"))
        }
        fn auth(&self, _auth: AuthCommand) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
        fn switch_user(&self, _switch: SwitchCommand) -> io::Result<String> {
            Err(io::Error::other("unused"))
        }
    }

    #[test]
    fn handle_connection_yaml_encodes_command_errors() {
        let handler = FailingRenameHandler;
        let mut conn = std::io::Cursor::new(Vec::new());
        ipc::write_frame(&mut conn, b"rename:new-name").unwrap();
        conn.set_position(0);

        handle_connection(&mut conn, &handler).unwrap();

        let written = conn.into_inner();
        let mut reader = std::io::Cursor::new(written);
        let _ = ipc::read_frame(&mut reader).unwrap();
        let response = ipc::read_frame(&mut reader).unwrap();
        let parsed: String = serde_yaml::from_slice(&response).unwrap();
        assert_eq!(parsed, "error rename failed: timed out");
    }
}
