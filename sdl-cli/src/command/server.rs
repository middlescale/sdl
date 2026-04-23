use crate::command::entity::{DeviceItem, GatewayItem, Info, RouteItem, TrafficSummary};
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
    fn traffic(&self) -> io::Result<TrafficSummary>;
    fn resume_runtime(&self) -> io::Result<String>;
    fn suspend_runtime(&self) -> io::Result<String>;
    fn channel_change(&self, use_channel_type: UseChannelType) -> io::Result<String>;
    fn rename(&self, new_name: &str) -> io::Result<String>;
    fn auth(&self, auth: AuthCommand) -> io::Result<String>;
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
    let out_str =
        match cmd {
            "route" => serde_yaml::to_string(&handler.route()?)
                .unwrap_or_else(|e| format!("error {:?}", e)),
            "list" => {
                serde_yaml::to_string(&handler.list()?).unwrap_or_else(|e| format!("error {:?}", e))
            }
            "status" | "info" => {
                serde_yaml::to_string(&handler.info()?).unwrap_or_else(|e| format!("error {:?}", e))
            }
            "gateway" => serde_yaml::to_string(&handler.gateway()?)
                .unwrap_or_else(|e| format!("error {:?}", e)),
            "traffic" => serde_yaml::to_string(&handler.traffic()?)
                .unwrap_or_else(|e| format!("error {:?}", e)),
            "resume" => serde_yaml::to_string(&handler.resume_runtime()?)
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
                } else {
                    format!(
                    "command '{}' not found.  Try to enter: 'route'/'list'/'resume'/'suspend' \n",
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
        fn traffic(&self) -> io::Result<TrafficSummary> {
            Ok(TrafficSummary::default())
        }
        fn resume_runtime(&self) -> io::Result<String> {
            Ok("ok".to_string())
        }
        fn suspend_runtime(&self) -> io::Result<String> {
            Ok("ok".to_string())
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
                    restart_required: false,
                    device_id: String::new(),
                    virtual_ip: String::new(),
                    virtual_gateway: String::new(),
                    virtual_netmask: String::new(),
                    gateway_session_status: String::new(),
                    gateway_endpoint: String::new(),
                    gateway_channel: String::new(),
                    connect_status: String::new(),
                    data_plane_status: String::new(),
                    auth_pending: false,
                    channel_policy: String::new(),
                    last_error: None,
                    nat_type: String::new(),
                    public_ips: String::new(),
                    local_addr: String::new(),
                    ipv6_addr: String::new(),
                    port_mapping_list: Vec::new(),
                    in_ips: Vec::new(),
                    out_ips: Vec::new(),
                    udp_listen_addr: Vec::new(),
                })
            }
            fn gateway(&self) -> io::Result<Vec<GatewayItem>> {
                Err(io::Error::other("unused"))
            }
            fn traffic(&self) -> io::Result<TrafficSummary> {
                Err(io::Error::other("unused"))
            }
            fn resume_runtime(&self) -> io::Result<String> {
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
        fn traffic(&self) -> io::Result<TrafficSummary> {
            Err(io::Error::other("unused"))
        }
        fn resume_runtime(&self) -> io::Result<String> {
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
