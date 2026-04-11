use crate::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};
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
    fn chart_a(&self) -> io::Result<ChartA>;
    fn chart_b(&self, input: Option<&str>) -> io::Result<ChartB>;
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
    let out = command(cmd, handler).unwrap_or_else(|e| format!("error {}", e));
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
            "info" => {
                serde_yaml::to_string(&handler.info()?).unwrap_or_else(|e| format!("error {:?}", e))
            }
            "chart_a" => serde_yaml::to_string(&handler.chart_a()?)
                .unwrap_or_else(|e| format!("error {:?}", e)),
            "resume" => serde_yaml::to_string(&handler.resume_runtime()?)
                .unwrap_or_else(|e| format!("error {:?}", e)),
            "suspend" => serde_yaml::to_string(&handler.suspend_runtime()?)
                .unwrap_or_else(|e| format!("error {:?}", e)),
            _ => {
                if let Some(ip) = cmd.strip_prefix("chart_b") {
                    let chart = if ip.is_empty() {
                        handler.chart_b(None)?
                    } else {
                        handler.chart_b(Some(&ip[1..]))?
                    };
                    serde_yaml::to_string(&chart).unwrap_or_else(|e| format!("error {:?}", e))
                } else if let Some(value) = cmd.strip_prefix("channel_change:") {
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
        fn chart_a(&self) -> io::Result<ChartA> {
            Err(io::Error::other("unused"))
        }
        fn chart_b(&self, _input: Option<&str>) -> io::Result<ChartB> {
            Err(io::Error::other("unused"))
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
}
