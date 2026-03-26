use crate::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};
use serde::Deserialize;
use std::io;
use std::io::Write;
use std::net::UdpSocket;
use std::str::FromStr;
use vnt::data_plane::use_channel_type::UseChannelType;

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
    fn start_runtime(&self) -> io::Result<String>;
    fn stop_runtime(&self) -> io::Result<String>;
    fn channel_change(&self, use_channel_type: UseChannelType) -> io::Result<String>;
    fn auth(&self, auth: AuthCommand) -> io::Result<String>;
}

impl CommandServer {
    pub fn start<H>(self, handler: H) -> io::Result<()>
    where
        H: CommandHandler,
    {
        let udp = if let Ok(udp) = UdpSocket::bind("127.0.0.1:39271") {
            udp
        } else {
            UdpSocket::bind("127.0.0.1:0")?
        };
        let addr = udp.local_addr()?;
        log::info!("启动后台cmd:{:?}", addr);
        if let Err(e) = save_port(addr.port()) {
            log::warn!("保存后台命令端口失败：{:?}", e);
        }

        let mut buf = [0u8; 64];
        loop {
            let (len, addr) = udp.recv_from(&mut buf)?;
            match std::str::from_utf8(&buf[..len]) {
                Ok(cmd) => {
                    if let Ok(out) = command(cmd, &handler) {
                        if let Err(e) = udp.send_to(out.as_bytes(), addr) {
                            log::warn!("cmd={},err={:?}", cmd, e);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("{:?}", e);
                }
            }
        }
    }
}
fn save_port(port: u16) -> io::Result<()> {
    let path_buf = crate::cli::app_home()?.join("command-port");
    let mut file = std::fs::File::create(path_buf)?;
    file.write_all(port.to_string().as_bytes())?;
    file.sync_all()
}

fn command<H>(cmd: &str, handler: &H) -> io::Result<String>
where
    H: CommandHandler,
{
    let cmd = cmd.trim();
    let out_str = match cmd {
        "route" => serde_yaml::to_string(&handler.route()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "list" => serde_yaml::to_string(&handler.list()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "info" => serde_yaml::to_string(&handler.info()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "chart_a" => serde_yaml::to_string(&handler.chart_a()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "start" => serde_yaml::to_string(&handler.start_runtime()?)
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "stop" => {
            serde_yaml::to_string(&handler.stop_runtime()?).unwrap_or_else(|e| format!("error {:?}", e))
        }
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
                    Ok(use_channel_type) => serde_yaml::to_string(
                        &handler.channel_change(use_channel_type)?,
                    )
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
            } else {
                format!(
                    "command '{}' not found.  Try to enter: 'route'/'list'/'stop' \n",
                    cmd
                )
            }
        }
    };
    Ok(out_str)
}
