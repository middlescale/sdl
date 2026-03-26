use serde::Deserialize;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

use crate::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};

pub struct CommandClient {
    buf: Vec<u8>,
    udp: UdpSocket,
}

impl CommandClient {
    pub fn new() -> io::Result<Self> {
        let port = read_command_port().unwrap_or_else(|e| {
            log::warn!("read_command_port:{:?}", e);
            39271
        });
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        udp.set_read_timeout(Some(Duration::from_secs(5)))?;
        udp.connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
        )))?;
        Ok(Self {
            udp,
            buf: vec![0; 65536 * 8],
        })
    }
}
fn read_command_port() -> io::Result<u16> {
    let path_buf = crate::cli::app_home()?.join("command-port");
    let port = std::fs::read_to_string(path_buf)?;
    match u16::from_str(&port) {
        Ok(port) => Ok(port),
        Err(_) => Err(io::Error::other("'command-port' file error")),
    }
}

impl CommandClient {
    pub fn resume(&mut self) -> io::Result<String> {
        self.send_string_cmd(b"resume")
    }
    pub fn list(&mut self) -> io::Result<Vec<DeviceItem>> {
        self.send_cmd(b"list")
    }
    pub fn route(&mut self) -> io::Result<Vec<RouteItem>> {
        self.send_cmd(b"route")
    }
    pub fn info(&mut self) -> io::Result<Info> {
        self.send_cmd(b"info")
    }
    pub fn chart_a(&mut self) -> io::Result<ChartA> {
        self.send_cmd(b"chart_a")
    }
    pub fn chart_b(&mut self, input: &str) -> io::Result<ChartB> {
        let cmd = if input.is_empty() {
            "chart_b".to_string()
        } else {
            format!("chart_b:{}", input)
        };
        self.send_cmd(cmd.as_bytes())
    }
    pub fn channel_change(&mut self, input: &str) -> io::Result<String> {
        let cmd = format!("channel_change:{}", input.trim());
        self.send_string_cmd(cmd.as_bytes())
    }
    pub fn auth(&mut self, user_id: &str, group: &str, ticket: &str) -> io::Result<String> {
        let cmd = serde_json::json!({
            "user_id": user_id,
            "group": group,
            "ticket": ticket,
        });
        let cmd = format!("auth:{}", serde_json::to_string(&cmd).unwrap());
        self.send_string_cmd(cmd.as_bytes())
    }
    fn send_cmd<'a, V: Deserialize<'a>>(&'a mut self, cmd: &[u8]) -> io::Result<V> {
        self.udp.send(cmd)?;
        let len = self.udp.recv(&mut self.buf)?;
        match serde_yaml::from_slice::<V>(&self.buf[..len]) {
            Ok(val) => Ok(val),
            Err(e) => {
                log::error!(
                    "send_cmd {:?} {:?},{:?}",
                    std::str::from_utf8(cmd),
                    std::str::from_utf8(&self.buf[..len]),
                    e
                );
                Err(io::Error::other(format!(
                    "data error {:?} buf_len={}",
                    e, len
                )))
            }
        }
    }
    fn send_string_cmd(&mut self, cmd: &[u8]) -> io::Result<String> {
        let value: String = self.send_cmd(cmd)?;
        if value.starts_with("error ") {
            Err(io::Error::other(value))
        } else {
            Ok(value)
        }
    }
    pub fn suspend(&mut self) -> io::Result<String> {
        self.send_string_cmd(b"suspend")
    }
}
