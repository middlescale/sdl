use serde::de::DeserializeOwned;
use std::io;

use crate::command::entity::{DeviceItem, GatewayItem, Info, RouteItem, TrafficSummary};
use crate::command::ipc;

pub struct CommandClient;

impl CommandClient {
    pub fn new() -> io::Result<Self> {
        Ok(Self)
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
    pub fn status(&mut self) -> io::Result<Info> {
        self.send_cmd(b"status")
    }
    pub fn info(&mut self) -> io::Result<Info> {
        self.send_cmd(b"info")
    }
    pub fn gateway(&mut self) -> io::Result<Vec<GatewayItem>> {
        self.send_cmd(b"gateway")
    }
    pub fn traffic(&mut self) -> io::Result<TrafficSummary> {
        self.send_cmd(b"traffic")
    }
    pub fn channel_change(&mut self, input: &str) -> io::Result<String> {
        let cmd = format!("channel_change:{}", input.trim());
        self.send_string_cmd(cmd.as_bytes())
    }
    pub fn rename(&mut self, input: &str) -> io::Result<String> {
        let cmd = format!("rename:{}", input);
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
    fn send_cmd<V: DeserializeOwned>(&mut self, cmd: &[u8]) -> io::Result<V> {
        let mut stream = ipc::connect_stream()?;
        ipc::write_frame(&mut stream, cmd)?;
        let response = ipc::read_frame(&mut stream)?;
        match serde_yaml::from_slice::<V>(&response) {
            Ok(val) => Ok(val),
            Err(e) => {
                log::error!(
                    "send_cmd {:?} {:?},{:?}",
                    std::str::from_utf8(cmd),
                    std::str::from_utf8(&response),
                    e
                );
                Err(io::Error::other(format!(
                    "data error {:?} buf_len={}",
                    e,
                    response.len()
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
