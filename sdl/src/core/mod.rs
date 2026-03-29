use crate::cipher::CipherModel;
use crate::compression::Compressor;
use crate::data_plane::use_channel_type::UseChannelType;
use crate::nat::punch::PunchModel;
use crate::transport::connect_protocol::ConnectProtocol;
use crate::transport::socket::LocalInterface;
use crate::util::{address_choose, dns_query_all};
use anyhow::anyhow;
pub use bootstrap::Sdl;
pub use runtime::{AuthRequestConfig, RuntimeConfig, SdlRuntime};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

mod bootstrap;
mod runtime;

pub const PUB_STUN: [&str; 4] = [
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
    "stun.cdnbye.com",
];

#[derive(Clone, Debug)]
pub struct Config {
    #[cfg(feature = "integrated_tun")]
    #[cfg(target_os = "windows")]
    pub tap: bool,
    pub token: String,
    pub device_id: String,
    pub name: String,
    pub server_address: SocketAddr,
    pub server_address_str: String,
    pub name_servers: Vec<String>,
    pub stun_server: Vec<String>,
    pub in_ips: Vec<(u32, u32, Ipv4Addr)>,
    pub out_ips: Vec<(u32, u32)>,
    pub mtu: Option<u32>,
    pub protocol: ConnectProtocol,
    pub ip: Option<Ipv4Addr>,
    pub cipher_model: CipherModel,
    pub punch_model: PunchModel,
    pub ports: Option<Vec<u16>>,
    pub latency_first: bool,
    #[cfg(feature = "integrated_tun")]
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub device_name: Option<String>,
    pub use_channel_type: UseChannelType,
    //控制丢包率
    pub packet_loss_rate: Option<f64>,
    pub packet_delay: u32,
    // 端口映射
    #[cfg(feature = "port_mapping")]
    pub port_mapping_list: Vec<(bool, SocketAddr, String)>,
    pub compressor: Compressor,
    pub enable_traffic: bool,
    pub local_ipv4: Option<Ipv4Addr>,
    pub local_interface: LocalInterface,
    pub auth_user_id: Option<String>,
    pub auth_group: Option<String>,
    pub auth_ticket: Option<String>,
}

impl Config {
    pub fn simple_new_config(
        device_id: String,
        token: String,
        server_address_str: String,
        ip: Option<Ipv4Addr>,
        ports: Option<Vec<u16>>,
        nic: Option<String>,
    ) -> anyhow::Result<Self> {
        let name = std::env::var("HOSTNAME")
            .unwrap_or_else(|_| gethostname::gethostname().to_string_lossy().into_owned());
        Config::new(
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            false,
            token,
            device_id,
            name,
            server_address_str,
            vec![],
            PUB_STUN.iter().map(|s| s.to_string()).collect(),
            vec![],
            vec![],
            None,
            ip,
            #[cfg(feature = "aes_gcm")]
            CipherModel::AesGcm,
            #[cfg(not(feature = "aes_gcm"))]
            CipherModel::None,
            PunchModel::All,
            ports,
            false,
            nic,
            UseChannelType::All,
            None,
            0,
            vec![],
            Compressor::None,
            false,
            None,
            None,
            None,
            None,
        )
    }

    pub fn new(
        #[cfg(feature = "integrated_tun")]
        #[cfg(target_os = "windows")]
        tap: bool,
        token: String,
        device_id: String,
        name: String,
        server_address_str: String,
        mut name_servers: Vec<String>,
        mut stun_server: Vec<String>,
        mut in_ips: Vec<(u32, u32, Ipv4Addr)>,
        out_ips: Vec<(u32, u32)>,
        mtu: Option<u32>,
        ip: Option<Ipv4Addr>,
        cipher_model: CipherModel,
        punch_model: PunchModel,
        ports: Option<Vec<u16>>,
        latency_first: bool,
        device_name: Option<String>,
        use_channel_type: UseChannelType,
        packet_loss_rate: Option<f64>,
        packet_delay: u32,
        // 例如 [udp:127.0.0.1:80->10.26.0.10:8080,tcp:127.0.0.1:80->10.26.0.10:8080]
        port_mapping_list: Vec<String>,
        compressor: Compressor,
        enable_traffic: bool,
        local_dev: Option<String>,
        auth_user_id: Option<String>,
        auth_group: Option<String>,
        auth_ticket: Option<String>,
    ) -> anyhow::Result<Self> {
        for x in stun_server.iter_mut() {
            if !x.contains(":") {
                x.push_str(":3478");
            }
        }
        for x in name_servers.iter_mut() {
            if Ipv6Addr::from_str(x).is_ok() {
                x.push_str(":53");
            } else if !x.contains(":") {
                x.push_str(":53");
            }
        }
        if token.is_empty() || token.len() > 128 {
            return Err(anyhow!("token too long"));
        }
        if device_id.is_empty() || device_id.len() > 128 {
            return Err(anyhow!("device_id too long"));
        }
        if name.is_empty() || name.len() > 128 {
            return Err(anyhow!("name too long"));
        }
        if !cipher_model.is_runtime_supported() {
            return Err(anyhow!(
                "unsupported runtime cipher model '{}', only aes_gcm or none are allowed",
                cipher_model
            ));
        }
        let mut server_address_str = server_address_str.to_lowercase();
        let _query_dns = true;
        let protocol = ConnectProtocol::QUIC;
        if server_address_str.starts_with("udp://")
            || server_address_str.starts_with("tcp://")
            || server_address_str.starts_with("ws://")
            || server_address_str.starts_with("wss://")
            || server_address_str.starts_with("http://")
            || server_address_str.starts_with("https://")
        {
            Err(anyhow!(
                "only quic:// is supported for sdl-control connection currently"
            ))?;
        }
        if let Some(s) = server_address_str.strip_prefix("quic://") {
            server_address_str = s.to_string();
        }
        #[cfg(not(feature = "quic"))]
        {
            let _ = protocol;
            Err(anyhow!("Quic not supported"))?;
        }

        let mut server_address = "0.0.0.0:0".parse().unwrap();
        if _query_dns {
            server_address = address_choose(dns_query_all(
                &server_address_str,
                name_servers.clone(),
                &LocalInterface::default(),
            )?)?;
        }
        #[cfg(feature = "port_mapping")]
        let port_mapping_list = crate::port_mapping::convert(port_mapping_list)?;
        #[cfg(not(feature = "port_mapping"))]
        let _ = port_mapping_list;
        #[cfg(not(feature = "integrated_tun"))]
        let _ = device_name;

        for (dest, mask, _) in &mut in_ips {
            *dest &= *mask;
        }
        in_ips.sort_by(|(dest1, _, _), (dest2, _, _)| dest2.cmp(dest1));
        let (local_interface, local_ipv4) = if let Some(local_dev) = local_dev {
            let (default_interface, ip) = crate::transport::socket::get_interface(local_dev)?;
            log::info!("default_interface = {:?} local_ip= {ip}", default_interface);
            (default_interface, Some(ip))
        } else {
            (LocalInterface::default(), None)
        };
        Ok(Self {
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            tap,
            token,
            device_id,
            name,
            server_address,
            server_address_str,
            name_servers,
            stun_server,
            in_ips,
            out_ips,
            mtu,
            protocol,
            ip,
            cipher_model,
            punch_model,
            ports,
            latency_first,
            #[cfg(feature = "integrated_tun")]
            #[cfg(not(target_os = "android"))]
            device_name,
            use_channel_type,
            packet_loss_rate,
            packet_delay,
            #[cfg(feature = "port_mapping")]
            port_mapping_list,
            compressor,
            enable_traffic,
            local_ipv4,
            local_interface,
            auth_user_id,
            auth_group,
            auth_ticket,
        })
    }
}
