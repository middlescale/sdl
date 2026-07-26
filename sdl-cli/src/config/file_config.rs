use anyhow::anyhow;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

use crate::config::get_device_id;
use sdl::cipher::CipherModel;
use sdl::compression::Compressor;
use sdl::core::Config;
use sdl::data_plane::use_channel_type::UseChannelType;
use sdl::nat::punch::PunchModel;
use serde::{Deserialize, Serialize};

pub const DEFAULT_SERVICE_GROUP: &str = "default.ms.net";
pub const DEFAULT_SERVICE_SERVER: &str = "https://control.middlescale.net/control";
pub const DEFAULT_CLIENT_LISTEN_PORT: u16 = 29873;
pub const FILE_CONFIG_VERSION: u32 = 2;

fn default_config_version() -> u32 {
    FILE_CONFIG_VERSION
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ActiveConfig {
    #[serde(default = "default_config_version")]
    config_version: u32,
    active_user_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default = "default_config_version")]
    pub config_version: u32,
    pub group: String,
    pub user_id: Option<String>,
    pub device_id: String,
    pub name: String,
    pub server_address: String,
    pub stun_server: Vec<String>,
    pub mtu: Option<u32>,
    pub tcp: bool,
    pub ip: Option<String>,
    pub use_channel: String,
    pub cipher_model: Option<String>,
    pub punch_model: String,
    pub ports: Option<Vec<u16>>,
    pub latency_first: bool,
    pub p2p_heartbeat_interval_sec: u64,
    pub p2p_route_idle_timeout_sec: u64,
    pub device_name: Option<String>,
    pub packet_loss: Option<f64>,
    pub packet_delay: u32,
    #[cfg(feature = "port_mapping")]
    pub mapping: Vec<String>,
    pub compressor: Option<String>,
    pub disable_stats: bool,
    pub local_dev: Option<String>,
    pub exit_node: ExitNodeFileConfig,
    pub traffic_policy: TrafficPolicyFileConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ExitNodeFileConfig {
    pub enabled: bool,
    pub egress_interface: Option<String>,
    pub client_active: bool,
    pub selected_device_id: Option<String>,
    pub tun_name: Option<String>,
    pub route_excludes: Vec<String>,
    pub applied_route_excludes: Vec<String>,
    pub original_dns: Vec<OriginalDnsServiceFileConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficPolicyFileConfig {
    /// The private policy itself is configured by the service argument. This
    /// state only records DNS changes that must be undone after stop/crash.
    pub dns_active: bool,
    pub tun_name: Option<String>,
    pub original_dns: Vec<OriginalDnsServiceFileConfig>,
    /// Upstream resolver addresses captured before policy DNS is redirected
    /// to SDL. They let an explicit policy `local` decision avoid looping
    /// through the SDL DNS service.
    pub local_resolvers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default, deny_unknown_fields)]
pub struct OriginalDnsServiceFileConfig {
    pub service: String,
    pub restore_servers: Vec<String>,
    pub restore_metric: Option<u32>,
    pub restore_automatic_metric: Option<bool>,
}

impl Default for FileConfig {
    fn default() -> Self {
        let mut stun_server = Vec::new();
        for x in sdl::core::PUB_STUN {
            stun_server.push(x.to_string());
        }
        Self {
            config_version: default_config_version(),
            group: DEFAULT_SERVICE_GROUP.to_string(),
            user_id: None,
            device_id: get_device_id(),
            name: sdl::core::default_device_name(),
            server_address: DEFAULT_SERVICE_SERVER.to_string(),
            stun_server,
            mtu: None,
            tcp: false,
            ip: None,
            use_channel: "auto".to_string(),
            cipher_model: None,
            punch_model: "all".to_string(),
            ports: Some(vec![DEFAULT_CLIENT_LISTEN_PORT]),
            latency_first: false,
            p2p_heartbeat_interval_sec: 10,
            p2p_route_idle_timeout_sec: 30,
            device_name: None,
            packet_loss: None,
            packet_delay: 0,
            #[cfg(feature = "port_mapping")]
            mapping: vec![],
            compressor: None,
            disable_stats: false,
            local_dev: None,
            exit_node: ExitNodeFileConfig::default(),
            traffic_policy: TrafficPolicyFileConfig::default(),
        }
    }
}

impl FileConfig {
    pub fn normalize_defaults(&mut self) {
        if self
            .ports
            .as_ref()
            .map(|ports| ports.is_empty())
            .unwrap_or(true)
        {
            self.ports = Some(vec![DEFAULT_CLIENT_LISTEN_PORT]);
        }
    }

    pub fn into_runtime_config(self) -> anyhow::Result<Config> {
        let virtual_ip = match self.ip.clone().map(|v| Ipv4Addr::from_str(&v)) {
            None => None,
            Some(r) => Some(r.map_err(|e| anyhow!("ip {:?} error:{}", &self.ip, e))?),
        };
        let cipher_model = if let Some(v) = self.cipher_model.clone() {
            CipherModel::from_str(&v).map_err(|e| anyhow!("{}", e))?
        } else {
            CipherModel::default_runtime()?
        };

        let punch_model = PunchModel::from_str(&self.punch_model).map_err(|e| anyhow!("{}", e))?;
        let use_channel_type =
            UseChannelType::from_str(&self.use_channel).map_err(|e| anyhow!("{}", e))?;
        let compressor = if let Some(compressor) = self.compressor.as_ref() {
            Compressor::from_str(compressor).map_err(|e| anyhow!("{}", e))?
        } else {
            Compressor::None
        };
        #[cfg(not(feature = "port_mapping"))]
        let port_mapping_list: Vec<String> = vec![];
        #[cfg(feature = "port_mapping")]
        let port_mapping_list = self.mapping.clone();
        let config = Config::new(
            self.group,
            self.device_id,
            self.name,
            self.server_address,
            self.stun_server,
            self.mtu,
            virtual_ip,
            cipher_model,
            punch_model,
            self.ports,
            self.latency_first,
            self.p2p_heartbeat_interval_sec,
            self.p2p_route_idle_timeout_sec,
            self.device_name,
            use_channel_type,
            self.packet_loss,
            self.packet_delay,
            port_mapping_list,
            compressor,
            !self.disable_stats,
            self.local_dev,
            None,
            None,
            None,
        )?;

        Ok(config)
    }
}

pub fn saved_config_path() -> std::io::Result<PathBuf> {
    Ok(crate::cli::app_home()?.join("config.json"))
}

fn encode_user_id_for_path(user_id: &str) -> String {
    let mut out = String::new();
    for byte in user_id.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    if out.is_empty() {
        "_".to_string()
    } else {
        out
    }
}

pub fn user_config_path(user_id: &str) -> std::io::Result<PathBuf> {
    let dir = crate::cli::profiles_home()?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    let _ = crate::fs_access::ensure_user_access(&dir, 0o700);
    Ok(dir.join(format!("{}.json", encode_user_id_for_path(user_id))))
}

fn parse_config_str(conf: &str) -> anyhow::Result<FileConfig> {
    let mut conf_value = match serde_yaml::from_str::<serde_yaml::Value>(conf) {
        Ok(val) => val,
        Err(e) => {
            log::error!("serde_yaml::from_str {:?}", e);
            return Err(anyhow!("serde_yaml::from_str {:?}", e));
        }
    };
    if let serde_yaml::Value::Mapping(mapping) = &mut conf_value {
        mapping.remove(serde_yaml::Value::String("cmd".to_string()));
        mapping.remove(serde_yaml::Value::String("in_ips".to_string()));
        mapping.remove(serde_yaml::Value::String("out_ips".to_string()));
        mapping.remove(serde_yaml::Value::String("external_route".to_string()));
        mapping.remove(serde_yaml::Value::String("externalroute".to_string()));
        let exit_node_key = serde_yaml::Value::String("exit_node".to_string());
        if let Some(serde_yaml::Value::Mapping(exit_node)) = mapping.get_mut(&exit_node_key) {
            // `client_dns` was emitted by an unreleased exit-node build. It did
            // not contain restorable DNS state and was replaced by `original_dns`.
            exit_node.remove(serde_yaml::Value::String("client_dns".to_string()));
        }
        if let Some(version) = mapping.get(serde_yaml::Value::String("config_version".to_string()))
        {
            let version = version
                .as_u64()
                .ok_or_else(|| anyhow!("config_version must be an unsigned integer"))?;
            if version != u64::from(FILE_CONFIG_VERSION) {
                return Err(anyhow!(
                    "unsupported config_version {}, expected {}",
                    version,
                    FILE_CONFIG_VERSION
                ));
            }
        }
    }
    let mut file_conf = match serde_yaml::from_value::<FileConfig>(conf_value) {
        Ok(val) => val,
        Err(e) => {
            log::error!("serde_yaml::from_value {:?}", e);
            return Err(anyhow!("serde_yaml::from_value {:?}", e));
        }
    };
    file_conf.normalize_defaults();
    if file_conf.use_channel.trim().eq_ignore_ascii_case("all") {
        file_conf.use_channel = "auto".to_string();
    }
    if file_conf.group.is_empty() {
        return Err(anyhow!("group is_empty"));
    }
    Ok(file_conf)
}

pub fn read_config(file_path: &str) -> anyhow::Result<(Config, FileConfig)> {
    let conf = std::fs::read_to_string(file_path)?;
    let file_conf = parse_config_str(&conf)?;
    let config = file_conf.clone().into_runtime_config()?;
    Ok((config, file_conf))
}

pub fn read_file_config(file_path: &str) -> anyhow::Result<FileConfig> {
    let conf = std::fs::read_to_string(file_path)?;
    parse_config_str(&conf)
}

pub fn read_saved_config() -> anyhow::Result<Option<(Config, FileConfig)>> {
    let Some(file_conf) = read_saved_file_config()? else {
        return Ok(None);
    };
    let config = file_conf.clone().into_runtime_config()?;
    Ok(Some((config, file_conf)))
}

pub fn read_saved_file_config() -> anyhow::Result<Option<FileConfig>> {
    let path = saved_config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)?;
    if let Ok(active_config) = serde_yaml::from_str::<ActiveConfig>(&contents) {
        if active_config.config_version != FILE_CONFIG_VERSION {
            return Err(anyhow!(
                "unsupported config_version {}, expected {}",
                active_config.config_version,
                FILE_CONFIG_VERSION
            ));
        }
        let user_id = active_config.active_user_id.trim();
        if user_id.is_empty() {
            return Err(anyhow!("active_user_id cannot be empty"));
        }
        let mut file_conf = match read_user_file_config(user_id)? {
            Some(saved) => saved,
            None => FileConfig::default(),
        };
        file_conf.user_id = Some(user_id.to_string());
        write_user_config(user_id, &file_conf)?;
        return Ok(Some(file_conf));
    }

    let file_conf = read_file_config(
        path.to_str()
            .ok_or_else(|| anyhow!("invalid config path"))?,
    )?;
    if let Some(user_id) = file_conf.user_id.as_deref() {
        write_user_config(user_id, &file_conf)?;
        write_active_user_id(user_id)?;
    }
    Ok(Some(file_conf))
}

pub fn write_active_user_id(user_id: &str) -> anyhow::Result<()> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err(anyhow!("active_user_id cannot be empty"));
    }
    let path = saved_config_path()?;
    let contents = serde_json::to_string_pretty(&ActiveConfig {
        config_version: FILE_CONFIG_VERSION,
        active_user_id: user_id.to_string(),
    })?;
    std::fs::write(&path, contents)?;
    crate::fs_access::ensure_user_access(&path, 0o600)?;
    Ok(())
}

pub fn write_saved_config(file_conf: &FileConfig) -> anyhow::Result<()> {
    if let Some(user_id) = file_conf.user_id.as_deref() {
        write_user_config(user_id, file_conf)?;
        write_active_user_id(user_id)?;
        return Ok(());
    }

    let path = saved_config_path()?;
    let contents = serde_json::to_string_pretty(file_conf)?;
    std::fs::write(&path, contents)?;
    crate::fs_access::ensure_user_access(&path, 0o600)?;
    Ok(())
}

pub fn read_user_config(user_id: &str) -> anyhow::Result<Option<(Config, FileConfig)>> {
    let Some(file_conf) = read_user_file_config(user_id)? else {
        return Ok(None);
    };
    let config = file_conf.clone().into_runtime_config()?;
    Ok(Some((config, file_conf)))
}

pub fn read_user_file_config(user_id: &str) -> anyhow::Result<Option<FileConfig>> {
    let path = user_config_path(user_id)?;
    if !path.exists() {
        return Ok(None);
    }
    read_file_config(
        path.to_str()
            .ok_or_else(|| anyhow!("invalid config path"))?,
    )
    .map(Some)
}

pub fn write_user_config(user_id: &str, file_conf: &FileConfig) -> anyhow::Result<()> {
    let path = user_config_path(user_id)?;
    let mut file_conf = file_conf.clone();
    file_conf.user_id = Some(user_id.to_string());
    let contents = serde_json::to_string_pretty(&file_conf)?;
    std::fs::write(&path, contents)?;
    crate::fs_access::ensure_user_access(&path, 0o600)?;
    Ok(())
}

pub fn save_current_user_config(file_conf: &FileConfig) -> anyhow::Result<()> {
    if let Some(user_id) = file_conf.user_id.as_deref() {
        write_user_config(user_id, file_conf)?;
    }
    Ok(())
}

pub fn switch_saved_config_to_user(user_id: &str) -> anyhow::Result<FileConfig> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err(anyhow!("user_id cannot be empty"));
    }

    let mut next = match read_user_config(user_id)? {
        Some((_, saved)) => saved,
        None => FileConfig::default(),
    };
    next.user_id = Some(user_id.to_string());
    write_user_config(user_id, &next)?;
    write_active_user_id(user_id)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::{
        encode_user_id_for_path, read_config, FileConfig, DEFAULT_CLIENT_LISTEN_PORT,
        DEFAULT_SERVICE_GROUP, DEFAULT_SERVICE_SERVER, FILE_CONFIG_VERSION,
    };
    use std::fs;

    fn write_temp_config(contents: &str, suffix: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sdl-cli-file-config-{}-{}.yaml",
            std::process::id(),
            suffix
        ));
        fs::write(&path, contents).expect("write temp config");
        path
    }

    #[test]
    fn read_config_accepts_group_field() {
        let path = write_temp_config(
            r#"
group: default.ms.net
device_id: dev-1
name: test-node
server_address: https://control.middlescale.net/control
"#,
            "group",
        );
        let (config, _) = read_config(path.to_str().unwrap()).expect("group config should parse");
        assert_eq!(config.token, "default.ms.net");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn default_config_uses_group_defaults() {
        let file_conf = FileConfig::default();
        assert_eq!(file_conf.config_version, FILE_CONFIG_VERSION);
        assert_eq!(file_conf.group, DEFAULT_SERVICE_GROUP);
        assert_eq!(file_conf.user_id, None);
        assert_eq!(file_conf.server_address, DEFAULT_SERVICE_SERVER);
        assert_eq!(file_conf.use_channel, "auto");
        assert_eq!(file_conf.ports, Some(vec![29873]));
        assert_eq!(file_conf.p2p_heartbeat_interval_sec, 10);
        assert_eq!(file_conf.p2p_route_idle_timeout_sec, 30);
    }

    #[test]
    fn read_config_normalizes_legacy_all_channel_to_auto() {
        let path = write_temp_config(
            r#"
group: user.ms.net
device_id: dev-user
name: user-node
server_address: https://control.middlescale.net/control
use_channel: all
"#,
            "legacy-channel-all",
        );
        let (_, file_conf) = read_config(path.to_str().unwrap()).expect("legacy all should parse");
        assert_eq!(file_conf.use_channel, "auto");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_config_accepts_user_id_field_without_auth_ticket() {
        let path = write_temp_config(
            r#"
group: user.ms.net
user_id: sdl-user-1
device_id: dev-user
name: user-node
server_address: https://control.middlescale.net/control
"#,
            "user-id",
        );
        let (config, file_conf) =
            read_config(path.to_str().unwrap()).expect("user_id config should parse");
        assert_eq!(file_conf.user_id.as_deref(), Some("sdl-user-1"));
        assert_eq!(config.auth_user_id, None);
        assert_eq!(config.auth_group, None);
        assert_eq!(config.auth_ticket, None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn encode_user_id_for_path_keeps_common_id_chars() {
        assert_eq!(
            encode_user_id_for_path("sdl-user_1.ms.net"),
            "sdl-user_1.ms.net"
        );
        assert_eq!(
            encode_user_id_for_path("user/name@example.com"),
            "user%2Fname%40example.com"
        );
    }

    #[test]
    fn switching_new_user_starts_from_default_not_current_config() {
        let mut current = FileConfig::default();
        current.user_id = Some("sdl-current".to_string());
        current.group = "custom.ms.net".to_string();
        current.name = "custom-node".to_string();

        let mut next = match None::<FileConfig> {
            Some(saved) => saved,
            None => FileConfig::default(),
        };
        next.user_id = Some("sdl-next".to_string());

        assert_eq!(next.user_id.as_deref(), Some("sdl-next"));
        assert_eq!(next.group, DEFAULT_SERVICE_GROUP);
        assert_ne!(next.group, current.group);
        assert_ne!(next.name, current.name);
    }

    #[test]
    fn read_config_accepts_legacy_file_without_config_version() {
        let path = write_temp_config(
            r#"
group: default.ms.net
device_id: dev-legacy
name: legacy-node
server_address: https://control.middlescale.net/control
"#,
            "legacy-no-version",
        );
        let (_, file_conf) =
            read_config(path.to_str().unwrap()).expect("legacy config should parse");
        assert_eq!(file_conf.config_version, FILE_CONFIG_VERSION);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_config_fills_missing_ports_with_default_listen_port() {
        let path = write_temp_config(
            r#"
group: default.ms.net
device_id: dev-missing-ports
name: missing-ports-node
server_address: https://control.middlescale.net/control
"#,
            "missing-ports",
        );
        let (config, file_conf) =
            read_config(path.to_str().unwrap()).expect("config without ports should parse");
        assert_eq!(file_conf.ports, Some(vec![DEFAULT_CLIENT_LISTEN_PORT]));
        assert_eq!(config.ports, Some(vec![DEFAULT_CLIENT_LISTEN_PORT]));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_config_ignores_removed_legacy_route_fields() {
        let path = write_temp_config(
            r#"
config_version: 2
group: default.ms.net
device_id: dev-legacy-routes
name: legacy-routes-node
server_address: https://control.middlescale.net/control
in_ips: []
out_ips: []
external_route: []
externalroute: []
"#,
            "legacy-route-fields",
        );
        let (_, file_conf) = read_config(path.to_str().unwrap())
            .expect("config with removed legacy route fields should parse");
        assert_eq!(file_conf.config_version, FILE_CONFIG_VERSION);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_config_ignores_removed_exit_node_client_dns_field() {
        let path = write_temp_config(
            r#"
config_version: 2
group: default.ms.net
device_id: dev-legacy-dns
name: legacy-dns-node
server_address: https://control.middlescale.net/control
exit_node:
  client_dns: null
"#,
            "legacy-exit-node-client-dns",
        );
        let (_, file_conf) = read_config(path.to_str().unwrap())
            .expect("config with removed exit-node client_dns should parse");
        assert!(file_conf.exit_node.original_dns.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_config_rejects_previous_config_version() {
        let path = write_temp_config(
            r#"
config_version: 1
group: default.ms.net
device_id: dev-v1
name: legacy-node
server_address: https://control.middlescale.net/control
"#,
            "previous-version",
        );
        let err = read_config(path.to_str().unwrap()).expect_err("version 1 config should fail");
        assert!(err
            .to_string()
            .contains("unsupported config_version 1, expected 2"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn into_runtime_config_rejects_idle_timeout_not_greater_than_heartbeat() {
        let mut file_conf = FileConfig::default();
        file_conf.p2p_heartbeat_interval_sec = 10;
        file_conf.p2p_route_idle_timeout_sec = 10;
        let err = file_conf
            .into_runtime_config()
            .expect_err("idle timeout must be greater than heartbeat");
        assert!(err.to_string().contains(
            "p2p_route_idle_timeout_sec must be greater than p2p_heartbeat_interval_sec"
        ));
    }

    #[test]
    fn into_runtime_config_rejects_cipher_model_none() {
        let mut file_conf = FileConfig::default();
        file_conf.cipher_model = Some("none".to_string());

        let err = file_conf
            .into_runtime_config()
            .expect_err("cipher_model=none should be rejected");

        assert!(err.to_string().contains("not match 'none'"));
    }

    #[test]
    fn read_config_rejects_legacy_token_alias() {
        let path = write_temp_config(
            r#"
token: default.ms.net
device_id: dev-2
name: test-node
server_address: https://control.middlescale.net/control
"#,
            "token",
        );
        let err = read_config(path.to_str().unwrap()).expect_err("legacy token config should fail");
        assert!(err.to_string().contains("unknown field `token`"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_config_rejects_legacy_dns_field() {
        let path = write_temp_config(
            r#"
group: default.ms.net
device_id: dev-3
name: test-node
server_address: https://control.middlescale.net/control
dns:
  - 223.5.5.5
"#,
            "dns",
        );
        let err = read_config(path.to_str().unwrap()).expect_err("legacy dns config should fail");
        assert!(err.to_string().contains("unknown field `dns`"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_config_ignores_legacy_cmd_field() {
        let path = write_temp_config(
            r#"
group: default.ms.net
device_id: dev-4
name: test-node
server_address: https://control.middlescale.net/control
cmd: true
"#,
            "legacy-cmd",
        );
        let (config, file_conf) =
            read_config(path.to_str().unwrap()).expect("legacy cmd config should parse");
        assert_eq!(config.token, DEFAULT_SERVICE_GROUP);
        assert_eq!(file_conf.group, DEFAULT_SERVICE_GROUP);
        let _ = fs::remove_file(path);
    }
}
