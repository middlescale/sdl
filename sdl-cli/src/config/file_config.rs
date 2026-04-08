use anyhow::anyhow;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::args_parse;
use crate::config::get_device_id;
use sdl::cipher::CipherModel;
use sdl::compression::Compressor;
use sdl::core::Config;
use sdl::data_plane::use_channel_type::UseChannelType;
use sdl::nat::punch::PunchModel;
use serde::{Deserialize, Serialize};

pub const DEFAULT_SERVICE_GROUP: &str = "default.ms.net";
pub const DEFAULT_SERVICE_SERVER: &str = "https://control.middlescale.net/control";

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    #[cfg(target_os = "windows")]
    pub tap: bool,
    pub group: String,
    pub device_id: String,
    pub name: String,
    pub server_address: String,
    pub stun_server: Vec<String>,
    pub in_ips: Vec<String>,
    pub out_ips: Vec<String>,
    pub mtu: Option<u32>,
    pub tcp: bool,
    pub ip: Option<String>,
    pub use_channel: String,
    pub cipher_model: Option<String>,
    pub punch_model: String,
    pub ports: Option<Vec<u16>>,
    pub latency_first: bool,
    pub device_name: Option<String>,
    pub packet_loss: Option<f64>,
    pub packet_delay: u32,
    #[cfg(feature = "port_mapping")]
    pub mapping: Vec<String>,
    pub compressor: Option<String>,
    pub disable_stats: bool,
    pub local_dev: Option<String>,
}

impl Default for FileConfig {
    fn default() -> Self {
        let mut stun_server = Vec::new();
        for x in sdl::core::PUB_STUN {
            stun_server.push(x.to_string());
        }
        Self {
            #[cfg(target_os = "windows")]
            tap: false,
            group: DEFAULT_SERVICE_GROUP.to_string(),
            device_id: get_device_id(),
            name: gethostname::gethostname()
                .to_str()
                .unwrap_or("UnknownName")
                .to_string(),
            server_address: DEFAULT_SERVICE_SERVER.to_string(),
            stun_server,
            in_ips: vec![],
            out_ips: vec![],
            mtu: None,
            tcp: false,
            ip: None,
            use_channel: "all".to_string(),
            cipher_model: None,
            punch_model: "all".to_string(),
            ports: None,
            latency_first: false,
            device_name: None,
            packet_loss: None,
            packet_delay: 0,
            #[cfg(feature = "port_mapping")]
            mapping: vec![],
            compressor: None,
            disable_stats: false,
            local_dev: None,
        }
    }
}

impl FileConfig {
    pub fn into_runtime_config(self) -> anyhow::Result<Config> {
        let in_ips = match args_parse::ips_parse(&self.in_ips) {
            Ok(in_ips) => in_ips,
            Err(e) => {
                return Err(anyhow!("in_ips {:?} error:{}", &self.in_ips, e));
            }
        };
        let out_ips = match args_parse::out_ips_parse(&self.out_ips) {
            Ok(out_ips) => out_ips,
            Err(e) => {
                return Err(anyhow!("out_ips {:?} error:{}", &self.out_ips, e));
            }
        };
        let virtual_ip = match self.ip.clone().map(|v| Ipv4Addr::from_str(&v)) {
            None => None,
            Some(r) => Some(r.map_err(|e| anyhow!("ip {:?} error:{}", &self.ip, e))?),
        };
        let cipher_model = if let Some(v) = self.cipher_model.clone() {
            CipherModel::from_str(&v).map_err(|e| anyhow!("{}", e))?
        } else {
            #[cfg(not(feature = "aes_gcm"))]
            {
                CipherModel::None
            }
            #[cfg(feature = "aes_gcm")]
            {
                CipherModel::AesGcm
            }
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
            #[cfg(target_os = "windows")]
            self.tap,
            self.group,
            self.device_id,
            self.name,
            self.server_address,
            self.stun_server,
            in_ips,
            out_ips,
            self.mtu,
            virtual_ip,
            cipher_model,
            punch_model,
            self.ports,
            self.latency_first,
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
    }
    let file_conf = match serde_yaml::from_value::<FileConfig>(conf_value) {
        Ok(val) => val,
        Err(e) => {
            log::error!("serde_yaml::from_value {:?}", e);
            return Err(anyhow!("serde_yaml::from_value {:?}", e));
        }
    };
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

pub fn read_config_from_path(path: &Path) -> anyhow::Result<(Config, FileConfig)> {
    read_config(
        path.to_str()
            .ok_or_else(|| anyhow!("invalid config path"))?,
    )
}

pub fn read_saved_config() -> anyhow::Result<Option<(Config, FileConfig)>> {
    let path = saved_config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    read_config_from_path(&path).map(Some)
}

pub fn write_saved_config(file_conf: &FileConfig) -> anyhow::Result<()> {
    let path = saved_config_path()?;
    let contents = serde_json::to_string_pretty(file_conf)?;
    std::fs::write(path, contents)?;
    crate::fs_access::ensure_user_access(&saved_config_path()?, 0o600)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_config, FileConfig, DEFAULT_SERVICE_GROUP, DEFAULT_SERVICE_SERVER};
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
        assert_eq!(file_conf.group, DEFAULT_SERVICE_GROUP);
        assert_eq!(file_conf.server_address, DEFAULT_SERVICE_SERVER);
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
