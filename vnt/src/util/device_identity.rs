use anyhow::{anyhow, Context};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::PathBuf;

const DEVICE_KEY_LEN: usize = 32;
const DEVICE_KEY_ALG: &str = "ed25519";

pub fn device_key_alg() -> &'static str {
    DEVICE_KEY_ALG
}

pub fn load_or_create_device_public_key(device_id: &str) -> anyhow::Result<Vec<u8>> {
    let key_path = resolve_device_key_path(device_id)?;
    let signing_key = if key_path.exists() {
        let key_bytes = std::fs::read(&key_path)
            .with_context(|| format!("read device key failed: {:?}", key_path))?;
        let key_bytes: [u8; DEVICE_KEY_LEN] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid device key bytes"))?;
        SigningKey::from_bytes(&key_bytes)
    } else {
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create device key parent dir failed: {:?}", parent))?;
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        std::fs::write(&key_path, signing_key.to_bytes())
            .with_context(|| format!("write device key failed: {:?}", key_path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
        signing_key
    };
    Ok(signing_key.verifying_key().to_bytes().to_vec())
}

fn resolve_device_key_path(device_id: &str) -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("VNT_DEVICE_KEY_PATH") {
        return Ok(PathBuf::from(path));
    }
    let safe_device_id: String = device_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let home =
        std::env::var("HOME").context("HOME is not set and VNT_DEVICE_KEY_PATH not provided")?;
    Ok(PathBuf::from(home)
        .join(".vnt")
        .join("identity")
        .join(format!("{safe_device_id}.key")))
}
