use anyhow::{anyhow, Context};
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand::rngs::OsRng;
use std::path::PathBuf;

const DEVICE_KEY_LEN: usize = 32;
const DEVICE_KEY_ALG: &str = "ed25519";

pub fn device_key_alg() -> &'static str {
    DEVICE_KEY_ALG
}

pub fn load_or_create_device_public_key(device_id: &str) -> anyhow::Result<Vec<u8>> {
    Ok(load_or_create_device_signing_key(device_id)?
        .verifying_key()
        .to_bytes()
        .to_vec())
}

pub fn load_or_create_device_signing_key(device_id: &str) -> anyhow::Result<SigningKey> {
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
    Ok(signing_key)
}

pub fn sign_device_payload(device_id: &str, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let signing_key = load_or_create_device_signing_key(device_id)?;
    let signature: Signature = signing_key.sign(payload);
    Ok(signature.to_bytes().to_vec())
}

fn resolve_device_key_path(device_id: &str) -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("SDL_DEVICE_KEY_PATH") {
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
    let root = resolve_device_key_root(|name| std::env::var(name), cfg!(target_os = "windows"))?;
    Ok(root.join("identity").join(format!("{safe_device_id}.key")))
}

fn resolve_device_key_root<F>(mut get_env: F, is_windows: bool) -> anyhow::Result<PathBuf>
where
    F: FnMut(&str) -> Result<String, std::env::VarError>,
{
    if let Ok(home) = get_env("HOME") {
        return Ok(PathBuf::from(home).join(".sdl"));
    }
    if is_windows {
        if let Ok(profile) = get_env("USERPROFILE") {
            return Ok(PathBuf::from(profile).join(".sdl"));
        }
        if let (Ok(home_drive), Ok(home_path)) = (get_env("HOMEDRIVE"), get_env("HOMEPATH")) {
            return Ok(PathBuf::from(format!("{home_drive}{home_path}")).join(".sdl"));
        }
        if let Ok(local_app_data) = get_env("LOCALAPPDATA") {
            return Ok(PathBuf::from(local_app_data).join("sdl"));
        }
        if let Ok(app_data) = get_env("APPDATA") {
            return Ok(PathBuf::from(app_data).join("sdl"));
        }
        return Err(anyhow!(
            "HOME/USERPROFILE/HOMEDRIVE+HOMEPATH/LOCALAPPDATA/APPDATA are not set and SDL_DEVICE_KEY_PATH not provided"
        ));
    }
    Err(anyhow!(
        "HOME is not set and SDL_DEVICE_KEY_PATH not provided"
    ))
}

#[cfg(test)]
mod tests {
    use super::resolve_device_key_root;
    use std::env::VarError;
    use std::path::PathBuf;

    #[test]
    fn resolve_device_key_root_uses_home_on_unix() {
        let root = resolve_device_key_root(
            |name| match name {
                "HOME" => Ok("/home/tester".into()),
                _ => Err(VarError::NotPresent),
            },
            false,
        )
        .expect("resolve root");
        assert_eq!(root, PathBuf::from("/home/tester/.sdl"));
    }

    #[test]
    fn resolve_device_key_root_uses_userprofile_on_windows() {
        let root = resolve_device_key_root(
            |name| match name {
                "USERPROFILE" => Ok(r"C:\Users\tester".into()),
                _ => Err(VarError::NotPresent),
            },
            true,
        )
        .expect("resolve root");
        assert_eq!(root, PathBuf::from(r"C:\Users\tester").join(".sdl"));
    }

    #[test]
    fn resolve_device_key_root_falls_back_to_appdata_on_windows() {
        let root = resolve_device_key_root(
            |name| match name {
                "APPDATA" => Ok(r"C:\Users\tester\AppData\Roaming".into()),
                _ => Err(VarError::NotPresent),
            },
            true,
        )
        .expect("resolve root");
        assert_eq!(
            root,
            PathBuf::from(r"C:\Users\tester\AppData\Roaming").join("sdl")
        );
    }
}
