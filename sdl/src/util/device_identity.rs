use anyhow::{anyhow, Context};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineSessionKeyMaterial {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl OnlineSessionKeyMaterial {
    pub fn generate() -> Self {
        let mut private_key = [0u8; 32];
        OsRng.fill_bytes(&mut private_key);
        let public_key = MontgomeryPoint::mul_base_clamped(private_key).to_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

pub fn derive_peer_session_key(
    online_session_key: &OnlineSessionKeyMaterial,
    peer_online_kx_pub: &[u8],
    group: &str,
) -> anyhow::Result<[u8; 32]> {
    let peer_pub_key: [u8; 32] = peer_online_kx_pub
        .try_into()
        .map_err(|_| anyhow!("invalid peer online key length"))?;
    let peer_point = MontgomeryPoint(peer_pub_key);

    let shared = peer_point
        .mul_clamped(online_session_key.private_key)
        .to_bytes();
    if shared.iter().all(|byte| *byte == 0) {
        return Err(anyhow!("invalid peer shared secret"));
    }

    let local_pub_key = online_session_key.public_key();
    let (first_pub, second_pub) = if local_pub_key.as_slice() <= peer_online_kx_pub {
        (local_pub_key.as_slice(), peer_online_kx_pub)
    } else {
        (peer_online_kx_pub, local_pub_key.as_slice())
    };

    let mut hasher = Sha256::new();
    hasher.update(b"sdl-peer-session-v2");
    hasher.update((group.len() as u32).to_be_bytes());
    hasher.update(group.as_bytes());
    hasher.update(shared);
    hasher.update(first_pub);
    hasher.update(second_pub);
    Ok(hasher.finalize().into())
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
    use super::{derive_peer_session_key, resolve_device_key_root, OnlineSessionKeyMaterial};
    use std::env::VarError;
    use std::path::PathBuf;

    #[test]
    fn derive_peer_session_key_is_symmetric() {
        let alice = OnlineSessionKeyMaterial::generate();
        let bob = OnlineSessionKeyMaterial::generate();
        let token = "ms.net";

        let alice_key = derive_peer_session_key(&alice, &bob.public_key(), token)
            .expect("derive alice session key");
        let bob_key = derive_peer_session_key(&bob, &alice.public_key(), token)
            .expect("derive bob session key");

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn online_session_key_is_random_per_generation() {
        let first = OnlineSessionKeyMaterial::generate();
        let second = OnlineSessionKeyMaterial::generate();
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn derive_peer_session_key_rejects_invalid_peer_key_length() {
        let alice = OnlineSessionKeyMaterial::generate();
        let err = derive_peer_session_key(&alice, &[1, 2, 3], "ms.net").unwrap_err();
        assert!(err.to_string().contains("invalid peer online key length"));
    }

    #[test]
    fn derive_peer_session_key_changes_with_group() {
        let alice = OnlineSessionKeyMaterial::generate();
        let bob = OnlineSessionKeyMaterial::generate();

        let first = derive_peer_session_key(&alice, &bob.public_key(), "group-a")
            .expect("derive key for group-a");
        let second = derive_peer_session_key(&alice, &bob.public_key(), "group-b")
            .expect("derive key for group-b");

        assert_ne!(first, second);
    }

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
