use serde::{Deserialize, Serialize};
use std::io;
use std::io::Write;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LocalServiceState {
    pub runtime_running: bool,
    pub auth_pending: bool,
    pub last_error: Option<String>,
}

fn state_path() -> io::Result<std::path::PathBuf> {
    Ok(crate::cli::app_home()?.join("service-state.json"))
}

pub fn read_service_state() -> io::Result<LocalServiceState> {
    let path = state_path()?;
    if !path.exists() {
        return Ok(LocalServiceState::default());
    }
    let contents = std::fs::read_to_string(path)?;
    serde_json::from_str(&contents)
        .map_err(|e| io::Error::other(format!("service-state parse error: {e}")))
}

pub fn write_service_state(state: &LocalServiceState) -> io::Result<()> {
    let path = state_path()?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(serde_json::to_string_pretty(state).unwrap().as_bytes())?;
    file.sync_all()
}

pub fn clear_service_state() -> io::Result<()> {
    write_service_state(&LocalServiceState::default())
}
