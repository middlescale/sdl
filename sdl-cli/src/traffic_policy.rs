use anyhow::{bail, Context, Result};
use libloading::Library;
use sdl::core::{
    DnsRouteFlow, DnsRouteObservation, ExitRouteDecision, ExitRouteFlow, ExitRoutePolicy,
};
use std::ffi::{c_char, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const ABI_VERSION: u32 = 2;
const ACTION_LOCAL: u8 = 0;
const ACTION_EXIT_NODE: u8 = 1;

#[repr(C)]
struct PluginDecision {
    action: u8,
    device_id_len: usize,
    device_id: [u8; 256],
}

type AbiVersion = unsafe extern "C" fn() -> u32;
type Create = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type Destroy = unsafe extern "C" fn(*mut c_void);
type DecideIpv4 = unsafe extern "C" fn(*const c_void, u32, *mut PluginDecision) -> bool;
type DecideDns =
    unsafe extern "C" fn(*const c_void, *const c_char, u16, *mut PluginDecision) -> bool;
type ObserveDnsIpv4 =
    unsafe extern "C" fn(*const c_void, *const c_char, *const u32, usize, u32) -> bool;
type LocalIpv4Cidrs = unsafe extern "C" fn(*const c_void) -> *mut c_char;
type StringFree = unsafe extern "C" fn(*mut c_char);

/// Keeps the library loaded for as long as its policy instance may be called.
/// The ABI accepts only plain C values, so the private crate cannot depend on
/// SDL's Rust types or invoke host system commands.
pub struct LoadedTrafficPolicy {
    _library: Library,
    instance: *mut c_void,
    destroy: Destroy,
    decide_ipv4: DecideIpv4,
    decide_dns: DecideDns,
    observe_dns_ipv4: ObserveDnsIpv4,
    local_ipv4_cidrs: LocalIpv4Cidrs,
    string_free: StringFree,
    plugin_path: PathBuf,
}

unsafe impl Send for LoadedTrafficPolicy {}
unsafe impl Sync for LoadedTrafficPolicy {}

impl LoadedTrafficPolicy {
    pub fn load(plugin_path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let plugin_path = plugin_path.as_ref().to_path_buf();
        let config_path = plugin_path
            .parent()
            .context("traffic policy plugin has no parent directory")?
            .join("config.yaml");
        let config_path = CString::new(config_path.to_string_lossy().as_bytes())?;
        let library = unsafe { Library::new(&plugin_path) }
            .with_context(|| format!("load traffic policy plugin {}", plugin_path.display()))?;
        unsafe {
            let abi_version: AbiVersion = *library.get(b"sdl_traffic_policy_abi_version\0")?;
            if abi_version() != ABI_VERSION {
                bail!(
                    "traffic policy plugin ABI {} is incompatible with SDL ABI {}",
                    abi_version(),
                    ABI_VERSION
                );
            }
            let create: Create = *library.get(b"sdl_traffic_policy_create\0")?;
            let instance = create(config_path.as_ptr());
            if instance.is_null() {
                bail!(
                    "traffic policy plugin rejected {}; validate its config and datasets",
                    config_path.to_string_lossy()
                );
            }
            Ok(Arc::new(Self {
                instance,
                destroy: *library.get(b"sdl_traffic_policy_destroy\0")?,
                decide_ipv4: *library.get(b"sdl_traffic_policy_decide_ipv4\0")?,
                decide_dns: *library.get(b"sdl_traffic_policy_decide_dns\0")?,
                observe_dns_ipv4: *library.get(b"sdl_traffic_policy_observe_dns_ipv4\0")?,
                local_ipv4_cidrs: *library.get(b"sdl_traffic_policy_local_ipv4_cidrs\0")?,
                string_free: *library.get(b"sdl_traffic_policy_string_free\0")?,
                _library: library,
                plugin_path,
            }))
        }
    }

    pub fn plugin_path(&self) -> &Path {
        &self.plugin_path
    }

    pub fn local_ipv4_cidrs(&self) -> Result<Vec<String>> {
        let value = unsafe { (self.local_ipv4_cidrs)(self.instance) };
        if value.is_null() {
            bail!("traffic policy plugin did not return local IPv4 CIDRs");
        }
        let text = unsafe { CStr::from_ptr(value) }
            .to_str()
            .context("traffic policy plugin returned non-UTF-8 CIDRs")?
            .to_string();
        unsafe { (self.string_free)(value) };
        Ok(text
            .lines()
            .map(str::trim)
            .filter(|cidr| !cidr.is_empty())
            .map(str::to_string)
            .collect())
    }
}

impl ExitRoutePolicy for LoadedTrafficPolicy {
    fn decide(&self, flow: &ExitRouteFlow) -> ExitRouteDecision {
        let mut output = PluginDecision {
            action: ACTION_LOCAL,
            device_id_len: 0,
            device_id: [0; 256],
        };
        let ok = unsafe {
            (self.decide_ipv4)(
                self.instance,
                u32::from_be_bytes(flow.destination.octets()),
                &mut output,
            )
        };
        if !ok || output.action != ACTION_EXIT_NODE || output.device_id_len > output.device_id.len()
        {
            return ExitRouteDecision::Local;
        }
        match std::str::from_utf8(&output.device_id[..output.device_id_len]) {
            Ok(device_id) if !device_id.trim().is_empty() => {
                ExitRouteDecision::ExitNodeDeviceId(device_id.to_string())
            }
            _ => ExitRouteDecision::Local,
        }
    }

    fn decide_dns(&self, flow: &DnsRouteFlow<'_>) -> Option<ExitRouteDecision> {
        let Ok(domain) = CString::new(flow.domain) else {
            return Some(ExitRouteDecision::Local);
        };
        let mut output = PluginDecision {
            action: ACTION_LOCAL,
            device_id_len: 0,
            device_id: [0; 256],
        };
        let ok = unsafe {
            (self.decide_dns)(self.instance, domain.as_ptr(), flow.query_type, &mut output)
        };
        Some(decision_from_plugin(ok, &output))
    }

    fn observe_dns(&self, observation: &DnsRouteObservation<'_>) {
        let Ok(domain) = CString::new(observation.domain) else {
            return;
        };
        let addresses: Vec<u32> = observation
            .ipv4_addresses
            .iter()
            .map(|address| u32::from_be_bytes(address.octets()))
            .collect();
        unsafe {
            (self.observe_dns_ipv4)(
                self.instance,
                domain.as_ptr(),
                addresses.as_ptr(),
                addresses.len(),
                observation.ttl_secs,
            );
        }
    }
}

fn decision_from_plugin(ok: bool, output: &PluginDecision) -> ExitRouteDecision {
    if !ok || output.action != ACTION_EXIT_NODE || output.device_id_len > output.device_id.len() {
        return ExitRouteDecision::Local;
    }
    match std::str::from_utf8(&output.device_id[..output.device_id_len]) {
        Ok(device_id) if !device_id.trim().is_empty() => {
            ExitRouteDecision::ExitNodeDeviceId(device_id.to_string())
        }
        _ => ExitRouteDecision::Local,
    }
}

impl Drop for LoadedTrafficPolicy {
    fn drop(&mut self) {
        unsafe { (self.destroy)(self.instance) };
    }
}
