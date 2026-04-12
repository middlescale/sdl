use crate::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};
use crate::command::server::{AuthCommand, CommandHandler, CommandServer};
use crate::command::service_state::{read_service_state, write_service_state, LocalServiceState};
use crate::config::{write_saved_config, FileConfig};
use anyhow::Context;
use console::style;
use sdl::core::{Config, RenameRequestOutcome, Sdl};
use sdl::data_plane::use_channel_type::UseChannelType;
use sdl::{ConnectInfo, ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, SdlCallback};
use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use crate::root_check;

struct ServiceManager {
    config: Mutex<Config>,
    saved_config: Mutex<FileConfig>,
    runtime: Mutex<Option<Arc<Sdl>>>,
}

#[derive(Clone)]
struct ServiceCommandHandler(Arc<ServiceManager>);

impl ServiceManager {
    fn apply_device_name_update(self: &Arc<Self>, applied_name: String) -> anyhow::Result<()> {
        {
            let mut config = self.config.lock().unwrap();
            let mut saved_config = self.saved_config.lock().unwrap();
            if config.name == applied_name && saved_config.name == applied_name {
                return Ok(());
            }
            config.name = applied_name.clone();
            saved_config.name = applied_name;
        }
        self.persist_saved_config();
        let _ = self.stop_service_runtime()?;
        self.resume_service_runtime()?;
        Ok(())
    }

    fn rename_device(self: &Arc<Self>, new_name: &str) -> anyhow::Result<String> {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            anyhow::bail!("name cannot be empty");
        }
        if trimmed.len() > 128 {
            anyhow::bail!("name too long");
        }
        let current_name = self.current_config().name;
        if current_name == trimmed {
            return Ok(format!("device name already set to {}", trimmed));
        }
        let runtime = self.current_runtime()?;
        match runtime.request_device_rename(trimmed.to_string(), Duration::from_secs(10))? {
            RenameRequestOutcome::Applied(applied_name) => {
                self.apply_device_name_update(applied_name.clone())?;
                Ok(format!("device renamed to {}", applied_name))
            }
            RenameRequestOutcome::PendingApproval => Ok(format!(
                "rename request submitted for approval: {}",
                trimmed
            )),
        }
    }

    fn new(config: Config, saved_config: FileConfig) -> Self {
        Self {
            config: Mutex::new(config),
            saved_config: Mutex::new(saved_config),
            runtime: Mutex::new(None),
        }
    }

    fn mutate_state<F>(&self, f: F)
    where
        F: FnOnce(&mut LocalServiceState),
    {
        let mut state = read_service_state().unwrap_or_default();
        f(&mut state);
        if let Err(e) = write_service_state(&state) {
            log::warn!("write service state failed: {:?}", e);
        }
    }

    fn current_config(&self) -> Config {
        self.config.lock().unwrap().clone()
    }

    fn persist_saved_config(&self) {
        let saved_config = self.saved_config.lock().unwrap().clone();
        if let Err(e) = write_saved_config(&saved_config) {
            log::warn!("write saved config failed: {:?}", e);
        }
    }

    fn current_runtime(&self) -> io::Result<Arc<Sdl>> {
        let runtime = self.runtime.lock().unwrap().clone();
        match runtime {
            Some(vnt) if !vnt.is_stopped() => Ok(vnt),
            _ => Err(io::Error::other(
                "service runtime is unavailable, run `sdl resume` or restart `sdl-service`",
            )),
        }
    }

    fn stopped_info(&self) -> Info {
        let config = self.current_config();
        let state = read_service_state().unwrap_or_default();
        let channel_policy = match config.use_channel_type {
            UseChannelType::Relay => "relay".to_string(),
            UseChannelType::P2p => "p2p".to_string(),
            UseChannelType::All => "auto".to_string(),
        };
        #[cfg(feature = "port_mapping")]
        let port_mapping_list = config.port_mapping_list.clone();
        #[cfg(not(feature = "port_mapping"))]
        let port_mapping_list = vec![];
        Info {
            name: config.name,
            device_id: config.device_id.clone(),
            virtual_ip: String::new(),
            virtual_gateway: String::new(),
            virtual_netmask: String::new(),
            gateway_session_status: "stopped".to_string(),
            gateway_endpoint: String::new(),
            gateway_channel: String::new(),
            connect_status: "Stopped".to_string(),
            data_plane_status: "stopped".to_string(),
            auth_pending: state.auth_pending,
            channel_policy,
            last_error: state.last_error,
            relay_server: config.server_address_str,
            nat_type: String::new(),
            public_ips: String::new(),
            local_addr: String::new(),
            ipv6_addr: String::new(),
            port_mapping_list,
            in_ips: config.in_ips,
            out_ips: config.out_ips,
            udp_listen_addr: vec![],
        }
    }

    fn spawn_service_runtime(self: &Arc<Self>) -> anyhow::Result<Arc<Sdl>> {
        if let Some(runtime) = self.runtime.lock().unwrap().clone() {
            if !runtime.is_stopped() {
                self.mutate_state(|state| {
                    state.runtime_running = true;
                    state.runtime_suspended = runtime.is_suspended();
                });
                return Ok(runtime);
            }
        }
        let config = self.current_config();
        let callback = ServiceCallback::new(Arc::downgrade(self));
        let vnt = Arc::new(Sdl::new(config, callback)?);
        *self.runtime.lock().unwrap() = Some(vnt.clone());
        self.mutate_state(|state| {
            state.runtime_running = true;
            state.runtime_suspended = false;
        });
        Ok(vnt)
    }

    fn resume_service_runtime(self: &Arc<Self>) -> anyhow::Result<String> {
        let runtime = self.spawn_service_runtime()?;
        if runtime.is_suspended() {
            runtime.resume()?;
            self.mutate_state(|state| {
                state.runtime_running = true;
                state.runtime_suspended = false;
            });
            self.persist_saved_config();
            Ok("service resumed".to_string())
        } else {
            self.mutate_state(|state| {
                state.runtime_running = true;
                state.runtime_suspended = false;
            });
            self.persist_saved_config();
            Ok("service already resumed".to_string())
        }
    }

    fn suspend_service_runtime(&self) -> anyhow::Result<String> {
        let runtime = self.current_runtime()?;
        if runtime.is_suspended() {
            self.mutate_state(|state| {
                state.runtime_running = true;
                state.runtime_suspended = true;
            });
            return Ok("service already suspended".to_string());
        }
        runtime.suspend()?;
        self.mutate_state(|state| {
            state.runtime_running = true;
            state.runtime_suspended = true;
        });
        Ok("service suspended".to_string())
    }

    fn stop_service_runtime(&self) -> anyhow::Result<String> {
        let runtime = self.runtime.lock().unwrap().take();
        if let Some(vnt) = runtime {
            vnt.stop();
            let _ = vnt.wait_timeout(Duration::from_secs(10));
            self.mutate_state(|state| {
                state.runtime_running = false;
                state.runtime_suspended = false;
            });
            Ok("service stopped".to_string())
        } else {
            self.mutate_state(|state| {
                state.runtime_running = false;
                state.runtime_suspended = false;
            });
            Ok("service already stopped".to_string())
        }
    }

    fn shutdown(&self) {
        if let Err(e) = self.stop_service_runtime() {
            log::warn!("shutdown stop failed: {:?}", e);
        }
    }

    fn record_auth_success(&self) {
        let mut config = self.config.lock().unwrap();
        let saved = self.saved_config.lock().unwrap();
        let authenticated_user_id = config.auth_user_id.clone();
        let authenticated_group = config.auth_group.clone();
        config.auth_ticket = None;
        self.mutate_state(|state| {
            state.runtime_running = true;
            state.runtime_suspended = false;
            state.auth_pending = false;
            state.last_error = None;
            state.authenticated_user_id = authenticated_user_id.clone();
            state.authenticated_group = authenticated_group.clone();
        });
        if let Some(user_id) = authenticated_user_id {
            log::info!("persisting authenticated user_id={}", user_id);
        }
        if let Err(e) = write_saved_config(&saved) {
            log::warn!("write saved config after auth failed: {:?}", e);
        }
    }
}

impl CommandHandler for ServiceCommandHandler {
    fn route(&self) -> io::Result<Vec<RouteItem>> {
        Ok(crate::command::command_route(
            self.0.current_runtime()?.as_ref(),
        ))
    }

    fn list(&self) -> io::Result<Vec<DeviceItem>> {
        Ok(crate::command::command_list(
            self.0.current_runtime()?.as_ref(),
        ))
    }

    fn info(&self) -> io::Result<Info> {
        match self.0.current_runtime() {
            Ok(vnt) => {
                let mut info = crate::command::command_info(vnt.as_ref());
                if vnt.is_suspended() {
                    info.connect_status = "Suspended".to_string();
                }
                Ok(info)
            }
            Err(_) => Ok(self.0.stopped_info()),
        }
    }

    fn chart_a(&self) -> io::Result<ChartA> {
        match self.0.current_runtime() {
            Ok(vnt) => Ok(crate::command::command_chart_a(vnt.as_ref())),
            Err(_) => Ok(ChartA::default()),
        }
    }

    fn chart_b(&self, input: Option<&str>) -> io::Result<ChartB> {
        let vnt = self.0.current_runtime()?;
        let input = input
            .map(|v| v.to_string())
            .unwrap_or_else(|| vnt.current_device().virtual_gateway.to_string());
        Ok(crate::command::command_chart_b(vnt.as_ref(), &input))
    }

    fn resume_runtime(&self) -> io::Result<String> {
        self.0
            .resume_service_runtime()
            .map_err(|e| io::Error::other(format!("resume runtime failed: {e:?}")))
    }

    fn suspend_runtime(&self) -> io::Result<String> {
        self.0
            .suspend_service_runtime()
            .map_err(|e| io::Error::other(format!("suspend runtime failed: {e:?}")))
    }

    fn channel_change(&self, use_channel_type: UseChannelType) -> io::Result<String> {
        self.0.config.lock().unwrap().use_channel_type = use_channel_type;
        self.0.saved_config.lock().unwrap().use_channel = match use_channel_type {
            UseChannelType::Relay => "relay".to_string(),
            UseChannelType::P2p => "p2p".to_string(),
            UseChannelType::All => "all".to_string(),
        };
        if let Ok(vnt) = self.0.current_runtime() {
            vnt.set_use_channel_type(use_channel_type);
        }
        self.0.persist_saved_config();
        Ok(format!(
            "channel policy changed to {}",
            match use_channel_type {
                UseChannelType::Relay => "relay",
                UseChannelType::P2p => "p2p",
                UseChannelType::All => "auto",
            }
        ))
    }

    fn rename(&self, new_name: &str) -> io::Result<String> {
        self.0
            .rename_device(new_name)
            .map_err(|e| io::Error::other(format!("rename failed: {e:?}")))
    }

    fn auth(&self, auth: AuthCommand) -> io::Result<String> {
        {
            let mut config = self.0.config.lock().unwrap();
            config.auth_user_id = Some(auth.user_id.clone());
            config.auth_group = Some(auth.group.clone());
            config.auth_ticket = Some(auth.ticket.clone());
        }
        let vnt = self.0.current_runtime()?;
        vnt.request_device_auth(auth.user_id, auth.group, auth.ticket)
            .map(|_| "device auth request submitted to local service".to_string())
            .map_err(|e| io::Error::other(format!("auth failed: {e:?}")))
    }
}

#[derive(Clone)]
struct ServiceCallback {
    manager: Weak<ServiceManager>,
}

impl ServiceCallback {
    fn new(manager: Weak<ServiceManager>) -> Self {
        Self { manager }
    }

    fn mutate_state<F>(&self, f: F)
    where
        F: FnOnce(&mut LocalServiceState),
    {
        if let Some(manager) = self.manager.upgrade() {
            manager.mutate_state(f);
        }
    }

    fn clear_error_state(&self) {
        self.mutate_state(|state| {
            state.runtime_running = true;
            state.runtime_suspended = false;
            state.auth_pending = false;
            state.last_error = None;
        });
    }

    fn is_auth_pending_message(message: &str) -> bool {
        let message = message.to_ascii_lowercase();
        message.contains("auth check failed")
            || message.contains("not_auth")
            || message.contains("auth_expired")
            || message.contains("reauth_required")
            || message.contains("device_key_mismatch")
    }

    fn request_runtime_stop(&self) {
        if let Some(manager) = self.manager.upgrade() {
            std::thread::spawn(move || {
                if let Err(e) = manager.stop_service_runtime() {
                    log::warn!("stop runtime after callback error failed: {:?}", e);
                }
            });
        }
    }

    fn request_runtime_name_refresh(&self, new_name: String) {
        if let Some(manager) = self.manager.upgrade() {
            std::thread::spawn(move || {
                if let Err(e) = manager.apply_device_name_update(new_name.clone()) {
                    log::warn!(
                        "apply device name update failed new_name={} err={:?}",
                        new_name,
                        e
                    );
                }
            });
        }
    }
}

impl SdlCallback for ServiceCallback {
    fn success(&self) {
        self.clear_error_state();
        if let Some(manager) = self.manager.upgrade() {
            let current = manager.current_config();
            if current.auth_user_id.is_some() && current.auth_group.is_some() {
                manager.record_auth_success();
            }
        }
        println!(" {} ", style("====== Connect Successfully ======").green())
    }

    fn create_tun(&self, info: sdl::DeviceInfo) {
        println!("create_tun {}", info)
    }

    fn connect(&self, info: ConnectInfo) {
        println!("connect {}", info)
    }

    fn handshake(&self, info: HandshakeInfo) -> bool {
        println!("handshake {}", info);
        true
    }

    fn register(&self, info: RegisterInfo) -> bool {
        self.clear_error_state();
        println!("register {}", style(info).green());
        true
    }

    fn device_renamed(&self, new_name: String) {
        println!(
            "{}",
            style(format!("device renamed to {}", new_name)).green()
        );
        self.request_runtime_name_refresh(new_name);
    }

    fn error(&self, info: ErrorInfo) {
        let message = format!("{}", info);
        let auth_pending = Self::is_auth_pending_message(&message);
        if auth_pending {
            log::warn!("auth pending {:?}", info);
        } else {
            log::error!("error {:?}", info);
        }
        self.mutate_state(|state| {
            state.runtime_running = true;
            state.runtime_suspended = false;
            state.auth_pending = auth_pending;
            state.last_error = if auth_pending {
                None
            } else {
                Some(message.clone())
            };
        });
        if auth_pending {
            println!(
                "{}",
                style(format!(
                    "auth pending: {}. run `sdl auth ...` to authenticate this device",
                    message
                ))
                .yellow()
            );
            return;
        }
        println!("{}", style(format!("error {}", info)).red());
        match info.code {
            ErrorType::TokenError
            | ErrorType::AddressExhausted
            | ErrorType::IpAlreadyExists
            | ErrorType::InvalidIp
            | ErrorType::LocalIpExists
            | ErrorType::FailedToCreateDevice => {
                self.request_runtime_stop();
            }
            _ => {}
        }
    }

    fn stop(&self) {
        self.mutate_state(|state| {
            state.runtime_running = false;
            state.runtime_suspended = false;
        });
        println!("stopped");
    }
}

pub fn run_service_from_args(args: Vec<String>) -> i32 {
    let (config, saved_config) = match crate::cli::parse_args_config_from(args) {
        Ok(rs) => match rs {
            Some(rs) => rs,
            None => return 0,
        },
        Err(e) => {
            log::error!("parse error={:?}", e);
            println!("{}", style(format!("Error {:?}", e)).red());
            return 1;
        }
    };
    run_service(config, saved_config)
}

pub fn run_service(config: Config, saved_config: FileConfig) -> i32 {
    if !root_check::is_app_elevated() {
        println!("Please run sdl-service with administrator or root privileges");
        return 1;
    }
    let build_version = crate::build_version_string();
    println!("sdl-service version {}", build_version);
    log::info!("sdl-service version {}", build_version);
    let manager = Arc::new(ServiceManager::new(config.clone(), saved_config));
    manager.mutate_state(|state| {
        state.runtime_running = false;
        state.runtime_suspended = false;
        state.auth_pending = false;
        state.last_error = None;
    });
    #[cfg(feature = "port_mapping")]
    for (is_tcp, addr, dest) in config.port_mapping_list.iter() {
        if *is_tcp {
            println!("TCP port mapping {}->{}", addr, dest)
        } else {
            println!("UDP port mapping {}->{}", addr, dest)
        }
    }
    if let Err(e) = manager
        .clone()
        .resume_service_runtime()
        .context("initial service start failed")
    {
        log::error!("sdl create error {:?}", e);
        println!("error: {:?}", e);
        return 1;
    }

    #[cfg(feature = "command")]
    {
        let manager_c = manager.clone();
        std::thread::Builder::new()
            .name("CommandServer".into())
            .spawn(move || {
                if let Err(e) = CommandServer::new().start(ServiceCommandHandler(manager_c)) {
                    log::warn!("cmd:{:?}", e);
                }
            })
            .expect("CommandServer");
    }

    let (shutdown_sender, shutdown_receiver) = std::sync::mpsc::channel::<()>();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let manager_c = manager.clone();
        let shutdown_sender = shutdown_sender.clone();
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ])
        .unwrap();
        let handle = signals.handle();
        std::thread::spawn(move || {
            for sig in signals.forever() {
                match sig {
                    signal_hook::consts::SIGINT | signal_hook::consts::SIGTERM => {
                        println!("Received SIGINT, {}", sig);
                        manager_c.shutdown();
                        let _ = shutdown_sender.send(());
                        handle.close();
                        break;
                    }
                    _ => {}
                }
            }
        });
    }

    let _ = shutdown_receiver.recv();
    manager.shutdown();
    0
}
