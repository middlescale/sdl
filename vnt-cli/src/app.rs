use anyhow::Context;
use common::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};
use common::command::server::{AuthCommand, CommandHandler, CommandServer};
use common::command::service_state::{read_service_state, write_service_state, LocalServiceState};
use console::style;
use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use vnt::core::{Config, Vnt};
use vnt::data_plane::use_channel_type::UseChannelType;
use vnt::{ConnectInfo, ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, VntCallback};

use crate::root_check;

struct ServiceManager {
    config: Mutex<Config>,
    runtime: Mutex<Option<Arc<Vnt>>>,
}

#[derive(Clone)]
struct ServiceCommandHandler(Arc<ServiceManager>);

impl ServiceManager {
    fn new(config: Config) -> Self {
        Self {
            config: Mutex::new(config),
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

    fn current_runtime(&self) -> io::Result<Arc<Vnt>> {
        let runtime = self.runtime.lock().unwrap().clone();
        match runtime {
            Some(vnt) if !vnt.is_stopped() => Ok(vnt),
            _ => Err(io::Error::other(
                "service runtime is stopped, run `vnt start` to resume it",
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
            virtual_ip: String::new(),
            virtual_gateway: String::new(),
            virtual_netmask: String::new(),
            connect_status: "Stopped".to_string(),
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
            tcp_listen_addr: String::new(),
        }
    }

    fn start_service_runtime(self: &Arc<Self>) -> anyhow::Result<String> {
        if let Some(runtime) = self.runtime.lock().unwrap().clone() {
            if !runtime.is_stopped() {
                self.mutate_state(|state| state.runtime_running = true);
                return Ok("service already running".to_string());
            }
        }
        let config = self.current_config();
        let callback = ServiceCallback::new(Arc::downgrade(self));
        let vnt = Arc::new(Vnt::new(config, callback)?);
        *self.runtime.lock().unwrap() = Some(vnt);
        self.mutate_state(|state| {
            state.runtime_running = true;
        });
        Ok("service started".to_string())
    }

    fn stop_service_runtime(&self) -> anyhow::Result<String> {
        let runtime = self.runtime.lock().unwrap().take();
        if let Some(vnt) = runtime {
            vnt.stop();
            let _ = vnt.wait_timeout(Duration::from_secs(10));
            self.mutate_state(|state| state.runtime_running = false);
            Ok("service stopped".to_string())
        } else {
            self.mutate_state(|state| state.runtime_running = false);
            Ok("service already stopped".to_string())
        }
    }

    fn shutdown(&self) {
        if let Err(e) = self.stop_service_runtime() {
            log::warn!("shutdown stop failed: {:?}", e);
        }
    }
}

impl CommandHandler for ServiceCommandHandler {
    fn route(&self) -> io::Result<Vec<RouteItem>> {
        Ok(common::command::command_route(
            self.0.current_runtime()?.as_ref(),
        ))
    }

    fn list(&self) -> io::Result<Vec<DeviceItem>> {
        Ok(common::command::command_list(
            self.0.current_runtime()?.as_ref(),
        ))
    }

    fn info(&self) -> io::Result<Info> {
        match self.0.current_runtime() {
            Ok(vnt) => Ok(common::command::command_info(vnt.as_ref())),
            Err(_) => Ok(self.0.stopped_info()),
        }
    }

    fn chart_a(&self) -> io::Result<ChartA> {
        match self.0.current_runtime() {
            Ok(vnt) => Ok(common::command::command_chart_a(vnt.as_ref())),
            Err(_) => Ok(ChartA::default()),
        }
    }

    fn chart_b(&self, input: Option<&str>) -> io::Result<ChartB> {
        let vnt = self.0.current_runtime()?;
        let input = input
            .map(|v| v.to_string())
            .unwrap_or_else(|| vnt.current_device().virtual_gateway.to_string());
        Ok(common::command::command_chart_b(vnt.as_ref(), &input))
    }

    fn start_runtime(&self) -> io::Result<String> {
        self.0
            .start_service_runtime()
            .map_err(|e| io::Error::other(format!("start runtime failed: {e:?}")))
    }

    fn stop_runtime(&self) -> io::Result<String> {
        self.0
            .stop_service_runtime()
            .map_err(|e| io::Error::other(format!("stop runtime failed: {e:?}")))
    }

    fn channel_change(&self, use_channel_type: UseChannelType) -> io::Result<String> {
        self.0.config.lock().unwrap().use_channel_type = use_channel_type;
        if let Ok(vnt) = self.0.current_runtime() {
            vnt.set_use_channel_type(use_channel_type);
        }
        Ok(format!(
            "channel policy changed to {}",
            match use_channel_type {
                UseChannelType::Relay => "relay",
                UseChannelType::P2p => "p2p",
                UseChannelType::All => "auto",
            }
        ))
    }

    fn auth(&self, auth: AuthCommand) -> io::Result<String> {
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
}

impl VntCallback for ServiceCallback {
    fn success(&self) {
        self.clear_error_state();
        println!(" {} ", style("====== Connect Successfully ======").green())
    }

    fn create_tun(&self, info: vnt::DeviceInfo) {
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

    fn error(&self, info: ErrorInfo) {
        log::error!("error {:?}", info);
        let message = format!("{}", info);
        let auth_pending = Self::is_auth_pending_message(&message);
        self.mutate_state(|state| {
            state.runtime_running = true;
            state.auth_pending = auth_pending;
            state.last_error = Some(message.clone());
        });
        if auth_pending {
            println!(
                "{}",
                style(format!(
                    "auth pending: {}. run `vnt auth ...` to authenticate this device",
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
        self.mutate_state(|state| state.runtime_running = false);
        println!("stopped");
    }
}

pub fn run_service_from_args(args: Vec<String>) -> i32 {
    let (config, show_cmd) = match common::cli::parse_args_config_from(args) {
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
    run_service(config, show_cmd)
}

pub fn run_service(config: Config, show_cmd: bool) -> i32 {
    if !root_check::is_app_elevated() {
        println!("Please run vnt-service with administrator or root privileges");
        return 1;
    }
    let manager = Arc::new(ServiceManager::new(config.clone()));
    manager.mutate_state(|state| {
        state.runtime_running = false;
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
        .start_service_runtime()
        .context("initial service start failed")
    {
        log::error!("vnt create error {:?}", e);
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

    if show_cmd {
        let shutdown_sender = shutdown_sender.clone();
        std::thread::spawn(move || loop {
            let mut cmd = String::new();
            println!(
                "======== input:start,list,info,route,all,stop,chart_a,chart_b[:ip],channel_change:<relay|p2p|auto> ========"
            );
            match std::io::stdin().read_line(&mut cmd) {
                Ok(_) => {
                    let cmd = cmd.trim();
                    if cmd.is_empty() {
                        continue;
                    }
                    if cmd.eq_ignore_ascii_case("exit") || cmd.eq_ignore_ascii_case("quit") {
                        let _ = shutdown_sender.send(());
                        break;
                    }
                    match common::command::client::CommandClient::new() {
                        Ok(mut client) => {
                            let result = if cmd == "start" {
                                client.start().map(|out| {
                                    println!("{}", out);
                                })
                            } else if cmd == "stop" {
                                client.stop().map(|out| {
                                    println!("{}", out);
                                })
                            } else if let Some(value) = cmd.strip_prefix("channel_change:") {
                                client.channel_change(value).map(|out| println!("{}", out))
                            } else {
                                match cmd {
                                    "list" => client.list().map(|list| {
                                        common::console_out::console_device_list(list);
                                    }),
                                    "info" => client.info().map(|info| {
                                        common::console_out::console_info(info);
                                    }),
                                    "route" => client.route().map(|route| {
                                        common::console_out::console_route_table(route);
                                    }),
                                    "all" => client.list().map(|list| {
                                        common::console_out::console_device_list_all(list);
                                    }),
                                    "chart_a" => client.chart_a().map(|chart| {
                                        common::console_out::console_chart_a(chart);
                                    }),
                                    _ if cmd.starts_with("chart_b") => {
                                        let input = cmd
                                            .split_once(':')
                                            .map(|(_, right)| right.to_string())
                                            .unwrap_or_default();
                                        client.chart_b(&input).map(|chart| {
                                            common::console_out::console_chart_b(chart);
                                        })
                                    }
                                    _ => Err(io::Error::other("unknown command")),
                                }
                            };
                            if let Err(e) = result {
                                println!("input err:{}", e);
                            }
                        }
                        Err(e) => {
                            println!("input err:{}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("input err:{}", e);
                    let _ = shutdown_sender.send(());
                    break;
                }
            }
        });
    }

    let _ = shutdown_receiver.recv();
    manager.shutdown();
    0
}
