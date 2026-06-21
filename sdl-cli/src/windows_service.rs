use std::ffi::OsString;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{service_dispatcher, Error as WindowsServiceError};

const SERVICE_NAME: &str = "sdl-service";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const START_WAIT_HINT: Duration = Duration::from_secs(15);
const STOP_WAIT_HINT: Duration = Duration::from_secs(15);
const PENDING_STATUS_UPDATE_INTERVAL: Duration = Duration::from_secs(5);
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
const SERVICE_EXIT_OK: ServiceExitCode = ServiceExitCode::Win32(0);
const SERVICE_EXIT_PARSE_ARGS_FAILED: ServiceExitCode = ServiceExitCode::ServiceSpecific(1);
const SERVICE_EXIT_START_FAILED: ServiceExitCode = ServiceExitCode::ServiceSpecific(2);

define_windows_service!(ffi_service_main, service_main);

pub(crate) fn run_service_process(args: Vec<String>) -> i32 {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => 0,
        Err(err) if should_run_as_console(&err) => crate::app::run_service_from_args(args),
        Err(err) => {
            eprintln!("failed to start Windows service dispatcher: {err}");
            1
        }
    }
}

fn service_main(arguments: Vec<OsString>) {
    if let Err(err) = run_service(arguments) {
        eprintln!("windows service main failed: {err}");
        log::error!("windows service main failed: {:?}", err);
    }
}

fn run_service(arguments: Vec<OsString>) -> windows_service::Result<()> {
    let (shutdown_sender, shutdown_receiver) = std::sync::mpsc::channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_sender.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = Arc::new(service_control_handler::register(
        SERVICE_NAME,
        event_handler,
    )?);
    let startup_reporter = PendingStatusReporter::start(
        Arc::clone(&status_handle),
        ServiceState::StartPending,
        START_WAIT_HINT,
    )?;

    let service_args = rebuild_service_arguments(arguments);
    if let Err(err) = crate::cli::ensure_service_device_key_path() {
        startup_reporter.stop();
        let _ = report_service_status(
            &status_handle,
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            SERVICE_EXIT_PARSE_ARGS_FAILED,
            0,
            Duration::default(),
        );
        log::error!("prepare device key path failed: {:?}", err);
        return Err(WindowsServiceError::Winapi(io::Error::other(err)));
    }
    let (config, saved_config) = match crate::cli::parse_args_config_from(service_args) {
        Ok(Some(config)) => config,
        Ok(None) => {
            startup_reporter.stop();
            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                SERVICE_EXIT_OK,
                0,
                Duration::default(),
            )?;
            return Ok(());
        }
        Err(err) => {
            log::error!("service argument parse failed: {:?}", err);
            startup_reporter.stop();
            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                SERVICE_EXIT_PARSE_ARGS_FAILED,
                0,
                Duration::default(),
            )?;
            return Ok(());
        }
    };

    let running_service = match crate::app::RunningService::start(config, saved_config) {
        Ok(running_service) => running_service,
        Err(_) => {
            startup_reporter.stop();
            report_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                SERVICE_EXIT_START_FAILED,
                0,
                Duration::default(),
            )?;
            return Ok(());
        }
    };
    startup_reporter.stop();

    report_service_status(
        &status_handle,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        SERVICE_EXIT_OK,
        0,
        Duration::default(),
    )?;

    let _ = shutdown_receiver.recv();
    let shutdown_reporter = PendingStatusReporter::start(
        Arc::clone(&status_handle),
        ServiceState::StopPending,
        STOP_WAIT_HINT,
    );
    running_service.shutdown();
    let stop_pending_err = match shutdown_reporter {
        Ok(reporter) => {
            reporter.stop();
            None
        }
        Err(err) => {
            log::warn!("failed to enter StopPending before shutdown: {:?}", err);
            Some(err)
        }
    };
    report_service_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        SERVICE_EXIT_OK,
        0,
        Duration::default(),
    )?;
    if let Some(err) = stop_pending_err {
        return Err(err);
    }
    Ok(())
}

fn report_service_status(
    status_handle: &service_control_handler::ServiceStatusHandle,
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    checkpoint: u32,
    wait_hint: Duration,
) -> windows_service::Result<()> {
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state,
        controls_accepted,
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    })
}

struct PendingStatusReporter {
    stop_sender: std::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PendingStatusReporter {
    fn start(
        status_handle: Arc<service_control_handler::ServiceStatusHandle>,
        state: ServiceState,
        wait_hint: Duration,
    ) -> windows_service::Result<Self> {
        report_service_status(
            &status_handle,
            state,
            ServiceControlAccept::empty(),
            SERVICE_EXIT_OK,
            1,
            wait_hint,
        )?;

        let (stop_sender, stop_receiver) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let mut checkpoint = 1u32;
            loop {
                match stop_receiver.recv_timeout(PENDING_STATUS_UPDATE_INTERVAL) {
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        checkpoint = checkpoint.saturating_add(1);
                        if let Err(err) = report_service_status(
                            &status_handle,
                            state,
                            ServiceControlAccept::empty(),
                            SERVICE_EXIT_OK,
                            checkpoint,
                            wait_hint,
                        ) {
                            log::warn!(
                                "failed to refresh pending service status state={:?} checkpoint={}: {:?}",
                                state,
                                checkpoint,
                                err
                            );
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            stop_sender,
            thread: Some(thread),
        })
    }

    fn stop(mut self) {
        let _ = self.stop_sender.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn rebuild_service_arguments(arguments: Vec<OsString>) -> Vec<String> {
    let mut args = Vec::with_capacity(arguments.len() + 1);
    let program = std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| SERVICE_NAME.to_string());
    args.push(program);
    args.extend(
        arguments
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned()),
    );
    args
}

fn should_run_as_console(err: &WindowsServiceError) -> bool {
    matches!(
        err,
        WindowsServiceError::Winapi(io_err)
            if io_err.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
    )
}
