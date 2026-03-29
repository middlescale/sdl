use std::process;

use console::style;
use sdl::{ConnectInfo, ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, SdlCallback};

#[derive(Clone)]
pub struct VntHandler {}

impl SdlCallback for VntHandler {
    fn success(&self) {
        println!(" {} ", style("====== Connect Successfully ======").green())
    }
    #[cfg(feature = "integrated_tun")]
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
        println!("register {}", style(info).green());
        true
    }

    fn error(&self, info: ErrorInfo) {
        log::error!("error {:?}", info);
        println!("{}", style(format!("error {}", info)).red());
        match info.code {
            ErrorType::TokenError
            | ErrorType::AddressExhausted
            | ErrorType::IpAlreadyExists
            | ErrorType::InvalidIp
            | ErrorType::LocalIpExists
            | ErrorType::FailedToCreateDevice => {
                self.stop();
            }
            _ => {}
        }
    }

    fn stop(&self) {
        println!("stopped");
        process::exit(0)
    }
}
