use std::mem;
use std::os::windows::io::AsRawSocket;

use windows_sys::core::PCSTR;
use windows_sys::Win32::Networking::WinSock::{
    htonl, setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET_ERROR,
};

use crate::transport::socket::{LocalInterface, VntSocketTrait};

impl VntSocketTrait for socket2::Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> anyhow::Result<()> {
        let index = interface.index;
        if index == 0 {
            return Ok(());
        }
        let raw_socket = self.as_raw_socket();
        let result = unsafe {
            let best_interface = htonl(index);
            setsockopt(
                raw_socket as usize,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &best_interface as *const _ as PCSTR,
                mem::size_of_val(&best_interface) as i32,
            )
        };
        if result == SOCKET_ERROR {
            Err(anyhow::anyhow!(
                "Failed to set IP_UNICAST_IF: {:?} {}",
                std::io::Error::last_os_error(),
                index
            ))?;
        }
        Ok(())
    }
}
