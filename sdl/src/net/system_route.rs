//! Operating-system route configuration, separate from SDL peer routing.

use std::io;
use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
pub(crate) fn add_route(index: u32, dest: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let cmd = format!(
        "route add {:?} mask {:?} {:?} metric {} if {}",
        dest,
        netmask,
        Ipv4Addr::UNSPECIFIED,
        1,
        index
    );
    exe_cmd(&cmd)
}
#[cfg(target_os = "windows")]
pub(crate) fn exe_cmd(cmd: &str) -> io::Result<()> {
    use std::os::windows::process::CommandExt;

    println!("exe cmd: {}", cmd);
    let out = std::process::Command::new("cmd")
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .arg("/C")
        .arg(&cmd)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={},out={:?}", cmd, String::from_utf8(out.stderr)),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn add_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let cmd = format!(
        "route -n add {} -netmask {} -interface {}",
        address, netmask, name
    );
    exe_cmd(&cmd)?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn add_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let prefix_len = u32::from(netmask).count_ones();
    let route_target = if netmask.is_broadcast() {
        format!("{address}/32")
    } else {
        format!("{address}/{prefix_len}")
    };
    if let Err(ip_err) = exe_linux_ip_route_cmd(name, &route_target) {
        let fallback_cmd = if netmask.is_broadcast() {
            format!("route add -host {:?} {}", address, name)
        } else {
            format!("route add -net {}/{} {}", address, prefix_len, name)
        };
        if let Err(route_err) = exe_cmd(&fallback_cmd) {
            return Err(io::Error::new(
                route_err.kind(),
                format!("ip route error: {ip_err}; fallback route error: {route_err}"),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn delete_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    use std::process::Command;

    let prefix_len = u32::from(netmask).count_ones();
    let route_target = if netmask.is_broadcast() {
        format!("{address}/32")
    } else {
        format!("{address}/{prefix_len}")
    };
    println!("exe cmd: ip route del {} dev {}", route_target, name);
    let out = Command::new("ip")
        .arg("route")
        .arg("del")
        .arg(&route_target)
        .arg("dev")
        .arg(name)
        .output()?;
    if !out.status.success() {
        let fallback_cmd = if netmask.is_broadcast() {
            format!("route del -host {:?} {}", address, name)
        } else {
            format!("route del -net {}/{} {}", address, prefix_len, name)
        };
        if let Err(route_err) = exe_cmd(&fallback_cmd) {
            return Err(io::Error::new(
                route_err.kind(),
                format!(
                    "ip route delete error: cmd=ip route del {} dev {},out={:?}; fallback route error: {route_err}",
                    route_target, name, out
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exe_linux_ip_route_cmd(name: &str, route_target: &str) -> io::Result<()> {
    use std::process::Command;

    println!("exe cmd: ip route replace {} dev {}", route_target, name);
    let out = Command::new("ip")
        .arg("route")
        .arg("replace")
        .arg(route_target)
        .arg("dev")
        .arg(name)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "cmd=ip route replace {} dev {},out={:?}",
                route_target, name, out
            ),
        ));
    }
    Ok(())
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn exe_cmd(cmd: &str) -> io::Result<std::process::Output> {
    use std::process::Command;
    println!("exe cmd: {}", cmd);
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("sh exec error!");
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={},out={:?}", cmd, out),
        ));
    }
    Ok(out)
}
