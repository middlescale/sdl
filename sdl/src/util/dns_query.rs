use anyhow::Context;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;

thread_local! {
    static HISTORY: RefCell<HashMap<SocketAddr,usize>> = RefCell::new(HashMap::new());
}

/// 保留一个地址使用记录，使用过的地址后续不再选中，直到地址全使用过
pub fn address_choose(addrs: Vec<SocketAddr>) -> anyhow::Result<SocketAddr> {
    HISTORY.with(|history| {
        let mut available = Vec::new();
        for x in &addrs {
            let num = history.borrow().get(x).map_or(0, |v| *v);
            if num < 3 {
                available.push(*x);
            }
        }
        if available.is_empty() {
            available = addrs;
            history.borrow_mut().clear();
        }
        let addr = address_choose0(available)?;
        history
            .borrow_mut()
            .entry(addr)
            .and_modify(|v| {
                *v += 1;
            })
            .or_insert(1);
        Ok(addr)
    })
}

/// 后续实现选择延迟最低的可用地址，需要服务端配合
/// 现在是选择第一个地址，优先ipv6
fn address_choose0(addrs: Vec<SocketAddr>) -> anyhow::Result<SocketAddr> {
    let v4: Vec<SocketAddr> = addrs.iter().filter(|v| v.is_ipv4()).copied().collect();
    let v6: Vec<SocketAddr> = addrs.iter().filter(|v| v.is_ipv6()).copied().collect();
    let check_addr = |addrs: &Vec<SocketAddr>| -> anyhow::Result<SocketAddr> {
        let mut err = Vec::new();
        if !addrs.is_empty() {
            let udp = if addrs[0].is_ipv6() {
                UdpSocket::bind("[::]:0")?
            } else {
                UdpSocket::bind("0.0.0.0:0")?
            };
            for addr in addrs {
                if let Err(e) = udp.connect(addr) {
                    err.push((*addr, e));
                } else {
                    return Ok(*addr);
                }
            }
        }
        Err(anyhow::anyhow!("Unable to connect to address {:?}", err))
    };
    if v6.is_empty() {
        return check_addr(&v4);
    }
    if v4.is_empty() {
        return check_addr(&v6);
    }
    match check_addr(&v6) {
        Ok(addr) => Ok(addr),
        Err(e1) => match check_addr(&v4) {
            Ok(addr) => Ok(addr),
            Err(e2) => Err(anyhow::anyhow!("{} , {}", e1, e2)),
        },
    }
}

pub fn dns_query_all(domain: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let mut current_domain = domain.to_string();
    for prefix in ["quic://", "udp://", "tcp://"] {
        if let Some(stripped) = current_domain.to_lowercase().strip_prefix(prefix) {
            current_domain = stripped.to_string();
            break;
        }
    }
    match SocketAddr::from_str(&current_domain) {
        Ok(addr) => Ok(vec![addr]),
        Err(_) => Ok(current_domain
            .to_socket_addrs()
            .with_context(|| format!("DNS query failed {:?}", current_domain))?
            .collect()),
    }
}
