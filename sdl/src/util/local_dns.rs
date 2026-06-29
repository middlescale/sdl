use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::handle::PeerDeviceInfo;
use crate::DnsProfile;

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_PTR: u16 = 12;

pub(crate) enum LocalDnsResolution {
    Answered(Vec<u8>),
    Miss,
    Unsupported,
}

struct ParsedDnsQuery {
    name: String,
    qtype: u16,
    question_end: usize,
}

pub(crate) fn resolve_local_query(
    payload: &[u8],
    profile: Option<&DnsProfile>,
    devices: &HashMap<Ipv4Addr, PeerDeviceInfo>,
) -> LocalDnsResolution {
    let Some(profile) = profile else {
        return LocalDnsResolution::Unsupported;
    };
    let Some(query) = parse_dns_query(payload) else {
        return LocalDnsResolution::Unsupported;
    };
    match query.qtype {
        DNS_TYPE_A => match resolve_forward(&query.name, profile, devices) {
            Some(ip) => {
                LocalDnsResolution::Answered(build_a_response(payload, query.question_end, ip))
            }
            None => LocalDnsResolution::Miss,
        },
        DNS_TYPE_PTR => match resolve_reverse(&query.name, profile, devices) {
            Some(name) => {
                LocalDnsResolution::Answered(build_ptr_response(payload, query.question_end, &name))
            }
            None => LocalDnsResolution::Miss,
        },
        _ => LocalDnsResolution::Unsupported,
    }
}

pub(crate) fn best_match_domain(name: &str, profile: &DnsProfile) -> Option<String> {
    let name = normalize_name(name)?;
    profile
        .match_domains
        .iter()
        .filter_map(|domain| {
            let domain = normalize_domain(domain)?;
            if name == domain || name.ends_with(&format!(".{domain}")) {
                Some(domain)
            } else {
                None
            }
        })
        .max_by_key(|domain| domain.len())
}

fn parse_dns_query(payload: &[u8]) -> Option<ParsedDnsQuery> {
    if payload.len() < 12 {
        return None;
    }
    let qd_count = u16::from_be_bytes([payload[4], payload[5]]);
    if qd_count != 1 {
        return None;
    }

    let mut pos = 12usize;
    let mut name = String::new();
    loop {
        if pos >= payload.len() {
            return None;
        }
        let len = payload[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) != 0 || pos + 1 + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        pos += 1 + len;
    }
    if pos + 4 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    let qclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
    if qclass != DNS_CLASS_IN {
        return None;
    }
    Some(ParsedDnsQuery {
        name,
        qtype,
        question_end: pos + 4,
    })
}

fn resolve_forward(
    name: &str,
    profile: &DnsProfile,
    devices: &HashMap<Ipv4Addr, PeerDeviceInfo>,
) -> Option<Ipv4Addr> {
    let name = normalize_name(name)?;
    let matched_domain = best_match_domain(&name, profile)?;
    if name == matched_domain {
        return None;
    }
    let host = name.strip_suffix(&matched_domain)?.strip_suffix('.')?;
    devices
        .values()
        .find(|device| normalize_name(&device.name).as_deref() == Some(host))
        .map(|device| device.virtual_ip)
}

fn resolve_reverse(
    name: &str,
    profile: &DnsProfile,
    devices: &HashMap<Ipv4Addr, PeerDeviceInfo>,
) -> Option<String> {
    let ip = parse_ptr_name(name)?;
    let device = devices.get(&ip)?;
    let suffix = canonical_ptr_suffix(profile)?;
    let host = normalize_name(&device.name)?;
    Some(format!("{host}.{suffix}"))
}

fn canonical_ptr_suffix(profile: &DnsProfile) -> Option<String> {
    profile
        .match_domains
        .iter()
        .filter_map(|domain| normalize_domain(domain))
        .max_by_key(|domain| domain.len())
}

fn parse_ptr_name(name: &str) -> Option<Ipv4Addr> {
    let name = normalize_name(name)?;
    let suffix = ".in-addr.arpa";
    let head = name.strip_suffix(suffix)?;
    let mut parts = head.split('.');
    let a = parts.next()?.parse::<u8>().ok()?;
    let b = parts.next()?.parse::<u8>().ok()?;
    let c = parts.next()?.parse::<u8>().ok()?;
    let d = parts.next()?.parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::new(d, c, b, a))
}

fn normalize_name(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_lowercase();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn normalize_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('~');
    normalize_name(value)
}

fn build_a_response(query: &[u8], question_end: usize, ip: Ipv4Addr) -> Vec<u8> {
    build_response(query, question_end, DNS_TYPE_A, &ip.octets())
}

fn build_ptr_response(query: &[u8], question_end: usize, name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_dns_name(name, &mut encoded);
    build_response(query, question_end, DNS_TYPE_PTR, &encoded)
}

fn build_response(query: &[u8], question_end: usize, qtype: u16, rdata: &[u8]) -> Vec<u8> {
    let query_flags = u16::from_be_bytes([query[2], query[3]]);
    let rd = query_flags & 0x0100;
    let opcode = query_flags & 0x7800;
    let resp_flags = 0x8480 | opcode | rd;

    let mut resp = Vec::with_capacity(question_end + 12 + rdata.len());
    resp.extend_from_slice(&query[..question_end]);
    resp[2] = (resp_flags >> 8) as u8;
    resp[3] = (resp_flags & 0xFF) as u8;
    resp[6] = 0;
    resp[7] = 1;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&qtype.to_be_bytes());
    resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(rdata);
    resp
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(domains: &[&str]) -> DnsProfile {
        DnsProfile {
            servers: vec!["10.26.0.53".into()],
            match_domains: domains.iter().map(|item| item.to_string()).collect(),
        }
    }

    fn devices() -> HashMap<Ipv4Addr, PeerDeviceInfo> {
        let mut out = HashMap::new();
        out.insert(
            Ipv4Addr::new(10, 26, 0, 3),
            PeerDeviceInfo::new(
                Ipv4Addr::new(10, 26, 0, 3),
                "node-a".into(),
                0,
                "dev-a".into(),
                vec![],
                vec![],
                crate::proto::message::ChannelMode::CHANNEL_MODE_AUTO,
                false,
                false,
                false,
            ),
        );
        out
    }

    fn a_query(name: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        payload.extend_from_slice(name);
        payload.extend_from_slice(&[0, 1, 0, 1]);
        payload
    }

    #[test]
    fn longest_suffix_wins() {
        let profile = profile(&["ms.net", "sales.ms.net"]);
        assert_eq!(
            best_match_domain("node-a.sales.ms.net", &profile).as_deref(),
            Some("sales.ms.net")
        );
    }

    #[test]
    fn resolves_a_from_full_name() {
        let query = a_query(&[
            6, b'n', b'o', b'd', b'e', b'-', b'a', 5, b's', b'a', b'l', b'e', b's', 2, b'm', b's',
            3, b'n', b'e', b't', 0,
        ]);
        match resolve_local_query(
            &query,
            Some(&profile(&["ms.net", "sales.ms.net"])),
            &devices(),
        ) {
            LocalDnsResolution::Answered(resp) => {
                assert_eq!(&resp[resp.len() - 4..], &[10, 26, 0, 3]);
            }
            _ => panic!("expected local answer"),
        }
    }

    #[test]
    fn short_name_falls_back() {
        let query = a_query(&[6, b'n', b'o', b'd', b'e', b'-', b'a', 0]);
        assert!(matches!(
            resolve_local_query(&query, Some(&profile(&["sales.ms.net"])), &devices()),
            LocalDnsResolution::Miss
        ));
    }

    #[test]
    fn misses_on_unknown_local_name() {
        let query = a_query(&[
            7, b'm', b'i', b's', b's', b'i', b'n', b'g', 5, b's', b'a', b'l', b'e', b's', 2, b'm',
            b's', 3, b'n', b'e', b't', 0,
        ]);
        assert!(matches!(
            resolve_local_query(&query, Some(&profile(&["sales.ms.net"])), &devices()),
            LocalDnsResolution::Miss
        ));
    }

    #[test]
    fn falls_back_for_aaaa() {
        let mut query = a_query(&[
            6, b'n', b'o', b'd', b'e', b'-', b'a', 5, b's', b'a', b'l', b'e', b's', 2, b'm', b's',
            3, b'n', b'e', b't', 0,
        ]);
        let len = query.len();
        query[len - 4] = 0;
        query[len - 3] = 28;
        assert!(matches!(
            resolve_local_query(&query, Some(&profile(&["sales.ms.net"])), &devices()),
            LocalDnsResolution::Unsupported
        ));
    }

    #[test]
    fn resolves_ptr_locally() {
        let mut query = a_query(&[
            1, b'3', 1, b'0', 2, b'2', b'6', 2, b'1', b'0', 7, b'i', b'n', b'-', b'a', b'd', b'd',
            b'r', 4, b'a', b'r', b'p', b'a', 0,
        ]);
        let len = query.len();
        query[len - 4] = 0;
        query[len - 3] = 12;
        match resolve_local_query(
            &query,
            Some(&profile(&["ms.net", "sales.ms.net"])),
            &devices(),
        ) {
            LocalDnsResolution::Answered(resp) => {
                assert!(resp.ends_with(&[
                    6, b'n', b'o', b'd', b'e', b'-', b'a', 5, b's', b'a', b'l', b'e', b's', 2,
                    b'm', b's', 3, b'n', b'e', b't', 0,
                ]));
            }
            _ => panic!("expected ptr answer"),
        }
    }
}
