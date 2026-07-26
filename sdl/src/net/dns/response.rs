use std::net::Ipv4Addr;

use super::query::parse_dns_name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsResponseObservation {
    pub domain: String,
    pub ipv4_addresses: Vec<Ipv4Addr>,
    pub ttl_secs: u32,
}

/// Extracts the original question and A records from a successful IN response.
/// The routing layer is IPv4-only today, so AAAA records are deliberately not
/// cached here.
pub(crate) fn parse_dns_response(payload: &[u8]) -> Option<DnsResponseObservation> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return None;
    }
    let question_count = u16::from_be_bytes([payload[4], payload[5]]);
    if question_count != 1 {
        return None;
    }
    let answer_count = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let (domain, mut pos) = parse_dns_name(payload, 12)?;
    if pos + 4 > payload.len() {
        return None;
    }
    pos += 4; // QTYPE and QCLASS

    let mut ipv4_addresses = Vec::new();
    let mut ttl_secs = u32::MAX;
    for _ in 0..answer_count {
        let (_, next) = parse_dns_name(payload, pos)?;
        pos = next;
        if pos + 10 > payload.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let record_class = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
        let ttl = u32::from_be_bytes(payload[pos + 4..pos + 8].try_into().ok()?);
        let data_len = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;
        if pos + data_len > payload.len() {
            return None;
        }
        if record_type == 1 && record_class == 1 && data_len == 4 {
            ipv4_addresses.push(Ipv4Addr::new(
                payload[pos],
                payload[pos + 1],
                payload[pos + 2],
                payload[pos + 3],
            ));
            ttl_secs = ttl_secs.min(ttl);
        }
        pos += data_len;
    }
    if ipv4_addresses.is_empty() || ttl_secs == 0 || ttl_secs == u32::MAX {
        return None;
    }
    Some(DnsResponseObservation {
        domain,
        ipv4_addresses,
        ttl_secs: ttl_secs.min(86_400),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_dns_response;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_question_and_a_answer() {
        let mut response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0,
            1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7,
        ];
        let observation = parse_dns_response(&response).unwrap();
        assert_eq!(observation.domain, "example.com");
        assert_eq!(
            observation.ipv4_addresses,
            vec![Ipv4Addr::new(203, 0, 113, 7)]
        );
        assert_eq!(observation.ttl_secs, 60);
        response[3] = 0x83;
        assert!(parse_dns_response(&response).is_none());
    }
}
