#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsQuery {
    pub domain: String,
    pub query_type: u16,
}

pub(crate) fn is_dns_query_payload(payload: &[u8]) -> bool {
    parse_dns_query(payload).is_some()
}

pub(crate) fn parse_dns_query(payload: &[u8]) -> Option<DnsQuery> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    let opcode = flags & 0x7800;
    if is_response || opcode != 0 {
        return None;
    }
    let qd_count = u16::from_be_bytes([payload[4], payload[5]]);
    if qd_count != 1 {
        return None;
    }

    let (domain, pos) = parse_dns_name(payload, 12)?;
    if pos + 4 > payload.len() {
        return None;
    }
    let query_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    let qclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
    if qclass != 1 {
        return None;
    }
    Some(DnsQuery { domain, query_type })
}

pub(crate) fn parse_dns_name(payload: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut encoded_end = None;
    let mut jumps = 0usize;
    loop {
        let byte = *payload.get(pos)?;
        if byte == 0 {
            let end = encoded_end.unwrap_or(pos + 1);
            return Some((labels.join(".").to_ascii_lowercase(), end));
        }
        if byte & 0xC0 == 0xC0 {
            let next = *payload.get(pos + 1)?;
            let pointer = (((byte as usize & 0x3F) << 8) | next as usize) as usize;
            if pointer >= payload.len() || jumps >= 16 {
                return None;
            }
            encoded_end.get_or_insert(pos + 2);
            pos = pointer;
            jumps += 1;
            continue;
        }
        let len = byte as usize;
        if len > 63 || pos + 1 + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]).ok()?;
        labels.push(label.to_string());
        pos += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::{is_dns_query_payload, parse_dns_query};

    fn a_query() -> Vec<u8> {
        let mut payload = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        payload.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        payload
    }

    #[test]
    fn accepts_standard_dns_query() {
        assert!(is_dns_query_payload(&a_query()));
        assert_eq!(parse_dns_query(&a_query()).unwrap().domain, "example.com");
    }

    #[test]
    fn rejects_dns_response() {
        let mut payload = a_query();
        payload[2] = 0x81;
        payload[3] = 0x80;
        assert!(!is_dns_query_payload(&payload));
    }

    #[test]
    fn rejects_non_dns_payload() {
        assert!(!is_dns_query_payload(b"not dns"));
    }

    #[test]
    fn rejects_non_in_class() {
        let mut payload = a_query();
        let len = payload.len();
        payload[len - 1] = 3;
        assert!(!is_dns_query_payload(&payload));
    }
}
