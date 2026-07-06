pub(crate) fn is_dns_query_payload(payload: &[u8]) -> bool {
    parse_dns_query_question_end(payload).is_some()
}

fn parse_dns_query_question_end(payload: &[u8]) -> Option<usize> {
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

    let mut pos = 12usize;
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
        pos += 1 + len;
    }
    if pos + 4 > payload.len() {
        return None;
    }
    let qclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
    if qclass != 1 {
        return None;
    }
    Some(pos + 4)
}

#[cfg(test)]
mod tests {
    use super::is_dns_query_payload;

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
