use std::net::Ipv4Addr;

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod igmp;
pub mod ip;
pub mod tcp;
pub mod udp;
// pub enum IpUpperLayer<B> {
//     UDP(UdpPacket<B>),
//     Unknown(B),
// }
//
// impl<B: AsRef<[u8]>> fmt::Debug for IpUpperLayer<B> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             IpUpperLayer::UDP(p) => {
//                 f.debug_struct("udp::Packet")
//                     .field("data", p).finish()
//             }
//             IpUpperLayer::Unknown(p) => {
//                 f.debug_struct("Unknown")
//                     .field("data", &p.as_ref()).finish()
//             }
//         }
//     }
// }

/// https://datatracker.ietf.org/doc/html/rfc1071 4.1节
///
/// 计算校验和，各协议都是通用的
/// 计算：
/// 首先将校验和置0，然后对首部每个16位数进行二进制反码求和，
/// 得到校验和之后，持续取高16位加到低16位，直到高16位全为0
/// 最后取反
///
/// 校验：
/// 在已有校验和的情况下，再计算校验和，正确的数据计算得到的值为0
/*
unsigned short getChecksum(unsigned short * iphead, int count)
{
    unsigned long int sum = 0;
    unsigned short checksum = 0;

    printf("\nStarting adress: %p\n", iphead);

    while(count > 1) {
        sum += * (unsigned short *) (iphead);
        count -=2;
        printf("a: %p, content is: %d, new sum: %ld\n", iphead, (unsigned short) *(iphead), sum);
        iphead++;
    }

    if(count > 0) {
        sum += * (unsigned short *) (iphead);
    }

    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checksum = ~sum;

    return checksum;
}
 */
pub fn cal_checksum(buffer: &[u8]) -> u16 {
    !fold_checksum(sum_words(buffer)) as u16
}

/// ipv4上层协议校验和计算方式
/// ipv4 udp伪首部 用于参与计算首部校验和
/*
   0      7 8     15 16    23 24    31
   +--------+--------+--------+--------+
   |          source address           |
   +--------+--------+--------+--------+
   |        destination address        |
   +--------+--------+--------+--------+
   |  zero  |protocol|       length    |
   +--------+--------+--------+--------+
*/
pub fn ipv4_cal_checksum(
    buffer: &[u8],
    src_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
    protocol: u8,
) -> u16 {
    let length = buffer.len();
    let mut sum = 0;
    let src_ip = src_ip.octets();
    sum += u32c(src_ip[0], src_ip[1]);
    sum += u32c(src_ip[2], src_ip[3]);
    let dest_ip = dest_ip.octets();
    sum += u32c(dest_ip[0], dest_ip[1]);
    sum += u32c(dest_ip[2], dest_ip[3]);
    sum += u32c(0, protocol);
    sum += length as u32;
    !fold_checksum(sum + sum_words(buffer)) as u16
}

#[inline]
fn u32c(x: u8, y: u8) -> u32 {
    ((x as u32) << 8) | y as u32
}

fn sum_words(buffer: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = buffer.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32c(*last, 0);
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u32 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cal_checksum_handles_odd_lengths() {
        assert_eq!(cal_checksum(&[0x12, 0x34, 0x56]), !0x6834u16);
    }

    #[test]
    fn ipv4_cal_checksum_handles_odd_lengths() {
        let payload = [0x12, 0x34, 0x56];
        let checksum = ipv4_cal_checksum(
            &payload,
            &Ipv4Addr::new(10, 26, 0, 53),
            &Ipv4Addr::new(10, 26, 0, 3),
            17,
        );
        let expected = !fold_checksum(
            u32c(10, 26)
                + u32c(0, 53)
                + u32c(10, 26)
                + u32c(0, 3)
                + u32c(0, 17)
                + payload.len() as u32
                + 0x1234
                + 0x5600,
        ) as u16;
        assert_eq!(checksum, expected);
    }
}
