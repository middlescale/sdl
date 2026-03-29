use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce, Tag};
use anyhow::anyhow;
use rand::RngCore;

use crate::protocol::{
    body::{AesGcmSecretBody, AES_GCM_ENCRYPTION_RESERVED, AES_GCM_NONCE_RESERVED},
    NetPacket,
};

#[derive(Clone)]
pub struct AesGcmCipher {
    pub(crate) cipher: AesGcmEnum,
}

#[derive(Clone)]
pub enum AesGcmEnum {
    AES128GCM(Box<Aes128Gcm>),
    AES256GCM(Box<Aes256Gcm>),
}

impl AesGcmCipher {
    pub fn new_128(key: [u8; 16]) -> Self {
        let key: &Key<Aes128Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES128GCM(Box::new(Aes128Gcm::new(key))),
        }
    }
    pub fn new_256(key: [u8; 32]) -> Self {
        let key: &Key<Aes256Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES256GCM(Box::new(Aes256Gcm::new(key))),
        }
    }

    fn encrypted_aad<B: AsRef<[u8]>>(net_packet: &NetPacket<B>) -> [u8; 12] {
        let mut aad = [0u8; 12];
        aad.copy_from_slice(net_packet.head());
        aad[0] |= 0x80;
        aad[3] &= 0xF0;
        aad
    }

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(anyhow!("not encrypt"));
        }
        if net_packet.payload().len() < AES_GCM_ENCRYPTION_RESERVED {
            log::error!("数据异常,长度小于{}", AES_GCM_ENCRYPTION_RESERVED);
            return Err(anyhow!("data err"));
        }
        let aad = Self::encrypted_aad(net_packet);
        let mut secret_body = AesGcmSecretBody::new(net_packet.payload_mut())?;
        let nonce_raw: [u8; AES_GCM_NONCE_RESERVED] = secret_body
            .nonce()
            .try_into()
            .map_err(|_| anyhow!("invalid aes-gcm nonce"))?;
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&nonce_raw);
        let tag: GenericArray<u8, U16> = Tag::clone_from_slice(secret_body.tag());
        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => {
                aes_gcm.decrypt_in_place_detached(nonce, &aad, secret_body.data_mut(), &tag)
            }
            AesGcmEnum::AES256GCM(aes_gcm) => {
                aes_gcm.decrypt_in_place_detached(nonce, &aad, secret_body.data_mut(), &tag)
            }
        };
        if let Err(e) = rs {
            return Err(anyhow!("解密失败:{}", e));
        }
        net_packet.set_encrypt_flag(false);
        net_packet.set_data_len(net_packet.data_len() - AES_GCM_ENCRYPTION_RESERVED)?;
        Ok(())
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if net_packet.reserve() < AES_GCM_ENCRYPTION_RESERVED {
            return Err(anyhow!("too short"));
        }
        let aad = Self::encrypted_aad(net_packet);
        let mut nonce_raw = [0u8; AES_GCM_NONCE_RESERVED];
        rand::thread_rng().fill_bytes(&mut nonce_raw);
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&nonce_raw);
        let data_len = net_packet.data_len() + AES_GCM_ENCRYPTION_RESERVED;
        net_packet.set_data_len(data_len)?;
        let mut secret_body = AesGcmSecretBody::new(net_packet.payload_mut())?;
        secret_body.set_nonce(&nonce_raw)?;
        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => {
                aes_gcm.encrypt_in_place_detached(nonce, &aad, secret_body.data_mut())
            }
            AesGcmEnum::AES256GCM(aes_gcm) => {
                aes_gcm.encrypt_in_place_detached(nonce, &aad, secret_body.data_mut())
            }
        };
        match rs {
            Ok(tag) => {
                secret_body.set_tag(tag.as_slice())?;
                net_packet.set_encrypt_flag(true);
                Ok(())
            }
            Err(e) => Err(anyhow!("加密失败:{}", e)),
        }
    }
}

#[test]
fn test_aes_gcm() {
    let d = AesGcmCipher::new_256([0; 32]);
    let mut p =
        NetPacket::new_encrypt([1; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);

    let d = AesGcmCipher::new_256([0; 32]);
    let mut p =
        NetPacket::new_encrypt([0; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
}

#[test]
fn test_aes_gcm_uses_unique_nonce() {
    let d = AesGcmCipher::new_256([7; 32]);
    let mut p1 =
        NetPacket::new_encrypt([0; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let mut p2 =
        NetPacket::new_encrypt([0; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    p1.head_mut()
        .copy_from_slice(&[0x80, 4, 1, 0x51, 10, 0, 0, 1, 10, 0, 0, 2]);
    p2.head_mut()
        .copy_from_slice(&[0x80, 4, 1, 0x51, 10, 0, 0, 1, 10, 0, 0, 2]);

    d.encrypt_ipv4(&mut p1).unwrap();
    d.encrypt_ipv4(&mut p2).unwrap();

    assert_ne!(p1.payload(), p2.payload());
}

#[test]
fn test_aes_gcm_ignores_mutable_ttl_nibble_in_aad() {
    let d = AesGcmCipher::new_256([9; 32]);
    let mut p =
        NetPacket::new_encrypt([0; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    p.head_mut()
        .copy_from_slice(&[0x80, 4, 1, 0x65, 10, 0, 0, 1, 10, 0, 0, 2]);

    d.encrypt_ipv4(&mut p).unwrap();
    p.set_ttl(4);
    d.decrypt_ipv4(&mut p).unwrap();

    assert!(!p.is_encrypt());
    assert_eq!(p.origin_ttl(), 6);
    assert_eq!(p.ttl(), 4);
}
