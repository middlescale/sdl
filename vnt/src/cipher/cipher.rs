use std::fmt::Display;
use std::str::FromStr;

use anyhow::anyhow;

#[cfg(feature = "aes_cbc")]
use crate::cipher::aes_cbc::AesCbcCipher;
#[cfg(feature = "aes_ecb")]
use crate::cipher::aes_ecb::AesEcbCipher;
#[cfg(feature = "aes_gcm")]
use crate::cipher::aes_gcm::AesGcmCipher;
#[cfg(feature = "chacha20_poly1305")]
use crate::cipher::chacha20::ChaCha20Cipher;
#[cfg(feature = "chacha20_poly1305")]
use crate::cipher::chacha20_poly1305::ChaCha20Poly1305Cipher;
#[cfg(feature = "sm4_cbc")]
use crate::cipher::sm4_cbc::Sm4CbcCipher;
use crate::cipher::xor::XORCipher;
use crate::protocol::NetPacket;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CipherModel {
    #[cfg(feature = "aes_gcm")]
    AesGcm,
    #[cfg(feature = "chacha20_poly1305")]
    Chacha20Poly1305,
    #[cfg(feature = "chacha20_poly1305")]
    Chacha20,
    #[cfg(feature = "aes_cbc")]
    AesCbc,
    #[cfg(feature = "aes_ecb")]
    AesEcb,
    #[cfg(feature = "sm4_cbc")]
    Sm4Cbc,
    Xor,
    None,
}

impl Display for CipherModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            #[cfg(feature = "aes_gcm")]
            CipherModel::AesGcm => "aes_gcm".to_string(),
            #[cfg(feature = "chacha20_poly1305")]
            CipherModel::Chacha20Poly1305 => "chacha20_poly1305".to_string(),
            #[cfg(feature = "chacha20_poly1305")]
            CipherModel::Chacha20 => "chacha20".to_string(),
            #[cfg(feature = "aes_cbc")]
            CipherModel::AesCbc => "aes_cbc".to_string(),
            #[cfg(feature = "aes_ecb")]
            CipherModel::AesEcb => "aes_ecb".to_string(),
            #[cfg(feature = "sm4_cbc")]
            CipherModel::Sm4Cbc => "sm4_cbc".to_string(),
            CipherModel::Xor => "xor".to_string(),
            CipherModel::None => "none".to_string(),
        };
        write!(f, "{}", str)
    }
}

impl CipherModel {
    pub fn is_runtime_supported(self) -> bool {
        #[cfg(feature = "aes_gcm")]
        {
            matches!(self, CipherModel::AesGcm | CipherModel::None)
        }
        #[cfg(not(feature = "aes_gcm"))]
        {
            matches!(self, CipherModel::None)
        }
    }
}

impl FromStr for CipherModel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            #[cfg(feature = "aes_gcm")]
            "aes_gcm" => Ok(CipherModel::AesGcm),
            #[cfg(feature = "chacha20_poly1305")]
            "chacha20_poly1305" => Ok(CipherModel::Chacha20Poly1305),
            #[cfg(feature = "chacha20_poly1305")]
            "chacha20" => Ok(CipherModel::Chacha20),
            #[cfg(feature = "aes_cbc")]
            "aes_cbc" => Ok(CipherModel::AesCbc),
            #[cfg(feature = "aes_ecb")]
            "aes_ecb" => Ok(CipherModel::AesEcb),
            #[cfg(feature = "sm4_cbc")]
            "sm4_cbc" => Ok(CipherModel::Sm4Cbc),
            "xor" => Ok(CipherModel::Xor),
            "none" => Ok(CipherModel::None),
            _ => {
                let mut enums = String::new();
                #[cfg(feature = "aes_gcm")]
                enums.push_str("/aes_gcm");
                #[cfg(feature = "chacha20_poly1305")]
                enums.push_str("/chacha20_poly1305/chacha20");
                #[cfg(feature = "aes_cbc")]
                enums.push_str("/aes_cbc");
                #[cfg(feature = "aes_ecb")]
                enums.push_str("/aes_ecb");
                #[cfg(feature = "sm4_cbc")]
                enums.push_str("/sm4_cbc");
                enums.push_str("/xor/none");
                Err(format!("not match '{}', enum:{}", s, &enums[1..]))
            }
        }
    }
}

#[derive(Clone)]
pub enum Cipher {
    #[cfg(feature = "aes_gcm")]
    AesGcm((AesGcmCipher, Vec<u8>)),
    #[cfg(feature = "chacha20_poly1305")]
    Chacha20Poly1305(ChaCha20Poly1305Cipher),
    #[cfg(feature = "chacha20_poly1305")]
    Chacha20(ChaCha20Cipher),
    #[cfg(feature = "aes_cbc")]
    AesCbc(AesCbcCipher),
    #[cfg(feature = "aes_ecb")]
    AesEcb(AesEcbCipher),
    #[cfg(feature = "sm4_cbc")]
    Sm4Cbc(Sm4CbcCipher),
    Xor(XORCipher),
    None,
}

impl Cipher {
    #[cfg(not(feature = "aes_gcm"))]
    pub fn new_key(_key: [u8; 32]) -> anyhow::Result<Self> {
        Err(anyhow!("key error"))
    }
    #[cfg(feature = "aes_gcm")]
    pub fn new_key(key: [u8; 32]) -> anyhow::Result<Self> {
        let aes = AesGcmCipher::new_256(key);
        Ok(Cipher::AesGcm((aes, key.to_vec())))
    }
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        match self {
            #[cfg(feature = "aes_gcm")]
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.decrypt_ipv4(net_packet),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => aes_cbc.decrypt_ipv4(net_packet),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20Poly1305(chacha20poly1305) => chacha20poly1305.decrypt_ipv4(net_packet),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20(chacha20) => chacha20.decrypt_ipv4(net_packet),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => aes_ecb.decrypt_ipv4(net_packet),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => sm4_cbc.decrypt_ipv4(net_packet),
            Cipher::Xor(xor) => xor.decrypt_ipv4(net_packet),
            Cipher::None => {
                if net_packet.is_encrypt() {
                    return Err(anyhow!("not key"));
                }
                Ok(())
            }
        }
    }
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        match self {
            #[cfg(feature = "aes_gcm")]
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.encrypt_ipv4(net_packet),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20Poly1305(chacha20poly1305) => chacha20poly1305.encrypt_ipv4(net_packet),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20(chacha20) => chacha20.encrypt_ipv4(net_packet),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => aes_cbc.encrypt_ipv4(net_packet),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => aes_ecb.encrypt_ipv4(net_packet),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => sm4_cbc.encrypt_ipv4(net_packet),
            Cipher::Xor(xor) => xor.encrypt_ipv4(net_packet),
            Cipher::None => Ok(()),
        }
    }
    pub fn key(&self) -> Option<&[u8]> {
        match self {
            #[cfg(feature = "aes_gcm")]
            Cipher::AesGcm((_, key)) => Some(key),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20Poly1305(chacha20poly1305) => Some(chacha20poly1305.key()),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20(chacha20) => Some(chacha20.key()),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => Some(aes_cbc.key()),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => Some(aes_ecb.key()),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => Some(sm4_cbc.key()),
            Cipher::Xor(xor) => Some(xor.key()),
            Cipher::None => None,
        }
    }
}
