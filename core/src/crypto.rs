//! Ed25519 签名与 SHA-256 哈希封装。

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// 生成一对新的 Ed25519 密钥。
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut rng = rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// 从 hex 编码的 32 字节私钥恢复签名密钥。
pub fn signing_key_from_hex(hex_str: &str) -> Result<SigningKey, CoreError> {
    let bytes = decode_32(hex_str, "signing key")?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// 从 hex 编码的 32 字节公钥恢复验证密钥。
pub fn verifying_key_from_hex(hex_str: &str) -> Result<VerifyingKey, CoreError> {
    let bytes = decode_32(hex_str, "verifying key")?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| CoreError::InvalidKey(e.to_string()))
}

/// 签名密钥导出为 hex（32 字节私钥种子）。
pub fn signing_key_to_hex(key: &SigningKey) -> String {
    hex::encode(key.to_bytes())
}

/// 验证密钥导出为 hex。
pub fn verifying_key_to_hex(key: &VerifyingKey) -> String {
    hex::encode(key.to_bytes())
}

/// 对载荷签名，输出 hex 编码签名。
pub fn sign_bytes(payload: &[u8], key: &SigningKey) -> String {
    hex::encode(key.sign(payload).to_bytes())
}

/// 验证 hex 编码签名；编码非法或验证不通过均返回 false。
pub fn verify_bytes(payload: &[u8], key: &VerifyingKey, signature_hex: &str) -> bool {
    let Ok(bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(raw): Result<[u8; 64], _> = bytes.as_slice().try_into() else {
        return false;
    };
    let signature = Signature::from_bytes(&raw);
    key.verify(payload, &signature).is_ok()
}

/// 计算 SHA-256 并输出 hex。
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn decode_32(hex_str: &str, what: &str) -> Result<[u8; 32], CoreError> {
    let bytes = hex::decode(hex_str).map_err(|e| CoreError::InvalidKey(format!("{what}: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidKey(format!("{what}: 期望 32 字节")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_hex_roundtrip() {
        let (sk, vk) = generate_keypair();
        let sk2 = signing_key_from_hex(&signing_key_to_hex(&sk)).unwrap();
        let vk2 = verifying_key_from_hex(&verifying_key_to_hex(&vk)).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        assert_eq!(vk.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn sign_and_verify() {
        let (sk, vk) = generate_keypair();
        let sig = sign_bytes(b"payload", &sk);
        assert!(verify_bytes(b"payload", &vk, &sig));
    }

    #[test]
    fn verify_rejects_tampered_payload_and_bad_encoding() {
        let (sk, vk) = generate_keypair();
        let sig = sign_bytes(b"payload", &sk);
        assert!(!verify_bytes(b"tampered", &vk, &sig));
        assert!(!verify_bytes(b"payload", &vk, "not-hex"));
        assert!(!verify_bytes(b"payload", &vk, "abcd"));
        let (sk2, _) = generate_keypair();
        let sig2 = sign_bytes(b"payload", &sk2);
        assert!(!verify_bytes(b"payload", &vk, &sig2));
    }

    #[test]
    fn sha256_hex_is_stable() {
        let h = sha256_hex(b"anchor");
        assert_eq!(h.len(), 64);
        assert_eq!(h, sha256_hex(b"anchor"));
        assert_ne!(h, sha256_hex(b"guard"));
    }
}
