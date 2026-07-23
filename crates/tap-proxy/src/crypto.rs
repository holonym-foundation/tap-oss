use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use tap_core::error::AgentSecError;

/// Encrypt plaintext using AES-256-GCM.
/// Returns (ciphertext, nonce).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AgentSecError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AgentSecError::Encryption(format!("Invalid key: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AgentSecError::Encryption(format!("Encryption failed: {e}")))?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decrypt ciphertext using AES-256-GCM.
pub fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, AgentSecError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AgentSecError::Encryption(format!("Invalid key: {e}")))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AgentSecError::Encryption(format!("Decryption failed: {e}")))?;

    Ok(plaintext)
}

/// Parse a 32-byte hex string into a key.
pub fn parse_encryption_key(hex_str: &str) -> Result<[u8; 32], AgentSecError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| AgentSecError::Encryption(format!("Invalid hex key: {e}")))?;

    if bytes.len() != 32 {
        return Err(AgentSecError::Encryption(format!(
            "Key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let plaintext = b"secret credentials json";
        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = test_key();
        let plaintext = b"";
        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let key = test_key();
        let plaintext = b"same plaintext";
        let (ct1, _n1) = encrypt(&key, plaintext).unwrap();
        let (ct2, _n2) = encrypt(&key, plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0xFF;

        let plaintext = b"secret";
        let (ciphertext, nonce) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_with_wrong_nonce_fails() {
        let key = test_key();
        let plaintext = b"secret";
        let (ciphertext, mut nonce) = encrypt(&key, plaintext).unwrap();
        nonce[0] ^= 0xFF;
        let result = decrypt(&key, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_with_tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = b"secret";
        let (mut ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        ciphertext[0] ^= 0xFF;
        let result = decrypt(&key, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn parse_encryption_key_valid() {
        let hex = "0001020304050607080910111213141516171819202122232425262728293031";
        let key = parse_encryption_key(hex).unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[1], 0x01);
    }

    #[test]
    fn parse_encryption_key_too_short() {
        let hex = "0001020304";
        let result = parse_encryption_key(hex);
        assert!(result.is_err());
    }

    #[test]
    fn parse_encryption_key_invalid_hex() {
        let hex = "not_hex_at_all_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = parse_encryption_key(hex);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_large_payload() {
        let key = test_key();
        let plaintext = vec![0xABu8; 10_000];
        let (ciphertext, nonce) = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
