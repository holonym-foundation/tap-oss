//! API-key hashing shared by every surface that stores or verifies agent keys.
//!
//! The proxy, the admin API, and the CLI must all produce the identical hash
//! for a key to authenticate — keep this the single implementation.

use sha2::{Digest, Sha256};

/// Deterministic SHA-256 hash for API key lookup.
pub fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_hash_is_deterministic() {
        assert_eq!(hash_api_key("my-api-key-123"), hash_api_key("my-api-key-123"));
    }

    #[test]
    fn api_key_hash_is_sha256_hex() {
        // Pinned vector: a change here silently locks every stored key out.
        assert_eq!(
            hash_api_key("key-alpha"),
            "39a00d29356083a9c9d65c14652350d61b11d5d2e8582da510887c8e11be08c8"
        );
    }
}
