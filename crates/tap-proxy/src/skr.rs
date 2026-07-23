//! Azure Secure Key Release (SKR) crypto primitives — pure, side-effect-free, and unit
//! tested without Azure or Postgres. Shared by the runtime `azure-skr` KMS backend
//! (`key_provider_enclave::azure`) and the one-time DEK re-wrap migration tool
//! (`src/bin/rewrap_dek.rs`), so both use the *identical* RSA-OAEP wrap path.
//!
//! The KEK is an RSA-HSM key released by the SKR sidecar as a JWK; it wraps/unwraps the
//! 32-byte master DEK with **RSA-OAEP-SHA256**. We do the OAEP in-process (the key is
//! *released*, not used via Key Vault crypto-ops) so attestation gating is preserved.

use tap_core::error::AgentSecError;

use base64::Engine as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

/// Minimum accepted RSA KEK modulus size. Sub-2048-bit RSA is below current guidance, and a
/// released KEK that small would be a misconfiguration we refuse rather than trust (L2).
const MIN_KEK_MODULUS_BITS: usize = 2048;

/// Pull the released-key JWK out of a sidecar `/key/release` response. The `key` field
/// may be a JSON object (JWK) or a JSON string containing one — handle both.
pub fn extract_released_jwk(body: &serde_json::Value) -> Result<serde_json::Value, AgentSecError> {
    let key = body.get("key").ok_or_else(|| {
        AgentSecError::Encryption("SKR release response missing 'key'".to_string())
    })?;
    match key {
        serde_json::Value::String(s) => serde_json::from_str(s).map_err(|e| {
            AgentSecError::Encryption(format!("SKR 'key' is not valid JWK JSON: {e}"))
        }),
        serde_json::Value::Object(_) => Ok(key.clone()),
        _ => Err(AgentSecError::Encryption(
            "SKR 'key' is neither an object nor a JSON string".to_string(),
        )),
    }
}

/// base64url (no pad) → BigUint, for JWK key components.
fn b64url_to_biguint(s: &str) -> Result<rsa::BigUint, AgentSecError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AgentSecError::Encryption(format!("Invalid base64url in JWK: {e}")))?;
    Ok(rsa::BigUint::from_bytes_be(&bytes))
}

fn jwk_field<'a>(jwk: &'a serde_json::Value, name: &str) -> Result<&'a str, AgentSecError> {
    jwk.get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| AgentSecError::Encryption(format!("JWK missing '{name}'")))
}

fn is_rsa_jwk(jwk: &serde_json::Value) -> bool {
    matches!(
        jwk.get("kty").and_then(|v| v.as_str()),
        Some("RSA" | "RSA-HSM")
    )
}

/// Reconstruct an RSA private key from a released JWK (kty=RSA/RSA-HSM, with private components).
pub fn parse_rsa_private_jwk(jwk: &serde_json::Value) -> Result<RsaPrivateKey, AgentSecError> {
    if !is_rsa_jwk(jwk) {
        return Err(AgentSecError::Encryption(
            "released KEK is not an RSA JWK (kty != RSA/RSA-HSM)".to_string(),
        ));
    }
    let n = b64url_to_biguint(jwk_field(jwk, "n")?)?;
    let e = b64url_to_biguint(jwk_field(jwk, "e")?)?;
    let d = b64url_to_biguint(jwk_field(jwk, "d")?)?;
    let p = b64url_to_biguint(jwk_field(jwk, "p")?)?;
    let q = b64url_to_biguint(jwk_field(jwk, "q")?)?;
    // from_components recomputes the CRT params (dp/dq/qi) from n,e,d,p,q, so dropping them
    // from the JWK is safe; validate() then checks key consistency.
    let key = RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|err| AgentSecError::Encryption(format!("Invalid RSA private JWK: {err}")))?;
    key.validate().map_err(|err| {
        AgentSecError::Encryption(format!("RSA private key failed validation: {err}"))
    })?;
    ensure_modulus_floor(key.n().bits())?;
    Ok(key)
}

/// Reconstruct an RSA public key from a JWK (kty=RSA/RSA-HSM, n + e). Used by the migration tool
/// to wrap the DEK with the KEK's public half.
pub fn parse_rsa_public_jwk(jwk: &serde_json::Value) -> Result<RsaPublicKey, AgentSecError> {
    if !is_rsa_jwk(jwk) {
        return Err(AgentSecError::Encryption(
            "KEK JWK is not RSA (kty != RSA/RSA-HSM)".to_string(),
        ));
    }
    let n = b64url_to_biguint(jwk_field(jwk, "n")?)?;
    let e = b64url_to_biguint(jwk_field(jwk, "e")?)?;
    let key = RsaPublicKey::new(n, e)
        .map_err(|err| AgentSecError::Encryption(format!("Invalid RSA public JWK: {err}")))?;
    ensure_modulus_floor(key.n().bits())?;
    Ok(key)
}

/// Refuse an RSA modulus below [`MIN_KEK_MODULUS_BITS`] (L2 — defense-in-depth against a
/// dangerously small released/supplied KEK).
fn ensure_modulus_floor(bits: usize) -> Result<(), AgentSecError> {
    if bits < MIN_KEK_MODULUS_BITS {
        return Err(AgentSecError::Encryption(format!(
            "RSA KEK modulus is {bits} bits; refusing keys under {MIN_KEK_MODULUS_BITS} bits"
        )));
    }
    Ok(())
}

/// Reject a JWK that carries any RSA *private* component. The DEK re-wrap paths
/// (`bin/rewrap_dek` and the proxy startup hook) must be handed the KEK's PUBLIC key only —
/// a JWK with `d/p/q/...` means the operator exported the private half outside the TEE/HSM,
/// which defeats SKR's custody guarantee (the KEK private key must only ever be *released*
/// to the attested image). (M1)
pub fn ensure_public_only_jwk(jwk: &serde_json::Value) -> Result<(), AgentSecError> {
    // RFC 7518 RSA private-key fields (including the optional `oth` other-primes array).
    const PRIVATE_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth"];
    for field in PRIVATE_FIELDS {
        if jwk.get(*field).is_some() {
            return Err(AgentSecError::Encryption(format!(
                "KEK JWK carries the private component '{field}' — supply the PUBLIC key only \
                 (the KEK private half must never leave the enclave/HSM)"
            )));
        }
    }
    Ok(())
}

/// Non-secret fingerprint of a DEK: the first 8 bytes of SHA-256 over a domain-separation
/// prefix concatenated with the DEK, hex-encoded. Lets an operator confirm the *same* DEK
/// survived a re-wrap (continuity) without ever exposing key material — it is a truncated,
/// one-way, domain-separated hash, not the key. (M3)
pub fn dek_fingerprint(dek: &[u8; 32]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"TAP-DEK-fingerprint-v1");
    hasher.update(dek);
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// RSA-OAEP-SHA256 unwrap of a base64(std)-encoded wrapped DEK → 32 bytes.
///
/// OAEP here uses SHA-256 for both the OAEP hash and MGF1, with an empty label — i.e. it is
/// wire-compatible with Azure Key Vault's **`RSA-OAEP-256`** algorithm. If this is ever
/// unwrapped/wrapped via Key Vault crypto-ops instead of local release, the caller MUST
/// select `RSA-OAEP-256` (NOT `RSA-OAEP`, which is SHA-1 in Azure, nor `RSA1_5`).
pub fn unwrap_dek(kek: &RsaPrivateKey, wrapped_b64: &str) -> Result<[u8; 32], AgentSecError> {
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(wrapped_b64.trim())
        .map_err(|e| AgentSecError::Encryption(format!("Invalid base64 wrapped DEK: {e}")))?;
    let dek = kek
        .decrypt(Oaep::new::<sha2::Sha256>(), &wrapped)
        .map_err(|e| AgentSecError::Encryption(format!("RSA-OAEP unwrap of DEK failed: {e}")))?;
    if dek.len() != 32 {
        return Err(AgentSecError::Encryption(format!(
            "unwrapped DEK is {} bytes, expected 32",
            dek.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&dek);
    Ok(out)
}

/// RSA-OAEP-SHA256 wrap of a 32-byte DEK with the KEK public key → base64(std).
/// Used on greenfield bootstrap and by the one-time re-wrap migration tool.
pub fn wrap_dek(kek_pub: &RsaPublicKey, dek: &[u8; 32]) -> Result<String, AgentSecError> {
    let wrapped = kek_pub
        .encrypt(&mut rand::rngs::OsRng, Oaep::new::<sha2::Sha256>(), dek)
        .map_err(|e| AgentSecError::Encryption(format!("RSA-OAEP wrap of DEK failed: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(wrapped))
}

/// Test-only: serialize an `RsaPrivateKey` to the JWK shape the SKR sidecar returns for
/// an exportable RSA-HSM key. `pub(crate)` so the `kms_azure` mocked-sidecar tests reuse it.
#[cfg(test)]
pub(crate) fn private_key_to_jwk(key: &RsaPrivateKey) -> serde_json::Value {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let b64 = |b: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let primes = key.primes();
    serde_json::json!({
        "kty": "RSA",
        "n": b64(key.n().to_bytes_be()),
        "e": b64(key.e().to_bytes_be()),
        "d": b64(key.d().to_bytes_be()),
        "p": b64(primes[0].to_bytes_be()),
        "q": b64(primes[1].to_bytes_be()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("generate test KEK")
    }

    #[test]
    fn oaep_wrap_unwrap_round_trip() {
        let kek = test_kek();
        let dek = [7u8; 32];
        let wrapped = wrap_dek(&kek.to_public_key(), &dek).unwrap();
        assert_eq!(unwrap_dek(&kek, &wrapped).unwrap(), dek);
    }

    #[test]
    fn unwrap_with_wrong_kek_fails() {
        let kek = test_kek();
        let other = test_kek();
        let wrapped = wrap_dek(&kek.to_public_key(), &[1u8; 32]).unwrap();
        assert!(unwrap_dek(&other, &wrapped).is_err());
    }

    #[test]
    fn parse_private_jwk_round_trips_through_unwrap() {
        let kek = test_kek();
        let jwk = private_key_to_jwk(&kek);
        let wrapped = wrap_dek(&kek.to_public_key(), &[42u8; 32]).unwrap();
        let parsed = parse_rsa_private_jwk(&jwk).unwrap();
        assert_eq!(unwrap_dek(&parsed, &wrapped).unwrap(), [42u8; 32]);
    }

    #[test]
    fn parse_public_jwk_round_trips_through_unwrap() {
        let kek = test_kek();
        let jwk = private_key_to_jwk(&kek); // contains n,e among the private components
        let pubk = parse_rsa_public_jwk(&jwk).unwrap();
        let wrapped = wrap_dek(&pubk, &[5u8; 32]).unwrap();
        assert_eq!(unwrap_dek(&kek, &wrapped).unwrap(), [5u8; 32]);
    }

    #[test]
    fn parse_public_jwk_accepts_azure_rsa_hsm_kty() {
        let kek = test_kek();
        let jwk = private_key_to_jwk(&kek);
        let pub_jwk = serde_json::json!({
            "kty": "RSA-HSM",
            "n": jwk.get("n").unwrap(),
            "e": jwk.get("e").unwrap(),
        });
        let pubk = parse_rsa_public_jwk(&pub_jwk).unwrap();
        let wrapped = wrap_dek(&pubk, &[9u8; 32]).unwrap();
        assert_eq!(unwrap_dek(&kek, &wrapped).unwrap(), [9u8; 32]);
    }

    #[test]
    fn parse_private_jwk_rejects_non_rsa() {
        let jwk = serde_json::json!({ "kty": "oct", "k": "AAAA" });
        assert!(parse_rsa_private_jwk(&jwk).is_err());
    }

    #[test]
    fn extract_jwk_handles_object_and_string() {
        let inner = serde_json::json!({ "kty": "RSA", "n": "AA", "e": "AQAB" });
        let obj = serde_json::json!({ "key": inner.clone() });
        assert_eq!(extract_released_jwk(&obj).unwrap(), inner);
        let strd = serde_json::json!({ "key": inner.to_string() });
        assert_eq!(extract_released_jwk(&strd).unwrap(), inner);
    }

    #[test]
    fn unwrap_rejects_non_32_byte_payload() {
        let kek = test_kek();
        // Wrap a 16-byte payload — unwrap must reject (DEK must be exactly 32 bytes).
        let wrapped = kek
            .to_public_key()
            .encrypt(
                &mut rand::rngs::OsRng,
                Oaep::new::<sha2::Sha256>(),
                &[0u8; 16],
            )
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(wrapped);
        assert!(unwrap_dek(&kek, &b64).is_err());
    }

    #[test]
    fn ensure_public_only_jwk_rejects_private_components() {
        // A full private JWK (what private_key_to_jwk emits) must be rejected.
        let private = private_key_to_jwk(&test_kek());
        assert!(ensure_public_only_jwk(&private).is_err());
        // Each private field on its own is enough to reject.
        for field in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
            let jwk = serde_json::json!({ "kty": "RSA", "n": "AA", "e": "AQAB", field: "x" });
            assert!(
                ensure_public_only_jwk(&jwk).is_err(),
                "field {field} should be rejected"
            );
        }
        // A genuinely public JWK (n + e only) passes.
        let public = serde_json::json!({ "kty": "RSA", "n": "AA", "e": "AQAB" });
        assert!(ensure_public_only_jwk(&public).is_ok());
    }

    #[test]
    fn dek_fingerprint_is_stable_and_distinguishing() {
        let a = dek_fingerprint(&[7u8; 32]);
        // Stable across calls and non-empty / hex.
        assert_eq!(a, dek_fingerprint(&[7u8; 32]));
        assert_eq!(a.len(), 16); // 8 bytes -> 16 hex chars
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        // A different DEK yields a different fingerprint.
        assert_ne!(a, dek_fingerprint(&[8u8; 32]));
        // It is not a raw hex of the key (domain-separated, truncated).
        assert_ne!(a, hex::encode(&[7u8; 32][..8]));
    }

    #[test]
    fn parse_rejects_modulus_under_2048_bits() {
        // A 1024-bit key must be refused by both parse paths (L2).
        let small = RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).expect("gen 1024-bit key");
        let jwk = private_key_to_jwk(&small);
        let pub_jwk = serde_json::json!({
            "kty": "RSA",
            "n": jwk.get("n").unwrap(),
            "e": jwk.get("e").unwrap(),
        });
        assert!(parse_rsa_public_jwk(&pub_jwk).is_err());
        assert!(parse_rsa_private_jwk(&jwk).is_err());
    }
}
