//! Cryptographic signing-key credentials — a *signer*, not a wallet.
//!
//! TAP custodies a raw private key and, on request, produces a signature over a
//! caller-supplied digest/message. It does **not** manage chain state, nonces,
//! RPC, fees, or transaction broadcasting — a wallet (or any client) builds and
//! encodes the payload, hashes it, asks TAP to sign, and assembles/broadcasts
//! the result itself. The private key never leaves the proxy.
//!
//! This mirrors the JSON-bundle detection approach used for the OAuth/AWS
//! sidecar credentials (`oauth1.rs`, `aws_sigv4.rs`): a credential whose stored
//! value parses as a [`SigningCredential`] bundle is a signing key. Unlike those
//! bundles it is *not* consumed by `/forward` — it is used only by `POST /sign`.
//!
//! Signing semantics (TAP stays chain-agnostic — the client owns the hashing):
//! - **secp256k1 / p256**: `payload` MUST be a pre-computed 32-byte digest.
//! - **ed25519**: `payload` is the message bytes, signed directly.

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// Signature algorithm a signing credential uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// ECDSA over secp256k1, recoverable (r||s||v). EVM/Bitcoin.
    Secp256k1,
    /// Ed25519. Solana, Cosmos, Sui, Aptos, and generic uses.
    Ed25519,
    /// ECDSA over NIST P-256 (secp256r1). Passkeys / AA chains.
    P256,
}

impl Algorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Secp256k1 => "secp256k1",
            Algorithm::Ed25519 => "ed25519",
            Algorithm::P256 => "p256",
        }
    }

    /// Parse a curve name (`secp256k1` | `ed25519` | `p256`) from a request.
    pub fn parse(s: &str) -> Option<Algorithm> {
        match s {
            "secp256k1" => Some(Algorithm::Secp256k1),
            "ed25519" => Some(Algorithm::Ed25519),
            "p256" => Some(Algorithm::P256),
            _ => None,
        }
    }
}

/// Parsed signing-credential value (stored AES-256-GCM-encrypted like any cred).
#[derive(Debug, Clone, Deserialize)]
pub struct SigningCredential {
    pub algorithm: Algorithm,
    /// Raw private scalar, encoded per `key_encoding` (default hex).
    pub private_key: String,
    /// "hex" (default) or "base64".
    #[serde(default)]
    pub key_encoding: Option<String>,
}

/// Try to parse a credential value as a signing-key bundle.
///
/// Returns `None` unless the value is a JSON object with a known `algorithm`
/// and a non-empty `private_key`. The required `algorithm` field keeps this
/// mutually exclusive from the Google/Twitter/AWS/OAuth-CC bundles, so existing
/// `/forward` detection is unaffected.
pub fn parse_signing_credential(cred_value: &str) -> Option<SigningCredential> {
    let parsed: SigningCredential = serde_json::from_str(cred_value).ok()?;
    if parsed.private_key.trim().is_empty() {
        return None;
    }
    Some(parsed)
}

/// The result of a signing operation. Signature and public key are non-secret.
#[derive(Debug, Clone, Serialize)]
pub struct SignOutput {
    pub algorithm: Algorithm,
    /// Full signature, hex. secp256k1: 65-byte r||s||v (v in {0,1}). ed25519/p256: 64-byte.
    pub signature: String,
    /// ECDSA r component, hex (32 bytes). None for ed25519.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
    /// ECDSA s component, hex (32 bytes). None for ed25519.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    /// secp256k1 recovery id (0/1). None for ed25519/p256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
    /// Public key, hex. ECDSA: compressed (SEC1). ed25519: 32-byte key.
    pub public_key: String,
    /// Uncompressed SEC1 public key (65-byte, 0x04…), hex. ECDSA only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_uncompressed: Option<String>,
    /// Derived Ethereum address (0x…), secp256k1 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// Public identity of a generated keypair (returned to the dashboard; the
/// private key is stored encrypted and never returned).
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedKey {
    /// JSON bundle to store as the credential value (contains the private key).
    #[serde(skip)]
    pub bundle: String,
    pub algorithm: Algorithm,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_uncompressed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

impl GeneratedKey {
    /// The public identity to surface to a caller (never the private bundle).
    pub fn public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "algorithm": self.algorithm.as_str(),
            "public_key": self.public_key,
            "public_key_uncompressed": self.public_key_uncompressed,
            "address": self.address,
        })
    }
}

fn decode_key_bytes(cred: &SigningCredential) -> Result<Vec<u8>, String> {
    let enc = cred.key_encoding.as_deref().unwrap_or("hex");
    let s = cred.private_key.trim();
    match enc {
        "hex" => hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .map_err(|e| format!("invalid hex private key: {e}")),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| format!("invalid base64 private key: {e}")),
        other => Err(format!(
            "unsupported key_encoding '{other}' (use 'hex' or 'base64')"
        )),
    }
}

/// Keccak-256 of `bytes`.
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = sha3::Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Derive the Ethereum address (last 20 bytes of keccak256 of the 64-byte
/// uncompressed public key, without the 0x04 SEC1 prefix), 0x-prefixed hex.
fn eth_address(uncompressed_sec1: &[u8]) -> String {
    // uncompressed_sec1 is 65 bytes: 0x04 || X(32) || Y(32).
    let hash = keccak256(&uncompressed_sec1[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// Sign `payload` with the credential. See module docs for per-algorithm
/// payload semantics (digest vs message).
pub fn sign(payload: &[u8], cred: &SigningCredential) -> Result<SignOutput, String> {
    let key_bytes = decode_key_bytes(cred)?;
    match cred.algorithm {
        Algorithm::Secp256k1 => {
            if payload.len() != 32 {
                return Err(format!(
                    "secp256k1 signs a 32-byte digest; got {} bytes. Hash your message first.",
                    payload.len()
                ));
            }
            let sk = k256::ecdsa::SigningKey::from_slice(&key_bytes)
                .map_err(|e| format!("invalid secp256k1 private key: {e}"))?;
            let (sig, recid) = sk
                .sign_prehash_recoverable(payload)
                .map_err(|e| format!("secp256k1 signing failed: {e}"))?;
            let rs = sig.to_bytes(); // 64 bytes r||s
            let v = recid.to_byte();
            let mut full = rs.to_vec();
            full.push(v);
            let vk = sk.verifying_key();
            let compressed = vk.to_encoded_point(true);
            let uncompressed = vk.to_encoded_point(false);
            Ok(SignOutput {
                algorithm: cred.algorithm,
                signature: hex::encode(&full),
                r: Some(hex::encode(&rs[..32])),
                s: Some(hex::encode(&rs[32..])),
                recovery_id: Some(v),
                public_key: hex::encode(compressed.as_bytes()),
                public_key_uncompressed: Some(hex::encode(uncompressed.as_bytes())),
                address: Some(eth_address(uncompressed.as_bytes())),
            })
        }
        Algorithm::P256 => {
            if payload.len() != 32 {
                return Err(format!(
                    "p256 signs a 32-byte digest; got {} bytes. Hash your message first.",
                    payload.len()
                ));
            }
            let sk = p256::ecdsa::SigningKey::from_slice(&key_bytes)
                .map_err(|e| format!("invalid p256 private key: {e}"))?;
            let sig: p256::ecdsa::Signature = sk
                .sign_prehash(payload)
                .map_err(|e| format!("p256 signing failed: {e}"))?;
            let rs = sig.to_bytes(); // 64 bytes r||s
            let vk = sk.verifying_key();
            let compressed = vk.to_encoded_point(true);
            let uncompressed = vk.to_encoded_point(false);
            Ok(SignOutput {
                algorithm: cred.algorithm,
                signature: hex::encode(rs.as_slice()),
                r: Some(hex::encode(&rs.as_slice()[..32])),
                s: Some(hex::encode(&rs.as_slice()[32..])),
                recovery_id: None,
                public_key: hex::encode(compressed.as_bytes()),
                public_key_uncompressed: Some(hex::encode(uncompressed.as_bytes())),
                address: None,
            })
        }
        Algorithm::Ed25519 => {
            let arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
                format!(
                    "ed25519 private key must be 32 bytes, got {}",
                    key_bytes.len()
                )
            })?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
            let sig = sk.sign(payload);
            Ok(SignOutput {
                algorithm: cred.algorithm,
                signature: hex::encode(sig.to_bytes()),
                r: None,
                s: None,
                recovery_id: None,
                public_key: hex::encode(sk.verifying_key().to_bytes()),
                public_key_uncompressed: None,
                address: None,
            })
        }
    }
}

/// Derive the public identity (public key + address) from a stored signing
/// credential, without producing a signature. Used to list/show an end-user's
/// keys by address without ever exposing the private key.
pub fn public_identity(cred: &SigningCredential) -> Result<serde_json::Value, String> {
    let key_bytes = decode_key_bytes(cred)?;
    let (public_key, public_key_uncompressed, address) = match cred.algorithm {
        Algorithm::Secp256k1 => {
            let sk = k256::ecdsa::SigningKey::from_slice(&key_bytes)
                .map_err(|e| format!("invalid secp256k1 private key: {e}"))?;
            let vk = sk.verifying_key();
            let uncompressed = vk.to_encoded_point(false);
            (
                hex::encode(vk.to_encoded_point(true).as_bytes()),
                Some(hex::encode(uncompressed.as_bytes())),
                Some(eth_address(uncompressed.as_bytes())),
            )
        }
        Algorithm::P256 => {
            let sk = p256::ecdsa::SigningKey::from_slice(&key_bytes)
                .map_err(|e| format!("invalid p256 private key: {e}"))?;
            let vk = sk.verifying_key();
            (
                hex::encode(vk.to_encoded_point(true).as_bytes()),
                Some(hex::encode(vk.to_encoded_point(false).as_bytes())),
                None,
            )
        }
        Algorithm::Ed25519 => {
            let arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
                format!(
                    "ed25519 private key must be 32 bytes, got {}",
                    key_bytes.len()
                )
            })?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
            (hex::encode(sk.verifying_key().to_bytes()), None, None)
        }
    };
    Ok(serde_json::json!({
        "algorithm": cred.algorithm.as_str(),
        "public_key": public_key,
        "public_key_uncompressed": public_key_uncompressed,
        "address": address,
    }))
}

/// Generate a fresh keypair in-proxy. Returns the bundle JSON to store (with the
/// private key) plus the public identity to surface to the user.
pub fn generate(algorithm: Algorithm) -> Result<GeneratedKey, String> {
    use rand::rngs::OsRng;
    let (private_hex, public_key, public_key_uncompressed, address) = match algorithm {
        Algorithm::Secp256k1 => {
            let sk = k256::ecdsa::SigningKey::random(&mut OsRng);
            let vk = sk.verifying_key();
            let uncompressed = vk.to_encoded_point(false);
            (
                hex::encode(sk.to_bytes()),
                hex::encode(vk.to_encoded_point(true).as_bytes()),
                Some(hex::encode(uncompressed.as_bytes())),
                Some(eth_address(uncompressed.as_bytes())),
            )
        }
        Algorithm::P256 => {
            let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
            let vk = sk.verifying_key();
            (
                hex::encode(sk.to_bytes()),
                hex::encode(vk.to_encoded_point(true).as_bytes()),
                Some(hex::encode(vk.to_encoded_point(false).as_bytes())),
                None,
            )
        }
        Algorithm::Ed25519 => {
            let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
            (
                hex::encode(sk.to_bytes()),
                hex::encode(sk.verifying_key().to_bytes()),
                None,
                None,
            )
        }
    };
    let bundle = serde_json::json!({
        "algorithm": algorithm.as_str(),
        "private_key": private_hex,
        "key_encoding": "hex",
    })
    .to_string();
    Ok(GeneratedKey {
        bundle,
        algorithm,
        public_key,
        public_key_uncompressed,
        address,
    })
}

/// Validate that an imported bundle is well-formed and the key matches the
/// declared algorithm (derives the public key, which fails on a bad key).
pub fn validate_import(cred: &SigningCredential) -> Result<(), String> {
    // A 32-byte digest of zero is a valid input for the ECDSA curves; for
    // ed25519 any message works. Signing exercises full key parsing.
    let probe = [0u8; 32];
    sign(&probe, cred).map(|_| ())
}

/// Supported pre-image hash functions for the anti-blind-signing guard. These
/// are standard hash *primitives* only — TAP never decodes or interprets the
/// pre-image's meaning (no calldata decoding, tx simulation, or EIP-712 logic).
pub fn hash_preimage(hash_name: &str, preimage: &[u8]) -> Result<[u8; 32], String> {
    // Only 32-byte-output hashes — they must be comparable to the digest being
    // signed (blockchains sign 32-byte digests).
    match hash_name {
        "keccak256" => Ok(keccak256(preimage)),
        "sha256" => Ok(sha2::Sha256::digest(preimage).into()),
        "sha3-256" => Ok(sha3::Sha3_256::digest(preimage).into()),
        other => Err(format!(
            "unsupported pre-image hash '{other}' (use keccak256, sha256, or sha3-256)"
        )),
    }
}

/// The anti-blind-signing check: recompute `hash(preimage)` and require it to
/// equal `digest`. On success the caller may safely show the decoded pre-image
/// to the approver — it is cryptographically bound to what is being signed.
pub fn verify_preimage(preimage: &[u8], hash_name: &str, digest: &[u8]) -> Result<(), String> {
    let computed = hash_preimage(hash_name, preimage)?;
    if computed.as_slice() == digest {
        Ok(())
    } else {
        Err(format!(
            "pre-image does not match digest: {}(preimage) = {} but payload digest = {}",
            hash_name,
            hex::encode(computed),
            hex::encode(digest)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(algorithm: Algorithm, private_hex: &str) -> SigningCredential {
        SigningCredential {
            algorithm,
            private_key: private_hex.to_string(),
            key_encoding: None,
        }
    }

    #[test]
    fn parse_requires_algorithm_and_key() {
        assert!(
            parse_signing_credential(r#"{"algorithm":"ed25519","private_key":"ab"}"#).is_some()
        );
        // Missing algorithm — must not match (keeps it distinct from AWS/OAuth bundles).
        assert!(parse_signing_credential(r#"{"private_key":"ab"}"#).is_none());
        // Empty key.
        assert!(parse_signing_credential(r#"{"algorithm":"ed25519","private_key":""}"#).is_none());
        // Unknown algorithm.
        assert!(parse_signing_credential(r#"{"algorithm":"rsa","private_key":"ab"}"#).is_none());
        // An AWS-shaped bundle must NOT parse as a signing credential.
        assert!(
            parse_signing_credential(r#"{"access_key_id":"x","secret_access_key":"y"}"#).is_none()
        );
    }

    #[test]
    fn secp256k1_sign_recovers_to_signer() {
        // Well-known test private key.
        let pk = "4646464646464646464646464646464646464646464646464646464646464646";
        let c = cred(Algorithm::Secp256k1, pk);
        let digest = [0x11u8; 32];
        let out = sign(&digest, &c).unwrap();
        assert_eq!(out.signature.len(), 130); // 65 bytes hex
        assert!(out.address.is_some());
        let recid = out.recovery_id.unwrap();
        assert!(recid == 0 || recid == 1);

        // Recover the verifying key from the signature and confirm it matches.
        let rs = hex::decode(out.r.as_ref().unwrap()).unwrap();
        let mut sigbytes = rs.clone();
        sigbytes.extend(hex::decode(out.s.as_ref().unwrap()).unwrap());
        let sig = k256::ecdsa::Signature::from_slice(&sigbytes).unwrap();
        let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
            &digest,
            &sig,
            k256::ecdsa::RecoveryId::from_byte(recid).unwrap(),
        )
        .unwrap();
        let expected = k256::ecdsa::SigningKey::from_slice(&hex::decode(pk).unwrap()).unwrap();
        assert_eq!(&recovered, expected.verifying_key());
    }

    #[test]
    fn secp256k1_eth_address_is_well_known() {
        // privkey 0x4646...46 → address 0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F
        let pk = "4646464646464646464646464646464646464646464646464646464646464646";
        let out = sign(&[0u8; 32], &cred(Algorithm::Secp256k1, pk)).unwrap();
        assert_eq!(
            out.address.unwrap().to_lowercase(),
            "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
        );
    }

    #[test]
    fn ed25519_sign_verifies() {
        let gen = generate(Algorithm::Ed25519).unwrap();
        let c = parse_signing_credential(&gen.bundle).unwrap();
        let msg = b"hello wallet";
        let out = sign(msg, &c).unwrap();
        let sig =
            ed25519_dalek::Signature::from_slice(&hex::decode(&out.signature).unwrap()).unwrap();
        let vk_bytes: [u8; 32] = hex::decode(&out.public_key).unwrap().try_into().unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap();
        use ed25519_dalek::Verifier;
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn p256_sign_verifies() {
        let gen = generate(Algorithm::P256).unwrap();
        let c = parse_signing_credential(&gen.bundle).unwrap();
        let digest = [0x22u8; 32];
        let out = sign(&digest, &c).unwrap();
        let sig =
            p256::ecdsa::Signature::from_slice(&hex::decode(&out.signature).unwrap()).unwrap();
        let pub_bytes = hex::decode(&out.public_key).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_bytes).unwrap();
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        assert!(vk.verify_prehash(&digest, &sig).is_ok());
    }

    #[test]
    fn ecdsa_rejects_non_digest_payload() {
        let gen = generate(Algorithm::Secp256k1).unwrap();
        let c = parse_signing_credential(&gen.bundle).unwrap();
        assert!(sign(b"short", &c).is_err());
    }

    #[test]
    fn generate_then_sign_roundtrips_all_curves() {
        for alg in [Algorithm::Secp256k1, Algorithm::Ed25519, Algorithm::P256] {
            let gen = generate(alg).unwrap();
            let c = parse_signing_credential(&gen.bundle).unwrap();
            let payload = if alg == Algorithm::Ed25519 {
                b"msg".to_vec()
            } else {
                vec![0x33u8; 32]
            };
            assert!(sign(&payload, &c).is_ok(), "sign failed for {alg:?}");
        }
    }

    #[test]
    fn preimage_guard_matches_and_mismatches() {
        let preimage = b"transfer 1 ETH to alice";
        let digest = keccak256(preimage);
        assert!(verify_preimage(preimage, "keccak256", &digest).is_ok());
        assert!(verify_preimage(b"different", "keccak256", &digest).is_err());
        // sha256 of same preimage must not equal the keccak digest.
        assert!(verify_preimage(preimage, "sha256", &digest).is_err());
    }
}
