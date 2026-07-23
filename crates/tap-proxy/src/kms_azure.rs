//! Azure Secure Key Release (SKR) KMS backend. Compiled only with --features enclave
//! and selected at runtime via `TAP_KMS_BACKEND=azure-skr`.
//!
//! # Design (locked in internal-docs#1187, "KEK/DEK envelope" comment)
//!
//! This is a **KEK/DEK envelope**, not a literal swap of Evervault's crypto endpoints:
//!
//! - **DEK (master key)** — the existing per-enclave 32-byte key that encrypts the
//!   credential DB via local AES-256-GCM. It is *preserved per service* across the
//!   Evervault → Azure move, which is what gives migration continuity + rollback.
//! - **KEK** — a per-platform, attestation-gated RSA-HSM key living in a Premium Key
//!   Vault. It only ever wraps/unwraps the DEK; it is never used to encrypt the DB.
//!
//! `load_encryption_key()` flow:
//!   1. Read the wrapped-DEK ciphertext from the Postgres `config` table (same
//!      `encryption_key_ciphertext` row shape as the Evervault backend).
//!   2. Call the **colocated SKR sidecar** `/key/release` (localhost) — the sidecar
//!      attests to MAA and, iff the CCE-policy hash matches the Key Vault release policy,
//!      returns the released KEK (an RSA private key, as a JWK).
//!   3. **Unwrap the DEK locally** with RSA-OAEP-SHA256 (see [`crate::skr`]) — the key
//!      material is used in-process, never sent back to Key Vault (this is *release*, not
//!      crypto-ops, so attestation gating is preserved).
//!   4. Hand the 32-byte DEK to the unchanged downstream AES-256-GCM path.
//!
//! Greenfield (TAP staging, never bootstrapped) has no stored DEK: we generate a fresh
//! 32-byte DEK, RSA-OAEP-wrap it with the KEK public key, and store it. For a *prod*
//! migration the DEK is pre-populated by the one-time re-wrap tool (`rewrap_dek` bin) so
//! continuity holds — set `TAP_SKR_REQUIRE_MIGRATED_DEK=1` there to refuse fresh
//! generation (a guard against silently clobbering a DB encrypted under the old DEK).
//!
//! # Why local unwrap (release) and not Key Vault encrypt/decrypt
//! Key Vault crypto-ops are gated only by RBAC/managed-identity — anyone holding the
//! identity could decrypt. SKR releases the key *only* to the attested image (the CCE
//! hash is hardware-proven via the SEV-SNP `x-ms-sevsnpvm-hostdata` claim), preserving
//! the §5 custody property the spike (#1178) validated.

use tap_core::error::AgentSecError;

use base64::Engine as _;
use rsa::RsaPrivateKey;

use super::{
    config_get, config_set, config_set_if_absent, dek_key_checked, has_encrypted_data,
    record_dek_backend_tag,
};
use crate::skr;

/// Canonical backend name for this backend (matches `TAP_KMS_BACKEND=azure-skr`). Used to
/// namespace the wrapped-DEK config key and tag it with its owning backend (H2).
const AZURE_SKR_BACKEND: &str = "azure-skr";

/// Default localhost endpoint of the SKR sidecar in the ACI container group.
/// The sidecar (`mcr.microsoft.com/aci/skr`) shares the group's network namespace, so it
/// is reachable on loopback. Override with `SKR_SIDECAR_URL`.
const DEFAULT_SKR_SIDECAR_URL: &str = "http://127.0.0.1:8080";

/// Process-wide cache of the released + unwrapped DEK. The DEK is identical for the whole
/// process lifetime, so we release the KEK from the sidecar **once** rather than on every
/// `load_secret` call (TAP loads the key + 5 secrets at boot).
static DEK_CACHE: tokio::sync::OnceCell<[u8; 32]> = tokio::sync::OnceCell::const_new();

/// Azure SKR backend configuration, read from the environment at boot.
pub(super) struct AzureSkrBackend {
    /// SKR sidecar base URL (e.g. `http://127.0.0.1:8080`).
    sidecar_url: String,
    /// MAA attestation provider endpoint (e.g. `sharedeus.eus.attest.azure.net`).
    maa_endpoint: String,
    /// Key Vault data-plane endpoint (e.g. `kv-tap-spike-1178.vault.azure.net`).
    akv_endpoint: String,
    /// Name (kid) of the exportable RSA-HSM KEK in the vault.
    kek_key_id: String,
    /// When true, refuse to generate a fresh DEK if none is stored (prod migration safety).
    require_migrated_dek: bool,
}

impl AzureSkrBackend {
    pub(super) fn from_env() -> Result<Self, AgentSecError> {
        let env = |k: &str| -> Result<String, AgentSecError> {
            std::env::var(k).map_err(|_| {
                AgentSecError::Config(format!("{k} is required for the azure-skr KMS backend"))
            })
        };
        Ok(Self {
            sidecar_url: std::env::var("SKR_SIDECAR_URL")
                .unwrap_or_else(|_| DEFAULT_SKR_SIDECAR_URL.to_string()),
            maa_endpoint: env("MAA_ENDPOINT")?,
            akv_endpoint: env("AKV_ENDPOINT")?,
            kek_key_id: env("KEK_KEY_ID")?,
            require_migrated_dek: parse_bool_env("TAP_SKR_REQUIRE_MIGRATED_DEK")?,
        })
    }

    /// Release the KEK (an RSA private key) from the SKR sidecar.
    ///
    /// Mirrors the Microsoft SKR sidecar contract: `POST {sidecar}/key/release` with
    /// `{maa_endpoint, akv_endpoint, kid}`, responding `{"key": <JWK>}`. The sidecar
    /// performs the SEV-SNP attestation → MAA → Key Vault `keys/release` dance and only
    /// succeeds when the running image's CCE hash is authorized in the release policy.
    async fn release_kek(&self) -> Result<RsaPrivateKey, AgentSecError> {
        let client =
            tap_core::http_client::build_client(tap_core::http_client::ClientRoute::Direct)
                .map_err(|e| {
                    AgentSecError::Encryption(format!("Failed to create HTTP client: {e}"))
                })?;

        let resp = client
            .post(format!(
                "{}/key/release",
                self.sidecar_url.trim_end_matches('/')
            ))
            // Bound boot time: a hung sidecar must not wedge startup indefinitely.
            .timeout(std::time::Duration::from_secs(30))
            .json(&serde_json::json!({
                "maa_endpoint": self.maa_endpoint,
                "akv_endpoint": self.akv_endpoint,
                "kid": self.kek_key_id,
            }))
            .send()
            .await
            .map_err(|e| AgentSecError::Encryption(format!("SKR sidecar release failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // A 403 here is the security property working: this image's CCE hash is not
            // authorized in the Key Vault release policy.
            return Err(AgentSecError::Encryption(format!(
                "SKR sidecar /key/release returned {status}: {body}"
            )));
        }

        let body: serde_json::Value = resp.json().await.map_err(|e| {
            AgentSecError::Encryption(format!("Failed to parse SKR release response: {e}"))
        })?;
        let jwk = skr::extract_released_jwk(&body)?;
        skr::parse_rsa_private_jwk(&jwk)
    }

    /// Release the KEK once and resolve the 32-byte DEK, caching it process-wide.
    async fn get_or_load_dek(&self, pool: &sqlx::PgPool) -> Result<[u8; 32], AgentSecError> {
        DEK_CACHE
            .get_or_try_init(|| async { self.load_dek(pool).await })
            .await
            .copied()
    }

    /// Resolve the DEK: unwrap the stored ciphertext, or (greenfield) generate + store one.
    ///
    /// Generating a fresh DEK is gated so it can never orphan an existing encrypted DB:
    ///  1. **Structural guard** — refuse if `credentials` already holds encrypted data
    ///     (data under a prior DEK we don't have). Derived from DB state, so it protects
    ///     against irrecoverable loss *without* relying on an operator-set env var.
    ///  2. **Defense-in-depth flag** — `TAP_SKR_REQUIRE_MIGRATED_DEK=1` refuses generation
    ///     even on an empty DB (a prod instance that must always be migrated, before any
    ///     data is written).
    ///  3. **Atomic claim** — the wrapped-DEK row is write-once; if a second instance won
    ///     the insert race, adopt *its* DEK so all instances converge on one key.
    async fn load_dek(&self, pool: &sqlx::PgPool) -> Result<[u8; 32], AgentSecError> {
        // Backend-namespaced DEK key + flip refusal (H2): azure-skr never reads the Evervault
        // backend's legacy row, and a stored ownership-tag mismatch is rejected up front.
        let dek_key = dek_key_checked(pool, AZURE_SKR_BACKEND).await?;

        if let Some(wrapped) = config_get(pool, &dek_key).await? {
            tracing::info!("azure-skr: releasing KEK to unwrap existing DEK");
            let kek = self.release_kek().await?;
            let dek = skr::unwrap_dek(&kek, &wrapped)?;
            record_dek_backend_tag(pool, AZURE_SKR_BACKEND, &dek_key).await?;
            return Ok(dek);
        }

        // (1) Structural guard — the irrecoverability backstop, independent of any env var.
        //     Covers both `credentials` rows and DEK-sealed `config` secrets (H1).
        if has_encrypted_data(pool).await? {
            return Err(AgentSecError::Encryption(
                "azure-skr: no wrapped DEK in config, but the database already holds data \
                 encrypted under a prior DEK (a credentials row or a sealed config secret) — \
                 refusing to generate a fresh DEK (it would permanently orphan that data). Run \
                 the rewrap_dek migration to install the original DEK."
                    .to_string(),
            ));
        }

        // (2) Explicit prod marker — refuse generation even on an empty DB.
        if self.require_migrated_dek {
            return Err(AgentSecError::Encryption(
                "azure-skr: no wrapped DEK in config and TAP_SKR_REQUIRE_MIGRATED_DEK=1 \
                 (run the rewrap_dek migration before first boot to preserve the existing DEK)"
                    .to_string(),
            ));
        }

        tracing::info!(
            "azure-skr: no stored DEK and DB is empty — generating a fresh one (greenfield)"
        );
        let kek = self.release_kek().await?;
        let mut dek = [0u8; 32];
        {
            use rand::RngCore as _;
            rand::rngs::OsRng.fill_bytes(&mut dek);
        }
        let wrapped = skr::wrap_dek(&kek.to_public_key(), &dek)?;

        // (3) Claim the write-once row atomically. If another instance booted concurrently
        // and won the insert, adopt ITS stored DEK rather than our just-generated one, so
        // every instance converges on a single key.
        if config_set_if_absent(pool, &dek_key, &wrapped).await? {
            record_dek_backend_tag(pool, AZURE_SKR_BACKEND, &dek_key).await?;
            tracing::info!("azure-skr: fresh DEK generated, wrapped with KEK, and stored");
            Ok(dek)
        } else {
            tracing::warn!("azure-skr: lost the first-boot DEK race; adopting the stored DEK");
            let winner = config_get(pool, &dek_key).await?.ok_or_else(|| {
                AgentSecError::Encryption(
                    "azure-skr: DEK row vanished after a lost claim".to_string(),
                )
            })?;
            record_dek_backend_tag(pool, AZURE_SKR_BACKEND, &dek_key).await?;
            skr::unwrap_dek(&kek, &winner)
        }
    }
}

/// Parse a boolean env var strictly: unset/empty ⇒ false; `1/true/yes/on` ⇒ true;
/// `0/false/no/off` ⇒ false; anything else is a hard error (fail-closed, never a silent
/// fall-through to `false` on a custody-critical flag).
fn parse_bool_env(name: &str) -> Result<bool, AgentSecError> {
    match std::env::var(name) {
        Err(_) => Ok(false),
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "" => Ok(false),
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(AgentSecError::Config(format!(
                "{name} must be a boolean (1/0/true/false/yes/no/on/off), got '{other}'"
            ))),
        },
    }
}

#[async_trait::async_trait]
impl super::KmsBackend for AzureSkrBackend {
    async fn load_encryption_key(&self, pool: &sqlx::PgPool) -> Result<[u8; 32], AgentSecError> {
        self.get_or_load_dek(pool).await
    }

    /// Secrets (telegram/matrix) are sealed with the **DEK** via the existing local
    /// AES-256-GCM path — not RSA-wrapped with the KEK.
    ///
    /// Design fork (not pinned by #1187, which only specifies the DEK envelope): sealing
    /// secrets under the DEK avoids RSA-OAEP's plaintext size limit (a 2048-bit KEK caps
    /// at ~190 bytes, smaller than some Matrix access tokens), keeps a single trust root
    /// (the KEK already protects the DEK), and reuses the unchanged AES-GCM code. Stored
    /// form: base64(nonce(12) || ciphertext). Flagged for review.
    async fn load_secret(
        &self,
        pool: &sqlx::PgPool,
        env_var: &str,
        db_key: &str,
    ) -> Result<String, AgentSecError> {
        let dek = self.get_or_load_dek(pool).await?;
        let azure_db_key = azure_secret_key(db_key);

        if let Some(stored) = config_get(pool, &azure_db_key).await? {
            tracing::info!(key = %azure_db_key, "azure-skr: decrypting secret with DEK");
            return aes_unseal(&dek, &stored);
        }

        let plaintext = std::env::var(env_var).map_err(|_| {
            AgentSecError::Encryption(format!(
                "{env_var} not set and no Azure-encrypted value in Postgres for '{azure_db_key}'"
            ))
        })?;
        tracing::info!(key = %azure_db_key, legacy_key = %db_key, "azure-skr: sealing secret from env var with DEK");
        let sealed = aes_seal(&dek, &plaintext)?;
        config_set(pool, &azure_db_key, &sealed).await?;
        Ok(plaintext)
    }

    async fn load_optional_secret(
        &self,
        pool: &sqlx::PgPool,
        env_var: &str,
        db_key: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let azure_db_key = azure_secret_key(db_key);
        if let Some(stored) = config_get(pool, &azure_db_key).await? {
            let dek = self.get_or_load_dek(pool).await?;
            tracing::info!(key = %azure_db_key, "azure-skr: decrypting optional secret with DEK");
            return aes_unseal(&dek, &stored).map(Some);
        }

        let Some(plaintext) = std::env::var(env_var).ok().filter(|v| !v.is_empty()) else {
            return Ok(None);
        };

        let dek = self.get_or_load_dek(pool).await?;
        tracing::info!(key = %azure_db_key, legacy_key = %db_key, "azure-skr: sealing optional secret from env var with DEK");
        let sealed = aes_seal(&dek, &plaintext)?;
        config_set(pool, &azure_db_key, &sealed).await?;
        Ok(Some(plaintext))
    }
}

fn azure_secret_key(db_key: &str) -> String {
    format!("{db_key}_azure_skr")
}

/// AES-256-GCM seal of a secret string with the DEK → base64(std) of nonce(12)||ciphertext.
fn aes_seal(dek: &[u8; 32], plaintext: &str) -> Result<String, AgentSecError> {
    let (ciphertext, nonce) = crate::crypto::encrypt(dek, plaintext.as_bytes())?;
    let mut blob = nonce; // 12 bytes
    blob.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(blob))
}

/// Reverse of [`aes_seal`].
fn aes_unseal(dek: &[u8; 32], stored_b64: &str) -> Result<String, AgentSecError> {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(stored_b64.trim())
        .map_err(|e| AgentSecError::Encryption(format!("Invalid base64 sealed secret: {e}")))?;
    if blob.len() < 12 {
        return Err(AgentSecError::Encryption(
            "sealed secret shorter than nonce".to_string(),
        ));
    }
    let (nonce, ciphertext) = blob.split_at(12);
    let plaintext = crate::crypto::decrypt(dek, ciphertext, nonce)?;
    String::from_utf8(plaintext)
        .map_err(|e| AgentSecError::Encryption(format!("sealed secret is not valid UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::super::dek_ciphertext_key;
    use super::*;
    use crate::skr::private_key_to_jwk;
    use rsa::RsaPrivateKey;

    fn test_kek() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("generate test KEK")
    }

    #[test]
    fn parse_bool_env_is_strict() {
        let k = "TAP_TEST_SKR_BOOL_GUARD";
        std::env::remove_var(k);
        assert!(!parse_bool_env(k).unwrap()); // unset → false
        std::env::set_var(k, "1");
        assert!(parse_bool_env(k).unwrap());
        std::env::set_var(k, " TRUE ");
        assert!(parse_bool_env(k).unwrap());
        std::env::set_var(k, "off");
        assert!(!parse_bool_env(k).unwrap());
        std::env::set_var(k, ""); // empty → false
        assert!(!parse_bool_env(k).unwrap());
        std::env::set_var(k, "maybe"); // unrecognized → hard error (fail-closed)
        assert!(parse_bool_env(k).is_err());
        std::env::remove_var(k);
    }

    #[test]
    fn aes_seal_unseal_round_trip() {
        let dek = [9u8; 32];
        let sealed = aes_seal(&dek, "matrix-access-token-xyz").unwrap();
        assert_eq!(
            aes_unseal(&dek, &sealed).unwrap(),
            "matrix-access-token-xyz"
        );
    }

    #[test]
    fn aes_unseal_wrong_dek_fails() {
        let sealed = aes_seal(&[1u8; 32], "secret").unwrap();
        assert!(aes_unseal(&[2u8; 32], &sealed).is_err());
    }

    /// Spawn a mock SKR sidecar that releases `kek` as a JWK from `/key/release`.
    /// Returns the base URL.
    async fn spawn_release_sidecar(kek: &RsaPrivateKey) -> String {
        use axum::{routing::post, Json, Router};
        let jwk = private_key_to_jwk(kek);
        let app = Router::new().route(
            "/key/release",
            post(move || {
                let jwk = jwk.clone();
                async move { Json(serde_json::json!({ "key": jwk })) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn backend_for(sidecar_url: String, require_migrated_dek: bool) -> AzureSkrBackend {
        AzureSkrBackend {
            sidecar_url,
            maa_endpoint: "test.attest.azure.net".to_string(),
            akv_endpoint: "test.vault.azure.net".to_string(),
            kek_key_id: "test-kek".to_string(),
            require_migrated_dek,
        }
    }

    /// Fresh, schema-reset test database with just the `config` table. Mirrors the
    /// integration-test convention (`DROP SCHEMA public`); shares the test Postgres, so
    /// these tests are not parallel-safe — run with `--test-threads=1` (as the repo does).
    async fn fresh_db() -> sqlx::PgPool {
        let db_url = std::env::var("POSTGRES_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://tap:tap@localhost:5434/tap".to_string());
        let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    /// Release-and-unwrap half against a mocked SKR sidecar (no DB): the original DEK
    /// returns through `release_kek` + `skr::unwrap_dek`, exactly as `load_dek` does.
    #[tokio::test]
    async fn mocked_sidecar_release_then_unwrap_returns_dek() {
        let kek = test_kek();
        let dek = [123u8; 32];
        let wrapped = skr::wrap_dek(&kek.to_public_key(), &dek).unwrap();
        let backend = backend_for(spawn_release_sidecar(&kek).await, false);

        let released = backend.release_kek().await.unwrap();
        assert_eq!(skr::unwrap_dek(&released, &wrapped).unwrap(), dek);
    }

    /// A 403 from the sidecar (this image's CCE hash not authorized) must surface as an
    /// error — the security property, proven in the negative.
    #[tokio::test]
    async fn mocked_sidecar_denied_release_errors() {
        use axum::{http::StatusCode, routing::post, Router};

        let app = Router::new().route(
            "/key/release",
            post(|| async {
                (
                    StatusCode::FORBIDDEN,
                    "Target environment attestation does not meet key release requirements",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let backend = backend_for(format!("http://{addr}"), false);
        let err = backend.release_kek().await.unwrap_err();
        assert!(format!("{err}").contains("403"));
    }

    // ── DB-backed orchestration tests (load_dek). Require the test Postgres; run with
    //    --test-threads=1. These cover the custody-critical generate/unwrap/refuse logic. ──

    /// Greenfield (empty DB): generates a fresh DEK, stores it wrapped, and re-resolves the
    /// SAME DEK on a second call (never regenerates once stored).
    #[tokio::test]
    async fn load_dek_greenfield_generates_then_unwraps_stably() {
        let pool = fresh_db().await;
        let kek = test_kek();
        let backend = backend_for(spawn_release_sidecar(&kek).await, false);

        let dek = backend.load_dek(&pool).await.unwrap();
        // The stored ciphertext (under the backend-namespaced key) unwraps to the same DEK.
        let dek_key = dek_ciphertext_key(AZURE_SKR_BACKEND);
        let stored = config_get(&pool, &dek_key).await.unwrap().unwrap();
        assert_eq!(skr::unwrap_dek(&kek, &stored).unwrap(), dek);
        // The DEK row is tagged with the owning backend (H2).
        assert_eq!(
            config_get(&pool, &format!("{dek_key}.backend"))
                .await
                .unwrap()
                .unwrap(),
            AZURE_SKR_BACKEND
        );
        // The Evervault legacy key is untouched (namespacing).
        assert!(config_get(&pool, "encryption_key_ciphertext")
            .await
            .unwrap()
            .is_none());
        // A second resolve takes the unwrap path and returns the same DEK (no regeneration).
        assert_eq!(backend.load_dek(&pool).await.unwrap(), dek);
    }

    /// A pre-populated wrapped DEK (the migration case) is released + unwrapped, not regenerated.
    #[tokio::test]
    async fn load_dek_unwraps_pre_migrated_dek() {
        let pool = fresh_db().await;
        let kek = test_kek();
        let migrated = [77u8; 32];
        let wrapped = skr::wrap_dek(&kek.to_public_key(), &migrated).unwrap();
        // Pre-migrated DEK lands under the backend-namespaced key.
        config_set(&pool, &dek_ciphertext_key(AZURE_SKR_BACKEND), &wrapped)
            .await
            .unwrap();

        let backend = backend_for(spawn_release_sidecar(&kek).await, true); // require_migrated ok
        assert_eq!(backend.load_dek(&pool).await.unwrap(), migrated);
    }

    /// Structural guard: existing encrypted data + no stored DEK ⇒ refuse to generate
    /// (would orphan the DB), regardless of the env flag.
    #[tokio::test]
    async fn load_dek_refuses_when_encrypted_data_exists() {
        let pool = fresh_db().await;
        sqlx::query("CREATE TABLE credentials (encrypted_value BYTEA)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO credentials (encrypted_value) VALUES ($1)")
            .bind(vec![1u8, 2, 3])
            .execute(&pool)
            .await
            .unwrap();
        let kek = test_kek();
        let backend = backend_for(spawn_release_sidecar(&kek).await, false);

        let err = backend.load_dek(&pool).await.unwrap_err();
        assert!(format!("{err}").contains("orphan"));
        // And nothing was written under the backend-namespaced key.
        assert!(config_get(&pool, &dek_ciphertext_key(AZURE_SKR_BACKEND))
            .await
            .unwrap()
            .is_none());
    }

    /// H1: a fresh DEK is refused when only DEK-sealed *config secrets* exist (no credentials
    /// row). This is the surface the original guard missed — generating a fresh DEK would
    /// permanently orphan the sealed Telegram/Matrix secrets.
    #[tokio::test]
    async fn load_dek_refuses_when_only_config_secret_exists() {
        let pool = fresh_db().await;
        // A sealed secret in `config`, but NO credentials table at all.
        config_set(&pool, "telegram_bot_token_ciphertext", "sealed-blob-base64")
            .await
            .unwrap();
        let kek = test_kek();
        let backend = backend_for(spawn_release_sidecar(&kek).await, false);

        let err = backend.load_dek(&pool).await.unwrap_err();
        assert!(format!("{err}").contains("orphan"));
        // No DEK was generated/stored.
        assert!(config_get(&pool, &dek_ciphertext_key(AZURE_SKR_BACKEND))
            .await
            .unwrap()
            .is_none());
    }

    /// H1 (unit): `has_encrypted_data` is true when only a DEK-sealed config secret exists,
    /// even with no `credentials` table.
    #[tokio::test]
    async fn has_encrypted_data_detects_config_secrets() {
        let pool = fresh_db().await;
        assert!(!has_encrypted_data(&pool).await.unwrap());
        config_set(&pool, "matrix_access_token_ciphertext", "sealed")
            .await
            .unwrap();
        assert!(has_encrypted_data(&pool).await.unwrap());
    }

    /// H2: a stored DEK whose ownership tag names a different backend is refused on load
    /// (the loud, by-design failure for a TAP_KMS_BACKEND flip / mismatched key material).
    #[tokio::test]
    async fn load_dek_refuses_on_backend_tag_mismatch() {
        let pool = fresh_db().await;
        let kek = test_kek();
        let dek_key = dek_ciphertext_key(AZURE_SKR_BACKEND);
        // A wrapped DEK under azure-skr's key, but tagged as belonging to evervault.
        let wrapped = skr::wrap_dek(&kek.to_public_key(), &[5u8; 32]).unwrap();
        config_set(&pool, &dek_key, &wrapped).await.unwrap();
        config_set(&pool, &format!("{dek_key}.backend"), "evervault")
            .await
            .unwrap();

        let backend = backend_for(spawn_release_sidecar(&kek).await, false);
        let err = backend.load_dek(&pool).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("evervault") && msg.contains("azure-skr"),
            "got: {msg}"
        );
    }

    /// Explicit prod marker refuses generation even on an empty DB.
    #[tokio::test]
    async fn load_dek_refuses_when_require_migrated_set() {
        let pool = fresh_db().await;
        let kek = test_kek();
        let backend = backend_for(spawn_release_sidecar(&kek).await, true);
        assert!(backend.load_dek(&pool).await.is_err());
    }

    /// `has_encrypted_data` returns false when the credentials table is absent (greenfield)
    /// and true once a row with a ciphertext exists.
    #[tokio::test]
    async fn has_encrypted_data_reflects_db_state() {
        let pool = fresh_db().await;
        assert!(!has_encrypted_data(&pool).await.unwrap()); // no credentials table yet
        sqlx::query("CREATE TABLE credentials (encrypted_value BYTEA)")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!has_encrypted_data(&pool).await.unwrap()); // empty
        sqlx::query("INSERT INTO credentials (encrypted_value) VALUES ($1)")
            .bind(vec![9u8])
            .execute(&pool)
            .await
            .unwrap();
        assert!(has_encrypted_data(&pool).await.unwrap());
    }

    /// Write-once claim: the second insert under the same key is a no-op and the original
    /// value survives (the atomic-claim primitive behind the first-boot race fix).
    #[tokio::test]
    async fn config_set_if_absent_is_write_once() {
        let pool = fresh_db().await;
        assert!(config_set_if_absent(&pool, "k", "v1").await.unwrap());
        assert!(!config_set_if_absent(&pool, "k", "v2").await.unwrap());
        assert_eq!(config_get(&pool, "k").await.unwrap().unwrap(), "v1");
    }
}
