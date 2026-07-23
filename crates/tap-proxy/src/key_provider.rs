//! Encryption key provider: abstracts key source between standard (env var)
//! and enclave (hardware TEE) modes.
//!
//! Standard mode: reads TAP_ENCRYPTION_KEY from environment.
//! Enclave mode (--features enclave): derives key from an in-enclave KMS
//! so the plaintext key never exists outside the trusted execution environment.

use tap_core::error::AgentSecError;

#[cfg(feature = "enclave")]
#[path = "key_provider_enclave.rs"]
mod enclave;

/// Load the 32-byte encryption key from the appropriate source.
///
/// Standard mode: reads TAP_ENCRYPTION_KEY env var (64 hex chars).
/// Enclave mode: derives key inside the TEE via the in-enclave KMS.
pub async fn load_encryption_key() -> Result<[u8; 32], AgentSecError> {
    #[cfg(feature = "enclave")]
    {
        return enclave::load_from_kms().await;
    }
    #[cfg(not(feature = "enclave"))]
    load_from_env()
}

fn load_from_env() -> Result<[u8; 32], AgentSecError> {
    let hex_str = std::env::var("TAP_ENCRYPTION_KEY").map_err(|_| {
        AgentSecError::Encryption("TAP_ENCRYPTION_KEY env var is required".to_string())
    })?;
    crate::crypto::parse_encryption_key(&hex_str)
}

/// Load a string secret from the appropriate source.
///
/// Standard mode: reads from the given env var.
/// Enclave mode: reads ciphertext from persistent storage, decrypts inside
/// the TEE. Bootstraps from the env var on first run so the env var can
/// be removed after initial deployment.
pub async fn load_secret(env_var: &str, db_key: &str) -> Result<String, AgentSecError> {
    #[cfg(feature = "enclave")]
    {
        return enclave::load_secret_from_kms(env_var, db_key).await;
    }
    #[cfg(not(feature = "enclave"))]
    {
        let _ = db_key;
        std::env::var(env_var)
            .map_err(|_| AgentSecError::Encryption(format!("{env_var} env var is required")))
    }
}

/// Load an optional string secret from the appropriate source.
///
/// Enclave mode checks persistent sealed storage first, then bootstraps from a
/// non-empty env var. If neither exists, returns `None` instead of forcing
/// callers to use a placeholder env var as a feature flag.
pub async fn load_optional_secret(
    env_var: &str,
    db_key: &str,
) -> Result<Option<String>, AgentSecError> {
    #[cfg(feature = "enclave")]
    {
        return enclave::load_optional_secret_from_kms(env_var, db_key).await;
    }
    #[cfg(not(feature = "enclave"))]
    {
        let _ = db_key;
        Ok(std::env::var(env_var).ok().filter(|v| !v.is_empty()))
    }
}

/// Default config-table key under which the startup re-wrap hook persists the wrapped DEK.
#[cfg(feature = "enclave")]
const DEFAULT_REWRAP_OUTPUT_KEY: &str = "migration_wrapped_dek";

/// Core of the startup re-wrap (option b): wrap a known plaintext DEK under the Azure KEK's
/// public key and persist the base64 ciphertext to the `config` table under `output_key`.
///
/// Factored out of [`run_startup_rewrap`] so it is unit-testable with a known DEK + a real
/// test pool, without standing up the full Evervault `load_encryption_key()` path (which,
/// under `--features enclave`, always goes through the in-enclave KMS). The plaintext DEK is
/// an input here; the only output that crosses any trust boundary is the wrapped ciphertext
/// (non-secret — only the attested Azure image can release the KEK private key to unwrap it).
#[cfg(feature = "enclave")]
async fn rewrap_dek_with(
    kek_pub: &rsa::RsaPublicKey,
    dek: &[u8; 32],
    pool: &sqlx::PgPool,
    output_key: &str,
) -> Result<String, AgentSecError> {
    let wrapped = crate::skr::wrap_dek(kek_pub, dek)?;
    if !enclave::config_set_if_absent(pool, output_key, &wrapped).await? {
        return Err(AgentSecError::Encryption(format!(
            "startup re-wrap refused to overwrite existing config key '{output_key}'"
        )));
    }
    Ok(wrapped)
}

#[cfg(feature = "enclave")]
async fn seal_azure_config_secret(
    dek: &[u8; 32],
    pool: &sqlx::PgPool,
    env_var: &str,
    legacy_key: &str,
) -> Result<bool, AgentSecError> {
    let Some(plaintext) = load_optional_secret(env_var, legacy_key).await? else {
        tracing::info!(
            legacy_key = %legacy_key,
            "Startup Azure config-secret export skipped; no source secret found"
        );
        return Ok(false);
    };

    let azure_key = format!("{legacy_key}_azure_skr");
    if enclave::config_get(pool, &azure_key).await?.is_some() {
        tracing::info!(
            legacy_key = %legacy_key,
            azure_key = %azure_key,
            "Startup Azure config-secret export already complete"
        );
        return Ok(false);
    }

    let sealed = aes_seal_with_dek(dek, &plaintext)?;
    if enclave::config_set_if_absent(pool, &azure_key, &sealed).await? {
        tracing::info!(
            legacy_key = %legacy_key,
            azure_key = %azure_key,
            "Startup Azure config-secret export complete"
        );
        Ok(true)
    } else {
        tracing::info!(
            legacy_key = %legacy_key,
            azure_key = %azure_key,
            "Startup Azure config-secret export raced with another writer"
        );
        Ok(false)
    }
}

#[cfg(feature = "enclave")]
fn aes_seal_with_dek(dek: &[u8; 32], plaintext: &str) -> Result<String, AgentSecError> {
    use base64::Engine as _;

    let (ciphertext, nonce) = crate::crypto::encrypt(dek, plaintext.as_bytes())?;
    let mut blob = nonce;
    blob.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(blob))
}

#[cfg(feature = "enclave")]
async fn export_config_secrets_for_azure(
    dek: &[u8; 32],
    pool: &sqlx::PgPool,
) -> Result<usize, AgentSecError> {
    let secrets = [
        ("TELEGRAM_BOT_TOKEN", "telegram_bot_token_ciphertext"),
        ("TELEGRAM_CHAT_ID", "telegram_chat_id_ciphertext"),
        ("MATRIX_HOMESERVER_URL", "matrix_homeserver_url_ciphertext"),
        ("MATRIX_ACCESS_TOKEN", "matrix_access_token_ciphertext"),
        ("MATRIX_ROOM_ID", "matrix_room_id_ciphertext"),
    ];

    let mut written = 0usize;
    for (env_var, legacy_key) in secrets {
        if seal_azure_config_secret(dek, pool, env_var, legacy_key).await? {
            written += 1;
        }
    }
    Ok(written)
}

/// Startup DEK re-wrap migration hook (option b of internal-docs#1187).
///
/// Runs INSIDE the source (Evervault) enclave, where the plaintext DEK already lives. It
/// wraps that in-memory DEK under the Azure KEK's *public* key and emits only the wrapped
/// ciphertext — the plaintext DEK never leaves the enclave. This is the zero-exec path for a
/// *sealed* Evervault enclave where you cannot `docker exec` the one-shot `rewrap_dek` binary
/// (option a) in.
///
/// Driven entirely by env (no-op unless explicitly enabled):
///   - `TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_B64` or `TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2`
///     — unset/empty ⇒ no-op (`Ok(None)`, normal startup). The base64 variant decodes to a
///     JSON JWK; the V2 variant is either inline JSON or a PATH to a file holding the Azure
///     KEK PUBLIC key as JWK (a bare JWK or a Key Vault `GET key` response `{"key": <jwk>}` —
///     both accepted). The original `TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK` name is intentionally
///     ignored after a malformed Evervault env value could not be reliably deleted.
///   - `TAP_MIGRATE_OUTPUT_KEY` — config-table key for the ciphertext (default
///     `migration_wrapped_dek`). Refuses to overwrite an existing row.
///
/// SAFETY: refuses to run under `TAP_KMS_BACKEND=azure-skr` — this must execute in the SOURCE
/// (Evervault) enclave, not the Azure target (mirrors the guard in `bin/rewrap_dek.rs`).
///
/// Returns `Ok(Some(base64))` when it wrapped+stored the DEK, `Ok(None)` when disabled.
#[cfg(feature = "enclave")]
pub async fn run_startup_rewrap() -> Result<Option<String>, AgentSecError> {
    let kek_jwk_source = match migration_jwk_source() {
        Some(p) => p,
        // Unset or empty: normal startup, no migration. Short-circuit before any DB/KMS work.
        None => return Ok(None),
    };

    // Safety: this must run in the SOURCE (Evervault) enclave so load_encryption_key() yields
    // the DEK to migrate. Under azure-skr it would wrap the Azure DEK with the Azure KEK —
    // circular and wrong. Mirrors bin/rewrap_dek.rs.
    if std::env::var("TAP_KMS_BACKEND").as_deref() == Ok("azure-skr") {
        return Err(AgentSecError::Config(
            "TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK set with TAP_KMS_BACKEND=azure-skr — run the \
             startup re-wrap inside the SOURCE (Evervault) enclave, not the Azure target"
                .to_string(),
        ));
    }

    let output_key = std::env::var("TAP_MIGRATE_OUTPUT_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_REWRAP_OUTPUT_KEY.to_string());

    // The DEK and config-secret export both run in the source KMS context. The config-secret
    // export is needed because legacy `ev:` config rows are sealed by Evervault, not by the
    // TAP DEK; Azure cannot decrypt them from the migrated DEK alone.
    let pool = enclave::open_enclave_pool().await?;
    if let Some(existing) = enclave::config_get(&pool, &output_key).await? {
        let dek = load_encryption_key().await?;
        let exported = export_config_secrets_for_azure(&dek, &pool).await?;
        tracing::info!(
            output_key = %output_key,
            azure_config_secrets_written = exported,
            "Startup DEK re-wrap already complete; existing wrapped-DEK row left unchanged"
        );
        return Ok(Some(existing));
    }

    let jwk = load_migration_public_jwk(&kek_jwk_source)?;
    // Custody: refuse a JWK carrying private components — the KEK private half must never
    // leave the enclave/HSM (M1). Mirrors the guard in bin/rewrap_dek.rs.
    crate::skr::ensure_public_only_jwk(&jwk)?;
    let kek_pub = crate::skr::parse_rsa_public_jwk(&jwk)?;

    // Load the DEK via the in-enclave KMS (Evervault). The plaintext DEK lives only here, in
    // the same trusted context the proxy itself uses — it is never printed or persisted.
    let dek = load_encryption_key().await?;

    // Non-secret continuity fingerprint (M3): logged so the operator can confirm the same
    // DEK re-wrapped here matches the azure-skr instance's boot log.
    let fingerprint = crate::skr::dek_fingerprint(&dek);

    let wrapped = rewrap_dek_with(&kek_pub, &dek, &pool, &output_key).await?;
    let exported = export_config_secrets_for_azure(&dek, &pool).await?;

    // The base64 ciphertext is non-secret (only the attested Azure image can unwrap it).
    tracing::info!(
        output_key = %output_key,
        dek_fingerprint = %fingerprint,
        wrapped_dek = %wrapped,
        azure_config_secrets_written = exported,
        "Startup DEK re-wrap complete — store this base64 as the azure-skr instance's \
         backend-namespaced wrapped-DEK config row (see deploy/azure/tap-skr-keymgmt.md)"
    );
    Ok(Some(wrapped))
}

#[cfg(feature = "enclave")]
fn migration_jwk_source() -> Option<String> {
    if let Some(encoded) = std::env::var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_B64")
        .ok()
        .filter(|s| !s.is_empty())
    {
        use base64::Engine as _;
        let encoded_compact: String = encoded.split_whitespace().collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded_compact)
            .ok()?;
        return String::from_utf8(decoded).ok();
    }

    std::env::var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Load the migration KEK PUBLIC JWK from either inline JSON or a filesystem path.
///
/// Inline JSON keeps the sealed-source-enclave startup hook operational when the deployment
/// surface can set env vars but cannot easily mount a one-off file. The JWK is public and
/// still checked by `ensure_public_only_jwk` before use.
#[cfg(feature = "enclave")]
fn load_migration_public_jwk(source: &str) -> Result<serde_json::Value, AgentSecError> {
    let trimmed = source.trim();
    let jwk_text = if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start <= end {
            trimmed[start..=end].to_string()
        } else {
            std::fs::read_to_string(source).map_err(|e| {
                AgentSecError::Config(format!("cannot read KEK JWK '{source}': {e}"))
            })?
        }
    } else {
        std::fs::read_to_string(source)
            .map_err(|e| AgentSecError::Config(format!("cannot read KEK JWK '{source}': {e}")))?
    };
    let jwk: serde_json::Value = serde_json::from_str(&jwk_text)
        .map_err(|e| AgentSecError::Config(format!("KEK JWK is not valid JSON: {e}")))?;
    Ok(jwk.get("key").cloned().unwrap_or(jwk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "enclave"))]
    #[tokio::test]
    async fn test_load_from_env() {
        std::env::set_var(
            "TAP_ENCRYPTION_KEY",
            "0001020304050607080910111213141516171819202122232425262728293031",
        );
        let key = load_encryption_key().await.unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[1], 0x01);
        std::env::remove_var("TAP_ENCRYPTION_KEY");
    }

    #[cfg(not(feature = "enclave"))]
    #[tokio::test]
    async fn test_load_from_env_missing() {
        std::env::remove_var("TAP_ENCRYPTION_KEY");
        let result = load_encryption_key().await;
        assert!(result.is_err());
    }

    // ── Startup re-wrap hook (option b) tests. Enclave-gated. The DB-backed ones use the
    //    shared test Postgres — run with --test-threads=1 (the env-var tests mutate process
    //    env, the DB tests reset the schema), as the repo already requires for enclave tests.
    #[cfg(feature = "enclave")]
    mod rewrap {
        use super::*;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        fn test_kek() -> RsaPrivateKey {
            RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("generate test KEK")
        }

        /// Fresh schema-reset DB with just the `config` table — mirrors `kms_azure::tests::fresh_db`.
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

        /// Env unset ⇒ no-op (returns None) and never touches the DB/KMS. We assert it
        /// short-circuits even with no Postgres reachable by leaving POSTGRES_DATABASE_URL
        /// untouched and relying on the early return before any pool is opened.
        #[tokio::test]
        async fn unset_env_is_noop() {
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK");
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2");
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_B64");
            assert!(run_startup_rewrap().await.unwrap().is_none());
            // Empty string is also a no-op.
            std::env::set_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2", "");
            assert!(run_startup_rewrap().await.unwrap().is_none());
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2");
        }

        #[test]
        fn migration_jwk_source_ignores_malformed_legacy_var() {
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_B64");
            std::env::set_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK", "bad-old-value");
            std::env::set_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2", "good-new-value");
            assert_eq!(migration_jwk_source().as_deref(), Some("good-new-value"));
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK");
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2");
        }

        #[test]
        fn migration_jwk_source_prefers_base64_json() {
            use base64::Engine as _;

            std::env::set_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK", "bad-old-value");
            std::env::set_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2", "also-ignored");
            std::env::set_var(
                "TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_B64",
                base64::engine::general_purpose::STANDARD.encode(r#"{"kty":"RSA"}"#),
            );
            assert_eq!(migration_jwk_source().as_deref(), Some(r#"{"kty":"RSA"}"#));
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK");
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2");
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_B64");
        }

        /// Guard: azure-skr backend ⇒ error (must run in the SOURCE Evervault enclave).
        #[tokio::test]
        async fn azure_skr_backend_refused() {
            // Use a temp JWK path so the env-set branch is taken (path need not be readable —
            // the backend guard fires first). The original env name is intentionally ignored
            // after a malformed Evervault value could not be deleted.
            std::env::set_var(
                "TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2",
                "/nonexistent/kek.jwk",
            );
            std::env::set_var("TAP_KMS_BACKEND", "azure-skr");
            let err = run_startup_rewrap().await.unwrap_err();
            assert!(format!("{err}").contains("azure-skr"));
            std::env::remove_var("TAP_KMS_BACKEND");
            std::env::remove_var("TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK_V2");
        }

        #[test]
        fn load_migration_public_jwk_accepts_inline_bare_jwk() {
            let jwk = load_migration_public_jwk(r#"{"kty":"RSA","n":"abc","e":"AQAB"}"#).unwrap();
            assert_eq!(jwk["kty"], "RSA");
        }

        #[test]
        fn load_migration_public_jwk_accepts_inline_key_vault_shape() {
            let jwk = load_migration_public_jwk(
                r#"{"key":{"kty":"RSA","n":"abc","e":"AQAB"},"attributes":{"enabled":true}}"#,
            )
            .unwrap();
            assert_eq!(jwk["e"], "AQAB");
        }

        #[test]
        fn load_migration_public_jwk_accepts_quoted_inline_json() {
            let jwk =
                load_migration_public_jwk(r#"'"{"kty":"RSA-HSM","n":"abc","e":"AQAB"}"'"#).unwrap();
            assert_eq!(jwk["kty"], "RSA-HSM");
        }

        /// Happy path for the testable core: given a KEK public key + a known DEK, the wrapped
        /// ciphertext is stored under the output key and RSA-OAEP-unwraps back to the SAME DEK.
        #[tokio::test]
        async fn rewrap_dek_with_stores_unwrappable_ciphertext() {
            let pool = fresh_db().await;
            let kek = test_kek();
            let kek_pub: RsaPublicKey = kek.to_public_key();
            let dek = [0x5au8; 32];

            let returned = rewrap_dek_with(&kek_pub, &dek, &pool, DEFAULT_REWRAP_OUTPUT_KEY)
                .await
                .unwrap();

            // Stored row matches the returned base64.
            let stored = enclave::config_get(&pool, DEFAULT_REWRAP_OUTPUT_KEY)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored, returned);
            // And it unwraps with the KEK private half back to the original DEK.
            assert_eq!(crate::skr::unwrap_dek(&kek, &stored).unwrap(), dek);
        }

        /// The output key is honored — a custom TAP_MIGRATE_OUTPUT_KEY value lands in that row.
        #[tokio::test]
        async fn rewrap_dek_with_honors_custom_output_key() {
            let pool = fresh_db().await;
            let kek = test_kek();
            let dek = [0x11u8; 32];

            rewrap_dek_with(&kek.to_public_key(), &dek, &pool, "custom_wrapped_dek")
                .await
                .unwrap();

            assert!(enclave::config_get(&pool, "custom_wrapped_dek")
                .await
                .unwrap()
                .is_some());
            assert!(enclave::config_get(&pool, DEFAULT_REWRAP_OUTPUT_KEY)
                .await
                .unwrap()
                .is_none());
        }

        /// The migration row is write-once: a second run must not silently rotate or
        /// replace the Azure-wrapped DEK used by production.
        #[tokio::test]
        async fn rewrap_dek_with_refuses_to_overwrite_existing_output_key() {
            let pool = fresh_db().await;
            let kek = test_kek();
            let dek = [0x22u8; 32];

            enclave::config_set(&pool, "existing_wrapped_dek", "already-present")
                .await
                .unwrap();
            let err = rewrap_dek_with(&kek.to_public_key(), &dek, &pool, "existing_wrapped_dek")
                .await
                .unwrap_err();

            assert!(format!("{err}").contains("refused to overwrite"));
            assert_eq!(
                enclave::config_get(&pool, "existing_wrapped_dek")
                    .await
                    .unwrap()
                    .unwrap(),
                "already-present"
            );
        }
    }
}
