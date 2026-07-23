//! Enclave key provider. Loaded only when compiled with --features enclave.
//! This file is not included in the public OSS distribution.
//!
//! Key management runs behind a [`KmsBackend`] trait so the Evervault and Azure-SKR
//! backends coexist during the migration (internal-docs#1187). The backend is chosen at
//! runtime via `TAP_KMS_BACKEND` (`evervault` — the default — or `azure-skr`); the
//! Postgres `config`-table ciphertext shape and the downstream local AES-256-GCM path are
//! identical across backends.

use tap_core::error::AgentSecError;

#[path = "kms_azure.rs"]
mod azure;

/// Canonical KMS backend name (matches a `TAP_KMS_BACKEND` value). The Evervault backend is
/// grandfathered onto the historical DEK config key; every other backend namespaces its DEK
/// row by name (see [`dek_ciphertext_key`]).
const EVERVAULT_BACKEND: &str = "evervault";

/// Historical config-table key for the wrapped/sealed DEK ciphertext. Kept for the Evervault
/// backend so existing deployments need no data migration.
const LEGACY_DEK_KEY: &str = "encryption_key_ciphertext";

/// Config-table keys whose values are secrets sealed under the DEK (AES-256-GCM) by
/// `load_secret`/`aes_seal`. These are part of the "encrypted under the DEK" surface the
/// irrecoverability guard must protect (H1): minting a fresh DEK while any of these exist
/// would orphan them exactly like an encrypted `credentials` row. Keep in sync with the
/// `load_secret` call sites in `main.rs`.
const DEK_SEALED_CONFIG_KEYS: &[&str] = &[
    "telegram_bot_token_ciphertext",
    "telegram_chat_id_ciphertext",
    "matrix_homeserver_url_ciphertext",
    "matrix_access_token_ciphertext",
    "matrix_room_id_ciphertext",
];

/// Config-table key holding a backend's wrapped/sealed DEK ciphertext. `evervault` keeps the
/// historical [`LEGACY_DEK_KEY`] (zero migration for existing deploys); every other backend
/// namespaces by name so an in-place cutover can hold the old and new wrapped DEK side by
/// side in one database (internal-docs#1187 decision 3, H2).
fn dek_ciphertext_key(backend_name: &str) -> String {
    if backend_name == EVERVAULT_BACKEND {
        LEGACY_DEK_KEY.to_string()
    } else {
        format!("{LEGACY_DEK_KEY}_{}", backend_name.replace('-', "_"))
    }
}

/// Sibling config key tagging a DEK row with the backend that owns it.
fn dek_backend_tag_key(dek_key: &str) -> String {
    format!("{dek_key}.backend")
}

/// Resolve a backend's DEK config key, refusing if the stored ownership tag names a
/// *different* backend (H2). This makes a `TAP_KMS_BACKEND` flip fail loudly and by design —
/// rather than as an incidental RSA/AES decode failure — when foreign key material sits under
/// the resolved key. A missing tag is legacy/greenfield (allowed); the caller records it via
/// [`record_dek_backend_tag`] after a successful load or store.
async fn dek_key_checked(pool: &sqlx::PgPool, backend_name: &str) -> Result<String, AgentSecError> {
    let dek_key = dek_ciphertext_key(backend_name);
    if let Some(stored) = config_get(pool, &dek_backend_tag_key(&dek_key)).await? {
        if stored != backend_name {
            return Err(AgentSecError::Config(format!(
                "the wrapped DEK at config key '{dek_key}' is tagged backend '{stored}', but the \
                 configured TAP_KMS_BACKEND is '{backend_name}' — refusing to use mismatched key \
                 material (re-wrap the DEK for the new backend before switching)"
            )));
        }
    }
    Ok(dek_key)
}

/// Record (write-once) which backend owns a DEK row. Idempotent: a second call is a no-op,
/// so a normal boot that re-reads an already-tagged DEK leaves the tag untouched.
async fn record_dek_backend_tag(
    pool: &sqlx::PgPool,
    backend_name: &str,
    dek_key: &str,
) -> Result<(), AgentSecError> {
    config_set_if_absent(pool, &dek_backend_tag_key(dek_key), backend_name).await?;
    Ok(())
}

/// Open a Postgres pool backed by the enclave CA certificate.
pub(super) async fn open_enclave_pool() -> Result<sqlx::PgPool, AgentSecError> {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
    use sqlx::Executor as _;
    use std::str::FromStr as _;

    let ca_cert_path = std::env::var("TAP_POSTGRES_CA_CERT_PATH")
        .unwrap_or_else(|_| "/etc/ssl/certs/tap-supabase-ca.crt".to_string());
    let url = std::env::var("POSTGRES_DATABASE_URL").map_err(|_| {
        AgentSecError::Encryption(
            "POSTGRES_DATABASE_URL is required for enclave key storage".to_string(),
        )
    })?;
    let opts = PgConnectOptions::from_str(&url)
        .map_err(|e| AgentSecError::Encryption(format!("Invalid POSTGRES_DATABASE_URL: {e}")))?
        .statement_cache_capacity(0)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(&ca_cert_path);
    let pool = PgPoolOptions::new()
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("DEALLOCATE ALL").await?;
                Ok(())
            })
        })
        .before_acquire(|conn, _meta| {
            Box::pin(async move {
                conn.execute("DEALLOCATE ALL").await?;
                Ok(true)
            })
        })
        .connect_with(opts)
        .await
        .map_err(|e| {
            AgentSecError::Encryption(format!(
                "Failed to connect to Postgres for key storage: {e}"
            ))
        })?;
    sqlx::query("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .execute(&pool)
        .await
        .map_err(|e| AgentSecError::Encryption(format!("Failed to create config table: {e}")))?;
    Ok(pool)
}

pub(super) async fn config_get(
    pool: &sqlx::PgPool,
    key: &str,
) -> Result<Option<String>, AgentSecError> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT value FROM config WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(|e| AgentSecError::Encryption(format!("Failed to query config: {e}")))?;
    // M2: propagate a column-read failure instead of silently returning Some("") via
    // unwrap_or_default — on a custody-critical read (the wrapped DEK, a sealed secret) a
    // decode error must fail loudly, not masquerade as an empty value.
    match row {
        Some(r) => {
            let value: String = r.try_get("value").map_err(|e| {
                AgentSecError::Encryption(format!("Failed to read config value for '{key}': {e}"))
            })?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

pub(super) async fn config_set(
    pool: &sqlx::PgPool,
    key: &str,
    value: &str,
) -> Result<(), AgentSecError> {
    sqlx::query(
        "INSERT INTO config (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    .map_err(|e| AgentSecError::Encryption(format!("Failed to write config: {e}")))?;
    Ok(())
}

/// Insert a config row only if the key does not already exist. Returns `true` if this
/// call created the row, `false` if a row was already present (another writer won).
///
/// Unlike [`config_set`], this never overwrites an existing value — used for write-once,
/// custody-critical keys (the wrapped DEK) where two instances booting concurrently must
/// converge on a single key rather than clobbering each other (see `kms_azure::load_dek`).
pub(super) async fn config_set_if_absent(
    pool: &sqlx::PgPool,
    key: &str,
    value: &str,
) -> Result<bool, AgentSecError> {
    let result =
        sqlx::query("INSERT INTO config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING")
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .map_err(|e| AgentSecError::Encryption(format!("Failed to write config: {e}")))?;
    Ok(result.rows_affected() == 1)
}

/// True if the DB already holds data encrypted under the DEK — either a
/// `credentials.encrypted_value` row **or** any DEK-sealed secret in the `config` table
/// ([`DEK_SEALED_CONFIG_KEYS`], the `load_secret`/`aes_seal` surface).
///
/// This is the **structural** safety invariant behind DEK generation: a fresh DEK may only
/// be minted when nothing is already encrypted under a prior DEK, otherwise that data is
/// permanently orphaned. It is derived from DB state, so it protects against irrecoverable
/// loss *without* depending on an operator remembering to set an env var. Returns `false`
/// when neither surface holds data (a truly greenfield database).
pub(super) async fn has_encrypted_data(pool: &sqlx::PgPool) -> Result<bool, AgentSecError> {
    use sqlx::Row as _;

    // (a) DEK-sealed secrets in the `config` table (H1 — load_secret/aes_seal surface). The
    //     config table always exists (created in open_enclave_pool), so this is parse-safe.
    //     Any one present means the DB holds data sealed under a prior DEK.
    for key in DEK_SEALED_CONFIG_KEYS {
        if config_get(pool, key).await?.is_some() {
            return Ok(true);
        }
    }

    // (b) DEK-encrypted rows in the `credentials` table.
    // Two steps on purpose: Postgres validates every relation a statement references at
    // PARSE time, even inside a not-taken CASE branch — so a single query mentioning
    // `credentials` would error on a greenfield DB where the table doesn't exist yet. First
    // check existence (parse-safe — never names the table), then query it only if present.
    let present: bool =
        sqlx::query("SELECT to_regclass('public.credentials') IS NOT NULL AS present")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                AgentSecError::Encryption(format!("Failed to check for credentials table: {e}"))
            })?
            .try_get("present")
            .map_err(|e| AgentSecError::Encryption(format!("Failed to read table check: {e}")))?;
    if !present {
        return Ok(false);
    }
    sqlx::query(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE encrypted_value IS NOT NULL) AS has_data",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        AgentSecError::Encryption(format!("Failed to check for existing encrypted data: {e}"))
    })?
    .try_get("has_data")
    .map_err(|e| AgentSecError::Encryption(format!("Failed to read encrypted-data check: {e}")))
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend seam
// ─────────────────────────────────────────────────────────────────────────────

/// A key-management backend: resolves the 32-byte master DEK and named secrets from a
/// platform KMS, persisting ciphertext in the Postgres `config` table.
#[async_trait::async_trait]
pub(super) trait KmsBackend: Send + Sync {
    /// Load (or, greenfield, generate) the 32-byte encryption key (DEK).
    async fn load_encryption_key(&self, pool: &sqlx::PgPool) -> Result<[u8; 32], AgentSecError>;
    /// Load a named secret, bootstrapping from `env_var` on first run.
    async fn load_secret(
        &self,
        pool: &sqlx::PgPool,
        env_var: &str,
        db_key: &str,
    ) -> Result<String, AgentSecError>;
    /// Load a named secret if it exists in storage or a non-empty bootstrap env var is set.
    async fn load_optional_secret(
        &self,
        pool: &sqlx::PgPool,
        env_var: &str,
        db_key: &str,
    ) -> Result<Option<String>, AgentSecError>;
}

/// Pick the KMS backend from `TAP_KMS_BACKEND`. Defaults to Evervault so existing
/// deployments are byte-for-byte unchanged until they opt into `azure-skr`.
fn select_backend() -> Result<Box<dyn KmsBackend>, AgentSecError> {
    match std::env::var("TAP_KMS_BACKEND").ok().as_deref() {
        None | Some("") | Some("evervault") => Ok(Box::new(EvervaultBackend::from_env())),
        Some("azure-skr") => Ok(Box::new(azure::AzureSkrBackend::from_env()?)),
        Some(other) => Err(AgentSecError::Config(format!(
            "unknown TAP_KMS_BACKEND '{other}' (expected 'evervault' or 'azure-skr')"
        ))),
    }
}

/// Load or generate the 32-byte encryption key via the selected KMS backend.
///
/// First startup: generate random key → seal → store ciphertext in Postgres.
/// Subsequent startups: fetch ciphertext from Postgres → unseal → return plaintext.
/// The key never exists as an env var or on disk in plaintext.
pub(super) async fn load_from_kms() -> Result<[u8; 32], AgentSecError> {
    let pool = open_enclave_pool().await?;
    tracing::info!("Enclave key storage: using Postgres");
    select_backend()?.load_encryption_key(&pool).await
}

/// Load a named secret via the selected KMS backend. Bootstraps from env var on first
/// run, then reads ciphertext from Postgres on subsequent startups so the env var can be
/// removed after initial deployment.
pub(super) async fn load_secret_from_kms(
    env_var: &str,
    db_key: &str,
) -> Result<String, AgentSecError> {
    let pool = open_enclave_pool().await?;
    select_backend()?.load_secret(&pool, env_var, db_key).await
}

/// Optional variant of [`load_secret_from_kms`]. This is for feature-enabling
/// configuration where an already sealed DB row should be enough to turn the
/// feature on, but a missing row/env should cleanly disable it.
pub(super) async fn load_optional_secret_from_kms(
    env_var: &str,
    db_key: &str,
) -> Result<Option<String>, AgentSecError> {
    let pool = open_enclave_pool().await?;
    select_backend()?
        .load_optional_secret(&pool, env_var, db_key)
        .await
}

// ─────────────────────────────────────────────────────────────────────────────
// Evervault backend (unchanged behavior; moved behind the trait)
// ─────────────────────────────────────────────────────────────────────────────

/// Evervault KMS: seals/unseals via the in-enclave Evervault `/encrypt` + `/decrypt`
/// HTTP endpoints and stores the ciphertext in the Postgres `config` table.
struct EvervaultBackend {
    kms_url: String,
}

impl EvervaultBackend {
    fn from_env() -> Self {
        let kms_url = std::env::var("EVERVAULT_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9999".to_string());
        Self { kms_url }
    }

    fn client(&self) -> Result<reqwest::Client, AgentSecError> {
        tap_core::http_client::build_client(tap_core::http_client::ClientRoute::Direct)
            .map_err(|e| AgentSecError::Encryption(format!("Failed to create HTTP client: {e}")))
    }

    /// POST `{ "data": <data> }` to `{kms_url}/{op}` and return the response `data` field.
    async fn call(&self, op: &str, data: &str) -> Result<String, AgentSecError> {
        let client = self.client()?;
        let resp = client
            .post(format!("{}/{op}", self.kms_url))
            .json(&serde_json::json!({ "data": data }))
            .send()
            .await
            .map_err(|e| AgentSecError::Encryption(format!("KMS {op} failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AgentSecError::Encryption(format!(
                "KMS {op} returned {status}: {body}"
            )));
        }

        let body: serde_json::Value = resp.json().await.map_err(|e| {
            AgentSecError::Encryption(format!("Failed to parse {op} response: {e}"))
        })?;
        body["data"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AgentSecError::Encryption(format!("{op} response missing 'data'")))
    }
}

#[async_trait::async_trait]
impl KmsBackend for EvervaultBackend {
    async fn load_encryption_key(&self, pool: &sqlx::PgPool) -> Result<[u8; 32], AgentSecError> {
        use rand::RngCore as _;

        // Backend-namespaced DEK key (evervault keeps the legacy key) + flip refusal (H2).
        let dek_key = dek_key_checked(pool, EVERVAULT_BACKEND).await?;

        if let Some(ciphertext) = config_get(pool, &dek_key).await? {
            tracing::info!("Enclave: decrypting existing encryption key from Postgres");
            let key_hex = self.call("decrypt", &ciphertext).await?;
            let key = crate::crypto::parse_encryption_key(&key_hex)?;
            record_dek_backend_tag(pool, EVERVAULT_BACKEND, &dek_key).await?;
            return Ok(key);
        }

        tracing::info!("Enclave: generating new encryption key");
        let mut key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        let key_hex = hex::encode(key_bytes);

        let ciphertext = self.call("encrypt", &key_hex).await?;
        config_set(pool, &dek_key, &ciphertext).await?;
        record_dek_backend_tag(pool, EVERVAULT_BACKEND, &dek_key).await?;
        tracing::info!("Enclave: encryption key generated and stored");
        Ok(key_bytes)
    }

    async fn load_secret(
        &self,
        pool: &sqlx::PgPool,
        env_var: &str,
        db_key: &str,
    ) -> Result<String, AgentSecError> {
        if let Some(ciphertext) = config_get(pool, db_key).await? {
            tracing::info!(key = %db_key, "Enclave: decrypting secret from Postgres");
            return self.call("decrypt", &ciphertext).await;
        }

        let plaintext = std::env::var(env_var).map_err(|_| {
            AgentSecError::Encryption(format!(
                "{env_var} not set and no encrypted value in Postgres for '{db_key}'"
            ))
        })?;

        tracing::info!(key = %db_key, "Enclave: encrypting secret from env var for storage in Postgres");
        let ciphertext = self.call("encrypt", &plaintext).await?;
        config_set(pool, db_key, &ciphertext).await?;
        tracing::info!(key = %db_key, "Enclave: secret encrypted and stored");
        Ok(plaintext)
    }

    async fn load_optional_secret(
        &self,
        pool: &sqlx::PgPool,
        env_var: &str,
        db_key: &str,
    ) -> Result<Option<String>, AgentSecError> {
        if let Some(ciphertext) = config_get(pool, db_key).await? {
            tracing::info!(key = %db_key, "Enclave: decrypting optional secret from Postgres");
            return self.call("decrypt", &ciphertext).await.map(Some);
        }

        let Some(plaintext) = std::env::var(env_var).ok().filter(|v| !v.is_empty()) else {
            return Ok(None);
        };

        tracing::info!(key = %db_key, "Enclave: encrypting optional secret from env var for storage in Postgres");
        let ciphertext = self.call("encrypt", &plaintext).await?;
        config_set(pool, db_key, &ciphertext).await?;
        tracing::info!(key = %db_key, "Enclave: optional secret encrypted and stored");
        Ok(Some(plaintext))
    }
}
