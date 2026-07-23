//! In-enclave TLS termination for the TAP proxy (internal-docs#1188, follow-up to #1187).
//!
//! TLS is terminated *inside* the TEE rather than at a CDN/gateway, so plaintext request
//! and response bodies never leave the enclave boundary. Certificates are obtained and
//! auto-renewed from Let's Encrypt over the **TLS-ALPN-01** challenge (no extra port, no
//! HTTP-01 listener) via [`rustls_acme`], and the issued cert chain plus the ACME account
//! key are persisted in the Postgres `config` table, **encrypted at rest under the DEK**.
//!
//! Persisting the cache matters operationally: the enclave scales to zero / restarts, and
//! Let's Encrypt enforces issuance rate limits. Without a surviving cache every cold start
//! would re-order a certificate and quickly trip those limits. With it, a restart re-loads
//! the existing cert and only talks to the ACME directory when renewal is actually due.
//!
//! This module is **not** gated behind `--features enclave`: it only needs the DEK and a
//! Postgres pool, both of which `main` already has in every build.
//!
//! ## Cache encryption shape
//!
//! Each cached blob is stored as a single `config` row whose `value` is
//! `base64(nonce ‖ ciphertext)` produced by [`crate::crypto::encrypt`] (AES-256-GCM under
//! the DEK). The 12-byte GCM nonce is prepended to the ciphertext so a single column round
//! trips without a second field. Keys are namespaced:
//!   - cert chains:  `acme_cert::<sha256(directory_url ‖ "\0" ‖ domains.join(","))>`
//!   - account keys: `acme_account::<sha256(directory_url ‖ "\0" ‖ contacts.join(","))>`
//!
//! Hashing the (directory, domains/contacts) tuple keeps row keys bounded and avoids
//! embedding raw domains/emails in primary keys, while still giving a stable, collision-
//! resistant identity per LE environment (staging vs prod get distinct rows).

use std::net::SocketAddr;

use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use rustls_acme::{AccountCache, AcmeConfig, CertCache};
use sha2::{Digest, Sha256};

/// Let's Encrypt **production** ACME directory. Selected only when `TLS_ACME_DIRECTORY` is
/// `prod`/`production`; otherwise we default to staging (see [`resolve_directory`]).
const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt **staging** ACME directory — the safe default. Staging certs are not
/// publicly trusted but share the issuance flow, so a misconfiguration can't burn prod
/// rate limits.
const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal config-table get/set (TLS is not enclave-gated, so we keep our own copy
// here rather than reaching into the `pub(super)` enclave-module helpers).
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure the `config` table exists. `ConfigStore`/`open_enclave_pool` already create it,
/// but the cache may be constructed before either has run, and the statement is idempotent.
async fn ensure_config_table(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    sqlx::query("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .execute(pool)
        .await
        .context("create config table")?;
    Ok(())
}

async fn config_get(pool: &sqlx::PgPool, key: &str) -> anyhow::Result<Option<String>> {
    use sqlx::Row as _;
    let row = sqlx::query("SELECT value FROM config WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .context("query config")?;
    match row {
        Some(r) => Ok(Some(
            r.try_get::<String, _>("value")
                .context("read config value")?,
        )),
        None => Ok(None),
    }
}

async fn config_set(pool: &sqlx::PgPool, key: &str, value: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO config (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    .context("write config")?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// DEK-encrypted Postgres ACME cache
// ─────────────────────────────────────────────────────────────────────────────

/// `rustls_acme` cache backed by the Postgres `config` table, encrypting every stored blob
/// under the DEK with AES-256-GCM. Implements both [`CertCache`] and [`AccountCache`] (and
/// therefore the blanket `Cache`).
#[derive(Clone)]
pub struct PostgresAcmeCache {
    pool: sqlx::PgPool,
    dek: [u8; 32],
}

impl PostgresAcmeCache {
    pub fn new(pool: sqlx::PgPool, dek: [u8; 32]) -> Self {
        Self { pool, dek }
    }

    /// Stable, bounded row key for a `(prefix, directory_url, parts)` tuple. Hashing keeps
    /// the primary key short and avoids embedding raw domains/emails; the directory URL is
    /// folded in so staging and prod never share a row.
    fn cache_key(prefix: &str, directory_url: &str, parts: &[String]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(directory_url.as_bytes());
        hasher.update([0u8]);
        hasher.update(parts.join(",").as_bytes());
        format!("{prefix}::{}", hex::encode(hasher.finalize()))
    }

    /// Encrypt `data` under the DEK and encode as `base64(nonce ‖ ciphertext)`.
    fn seal(&self, data: &[u8]) -> anyhow::Result<String> {
        let (ciphertext, nonce) =
            crate::crypto::encrypt(&self.dek, data).map_err(|e| anyhow::anyhow!(e))?;
        let mut blob = nonce; // 12-byte GCM nonce first
        blob.extend_from_slice(&ciphertext);
        Ok(base64::engine::general_purpose::STANDARD.encode(blob))
    }

    /// Reverse of [`Self::seal`]: base64-decode, split off the 12-byte nonce, decrypt.
    fn unseal(&self, encoded: &str) -> anyhow::Result<Vec<u8>> {
        let blob = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("base64-decode cached ACME blob")?;
        if blob.len() < 12 {
            anyhow::bail!("cached ACME blob too short to contain a nonce");
        }
        let (nonce, ciphertext) = blob.split_at(12);
        crate::crypto::decrypt(&self.dek, ciphertext, nonce).map_err(|e| anyhow::anyhow!(e))
    }

    async fn load(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match config_get(&self.pool, key).await? {
            Some(encoded) => Ok(Some(self.unseal(&encoded)?)),
            None => Ok(None),
        }
    }

    async fn store(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        let encoded = self.seal(data)?;
        config_set(&self.pool, key, &encoded).await
    }
}

#[async_trait]
impl CertCache for PostgresAcmeCache {
    type EC = anyhow::Error;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let key = Self::cache_key("acme_cert", directory_url, domains);
        self.load(&key).await
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        let key = Self::cache_key("acme_cert", directory_url, domains);
        self.store(&key, cert).await
    }
}

#[async_trait]
impl AccountCache for PostgresAcmeCache {
    type EA = anyhow::Error;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        let key = Self::cache_key("acme_account", directory_url, contact);
        self.load(&key).await
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        let key = Self::cache_key("acme_account", directory_url, contact);
        self.store(&key, account).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Serve entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the ACME directory URL from `TLS_ACME_DIRECTORY`. Default and any unrecognized
/// value resolve to **staging** (fail-safe); `prod`/`production` selects LE production; a
/// value starting with `http` is used verbatim (custom/pebble directories).
fn resolve_directory(raw: Option<String>) -> String {
    match raw.as_deref().map(str::trim) {
        None | Some("") | Some("staging") => LETS_ENCRYPT_STAGING.to_string(),
        Some("prod") | Some("production") => LETS_ENCRYPT_PRODUCTION.to_string(),
        Some(url) if url.starts_with("http") => url.to_string(),
        Some(other) => {
            tracing::warn!(
                value = %other,
                "TLS_ACME_DIRECTORY not recognized; defaulting to Let's Encrypt staging"
            );
            LETS_ENCRYPT_STAGING.to_string()
        }
    }
}

/// Terminate TLS for `app` inside the enclave.
///
/// Reads:
///   - `TLS_DOMAIN`           (required) — primary domain to obtain a certificate for.
///   - `TLS_ADDITIONAL_DOMAINS` (optional) — comma-separated SAN names for the same cert.
///   - `TLS_ACME_EMAIL`       (required) — ACME account contact (a `mailto:` prefix is added
///                                          if absent).
///   - `TLS_ACME_DIRECTORY`   (optional) — `staging` (default), `prod`/`production`, or a
///                                          full directory URL.
///   - `TAP_TLS_LISTEN_ADDR`  (optional) — bind address; defaults to `0.0.0.0:443`.
///
/// Certificates and the ACME account key are cached in Postgres, DEK-encrypted, so they
/// survive restarts and scale-to-zero. The certificate is acquired/renewed via TLS-ALPN-01
/// on the same listener — no second port and no plaintext HTTP listener are opened.
#[allow(clippy::doc_overindented_list_items)]
pub async fn serve_tls(app: axum::Router, dek: [u8; 32], pool: sqlx::PgPool) -> anyhow::Result<()> {
    let domain = std::env::var("TLS_DOMAIN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .context("TLS_DOMAIN is required to terminate TLS in the enclave")?;
    let domains: Vec<String> = std::iter::once(domain.clone())
        .chain(
            std::env::var("TLS_ADDITIONAL_DOMAINS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned),
        )
        .collect();
    let email = std::env::var("TLS_ACME_EMAIL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .context("TLS_ACME_EMAIL is required for ACME account registration")?;
    let contact = if email.starts_with("mailto:") {
        email
    } else {
        format!("mailto:{email}")
    };

    let directory = resolve_directory(std::env::var("TLS_ACME_DIRECTORY").ok());
    let listen_addr =
        std::env::var("TAP_TLS_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:443".to_string());
    let addr: SocketAddr = listen_addr
        .parse()
        .with_context(|| format!("invalid TAP_TLS_LISTEN_ADDR '{listen_addr}'"))?;

    // Make sure the cache's backing table exists before the ACME state touches it.
    ensure_config_table(&pool).await?;

    tracing::info!(
        %domain,
        ?domains,
        %directory,
        %addr,
        "Terminating TLS in-enclave (TLS-ALPN-01, Postgres+DEK ACME cache)"
    );

    let cache = PostgresAcmeCache::new(pool, dek);
    let mut state = AcmeConfig::new(domains)
        .contact([contact])
        .directory(directory)
        .cache(cache)
        .state();

    // The rustls cert resolver served to clients; rustls-acme swaps in the live cert as it
    // is issued/renewed, and answers TLS-ALPN-01 challenges on the same connection.
    let rustls_config = state.default_rustls_config();
    let acceptor = state.axum_acceptor(rustls_config);

    // Drive the ACME state machine: ordering on first boot, then renewal forever. This must
    // run for the lifetime of the server, so it lives in its own task. Errors here are
    // recoverable (rustls-acme retries with backoff); we log and keep going.
    tokio::spawn(async move {
        use futures::StreamExt as _;
        loop {
            match state.next().await {
                Some(Ok(ok)) => tracing::info!(event = ?ok, "ACME event"),
                Some(Err(err)) => tracing::error!(error = ?err, "ACME error (will retry)"),
                None => {
                    tracing::error!("ACME state stream ended unexpectedly");
                    break;
                }
            }
        }
    });

    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .context("axum-server TLS serve loop exited")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dek() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        k
    }

    /// Fresh, schema-reset test database with just the `config` table. Mirrors the
    /// convention in `kms_azure.rs` tests (`DROP SCHEMA public`); shares the test Postgres,
    /// so these are not parallel-safe — run with `--test-threads=1`.
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

    /// A cert blob round-trips through store_cert/load_cert, and the row persisted in
    /// Postgres is NOT the plaintext (it is DEK-encrypted + base64).
    #[tokio::test]
    async fn cert_cache_round_trips_and_is_encrypted_at_rest() {
        let pool = fresh_db().await;
        let cache = PostgresAcmeCache::new(pool.clone(), test_dek());
        let domains = vec!["proxy.tap.human.tech".to_string()];
        let directory = LETS_ENCRYPT_STAGING;
        let fake_cert =
            b"-----BEGIN CERTIFICATE-----\nFAKEPEMBYTES_for_test_only\n-----END CERTIFICATE-----";

        // Empty before anything is stored.
        assert!(cache
            .load_cert(&domains, directory)
            .await
            .unwrap()
            .is_none());

        cache
            .store_cert(&domains, directory, fake_cert)
            .await
            .unwrap();

        // (a) round-trips
        let loaded = cache.load_cert(&domains, directory).await.unwrap().unwrap();
        assert_eq!(loaded, fake_cert);

        // (b) the stored `value` is NOT the plaintext — verify directly against the row.
        let key = PostgresAcmeCache::cache_key("acme_cert", directory, &domains);
        let stored = config_get(&pool, &key).await.unwrap().unwrap();
        assert_ne!(stored.as_bytes(), &fake_cert[..]);
        assert!(!stored.contains("BEGIN CERTIFICATE"));
        // It must be valid base64 of (nonce ‖ ciphertext), longer than the 12-byte nonce.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&stored)
            .unwrap();
        assert!(raw.len() > 12);
    }

    /// The account-key cache round-trips and is likewise encrypted at rest, and uses a
    /// distinct row key from the cert cache for the same directory.
    #[tokio::test]
    async fn account_cache_round_trips_and_is_encrypted_at_rest() {
        let pool = fresh_db().await;
        let cache = PostgresAcmeCache::new(pool.clone(), test_dek());
        let contacts = vec!["mailto:ops@human.tech".to_string()];
        let directory = LETS_ENCRYPT_STAGING;
        let fake_account = b"fake-acme-account-private-key-pkcs8-bytes";

        cache
            .store_account(&contacts, directory, fake_account)
            .await
            .unwrap();

        let loaded = cache
            .load_account(&contacts, directory)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded, fake_account);

        let key = PostgresAcmeCache::cache_key("acme_account", directory, &contacts);
        let stored = config_get(&pool, &key).await.unwrap().unwrap();
        assert_ne!(stored.as_bytes(), &fake_account[..]);

        // Cert and account namespaces never collide for the same directory.
        let cert_key = PostgresAcmeCache::cache_key("acme_cert", directory, &contacts);
        assert_ne!(key, cert_key);
    }

    /// Staging and production directories must map to different cache rows so a staging
    /// cert is never served as if it were a production cert (and vice versa).
    #[tokio::test]
    async fn staging_and_prod_use_distinct_rows() {
        let pool = fresh_db().await;
        let cache = PostgresAcmeCache::new(pool.clone(), test_dek());
        let domains = vec!["proxy.tap.human.tech".to_string()];

        cache
            .store_cert(&domains, LETS_ENCRYPT_STAGING, b"staging-cert")
            .await
            .unwrap();
        cache
            .store_cert(&domains, LETS_ENCRYPT_PRODUCTION, b"prod-cert")
            .await
            .unwrap();

        assert_eq!(
            cache
                .load_cert(&domains, LETS_ENCRYPT_STAGING)
                .await
                .unwrap()
                .unwrap(),
            b"staging-cert"
        );
        assert_eq!(
            cache
                .load_cert(&domains, LETS_ENCRYPT_PRODUCTION)
                .await
                .unwrap()
                .unwrap(),
            b"prod-cert"
        );
    }

    /// A row written under one DEK cannot be read under a different DEK (defense in depth:
    /// the cache is only meaningful inside the enclave that holds the DEK).
    #[tokio::test]
    async fn wrong_dek_cannot_decrypt_cached_cert() {
        let pool = fresh_db().await;
        let domains = vec!["proxy.tap.human.tech".to_string()];
        let directory = LETS_ENCRYPT_STAGING;

        let cache_a = PostgresAcmeCache::new(pool.clone(), test_dek());
        cache_a
            .store_cert(&domains, directory, b"secret-cert")
            .await
            .unwrap();

        let mut other = test_dek();
        other[0] ^= 0xFF;
        let cache_b = PostgresAcmeCache::new(pool.clone(), other);
        assert!(cache_b.load_cert(&domains, directory).await.is_err());
    }

    #[test]
    fn directory_resolution_defaults_to_staging_and_is_failsafe() {
        assert_eq!(resolve_directory(None), LETS_ENCRYPT_STAGING);
        assert_eq!(resolve_directory(Some("".into())), LETS_ENCRYPT_STAGING);
        assert_eq!(
            resolve_directory(Some("staging".into())),
            LETS_ENCRYPT_STAGING
        );
        assert_eq!(
            resolve_directory(Some("prod".into())),
            LETS_ENCRYPT_PRODUCTION
        );
        assert_eq!(
            resolve_directory(Some("production".into())),
            LETS_ENCRYPT_PRODUCTION
        );
        assert_eq!(
            resolve_directory(Some("https://pebble.local/dir".into())),
            "https://pebble.local/dir"
        );
        // Unrecognized -> staging (fail-safe), never prod.
        assert_eq!(
            resolve_directory(Some("garbage".into())),
            LETS_ENCRYPT_STAGING
        );
    }
}
