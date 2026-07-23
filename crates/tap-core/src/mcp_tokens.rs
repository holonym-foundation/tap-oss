//! Durable, cross-instance state for the remote MCP server's OAuth tokens.
//!
//! `tap-mcp` mints stateless HMAC access/refresh tokens and authorization codes.
//! Statelessness alone violates two properties the TAP Distributed State Rule
//! requires:
//!
//! 1. **Refresh tokens must be revocable.** A stateless refresh token cannot be
//!    invalidated before its (30-day) expiry, and rotation carries the original
//!    family expiry forward, so a leaked token renews silently. We persist a
//!    *token family* keyed by a random `family_id` with a `revoked` flag and the
//!    `current_jti` of the one live refresh token. Rotation is a single atomic
//!    `UPDATE … WHERE current_jti = <old> AND NOT revoked … RETURNING` — so a
//!    replayed/superseded refresh token fails, and any instance can revoke.
//! 2. **Authorization codes must be single-use.** A stateless code is replayable
//!    for its whole TTL. We record each code's `jti` with an atomic
//!    `INSERT … ON CONFLICT DO NOTHING`, so exactly one exchange wins,
//!    cross-instance.
//!
//! The tables live in the shared Postgres, created by `ConfigStore::new` on
//! boot, so `tap-proxy` can verify a token family's `revoked` flag at `/forward`
//! time (`mcp_auth::resolve_mcp_agent`) and the dashboard can revoke a
//! connection without deleting its agent.
//!
//! # Who calls this
//!
//! **Only `tap-proxy`.** `tap-mcp` has no database access at all: it is an
//! internet-facing OAuth server running outside the attested Azure confidential
//! container group, so a connection string there would be a live credential for
//! the database holding encrypted credential blobs. Its three operations
//! (`record_family`, `rotate_family`, `consume_code`) are invoked on its behalf
//! by `tap-proxy`'s authenticated `/internal/mcp/*` endpoints
//! (`tap-proxy/src/mcp_internal.rs`); the HTTP layer is a thin wrapper that
//! preserves the atomicity of each statement below verbatim. `family_is_active`
//! (per-`/forward`) and `revoke_families_for_agent` (dashboard disconnect) are
//! called directly by the proxy and never cross a network boundary.

use sqlx::{PgPool, Row};

use crate::error::AgentSecError;

/// Schema for the MCP token-state tables. Executed by `ConfigStore::new`.
/// Timestamps are BIGINT unix seconds, matching `tap-mcp`'s `now_timestamp()`.
pub const MCP_TOKEN_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS mcp_token_families (
    family_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    team_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    current_jti TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS mcp_token_families_agent_idx
    ON mcp_token_families(team_id, agent_id);

CREATE TABLE IF NOT EXISTS mcp_consumed_codes (
    jti TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT NOT NULL
);
"#;

fn cfg_err(context: &str, err: sqlx::Error) -> AgentSecError {
    AgentSecError::Config(format!("{context}: {err}"))
}

/// Record a freshly-minted refresh-token family (first issuance, on the
/// authorization_code grant). `family_id` and `jti` are caller-generated random
/// ids; `expires_at` is the absolute family expiry carried through rotations.
#[allow(clippy::too_many_arguments)]
pub async fn record_family(
    pool: &PgPool,
    family_id: &str,
    subject: &str,
    team_id: &str,
    agent_id: &str,
    client_id: &str,
    jti: &str,
    issued_at: i64,
    expires_at: i64,
) -> Result<(), AgentSecError> {
    sqlx::query(
        "INSERT INTO mcp_token_families
             (family_id, subject, team_id, agent_id, client_id, current_jti,
              revoked, issued_at, expires_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7, $8, $7)",
    )
    .bind(family_id)
    .bind(subject)
    .bind(team_id)
    .bind(agent_id)
    .bind(client_id)
    .bind(jti)
    .bind(issued_at)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(|e| cfg_err("record MCP token family", e))?;
    Ok(())
}

/// Atomically rotate a refresh-token family: the presented `old_jti` must be the
/// family's current live token, the family must be un-revoked and un-expired.
/// Exactly one concurrent caller wins (single `UPDATE … RETURNING`); a replayed
/// or already-rotated refresh token matches no row. Returns `true` on success.
pub async fn rotate_family(
    pool: &PgPool,
    family_id: &str,
    old_jti: &str,
    new_jti: &str,
    now: i64,
) -> Result<bool, AgentSecError> {
    let rotated = sqlx::query(
        "UPDATE mcp_token_families
            SET current_jti = $3, updated_at = $4
          WHERE family_id = $1
            AND current_jti = $2
            AND NOT revoked
            AND expires_at > $4
        RETURNING family_id",
    )
    .bind(family_id)
    .bind(old_jti)
    .bind(new_jti)
    .bind(now)
    .fetch_optional(pool)
    .await
    .map_err(|e| cfg_err("rotate MCP token family", e))?;
    Ok(rotated.is_some())
}

/// True when the family exists, is not revoked, and has not passed its absolute
/// expiry. Used by the proxy at `/forward` time to reject an access token whose
/// family was revoked (or expired) even though the short-lived access token
/// itself still verifies. Fail-closed: a DB error propagates.
pub async fn family_is_active(
    pool: &PgPool,
    family_id: &str,
    now: i64,
) -> Result<bool, AgentSecError> {
    let row = sqlx::query(
        "SELECT 1 AS ok FROM mcp_token_families
          WHERE family_id = $1 AND NOT revoked AND expires_at > $2",
    )
    .bind(family_id)
    .bind(now)
    .fetch_optional(pool)
    .await
    .map_err(|e| cfg_err("check MCP token family", e))?;
    Ok(row.is_some())
}

/// Revoke every live token family for a connection's provisioned agent (the
/// per-connection disconnect path). Flips `revoked` WITHOUT deleting the
/// `mcp-<user>` agent, so it can't nuke the user's own re-connection. Returns
/// how many families were revoked.
pub async fn revoke_families_for_agent(
    pool: &PgPool,
    team_id: &str,
    agent_id: &str,
    now: i64,
) -> Result<u64, AgentSecError> {
    let result = sqlx::query(
        "UPDATE mcp_token_families
            SET revoked = TRUE, updated_at = $3
          WHERE team_id = $1 AND agent_id = $2 AND NOT revoked",
    )
    .bind(team_id)
    .bind(agent_id)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| cfg_err("revoke MCP token families", e))?;
    Ok(result.rows_affected())
}

/// Atomically consume an authorization code's `jti` exactly once. The first
/// caller inserts and gets `true`; a replay hits the primary-key conflict,
/// inserts nothing, and gets `false`. Cross-instance safe (the DB is the single
/// arbiter). Best-effort prunes expired rows.
pub async fn consume_code(
    pool: &PgPool,
    jti: &str,
    expires_at: i64,
    now: i64,
) -> Result<bool, AgentSecError> {
    let result = sqlx::query(
        "INSERT INTO mcp_consumed_codes (jti, expires_at, consumed_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (jti) DO NOTHING",
    )
    .bind(jti)
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| cfg_err("consume MCP authorization code", e))?;

    // Bounded best-effort cleanup; never blocks the exchange.
    let _ = sqlx::query("DELETE FROM mcp_consumed_codes WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await;

    Ok(result.rows_affected() == 1)
}

/// Read a family's row for tests/diagnostics (revoked flag + current jti).
pub async fn family_status(
    pool: &PgPool,
    family_id: &str,
) -> Result<Option<(bool, String)>, AgentSecError> {
    let row = sqlx::query(
        "SELECT revoked, current_jti FROM mcp_token_families WHERE family_id = $1",
    )
    .bind(family_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| cfg_err("read MCP token family", e))?;
    match row {
        Some(row) => {
            let revoked: bool = row
                .try_get("revoked")
                .map_err(|e| cfg_err("read MCP token family.revoked", e))?;
            let jti: String = row
                .try_get("current_jti")
                .map_err(|e| cfg_err("read MCP token family.current_jti", e))?;
            Ok(Some((revoked, jti)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[tokio::test]
    async fn refresh_family_rotates_once_and_revokes_cross_instance() {
        // Begin on store A, finish/verify on store B sharing the same schema.
        let (store_a, url) = ConfigStore::new_isolated_test(key()).await;
        let store_b = ConfigStore::new(&url, key()).await.expect("join schema");
        let pool_a = store_a.pool();
        let pool_b = store_b.pool();
        let now = 1_000;
        let expires = now + 3600;

        record_family(pool_a, "fam-1", "u", "t", "mcp-u", "c", "jti-1", now, expires)
            .await
            .expect("record family");

        assert!(family_is_active(pool_b, "fam-1", now).await.unwrap());

        // First rotation with the live jti succeeds (seen from instance B).
        assert!(rotate_family(pool_b, "fam-1", "jti-1", "jti-2", now + 1)
            .await
            .unwrap());
        // Replaying the OLD jti now fails — single-use rotation.
        assert!(!rotate_family(pool_a, "fam-1", "jti-1", "jti-x", now + 2)
            .await
            .unwrap());
        // The new jti is the live one.
        assert_eq!(
            family_status(pool_a, "fam-1").await.unwrap().unwrap().1,
            "jti-2"
        );

        // Per-connection revoke flips the flag; rotation + active check then fail.
        let revoked = revoke_families_for_agent(pool_a, "t", "mcp-u", now + 3)
            .await
            .unwrap();
        assert_eq!(revoked, 1);
        assert!(!family_is_active(pool_b, "fam-1", now + 3).await.unwrap());
        assert!(!rotate_family(pool_b, "fam-1", "jti-2", "jti-3", now + 4)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn expired_family_is_inactive_and_unrotatable() {
        let (store, _url) = ConfigStore::new_isolated_test(key()).await;
        let pool = store.pool();
        record_family(pool, "fam-exp", "u", "t", "a", "c", "j", 100, 200)
            .await
            .unwrap();
        assert!(!family_is_active(pool, "fam-exp", 300).await.unwrap());
        assert!(!rotate_family(pool, "fam-exp", "j", "j2", 300)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn authorization_code_consumes_exactly_once() {
        let (store_a, url) = ConfigStore::new_isolated_test(key()).await;
        let store_b = ConfigStore::new(&url, key()).await.expect("join schema");
        let now = 5_000;
        let expires = now + 120;
        // First consume wins on A, replay loses on B (cross-instance single-use).
        assert!(consume_code(store_a.pool(), "code-1", expires, now)
            .await
            .unwrap());
        assert!(!consume_code(store_b.pool(), "code-1", expires, now + 1)
            .await
            .unwrap());
    }
}
