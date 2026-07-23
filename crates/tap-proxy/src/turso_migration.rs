//! One-time migration from Turso (libsql) to Postgres.
//!
//! Called at proxy startup. Checks for `turso_migration_v1 = done` in the
//! Postgres config table. If absent and TURSO_DATABASE_URL is set, migrates
//! all tables from Turso into Postgres (ON CONFLICT DO NOTHING) then sets
//! the flag. Safe to call on every startup — skips immediately after the
//! first successful run.

use libsql::{Builder, Connection, Value};
use sqlx::PgPool;
use tracing::{info, warn};

const MIGRATION_FLAG: &str = "turso_migration_v1";

pub async fn maybe_migrate(pool: &PgPool) {
    let turso_url = match std::env::var("TURSO_DATABASE_URL") {
        Ok(v) if !v.is_empty() => v,
        _ => return, // no Turso configured — fresh install, nothing to do
    };
    let turso_token = std::env::var("TURSO_AUTH_TOKEN").unwrap_or_default();

    // Check if already done
    match sqlx::query("SELECT value FROM config WHERE key = $1")
        .bind(MIGRATION_FLAG)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(_)) => {
            info!("Turso migration already complete, skipping");
            return;
        }
        Ok(None) => {}
        Err(e) => {
            warn!("Could not check migration flag: {e}. Skipping migration.");
            return;
        }
    }

    info!("Starting one-time migration from Turso → Postgres");

    let db = match Builder::new_remote(turso_url.clone(), turso_token)
        .build()
        .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!("Could not connect to Turso for migration: {e}. Skipping.");
            return;
        }
    };
    let src = match db.connect() {
        Ok(c) => c,
        Err(e) => {
            warn!("Could not open Turso connection: {e}. Skipping.");
            return;
        }
    };

    macro_rules! run {
        ($name:expr, $fn:expr) => {
            match $fn(&src, pool).await {
                Ok(n) => info!(table = $name, rows = n, "Migrated"),
                Err(e) => warn!(table = $name, error = %e, "Migration error (continuing)"),
            }
        };
    }

    run!("teams", migrate_teams);
    // Identity is now `users` + `memberships` (the legacy `admins` table and the
    // webauthn_credentials.admin_id column no longer exist), so the one-time
    // Turso import of those tables is a dead path and has been removed.
    run!("credentials", migrate_credentials);
    run!("roles", migrate_roles);
    run!("role_credentials", migrate_role_credentials);
    run!("agents", migrate_agents);
    run!("agent_roles", migrate_agent_roles);
    run!("agent_credentials", migrate_agent_credentials);
    run!("policies", migrate_policies);
    run!("policy_templates", migrate_policy_templates);
    run!("config", migrate_config);
    run!("approver_passkeys", migrate_approver_passkeys);
    run!("notification_channels", migrate_notification_channels);
    run!("whitelist", migrate_whitelist);
    run!("audit_log", migrate_audit_log);
    run!("async_approvals", migrate_async_approvals);
    run!("pending_approvals", migrate_pending_approvals);

    // Set the done flag
    if let Err(e) =
        sqlx::query("INSERT INTO config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING")
            .bind(MIGRATION_FLAG)
            .bind("done")
            .execute(pool)
            .await
    {
        warn!("Could not set migration flag: {e}");
    } else {
        info!("Turso → Postgres migration complete");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn get_str(row: &libsql::Row, idx: i32) -> Result<String, libsql::Error> {
    match row.get_value(idx)? {
        Value::Text(s) => Ok(s),
        Value::Null => Ok(String::new()),
        other => Ok(format!("{other:?}")),
    }
}

fn get_opt_str(row: &libsql::Row, idx: i32) -> Result<Option<String>, libsql::Error> {
    match row.get_value(idx)? {
        Value::Text(s) => Ok(Some(s)),
        Value::Null => Ok(None),
        other => Ok(Some(format!("{other:?}"))),
    }
}

fn get_bool(row: &libsql::Row, idx: i32) -> Result<bool, libsql::Error> {
    match row.get_value(idx)? {
        Value::Integer(n) => Ok(n != 0),
        _ => Ok(false),
    }
}

fn get_i64(row: &libsql::Row, idx: i32) -> Result<i64, libsql::Error> {
    match row.get_value(idx)? {
        Value::Integer(n) => Ok(n),
        _ => Ok(0),
    }
}

fn get_opt_i64(row: &libsql::Row, idx: i32) -> Result<Option<i64>, libsql::Error> {
    match row.get_value(idx)? {
        Value::Integer(n) => Ok(Some(n)),
        _ => Ok(None),
    }
}

fn get_opt_blob(row: &libsql::Row, idx: i32) -> Result<Option<Vec<u8>>, libsql::Error> {
    match row.get_value(idx)? {
        Value::Blob(b) => Ok(Some(b)),
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Per-table functions — each returns the number of rows read from Turso
// ---------------------------------------------------------------------------

async fn migrate_teams(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src
        .query(
            "SELECT id, name, tier, stripe_customer_id, created_at FROM teams",
            libsql::params![],
        )
        .await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO teams (id, name, tier, stripe_customer_id, created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_opt_str(&row, 3)?).bind(get_str(&row, 4)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_credentials(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query(
        "SELECT name, team_id, description, connector, api_base, relative_target, auth_header_format, auth_bindings_json, encrypted_value, created_at, updated_at FROM credentials",
        libsql::params![],
    ).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO credentials (name, team_id, description, connector, api_base, relative_target, auth_header_format, auth_bindings_json, encrypted_value, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (team_id, name) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_str(&row, 3)?).bind(get_opt_str(&row, 4)?).bind(get_bool(&row, 5)?)
            .bind(get_opt_str(&row, 6)?).bind(get_opt_str(&row, 7)?).bind(get_opt_blob(&row, 8)?)
            .bind(get_str(&row, 9)?).bind(get_str(&row, 10)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_roles(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src
        .query(
            "SELECT name, team_id, description, rate_limit_per_hour, created_at FROM roles",
            libsql::params![],
        )
        .await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO roles (name, team_id, description, rate_limit_per_hour, created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (team_id, name) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_opt_str(&row, 2)?)
            .bind(get_opt_i64(&row, 3)?).bind(get_str(&row, 4)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_role_credentials(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src
        .query(
            "SELECT team_id, role_name, credential_name FROM role_credentials",
            libsql::params![],
        )
        .await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO role_credentials (team_id, role_name, credential_name) VALUES ($1,$2,$3) ON CONFLICT (team_id, role_name, credential_name) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_agents(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query(
        "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, created_at, updated_at FROM agents",
        libsql::params![],
    ).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO agents (id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (team_id, id) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_opt_str(&row, 2)?)
            .bind(get_str(&row, 3)?).bind(get_opt_i64(&row, 4)?).bind(get_bool(&row, 5)?)
            .bind(get_bool(&row, 6)?).bind(get_str(&row, 7)?).bind(get_str(&row, 8)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_agent_roles(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src
        .query(
            "SELECT team_id, agent_id, role_name FROM agent_roles",
            libsql::params![],
        )
        .await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO agent_roles (team_id, agent_id, role_name) VALUES ($1,$2,$3) ON CONFLICT (team_id, agent_id, role_name) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_agent_credentials(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src
        .query(
            "SELECT team_id, agent_id, credential_name FROM agent_credentials",
            libsql::params![],
        )
        .await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO agent_credentials (team_id, agent_id, credential_name) VALUES ($1,$2,$3) ON CONFLICT (team_id, agent_id, credential_name) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_policies(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query(
        "SELECT team_id, credential_name, COALESCE(auto_approve_methods,'[]'), COALESCE(require_approval_methods,'[]'), COALESCE(auto_approve_urls,'[]'), COALESCE(allowed_approvers,'[]'), telegram_chat_id, matrix_room_id, COALESCE(matrix_allowed_approvers,'[]'), COALESCE(require_passkey,0), COALESCE(min_approvals,1) FROM policies",
        libsql::params![],
    ).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO policies (team_id, credential_name, auto_approve_methods, require_approval_methods, auto_approve_urls, allowed_approvers, telegram_chat_id, matrix_room_id, matrix_allowed_approvers, require_passkey, min_approvals) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (team_id, credential_name) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_str(&row, 3)?).bind(get_str(&row, 4)?).bind(get_str(&row, 5)?)
            .bind(get_opt_str(&row, 6)?).bind(get_opt_str(&row, 7)?).bind(get_str(&row, 8)?)
            .bind(get_i64(&row, 9)?).bind(get_i64(&row, 10)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_policy_templates(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query(
        "SELECT team_id, template_name, COALESCE(auto_approve_methods,'[]'), COALESCE(require_approval_methods,'[]'), COALESCE(auto_approve_urls,'[]'), COALESCE(allowed_approvers,'[]'), telegram_chat_id, matrix_room_id, COALESCE(matrix_allowed_approvers,'[]'), COALESCE(require_passkey,0), COALESCE(min_approvals,1), created_at, updated_at FROM policy_templates",
        libsql::params![],
    ).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO policy_templates (team_id, template_name, auto_approve_methods, require_approval_methods, auto_approve_urls, allowed_approvers, telegram_chat_id, matrix_room_id, matrix_allowed_approvers, require_passkey, min_approvals, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (team_id, template_name) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_str(&row, 3)?).bind(get_str(&row, 4)?).bind(get_str(&row, 5)?)
            .bind(get_opt_str(&row, 6)?).bind(get_opt_str(&row, 7)?).bind(get_str(&row, 8)?)
            .bind(get_i64(&row, 9)?).bind(get_i64(&row, 10)?).bind(get_str(&row, 11)?)
            .bind(get_str(&row, 12)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_config(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src
        .query("SELECT key, value FROM config", libsql::params![])
        .await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO config (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_approver_passkeys(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query("SELECT credential_id, approver_name, display_name, public_key_json, created_at FROM approver_passkeys", libsql::params![]).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO approver_passkeys (credential_id, approver_name, display_name, public_key_json, created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (credential_id) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_str(&row, 3)?).bind(get_str(&row, 4)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_notification_channels(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query("SELECT id, team_id, channel_type, name, config_json, enabled, created_at, updated_at FROM notification_channels", libsql::params![]).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO notification_channels (id, team_id, channel_type, name, config_json, enabled, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_str(&row, 3)?).bind(get_str(&row, 4)?).bind(get_bool(&row, 5)?)
            .bind(get_str(&row, 6)?).bind(get_str(&row, 7)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_whitelist(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src
        .query(
            "SELECT email, tier, created_at FROM whitelist",
            libsql::params![],
        )
        .await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO whitelist (email, tier, created_at) VALUES ($1,$2,$3) ON CONFLICT (email) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_audit_log(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query(
        "SELECT request_id, agent_id, credential_names, target_url, method, approval_status, upstream_status, total_latency_ms, approval_latency_ms, upstream_latency_ms, response_sanitized, timestamp FROM audit_log",
        libsql::params![],
    ).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO audit_log (request_id, agent_id, credential_names, target_url, method, approval_status, upstream_status, total_latency_ms, approval_latency_ms, upstream_latency_ms, response_sanitized, timestamp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (request_id) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_str(&row, 3)?).bind(get_str(&row, 4)?).bind(get_opt_str(&row, 5)?)
            .bind(get_opt_i64(&row, 6)?).bind(get_i64(&row, 7)?).bind(get_opt_i64(&row, 8)?)
            .bind(get_opt_i64(&row, 9)?).bind(get_bool(&row, 10)?).bind(get_str(&row, 11)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_async_approvals(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query(
        "SELECT txn_id, agent_id, team_id, status, created_at, expires_at, response_status, response_headers_json, response_body, response_error FROM async_approvals",
        libsql::params![],
    ).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO async_approvals (txn_id, agent_id, team_id, status, created_at, expires_at, response_status, response_headers_json, response_body, response_error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (txn_id) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_str(&row, 3)?).bind(get_str(&row, 4)?).bind(get_str(&row, 5)?)
            .bind(get_opt_i64(&row, 6)?).bind(get_opt_str(&row, 7)?).bind(get_opt_blob(&row, 8)?)
            .bind(get_opt_str(&row, 9)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}

async fn migrate_pending_approvals(
    src: &Connection,
    dst: &PgPool,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut rows = src.query(
        "SELECT txn_id, details_json, status, resolved_by, created_at, expires_at, matrix_event_id, matrix_room_id, allowed_approvers_json, COALESCE(approval_count,0), COALESCE(min_approvals,1) FROM pending_approvals",
        libsql::params![],
    ).await?;
    let mut n = 0usize;
    while let Some(row) = rows.next().await? {
        sqlx::query("INSERT INTO pending_approvals (txn_id, details_json, status, resolved_by, created_at, expires_at, matrix_event_id, matrix_room_id, allowed_approvers_json, approval_count, min_approvals) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (txn_id) DO NOTHING")
            .bind(get_str(&row, 0)?).bind(get_str(&row, 1)?).bind(get_str(&row, 2)?)
            .bind(get_opt_str(&row, 3)?).bind(get_str(&row, 4)?).bind(get_str(&row, 5)?)
            .bind(get_opt_str(&row, 6)?).bind(get_opt_str(&row, 7)?).bind(get_opt_str(&row, 8)?)
            .bind(get_i64(&row, 9)?).bind(get_i64(&row, 10)?).execute(dst).await?;
        n += 1;
    }
    Ok(n)
}
