//! Postgres-backed configuration store for TAP v0.2.
//!
//! Replaces static YAML config with a database that supports hot-reload,
//! RBAC roles, direct per-agent permissions, and encrypted credential storage.

use crate::error::AgentSecError;
use chrono;
use sqlx::Row;
use std::collections::HashSet;

// Re-implement encrypt/decrypt here to avoid cross-crate dependency on tap-proxy.
// Same AES-256-GCM algorithm as crypto.rs.
mod crypto {
    use aes_gcm::aead::{Aead, KeyInit, OsRng};
    use aes_gcm::{Aes256Gcm, Nonce};
    use rand::RngCore;

    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {e}"))?;
        // Store as: nonce (12 bytes) || ciphertext
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("Data too short for nonce".to_string());
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Produce a short display hint for a decrypted credential value.
pub fn credential_value_hint(plaintext: &[u8]) -> String {
    match std::str::from_utf8(plaintext) {
        Ok(s) => {
            let s = s.trim();
            // JSON object → show field names (multi-secret credential)
            if s.starts_with('{') {
                if let Ok(obj) =
                    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s)
                {
                    let keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
                    return format!("{{{}}}", keys.join(", "));
                }
            }
            let chars: Vec<char> = s.chars().collect();
            let n = chars.len();
            if n <= 4 {
                "***".to_string()
            } else {
                let head: String = chars[..2].iter().collect();
                let tail: String = chars[n - 2..].iter().collect();
                format!("{head}***{tail}")
            }
        }
        Err(_) => "[binary]".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TeamRow {
    pub id: String,
    pub name: String,
    pub tier: String,
    pub stripe_customer_id: Option<String>,
    pub created_at: String,
}

/// A person's identity. One row per email, independent of team membership.
/// Part of the identity/membership split that supersedes `AdminRow`.
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub matrix_user_id: Option<String>,
    pub telegram_user_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// A user's membership in one team, carrying their role there.
#[derive(Debug, Clone)]
pub struct Membership {
    pub user_id: String,
    pub team_id: String,
    /// "owner" | "admin" | "approver"
    pub member_role: String,
    pub created_at: String,
}

/// A user resolved in the context of one team — identity joined with the
/// membership for that team. Mirrors the fields of `AdminRow` (so handlers can
/// migrate with minimal churn): `id` is the user id; `team_id`/`member_role`
/// come from the membership; `created_at` is the membership's, `updated_at` the
/// user's.
#[derive(Debug, Clone)]
pub struct Member {
    pub id: String,
    pub team_id: String,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    /// "owner" | "admin" | "approver"
    pub member_role: String,
    pub created_at: String,
    pub updated_at: String,
    pub display_name: Option<String>,
    pub matrix_user_id: Option<String>,
    pub telegram_user_id: Option<String>,
}

impl Member {
    pub fn is_owner(&self) -> bool {
        self.member_role == "owner"
    }
}

#[derive(Debug, Clone)]
pub struct AdminInviteRow {
    pub id: String,
    pub team_id: String,
    pub email: String,
    pub role: String,
    pub invited_by_user_id: String,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct CredentialRow {
    pub name: String,
    pub team_id: String,
    pub description: String,
    pub connector: String,
    pub api_base: Option<String>,
    pub relative_target: bool,
    pub auth_header_format: Option<String>,
    pub auth_bindings_json: Option<String>,
    /// JSON array of destination host patterns (`["api.stripe.com","*.googleapis.com"]`).
    /// `None`/absent = unrestricted. Enforced in `tap-proxy/src/routing.rs` to
    /// stop a compromised agent exfiltrating the injected secret to an
    /// attacker-controlled host.
    pub allowed_hosts_json: Option<String>,
    /// `Some(ext_id)` when this credential is scoped to a managed end-user
    /// (TAP for Platforms); `None` for ordinary team-scoped credentials.
    pub end_user_id: Option<String>,
    /// `Some(app_agent_id)` when this credential was provisioned by a TAP app
    /// key. Used to ensure only the corresponding app can approve managed
    /// end-user requests when policy allows app-mediated approval.
    pub app_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: String,
    pub team_id: String,
    pub description: Option<String>,
    pub api_key_hash: String,
    pub rate_limit_per_hour: Option<i64>,
    pub enabled: bool,
    pub is_admin: bool,
    pub owner_user_id: Option<String>,
    /// Row kind: `"agent"` (an AI caller) or `"app"` (TAP for Platforms — a
    /// partner app key that may assert a managed end-user sub-scope via
    /// `X-TAP-End-User`). Ordinary agent keys cannot assert end-users.
    pub kind: String,
    /// An **Account key**: authorized for every credential in its team,
    /// including ones added later, instead of the per-credential
    /// (`agent_credentials`) whitelist. Workspace-manager-only to set.
    pub all_credentials: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl AgentRow {
    pub fn is_app(&self) -> bool {
        self.kind == "app"
    }
}

#[derive(Debug, Clone)]
pub struct RoleRow {
    pub name: String,
    pub team_id: String,
    pub description: Option<String>,
    pub rate_limit_per_hour: Option<i64>,
    pub created_at: String,
}

/// A policy change staged behind an end-user passkey approval (passkey-lock).
#[derive(Debug, Clone)]
pub struct PendingPolicyChangeRow {
    pub txn_id: String,
    pub team_id: String,
    pub credential_name: String,
    pub required_end_user: String,
    pub proposed_policy_json: String,
    pub status: String,
}

/// A managed end-user of a platform partner (TAP for Platforms). Scoped to one
/// team; `ext_id` is the partner's own user id and is only unique within a team.
#[derive(Debug, Clone)]
pub struct EndUserRow {
    pub team_id: String,
    pub ext_id: String,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

/// A time-boxed approval grant (#49): a human-authored auto-approve rule with
/// a TTL, an optional use cap, and a narrow method+route scope. Conceptually
/// "auto_approve_urls with a lifecycle" — it skips the human prompt, never
/// proxy enforcement (audit, sanitization, allowed_hosts all still apply).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GrantRow {
    pub id: String,
    pub team_id: String,
    pub credential_name: String,
    /// HTTP methods the grant covers (uppercase, non-empty).
    pub methods: Vec<String>,
    /// URL patterns (same structural matcher as `auto_approve_urls`), non-empty.
    pub route_scope: Vec<String>,
    /// RFC 3339; compared against an injected `now`, never the ambient clock.
    pub expires_at: String,
    /// Email of the workspace manager who authored the grant.
    pub granted_by: String,
    /// None = time-boxed only; Some(n) additionally caps total uses.
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub revoked: bool,
    pub created_at: String,
}

fn grant_row_from_pg(row: &sqlx::postgres::PgRow) -> Result<GrantRow, AgentSecError> {
    use sqlx::Row;
    let get = |col: &str| -> Result<String, AgentSecError> {
        row.try_get::<String, _>(col)
            .map_err(|e| AgentSecError::Config(format!("Bad grant row column {col}: {e}")))
    };
    let json_vec = |col: &str| -> Result<Vec<String>, AgentSecError> {
        serde_json::from_str(&get(col)?)
            .map_err(|e| AgentSecError::Config(format!("Bad grant row JSON in {col}: {e}")))
    };
    Ok(GrantRow {
        id: get("id")?,
        team_id: get("team_id")?,
        credential_name: get("credential_name")?,
        methods: json_vec("methods")?,
        route_scope: json_vec("route_scope")?,
        expires_at: get("expires_at")?,
        granted_by: get("granted_by")?,
        max_uses: row
            .try_get::<Option<i64>, _>("max_uses")
            .map_err(|e| AgentSecError::Config(format!("Bad grant row column max_uses: {e}")))?,
        uses: row
            .try_get::<i64, _>("uses")
            .map_err(|e| AgentSecError::Config(format!("Bad grant row column uses: {e}")))?,
        revoked: row
            .try_get::<bool, _>("revoked")
            .map_err(|e| AgentSecError::Config(format!("Bad grant row column revoked: {e}")))?,
        created_at: get("created_at")?,
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyRow {
    pub credential_name: String,
    pub team_id: String,
    pub auto_approve_methods: Vec<String>,
    pub require_approval_methods: Vec<String>,
    pub auto_approve_urls: Vec<String>,
    pub require_approval_urls: Vec<String>,
    pub allowed_approvers: Vec<String>,
    pub approval_channel: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub matrix_room_id: Option<String>,
    pub matrix_allowed_approvers: Vec<String>,
    pub require_passkey: bool,
    pub min_approvals: u32,
}

#[derive(Debug, Clone)]
pub struct PolicyTemplateRow {
    pub template_name: String,
    pub team_id: String,
    pub auto_approve_methods: Vec<String>,
    pub require_approval_methods: Vec<String>,
    pub auto_approve_urls: Vec<String>,
    pub require_approval_urls: Vec<String>,
    pub allowed_approvers: Vec<String>,
    pub approval_channel: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub matrix_room_id: Option<String>,
    pub matrix_allowed_approvers: Vec<String>,
    pub require_passkey: bool,
    pub min_approvals: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct NotificationChannelRow {
    pub id: String,
    pub team_id: String,
    pub channel_type: String,
    pub name: String,
    pub config_json: String,
    pub enabled: bool,
    pub priority: i32,
    pub created_at: String,
    pub updated_at: String,
}

/// A pending approval as surfaced to the dashboard inbox. `details_json` is the
/// serialized request detail (target, method, body preview, allowed approvers);
/// the caller deserializes it into the proxy-side `ApprovalDetails` shape.
#[derive(Debug, Clone)]
pub struct PendingApprovalRow {
    pub txn_id: String,
    pub details_json: String,
    pub created_at: String,
    pub expires_at: String,
}

/// An agent-originated proposal awaiting a workspace manager's decision.
/// `payload_json` is the serialized proposal payload (currently a policy change).
/// `agent_id` is the proposing agent (not FK'd — survives agent deletion as an
/// audit record). Resolution is a single atomic claim (see `resolve_proposal`).
#[derive(Debug, Clone)]
pub struct ProposalRow {
    pub id: String,
    pub team_id: String,
    pub agent_id: String,
    pub proposal_type: String,
    pub payload_json: String,
    pub status: String,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

/// A browser Web Push subscription registered by a team member for approval
/// notifications. `p256dh` and `auth` are the subscription's public encryption
/// keys (base64url), used by the sender to encrypt the push payload (RFC 8291).
#[derive(Debug, Clone)]
pub struct PushSubscriptionRow {
    pub endpoint: String,
    pub team_id: String,
    pub user_email: String,
    pub p256dh: String,
    pub auth: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct ApproverPasskeyRow {
    pub credential_id: String,
    pub approver_name: String,
    pub display_name: String,
    pub public_key_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct UserPasskeyRow {
    pub credential_id: String,
    pub user_id: String,
    pub public_key_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct AsyncApprovalRow {
    pub txn_id: String,
    pub agent_id: String,
    pub team_id: String,
    /// "pending" | "forwarded" | "denied" | "timed_out" | "error"
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    pub response_status: Option<u16>,
    pub response_headers_json: Option<String>,
    pub response_body: Option<Vec<u8>>,
    pub response_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MatrixApprovalData {
    pub txn_id: String,
    pub room_id: String,
    pub event_id: String,
    pub allowed_approvers_json: String,
    pub approval_count: usize,
    pub min_approvals: usize,
    pub status: String,
}

/// Normalize a Supabase connection URL onto the **session pooler** (`:5432`).
///
/// Supabase exposes two PgBouncer endpoints: the transaction pooler on `:6543`
/// and the session pooler on `:5432`. sqlx issues *named* prepared statements,
/// which break on the transaction pooler — a statement prepared on one backend
/// vanishes when the next transaction is multiplexed onto a different backend,
/// surfacing as intermittent `prepared statement "sqlx_s_N" does not exist` /
/// `already exists` errors under concurrency (worst on pages that fan out
/// parallel queries). The session pooler pins one backend per connection for its
/// lifetime, so named statements are safe.
///
/// We normalize in the one place every pool connection is built so that no deploy
/// path (env var, secret, or workflow string-rewrite) can route runtime traffic
/// onto the transaction pooler. Only a Supabase pooler host on `:6543` is touched;
/// the rewrite is scoped to the URL's `host:port` (after the last `@`) so a literal
/// `:6543` inside a password is never altered. Any other URL is returned unchanged.
pub(crate) fn normalize_supabase_pooler_url(database_url: &str) -> String {
    let Some(scheme_end) = database_url.find("://") else {
        return database_url.to_string();
    };
    let authority_start = scheme_end + 3;
    let rest = &database_url[authority_start..];
    // Authority ends at the first '/' (path) or '?' (query), whichever comes first.
    let authority_len = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_len];

    // Strip userinfo: host:port is whatever follows the last '@'.
    let host_port_start = authority.rfind('@').map(|i| i + 1).unwrap_or(0);
    let host_port = &authority[host_port_start..];

    // Supabase pooler is a hostname (no IPv6 brackets), so the last ':' is the port.
    let Some((host, port)) = host_port.rsplit_once(':') else {
        return database_url.to_string();
    };
    if port != "6543" || !host.contains("pooler.supabase.com") {
        return database_url.to_string();
    }

    let abs_port_start = authority_start + host_port_start + host.len() + 1; // +1 for ':'
    let abs_port_end = abs_port_start + port.len();
    let mut out = String::with_capacity(database_url.len());
    out.push_str(&database_url[..abs_port_start]);
    out.push_str("5432");
    out.push_str(&database_url[abs_port_end..]);

    tracing::warn!(
        host = %host,
        "POSTGRES_DATABASE_URL pointed at the Supabase transaction pooler (:6543); \
         rewrote to the session pooler (:5432) — sqlx prepared statements require it"
    );
    out
}

/// A pending Google OAuth consent flow, persisted in `oauth_states` so the
/// callback can be served by any stateless proxy instance and survive a restart.
/// Single-use: claimed atomically (DELETE … RETURNING) by the callback.
#[derive(Debug, Clone)]
pub struct OAuthState {
    pub admin_id: String,
    pub team_id: String,
    pub credential_name: String,
    pub credential_description: String,
    /// Space-separated scope URLs requested at consent time. The callback
    /// compares these against the scopes Google actually granted (the user can
    /// uncheck individual scopes on the granular consent screen).
    pub scopes: String,
    /// OAuth flow mode. `create` creates a new credential; `reauthorize`
    /// updates the encrypted value for an existing credential.
    pub flow_type: String,
    /// OAuth provider (`google` | `microsoft`). The provider-specific callback
    /// asserts this matches to avoid cross-consuming another provider's state.
    pub provider: String,
    /// `Some(ext_id)` for a TAP-mediated per-end-user OAuth flow: the callback
    /// stores the bundle scoped to this managed end-user.
    pub end_user_id: Option<String>,
    /// Where to send the user's browser after the callback completes (the
    /// partner's app). `None` ⇒ the TAP dashboard (the admin-initiated flow).
    pub return_url: Option<String>,
    /// Agent key ids the callback grants the created credential to (chosen on the
    /// connect page under the start passkey). Empty ⇒ created unassigned. Only
    /// honored for the team-scoped `create` flow.
    pub assign_agents: Vec<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// ConfigStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ConfigStore {
    pool: sqlx::PgPool,
    encryption_key: [u8; 32],
}

/// Result of a CLI device-code poll (`claim_device_authorization`).
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceClaim {
    Pending,
    Approved { user_id: String, team_id: String },
    Denied,
    ExpiredOrUnknown,
}

/// Metadata for a pending credential setup (`tap cred set`), WITHOUT the secret.
/// Returned to the CLI poll and the dashboard activation page.
#[derive(Debug, Clone)]
pub struct CredentialSetupInfo {
    pub setup_id: String,
    pub team_id: String,
    pub created_by: String,
    pub name: String,
    pub description: String,
    pub allowed_hosts_json: Option<String>,
    pub status: String,
    pub expires_at: String,
}

/// A claimed credential setup: everything needed to write the live credential,
/// including the DECRYPTED secret. Only produced by `activate_credential_setup`
/// after the passkey ceremony; never serialized or returned over the wire.
#[derive(Debug, Clone)]
pub struct CredentialSetupData {
    pub team_id: String,
    pub created_by: String,
    pub name: String,
    pub description: String,
    pub connector: String,
    pub api_base: Option<String>,
    pub auth_header_format: Option<String>,
    pub allowed_hosts_json: Option<String>,
    pub plaintext_value: Vec<u8>,
    /// Gate every agent action on the resulting credential behind a passkey
    /// approval (set at `tap cred set --require-passkey`; applied at activation).
    pub require_passkey: bool,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL DEFAULT 'free',
    stripe_customer_id TEXT,
    default_approval_mode TEXT NOT NULL DEFAULT 'gated',
    created_at TEXT NOT NULL
);

-- Identity: one row per person, email globally unique. Password, email
-- verification, and personal identity fields live here (not per team). The
-- legacy `admins` table has been dropped; its data was migrated into
-- users/memberships by `backfill_identity_from_admins` before the drop.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    display_name TEXT,
    matrix_user_id TEXT,
    telegram_user_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Membership: which team a user belongs to, and at what role. A person can
-- belong to many teams; the role is per (user, team).
CREATE TABLE IF NOT EXISTS memberships (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    member_role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, team_id)
);

CREATE TABLE IF NOT EXISTS admin_invites (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    invited_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    -- 'full' = dashboard login (full management API). 'agent' = a session minted
    -- by `tap login` for a CLI/agent: restricted at the router to a tiny
    -- allowlist so a compromised agent that reads the token can't drive the
    -- privileged dashboard API. See the agent-session guard in tap-proxy.
    scope TEXT NOT NULL DEFAULT 'full'
);

-- OAuth-style device authorization flow for the CLI (`tap login`). The raw
-- device_code / session token are NEVER stored: only the device_code hash
-- lives here, and the session is minted at claim time from user_id/team_id.
-- status: pending -> approved (human confirmed in dashboard) -> claimed (CLI
-- retrieved a session) | denied.
CREATE TABLE IF NOT EXISTS device_authorizations (
    device_code_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending',
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Dashboard-free credential setup (`tap cred set`): the CLI stores the secret
-- here (encrypted at rest, exactly like a live credential value) over the user's
-- session; it becomes a real credential only after the CREATOR approves it with a
-- passkey on the dashboard. status: pending -> activated. Single-use; expired
-- rows are pruned on create (mirrors device_authorizations).
CREATE TABLE IF NOT EXISTS credential_setups (
    setup_id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    connector TEXT NOT NULL DEFAULT 'direct',
    api_base TEXT,
    auth_header_format TEXT,
    allowed_hosts_json TEXT,
    require_passkey BOOLEAN NOT NULL DEFAULT FALSE,
    encrypted_value BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS email_verifications (
    code_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    -- At most one live reset per user is enforced by a UNIQUE INDEX
    -- (password_resets_user_id_unique) created UNCONDITIONALLY after the
    -- identity backfill in `new()` — deliberately NOT a column constraint here,
    -- because `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so a
    -- column-level UNIQUE would be missing on any DB created before this change
    -- (e.g. a prod install already past the admins->users cutover). Creating the
    -- index in `new()` guarantees it in every install state (fresh / legacy /
    -- already-migrated). `create_password_reset`'s ON CONFLICT (user_id) upsert
    -- relies on it to serialize concurrent /forgot-password requests (#119).
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    name TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    connector TEXT NOT NULL DEFAULT 'direct',
    api_base TEXT,
    relative_target BOOLEAN NOT NULL DEFAULT FALSE,
    auth_header_format TEXT,
    auth_bindings_json TEXT,
    allowed_hosts_json TEXT,
    encrypted_value BYTEA,
    app_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (team_id, name)
);

CREATE TABLE IF NOT EXISTS roles (
    name TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    description TEXT,
    rate_limit_per_hour BIGINT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (team_id, name)
);

CREATE TABLE IF NOT EXISTS role_credentials (
    team_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    credential_name TEXT NOT NULL,
    PRIMARY KEY (team_id, role_name, credential_name),
    FOREIGN KEY (team_id, role_name) REFERENCES roles(team_id, name) ON DELETE CASCADE,
    FOREIGN KEY (team_id, credential_name) REFERENCES credentials(team_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    description TEXT,
    api_key_hash TEXT NOT NULL UNIQUE,
    rate_limit_per_hour BIGINT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL DEFAULT 'agent',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (team_id, id)
);

CREATE TABLE IF NOT EXISTS agent_roles (
    team_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    PRIMARY KEY (team_id, agent_id, role_name),
    FOREIGN KEY (team_id, agent_id) REFERENCES agents(team_id, id) ON DELETE CASCADE,
    FOREIGN KEY (team_id, role_name) REFERENCES roles(team_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_credentials (
    team_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    credential_name TEXT NOT NULL,
    PRIMARY KEY (team_id, agent_id, credential_name),
    FOREIGN KEY (team_id, agent_id) REFERENCES agents(team_id, id) ON DELETE CASCADE,
    FOREIGN KEY (team_id, credential_name) REFERENCES credentials(team_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policies (
    team_id TEXT NOT NULL,
    credential_name TEXT NOT NULL,
    auto_approve_methods TEXT NOT NULL DEFAULT '[]',
    require_approval_methods TEXT NOT NULL DEFAULT '[]',
    auto_approve_urls TEXT NOT NULL DEFAULT '[]',
    require_approval_urls TEXT NOT NULL DEFAULT '[]',
    allowed_approvers TEXT NOT NULL DEFAULT '[]',
    approval_channel TEXT,
    telegram_chat_id TEXT,
    matrix_room_id TEXT,
    matrix_allowed_approvers TEXT NOT NULL DEFAULT '[]',
    require_passkey INTEGER NOT NULL DEFAULT 0,
    min_approvals INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (team_id, credential_name),
    FOREIGN KEY (team_id, credential_name) REFERENCES credentials(team_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key_json TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approver_passkeys (
    credential_id TEXT PRIMARY KEY,
    approver_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    public_key_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_channels (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    channel_type TEXT NOT NULL DEFAULT 'telegram',
    name TEXT NOT NULL,
    config_json TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 1000,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(team_id, name)
);

CREATE TABLE IF NOT EXISTS whitelist (
    email TEXT PRIMARY KEY,
    tier TEXT NOT NULL DEFAULT 'pro',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limit_counters (
    agent_id TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, window_start)
);

CREATE TABLE IF NOT EXISTS relay_sessions (
    session_key TEXT PRIMARY KEY,
    holder TEXT NOT NULL,
    connected_at BIGINT NOT NULL,
    last_heartbeat BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    request_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    credential_names TEXT NOT NULL,
    target_url TEXT NOT NULL,
    method TEXT NOT NULL,
    approval_status TEXT,
    upstream_status INTEGER,
    total_latency_ms INTEGER NOT NULL,
    approval_latency_ms INTEGER,
    upstream_latency_ms INTEGER,
    response_sanitized BOOLEAN NOT NULL DEFAULT FALSE,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS async_approvals (
    txn_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    response_status BIGINT,
    response_headers_json TEXT,
    response_body BYTEA,
    response_error TEXT
);

CREATE TABLE IF NOT EXISTS policy_templates (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    template_name TEXT NOT NULL,
    auto_approve_methods TEXT NOT NULL DEFAULT '[]',
    require_approval_methods TEXT NOT NULL DEFAULT '[]',
    auto_approve_urls TEXT NOT NULL DEFAULT '[]',
    require_approval_urls TEXT NOT NULL DEFAULT '[]',
    allowed_approvers TEXT NOT NULL DEFAULT '[]',
    approval_channel TEXT,
    telegram_chat_id TEXT,
    matrix_room_id TEXT,
    matrix_allowed_approvers TEXT NOT NULL DEFAULT '[]',
    require_passkey INTEGER NOT NULL DEFAULT 0,
    min_approvals INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (team_id, template_name)
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    txn_id TEXT PRIMARY KEY,
    details_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    resolved_by TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    matrix_event_id TEXT,
    matrix_room_id TEXT,
    telegram_chat_id TEXT,
    telegram_message_id BIGINT,
    allowed_approvers_json TEXT,
    approval_challenge_json TEXT,
    approval_count INTEGER NOT NULL DEFAULT 0,
    min_approvals INTEGER NOT NULL DEFAULT 1,
    required_end_user TEXT
);

CREATE TABLE IF NOT EXISTS proposals (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    proposal_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    resolved_by TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS proposals_team_status_idx ON proposals(team_id, status);

-- In-flight WebAuthn login challenges. Durable so that `begin_user_login` on one
-- stateless proxy instance and `finish_user_login` on another share the challenge
-- state (the in-memory map was instance-local, causing intermittent login
-- failures behind a load balancer). Single-use: the row is deleted on claim.
CREATE TABLE IF NOT EXISTS user_login_challenges (
    passkey_token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    challenge_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- In-flight WebAuthn registration challenges (passkey setup / add-a-passkey).
-- Durable for the same reason as user_login_challenges: `begin` and `finish`
-- may be served by different proxy instances. Keyed by user_id (one in-flight
-- registration per user; a new begin overwrites the prior one).
CREATE TABLE IF NOT EXISTS user_registration_challenges (
    user_id TEXT PRIMARY KEY,
    challenge_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- In-flight WebAuthn registration challenges for approver/end-user passkeys
-- (keyed by the free-form approver_name, e.g. `eu:{team}:{ext}`). Durable so a
-- headless register-begin on one instance can be finished on another — the old
-- approver registration used an instance-local in-memory map, a Distributed
-- State Rule violation for the account-less platform passkey flow.
CREATE TABLE IF NOT EXISTS approver_registration_challenges (
    approver_name TEXT PRIMARY KEY,
    challenge_json TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

"#;

/// Build a `User` (identity only) from a `users` row.
fn row_to_proposal(row: sqlx::postgres::PgRow) -> Result<ProposalRow, AgentSecError> {
    use sqlx::Row as _;
    let g = |c: &str| {
        row.try_get::<String, _>(c)
            .map_err(|e| AgentSecError::Config(format!("proposal.{c}: {e}")))
    };
    Ok(ProposalRow {
        id: g("id")?,
        team_id: g("team_id")?,
        agent_id: g("agent_id")?,
        proposal_type: g("proposal_type")?,
        payload_json: g("payload_json")?,
        status: g("status")?,
        resolved_by: row.try_get("resolved_by").unwrap_or(None),
        resolved_at: row.try_get("resolved_at").unwrap_or(None),
        created_at: g("created_at")?,
        expires_at: g("expires_at")?,
    })
}

fn user_from_query(row: &sqlx::postgres::PgRow, ctx: &str) -> Result<User, AgentSecError> {
    use sqlx::Row as _;
    Ok(User {
        id: row
            .try_get("id")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        email: row
            .try_get("email")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        password_hash: row
            .try_get("password_hash")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        email_verified: row
            .try_get("email_verified")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        display_name: row.try_get("display_name").unwrap_or(None),
        matrix_user_id: row.try_get("matrix_user_id").unwrap_or(None),
        telegram_user_id: row.try_get("telegram_user_id").unwrap_or(None),
        created_at: row
            .try_get("created_at")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
    })
}

/// Build a `Member` from a row produced by a `users JOIN memberships` query.
/// Expected aliased columns: id, team_id, email, password_hash, email_verified,
/// member_role, created_at (membership), updated_at (user), display_name,
/// matrix_user_id, telegram_user_id.
fn member_from_query(row: &sqlx::postgres::PgRow, ctx: &str) -> Result<Member, AgentSecError> {
    use sqlx::Row as _;
    Ok(Member {
        id: row
            .try_get("id")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        team_id: row
            .try_get("team_id")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        email: row
            .try_get("email")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        password_hash: row
            .try_get("password_hash")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        email_verified: row
            .try_get("email_verified")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        member_role: row
            .try_get("member_role")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| AgentSecError::Config(format!("{ctx}: {e}")))?,
        display_name: row.try_get("display_name").unwrap_or(None),
        matrix_user_id: row.try_get("matrix_user_id").unwrap_or(None),
        telegram_user_id: row.try_get("telegram_user_id").unwrap_or(None),
    })
}

impl ConfigStore {
    pub async fn new(database_url: &str, encryption_key: [u8; 32]) -> Result<Self, AgentSecError> {
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
        use sqlx::Executor as _;
        use std::str::FromStr as _;
        use std::time::Duration;

        // Guarantee runtime traffic uses Supabase's session pooler (:5432); sqlx's
        // named prepared statements break on the transaction pooler (:6543). Done
        // here so no deploy path can footgun it. See normalize_supabase_pooler_url.
        let normalized_url = normalize_supabase_pooler_url(database_url);
        let database_url = normalized_url.as_str();

        // Pool settings that prevent stale-connection failures after days of low traffic.
        // test_before_acquire: re-ping each connection before handing it to a caller,
        //   so silently-dead connections (Supabase idle timeout) are replaced immediately.
        // max_lifetime: recycle connections every 25 minutes; Supabase drops idle ones ~5 min.
        // idle_timeout: return idle connections to the OS after 10 minutes.
        // acquire_timeout: surface pool exhaustion as a clean error instead of hanging forever.
        let pool_opts = PgPoolOptions::new()
            .max_connections(10)
            .min_connections(1)
            .max_lifetime(Duration::from_secs(25 * 60))
            .idle_timeout(Duration::from_secs(10 * 60))
            .acquire_timeout(Duration::from_secs(30))
            .test_before_acquire(true)
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
            });

        let ca_cert_path = std::env::var("TAP_POSTGRES_CA_CERT_PATH")
            .unwrap_or_else(|_| "/etc/ssl/certs/tap-supabase-ca.crt".to_string());
        let pool = if std::path::Path::new(&ca_cert_path).exists() {
            let opts = PgConnectOptions::from_str(database_url)
                .map_err(|e| AgentSecError::Config(format!("Invalid database URL: {e}")))?
                .statement_cache_capacity(0)
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert(&ca_cert_path);
            pool_opts.connect_with(opts).await
        } else {
            let opts = PgConnectOptions::from_str(database_url)
                .map_err(|e| AgentSecError::Config(format!("Invalid database URL: {e}")))?
                .statement_cache_capacity(0);
            pool_opts.connect_with(opts).await
        }
        .map_err(|e| AgentSecError::Config(format!("Failed to connect to database: {e}")))?;

        sqlx::raw_sql(SCHEMA)
            .execute(&pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Schema init failed: {e}")))?;

        // Remote MCP server token-state tables (durable refresh-token families +
        // single-use authorization codes). Kept in their own module so tap-mcp
        // can init the identical tables from its own pool; idempotent here so the
        // proxy has them for the `/forward`-time family-revocation check.
        sqlx::raw_sql(crate::mcp_tokens::MCP_TOKEN_SCHEMA)
            .execute(&pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("MCP token schema init failed: {e}")))?;

        // Idempotent migrations
        let migrations: &[&str] = &[
            // Team-wide default approval posture (see config::ApprovalMode).
            // Defaults to 'gated' so existing teams keep historical behavior;
            // the flip to 'autonomous' only happens on explicit opt-in.
            "ALTER TABLE teams ADD COLUMN IF NOT EXISTS default_approval_mode TEXT NOT NULL DEFAULT 'gated'",
            // Session scope: 'full' (dashboard) vs 'agent' (`tap login`, router-
            // restricted). Existing rows backfill to 'full' (unchanged behavior).
            "ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'full'",
            "ALTER TABLE policies ADD COLUMN IF NOT EXISTS require_passkey BIGINT NOT NULL DEFAULT 0",
            "ALTER TABLE policies ADD COLUMN IF NOT EXISTS require_approval_urls TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE policies ADD COLUMN IF NOT EXISTS approval_channel TEXT",
            "ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS approval_channel TEXT",
            "ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS require_approval_urls TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 1000",
            "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS auth_bindings_json TEXT",
            "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS allowed_hosts_json TEXT",
            "ALTER TABLE policies ADD COLUMN IF NOT EXISTS matrix_room_id TEXT",
            "ALTER TABLE policies ADD COLUMN IF NOT EXISTS matrix_allowed_approvers TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE policies ADD COLUMN IF NOT EXISTS min_approvals BIGINT NOT NULL DEFAULT 1",
            "ALTER TABLE admins ADD COLUMN IF NOT EXISTS display_name TEXT",
            "ALTER TABLE admins ADD COLUMN IF NOT EXISTS matrix_user_id TEXT",
            "ALTER TABLE admins ADD COLUMN IF NOT EXISTS telegram_user_id TEXT",
            "ALTER TABLE admins ADD COLUMN IF NOT EXISTS is_owner BOOLEAN NOT NULL DEFAULT FALSE",
            "CREATE TABLE IF NOT EXISTS admin_invites (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
                email TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                invited_by_admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS password_resets (
                token_hash TEXT PRIMARY KEY,
                admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            // Promote INTEGER columns to BIGINT to match Rust i64 types.
            // These were INTEGER in the original schema; ALTER TYPE is idempotent
            // (no-op if already BIGINT) and errors are silently ignored below.
            "ALTER TABLE agents ALTER COLUMN rate_limit_per_hour TYPE BIGINT",
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS owner_user_id TEXT",
            "ALTER TABLE roles ALTER COLUMN rate_limit_per_hour TYPE BIGINT",
            "ALTER TABLE async_approvals ALTER COLUMN response_status TYPE BIGINT",
            "ALTER TABLE audit_log ALTER COLUMN upstream_status TYPE BIGINT",
            "ALTER TABLE audit_log ALTER COLUMN total_latency_ms TYPE BIGINT",
            "ALTER TABLE audit_log ALTER COLUMN approval_latency_ms TYPE BIGINT",
            "ALTER TABLE audit_log ALTER COLUMN upstream_latency_ms TYPE BIGINT",
            "ALTER TABLE pending_approvals ALTER COLUMN approval_count TYPE BIGINT",
            "ALTER TABLE pending_approvals ALTER COLUMN min_approvals TYPE BIGINT",
            "ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS telegram_chat_id TEXT",
            "ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS telegram_message_id BIGINT",
            "ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS approval_challenge_json TEXT",
            "ALTER TABLE admins ADD COLUMN IF NOT EXISTS is_owner BOOLEAN NOT NULL DEFAULT FALSE",
            "CREATE TABLE IF NOT EXISTS admin_invites (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE, email TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, invited_by_admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL)",
            // member_role replaces is_owner boolean with a 3-tier string enum.
            "ALTER TABLE admins ADD COLUMN IF NOT EXISTS member_role TEXT NOT NULL DEFAULT 'admin'",
            "UPDATE admins SET member_role = 'owner' WHERE is_owner = TRUE AND member_role = 'admin'",
            // Per-team email uniqueness: one email can belong to multiple teams.
            "ALTER TABLE admins DROP CONSTRAINT IF EXISTS admins_email_key",
            "CREATE UNIQUE INDEX IF NOT EXISTS admins_email_team_unique ON admins(email, team_id)",
            // Role carried on the invite so accept knows what to grant.
            "ALTER TABLE admin_invites ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'admin'",
            // Per-approver credential allow-list (used when member_role = 'approver').
            // `member_id` holds a user id (post identity/membership cutover), so
            // the FK references users(id). On existing installs that predate the
            // cutover, the table already exists referencing the now-dropped
            // `admins` table; the repoint logic in
            // `backfill_identity_from_admins` swaps that FK to users(id).
            "CREATE TABLE IF NOT EXISTS member_credentials (
                team_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                credential_name TEXT NOT NULL,
                PRIMARY KEY (team_id, member_id, credential_name),
                FOREIGN KEY (member_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (team_id, credential_name) REFERENCES credentials(team_id, name) ON DELETE CASCADE
            )",
            // Rename member -> approver role value and table name.
            "UPDATE admins SET member_role = 'approver' WHERE member_role = 'member'",
            "ALTER TABLE member_credentials RENAME TO approver_credentials",
            // Dashboard approval channel: team-scoped pending lookups for the
            // in-dashboard approvals inbox. team_id was previously only inside
            // details_json; promote it to an indexed column.
            "ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS team_id TEXT",
            "CREATE INDEX IF NOT EXISTS pending_approvals_team_status_idx ON pending_approvals(team_id, status)",
            // Web Push subscriptions for the dashboard approval channel. One row
            // per browser/device that opted into approval notifications. Keyed by
            // endpoint (the push service URL is globally unique per subscription).
            "CREATE TABLE IF NOT EXISTS push_subscriptions (
                endpoint TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                user_email TEXT NOT NULL,
                p256dh TEXT NOT NULL,
                auth TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS push_subscriptions_team_idx ON push_subscriptions(team_id)",
            "CREATE TABLE IF NOT EXISTS proposals (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                proposal_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                resolved_by TEXT,
                resolved_at TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS proposals_team_status_idx ON proposals(team_id, status)",
            // /agent/logs reads `WHERE agent_id = $1 ORDER BY timestamp DESC LIMIT $2`.
            // Without this index it is a full scan + sort of the whole audit_log, which
            // grows one row per proxied request — the read got slow enough on a busy
            // table to block a worker thread (see handle_agent_logs spawn_blocking).
            "CREATE INDEX IF NOT EXISTS audit_log_agent_timestamp_idx ON audit_log(agent_id, timestamp DESC)",
            // OAuth consent flow state. The /admin/oauth/google/start handler and
            // the public /oauth/google/callback can run on different stateless
            // instances (and the flow can span a restart), so this state must be
            // durable — it was an instance-local in-memory map, a Distributed State
            // Rule violation that breaks the callback when it lands on another node.
            "CREATE TABLE IF NOT EXISTS oauth_states (
                state_hash TEXT PRIMARY KEY,
                admin_id TEXT NOT NULL,
                team_id TEXT NOT NULL,
                credential_name TEXT NOT NULL,
                credential_description TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            // Requested scopes, recorded so the callback can detect partial
            // grants (Google's granular consent lets users uncheck scopes).
            "ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT ''",
            // `create` is the legacy behavior. `reauthorize` is used by Google
            // credential repair flows that replace only the refresh token.
            "ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS flow_type TEXT NOT NULL DEFAULT 'create'",
            // OAuth provider for the flow (`google` | `microsoft`). Default
            // `google` for back-compat with rows created before Microsoft support.
            // The provider-specific callback asserts this matches so the two
            // callbacks can't cross-consume each other's state.
            "ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'google'",
            // -- TAP for Platforms: managed end-users --------------------------
            // A partner (the team) provisions credentials on behalf of its own
            // end-users, who never hold a TAP account. `ext_id` is the partner's
            // own user id — only meaningful within a team, so (team_id, ext_id)
            // makes cross-team isolation structural.
            "CREATE TABLE IF NOT EXISTS end_users (
                team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
                ext_id TEXT NOT NULL,
                display_name TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                last_seen_at TEXT,
                PRIMARY KEY (team_id, ext_id)
            )",
            "CREATE INDEX IF NOT EXISTS end_users_team_idx ON end_users(team_id)",
            // A credential may be scoped to one end-user. NULL = team-scoped
            // (existing behavior, unchanged). The stored `name` for an end-user
            // credential is namespaced (`eu:{ext_id}/{logical}`) so it stays
            // unique under the existing (team_id, name) PK without disturbing the
            // FK web; this column is the authoritative isolation check.
            "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS end_user_id TEXT",
            "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS app_id TEXT",
            "CREATE INDEX IF NOT EXISTS credentials_team_enduser_idx ON credentials(team_id, end_user_id)",
            "CREATE INDEX IF NOT EXISTS credentials_team_app_idx ON credentials(team_id, app_id)",
            // Legacy: the original TAP-for-Platforms flag. Superseded by
            // `kind='app'` below; kept (non-destructive) and backfilled.
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS is_platform BOOLEAN NOT NULL DEFAULT FALSE",
            // An app key (TAP for Platforms) is an `agents` row with kind='app'.
            // It manages end-users; ordinary AI-caller keys keep kind='agent'.
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'agent'",
            "UPDATE agents SET kind = 'app' WHERE is_platform = TRUE",
            // "Account key": authorized for every credential in the team,
            // including ones added later, bypassing the per-credential
            // (`agent_credentials`) whitelist. Opt-in, workspace-manager-only.
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS all_credentials BOOLEAN NOT NULL DEFAULT FALSE",
            // Audit + metering dimension. Nullable; backfill not needed.
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS end_user_id TEXT",
            "CREATE INDEX IF NOT EXISTS audit_log_enduser_idx ON audit_log(end_user_id, timestamp DESC)",
            // TAP-mediated per-end-user OAuth: the callback stores the bundle
            // scoped to an end-user and redirects to the partner's return_url.
            "ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS end_user_id TEXT",
            "ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS return_url TEXT",
            // Agent key ids (JSON array) to grant the created credential to once
            // the OAuth callback lands — chosen on the connect page under the same
            // passkey that starts the flow. NULL/'' = none.
            "ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS assign_agents TEXT",
            // `tap cred set --require-passkey`: gate the resulting credential's
            // agent actions behind a passkey (applied as a Gated policy at activation).
            "ALTER TABLE credential_setups ADD COLUMN IF NOT EXISTS require_passkey BOOLEAN NOT NULL DEFAULT FALSE",
            // Durable approver/end-user passkey registration challenges (replaces
            // the instance-local in-memory map for headless multi-instance flows).
            "CREATE TABLE IF NOT EXISTS approver_registration_challenges (
                approver_name TEXT PRIMARY KEY,
                challenge_json TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )",
            // An approval row that may ONLY be resolved by a specific managed
            // end-user's authenticated approval (default-deny gate). NULL = an
            // ordinary team-approvable request.
            "ALTER TABLE pending_approvals ADD COLUMN IF NOT EXISTS required_end_user TEXT",
            // Staged policy changes that loosen a passkey-protected end-user
            // credential — applied ONLY after that end-user's passkey approval
            // (passkey-lock / R2). The partner cannot weaken an end-user's
            // protection on its own.
            "CREATE TABLE IF NOT EXISTS pending_policy_changes (
                txn_id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                credential_name TEXT NOT NULL,
                required_end_user TEXT NOT NULL,
                proposed_policy_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )",
            // Audit-log visibility into the original request and the policy
            // decision that governed it. `request_headers`/`request_body` are
            // the agent's request BEFORE credential substitution — placeholders
            // only, never a real secret value (see AuditEntry doc comments).
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS request_headers TEXT",
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS request_body TEXT",
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS request_body_truncated BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS policy_reason TEXT",
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS require_passkey BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS approver_identity TEXT",
            // Time-boxed approval grants (#49): human-authored auto-approve
            // rules with a TTL, an optional use cap, and a narrow scope. A
            // grant skips the human PROMPT, never proxy enforcement. Dedicated
            // table because consumption needs an atomic per-row use claim.
            "CREATE TABLE IF NOT EXISTS approval_grants (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                credential_name TEXT NOT NULL,
                methods TEXT NOT NULL DEFAULT '[]',
                route_scope TEXT NOT NULL DEFAULT '[]',
                expires_at TEXT NOT NULL,
                granted_by TEXT NOT NULL,
                max_uses BIGINT,
                uses BIGINT NOT NULL DEFAULT 0,
                revoked BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT NOT NULL,
                FOREIGN KEY (team_id, credential_name)
                    REFERENCES credentials(team_id, name) ON DELETE CASCADE
            )",
            "CREATE INDEX IF NOT EXISTS idx_grants_lookup
                ON approval_grants (team_id, credential_name, revoked, expires_at)",
            // -- Social login (Google/GitHub) ----------------------------------
            // One row per linked external identity. The stable key is the
            // provider's subject id (`sub`), NEVER the email — provider emails
            // can change while `sub` is permanent. A user may link several
            // providers; a provider identity maps to exactly one user.
            "CREATE TABLE IF NOT EXISTS user_identities (
                provider TEXT NOT NULL,
                provider_sub TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                email_at_link TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (provider, provider_sub)
            )",
            "CREATE INDEX IF NOT EXISTS user_identities_user_idx ON user_identities(user_id)",
            // Login-flow OAuth state (CSRF binding for /auth/{provider}/start →
            // callback). Deliberately a SEPARATE table from `oauth_states` (the
            // credential-consent flow): a login state has no admin/team/credential
            // and, by construction, neither callback can consume the other's rows.
            // Single-use: claimed atomically (DELETE … RETURNING) by the callback.
            "CREATE TABLE IF NOT EXISTS login_oauth_states (
                state_hash TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )",
            // Browser-binding for the login-CSRF / session-fixation defense
            // (provider-agnostic — shared by every social-login provider). At
            // `/start` the handler sets an HttpOnly cookie carrying a random
            // nonce and persists only its hash here; the callback must present a
            // cookie whose hash matches before the state is honored, so an
            // attacker-initiated flow can't be completed in a victim's browser.
            // Nullable: NULL = a row created without binding (legacy / tests);
            // the callback only enforces when a hash is present.
            "ALTER TABLE login_oauth_states ADD COLUMN IF NOT EXISTS browser_bind_hash TEXT",
            // Bridge between the provider callback (a browser redirect) and the
            // SPA's completion POST. `kind` = 'login' (user_id set) or 'signup'
            // (no account yet; provider identity fields set). Single-use.
            "CREATE TABLE IF NOT EXISTS login_continuations (
                token_hash TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                user_id TEXT,
                provider TEXT,
                provider_sub TEXT,
                email TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )",
            // An identity link waiting on proof of account ownership: persisted
            // to `user_identities` only after the matched user completes a FULL
            // login (passkey step included) — never on the email match alone.
            "CREATE TABLE IF NOT EXISTS pending_identity_links (
                user_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                provider_sub TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (user_id, provider)
            )",
        ];
        for migration in migrations {
            let _ = sqlx::raw_sql(migration).execute(&pool).await;
        }

        let store = Self {
            pool,
            encryption_key,
        };

        // Backfill the identity/membership split from any existing `admins`
        // rows. Idempotent; a no-op once users/memberships are populated.
        store.backfill_identity_from_admins().await?;

        // Drop the legacy `admins` table AFTER the backfill has migrated its
        // data into users/memberships. Ordering is critical: migrate first,
        // then drop the source. Harmless no-op on fresh installs and on every
        // subsequent boot.
        store.drop_legacy_admins_table().await?;

        // Enforce "at most one live password-reset per user" via a UNIQUE index
        // on password_resets(user_id). Runs UNCONDITIONALLY here — after the
        // backfill — so `password_resets.user_id` is guaranteed to exist in
        // every install state: fresh (from SCHEMA), legacy-with-admins (the
        // backfill's repoint ADDs the column), and already-migrated (column
        // present, but no column-level UNIQUE because CREATE TABLE IF NOT EXISTS
        // was a no-op on the pre-existing table). This index is what
        // `create_password_reset`'s ON CONFLICT (user_id) upsert depends on to
        // serialize concurrent /forgot-password requests and hold the cooldown
        // (#119). Dedupe first (keep the newest row per user_id) or the unique
        // build would fail on any pre-existing duplicates. Best-effort like the
        // migration loop; nanosecond `created_at` makes exact-tie duplicates
        // that survive the strict `<` effectively impossible.
        let _ = sqlx::raw_sql(
            "DELETE FROM password_resets a USING password_resets b
             WHERE a.user_id = b.user_id AND a.created_at < b.created_at",
        )
        .execute(&store.pool)
        .await;
        let _ = sqlx::raw_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS password_resets_user_id_unique
             ON password_resets(user_id)",
        )
        .execute(&store.pool)
        .await;

        Ok(store)
    }

    /// Backfill `users` and `memberships` from the legacy `admins` table.
    ///
    /// One `users` row per distinct email, identity taken from the OLDEST admin
    /// row (so its id becomes the canonical user id — minimizing FK repointing
    /// when the code cutover lands). One `memberships` row per admin row.
    /// Idempotent via `ON CONFLICT DO NOTHING`.
    pub async fn backfill_identity_from_admins(&self) -> Result<(), AgentSecError> {
        // No-op when the legacy `admins` table is absent (fresh installs, and
        // every boot after `drop_legacy_admins_table` has run). `to_regclass`
        // returns NULL if the table does not exist.
        // Unqualified so it resolves via search_path (production search_path
        // includes public; tests run inside an isolated schema).
        let admins_exists: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('admins')::text")
                .fetch_one(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to check for admins table: {e}"))
                })?;
        if admins_exists.is_none() {
            return Ok(());
        }

        // Identity (id/password/etc.) is taken from the OLDEST admin row per
        // email (DISTINCT ON + ORDER BY created_at ASC). But `email_verified`
        // proves ownership of the *email*, not a team membership — so it must
        // be OR'd across ALL of a person's legacy rows, not read off the oldest
        // one. Picking the oldest row's flag mis-migrated multi-team users whose
        // oldest row was unverified (they verified on a later team) to
        // email_verified=false, blocking login. See #34.
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified, display_name, matrix_user_id, telegram_user_id, created_at, updated_at)
             SELECT DISTINCT ON (email) id, email, password_hash,
                    bool_or(email_verified) OVER (PARTITION BY email) AS email_verified,
                    display_name, matrix_user_id, telegram_user_id, created_at, updated_at
             FROM admins
             ORDER BY email, created_at ASC, id ASC
             ON CONFLICT (email) DO NOTHING",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to backfill users: {e}")))?;

        sqlx::query(
            "INSERT INTO memberships (user_id, team_id, member_role, created_at)
             SELECT u.id, a.team_id, a.member_role, a.created_at
             FROM admins a JOIN users u ON u.email = a.email
             ON CONFLICT (user_id, team_id) DO NOTHING",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to backfill memberships: {e}")))?;

        // --------------------------------------------------------------------
        // Repoint FK tables from the legacy `admins.id` space to `users.id`.
        //
        // Because the canonical user id == the OLDEST admin row's id for each
        // email (see the INSERT above), any FK row that already points at the
        // canonical admin id needs no change. Only rows pointing at a
        // non-canonical (newer-team) admin id are remapped. We run this
        // unconditionally — it is idempotent:
        //   * ADD COLUMN IF NOT EXISTS adds the new user-id column on existing
        //     installs (fresh installs already have it from SCHEMA).
        //   * The UPDATE ... FROM admins JOIN users maps old admin_id -> u.id.
        //     On fresh installs there are no `admins` rows, so it's a no-op.
        //   * DROP COLUMN IF EXISTS removes the legacy admin-id column.
        // Errors from individual steps (e.g. column already dropped) are
        // tolerated, mirroring the migration loop's best-effort style.
        let repoint: &[&str] = &[
            // admin_sessions: admin_id -> (user_id, team_id)
            "ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS user_id TEXT",
            "ALTER TABLE admin_sessions ADD COLUMN IF NOT EXISTS team_id TEXT",
            "UPDATE admin_sessions s SET user_id = u.id, team_id = a.team_id
             FROM admins a JOIN users u ON u.email = a.email
             WHERE s.admin_id = a.id AND (s.user_id IS NULL OR s.team_id IS NULL)",
            "ALTER TABLE admin_sessions DROP COLUMN IF EXISTS admin_id",
            // email_verifications: admin_id -> user_id
            "ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS user_id TEXT",
            "UPDATE email_verifications v SET user_id = u.id
             FROM admins a JOIN users u ON u.email = a.email
             WHERE v.admin_id = a.id AND v.user_id IS NULL",
            "ALTER TABLE email_verifications DROP COLUMN IF EXISTS admin_id",
            // password_resets: admin_id -> user_id
            "ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS user_id TEXT",
            "UPDATE password_resets r SET user_id = u.id
             FROM admins a JOIN users u ON u.email = a.email
             WHERE r.admin_id = a.id AND r.user_id IS NULL",
            "ALTER TABLE password_resets DROP COLUMN IF EXISTS admin_id",
            // webauthn_credentials: admin_id -> user_id
            "ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS user_id TEXT",
            "UPDATE webauthn_credentials w SET user_id = u.id
             FROM admins a JOIN users u ON u.email = a.email
             WHERE w.admin_id = a.id AND w.user_id IS NULL",
            "ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS admin_id",
            // admin_invites: invited_by_admin_id -> invited_by_user_id
            "ALTER TABLE admin_invites ADD COLUMN IF NOT EXISTS invited_by_user_id TEXT",
            "UPDATE admin_invites i SET invited_by_user_id = u.id
             FROM admins a JOIN users u ON u.email = a.email
             WHERE i.invited_by_admin_id = a.id AND i.invited_by_user_id IS NULL",
            "ALTER TABLE admin_invites DROP COLUMN IF EXISTS invited_by_admin_id",
            // approver_credentials: member_id column kept, but remap any rows
            // that point at a non-canonical admin id to the canonical user id.
            "UPDATE approver_credentials c SET member_id = u.id
             FROM admins a JOIN users u ON u.email = a.email
             WHERE c.member_id = a.id AND c.member_id <> u.id",
            // member_id now holds a user id, so its FK must point at users(id),
            // not admins(id). The constraint name is inherited from the original
            // `member_credentials` table (member_credentials_member_id_fkey).
            // Drop both possible names idempotently, then add the users FK.
            "ALTER TABLE approver_credentials DROP CONSTRAINT IF EXISTS member_credentials_member_id_fkey",
            "ALTER TABLE approver_credentials DROP CONSTRAINT IF EXISTS approver_credentials_member_id_fkey",
            "ALTER TABLE approver_credentials ADD CONSTRAINT approver_credentials_member_id_fkey
             FOREIGN KEY (member_id) REFERENCES users(id) ON DELETE CASCADE",
        ];
        for stmt in repoint {
            let _ = sqlx::raw_sql(stmt).execute(&self.pool).await;
        }

        Ok(())
    }

    /// Drop the legacy `admins` table. Must be called only AFTER
    /// `backfill_identity_from_admins` has migrated its data into
    /// users/memberships and repointed all FK columns. `CASCADE` removes any
    /// leftover dependent objects (e.g. the `admins_email_team_unique` index).
    /// Idempotent: a no-op once the table is gone (fresh installs, reboots).
    pub async fn drop_legacy_admins_table(&self) -> Result<(), AgentSecError> {
        sqlx::raw_sql("DROP TABLE IF EXISTS admins CASCADE")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to drop legacy admins table: {e}"))
            })?;
        Ok(())
    }

    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }

    pub async fn ping(&self) -> Result<(), AgentSecError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("DB ping failed: {e}")))?;
        Ok(())
    }

    // -- Teams ----------------------------------------------------------------

    /// Create a team. **New teams start in `autonomous` approval mode** — the
    /// value is written EXPLICITLY here rather than by changing the column
    /// default, which is deliberate and load-bearing:
    ///
    /// * `teams.default_approval_mode` keeps its `DEFAULT 'gated'`, so the
    ///   migration that backfilled every pre-existing team to `'gated'` stays
    ///   intact and any other/legacy INSERT path still fails safe.
    /// * `ApprovalMode::default()` stays `Gated`, so a missing row or an
    ///   unrecognized value still fails safe at read time.
    ///
    /// Net effect: only teams created from here — i.e. genuinely new signups —
    /// are autonomous. Every existing team keeps the gated posture it already
    /// has stored.
    ///
    /// Note what `autonomous` actually means: `Gated` already auto-approves
    /// safe reads (GET/HEAD), so the ONLY behavioural difference is writes.
    /// An autonomous team auto-approves POST/PUT/PATCH/DELETE on any credential
    /// that has no explicit policy. Per-credential policies still override, and
    /// a team can switch back on the Team page.
    pub async fn create_team(&self, id: &str, name: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO teams (id, name, created_at, default_approval_mode) \
             VALUES ($1, $2, $3, 'autonomous')",
        )
        .bind(id)
        .bind(name)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create team: {e}")))?;
        Ok(())
    }

    /// Idempotently create a team — used by the CLI so self-hosted deployments
    /// have a working default team without going through dashboard signup.
    pub async fn ensure_team(&self, id: &str, name: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO teams (id, name, created_at) VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(name)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to ensure team: {e}")))?;
        Ok(())
    }

    pub async fn get_team(&self, id: &str) -> Result<Option<TeamRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, name, tier, stripe_customer_id, created_at FROM teams WHERE id = $1",
        )
        .persistent(false)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?;
        match row {
            Some(row) => Ok(Some(TeamRow {
                id: row
                    .try_get("id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
                name: row
                    .try_get("name")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
                tier: row
                    .try_get("tier")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
                stripe_customer_id: row
                    .try_get("stripe_customer_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
            })),
            None => Ok(None),
        }
    }

    /// Team-wide default approval posture, governing credentials with no
    /// explicit policy. A missing row or unknown value fails safe to `Gated`.
    pub async fn get_team_default_approval_mode(
        &self,
        team_id: &str,
    ) -> Result<crate::config::ApprovalMode, AgentSecError> {
        let row = sqlx::query("SELECT default_approval_mode FROM teams WHERE id = $1")
            .persistent(false)
            .bind(team_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get team approval mode: {e}")))?;
        let mode = row
            .and_then(|r| r.try_get::<String, _>("default_approval_mode").ok())
            .map(|s| crate::config::ApprovalMode::from_stored(&s))
            .unwrap_or_default();
        Ok(mode)
    }

    pub async fn set_team_default_approval_mode(
        &self,
        team_id: &str,
        mode: crate::config::ApprovalMode,
    ) -> Result<(), AgentSecError> {
        sqlx::query("UPDATE teams SET default_approval_mode = $1 WHERE id = $2")
            .bind(mode.as_str())
            .bind(team_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to set team approval mode: {e}")))?;
        Ok(())
    }

    pub async fn get_team_by_name(&self, name: &str) -> Result<Option<TeamRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, name, tier, stripe_customer_id, created_at FROM teams WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get team by name: {e}")))?;
        match row {
            Some(row) => Ok(Some(TeamRow {
                id: row.try_get("id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
                name: row.try_get("name").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
                tier: row.try_get("tier").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
                stripe_customer_id: row.try_get("stripe_customer_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
                created_at: row.try_get("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
            })),
            None => Ok(None),
        }
    }

    pub async fn update_team_tier(&self, team_id: &str, tier: &str) -> Result<(), AgentSecError> {
        sqlx::query("UPDATE teams SET tier = $1 WHERE id = $2")
            .bind(tier)
            .bind(team_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to update team tier: {e}")))?;
        Ok(())
    }

    pub async fn set_stripe_customer_id(
        &self,
        team_id: &str,
        customer_id: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query("UPDATE teams SET stripe_customer_id = $1 WHERE id = $2")
            .bind(customer_id)
            .bind(team_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to set Stripe customer ID: {e}")))?;
        Ok(())
    }

    pub async fn get_team_by_stripe_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<TeamRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, name, tier, stripe_customer_id, created_at FROM teams WHERE stripe_customer_id = $1",
        )
        .bind(customer_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}")))?;
        match row {
            Some(row) => Ok(Some(TeamRow {
                id: row.try_get("id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
                name: row.try_get("name").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
                tier: row.try_get("tier").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
                stripe_customer_id: row.try_get("stripe_customer_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
                created_at: row.try_get("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
            })),
            None => Ok(None),
        }
    }

    // -- Memberships (role changes & removal within a team) -------------------

    /// Change a user's role within a team.
    pub async fn update_member_role(
        &self,
        user_id: &str,
        team_id: &str,
        role: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query("UPDATE memberships SET member_role = $1 WHERE user_id = $2 AND team_id = $3")
            .bind(role)
            .bind(user_id)
            .bind(team_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to update member role: {e}")))?;
        Ok(())
    }

    /// Remove a user's membership in a team. The user identity itself is not
    /// deleted (they may belong to other teams).
    pub async fn delete_membership(
        &self,
        user_id: &str,
        team_id: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM memberships WHERE user_id = $1 AND team_id = $2")
            .bind(user_id)
            .bind(team_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete membership: {e}")))?;
        Ok(())
    }

    /// Mark a user's email as verified (identity-level, team-independent).
    pub async fn set_user_email_verified(&self, user_id: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE users SET email_verified = TRUE, updated_at = $1 WHERE id = $2")
            .bind(now)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to verify user email: {e}")))?;
        Ok(())
    }

    /// Update a user's personal identity fields (team-independent).
    pub async fn update_user_identity(
        &self,
        user_id: &str,
        display_name: Option<&str>,
        matrix_user_id: Option<&str>,
        telegram_user_id: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE users SET display_name = $1, matrix_user_id = $2, telegram_user_id = $3,
             updated_at = $4 WHERE id = $5",
        )
        .bind(display_name)
        .bind(matrix_user_id)
        .bind(telegram_user_id)
        .bind(now)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to update user identity: {e}")))?;
        Ok(())
    }

    // -- Approver credential access (for approver-tier scoping) -------------------

    pub async fn assign_credential_to_approver(
        &self,
        team_id: &str,
        member_id: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "INSERT INTO approver_credentials (team_id, member_id, credential_name)
             VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(team_id)
        .bind(member_id)
        .bind(credential_name)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to assign credential to approver: {e}"))
        })?;
        Ok(())
    }

    pub async fn remove_credential_from_approver(
        &self,
        team_id: &str,
        member_id: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "DELETE FROM approver_credentials WHERE team_id = $1 AND member_id = $2 AND credential_name = $3",
        )
        .bind(team_id)
        .bind(member_id)
        .bind(credential_name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to remove credential from approver: {e}")))?;
        Ok(())
    }

    pub async fn list_approver_credentials(
        &self,
        team_id: &str,
        member_id: &str,
    ) -> Result<Vec<String>, AgentSecError> {
        use sqlx::Row as _;
        let rows = sqlx::query(
            "SELECT credential_name FROM approver_credentials WHERE team_id = $1 AND member_id = $2 ORDER BY credential_name ASC",
        )
        .bind(team_id)
        .bind(member_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list approver credentials: {e}")))?;
        rows.iter()
            .map(|r| {
                r.try_get::<String, _>("credential_name")
                    .map_err(|e| AgentSecError::Config(format!("list_approver_credentials: {e}")))
            })
            .collect()
    }

    // -- Users & memberships (identity/membership split) ----------------------
    // These coexist with the legacy `admins` methods above; the handler cutover
    // switches callers over to them. `MEMBER_SELECT` joins a user with one
    // membership into `Member` shape.

    const MEMBER_SELECT: &'static str = "SELECT u.id AS id, m.team_id AS team_id, u.email AS email,
                u.password_hash AS password_hash, u.email_verified AS email_verified,
                m.member_role AS member_role, m.created_at AS created_at, u.updated_at AS updated_at,
                u.display_name AS display_name, u.matrix_user_id AS matrix_user_id,
                u.telegram_user_id AS telegram_user_id
         FROM users u JOIN memberships m ON m.user_id = u.id";

    /// Create a user identity (no team). If a user with this email already
    /// exists, the existing identity is reused. Returns the effective user id
    /// (the existing one when the email was already present).
    pub async fn create_user(
        &self,
        user_id: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<String, AgentSecError> {
        use sqlx::Row as _;
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, FALSE, $4, $4) ON CONFLICT (email) DO NOTHING",
        )
        .bind(user_id)
        .bind(email)
        .bind(password_hash)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create user: {e}")))?;

        let effective_id: String = sqlx::query("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to load user after create: {e}")))?
            .try_get("id")
            .map_err(|e| AgentSecError::Config(format!("create user id: {e}")))?;

        Ok(effective_id)
    }

    /// Strict variant of [`Self::create_user`] for flows where adopting an
    /// existing row would be an account takeover — social signup verifies the
    /// email and links a provider identity to whatever id it gets back, so it
    /// must never be handed someone else's row. Inserts only; returns `false`
    /// (touching nothing) when the email is already taken.
    pub async fn create_user_strict(
        &self,
        user_id: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at)
             VALUES ($1, $2, $3, FALSE, $4, $4) ON CONFLICT (email) DO NOTHING",
        )
        .bind(user_id)
        .bind(email)
        .bind(password_hash)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create user: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    /// Add a user to a team with a role. Idempotent — a no-op if the membership
    /// already exists, so it is safe to call when auto-joining invited teams.
    pub async fn add_membership(
        &self,
        user_id: &str,
        team_id: &str,
        member_role: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO memberships (user_id, team_id, member_role, created_at)
             VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, team_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(team_id)
        .bind(member_role)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create membership: {e}")))?;
        Ok(())
    }

    /// Create a user identity and a membership in one team. If a user with this
    /// email already exists (e.g. accepting an invite to a second team), the
    /// existing identity is reused and only the membership is added. Returns the
    /// effective user id (the existing one when the email was already present).
    pub async fn create_user_with_membership(
        &self,
        user_id: &str,
        team_id: &str,
        email: &str,
        password_hash: &str,
        member_role: &str,
    ) -> Result<String, AgentSecError> {
        let effective_id = self.create_user(user_id, email, password_hash).await?;
        self.add_membership(&effective_id, team_id, member_role)
            .await?;
        Ok(effective_id)
    }

    /// Look up a user's identity by email (globally unique — unambiguous).
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, email_verified, display_name, matrix_user_id,
                    telegram_user_id, created_at, updated_at
             FROM users WHERE email = $1",
        )
        .persistent(false)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get user by email: {e}")))?;
        match row {
            Some(row) => Ok(Some(user_from_query(&row, "get user by email")?)),
            None => Ok(None),
        }
    }

    /// Look up a user's identity by id.
    pub async fn get_user(&self, id: &str) -> Result<Option<User>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, email_verified, display_name, matrix_user_id,
                    telegram_user_id, created_at, updated_at
             FROM users WHERE id = $1",
        )
        .persistent(false)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get user: {e}")))?;
        match row {
            Some(row) => Ok(Some(user_from_query(&row, "get user")?)),
            None => Ok(None),
        }
    }

    /// Resolve a user in the context of one team (identity + membership).
    /// Returns None if the user has no membership in that team.
    pub async fn get_member(
        &self,
        user_id: &str,
        team_id: &str,
    ) -> Result<Option<Member>, AgentSecError> {
        let sql = format!("{} WHERE u.id = $1 AND m.team_id = $2", Self::MEMBER_SELECT);
        let row = sqlx::query(&sql)
            .persistent(false)
            .bind(user_id)
            .bind(team_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get member: {e}")))?;
        match row {
            Some(row) => Ok(Some(member_from_query(&row, "get member")?)),
            None => Ok(None),
        }
    }

    /// Resolve a member by email within a team (identity + membership).
    pub async fn get_member_by_email_and_team(
        &self,
        email: &str,
        team_id: &str,
    ) -> Result<Option<Member>, AgentSecError> {
        let sql = format!(
            "{} WHERE u.email = $1 AND m.team_id = $2",
            Self::MEMBER_SELECT
        );
        let row = sqlx::query(&sql)
            .bind(email)
            .bind(team_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to get member by email+team: {e}"))
            })?;
        match row {
            Some(row) => Ok(Some(member_from_query(&row, "get member by email+team")?)),
            None => Ok(None),
        }
    }

    /// Resolve a member by their linked Telegram user id within a team. Used
    /// by the Telegram grant button to check the clicker's workspace role.
    pub async fn get_member_by_telegram_id(
        &self,
        team_id: &str,
        telegram_user_id: &str,
    ) -> Result<Option<Member>, AgentSecError> {
        let sql = format!(
            "{} WHERE m.team_id = $1 AND u.telegram_user_id = $2",
            Self::MEMBER_SELECT
        );
        let row = sqlx::query(&sql)
            .bind(team_id)
            .bind(telegram_user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get member by telegram id: {e}")))?;
        match row {
            Some(row) => Ok(Some(member_from_query(&row, "get member by telegram id")?)),
            None => Ok(None),
        }
    }

    /// Resolve a member by their linked Matrix user id within a team. Used by
    /// the Matrix grant reaction to check the reactor's workspace role.
    pub async fn get_member_by_matrix_id(
        &self,
        team_id: &str,
        matrix_user_id: &str,
    ) -> Result<Option<Member>, AgentSecError> {
        let sql = format!(
            "{} WHERE m.team_id = $1 AND u.matrix_user_id = $2",
            Self::MEMBER_SELECT
        );
        let row = sqlx::query(&sql)
            .bind(team_id)
            .bind(matrix_user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get member by matrix id: {e}")))?;
        match row {
            Some(row) => Ok(Some(member_from_query(&row, "get member by matrix id")?)),
            None => Ok(None),
        }
    }

    /// List all members of a team (identity joined with membership).
    pub async fn list_team_members(&self, team_id: &str) -> Result<Vec<Member>, AgentSecError> {
        let sql = format!(
            "{} WHERE m.team_id = $1 ORDER BY m.created_at ASC",
            Self::MEMBER_SELECT
        );
        let rows = sqlx::query(&sql)
            .bind(team_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list team members: {e}")))?;
        rows.iter()
            .map(|r| member_from_query(r, "list team members"))
            .collect()
    }

    /// All teams a user belongs to, with their role in each. Returns tuples of
    /// (team_id, team_name, member_role). Drives the multi-team team switcher.
    pub async fn list_user_teams(
        &self,
        user_id: &str,
    ) -> Result<Vec<(String, String, String)>, AgentSecError> {
        use sqlx::Row as _;
        let rows = sqlx::query(
            "SELECT t.id AS team_id, t.name AS team_name, m.member_role AS member_role
             FROM memberships m JOIN teams t ON t.id = m.team_id
             WHERE m.user_id = $1
             ORDER BY m.created_at ASC, t.name ASC",
        )
        .persistent(false)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list user teams: {e}")))?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get::<String, _>("team_id")
                        .map_err(|e| AgentSecError::Config(format!("list_user_teams: {e}")))?,
                    r.try_get::<String, _>("team_name")
                        .map_err(|e| AgentSecError::Config(format!("list_user_teams: {e}")))?,
                    r.try_get::<String, _>("member_role")
                        .map_err(|e| AgentSecError::Config(format!("list_user_teams: {e}")))?,
                ))
            })
            .collect()
    }

    /// Return any owner member (user + membership) — used only by the dev
    /// auto-login endpoint.
    pub async fn first_owner_member(&self) -> Result<Option<Member>, AgentSecError> {
        let sql = format!(
            "{} WHERE m.member_role = 'owner' ORDER BY m.created_at ASC LIMIT 1",
            Self::MEMBER_SELECT
        );
        let row = sqlx::query(&sql)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("first_owner_member: {e}")))?;
        match row {
            Some(r) => Ok(Some(member_from_query(&r, "first_owner_member")?)),
            None => Ok(None),
        }
    }

    // -- Admin invites ---------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn create_invite(
        &self,
        id: &str,
        team_id: &str,
        email: &str,
        role: &str,
        token_hash: &str,
        invited_by_user_id: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO admin_invites (id, team_id, email, role, token_hash, invited_by_user_id, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(id)
        .bind(team_id)
        .bind(email)
        .bind(role)
        .bind(token_hash)
        .bind(invited_by_user_id)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create invite: {e}")))?;
        Ok(())
    }

    pub async fn get_invite_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<AdminInviteRow>, AgentSecError> {
        use sqlx::Row as _;
        let row = sqlx::query(
            "SELECT id, team_id, email, role, invited_by_user_id, expires_at, created_at
             FROM admin_invites WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get invite: {e}")))?;
        match row {
            Some(row) => Ok(Some(AdminInviteRow {
                id: row
                    .try_get("id")
                    .map_err(|e| AgentSecError::Config(format!("get_invite: {e}")))?,
                team_id: row
                    .try_get("team_id")
                    .map_err(|e| AgentSecError::Config(format!("get_invite: {e}")))?,
                email: row
                    .try_get("email")
                    .map_err(|e| AgentSecError::Config(format!("get_invite: {e}")))?,
                role: row.try_get("role").unwrap_or_else(|_| "admin".to_string()),
                invited_by_user_id: row
                    .try_get("invited_by_user_id")
                    .map_err(|e| AgentSecError::Config(format!("get_invite: {e}")))?,
                expires_at: row
                    .try_get("expires_at")
                    .map_err(|e| AgentSecError::Config(format!("get_invite: {e}")))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| AgentSecError::Config(format!("get_invite: {e}")))?,
            })),
            None => Ok(None),
        }
    }

    pub async fn delete_invite(&self, id: &str) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM admin_invites WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete invite: {e}")))?;
        Ok(())
    }

    pub async fn list_pending_invites(
        &self,
        team_id: &str,
    ) -> Result<Vec<AdminInviteRow>, AgentSecError> {
        use sqlx::Row as _;
        let now = chrono::Utc::now().to_rfc3339();
        let rows = sqlx::query(
            "SELECT id, team_id, email, role, invited_by_user_id, expires_at, created_at
             FROM admin_invites WHERE team_id = $1 AND expires_at > $2
             ORDER BY created_at DESC",
        )
        .bind(team_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list invites: {e}")))?;
        rows.iter()
            .map(|row| {
                Ok(AdminInviteRow {
                    id: row
                        .try_get("id")
                        .map_err(|e| AgentSecError::Config(format!("list_invites: {e}")))?,
                    team_id: row
                        .try_get("team_id")
                        .map_err(|e| AgentSecError::Config(format!("list_invites: {e}")))?,
                    email: row
                        .try_get("email")
                        .map_err(|e| AgentSecError::Config(format!("list_invites: {e}")))?,
                    role: row.try_get("role").unwrap_or_else(|_| "admin".to_string()),
                    invited_by_user_id: row
                        .try_get("invited_by_user_id")
                        .map_err(|e| AgentSecError::Config(format!("list_invites: {e}")))?,
                    expires_at: row
                        .try_get("expires_at")
                        .map_err(|e| AgentSecError::Config(format!("list_invites: {e}")))?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|e| AgentSecError::Config(format!("list_invites: {e}")))?,
                })
            })
            .collect()
    }

    /// All unexpired invites addressed to an email, across every team, oldest
    /// first. Drives auto-join on signup/login so an invited person is never
    /// stranded outside the team they were invited to.
    pub async fn list_invites_by_email(
        &self,
        email: &str,
    ) -> Result<Vec<AdminInviteRow>, AgentSecError> {
        use sqlx::Row as _;
        let now = chrono::Utc::now().to_rfc3339();
        let rows = sqlx::query(
            "SELECT id, team_id, email, role, invited_by_user_id, expires_at, created_at
             FROM admin_invites WHERE email = $1 AND expires_at > $2
             ORDER BY created_at ASC",
        )
        .persistent(false)
        .bind(email)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list invites by email: {e}")))?;
        rows.iter()
            .map(|row| {
                Ok(AdminInviteRow {
                    id: row.try_get("id").map_err(|e| {
                        AgentSecError::Config(format!("list_invites_by_email: {e}"))
                    })?,
                    team_id: row.try_get("team_id").map_err(|e| {
                        AgentSecError::Config(format!("list_invites_by_email: {e}"))
                    })?,
                    email: row.try_get("email").map_err(|e| {
                        AgentSecError::Config(format!("list_invites_by_email: {e}"))
                    })?,
                    role: row.try_get("role").unwrap_or_else(|_| "admin".to_string()),
                    invited_by_user_id: row.try_get("invited_by_user_id").map_err(|e| {
                        AgentSecError::Config(format!("list_invites_by_email: {e}"))
                    })?,
                    expires_at: row.try_get("expires_at").map_err(|e| {
                        AgentSecError::Config(format!("list_invites_by_email: {e}"))
                    })?,
                    created_at: row.try_get("created_at").map_err(|e| {
                        AgentSecError::Config(format!("list_invites_by_email: {e}"))
                    })?,
                })
            })
            .collect()
    }

    // -- Credentials ----------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn create_credential(
        &self,
        team_id: &str,
        name: &str,
        description: &str,
        connector: &str,
        api_base: Option<&str>,
        relative_target: bool,
        auth_header_format: Option<&str>,
        auth_bindings_json: Option<&str>,
        plaintext_value: Option<&[u8]>,
    ) -> Result<(), AgentSecError> {
        self.create_credential_scoped(
            team_id,
            name,
            description,
            connector,
            api_base,
            relative_target,
            auth_header_format,
            auth_bindings_json,
            plaintext_value,
            None,
        )
        .await
    }

    /// Like `create_credential`, but optionally scoped to a managed end-user
    /// (`end_user_id`). For end-user credentials the caller passes a namespaced
    /// `name` (`eu:{ext_id}/{logical}`) so it stays unique under the existing
    /// (team_id, name) PK; `end_user_id` is the authoritative isolation column.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_credential_scoped(
        &self,
        team_id: &str,
        name: &str,
        description: &str,
        connector: &str,
        api_base: Option<&str>,
        relative_target: bool,
        auth_header_format: Option<&str>,
        auth_bindings_json: Option<&str>,
        plaintext_value: Option<&[u8]>,
        end_user_id: Option<&str>,
    ) -> Result<(), AgentSecError> {
        self.create_credential_scoped_for_app(
            team_id,
            name,
            description,
            connector,
            api_base,
            relative_target,
            auth_header_format,
            auth_bindings_json,
            plaintext_value,
            end_user_id,
            None,
        )
        .await
    }

    /// Like `create_credential_scoped`, but records the app key that provisioned
    /// the managed credential. This is intentionally separate from ordinary
    /// agent credential assignment: it is an ownership boundary for TAP for Apps.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_credential_scoped_for_app(
        &self,
        team_id: &str,
        name: &str,
        description: &str,
        connector: &str,
        api_base: Option<&str>,
        relative_target: bool,
        auth_header_format: Option<&str>,
        auth_bindings_json: Option<&str>,
        plaintext_value: Option<&[u8]>,
        end_user_id: Option<&str>,
        app_id: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let api_base_owned = api_base.map(|s| s.to_string());
        let auth_header_format_owned = auth_header_format.map(|s| s.to_string());
        let auth_bindings_owned = auth_bindings_json.map(|s| s.to_string());
        let end_user_owned = end_user_id.map(|s| s.to_string());
        let app_owned = app_id.map(|s| s.to_string());
        let encrypted: Option<Vec<u8>> = plaintext_value
            .map(|p| crypto::encrypt(&self.encryption_key, p))
            .transpose()
            .map_err(AgentSecError::Encryption)?;

        sqlx::query(
            "INSERT INTO credentials (team_id, name, description, connector, api_base, relative_target, auth_header_format, auth_bindings_json, encrypted_value, end_user_id, app_id, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(team_id)
        .bind(name)
        .bind(description)
        .bind(connector)
        .bind(api_base_owned)
        .bind(relative_target)
        .bind(auth_header_format_owned)
        .bind(auth_bindings_owned)
        .bind(encrypted)
        .bind(end_user_owned)
        .bind(app_owned)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("duplicate key") || msg.contains("unique constraint") {
                AgentSecError::AlreadyExists(format!("credential '{name}' already exists"))
            } else {
                AgentSecError::Config(format!("Failed to create credential: {e}"))
            }
        })?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_credential_config(
        &self,
        team_id: &str,
        name: &str,
        description: Option<&str>,
        connector: Option<&str>,
        api_base: Option<&str>,
        clear_api_base: bool,
        relative_target: Option<bool>,
        auth_header_format: Option<&str>,
        clear_auth_header_format: bool,
        // Same clear/set/leave semantics as auth_header_format: `clear` wins and
        // NULLs the column (back to default Bearer / unbound); otherwise a
        // non-null JSON string replaces the field→header bindings; None leaves
        // it untouched. This is what lets an imported header-scheme credential
        // (Anthropic x-api-key, Datadog) have a wrong binding corrected without
        // a delete-and-recreate.
        auth_bindings_json: Option<&str>,
        clear_auth_bindings: bool,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE credentials SET
                description = COALESCE($3, description),
                connector = COALESCE($4, connector),
                api_base = CASE WHEN $5 THEN NULL WHEN $6 IS NOT NULL THEN $6 ELSE api_base END,
                relative_target = COALESCE($7, relative_target),
                auth_header_format = CASE WHEN $8 THEN NULL WHEN $9 IS NOT NULL THEN $9 ELSE auth_header_format END,
                auth_bindings_json = CASE WHEN $11 THEN NULL WHEN $12 IS NOT NULL THEN $12 ELSE auth_bindings_json END,
                updated_at = $10
             WHERE team_id = $1 AND name = $2",
        )
        .bind(team_id)
        .bind(name)
        .bind(description)
        .bind(connector)
        .bind(clear_api_base)
        .bind(api_base)
        .bind(relative_target)
        .bind(clear_auth_header_format)
        .bind(auth_header_format)
        .bind(&now)
        .bind(clear_auth_bindings)
        .bind(auth_bindings_json)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to update credential: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    /// Atomically increment an agent's request counter for the given fixed
    /// hourly window and return the new count. DB-backed so the limit holds
    /// across stateless proxy instances (a process-local counter would let an
    /// agent do `N × limit` across N instances and reset on every deploy). The
    /// `INSERT … ON CONFLICT DO UPDATE … RETURNING` is a single atomic claim, so
    /// concurrent requests on different instances can't lose increments.
    /// Best-effort prunes the agent's older windows in the same call.
    pub async fn increment_rate_counter(
        &self,
        agent_id: &str,
        window_start: i64,
    ) -> Result<i64, AgentSecError> {
        let row = sqlx::query(
            "INSERT INTO rate_limit_counters (agent_id, window_start, count)
             VALUES ($1, $2, 1)
             ON CONFLICT (agent_id, window_start)
             DO UPDATE SET count = rate_limit_counters.count + 1
             RETURNING count",
        )
        .bind(agent_id)
        .bind(window_start)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to increment rate counter: {e}")))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|e| AgentSecError::Config(format!("Failed to read rate counter: {e}")))?;

        // Best-effort cleanup of this agent's stale windows (bounded: one row per
        // past active hour). Failure here must not block the request.
        let _ = sqlx::query(
            "DELETE FROM rate_limit_counters WHERE agent_id = $1 AND window_start < $2",
        )
        .bind(agent_id)
        .bind(window_start)
        .execute(&self.pool)
        .await;

        Ok(count)
    }

    /// Claim (or renew) the single-holder lease for a relay session.
    ///
    /// Distributed State Rule: the enclave is multi-process, so "exactly one live
    /// Telethon connection + relay per session" must be a durable, atomically
    /// transitioned claim — a process-local flag let two processes connect the
    /// same MTProto auth key and trip Telegram's two-IP invalidation. A single
    /// atomic `INSERT … ON CONFLICT DO UPDATE … WHERE` grants the lease iff there
    /// is no current holder, the existing holder is stale (no heartbeat within
    /// `ttl_secs`), or the caller already holds it (idempotent renew /
    /// reclaim-on-reconnect). Returns `true` when this caller holds the lease.
    pub async fn claim_relay_session(
        &self,
        session_key: &str,
        holder: &str,
        ttl_secs: i64,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now().timestamp_millis();
        let stale_before = now - ttl_secs * 1000;
        let result = sqlx::query(
            "INSERT INTO relay_sessions (session_key, holder, connected_at, last_heartbeat)
             VALUES ($1, $2, $3, $3)
             ON CONFLICT (session_key) DO UPDATE SET
                 holder = excluded.holder,
                 connected_at = excluded.connected_at,
                 last_heartbeat = excluded.last_heartbeat
             WHERE relay_sessions.holder = excluded.holder
                OR relay_sessions.last_heartbeat < $4",
        )
        .bind(session_key)
        .bind(holder)
        .bind(now)
        .bind(stale_before)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to claim relay session: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    /// Refresh the heartbeat for a lease this caller holds. Returns `false` if the
    /// lease was lost (taken over after a stale window) — the caller must then tear
    /// down its Telethon connection to preserve the single-holder invariant.
    pub async fn heartbeat_relay_session(
        &self,
        session_key: &str,
        holder: &str,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now().timestamp_millis();
        let result = sqlx::query(
            "UPDATE relay_sessions SET last_heartbeat = $3 WHERE session_key = $1 AND holder = $2",
        )
        .bind(session_key)
        .bind(holder)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to heartbeat relay session: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    /// Release a lease on clean disconnect. Only deletes the row if the caller
    /// still owns it, so it can never steal another holder's lease. Idempotent.
    pub async fn release_relay_session(
        &self,
        session_key: &str,
        holder: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM relay_sessions WHERE session_key = $1 AND holder = $2")
            .bind(session_key)
            .bind(holder)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to release relay session: {e}")))?;
        Ok(())
    }

    /// Read the current live holder of a relay session (heartbeat within
    /// `ttl_secs`), if any. The forward path uses this to decide whether a user's
    /// relay is up, failing closed when `None`.
    pub async fn live_relay_holder(
        &self,
        session_key: &str,
        ttl_secs: i64,
    ) -> Result<Option<String>, AgentSecError> {
        let stale_before = chrono::Utc::now().timestamp_millis() - ttl_secs * 1000;
        let row = sqlx::query(
            "SELECT holder FROM relay_sessions WHERE session_key = $1 AND last_heartbeat >= $2",
        )
        .bind(session_key)
        .bind(stale_before)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to read relay session: {e}")))?;
        match row {
            Some(r) => {
                let holder: String = r
                    .try_get("holder")
                    .map_err(|e| AgentSecError::Config(format!("Failed to read holder: {e}")))?;
                Ok(Some(holder))
            }
            None => Ok(None),
        }
    }

    /// List the session keys of all currently-live relays (heartbeat within
    /// `ttl_secs`). The proxy projects the chisel authfile from this set, so a
    /// session that stops heartbeating drops out of the authfile and its port is
    /// freed. Ordered for deterministic authfile output.
    pub async fn list_live_relay_sessions(
        &self,
        ttl_secs: i64,
    ) -> Result<Vec<String>, AgentSecError> {
        let stale_before = chrono::Utc::now().timestamp_millis() - ttl_secs * 1000;
        let rows = sqlx::query(
            "SELECT session_key FROM relay_sessions WHERE last_heartbeat >= $1 ORDER BY session_key",
        )
        .bind(stale_before)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list relay sessions: {e}")))?;
        rows.into_iter()
            .map(|r| {
                r.try_get::<String, _>("session_key")
                    .map_err(|e| AgentSecError::Config(format!("Failed to read session_key: {e}")))
            })
            .collect()
    }

    /// Set (or clear) a credential's destination host allowlist. Stored as a JSON
    /// array string; an empty slice clears the binding (NULL = unrestricted).
    /// Kept separate from `create_credential*`/`update_credential_config` so the
    /// many existing call sites stay untouched — the admin create/update handlers
    /// call this as a focused follow-up write.
    pub async fn set_credential_allowed_hosts(
        &self,
        team_id: &str,
        name: &str,
        allowed_hosts: &[String],
    ) -> Result<bool, AgentSecError> {
        let json: Option<String> = if allowed_hosts.is_empty() {
            None
        } else {
            Some(serde_json::to_string(allowed_hosts).map_err(|e| {
                AgentSecError::Config(format!("Failed to serialize allowed_hosts: {e}"))
            })?)
        };
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE credentials SET allowed_hosts_json = $3, updated_at = $4
             WHERE team_id = $1 AND name = $2",
        )
        .bind(team_id)
        .bind(name)
        .bind(json)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to set credential allowed_hosts: {e}"))
        })?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_credential(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<Option<CredentialRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT name, team_id, description, connector, api_base, relative_target, auth_header_format, auth_bindings_json, allowed_hosts_json, end_user_id, app_id, created_at, updated_at
             FROM credentials WHERE team_id = $1 AND name = $2",
        )
        .bind(team_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?;
        match row {
            Some(row) => Ok(Some(CredentialRow {
                name: row
                    .try_get("name")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                team_id: row
                    .try_get("team_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                description: row
                    .try_get("description")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                connector: row
                    .try_get("connector")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                api_base: row
                    .try_get("api_base")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                relative_target: row
                    .try_get("relative_target")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                auth_header_format: row
                    .try_get("auth_header_format")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                auth_bindings_json: row
                    .try_get("auth_bindings_json")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                allowed_hosts_json: row
                    .try_get("allowed_hosts_json")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                end_user_id: row
                    .try_get("end_user_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                app_id: row
                    .try_get("app_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                updated_at: row
                    .try_get("updated_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
            })),
            None => Ok(None),
        }
    }

    pub async fn list_credentials(
        &self,
        team_id: &str,
    ) -> Result<Vec<CredentialRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT name, team_id, description, connector, api_base, relative_target, auth_header_format, auth_bindings_json, allowed_hosts_json, end_user_id, app_id, created_at, updated_at
             FROM credentials WHERE team_id = $1 ORDER BY name",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list credentials: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(CredentialRow {
                name: row.try_get("name").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                team_id: row.try_get("team_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                description: row.try_get("description").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                connector: row.try_get("connector").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                api_base: row.try_get("api_base").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                relative_target: row.try_get("relative_target").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                auth_header_format: row.try_get("auth_header_format").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                auth_bindings_json: row.try_get("auth_bindings_json").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                allowed_hosts_json: row.try_get("allowed_hosts_json").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                end_user_id: row.try_get("end_user_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                app_id: row.try_get("app_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                created_at: row.try_get("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                updated_at: row.try_get("updated_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    // -- Managed end-users (TAP for Platforms) --------------------------------

    /// Create or refresh a managed end-user. Idempotent: on conflict it bumps
    /// `last_seen_at` and updates `display_name` if a new one is supplied. Used
    /// both by the explicit provisioning endpoint and lazily on first reference.
    pub async fn upsert_end_user(
        &self,
        team_id: &str,
        ext_id: &str,
        display_name: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO end_users (team_id, ext_id, display_name, status, created_at, last_seen_at)
             VALUES ($1, $2, $3, 'active', $4, $4)
             ON CONFLICT (team_id, ext_id) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                display_name = COALESCE(excluded.display_name, end_users.display_name)",
        )
        .bind(team_id)
        .bind(ext_id)
        .bind(display_name)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to upsert end-user: {e}")))?;
        Ok(())
    }

    /// Update only `last_seen_at` for an existing end-user (cheap per-request
    /// touch). No-op if the end-user does not exist.
    pub async fn touch_end_user(&self, team_id: &str, ext_id: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE end_users SET last_seen_at = $3 WHERE team_id = $1 AND ext_id = $2")
            .bind(team_id)
            .bind(ext_id)
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to touch end-user: {e}")))?;
        Ok(())
    }

    pub async fn get_end_user(
        &self,
        team_id: &str,
        ext_id: &str,
    ) -> Result<Option<EndUserRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT team_id, ext_id, display_name, status, created_at, last_seen_at
             FROM end_users WHERE team_id = $1 AND ext_id = $2",
        )
        .bind(team_id)
        .bind(ext_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get end-user: {e}")))?;
        row.map(|r| Self::end_user_from_row(&r)).transpose()
    }

    pub async fn list_end_users(&self, team_id: &str) -> Result<Vec<EndUserRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT team_id, ext_id, display_name, status, created_at, last_seen_at
             FROM end_users WHERE team_id = $1 ORDER BY ext_id",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list end-users: {e}")))?;
        rows.iter().map(Self::end_user_from_row).collect()
    }

    /// Credentials owned by one end-user (the authoritative `end_user_id` column,
    /// not the namespaced name). Strictly team-scoped.
    pub async fn list_end_user_credentials(
        &self,
        team_id: &str,
        ext_id: &str,
    ) -> Result<Vec<CredentialRow>, AgentSecError> {
        let all = self.list_credentials(team_id).await?;
        Ok(all
            .into_iter()
            .filter(|c| c.end_user_id.as_deref() == Some(ext_id))
            .collect())
    }

    /// Per-end-user request counts for a team over `[from, to]` (RFC3339),
    /// derived from the audit log. Scoped to the team's agents (audit_log has no
    /// team column, so we join on the agent). Powers `/app/usage` and the
    /// dashboard "End Users" tab. Ordered busiest-first.
    pub async fn end_user_usage(
        &self,
        team_id: &str,
        from: &str,
        to: &str,
    ) -> Result<Vec<(String, i64)>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT al.end_user_id AS ext_id, COUNT(*) AS n
             FROM audit_log al
             JOIN agents ag ON ag.id = al.agent_id AND ag.team_id = $1
             WHERE al.end_user_id IS NOT NULL
               AND al.timestamp >= $2 AND al.timestamp <= $3
             GROUP BY al.end_user_id
             ORDER BY n DESC",
        )
        .bind(team_id)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to read end-user usage: {e}")))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let ext: String = r
                .try_get("ext_id")
                .map_err(|e| AgentSecError::Config(format!("usage row: {e}")))?;
            let n: i64 = r
                .try_get("n")
                .map_err(|e| AgentSecError::Config(format!("usage row: {e}")))?;
            out.push((ext, n));
        }
        Ok(out)
    }

    fn end_user_from_row(row: &sqlx::postgres::PgRow) -> Result<EndUserRow, AgentSecError> {
        Ok(EndUserRow {
            team_id: row
                .try_get("team_id")
                .map_err(|e| AgentSecError::Config(format!("Failed to read end-user: {e}")))?,
            ext_id: row
                .try_get("ext_id")
                .map_err(|e| AgentSecError::Config(format!("Failed to read end-user: {e}")))?,
            display_name: row
                .try_get("display_name")
                .map_err(|e| AgentSecError::Config(format!("Failed to read end-user: {e}")))?,
            status: row
                .try_get("status")
                .map_err(|e| AgentSecError::Config(format!("Failed to read end-user: {e}")))?,
            created_at: row
                .try_get("created_at")
                .map_err(|e| AgentSecError::Config(format!("Failed to read end-user: {e}")))?,
            last_seen_at: row
                .try_get("last_seen_at")
                .map_err(|e| AgentSecError::Config(format!("Failed to read end-user: {e}")))?,
        })
    }

    pub async fn delete_credential(&self, team_id: &str, name: &str) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM credentials WHERE team_id = $1 AND name = $2")
            .bind(team_id)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete credential: {e}")))?;
        Ok(())
    }

    pub async fn set_credential_value(
        &self,
        team_id: &str,
        name: &str,
        plaintext: &[u8],
    ) -> Result<(), AgentSecError> {
        let encrypted =
            crypto::encrypt(&self.encryption_key, plaintext).map_err(AgentSecError::Encryption)?;
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE credentials SET encrypted_value = $1, updated_at = $2 WHERE team_id = $3 AND name = $4",
        )
        .bind(encrypted)
        .bind(now)
        .bind(team_id)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to set credential value: {e}")))?;
        Ok(())
    }

    pub async fn get_credential_value(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>, AgentSecError> {
        let row =
            sqlx::query("SELECT encrypted_value FROM credentials WHERE team_id = $1 AND name = $2")
                .bind(team_id)
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to get credential value: {e}"))
                })?;
        match row {
            Some(row) => {
                let blob: Option<Vec<u8>> = row.try_get("encrypted_value").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get credential value: {e}"))
                })?;
                match blob {
                    Some(data) => {
                        let plaintext = crypto::decrypt(&self.encryption_key, &data)
                            .map_err(AgentSecError::Encryption)?;
                        Ok(Some(plaintext))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// For each credential in the team that has a stored value, decrypt it and
    /// return a short display hint (never the full value). The hint is:
    /// - `{field1, field2}` for JSON-object (multi-secret) credentials
    /// - `abc***xyz` showing the first 3 and last 3 UTF-8 characters
    /// - `***` when the value is too short (≤6 chars) to hint safely
    /// - `[binary]` when the value is not valid UTF-8
    pub async fn list_credential_value_hints(
        &self,
        team_id: &str,
    ) -> Result<std::collections::HashMap<String, String>, AgentSecError> {
        let rows = sqlx::query("SELECT name, encrypted_value FROM credentials WHERE team_id = $1")
            .bind(team_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list credential hints: {e}")))?;

        let mut hints = std::collections::HashMap::new();
        for row in rows {
            let name: String = row.try_get("name").map_err(|e| {
                AgentSecError::Config(format!("Failed to list credential hints: {e}"))
            })?;
            let blob: Option<Vec<u8>> = row.try_get("encrypted_value").map_err(|e| {
                AgentSecError::Config(format!("Failed to list credential hints: {e}"))
            })?;
            if let Some(data) = blob {
                if let Ok(plaintext) = crypto::decrypt(&self.encryption_key, &data) {
                    hints.insert(name, credential_value_hint(&plaintext));
                }
            }
        }
        Ok(hints)
    }

    // -- Agents ---------------------------------------------------------------

    pub async fn create_agent(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
        rate_limit_per_hour: Option<i64>,
    ) -> Result<(), AgentSecError> {
        self.create_agent_with_admin(
            team_id,
            id,
            description,
            api_key_hash,
            rate_limit_per_hour,
            false,
            None,
            "agent",
            false,
        )
        .await
    }

    /// Create an **Account key** (all team credentials, present and future)
    /// atomically: the `all_credentials` flag rides in the INSERT itself, so
    /// there is no window — and no separately-failable follow-up UPDATE —
    /// where the key exists as a Scoped key with an empty whitelist.
    pub async fn create_agent_all_credentials(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
        rate_limit_per_hour: Option<i64>,
    ) -> Result<(), AgentSecError> {
        self.create_agent_with_admin(
            team_id,
            id,
            description,
            api_key_hash,
            rate_limit_per_hour,
            false,
            None,
            "agent",
            true,
        )
        .await
    }

    /// Create an **app key** (TAP for Platforms): an `agents` row with
    /// `kind = 'app'`. An app key manages end-users and may assert
    /// `X-TAP-End-User`. It is still an API key (auth/rate-limit/hashing apply).
    pub async fn create_app(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
        rate_limit_per_hour: Option<i64>,
    ) -> Result<(), AgentSecError> {
        self.create_agent_with_admin(
            team_id,
            id,
            description,
            api_key_hash,
            rate_limit_per_hour,
            false,
            None,
            "app",
            false,
        )
        .await
    }

    pub async fn create_admin_agent(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
    ) -> Result<(), AgentSecError> {
        self.create_agent_with_admin(
            team_id,
            id,
            description,
            api_key_hash,
            None,
            true,
            None,
            "agent",
            false,
        )
        .await
    }

    pub async fn create_agent_owned(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
        rate_limit_per_hour: Option<i64>,
        owner_user_id: &str,
    ) -> Result<(), AgentSecError> {
        self.create_agent_with_admin(
            team_id,
            id,
            description,
            api_key_hash,
            rate_limit_per_hour,
            false,
            Some(owner_user_id),
            "agent",
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_agent_with_admin(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
        rate_limit_per_hour: Option<i64>,
        is_admin: bool,
        owner_user_id: Option<&str>,
        kind: &str,
        all_credentials: bool,
    ) -> Result<(), AgentSecError> {
        let description_owned = description.map(|s| s.to_string());
        let owner_owned = owner_user_id.map(|s| s.to_string());
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO agents (team_id, id, description, api_key_hash, rate_limit_per_hour, is_admin, owner_user_id, kind, all_credentials, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(team_id)
        .bind(id)
        .bind(description_owned)
        .bind(api_key_hash)
        .bind(rate_limit_per_hour)
        .bind(is_admin)
        .bind(owner_owned)
        .bind(kind)
        .bind(all_credentials)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create agent: {e}")))?;
        Ok(())
    }

    /// Toggle whether an agent key is an **Account key** (all team credentials,
    /// including future ones) vs a Scoped key (per-credential whitelist).
    /// Workspace-manager-gated at the admin layer.
    pub async fn set_agent_all_credentials(
        &self,
        team_id: &str,
        id: &str,
        all_credentials: bool,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE agents SET all_credentials = $1, updated_at = $2 WHERE team_id = $3 AND id = $4",
        )
        .bind(all_credentials)
        .bind(now)
        .bind(team_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to update agent: {e}")))?;
        Ok(())
    }

    pub async fn get_agent(
        &self,
        team_id: &str,
        id: &str,
    ) -> Result<Option<AgentRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, owner_user_id, kind, all_credentials, created_at, updated_at
             FROM agents WHERE team_id = $1 AND id = $2",
        )
        .bind(team_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?;
        match row {
            Some(row) => Ok(Some(AgentRow {
                id: row
                    .try_get("id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                team_id: row
                    .try_get("team_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                description: row
                    .try_get("description")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                api_key_hash: row
                    .try_get("api_key_hash")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                rate_limit_per_hour: row
                    .try_get("rate_limit_per_hour")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                enabled: row
                    .try_get("enabled")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                is_admin: row
                    .try_get("is_admin")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                owner_user_id: row
                    .try_get("owner_user_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                kind: row
                    .try_get("kind")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                all_credentials: row
                    .try_get("all_credentials")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                updated_at: row
                    .try_get("updated_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
            })),
            None => Ok(None),
        }
    }

    pub async fn list_agents(&self, team_id: &str) -> Result<Vec<AgentRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, owner_user_id, kind, all_credentials, created_at, updated_at
             FROM agents WHERE team_id = $1 AND kind = 'agent' ORDER BY id",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(AgentRow {
                id: row
                    .try_get("id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                team_id: row
                    .try_get("team_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                description: row
                    .try_get("description")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                api_key_hash: row
                    .try_get("api_key_hash")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                rate_limit_per_hour: row
                    .try_get("rate_limit_per_hour")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                enabled: row
                    .try_get("enabled")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                is_admin: row
                    .try_get("is_admin")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                owner_user_id: row
                    .try_get("owner_user_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                kind: row
                    .try_get("kind")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                all_credentials: row
                    .try_get("all_credentials")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                updated_at: row
                    .try_get("updated_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
            });
        }
        Ok(results)
    }

    /// List **app keys** (TAP for Platforms) for a team — `agents` rows with
    /// `kind = 'app'`. These are intentionally excluded from `list_agents`.
    pub async fn list_apps(&self, team_id: &str) -> Result<Vec<AgentRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, owner_user_id, kind, all_credentials, created_at, updated_at
             FROM agents WHERE team_id = $1 AND kind = 'app' ORDER BY id",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(AgentRow {
                id: row
                    .try_get("id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                team_id: row
                    .try_get("team_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                description: row
                    .try_get("description")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                api_key_hash: row
                    .try_get("api_key_hash")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                rate_limit_per_hour: row
                    .try_get("rate_limit_per_hour")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                enabled: row
                    .try_get("enabled")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                is_admin: row
                    .try_get("is_admin")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                owner_user_id: row
                    .try_get("owner_user_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                kind: row
                    .try_get("kind")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                all_credentials: row
                    .try_get("all_credentials")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
                updated_at: row
                    .try_get("updated_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list apps: {e}")))?,
            });
        }
        Ok(results)
    }

    pub async fn list_agents_for_owner(
        &self,
        team_id: &str,
        owner_user_id: &str,
    ) -> Result<Vec<AgentRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, owner_user_id, kind, all_credentials, created_at, updated_at
             FROM agents WHERE team_id = $1 AND owner_user_id = $2 AND kind = 'agent' ORDER BY id",
        )
        .bind(team_id)
        .bind(owner_user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list owned agents: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(AgentRow {
                id: row.try_get("id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                team_id: row.try_get("team_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                description: row.try_get("description").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                api_key_hash: row.try_get("api_key_hash").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                rate_limit_per_hour: row.try_get("rate_limit_per_hour").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                enabled: row.try_get("enabled").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                is_admin: row.try_get("is_admin").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                owner_user_id: row.try_get("owner_user_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                kind: row.try_get("kind").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                all_credentials: row.try_get("all_credentials").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                created_at: row.try_get("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
                updated_at: row.try_get("updated_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list owned agents: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    pub async fn delete_agent(&self, team_id: &str, id: &str) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM agents WHERE team_id = $1 AND id = $2")
            .bind(team_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete agent: {e}")))?;
        Ok(())
    }

    pub async fn enable_agent(&self, team_id: &str, id: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE agents SET enabled = TRUE, updated_at = $1 WHERE team_id = $2 AND id = $3",
        )
        .bind(now)
        .bind(team_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to enable agent: {e}")))?;
        Ok(())
    }

    pub async fn disable_agent(&self, team_id: &str, id: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE agents SET enabled = FALSE, updated_at = $1 WHERE team_id = $2 AND id = $3",
        )
        .bind(now)
        .bind(team_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to disable agent: {e}")))?;
        Ok(())
    }

    pub async fn rotate_agent_api_key(
        &self,
        team_id: &str,
        id: &str,
        api_key_hash: &str,
    ) -> Result<(), AgentSecError> {
        if self.get_agent(team_id, id).await?.is_none() {
            return Err(AgentSecError::Config(format!("Agent '{id}' not found")));
        }

        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE agents SET api_key_hash = $1, updated_at = $2 WHERE team_id = $3 AND id = $4",
        )
        .bind(api_key_hash)
        .bind(now)
        .bind(team_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to rotate agent API key: {e}")))?;
        Ok(())
    }

    /// Get the effective credential set for an agent: union of role credentials + direct credentials.
    pub async fn get_agent_effective_credentials(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<HashSet<String>, AgentSecError> {
        let mut creds = HashSet::new();

        // Direct credentials
        let direct_rows = sqlx::query(
            "SELECT credential_name FROM agent_credentials WHERE team_id = $1 AND agent_id = $2",
        )
        .bind(team_id)
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get effective credentials: {e}")))?;
        for row in direct_rows {
            let name: String = row.try_get("credential_name").map_err(|e| {
                AgentSecError::Config(format!("Failed to get effective credentials: {e}"))
            })?;
            creds.insert(name);
        }

        // Role credentials (via agent_roles -> role_credentials)
        let role_rows = sqlx::query(
            "SELECT DISTINCT rc.credential_name
             FROM agent_roles ar
             JOIN role_credentials rc ON ar.team_id = rc.team_id AND ar.role_name = rc.role_name
             WHERE ar.team_id = $1 AND ar.agent_id = $2",
        )
        .bind(team_id)
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get effective credentials: {e}")))?;
        for row in role_rows {
            let name: String = row.try_get("credential_name").map_err(|e| {
                AgentSecError::Config(format!("Failed to get effective credentials: {e}"))
            })?;
            creds.insert(name);
        }

        Ok(creds)
    }

    /// Authenticate an agent by API key hash. Returns the agent if found (caller checks enabled).
    pub async fn authenticate_agent(
        &self,
        api_key_hash: &str,
    ) -> Result<Option<AgentRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, owner_user_id, kind, all_credentials, created_at, updated_at
             FROM agents WHERE api_key_hash = $1",
        )
        .bind(api_key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?;
        match row {
            Some(row) => Ok(Some(AgentRow {
                id: row
                    .try_get("id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                team_id: row
                    .try_get("team_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                description: row
                    .try_get("description")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                api_key_hash: row
                    .try_get("api_key_hash")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                rate_limit_per_hour: row
                    .try_get("rate_limit_per_hour")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                enabled: row
                    .try_get("enabled")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                is_admin: row
                    .try_get("is_admin")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                owner_user_id: row
                    .try_get("owner_user_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                kind: row
                    .try_get("kind")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                all_credentials: row
                    .try_get("all_credentials")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                updated_at: row
                    .try_get("updated_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
            })),
            None => Ok(None),
        }
    }

    // -- Roles ----------------------------------------------------------------

    pub async fn create_role(
        &self,
        team_id: &str,
        name: &str,
        description: Option<&str>,
        rate_limit_per_hour: Option<i64>,
    ) -> Result<(), AgentSecError> {
        let description_owned = description.map(|s| s.to_string());
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO roles (team_id, name, description, rate_limit_per_hour, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(team_id)
        .bind(name)
        .bind(description_owned)
        .bind(rate_limit_per_hour)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create role: {e}")))?;
        Ok(())
    }

    pub async fn list_roles(&self, team_id: &str) -> Result<Vec<RoleRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT name, team_id, description, rate_limit_per_hour, created_at
             FROM roles WHERE team_id = $1 ORDER BY name",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(RoleRow {
                name: row
                    .try_get::<String, _>("name")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
                team_id: row
                    .try_get::<String, _>("team_id")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
                description: row
                    .try_get::<Option<String>, _>("description")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
                rate_limit_per_hour: row
                    .try_get::<Option<i64>, _>("rate_limit_per_hour")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
                created_at: row
                    .try_get::<String, _>("created_at")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
            });
        }
        Ok(results)
    }

    pub async fn update_role(
        &self,
        team_id: &str,
        name: &str,
        description: Option<&str>,
        rate_limit_per_hour: Option<i64>,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "UPDATE roles SET description = $1, rate_limit_per_hour = $2 WHERE team_id = $3 AND name = $4",
        )
        .bind(description)
        .bind(rate_limit_per_hour)
        .bind(team_id)
        .bind(name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to update role: {e}")))?;
        Ok(())
    }

    pub async fn list_role_credentials(
        &self,
        team_id: &str,
        role_name: &str,
    ) -> Result<Vec<String>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT credential_name FROM role_credentials WHERE team_id = $1 AND role_name = $2 ORDER BY credential_name",
        )
        .bind(team_id)
        .bind(role_name)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list role credentials: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row.try_get::<String, _>("credential_name")
                    .map_err(|e| AgentSecError::Config(format!("list_role_credentials: {e}")))?,
            );
        }
        Ok(out)
    }

    pub async fn delete_role(&self, team_id: &str, name: &str) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM roles WHERE team_id = $1 AND name = $2")
            .bind(team_id)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete role: {e}")))?;
        Ok(())
    }

    pub async fn add_credential_to_role(
        &self,
        team_id: &str,
        role_name: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "INSERT INTO role_credentials (team_id, role_name, credential_name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(team_id)
        .bind(role_name)
        .bind(credential_name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to add credential to role: {e}")))?;
        Ok(())
    }

    pub async fn remove_credential_from_role(
        &self,
        team_id: &str,
        role_name: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "DELETE FROM role_credentials WHERE team_id = $1 AND role_name = $2 AND credential_name = $3",
        )
        .bind(team_id)
        .bind(role_name)
        .bind(credential_name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to remove credential from role: {e}")))?;
        Ok(())
    }

    // -- Agent assignments ----------------------------------------------------

    pub async fn assign_role_to_agent(
        &self,
        team_id: &str,
        agent_id: &str,
        role_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "INSERT INTO agent_roles (team_id, agent_id, role_name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(team_id)
        .bind(agent_id)
        .bind(role_name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to assign role: {e}")))?;
        Ok(())
    }

    pub async fn remove_role_from_agent(
        &self,
        team_id: &str,
        agent_id: &str,
        role_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "DELETE FROM agent_roles WHERE team_id = $1 AND agent_id = $2 AND role_name = $3",
        )
        .bind(team_id)
        .bind(agent_id)
        .bind(role_name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to remove role: {e}")))?;
        Ok(())
    }

    pub async fn get_agent_direct_credentials(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<Vec<String>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT credential_name FROM agent_credentials WHERE team_id = $1 AND agent_id = $2",
        )
        .bind(team_id)
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get agent credentials: {e}")))?;
        let mut names = Vec::new();
        for row in rows {
            names.push(row.try_get::<String, _>("credential_name").map_err(|e| {
                AgentSecError::Config(format!("Failed to get agent credentials: {e}"))
            })?);
        }
        Ok(names)
    }

    pub async fn get_agent_roles(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<Vec<String>, AgentSecError> {
        let rows =
            sqlx::query("SELECT role_name FROM agent_roles WHERE team_id = $1 AND agent_id = $2")
                .bind(team_id)
                .bind(agent_id)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| AgentSecError::Config(format!("Failed to get agent roles: {e}")))?;
        let mut names = Vec::new();
        for row in rows {
            names.push(
                row.try_get::<String, _>("role_name").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get agent roles: {e}"))
                })?,
            );
        }
        Ok(names)
    }

    pub async fn add_direct_credential(
        &self,
        team_id: &str,
        agent_id: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "INSERT INTO agent_credentials (team_id, agent_id, credential_name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(team_id)
        .bind(agent_id)
        .bind(credential_name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to add direct credential: {e}")))?;
        Ok(())
    }

    pub async fn remove_direct_credential(
        &self,
        team_id: &str,
        agent_id: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "DELETE FROM agent_credentials WHERE team_id = $1 AND agent_id = $2 AND credential_name = $3",
        )
        .bind(team_id)
        .bind(agent_id)
        .bind(credential_name)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to remove direct credential: {e}")))?;
        Ok(())
    }

    // -- Policies -------------------------------------------------------------

    pub async fn set_policy(&self, policy: &PolicyRow) -> Result<(), AgentSecError> {
        let auto = serde_json::to_string(&policy.auto_approve_methods).unwrap();
        let require = serde_json::to_string(&policy.require_approval_methods).unwrap();
        let urls = serde_json::to_string(&policy.auto_approve_urls).unwrap();
        let require_urls = serde_json::to_string(&policy.require_approval_urls).unwrap();
        let approvers = serde_json::to_string(&policy.allowed_approvers).unwrap();
        let matrix_approvers = serde_json::to_string(&policy.matrix_allowed_approvers).unwrap();
        let passkey_val: i32 = if policy.require_passkey { 1 } else { 0 };
        let min_approvals_val: i32 = policy.min_approvals.max(1) as i32;

        sqlx::query(
            "INSERT INTO policies
             (team_id, credential_name, auto_approve_methods, require_approval_methods, auto_approve_urls, require_approval_urls, allowed_approvers, approval_channel, telegram_chat_id, matrix_room_id, matrix_allowed_approvers, require_passkey, min_approvals)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (team_id, credential_name) DO UPDATE SET
              auto_approve_methods = EXCLUDED.auto_approve_methods,
              require_approval_methods = EXCLUDED.require_approval_methods,
              auto_approve_urls = EXCLUDED.auto_approve_urls,
              require_approval_urls = EXCLUDED.require_approval_urls,
              allowed_approvers = EXCLUDED.allowed_approvers,
              approval_channel = EXCLUDED.approval_channel,
              telegram_chat_id = EXCLUDED.telegram_chat_id,
              matrix_room_id = EXCLUDED.matrix_room_id,
              matrix_allowed_approvers = EXCLUDED.matrix_allowed_approvers,
              require_passkey = EXCLUDED.require_passkey,
              min_approvals = EXCLUDED.min_approvals",
        )
        .bind(&policy.team_id)
        .bind(&policy.credential_name)
        .bind(auto)
        .bind(require)
        .bind(urls)
        .bind(require_urls)
        .bind(approvers)
        .bind(&policy.approval_channel)
        .bind(&policy.telegram_chat_id)
        .bind(&policy.matrix_room_id)
        .bind(matrix_approvers)
        .bind(passkey_val)
        .bind(min_approvals_val)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to set policy: {e}")))?;
        Ok(())
    }

    pub async fn get_policy(
        &self,
        team_id: &str,
        credential_name: &str,
    ) -> Result<Option<PolicyRow>, AgentSecError> {
        let row_opt = sqlx::query(
            "SELECT credential_name, team_id, auto_approve_methods, require_approval_methods, auto_approve_urls, require_approval_urls, allowed_approvers, approval_channel, telegram_chat_id, require_passkey, matrix_room_id, matrix_allowed_approvers, min_approvals
             FROM policies WHERE team_id = $1 AND credential_name = $2",
        )
        .bind(team_id)
        .bind(credential_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
        match row_opt {
            Some(row) => {
                let auto: String = row
                    .try_get::<String, _>("auto_approve_methods")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let require: String = row
                    .try_get::<String, _>("require_approval_methods")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let urls: String = row
                    .try_get::<String, _>("auto_approve_urls")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let require_urls: String = row
                    .try_get::<String, _>("require_approval_urls")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let approvers: String = row
                    .try_get::<String, _>("allowed_approvers")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let passkey_int: i32 = row
                    .try_get::<i32, _>("require_passkey")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let min_approvals_int: i32 = row
                    .try_get::<i32, _>("min_approvals")
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                Ok(Some(PolicyRow {
                    credential_name: row
                        .try_get::<String, _>("credential_name")
                        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?,
                    team_id: row
                        .try_get::<String, _>("team_id")
                        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?,
                    auto_approve_methods: serde_json::from_str(&auto).map_err(|e| {
                        AgentSecError::Config(format!("Failed to parse auto_approve_methods: {e}"))
                    })?,
                    require_approval_methods: serde_json::from_str(&require).map_err(|e| {
                        AgentSecError::Config(format!(
                            "Failed to parse require_approval_methods: {e}"
                        ))
                    })?,
                    auto_approve_urls: serde_json::from_str(&urls).map_err(|e| {
                        AgentSecError::Config(format!("Failed to parse auto_approve_urls: {e}"))
                    })?,
                    require_approval_urls: serde_json::from_str(&require_urls).map_err(|e| {
                        AgentSecError::Config(format!("Failed to parse require_approval_urls: {e}"))
                    })?,
                    allowed_approvers: serde_json::from_str(&approvers).map_err(|e| {
                        AgentSecError::Config(format!("Failed to parse allowed_approvers: {e}"))
                    })?,
                    approval_channel: row
                        .try_get::<Option<String>, _>("approval_channel")
                        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?,
                    telegram_chat_id: row
                        .try_get::<Option<String>, _>("telegram_chat_id")
                        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?,
                    matrix_room_id: row
                        .try_get::<Option<String>, _>("matrix_room_id")
                        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?,
                    matrix_allowed_approvers: serde_json::from_str(
                        &row.try_get::<String, _>("matrix_allowed_approvers")
                            .map_err(|e| {
                                AgentSecError::Config(format!("Failed to get policy: {e}"))
                            })?,
                    )
                    .map_err(|e| {
                        AgentSecError::Config(format!(
                            "Failed to parse matrix_allowed_approvers: {e}"
                        ))
                    })?,
                    require_passkey: passkey_int != 0,
                    min_approvals: min_approvals_int.max(1) as u32,
                }))
            }
            None => Ok(None),
        }
    }

    // -- Policy Templates -------------------------------------------------------

    /// Upsert a named policy template for a team. The `policy` credential_name field
    /// is ignored — the template is keyed by `template_name`.
    pub async fn set_policy_template(
        &self,
        team_id: &str,
        template_name: &str,
        policy: &PolicyRow,
    ) -> Result<(), AgentSecError> {
        let auto = serde_json::to_string(&policy.auto_approve_methods).unwrap();
        let require = serde_json::to_string(&policy.require_approval_methods).unwrap();
        let urls = serde_json::to_string(&policy.auto_approve_urls).unwrap();
        let require_urls = serde_json::to_string(&policy.require_approval_urls).unwrap();
        let approvers = serde_json::to_string(&policy.allowed_approvers).unwrap();
        let matrix_approvers = serde_json::to_string(&policy.matrix_allowed_approvers).unwrap();
        let passkey_val: i32 = if policy.require_passkey { 1 } else { 0 };
        let min_approvals_val: i32 = policy.min_approvals.max(1) as i32;
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO policy_templates
             (team_id, template_name, auto_approve_methods, require_approval_methods,
              auto_approve_urls, require_approval_urls, allowed_approvers, approval_channel, telegram_chat_id, matrix_room_id,
              matrix_allowed_approvers, require_passkey, min_approvals, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
             ON CONFLICT(team_id, template_name) DO UPDATE SET
              auto_approve_methods = excluded.auto_approve_methods,
              require_approval_methods = excluded.require_approval_methods,
              auto_approve_urls = excluded.auto_approve_urls,
              require_approval_urls = excluded.require_approval_urls,
              allowed_approvers = excluded.allowed_approvers,
              approval_channel = excluded.approval_channel,
              telegram_chat_id = excluded.telegram_chat_id,
              matrix_room_id = excluded.matrix_room_id,
              matrix_allowed_approvers = excluded.matrix_allowed_approvers,
              require_passkey = excluded.require_passkey,
              min_approvals = excluded.min_approvals,
              updated_at = excluded.updated_at",
        )
        .bind(team_id)
        .bind(template_name)
        .bind(auto)
        .bind(require)
        .bind(urls)
        .bind(require_urls)
        .bind(approvers)
        .bind(&policy.approval_channel)
        .bind(&policy.telegram_chat_id)
        .bind(&policy.matrix_room_id)
        .bind(matrix_approvers)
        .bind(passkey_val)
        .bind(min_approvals_val)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to set policy template: {e}")))?;
        Ok(())
    }

    /// Fetch a named policy template. Returns the data as a `PolicyRow` with
    /// `credential_name` set to the template name for convenience.
    pub async fn get_policy_template(
        &self,
        team_id: &str,
        template_name: &str,
    ) -> Result<Option<PolicyRow>, AgentSecError> {
        let row_opt = sqlx::query(
            "SELECT template_name, team_id, auto_approve_methods, require_approval_methods,
                    auto_approve_urls, require_approval_urls, allowed_approvers, approval_channel, telegram_chat_id, require_passkey,
                    matrix_room_id, matrix_allowed_approvers, min_approvals
             FROM policy_templates WHERE team_id = $1 AND template_name = $2",
        )
        .bind(team_id)
        .bind(template_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get policy template: {e}")))?;
        match row_opt {
            Some(row) => {
                let auto: String =
                    row.try_get::<String, _>("auto_approve_methods")
                        .map_err(|e| {
                            AgentSecError::Config(format!("Failed to get policy template: {e}"))
                        })?;
                let require: String = row
                    .try_get::<String, _>("require_approval_methods")
                    .map_err(|e| {
                        AgentSecError::Config(format!("Failed to get policy template: {e}"))
                    })?;
                let urls: String = row.try_get::<String, _>("auto_approve_urls").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get policy template: {e}"))
                })?;
                let require_urls: String = row
                    .try_get::<String, _>("require_approval_urls")
                    .map_err(|e| {
                        AgentSecError::Config(format!("Failed to get policy template: {e}"))
                    })?;
                let approvers: String =
                    row.try_get::<String, _>("allowed_approvers").map_err(|e| {
                        AgentSecError::Config(format!("Failed to get policy template: {e}"))
                    })?;
                let passkey_int: i32 = row.try_get::<i32, _>("require_passkey").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get policy template: {e}"))
                })?;
                let min_approvals_int: i32 =
                    row.try_get::<i32, _>("min_approvals").map_err(|e| {
                        AgentSecError::Config(format!("Failed to get policy template: {e}"))
                    })?;
                Ok(Some(PolicyRow {
                    credential_name: row.try_get::<String, _>("template_name").map_err(|e| {
                        AgentSecError::Config(format!("Failed to get policy template: {e}"))
                    })?,
                    team_id: row.try_get::<String, _>("team_id").map_err(|e| {
                        AgentSecError::Config(format!("Failed to get policy template: {e}"))
                    })?,
                    auto_approve_methods: serde_json::from_str(&auto).map_err(|e| {
                        AgentSecError::Config(format!("Failed to parse auto_approve_methods: {e}"))
                    })?,
                    require_approval_methods: serde_json::from_str(&require).map_err(|e| {
                        AgentSecError::Config(format!(
                            "Failed to parse require_approval_methods: {e}"
                        ))
                    })?,
                    auto_approve_urls: serde_json::from_str(&urls).map_err(|e| {
                        AgentSecError::Config(format!("Failed to parse auto_approve_urls: {e}"))
                    })?,
                    require_approval_urls: serde_json::from_str(&require_urls).map_err(|e| {
                        AgentSecError::Config(format!("Failed to parse require_approval_urls: {e}"))
                    })?,
                    allowed_approvers: serde_json::from_str(&approvers).map_err(|e| {
                        AgentSecError::Config(format!("Failed to parse allowed_approvers: {e}"))
                    })?,
                    approval_channel: row
                        .try_get::<Option<String>, _>("approval_channel")
                        .map_err(|e| {
                            AgentSecError::Config(format!("Failed to get policy template: {e}"))
                        })?,
                    telegram_chat_id: row
                        .try_get::<Option<String>, _>("telegram_chat_id")
                        .map_err(|e| {
                            AgentSecError::Config(format!("Failed to get policy template: {e}"))
                        })?,
                    matrix_room_id: row.try_get::<Option<String>, _>("matrix_room_id").map_err(
                        |e| AgentSecError::Config(format!("Failed to get policy template: {e}")),
                    )?,
                    matrix_allowed_approvers: serde_json::from_str(
                        &row.try_get::<String, _>("matrix_allowed_approvers")
                            .map_err(|e| {
                                AgentSecError::Config(format!("Failed to get policy template: {e}"))
                            })?,
                    )
                    .map_err(|e| {
                        AgentSecError::Config(format!(
                            "Failed to parse matrix_allowed_approvers: {e}"
                        ))
                    })?,
                    require_passkey: passkey_int != 0,
                    min_approvals: min_approvals_int.max(1) as u32,
                }))
            }
            None => Ok(None),
        }
    }

    /// List the names of all policy templates for a team.
    pub async fn list_policy_templates(&self, team_id: &str) -> Result<Vec<String>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT template_name FROM policy_templates WHERE team_id = $1 ORDER BY template_name ASC",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list policy templates: {e}")))?;
        let mut names = Vec::new();
        for row in rows {
            let name = row.try_get::<String, _>("template_name").map_err(|e| {
                AgentSecError::Config(format!("Failed to list policy templates: {e}"))
            })?;
            names.push(name);
        }
        Ok(names)
    }

    /// Delete a named policy template.
    pub async fn delete_policy_template(
        &self,
        team_id: &str,
        template_name: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM policy_templates WHERE team_id = $1 AND template_name = $2")
            .bind(team_id)
            .bind(template_name)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete policy template: {e}")))?;
        Ok(())
    }

    // -- Notification Channels -------------------------------------------------

    pub async fn create_notification_channel(
        &self,
        team_id: &str,
        channel_type: &str,
        name: &str,
        config_json: &str,
    ) -> Result<String, AgentSecError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO notification_channels (id, team_id, channel_type, name, config_json, enabled, priority, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, TRUE, 1000, $6, $6)",
        )
        .bind(&id)
        .bind(team_id)
        .bind(channel_type)
        .bind(name)
        .bind(config_json)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create notification channel: {e}")))?;
        Ok(id)
    }

    pub async fn get_notification_channel(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<Option<NotificationChannelRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, team_id, channel_type, name, config_json, enabled, priority, created_at, updated_at
             FROM notification_channels WHERE team_id = $1 AND name = $2",
        )
        .bind(team_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get notification channel: {e}")))?;
        match row {
            Some(row) => Ok(Some(NotificationChannelRow {
                id: row.try_get::<String, _>("id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                team_id: row.try_get::<String, _>("team_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                channel_type: row.try_get::<String, _>("channel_type").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                name: row.try_get::<String, _>("name").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                config_json: row.try_get::<String, _>("config_json").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                enabled: row.try_get::<bool, _>("enabled").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                priority: row.try_get::<i32, _>("priority").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                created_at: row.try_get::<String, _>("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                updated_at: row.try_get::<String, _>("updated_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
            })),
            None => Ok(None),
        }
    }

    pub async fn list_notification_channels(
        &self,
        team_id: &str,
    ) -> Result<Vec<NotificationChannelRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT id, team_id, channel_type, name, config_json, enabled, priority, created_at, updated_at
             FROM notification_channels WHERE team_id = $1 ORDER BY priority, created_at",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list notification channels: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(NotificationChannelRow {
                id: row.try_get::<String, _>("id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                team_id: row.try_get::<String, _>("team_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                channel_type: row.try_get::<String, _>("channel_type").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                name: row.try_get::<String, _>("name").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                config_json: row.try_get::<String, _>("config_json").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                enabled: row.try_get::<bool, _>("enabled").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                priority: row.try_get::<i32, _>("priority").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                created_at: row.try_get::<String, _>("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                updated_at: row.try_get::<String, _>("updated_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    pub async fn delete_notification_channel(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<(), AgentSecError> {
        let result =
            sqlx::query("DELETE FROM notification_channels WHERE team_id = $1 AND name = $2")
                .bind(team_id)
                .bind(name)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to delete notification channel: {e}"))
                })?;
        if result.rows_affected() == 0 {
            return Err(AgentSecError::Config(
                "Failed to delete notification channel: no matching channel found".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn set_default_notification_channel(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE notification_channels
             SET priority = 1000, updated_at = $2
             WHERE team_id = $1",
        )
        .bind(team_id)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to set default notification channel: {e}"))
        })?;

        let result = sqlx::query(
            "UPDATE notification_channels
             SET priority = 0, updated_at = $3
             WHERE team_id = $1 AND name = $2 AND enabled = TRUE",
        )
        .bind(team_id)
        .bind(name)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to set default notification channel: {e}"))
        })?;

        if result.rows_affected() == 0 {
            return Err(AgentSecError::Config(
                "Failed to set default notification channel: no enabled channel found".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the default Telegram chat_id for a team.
    /// Finds the first enabled telegram channel and parses chat_id from config_json.
    pub async fn get_default_telegram_chat_id(
        &self,
        team_id: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let row = sqlx::query(
            "SELECT config_json FROM notification_channels
             WHERE team_id = $1 AND channel_type = 'telegram' AND enabled = TRUE
             ORDER BY created_at LIMIT 1",
        )
        .bind(team_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to get default telegram chat_id: {e}"))
        })?;
        match row {
            Some(row) => {
                let json_str: String = row.try_get::<String, _>("config_json").map_err(|e| {
                    AgentSecError::Config(format!("Failed to get default telegram chat_id: {e}"))
                })?;
                let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_default();
                Ok(parsed
                    .get("chat_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()))
            }
            None => Ok(None),
        }
    }

    // -- Sessions -------------------------------------------------------------

    /// Create a session bound to a user identity AND an active team. The active
    /// team determines which membership the session resolves to on validation.
    /// This mints a normal (full-privilege) dashboard session.
    pub async fn create_session(
        &self,
        token_hash: &str,
        user_id: &str,
        team_id: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        self.insert_session(token_hash, user_id, team_id, expires_at, "full")
            .await
    }

    /// Mint a SCOPED "agent" session for the CLI (`tap login`). An agent session
    /// is restricted at the router to a small allowlist (read own identity, log
    /// out) so a compromised agent that reads the token can never drive the full
    /// dashboard API. Enforcement lives in the agent-session guard in tap-proxy.
    pub async fn create_agent_session(
        &self,
        token_hash: &str,
        user_id: &str,
        team_id: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        self.insert_session(token_hash, user_id, team_id, expires_at, "agent")
            .await
    }

    async fn insert_session(
        &self,
        token_hash: &str,
        user_id: &str,
        team_id: &str,
        expires_at: &str,
        scope: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO admin_sessions (token_hash, user_id, team_id, expires_at, created_at, scope)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .persistent(false)
        .bind(token_hash)
        .bind(user_id)
        .bind(team_id)
        .bind(expires_at)
        .bind(now)
        .bind(scope)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create session: {e}")))?;
        Ok(())
    }

    /// Return the scope ('full' | 'agent') of a valid, unexpired session, or None
    /// if the token is unknown/expired. Used by the router's agent-session guard
    /// to restrict what a `tap login` (agent) session may reach.
    pub async fn session_scope(
        &self,
        token_hash: &str,
    ) -> Result<Option<String>, AgentSecError> {
        use sqlx::Row;
        let now = chrono::Utc::now().to_rfc3339();
        let row =
            sqlx::query("SELECT scope FROM admin_sessions WHERE token_hash = $1 AND expires_at > $2")
                .persistent(false)
                .bind(token_hash)
                .bind(&now)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to read session scope: {e}"))
                })?;
        Ok(row.map(|r| r.get::<String, _>("scope")))
    }

    /// Validate a session token hash. Returns the resolved `Member` (the user in
    /// the session's active team) if valid and not expired. Returns None if the
    /// token is unknown/expired OR if the user no longer has a membership in the
    /// session's active team.
    pub async fn validate_session(
        &self,
        token_hash: &str,
    ) -> Result<Option<Member>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let sql = format!(
            "{} JOIN admin_sessions s ON s.user_id = u.id AND s.team_id = m.team_id
             WHERE s.token_hash = $1 AND s.expires_at > $2",
            Self::MEMBER_SELECT
        );
        let row = sqlx::query(&sql)
            .persistent(false)
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to validate session: {e}")))?;
        match row {
            Some(row) => Ok(Some(member_from_query(&row, "validate session")?)),
            None => Ok(None),
        }
    }

    pub async fn delete_session(&self, token_hash: &str) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM admin_sessions WHERE token_hash = $1")
            .persistent(false)
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete session: {e}")))?;
        Ok(())
    }

    /// Device authorization flow (`tap login`): create a pending row keyed by
    /// the device_code hash. The raw device_code is returned to the CLI only,
    /// never stored.
    pub async fn create_device_authorization(
        &self,
        device_code_hash: &str,
        user_code: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        // Best-effort prune of expired rows so abandoned flows don't accumulate
        // (this endpoint is unauthenticated; mirrors the oauth_states pattern).
        let _ = sqlx::query("DELETE FROM device_authorizations WHERE expires_at < $1")
            .persistent(false)
            .bind(&now)
            .execute(&self.pool)
            .await;
        sqlx::query(
            "INSERT INTO device_authorizations
                (device_code_hash, user_code, status, expires_at, created_at)
             VALUES ($1, $2, 'pending', $3, $4)",
        )
        .persistent(false)
        .bind(device_code_hash)
        .bind(user_code)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create device authorization: {e}")))?;
        Ok(())
    }

    /// Human confirms a device code from the dashboard: bind their identity and
    /// flip pending -> approved atomically. Returns false if the code is
    /// unknown, expired, or already resolved.
    pub async fn approve_device_authorization(
        &self,
        user_code: &str,
        user_id: &str,
        team_id: &str,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "UPDATE device_authorizations
                SET status = 'approved', user_id = $1, team_id = $2
              WHERE user_code = $3 AND status = 'pending' AND expires_at > $4
          RETURNING device_code_hash",
        )
        .persistent(false)
        .bind(user_id)
        .bind(team_id)
        .bind(user_code)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to approve device authorization: {e}"))
        })?;
        Ok(row.is_some())
    }

    /// CLI polls with the device_code. If approved, atomically flip
    /// approved -> claimed and return the bound identity so the caller can mint
    /// a fresh session. Otherwise report why (pending/denied/expired).
    pub async fn claim_device_authorization(
        &self,
        device_code_hash: &str,
    ) -> Result<DeviceClaim, AgentSecError> {
        use sqlx::Row;
        let now = chrono::Utc::now().to_rfc3339();
        let claimed = sqlx::query(
            "UPDATE device_authorizations
                SET status = 'claimed'
              WHERE device_code_hash = $1 AND status = 'approved' AND expires_at > $2
          RETURNING user_id, team_id",
        )
        .persistent(false)
        .bind(device_code_hash)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to claim device authorization: {e}")))?;
        if let Some(row) = claimed {
            let user_id: String = row.get("user_id");
            let team_id: String = row.get("team_id");
            return Ok(DeviceClaim::Approved { user_id, team_id });
        }
        let status_row = sqlx::query(
            "SELECT status, expires_at FROM device_authorizations WHERE device_code_hash = $1",
        )
        .persistent(false)
        .bind(device_code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to read device authorization: {e}")))?;
        match status_row {
            None => Ok(DeviceClaim::ExpiredOrUnknown),
            Some(row) => {
                let status: String = row.get("status");
                let expires_at: String = row.get("expires_at");
                if expires_at.as_str() <= now.as_str() {
                    return Ok(DeviceClaim::ExpiredOrUnknown);
                }
                match status.as_str() {
                    "pending" => Ok(DeviceClaim::Pending),
                    "denied" => Ok(DeviceClaim::Denied),
                    _ => Ok(DeviceClaim::ExpiredOrUnknown),
                }
            }
        }
    }

    /// Store a pending credential setup (`tap cred set`). The secret is encrypted
    /// at rest with the same AES-256-GCM key as live credential values; it is
    /// only promoted to a real credential by `activate_credential_setup` after the
    /// passkey ceremony. Best-effort prunes expired rows first.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_credential_setup(
        &self,
        setup_id: &str,
        team_id: &str,
        created_by: &str,
        name: &str,
        description: &str,
        connector: &str,
        api_base: Option<&str>,
        auth_header_format: Option<&str>,
        allowed_hosts_json: Option<&str>,
        plaintext_value: &[u8],
        require_passkey: bool,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = sqlx::query("DELETE FROM credential_setups WHERE expires_at < $1")
            .persistent(false)
            .bind(&now)
            .execute(&self.pool)
            .await;
        let encrypted = crypto::encrypt(&self.encryption_key, plaintext_value)
            .map_err(AgentSecError::Encryption)?;
        sqlx::query(
            "INSERT INTO credential_setups
                (setup_id, team_id, created_by, name, description, connector, api_base,
                 auth_header_format, allowed_hosts_json, require_passkey, encrypted_value, status, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending', $12, $13)",
        )
        .persistent(false)
        .bind(setup_id)
        .bind(team_id)
        .bind(created_by)
        .bind(name)
        .bind(description)
        .bind(connector)
        .bind(api_base)
        .bind(auth_header_format)
        .bind(allowed_hosts_json)
        .bind(require_passkey)
        .bind(encrypted)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create credential setup: {e}")))?;
        Ok(())
    }

    /// Read a pending setup's metadata (never the secret) for the CLI poll and the
    /// dashboard activation page.
    pub async fn get_credential_setup(
        &self,
        setup_id: &str,
    ) -> Result<Option<CredentialSetupInfo>, AgentSecError> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT setup_id, team_id, created_by, name, description, allowed_hosts_json, status, expires_at
             FROM credential_setups WHERE setup_id = $1",
        )
        .persistent(false)
        .bind(setup_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to read credential setup: {e}")))?;
        Ok(row.map(|row| CredentialSetupInfo {
            setup_id: row.get("setup_id"),
            team_id: row.get("team_id"),
            created_by: row.get("created_by"),
            name: row.get("name"),
            description: row.get("description"),
            allowed_hosts_json: row.get("allowed_hosts_json"),
            status: row.get("status"),
            expires_at: row.get("expires_at"),
        }))
    }

    /// Atomically claim a pending, unexpired setup (single-use, cross-instance
    /// safe) and return its data with the secret DECRYPTED, so the caller can
    /// write the live credential. Returns None if it isn't claimable (already
    /// activated, expired, or unknown).
    pub async fn activate_credential_setup(
        &self,
        setup_id: &str,
    ) -> Result<Option<CredentialSetupData>, AgentSecError> {
        use sqlx::Row;
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "UPDATE credential_setups
                SET status = 'activated'
              WHERE setup_id = $1 AND status = 'pending' AND expires_at > $2
          RETURNING team_id, created_by, name, description, connector, api_base,
                    auth_header_format, allowed_hosts_json, require_passkey, encrypted_value",
        )
        .persistent(false)
        .bind(setup_id)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to activate credential setup: {e}")))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let encrypted: Vec<u8> = row.get("encrypted_value");
        let plaintext =
            crypto::decrypt(&self.encryption_key, &encrypted).map_err(AgentSecError::Encryption)?;
        Ok(Some(CredentialSetupData {
            team_id: row.get("team_id"),
            created_by: row.get("created_by"),
            name: row.get("name"),
            description: row.get("description"),
            connector: row.get("connector"),
            api_base: row.get("api_base"),
            auth_header_format: row.get("auth_header_format"),
            allowed_hosts_json: row.get("allowed_hosts_json"),
            plaintext_value: plaintext,
            require_passkey: row.get("require_passkey"),
        }))
    }

    /// Atomically switch a session's active team. Returns true if a row was
    /// updated (the session exists). Caller is responsible for verifying the
    /// user actually has a membership in the target team before calling this.
    /// Single-statement UPDATE — safe across stateless proxy instances.
    pub async fn update_session_team(
        &self,
        token_hash: &str,
        team_id: &str,
    ) -> Result<bool, AgentSecError> {
        let result = sqlx::query("UPDATE admin_sessions SET team_id = $1 WHERE token_hash = $2")
            .bind(team_id)
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to switch session team: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    // -----------------------------------------------------------------------
    // Social login (Google/GitHub): identities, login states, continuations
    // -----------------------------------------------------------------------

    /// The user a provider identity (`sub`) is linked to, if any.
    pub async fn get_identity_user(
        &self,
        provider: &str,
        provider_sub: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let row =
            sqlx::query("SELECT user_id FROM user_identities WHERE provider = $1 AND provider_sub = $2")
                .persistent(false)
                .bind(provider)
                .bind(provider_sub)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AgentSecError::Config(format!("Failed to load identity: {e}")))?;
        row.map(|r| {
            r.try_get("user_id")
                .map_err(|e| AgentSecError::Config(format!("identity user_id: {e}")))
        })
        .transpose()
    }

    /// Link a provider identity to a user. Idempotent when the identity is
    /// already linked to the SAME user. Never repoints an identity linked to a
    /// DIFFERENT user — that case returns `Ok(false)` (the existing link wins,
    /// untouched) so callers surface the conflict instead of proceeding as if
    /// the link landed. Callers resolve identities via
    /// [`Self::get_identity_user`] before ever calling this, so `false` here
    /// means a concurrent flow claimed the identity in the window.
    pub async fn link_user_identity(
        &self,
        user_id: &str,
        provider: &str,
        provider_sub: &str,
        email: &str,
    ) -> Result<bool, AgentSecError> {
        let result = sqlx::query(
            "INSERT INTO user_identities (provider, provider_sub, user_id, email_at_link, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (provider, provider_sub) DO NOTHING",
        )
        .persistent(false)
        .bind(provider)
        .bind(provider_sub)
        .bind(user_id)
        .bind(email)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to link identity: {e}")))?;
        if result.rows_affected() > 0 {
            return Ok(true);
        }
        Ok(self.get_identity_user(provider, provider_sub).await?.as_deref() == Some(user_id))
    }

    /// Providers linked to a user (for the account settings surface).
    pub async fn list_user_identities(
        &self,
        user_id: &str,
    ) -> Result<Vec<(String, String)>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT provider, email_at_link FROM user_identities WHERE user_id = $1 ORDER BY provider",
        )
        .persistent(false)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list identities: {e}")))?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    r.try_get("provider")
                        .map_err(|e| AgentSecError::Config(format!("identity provider: {e}")))?,
                    r.try_get("email_at_link")
                        .map_err(|e| AgentSecError::Config(format!("identity email: {e}")))?,
                ))
            })
            .collect()
    }

    /// Persist a login-flow OAuth state (CSRF binding). Prunes expired rows.
    /// `browser_bind_hash` is the hash of the per-browser nonce set as an
    /// HttpOnly cookie at `/start`; the callback must present a matching cookie
    /// (session-fixation / login-CSRF defense). Provider-agnostic.
    pub async fn create_login_oauth_state(
        &self,
        state_hash: &str,
        provider: &str,
        expires_at: &str,
        browser_bind_hash: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = sqlx::query("DELETE FROM login_oauth_states WHERE expires_at < $1")
            .persistent(false)
            .bind(&now)
            .execute(&self.pool)
            .await;
        sqlx::query(
            "INSERT INTO login_oauth_states (state_hash, provider, created_at, expires_at, browser_bind_hash)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .persistent(false)
        .bind(state_hash)
        .bind(provider)
        .bind(now)
        .bind(expires_at)
        .bind(browser_bind_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create login OAuth state: {e}")))?;
        Ok(())
    }

    /// Atomically claim a login-flow OAuth state (single DELETE … RETURNING —
    /// a replayed callback can't double-spend, works across instances). Returns
    /// `(provider, expires_at, browser_bind_hash)`; the caller checks expiry and
    /// verifies the browser-binding cookie against the returned hash.
    pub async fn take_login_oauth_state(
        &self,
        state_hash: &str,
    ) -> Result<Option<(String, chrono::DateTime<chrono::Utc>, Option<String>)>, AgentSecError> {
        let row = sqlx::query(
            "DELETE FROM login_oauth_states WHERE state_hash = $1 RETURNING provider, expires_at, browser_bind_hash",
        )
        .persistent(false)
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to take login OAuth state: {e}")))?;
        let Some(row) = row else { return Ok(None) };
        let provider: String = row
            .try_get("provider")
            .map_err(|e| AgentSecError::Config(format!("login state provider: {e}")))?;
        let expires_str: String = row
            .try_get("expires_at")
            .map_err(|e| AgentSecError::Config(format!("login state expires_at: {e}")))?;
        let browser_bind_hash: Option<String> = row.try_get("browser_bind_hash").ok().flatten();
        let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_str)
            .map_err(|e| AgentSecError::Config(format!("login state bad expires_at: {e}")))?
            .with_timezone(&chrono::Utc);
        Ok(Some((provider, expires_at, browser_bind_hash)))
    }

    /// Persist a login continuation: the bridge between the provider callback
    /// (browser redirect) and the SPA's completion POST. `kind` = 'login'
    /// (`user_id` set) or 'signup' (provider identity fields set).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_login_continuation(
        &self,
        token_hash: &str,
        kind: &str,
        user_id: Option<&str>,
        provider: Option<&str>,
        provider_sub: Option<&str>,
        email: Option<&str>,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = sqlx::query("DELETE FROM login_continuations WHERE expires_at < $1")
            .persistent(false)
            .bind(&now)
            .execute(&self.pool)
            .await;
        sqlx::query(
            "INSERT INTO login_continuations
                (token_hash, kind, user_id, provider, provider_sub, email, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .persistent(false)
        .bind(token_hash)
        .bind(kind)
        .bind(user_id)
        .bind(provider)
        .bind(provider_sub)
        .bind(email)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create login continuation: {e}")))?;
        Ok(())
    }

    /// Atomically claim a login continuation (single-use, cross-instance).
    /// Returns `(kind, user_id, provider, provider_sub, email, expires_at)`.
    #[allow(clippy::type_complexity)]
    pub async fn take_login_continuation(
        &self,
        token_hash: &str,
    ) -> Result<
        Option<(
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
        )>,
        AgentSecError,
    > {
        let row = sqlx::query(
            "DELETE FROM login_continuations WHERE token_hash = $1
             RETURNING kind, user_id, provider, provider_sub, email, expires_at",
        )
        .persistent(false)
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to take login continuation: {e}")))?;
        let Some(row) = row else { return Ok(None) };
        let expires_str: String = row
            .try_get("expires_at")
            .map_err(|e| AgentSecError::Config(format!("continuation expires_at: {e}")))?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_str)
            .map_err(|e| AgentSecError::Config(format!("continuation bad expires_at: {e}")))?
            .with_timezone(&chrono::Utc);
        Ok(Some((
            row.try_get("kind")
                .map_err(|e| AgentSecError::Config(format!("continuation kind: {e}")))?,
            row.try_get("user_id")
                .map_err(|e| AgentSecError::Config(format!("continuation user_id: {e}")))?,
            row.try_get("provider")
                .map_err(|e| AgentSecError::Config(format!("continuation provider: {e}")))?,
            row.try_get("provider_sub")
                .map_err(|e| AgentSecError::Config(format!("continuation provider_sub: {e}")))?,
            row.try_get("email")
                .map_err(|e| AgentSecError::Config(format!("continuation email: {e}")))?,
            expires_at,
        )))
    }

    /// Stage an identity link that must wait for the matched user to complete
    /// a full login (passkey included). Upserts per `(user_id, provider)`.
    pub async fn create_pending_identity_link(
        &self,
        user_id: &str,
        provider: &str,
        provider_sub: &str,
        email: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        sqlx::query(
            "INSERT INTO pending_identity_links (user_id, provider, provider_sub, email, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (user_id, provider) DO UPDATE
                SET provider_sub = EXCLUDED.provider_sub,
                    email = EXCLUDED.email,
                    created_at = EXCLUDED.created_at,
                    expires_at = EXCLUDED.expires_at",
        )
        .persistent(false)
        .bind(user_id)
        .bind(provider)
        .bind(provider_sub)
        .bind(email)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to stage identity link: {e}")))?;
        Ok(())
    }

    /// Atomically consume every non-expired staged link for a user (called
    /// after that user completes a full login). Returns
    /// `(provider, provider_sub, email)` triples to persist.
    pub async fn take_pending_identity_links(
        &self,
        user_id: &str,
    ) -> Result<Vec<(String, String, String)>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let rows = sqlx::query(
            "DELETE FROM pending_identity_links WHERE user_id = $1
             RETURNING provider, provider_sub, email, expires_at",
        )
        .persistent(false)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to take pending links: {e}")))?;
        let mut links = Vec::new();
        for row in rows {
            let expires_at: String = row
                .try_get("expires_at")
                .map_err(|e| AgentSecError::Config(format!("pending link expires_at: {e}")))?;
            // Expired staged links are dropped, not honored.
            if expires_at < now {
                continue;
            }
            links.push((
                row.try_get("provider")
                    .map_err(|e| AgentSecError::Config(format!("pending link provider: {e}")))?,
                row.try_get("provider_sub")
                    .map_err(|e| AgentSecError::Config(format!("pending link sub: {e}")))?,
                row.try_get("email")
                    .map_err(|e| AgentSecError::Config(format!("pending link email: {e}")))?,
            ));
        }
        Ok(links)
    }

    // -- OAuth consent state --------------------------------------------------

    /// Persist a pending OAuth consent state. `expires_at` is RFC 3339;
    /// `scopes` is the space-separated scope set requested at consent time.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_oauth_state(
        &self,
        state_hash: &str,
        admin_id: &str,
        team_id: &str,
        credential_name: &str,
        credential_description: &str,
        scopes: &str,
        provider: &str,
        assign_agents: &[String],
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        self.create_oauth_state_with_flow(
            state_hash,
            admin_id,
            team_id,
            credential_name,
            credential_description,
            scopes,
            "create",
            provider,
            assign_agents,
            expires_at,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_oauth_state_with_flow(
        &self,
        state_hash: &str,
        admin_id: &str,
        team_id: &str,
        credential_name: &str,
        credential_description: &str,
        scopes: &str,
        flow_type: &str,
        provider: &str,
        assign_agents: &[String],
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        // Best-effort prune of expired rows so abandoned flows don't accumulate.
        let _ = sqlx::query("DELETE FROM oauth_states WHERE expires_at < $1")
            .persistent(false)
            .bind(&now)
            .execute(&self.pool)
            .await;
        // Persist the chosen agent ids as a JSON array (NULL when none) so the
        // callback can grant the created credential under the start passkey.
        let assign_agents_json = if assign_agents.is_empty() {
            None
        } else {
            Some(serde_json::to_string(assign_agents).unwrap_or_default())
        };
        sqlx::query(
            "INSERT INTO oauth_states
                (state_hash, admin_id, team_id, credential_name, credential_description, scopes, flow_type, provider, assign_agents, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .persistent(false)
        .bind(state_hash)
        .bind(admin_id)
        .bind(team_id)
        .bind(credential_name)
        .bind(credential_description)
        .bind(scopes)
        .bind(flow_type)
        .bind(provider)
        .bind(assign_agents_json)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create OAuth state: {e}")))?;
        Ok(())
    }

    /// Atomically claim a pending OAuth state: delete the row and return it in a
    /// single statement so a replayed callback can't consume it twice. Returns
    /// None if `state_hash` is unknown. The returned row MAY be expired — the
    /// caller checks `expires_at` so it can distinguish invalid vs expired.
    /// Single-statement claim ⇒ safe across stateless instances.
    pub async fn take_oauth_state(
        &self,
        state_hash: &str,
    ) -> Result<Option<OAuthState>, AgentSecError> {
        let row = sqlx::query(
            "DELETE FROM oauth_states WHERE state_hash = $1
             RETURNING admin_id, team_id, credential_name, credential_description, scopes, flow_type, provider, end_user_id, return_url, assign_agents, expires_at",
        )
        .persistent(false)
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to take OAuth state: {e}")))?;

        let Some(row) = row else { return Ok(None) };
        let expires_str: String = row
            .try_get("expires_at")
            .map_err(|e| AgentSecError::Config(format!("take_oauth_state expires_at: {e}")))?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_str)
            .map_err(|e| AgentSecError::Config(format!("take_oauth_state bad expires_at: {e}")))?
            .with_timezone(&chrono::Utc);
        Ok(Some(OAuthState {
            admin_id: row
                .try_get("admin_id")
                .map_err(|e| AgentSecError::Config(format!("take_oauth_state admin_id: {e}")))?,
            team_id: row
                .try_get("team_id")
                .map_err(|e| AgentSecError::Config(format!("take_oauth_state team_id: {e}")))?,
            credential_name: row.try_get("credential_name").map_err(|e| {
                AgentSecError::Config(format!("take_oauth_state credential_name: {e}"))
            })?,
            credential_description: row.try_get("credential_description").map_err(|e| {
                AgentSecError::Config(format!("take_oauth_state credential_description: {e}"))
            })?,
            scopes: row
                .try_get("scopes")
                .map_err(|e| AgentSecError::Config(format!("take_oauth_state scopes: {e}")))?,
            flow_type: row
                .try_get("flow_type")
                .map_err(|e| AgentSecError::Config(format!("take_oauth_state flow_type: {e}")))?,
            provider: row
                .try_get("provider")
                .map_err(|e| AgentSecError::Config(format!("take_oauth_state provider: {e}")))?,
            end_user_id: row
                .try_get("end_user_id")
                .map_err(|e| AgentSecError::Config(format!("take_oauth_state end_user_id: {e}")))?,
            return_url: row
                .try_get("return_url")
                .map_err(|e| AgentSecError::Config(format!("take_oauth_state return_url: {e}")))?,
            assign_agents: {
                let raw: Option<String> = row.try_get("assign_agents").map_err(|e| {
                    AgentSecError::Config(format!("take_oauth_state assign_agents: {e}"))
                })?;
                raw.and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                    .unwrap_or_default()
            },
            expires_at,
        }))
    }

    /// Persist a TAP-mediated per-end-user OAuth flow state (`create` flow,
    /// scoped to a managed end-user, with a partner return URL).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_oauth_state_scoped(
        &self,
        state_hash: &str,
        admin_id: &str,
        team_id: &str,
        credential_name: &str,
        credential_description: &str,
        scopes: &str,
        provider: &str,
        end_user_id: &str,
        return_url: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let _ = sqlx::query("DELETE FROM oauth_states WHERE expires_at < $1")
            .persistent(false)
            .bind(&now)
            .execute(&self.pool)
            .await;
        sqlx::query(
            "INSERT INTO oauth_states
                (state_hash, admin_id, team_id, credential_name, credential_description, scopes, flow_type, provider, end_user_id, return_url, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'create', $7, $8, $9, $10, $11)",
        )
        .persistent(false)
        .bind(state_hash)
        .bind(admin_id)
        .bind(team_id)
        .bind(credential_name)
        .bind(credential_description)
        .bind(scopes)
        .bind(provider)
        .bind(end_user_id)
        .bind(return_url)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create scoped OAuth state: {e}")))?;
        Ok(())
    }

    // -- Email verification ---------------------------------------------------

    pub async fn create_email_verification(
        &self,
        code_hash: &str,
        user_id: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO email_verifications (code_hash, user_id, expires_at, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(code_hash)
        .bind(user_id)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create verification: {e}")))?;
        Ok(())
    }

    /// Validate an email verification code. Returns user_id if valid and not expired.
    /// Deletes the code on success (one-time use) and marks the user verified.
    pub async fn validate_email_verification(
        &self,
        code_hash: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();

        // Try to find the verification code
        let row = sqlx::query(
            "SELECT user_id FROM email_verifications
             WHERE code_hash = $1 AND expires_at > $2",
        )
        .bind(code_hash)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to validate verification: {e}")))?;

        let user_id: Option<String> = match row {
            Some(row) => Some(row.try_get::<String, _>("user_id").map_err(|e| {
                AgentSecError::Config(format!("Failed to validate verification: {e}"))
            })?),
            None => None,
        };

        if let Some(ref id) = user_id {
            // Delete used code
            sqlx::query("DELETE FROM email_verifications WHERE code_hash = $1")
                .bind(code_hash)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate verification: {e}"))
                })?;
            // Mark user as verified
            sqlx::query("UPDATE users SET email_verified = TRUE, updated_at = $1 WHERE id = $2")
                .bind(&now)
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate verification: {e}"))
                })?;
        }

        Ok(user_id)
    }

    // -- Time-boxed approval grants (#49) ---------------------------------------

    /// Create a time-boxed approval grant. Guardrail validation (narrow scope,
    /// TTL cap, no `require_passkey` credential) happens at the admin layer;
    /// this only persists.
    pub async fn create_approval_grant(&self, grant: &GrantRow) -> Result<(), AgentSecError> {
        sqlx::query(
            "INSERT INTO approval_grants
                 (id, team_id, credential_name, methods, route_scope, expires_at,
                  granted_by, max_uses, uses, revoked, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, FALSE, $9)",
        )
        .bind(&grant.id)
        .bind(&grant.team_id)
        .bind(&grant.credential_name)
        .bind(serde_json::to_string(&grant.methods).unwrap_or_else(|_| "[]".into()))
        .bind(serde_json::to_string(&grant.route_scope).unwrap_or_else(|_| "[]".into()))
        .bind(&grant.expires_at)
        .bind(&grant.granted_by)
        .bind(grant.max_uses)
        .bind(&grant.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create approval grant: {e}")))?;
        Ok(())
    }

    /// All grants for a team (newest first, capped) — the dashboard derives
    /// active/expired/exhausted state from the row fields.
    pub async fn list_approval_grants(&self, team_id: &str) -> Result<Vec<GrantRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT id, team_id, credential_name, methods, route_scope, expires_at,
                    granted_by, max_uses, uses, revoked, created_at
             FROM approval_grants WHERE team_id = $1
             ORDER BY created_at DESC LIMIT 200",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list approval grants: {e}")))?;
        rows.iter().map(grant_row_from_pg).collect()
    }

    /// Live grants for one credential: not revoked, not expired, uses left.
    /// `now` is injected (not the ambient clock) for deterministic expiry tests.
    /// The proxy matches method + URL against these in Rust, then claims by id.
    pub async fn live_grants_for_credential(
        &self,
        team_id: &str,
        credential_name: &str,
        now: &str,
    ) -> Result<Vec<GrantRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT id, team_id, credential_name, methods, route_scope, expires_at,
                    granted_by, max_uses, uses, revoked, created_at
             FROM approval_grants
             WHERE team_id = $1 AND credential_name = $2 AND revoked = FALSE
               AND expires_at > $3 AND (max_uses IS NULL OR uses < max_uses)
             ORDER BY created_at ASC",
        )
        .bind(team_id)
        .bind(credential_name)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to load live grants: {e}")))?;
        rows.iter().map(grant_row_from_pg).collect()
    }

    /// Atomically consume one use of a grant. The liveness conditions are in
    /// the UPDATE's own WHERE clause, so they are re-checked under the row
    /// lock — concurrent claims can never push `uses` past `max_uses`, and a
    /// revocation or expiry that lands between candidate SELECT and claim
    /// causes a clean miss (caller falls through to the human prompt).
    pub async fn claim_approval_grant(&self, id: &str, now: &str) -> Result<bool, AgentSecError> {
        let row = sqlx::query(
            "UPDATE approval_grants SET uses = uses + 1
             WHERE id = $1 AND revoked = FALSE AND expires_at > $2
               AND (max_uses IS NULL OR uses < max_uses)
             RETURNING id",
        )
        .bind(id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to claim approval grant: {e}")))?;
        Ok(row.is_some())
    }

    /// Revoke a grant (one-click kill). Team-scoped; returns false if the id
    /// doesn't belong to the team. The row is kept for audit; a revoked grant
    /// can never be claimed again.
    pub async fn revoke_approval_grant(
        &self,
        team_id: &str,
        id: &str,
    ) -> Result<bool, AgentSecError> {
        let row = sqlx::query(
            "UPDATE approval_grants SET revoked = TRUE
             WHERE id = $1 AND team_id = $2 RETURNING id",
        )
        .bind(id)
        .bind(team_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to revoke approval grant: {e}")))?;
        Ok(row.is_some())
    }

    // -- Password resets -------------------------------------------------------

    /// Create a password reset token, enforcing a per-user cooldown: if a
    /// reset was already created within the last `cooldown_minutes`, nothing
    /// is written and `Ok(false)` is returned (the caller must not send
    /// another email). Otherwise any prior pending token is replaced (one
    /// reset token per user at a time) and `Ok(true)` is returned.
    ///
    /// A single race-free upsert enforces the cooldown across stateless proxy
    /// instances. `password_resets` has a UNIQUE constraint on `user_id`, so
    /// there is at most one reset row per user and the `ON CONFLICT (user_id)`
    /// arm serializes concurrent requests: exactly one INSERT wins the row and
    /// every concurrent request conflicts into the DO UPDATE arm, whose
    /// `WHERE password_resets.created_at <= $5` predicate (evaluated against the
    /// EXISTING row) fails while inside the cooldown window, yielding no updated
    /// row and thus `Ok(false)` with the old token preserved. Outside the
    /// window the predicate passes, the row is overwritten (one live token per
    /// user), and `Ok(true)` is returned.
    ///
    /// This closes the READ COMMITTED race in the prior WITH recent/cleared/
    /// INSERT CTE: because `password_resets` had no UNIQUE on `user_id`, N
    /// concurrent statements could each see `NOT EXISTS(recent)` and all INSERT
    /// distinct `token_hash` rows, minting multiple valid tokens and sending
    /// multiple emails — bypassing the cooldown. The unique constraint plus
    /// `ON CONFLICT` makes the check-and-write a single serialized operation.
    pub async fn create_password_reset(
        &self,
        token_hash: &str,
        user_id: &str,
        expires_at: &str,
        cooldown_minutes: i64,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now();
        let cutoff = (now - chrono::Duration::minutes(cooldown_minutes)).to_rfc3339();
        let row = sqlx::query(
            "INSERT INTO password_resets (token_hash, user_id, expires_at, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id) DO UPDATE
               SET token_hash = EXCLUDED.token_hash,
                   expires_at = EXCLUDED.expires_at,
                   created_at = EXCLUDED.created_at
               WHERE password_resets.created_at <= $5
             RETURNING token_hash",
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .bind(now.to_rfc3339())
        .bind(cutoff)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create password reset: {e}")))?;
        Ok(row.is_some())
    }

    /// Validate a password reset token. Returns user_id if valid and not expired.
    /// Deletes the token on success (one-time use) and logs the user out of all
    /// sessions.
    pub async fn validate_and_consume_password_reset(
        &self,
        token_hash: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "SELECT user_id FROM password_resets
             WHERE token_hash = $1 AND expires_at > $2",
        )
        .bind(token_hash)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to validate password reset: {e}")))?;

        let user_id: Option<String> = match row {
            Some(row) => Some(row.try_get::<String, _>("user_id").map_err(|e| {
                AgentSecError::Config(format!("Failed to read password reset row: {e}"))
            })?),
            None => None,
        };

        if let Some(ref id) = user_id {
            sqlx::query("DELETE FROM password_resets WHERE token_hash = $1")
                .bind(token_hash)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to consume password reset token: {e}"))
                })?;
            // Invalidate all existing sessions for the user (security: log out everywhere).
            sqlx::query("DELETE FROM admin_sessions WHERE user_id = $1")
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to invalidate sessions: {e}"))
                })?;
        }

        Ok(user_id)
    }

    /// Update a user's password. Email is globally unique, so this targets one
    /// identity (no per-team fan-out needed).
    pub async fn update_user_password(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3")
            .bind(password_hash)
            .bind(now)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to update password: {e}")))?;
        Ok(())
    }

    // -- Approver Passkeys ------------------------------------------------

    /// Save a WebAuthn passkey for an approver.
    pub async fn save_approver_passkey(
        &self,
        credential_id: &str,
        approver_name: &str,
        display_name: &str,
        public_key_json: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO approver_passkeys (credential_id, approver_name, display_name, public_key_json, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(credential_id)
        .bind(approver_name)
        .bind(display_name)
        .bind(public_key_json)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to save approver passkey: {e}")))?;
        Ok(())
    }

    /// List all approver passkeys (for loading into WebAuthnState at startup).
    pub async fn list_all_approver_passkeys(
        &self,
    ) -> Result<Vec<ApproverPasskeyRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT credential_id, approver_name, display_name, public_key_json, created_at FROM approver_passkeys ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list approver passkeys: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(ApproverPasskeyRow {
                credential_id: row.try_get::<String, _>("credential_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
                approver_name: row.try_get::<String, _>("approver_name").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
                display_name: row.try_get::<String, _>("display_name").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
                public_key_json: row.try_get::<String, _>("public_key_json").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
                created_at: row.try_get::<String, _>("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    // -- Admin Passkeys (WebAuthn 2FA for admin login) ----------------------

    /// Save a WebAuthn passkey for a user (2FA login). The `user_id` parameter
    /// is the canonical user identity id.
    pub async fn save_user_passkey(
        &self,
        user_id: &str,
        credential_id: &str,
        public_key_json: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO webauthn_credentials (credential_id, user_id, public_key_json, counter, created_at) VALUES ($1, $2, $3, 0, $4)",
        )
        .persistent(false)
        .bind(credential_id)
        .bind(user_id)
        .bind(public_key_json)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to save admin passkey: {e}")))?;
        Ok(())
    }

    /// List all passkeys for a user.
    pub async fn list_user_passkeys(
        &self,
        user_id: &str,
    ) -> Result<Vec<UserPasskeyRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT credential_id, user_id, public_key_json, created_at FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at",
        )
        .persistent(false)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list admin passkeys: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(UserPasskeyRow {
                credential_id: row.try_get::<String, _>("credential_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list admin passkeys: {e}"))
                })?,
                user_id: row.try_get::<String, _>("user_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list admin passkeys: {e}"))
                })?,
                public_key_json: row.try_get::<String, _>("public_key_json").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list admin passkeys: {e}"))
                })?,
                created_at: row.try_get::<String, _>("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list admin passkeys: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    /// Delete a user passkey by credential_id (only if the user owns it).
    pub async fn delete_user_passkey(
        &self,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool, AgentSecError> {
        let result = sqlx::query(
            "DELETE FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2",
        )
        .bind(credential_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to delete admin passkey: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    /// Count passkeys for a user (used to prevent deleting the last one).
    pub async fn count_user_passkeys(&self, user_id: &str) -> Result<i64, AgentSecError> {
        let row =
            sqlx::query("SELECT COUNT(*) AS cnt FROM webauthn_credentials WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to count admin passkeys: {e}"))
                })?;
        match row {
            Some(row) => row
                .try_get::<i64, _>("cnt")
                .map_err(|e| AgentSecError::Config(format!("Failed to count admin passkeys: {e}"))),
            None => Ok(0),
        }
    }

    /// List all user passkeys across all users (for loading at startup).
    pub async fn list_all_user_passkeys(&self) -> Result<Vec<UserPasskeyRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT credential_id, user_id, public_key_json, created_at FROM webauthn_credentials ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list all admin passkeys: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(UserPasskeyRow {
                credential_id: row.try_get::<String, _>("credential_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list all admin passkeys: {e}"))
                })?,
                user_id: row.try_get::<String, _>("user_id").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list all admin passkeys: {e}"))
                })?,
                public_key_json: row.try_get::<String, _>("public_key_json").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list all admin passkeys: {e}"))
                })?,
                created_at: row.try_get::<String, _>("created_at").map_err(|e| {
                    AgentSecError::Config(format!("Failed to list all admin passkeys: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Whitelist (managed hosting MVP)
    // -----------------------------------------------------------------------

    /// Add an email to the whitelist (or update its tier if already present).
    pub async fn add_to_whitelist(&self, email: &str, tier: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO whitelist (email, tier, created_at) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET tier = EXCLUDED.tier, created_at = EXCLUDED.created_at",
        )
        .bind(email)
        .bind(tier)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to add to whitelist: {e}")))?;
        Ok(())
    }

    /// Remove an email from the whitelist.
    pub async fn remove_from_whitelist(&self, email: &str) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM whitelist WHERE email = $1")
            .bind(email)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to remove from whitelist: {e}")))?;
        Ok(())
    }

    /// Look up a whitelisted email. Returns `Some((email, tier))` if found.
    pub async fn get_whitelist_entry(
        &self,
        email: &str,
    ) -> Result<Option<(String, String)>, AgentSecError> {
        let row = sqlx::query("SELECT email, tier FROM whitelist WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to query whitelist: {e}")))?;
        match row {
            Some(row) => Ok(Some((
                row.try_get::<String, _>("email").map_err(|e| {
                    AgentSecError::Config(format!("Failed to query whitelist: {e}"))
                })?,
                row.try_get::<String, _>("tier").map_err(|e| {
                    AgentSecError::Config(format!("Failed to query whitelist: {e}"))
                })?,
            ))),
            None => Ok(None),
        }
    }

    /// List all whitelisted emails (newest first).
    pub async fn list_whitelist(&self) -> Result<Vec<(String, String)>, AgentSecError> {
        let rows = sqlx::query("SELECT email, tier FROM whitelist ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list whitelist: {e}")))?;
        let mut results = Vec::new();
        for row in rows {
            results.push((
                row.try_get::<String, _>("email")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list whitelist: {e}")))?,
                row.try_get::<String, _>("tier")
                    .map_err(|e| AgentSecError::Config(format!("Failed to list whitelist: {e}")))?,
            ));
        }
        Ok(results)
    }

    // -- Audit log ------------------------------------------------------------

    pub async fn write_audit_entry(
        &self,
        entry: &crate::types::AuditEntry,
    ) -> Result<(), AgentSecError> {
        let cred_names_json = serde_json::to_string(&entry.credential_names).map_err(|e| {
            AgentSecError::Config(format!("Failed to serialize credential_names: {e}"))
        })?;
        let method_str = serde_json::to_string(&entry.method)
            .map_err(|e| AgentSecError::Config(format!("Failed to serialize method: {e}")))?;
        // Strip quotes from serde serialized string (e.g. "\"GET\"" -> "GET")
        let method_str = method_str.trim_matches('"');
        let approval_str = entry.approval_status.as_ref().map(|s| {
            let j = serde_json::to_string(s).unwrap_or_default();
            j.trim_matches('"').to_string()
        });
        let timestamp = entry.timestamp.to_rfc3339();
        let request_headers_json = serde_json::to_string(&entry.request_headers).map_err(|e| {
            AgentSecError::Config(format!("Failed to serialize request_headers: {e}"))
        })?;

        sqlx::query(
            "INSERT INTO audit_log (request_id, agent_id, credential_names, target_url, method, approval_status, upstream_status, total_latency_ms, approval_latency_ms, upstream_latency_ms, response_sanitized, end_user_id, request_headers, request_body, request_body_truncated, policy_reason, require_passkey, approver_identity, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) ON CONFLICT (request_id) DO UPDATE SET agent_id = EXCLUDED.agent_id, credential_names = EXCLUDED.credential_names, target_url = EXCLUDED.target_url, method = EXCLUDED.method, approval_status = EXCLUDED.approval_status, upstream_status = EXCLUDED.upstream_status, total_latency_ms = EXCLUDED.total_latency_ms, approval_latency_ms = EXCLUDED.approval_latency_ms, upstream_latency_ms = EXCLUDED.upstream_latency_ms, response_sanitized = EXCLUDED.response_sanitized, end_user_id = EXCLUDED.end_user_id, request_headers = EXCLUDED.request_headers, request_body = EXCLUDED.request_body, request_body_truncated = EXCLUDED.request_body_truncated, policy_reason = EXCLUDED.policy_reason, require_passkey = EXCLUDED.require_passkey, approver_identity = EXCLUDED.approver_identity, timestamp = EXCLUDED.timestamp",
        )
        .bind(entry.request_id.to_string())
        .bind(entry.agent_id.clone())
        .bind(cred_names_json)
        .bind(entry.target_url.clone())
        .bind(method_str)
        .bind(approval_str)
        .bind(entry.upstream_status.map(|s| s as i64))
        .bind(entry.total_latency_ms as i64)
        .bind(entry.approval_latency_ms.map(|v| v as i64))
        .bind(entry.upstream_latency_ms.map(|v| v as i64))
        .bind(entry.response_sanitized)
        .bind(entry.end_user_id.clone())
        .bind(request_headers_json)
        .bind(entry.request_body.clone())
        .bind(entry.request_body_truncated)
        .bind(entry.policy_reason.clone())
        .bind(entry.require_passkey)
        .bind(entry.approver_identity.clone())
        .bind(timestamp)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to write audit entry: {e}")))?;
        Ok(())
    }

    pub async fn read_audit_entries(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> Result<Vec<crate::types::AuditEntry>, AgentSecError> {
        use crate::types::{ApprovalStatus, HttpMethod};
        use chrono::DateTime;
        use uuid::Uuid;

        let rows = sqlx::query(
            "SELECT request_id, agent_id, credential_names, target_url, method, approval_status, upstream_status, total_latency_ms, approval_latency_ms, upstream_latency_ms, response_sanitized, end_user_id, request_headers, request_body, request_body_truncated, policy_reason, require_passkey, approver_identity, timestamp FROM audit_log WHERE agent_id = $1 ORDER BY timestamp DESC LIMIT $2",
        )
        .bind(agent_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to read audit entries: {e}")))?;

        let mut entries = Vec::new();
        for row in rows {
            let request_id_str: String = row
                .try_get::<String, _>("request_id")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let agent_id: String = row
                .try_get::<String, _>("agent_id")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let cred_names_json: String = row
                .try_get::<String, _>("credential_names")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let target_url: String = row
                .try_get::<String, _>("target_url")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let method_str: String = row
                .try_get::<String, _>("method")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let approval_str: Option<String> = row
                .try_get::<Option<String>, _>("approval_status")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let upstream_status: Option<i64> = row
                .try_get::<Option<i64>, _>("upstream_status")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let total_latency_ms: i64 = row
                .try_get::<i64, _>("total_latency_ms")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let approval_latency_ms: Option<i64> = row
                .try_get::<Option<i64>, _>("approval_latency_ms")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let upstream_latency_ms: Option<i64> = row
                .try_get::<Option<i64>, _>("upstream_latency_ms")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let response_sanitized: bool = row
                .try_get::<bool, _>("response_sanitized")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let end_user_id: Option<String> = row
                .try_get::<Option<String>, _>("end_user_id")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let request_headers_json: Option<String> = row
                .try_get::<Option<String>, _>("request_headers")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let request_body: Option<String> = row
                .try_get::<Option<String>, _>("request_body")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let request_body_truncated: bool = row
                .try_get::<bool, _>("request_body_truncated")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let policy_reason: Option<String> =
                row.try_get::<Option<String>, _>("policy_reason")
                    .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let require_passkey: bool = row
                .try_get::<bool, _>("require_passkey")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let approver_identity: Option<String> = row
                .try_get::<Option<String>, _>("approver_identity")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let timestamp_str: String = row
                .try_get::<String, _>("timestamp")
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;

            let request_id = Uuid::parse_str(&request_id_str).unwrap_or_default();
            let credential_names: Vec<String> =
                serde_json::from_str(&cred_names_json).unwrap_or_default();
            let method = HttpMethod::parse(&method_str);
            let approval_status: Option<ApprovalStatus> =
                approval_str.and_then(|s| serde_json::from_str(&format!("\"{s}\"")).ok());
            let request_headers: Vec<(String, String)> = request_headers_json
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());

            entries.push(crate::types::AuditEntry {
                request_id,
                agent_id,
                credential_names,
                target_url,
                method,
                approval_status,
                upstream_status: upstream_status.map(|s| s as u16),
                total_latency_ms: total_latency_ms as u64,
                approval_latency_ms: approval_latency_ms.map(|v| v as u64),
                upstream_latency_ms: upstream_latency_ms.map(|v| v as u64),
                response_sanitized,
                end_user_id,
                request_headers,
                request_body,
                request_body_truncated,
                policy_reason,
                require_passkey,
                approver_identity,
                timestamp,
            });
        }
        // Reverse to chronological order (query was DESC)
        entries.reverse();
        Ok(entries)
    }

    // -- Async approvals ------------------------------------------------------

    pub async fn create_async_approval(
        &self,
        txn_id: &str,
        agent_id: &str,
        team_id: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO async_approvals (txn_id, agent_id, team_id, status, created_at, expires_at)
             VALUES ($1, $2, $3, 'pending', $4, $5)",
        )
        .bind(txn_id)
        .bind(agent_id)
        .bind(team_id)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create async approval: {e}")))?;
        Ok(())
    }

    pub async fn get_async_approval(
        &self,
        txn_id: &str,
    ) -> Result<Option<AsyncApprovalRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT txn_id, agent_id, team_id, status, created_at, expires_at,
                    response_status, response_headers_json, response_body, response_error
             FROM async_approvals WHERE txn_id = $1",
        )
        .bind(txn_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to query async approval: {e}")))?;

        match row {
            Some(row) => {
                let response_status: Option<i64> = row
                    .try_get::<Option<i64>, _>("response_status")
                    .ok()
                    .flatten();
                Ok(Some(AsyncApprovalRow {
                    txn_id: row
                        .try_get::<String, _>("txn_id")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    agent_id: row
                        .try_get::<String, _>("agent_id")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    team_id: row
                        .try_get::<String, _>("team_id")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    status: row
                        .try_get::<String, _>("status")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    created_at: row
                        .try_get::<String, _>("created_at")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    expires_at: row
                        .try_get::<String, _>("expires_at")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    response_status: response_status.map(|s| s as u16),
                    response_headers_json: row
                        .try_get::<Option<String>, _>("response_headers_json")
                        .unwrap_or(None),
                    response_body: row
                        .try_get::<Option<Vec<u8>>, _>("response_body")
                        .unwrap_or(None),
                    response_error: row
                        .try_get::<Option<String>, _>("response_error")
                        .unwrap_or(None),
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn resolve_async_approval(
        &self,
        txn_id: &str,
        status: &str,
        response_status: Option<u16>,
        response_headers_json: Option<&str>,
        response_body: Option<&[u8]>,
        response_error: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let rs: Option<i64> = response_status.map(|s| s as i64);
        sqlx::query(
            "UPDATE async_approvals
             SET status = $2, response_status = $3, response_headers_json = $4,
                 response_body = $5, response_error = $6
             WHERE txn_id = $1",
        )
        .bind(txn_id)
        .bind(status)
        .bind(rs)
        .bind(response_headers_json)
        .bind(response_body.map(|b| b.to_vec()))
        .bind(response_error)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to resolve async approval: {e}")))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Pending approval persistence (survives process restarts)
    // -----------------------------------------------------------------------

    pub async fn save_pending_approval(
        &self,
        txn_id: &str,
        details_json: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        self.save_pending_approval_with_team(txn_id, details_json, expires_at, None)
            .await
    }

    /// Persist a pending approval, recording the owning team so the dashboard
    /// inbox can list a team's requests without parsing `details_json`.
    /// `team_id` is `None` for legacy callers that only key by `txn_id`.
    pub async fn save_pending_approval_with_team(
        &self,
        txn_id: &str,
        details_json: &str,
        expires_at: &str,
        team_id: Option<&str>,
    ) -> Result<(), AgentSecError> {
        self.save_pending_approval_scoped(txn_id, details_json, expires_at, team_id, None)
            .await
    }

    /// Like `save_pending_approval_with_team`, plus `required_end_user`: when
    /// set, the row may only be *approved* by that managed end-user's own
    /// authenticated approval (the default-deny gate in `resolve_pending_approval`).
    pub async fn save_pending_approval_scoped(
        &self,
        txn_id: &str,
        details_json: &str,
        expires_at: &str,
        team_id: Option<&str>,
        required_end_user: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO pending_approvals (txn_id, details_json, status, created_at, expires_at, team_id, required_end_user)
             VALUES ($1, $2, 'pending', $3, $4, $5, $6)
             ON CONFLICT(txn_id) DO UPDATE SET details_json = excluded.details_json,
                 status = CASE
                     WHEN pending_approvals.status = 'pending' THEN 'pending'
                     ELSE pending_approvals.status
                 END,
                 resolved_by = CASE
                     WHEN pending_approvals.status = 'pending' THEN NULL
                     ELSE pending_approvals.resolved_by
                 END,
                 expires_at = excluded.expires_at,
                 team_id = COALESCE(excluded.team_id, pending_approvals.team_id),
                 required_end_user = COALESCE(excluded.required_end_user, pending_approvals.required_end_user)",
        )
        .bind(txn_id)
        .bind(details_json)
        .bind(now)
        .bind(expires_at)
        .bind(team_id)
        .bind(required_end_user)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to save pending approval: {e}")))?;
        Ok(())
    }

    /// List the team's currently-pending (unresolved, unexpired) approvals,
    /// newest first. Powers the in-dashboard approvals inbox.
    pub async fn list_pending_approvals_for_team(
        &self,
        team_id: &str,
    ) -> Result<Vec<PendingApprovalRow>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let rows = sqlx::query(
            // Exclude end-user-reserved rows: a team member's inbox must never
            // show (or be able to act on) a managed end-user's approval.
            "SELECT txn_id, details_json, created_at, expires_at
             FROM pending_approvals
             WHERE team_id = $1 AND status = 'pending' AND expires_at > $2
               AND required_end_user IS NULL
             ORDER BY created_at DESC",
        )
        .bind(team_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list pending approvals: {e}")))?;
        rows.iter()
            .map(|row| {
                Ok(PendingApprovalRow {
                    txn_id: row
                        .try_get("txn_id")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    details_json: row
                        .try_get("details_json")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    expires_at: row
                        .try_get("expires_at")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                })
            })
            .collect()
    }

    pub async fn get_pending_approval_details(
        &self,
        txn_id: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "SELECT details_json FROM pending_approvals
             WHERE txn_id = $1 AND status = 'pending' AND expires_at > $2",
        )
        .bind(txn_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to query pending approval: {e}")))?;
        match row {
            Some(row) => Ok(Some(
                row.try_get::<String, _>("details_json")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
            )),
            None => Ok(None),
        }
    }

    /// Read the persisted `min_approvals` (N-of-M threshold) for a pending
    /// approval by its txn_id. Returns `None` when no row exists. Used as a
    /// cross-instance fallback for the Telegram ⏳ grant guard: an instance
    /// that never held the in-memory pending entry must still refuse to
    /// short-circuit a multi-approval request into a single-manager grant.
    pub async fn get_pending_approval_min_approvals(
        &self,
        txn_id: &str,
    ) -> Result<Option<u32>, AgentSecError> {
        let row = sqlx::query(
            "SELECT COALESCE(min_approvals, 1) FROM pending_approvals WHERE txn_id = $1",
        )
        .bind(txn_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to query min_approvals: {e}")))?;
        match row {
            Some(row) => Ok(Some(
                row.try_get::<i64, _>(0)
                    .map_err(|e| AgentSecError::Config(format!("{e}")))? as u32,
            )),
            None => Ok(None),
        }
    }

    pub async fn get_pending_approval_status(
        &self,
        txn_id: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let row = sqlx::query("SELECT status FROM pending_approvals WHERE txn_id = $1")
            .bind(txn_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to query approval status: {e}")))?;
        match row {
            Some(row) => Ok(Some(
                row.try_get::<String, _>("status")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
            )),
            None => Ok(None),
        }
    }

    pub async fn get_pending_approval_resolved_by(
        &self,
        txn_id: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let row = sqlx::query("SELECT resolved_by FROM pending_approvals WHERE txn_id = $1")
            .bind(txn_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to query approval resolver: {e}"))
            })?;
        match row {
            Some(row) => row
                .try_get::<Option<String>, _>("resolved_by")
                .map_err(|e| AgentSecError::Config(format!("{e}"))),
            None => Ok(None),
        }
    }

    pub async fn resolve_pending_approval(
        &self,
        txn_id: &str,
        status: &str,
        resolved_by: Option<&str>,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(20)).to_rfc3339();
        // Default-deny gate (TAP for Platforms): the team/messaging/dashboard
        // resolution path may NOT *approve* a row reserved for a managed
        // end-user (`required_end_user IS NOT NULL`) — only the end-user's own
        // authenticated approval (`resolve_pending_approval_as_end_user`) can.
        // Denials are always allowed (fail-closed is safe). This is enforced in
        // the single atomic UPDATE, so any current or future caller of this
        // method is auto-rejected for end-user rows without a per-channel block.
        let result = sqlx::query(
            "INSERT INTO pending_approvals
                 (txn_id, details_json, status, resolved_by, created_at, expires_at)
             VALUES ($1, '{}', $2, $3, $4, $5)
             ON CONFLICT(txn_id) DO UPDATE SET
                 status = excluded.status,
                 resolved_by = COALESCE(excluded.resolved_by, pending_approvals.resolved_by)
             WHERE (pending_approvals.status = 'pending'
                    OR pending_approvals.status = excluded.status)
               AND (excluded.status <> 'approved'
                    OR pending_approvals.required_end_user IS NULL)",
        )
        .bind(txn_id)
        .bind(status)
        .bind(resolved_by)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to resolve pending approval: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    /// Exclusive pending→approved claim for the grant-from-approval surfaces
    /// (#49). `resolve_pending_approval` deliberately treats a re-resolution to
    /// the same status as success (duplicate callback delivery must be safe),
    /// but a grant decision must fire at most once: this matches ONLY the
    /// actual pending→approved transition, so two concurrent "approve with
    /// grant" actions can never both return true and mint two windows.
    /// UPDATE-only — the grant path has already read the pending row, so no
    /// phantom insert. End-user-reserved rows (`required_end_user IS NOT
    /// NULL`) never match: they can't be approved by team surfaces at all,
    /// let alone time-boxed.
    pub async fn claim_pending_approval_for_grant(
        &self,
        txn_id: &str,
        resolved_by: Option<&str>,
    ) -> Result<bool, AgentSecError> {
        let result = sqlx::query(
            "UPDATE pending_approvals SET
                 status = 'approved',
                 resolved_by = COALESCE($2, resolved_by)
             WHERE txn_id = $1
               AND status = 'pending'
               AND required_end_user IS NULL",
        )
        .bind(txn_id)
        .bind(resolved_by)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to claim pending approval for grant: {e}"))
        })?;
        Ok(result.rows_affected() > 0)
    }

    /// Resolve an approval reserved for a managed end-user. Identity-based, not
    /// method-based: any channel that can authenticate the end-user (the passkey
    /// ceremony today; Telegram/Matrix/email linkage later) calls this with the
    /// end-user's `ext_id`. Approves only the row whose `required_end_user`
    /// matches. UPDATE-only (the row always exists by the time the end-user
    /// acts), so it can never fabricate a phantom approved row.
    pub async fn resolve_pending_approval_as_end_user(
        &self,
        txn_id: &str,
        status: &str,
        ext_id: &str,
        resolved_by: Option<&str>,
    ) -> Result<bool, AgentSecError> {
        let result = sqlx::query(
            "UPDATE pending_approvals SET
                 status = $2,
                 resolved_by = COALESCE($3, resolved_by)
             WHERE txn_id = $1
               AND status = 'pending'
               AND required_end_user = $4",
        )
        .bind(txn_id)
        .bind(status)
        .bind(resolved_by)
        .bind(ext_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to resolve end-user approval: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    // -- Staged end-user policy changes (passkey-lock / R2) -------------------

    pub async fn create_pending_policy_change(
        &self,
        txn_id: &str,
        team_id: &str,
        credential_name: &str,
        required_end_user: &str,
        proposed_policy_json: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO pending_policy_changes
                 (txn_id, team_id, credential_name, required_end_user, proposed_policy_json, status, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)",
        )
        .bind(txn_id)
        .bind(team_id)
        .bind(credential_name)
        .bind(required_end_user)
        .bind(proposed_policy_json)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to stage policy change: {e}")))?;
        Ok(())
    }

    pub async fn get_pending_policy_change(
        &self,
        txn_id: &str,
    ) -> Result<Option<PendingPolicyChangeRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT txn_id, team_id, credential_name, required_end_user, proposed_policy_json, status
             FROM pending_policy_changes WHERE txn_id = $1",
        )
        .bind(txn_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to get policy change: {e}")))?;
        match row {
            Some(r) => Ok(Some(PendingPolicyChangeRow {
                txn_id: r
                    .try_get("txn_id")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                team_id: r
                    .try_get("team_id")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                credential_name: r
                    .try_get("credential_name")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                required_end_user: r
                    .try_get("required_end_user")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                proposed_policy_json: r
                    .try_get("proposed_policy_json")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                status: r
                    .try_get("status")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
            })),
            None => Ok(None),
        }
    }

    /// Atomically claim a staged policy change for application: marks it
    /// `applied` only if still pending, unexpired, and owned by `ext_id`.
    /// Single-use, so a replayed passkey-finish can't apply twice.
    pub async fn claim_pending_policy_change(
        &self,
        txn_id: &str,
        ext_id: &str,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE pending_policy_changes SET status = 'applied'
             WHERE txn_id = $1 AND status = 'pending'
               AND required_end_user = $2 AND expires_at > $3",
        )
        .bind(txn_id)
        .bind(ext_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to claim policy change: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_pending_approval(&self, txn_id: &str) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM pending_approvals WHERE txn_id = $1")
            .bind(txn_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to delete pending approval: {e}"))
            })?;
        Ok(())
    }

    // --- Agent-originated proposals -------------------------------------------

    /// Persist a new pending proposal.
    pub async fn create_proposal(&self, p: &ProposalRow) -> Result<(), AgentSecError> {
        sqlx::query(
            "INSERT INTO proposals
                 (id, team_id, agent_id, proposal_type, payload_json, status, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)",
        )
        .bind(&p.id)
        .bind(&p.team_id)
        .bind(&p.agent_id)
        .bind(&p.proposal_type)
        .bind(&p.payload_json)
        .bind(&p.created_at)
        .bind(&p.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to create proposal: {e}")))?;
        Ok(())
    }

    /// Fetch a proposal scoped to its team (cross-team lookups return None).
    pub async fn get_proposal(
        &self,
        team_id: &str,
        id: &str,
    ) -> Result<Option<ProposalRow>, AgentSecError> {
        let row = sqlx::query(
            "SELECT id, team_id, agent_id, proposal_type, payload_json, status,
                    resolved_by, resolved_at, created_at, expires_at
             FROM proposals WHERE id = $1 AND team_id = $2",
        )
        .bind(id)
        .bind(team_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to query proposal: {e}")))?;
        row.map(row_to_proposal).transpose()
    }

    /// List a team's proposals, optionally filtered by status, newest first.
    /// When `status == Some("pending")`, expired rows are excluded.
    pub async fn list_proposals_for_team(
        &self,
        team_id: &str,
        status: Option<&str>,
    ) -> Result<Vec<ProposalRow>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let rows = sqlx::query(
            "SELECT id, team_id, agent_id, proposal_type, payload_json, status,
                    resolved_by, resolved_at, created_at, expires_at
             FROM proposals
             WHERE team_id = $1
               AND ($2::text IS NULL OR status = $2)
               AND ($2 IS DISTINCT FROM 'pending' OR expires_at > $3)
             ORDER BY created_at DESC",
        )
        .bind(team_id)
        .bind(status)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list proposals: {e}")))?;
        rows.into_iter().map(row_to_proposal).collect()
    }

    /// Count an agent's currently-pending (unexpired) proposals. Used to cap
    /// inbox flooding.
    pub async fn count_pending_proposals_for_agent(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<i64, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM proposals
             WHERE team_id = $1 AND agent_id = $2 AND status = 'pending' AND expires_at > $3",
        )
        .bind(team_id)
        .bind(agent_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to count proposals: {e}")))?;
        row.try_get::<i64, _>("n")
            .map_err(|e| AgentSecError::Config(format!("{e}")))
    }

    /// Atomically claim and resolve a pending proposal. Returns `true` only if
    /// THIS call transitioned it (single DB claim: still pending AND unexpired).
    /// `false` ⇒ missing / wrong team / already resolved / expired — so a
    /// double-submit or a resolve on another instance is a safe no-op.
    pub async fn resolve_proposal(
        &self,
        team_id: &str,
        id: &str,
        status: &str,
        resolved_by: &str,
    ) -> Result<bool, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE proposals
                SET status = $3, resolved_by = $4, resolved_at = $5
              WHERE id = $1 AND team_id = $2 AND status = 'pending' AND expires_at > $5",
        )
        .bind(id)
        .bind(team_id)
        .bind(status)
        .bind(resolved_by)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to resolve proposal: {e}")))?;
        Ok(result.rows_affected() > 0)
    }

    /// Purge expired rows from `pending_approvals` and `async_approvals`.
    ///
    /// `pending_approvals` rows that are past their `expires_at` AND no longer
    /// `pending` (i.e. already resolved or timed out) have no further use — the
    /// decision was made and the agent received it. We keep rows that are still
    /// `pending` even if past expiry so the next `wait_for_decision` tick can
    /// atomically mark them `expired` before they disappear.
    ///
    /// `async_approvals` store upstream response bodies (potentially sensitive
    /// content such as AI-generated text). Once past expiry the agent has had
    /// ample time to poll; purge unconditionally.
    ///
    /// Safe to call concurrently — both DELETEs are independent and idempotent.
    pub async fn cleanup_expired_rows(&self) -> Result<(u64, u64), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();

        let pending = sqlx::query(
            "DELETE FROM pending_approvals WHERE expires_at < $1 AND status != 'pending'",
        )
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("cleanup pending_approvals: {e}")))?
        .rows_affected();

        let async_rows = sqlx::query("DELETE FROM async_approvals WHERE expires_at < $1")
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(|e| AgentSecError::Config(format!("cleanup async_approvals: {e}")))?
            .rows_affected();

        Ok((pending, async_rows))
    }

    /// Upsert a Web Push subscription. Re-subscribing the same endpoint refreshes
    /// the keys and re-points it at the current team/user (endpoints are stable
    /// per browser-profile but their owner can change on re-login).
    pub async fn save_push_subscription(
        &self,
        endpoint: &str,
        team_id: &str,
        user_email: &str,
        p256dh: &str,
        auth: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO push_subscriptions (endpoint, team_id, user_email, p256dh, auth, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT(endpoint) DO UPDATE SET
                 team_id = excluded.team_id,
                 user_email = excluded.user_email,
                 p256dh = excluded.p256dh,
                 auth = excluded.auth",
        )
        .bind(endpoint)
        .bind(team_id)
        .bind(user_email)
        .bind(p256dh)
        .bind(auth)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to save push subscription: {e}")))?;
        Ok(())
    }

    /// List all Web Push subscriptions for a team (every member's devices).
    pub async fn list_push_subscriptions_for_team(
        &self,
        team_id: &str,
    ) -> Result<Vec<PushSubscriptionRow>, AgentSecError> {
        let rows = sqlx::query(
            "SELECT endpoint, team_id, user_email, p256dh, auth, created_at
             FROM push_subscriptions WHERE team_id = $1",
        )
        .bind(team_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to list push subscriptions: {e}")))?;
        rows.iter()
            .map(|row| {
                Ok(PushSubscriptionRow {
                    endpoint: row
                        .try_get("endpoint")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    team_id: row
                        .try_get("team_id")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    user_email: row
                        .try_get("user_email")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    p256dh: row
                        .try_get("p256dh")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    auth: row
                        .try_get("auth")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    created_at: row
                        .try_get("created_at")
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                })
            })
            .collect()
    }

    /// Remove a Web Push subscription by endpoint. Called on explicit unsubscribe
    /// and when a push service reports the subscription is gone (404/410).
    pub async fn delete_push_subscription(&self, endpoint: &str) -> Result<(), AgentSecError> {
        sqlx::query("DELETE FROM push_subscriptions WHERE endpoint = $1")
            .bind(endpoint)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to delete push subscription: {e}"))
            })?;
        Ok(())
    }

    pub async fn set_pending_approval_challenge(
        &self,
        txn_id: &str,
        challenge_json: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(20)).to_rfc3339();
        sqlx::query(
            "INSERT INTO pending_approvals
                 (txn_id, details_json, status, created_at, expires_at, approval_challenge_json)
             VALUES ($1, '{}', 'pending', $3, $4, $2)
             ON CONFLICT(txn_id) DO UPDATE SET
                 approval_challenge_json = excluded.approval_challenge_json,
                 expires_at = excluded.expires_at
             WHERE pending_approvals.status = 'pending'",
        )
        .bind(txn_id)
        .bind(challenge_json)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to save approval challenge: {e}")))?;
        Ok(())
    }

    pub async fn take_pending_approval_challenge(
        &self,
        txn_id: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "WITH challenge AS (
                 SELECT approval_challenge_json
                 FROM pending_approvals
                 WHERE txn_id = $1
                   AND status = 'pending'
                   AND expires_at > $2
                   AND approval_challenge_json IS NOT NULL
                 FOR UPDATE
             ),
             consumed AS (
                 UPDATE pending_approvals
                 SET approval_challenge_json = NULL
                 WHERE txn_id = $1
                   AND EXISTS (SELECT 1 FROM challenge)
             )
             SELECT approval_challenge_json FROM challenge",
        )
        .bind(txn_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to take approval challenge: {e}")))?;

        match row {
            Some(row) => Ok(Some(
                row.try_get::<String, _>("approval_challenge_json")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
            )),
            None => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // WebAuthn login challenge persistence (cross-instance, single-use)
    // -----------------------------------------------------------------------

    /// Persist an in-flight login challenge keyed by `passkey_token` so that the
    /// `finish` request can be served by a different proxy instance than `begin`.
    pub async fn set_login_challenge(
        &self,
        passkey_token: &str,
        user_id: &str,
        challenge_json: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        sqlx::query(
            "INSERT INTO user_login_challenges
                 (passkey_token, user_id, challenge_json, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(passkey_token) DO UPDATE SET
                 user_id = excluded.user_id,
                 challenge_json = excluded.challenge_json,
                 expires_at = excluded.expires_at",
        )
        .persistent(false)
        .bind(passkey_token)
        .bind(user_id)
        .bind(challenge_json)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to save login challenge: {e}")))?;
        Ok(())
    }

    /// Atomically claim a login challenge: deletes the row and returns
    /// `(user_id, challenge_json)`. Single-use — a second concurrent or repeated
    /// claim gets `None`. Expired rows are treated as absent.
    pub async fn take_login_challenge(
        &self,
        passkey_token: &str,
    ) -> Result<Option<(String, String)>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "DELETE FROM user_login_challenges
             WHERE passkey_token = $1 AND expires_at > $2
             RETURNING user_id, challenge_json",
        )
        .persistent(false)
        .bind(passkey_token)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to take login challenge: {e}")))?;

        match row {
            Some(row) => {
                let user_id = row
                    .try_get::<String, _>("user_id")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?;
                let challenge_json = row
                    .try_get::<String, _>("challenge_json")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?;
                Ok(Some((user_id, challenge_json)))
            }
            None => Ok(None),
        }
    }

    /// Persist an in-flight registration challenge keyed by `user_id`.
    pub async fn set_registration_challenge(
        &self,
        user_id: &str,
        challenge_json: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        sqlx::query(
            "INSERT INTO user_registration_challenges
                 (user_id, challenge_json, created_at, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(user_id) DO UPDATE SET
                 challenge_json = excluded.challenge_json,
                 expires_at = excluded.expires_at",
        )
        .persistent(false)
        .bind(user_id)
        .bind(challenge_json)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to save registration challenge: {e}"))
        })?;
        Ok(())
    }

    /// Atomically claim a registration challenge: deletes the row and returns
    /// `challenge_json`. Single-use; expired rows are treated as absent.
    pub async fn take_registration_challenge(
        &self,
        user_id: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "DELETE FROM user_registration_challenges
             WHERE user_id = $1 AND expires_at > $2
             RETURNING challenge_json",
        )
        .persistent(false)
        .bind(user_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to take registration challenge: {e}"))
        })?;

        match row {
            Some(row) => Ok(Some(
                row.try_get::<String, _>("challenge_json")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist an in-flight approver/end-user passkey registration challenge,
    /// keyed by the free-form `approver_name`. Single in-flight per name; a new
    /// begin overwrites the prior one. Durable so begin/finish can span
    /// instances (TAP for Platforms headless passkey ceremony).
    pub async fn set_approver_registration_challenge(
        &self,
        approver_name: &str,
        challenge_json: &str,
        display_name: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        sqlx::query(
            "INSERT INTO approver_registration_challenges
                 (approver_name, challenge_json, display_name, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(approver_name) DO UPDATE SET
                 challenge_json = excluded.challenge_json,
                 display_name = excluded.display_name,
                 expires_at = excluded.expires_at",
        )
        .persistent(false)
        .bind(approver_name)
        .bind(challenge_json)
        .bind(display_name)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!(
                "Failed to save approver registration challenge: {e}"
            ))
        })?;
        Ok(())
    }

    /// Atomically claim an approver registration challenge: deletes the row and
    /// returns `(challenge_json, display_name)`. Single-use; expired ⇒ absent.
    pub async fn take_approver_registration_challenge(
        &self,
        approver_name: &str,
    ) -> Result<Option<(String, String)>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let row = sqlx::query(
            "DELETE FROM approver_registration_challenges
             WHERE approver_name = $1 AND expires_at > $2
             RETURNING challenge_json, display_name",
        )
        .persistent(false)
        .bind(approver_name)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!(
                "Failed to take approver registration challenge: {e}"
            ))
        })?;

        match row {
            Some(row) => Ok(Some((
                row.try_get::<String, _>("challenge_json")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                row.try_get::<String, _>("display_name")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?,
            ))),
            None => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // Telegram channel persistence
    // -----------------------------------------------------------------------

    /// Persist the Telegram chat/message IDs for an in-flight approval request.
    /// Called after sendMessage so callbacks handled by another process can
    /// still update the original approval notification.
    pub async fn set_pending_approval_telegram_message(
        &self,
        txn_id: &str,
        chat_id: &str,
        message_id: i64,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(20)).to_rfc3339();
        sqlx::query(
            "INSERT INTO pending_approvals
                 (txn_id, details_json, status, created_at, expires_at,
                  telegram_chat_id, telegram_message_id)
             VALUES ($1, '{}', 'pending', $4, $5, $2, $3)
             ON CONFLICT(txn_id) DO UPDATE SET
                 telegram_chat_id = excluded.telegram_chat_id,
                 telegram_message_id = excluded.telegram_message_id",
        )
        .bind(txn_id)
        .bind(chat_id)
        .bind(message_id)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!("Failed to set Telegram approval message: {e}"))
        })?;
        Ok(())
    }

    /// Return `(chat_id, message_id)` for a Telegram approval if the row exists.
    pub async fn get_pending_approval_telegram_message(
        &self,
        txn_id: &str,
    ) -> Result<Option<(String, i64)>, AgentSecError> {
        let row = sqlx::query(
            "SELECT telegram_chat_id, telegram_message_id
             FROM pending_approvals
             WHERE txn_id = $1",
        )
        .bind(txn_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to query Telegram message: {e}")))?;

        match row {
            Some(row) => {
                let chat_id: Option<String> = row
                    .try_get("telegram_chat_id")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?;
                let message_id: Option<i64> = row
                    .try_get("telegram_message_id")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?;
                match (chat_id, message_id) {
                    (Some(c), Some(m)) if !c.is_empty() => Ok(Some((c, m))),
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // Matrix channel persistence
    // -----------------------------------------------------------------------

    /// Persist the Matrix event/room IDs, allowed approvers, and N-of-M
    /// settings for an in-flight approval request. Called after the Matrix
    /// message is posted so that reactions survive a proxy restart.
    pub async fn set_pending_approval_matrix_data(
        &self,
        txn_id: &str,
        room_id: &str,
        event_id: &str,
        allowed_approvers_json: &str,
        min_approvals: usize,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(20)).to_rfc3339();
        sqlx::query(
            "INSERT INTO pending_approvals
                 (txn_id, details_json, status, created_at, expires_at,
                  matrix_room_id, matrix_event_id, allowed_approvers_json, min_approvals)
             VALUES ($1, '{}', 'pending', $6, $7, $2, $3, $4, $5)
             ON CONFLICT(txn_id) DO UPDATE SET
                 matrix_room_id = excluded.matrix_room_id,
                 matrix_event_id = excluded.matrix_event_id,
                 allowed_approvers_json = excluded.allowed_approvers_json,
                 min_approvals = excluded.min_approvals",
        )
        .bind(txn_id)
        .bind(room_id)
        .bind(event_id)
        .bind(allowed_approvers_json)
        .bind(min_approvals as i64)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to set Matrix approval data: {e}")))?;
        Ok(())
    }

    /// Look up a pending approval row by Matrix event_id.
    /// Returns `None` if no row exists with that event_id or it is not pending.
    pub async fn get_pending_approval_by_matrix_event(
        &self,
        event_id: &str,
    ) -> Result<Option<MatrixApprovalData>, AgentSecError> {
        let row = sqlx::query(
            "SELECT txn_id, matrix_room_id, matrix_event_id,
                    COALESCE(allowed_approvers_json, '[]'),
                    COALESCE(approval_count, 0),
                    COALESCE(min_approvals, 1),
                    status
             FROM pending_approvals
             WHERE matrix_event_id = $1",
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            AgentSecError::Config(format!(
                "Failed to query pending approval by matrix event: {e}"
            ))
        })?;

        match row {
            Some(row) => {
                let room_id: Option<String> = row
                    .try_get(1)
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?;
                let ev_id: Option<String> = row
                    .try_get(2)
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?;
                Ok(Some(MatrixApprovalData {
                    txn_id: row
                        .try_get(0)
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    room_id: room_id.unwrap_or_default(),
                    event_id: ev_id.unwrap_or_default(),
                    allowed_approvers_json: row
                        .try_get(3)
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                    approval_count: row
                        .try_get::<i64, _>(4)
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?
                        as usize,
                    min_approvals: row
                        .try_get::<i64, _>(5)
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?
                        as usize,
                    status: row
                        .try_get(6)
                        .map_err(|e| AgentSecError::Config(format!("{e}")))?,
                }))
            }
            None => Ok(None),
        }
    }

    /// Atomically increment the approval_count for a pending approval and
    /// return `(new_count, min_approvals)`.
    pub async fn increment_pending_approval_count(
        &self,
        txn_id: &str,
    ) -> Result<(usize, usize), AgentSecError> {
        sqlx::query(
            "UPDATE pending_approvals
             SET approval_count = COALESCE(approval_count, 0) + 1
             WHERE txn_id = $1",
        )
        .bind(txn_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to increment approval count: {e}")))?;

        let row = sqlx::query(
            "SELECT COALESCE(approval_count, 0), COALESCE(min_approvals, 1)
             FROM pending_approvals WHERE txn_id = $1",
        )
        .bind(txn_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to read approval count: {e}")))?;

        match row {
            Some(row) => {
                let count = row
                    .try_get::<i64, _>(0)
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?
                    as usize;
                let min = row
                    .try_get::<i64, _>(1)
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?
                    as usize;
                Ok((count, min))
            }
            None => Err(AgentSecError::Config(format!(
                "No pending approval row found for txn_id={txn_id}"
            ))),
        }
    }

    /// Return `(room_id, event_id)` for a pending Matrix approval if the row
    /// exists and its status is still 'pending'. Returns `None` otherwise.
    pub async fn get_pending_approval_matrix_message(
        &self,
        txn_id: &str,
    ) -> Result<Option<(String, String)>, AgentSecError> {
        let row = sqlx::query(
            "SELECT matrix_room_id, matrix_event_id
             FROM pending_approvals
             WHERE txn_id = $1 AND status = 'pending'",
        )
        .bind(txn_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentSecError::Config(format!("Failed to query Matrix message: {e}")))?;

        match row {
            Some(row) => {
                let room_id: Option<String> = row
                    .try_get("matrix_room_id")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?;
                let event_id: Option<String> = row
                    .try_get("matrix_event_id")
                    .map_err(|e| AgentSecError::Config(format!("{e}")))?;
                match (room_id, event_id) {
                    (Some(r), Some(e)) if !r.is_empty() && !e.is_empty() => Ok(Some((r, e))),
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Test support
// ---------------------------------------------------------------------------

/// Test-only helpers, available to this crate's tests and to downstream crates
/// that enable the `test-support` feature (the proxy's integration/e2e suites).
#[cfg(any(test, feature = "test-support"))]
impl ConfigStore {
    /// Create a `ConfigStore` isolated in its own freshly-created Postgres
    /// **schema**, so tests are isolated and can run in parallel without
    /// colliding on a shared `public` schema (and without the disk cost of
    /// cloning a database per test).
    ///
    /// Returns the store and a connection URL whose `search_path` points at the
    /// new schema. The URL lets a second `ConfigStore` join the *same* schema to
    /// exercise cross-instance flows (begin on instance A, resolve on B).
    ///
    /// The throwaway schema is left in place (schemas are cheap). To clear
    /// leftovers locally: `DROP SCHEMA` each `test_*` schema, e.g.
    ///   `psql -tAc "SELECT 'DROP SCHEMA \"'||nspname||'\" CASCADE;' FROM pg_namespace WHERE nspname LIKE 'test\_%'" | psql`
    pub async fn new_isolated_test(encryption_key: [u8; 32]) -> (ConfigStore, String) {
        use sqlx::Connection as _;

        // Tests forward to 127.0.0.1 mock upstreams, so opt out of the
        // production SSRF guard (which blocks loopback/internal targets).
        // Safe on edition 2021; every test suite funnels through this helper.
        std::env::set_var("DANGEROUS_TAP_ALLOW_PRIVATE_TARGETS", "1");

        let base = std::env::var("POSTGRES_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://tap:tap@localhost:5434/tap".to_string());
        // Embed a creation timestamp so leftover schemas (from crashed/aborted
        // runs) can be pruned by age. Format: `test_{created_ms}_{uuid}`.
        let created_ms = chrono::Utc::now().timestamp_millis();
        let schema = format!("test_{}_{}", created_ms, uuid::Uuid::new_v4().simple());

        // Single connection (not a pool) for the DDL statements.
        let mut admin = sqlx::PgConnection::connect(&base)
            .await
            .expect("connect to base database to create test schema");

        // Best-effort GC of stale test schemas from prior runs so they don't
        // accumulate and fill the disk (a single run leaks one schema; left
        // unchecked this reached thousands and exhausted the DB volume). Only
        // schemas older than the cutoff are dropped, so concurrent in-flight
        // test schemas (parallel suites) are never touched; each DROP is its own
        // statement with errors ignored, so a race with another pruner is safe.
        //
        // `ORDER BY schema_name` is LOAD-BEARING, not cosmetic. The name is
        // `test_{unix_ms}_{uuid}` with a fixed-width millisecond field, so
        // lexicographic order == chronological order and the LIMIT samples the
        // OLDEST schemas — the only ones that can be stale. Without it the LIMIT
        // took an arbitrary slice, the age filter below (which runs in Rust,
        // i.e. AFTER the LIMIT) matched nothing, and GC quietly did nothing
        // precisely when a backlog had built up. That is how ~2000 schemas
        // accumulated and filled the disk, which then surfaced as ~160 unrelated
        // tests "failing" with `No space left on device`.
        //
        // The limit is deliberately SMALL: this runs on every single test, and a
        // DROP SCHEMA CASCADE costs ~100-200ms. Dropping the steady-state cost
        // to ~0 matters more than draining fast — with no backlog the oldest
        // rows are recent, fail the age check, and nothing is dropped. With a
        // backlog every test retires a few, so a suite of N tests clears ~N*8.
        const STALE_SCHEMA_AGE_MS: i64 = 2 * 60 * 60 * 1000; // 2h
        const GC_BATCH: i32 = 8;
        if let Ok(names) = sqlx::query_scalar::<_, String>(
            "SELECT schema_name FROM information_schema.schemata \
             WHERE schema_name LIKE 'test\\_%' ORDER BY schema_name ASC LIMIT $1",
        )
        .bind(GC_BATCH)
        .fetch_all(&mut admin)
        .await
        {
            for name in names {
                // Parse the embedded millis (`test_{ms}_…`). A name without a
                // parseable timestamp is a legacy leftover — no current code path
                // creates that format, so it can only be stale and is safe to drop.
                let stale = match name
                    .strip_prefix("test_")
                    .and_then(|rest| rest.split('_').next())
                    .and_then(|ms| ms.parse::<i64>().ok())
                {
                    Some(created) => created_ms - created > STALE_SCHEMA_AGE_MS,
                    None => true,
                };
                if stale {
                    let _ = sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS \"{name}\" CASCADE"))
                        .execute(&mut admin)
                        .await;
                }
            }
        }

        sqlx::raw_sql(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&mut admin)
            .await
            .expect("CREATE SCHEMA for isolated test store");
        admin.close().await.expect("close admin connection");

        let url = with_search_path(&base, &schema);
        let store = ConfigStore::new(&url, encryption_key)
            .await
            .expect("ConfigStore::new on isolated test schema");
        (store, url)
    }
}

/// Append a `search_path` connection option to a Postgres URL so every
/// connection from the pool operates inside the given schema. Postgres reads
/// the libpq-style `options` startup parameter (sqlx forwards it).
#[cfg(any(test, feature = "test-support"))]
fn with_search_path(base: &str, schema: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    // `-c search_path=<schema>`, URL-encoded (space → %20, '=' → %3D).
    format!("{base}{sep}options=-c%20search_path%3D{schema}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    fn normalize_rewrites_supabase_transaction_pooler_to_session_pooler() {
        let input = "postgresql://postgres.wspwllkjkgihnrfhpcot:s3cr3t@aws-1-us-east-1.pooler.supabase.com:6543/postgres?sslmode=require";
        let expected = "postgresql://postgres.wspwllkjkgihnrfhpcot:s3cr3t@aws-1-us-east-1.pooler.supabase.com:5432/postgres?sslmode=require";
        assert_eq!(normalize_supabase_pooler_url(input), expected);
    }

    #[test]
    fn normalize_rewrites_when_query_immediately_follows_port() {
        // No '/path' between the port and the query — the deploy-time string
        // rewrite (which keys on ":6543/") would MISS this; we must not.
        let input = "postgres://u:p@db.pooler.supabase.com:6543?sslmode=require";
        let expected = "postgres://u:p@db.pooler.supabase.com:5432?sslmode=require";
        assert_eq!(normalize_supabase_pooler_url(input), expected);
    }

    #[test]
    fn normalize_leaves_session_pooler_untouched() {
        let input =
            "postgresql://u:p@aws-1-us-east-1.pooler.supabase.com:5432/postgres?sslmode=require";
        assert_eq!(normalize_supabase_pooler_url(input), input);
    }

    #[test]
    fn normalize_leaves_non_supabase_host_untouched() {
        // Some other host on :6543 is not the Supabase pooler — don't touch it.
        let input = "postgres://u:p@localhost:6543/tap";
        assert_eq!(normalize_supabase_pooler_url(input), input);
    }

    #[test]
    fn normalize_does_not_rewrite_6543_inside_password() {
        // ":6543" appears in the password but the host:port is the session pooler.
        let input =
            "postgresql://user:p6543:6543word@aws-1-us-east-1.pooler.supabase.com:5432/postgres";
        assert_eq!(normalize_supabase_pooler_url(input), input);
    }

    #[test]
    fn normalize_passes_through_malformed_or_sqlite_url() {
        assert_eq!(
            normalize_supabase_pooler_url("sqlite://./tap.db"),
            "sqlite://./tap.db"
        );
        assert_eq!(normalize_supabase_pooler_url("not a url"), "not a url");
    }

    async fn test_store() -> ConfigStore {
        // Each test gets its own freshly-created database, so tests are isolated
        // and can run in parallel (and never collide with another process using
        // the same Postgres).
        ConfigStore::new_isolated_test(test_key()).await.0
    }

    #[tokio::test]
    async fn ensure_team_is_idempotent_and_creates_usable_team() {
        // The CLI bootstraps self-hosted deployments with ensure_team("default")
        // — it must succeed on a fresh DB, be repeat-safe, and never clobber an
        // existing team's name.
        let store = test_store().await;
        store.ensure_team("default", "default").await.unwrap();
        store.ensure_team("default", "default").await.unwrap();
        let team = store.get_team("default").await.unwrap().unwrap();
        assert_eq!(team.name, "default");

        // A CLI-style credential + agent create against the ensured team works.
        store
            .create_credential(
                "default",
                "openai",
                "OpenAI",
                "direct",
                Some("https://api.openai.com"),
                false,
                None,
                None,
                Some(b"sk-test"),
            )
            .await
            .unwrap();
        store
            .create_agent(
                "default",
                "my-agent",
                None,
                &crate::auth::hash_api_key("some-key"),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oauth_state_create_take_is_single_use_and_tracks_expiry() {
        let store = test_store().await;
        let future = (chrono::Utc::now() + chrono::Duration::seconds(600)).to_rfc3339();

        store
            .create_oauth_state(
                "hash-abc",
                "admin-1",
                "team-1",
                "gmail",
                "my gmail",
                "https://mail.google.com/ https://www.googleapis.com/auth/drive",
                "google",
                &[],
                &future,
            )
            .await
            .unwrap();

        // First claim returns the row intact, not expired.
        let claimed = store
            .take_oauth_state("hash-abc")
            .await
            .unwrap()
            .expect("state present");
        assert_eq!(claimed.admin_id, "admin-1");
        assert_eq!(claimed.team_id, "team-1");
        assert_eq!(claimed.credential_name, "gmail");
        assert_eq!(claimed.credential_description, "my gmail");
        assert_eq!(claimed.flow_type, "create");
        assert_eq!(claimed.provider, "google");
        assert_eq!(
            claimed.scopes,
            "https://mail.google.com/ https://www.googleapis.com/auth/drive"
        );
        assert!(claimed.expires_at > chrono::Utc::now());

        // Single-use: a replayed callback gets nothing (atomic DELETE…RETURNING).
        assert!(store.take_oauth_state("hash-abc").await.unwrap().is_none());

        // Unknown hash → None (callback reports invalid_state).
        assert!(store
            .take_oauth_state("never-existed")
            .await
            .unwrap()
            .is_none());

        // Expired rows are still returned so the caller can distinguish expired
        // from invalid (the callback reports expired_state).
        let past = (chrono::Utc::now() - chrono::Duration::seconds(10)).to_rfc3339();
        store
            .create_oauth_state("hash-exp", "admin-1", "team-1", "gmail2", "", "", "google", &[], &past)
            .await
            .unwrap();
        let expired = store
            .take_oauth_state("hash-exp")
            .await
            .unwrap()
            .expect("row returned");
        assert!(expired.expires_at < chrono::Utc::now());
    }

    // --- Proposals -----------------------------------------------------------

    fn proposal_row(id: &str, team: &str) -> ProposalRow {
        let now = chrono::Utc::now();
        ProposalRow {
            id: id.to_string(),
            team_id: team.to_string(),
            agent_id: "agent-1".to_string(),
            proposal_type: "policy_change".to_string(),
            payload_json: r#"{"credential_name":"cred-a","auto_approve_methods":["POST"]}"#
                .to_string(),
            status: "pending".to_string(),
            resolved_by: None,
            resolved_at: None,
            created_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::days(7)).to_rfc3339(),
        }
    }

    async fn seeded_store() -> ConfigStore {
        let store = test_store().await;
        store.create_team("t1", "Team One").await.unwrap();
        store
    }

    #[tokio::test]
    async fn team_default_approval_mode_roundtrips_and_fails_safe() {
        use crate::config::ApprovalMode;
        let store = seeded_store().await; // creates team t1
        // A freshly created team now starts AUTONOMOUS (see `create_team`).
        // This assertion was previously `Gated`; the change is deliberate and
        // scoped to newly created teams only — the column default stays
        // 'gated' so existing rows and any other INSERT path are untouched.
        assert_eq!(
            store.get_team_default_approval_mode("t1").await.unwrap(),
            ApprovalMode::Autonomous
        );
        // Explicitly switch to gated and back, to prove both directions persist.
        store
            .set_team_default_approval_mode("t1", ApprovalMode::Gated)
            .await
            .unwrap();
        assert_eq!(
            store.get_team_default_approval_mode("t1").await.unwrap(),
            ApprovalMode::Gated
        );
        // Set autonomous, read it back.
        store
            .set_team_default_approval_mode("t1", ApprovalMode::Autonomous)
            .await
            .unwrap();
        assert_eq!(
            store.get_team_default_approval_mode("t1").await.unwrap(),
            ApprovalMode::Autonomous
        );
        // A missing team fails safe to gated (never silently autonomous).
        assert_eq!(
            store
                .get_team_default_approval_mode("nonexistent")
                .await
                .unwrap(),
            ApprovalMode::Gated
        );
    }

    #[tokio::test]
    async fn proposal_create_get_roundtrip_and_team_scoped() {
        let store = seeded_store().await;
        store
            .create_proposal(&proposal_row("p1", "t1"))
            .await
            .unwrap();
        let got = store.get_proposal("t1", "p1").await.unwrap().unwrap();
        assert_eq!(got.status, "pending");
        assert_eq!(got.agent_id, "agent-1");
        // Cross-team lookup returns None.
        store.create_team("t2", "Team Two").await.unwrap();
        assert!(store.get_proposal("t2", "p1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn proposal_list_team_scoped() {
        let store = seeded_store().await;
        store.create_team("t2", "T2").await.unwrap();
        store
            .create_proposal(&proposal_row("p1", "t1"))
            .await
            .unwrap();
        store
            .create_proposal(&proposal_row("p2", "t1"))
            .await
            .unwrap();
        store
            .create_proposal(&proposal_row("p3", "t2"))
            .await
            .unwrap();
        assert_eq!(
            store
                .list_proposals_for_team("t1", Some("pending"))
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store
                .list_proposals_for_team("t2", Some("pending"))
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn proposal_resolve_atomic_and_double_submit() {
        let store = seeded_store().await;
        store
            .create_proposal(&proposal_row("p1", "t1"))
            .await
            .unwrap();
        // First resolve claims it.
        assert!(store
            .resolve_proposal("t1", "p1", "approved", "mgr@x.com")
            .await
            .unwrap());
        // Second is a no-op — already resolved (double-submit safe).
        assert!(!store
            .resolve_proposal("t1", "p1", "denied", "mgr2@x.com")
            .await
            .unwrap());
        let got = store.get_proposal("t1", "p1").await.unwrap().unwrap();
        assert_eq!(got.status, "approved");
        assert_eq!(got.resolved_by.as_deref(), Some("mgr@x.com"));
    }

    #[tokio::test]
    async fn proposal_resolve_cross_team_is_noop() {
        let store = seeded_store().await;
        store.create_team("t2", "T2").await.unwrap();
        store
            .create_proposal(&proposal_row("p1", "t1"))
            .await
            .unwrap();
        assert!(!store
            .resolve_proposal("t2", "p1", "approved", "x@x.com")
            .await
            .unwrap());
        assert_eq!(
            store
                .get_proposal("t1", "p1")
                .await
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
    }

    #[tokio::test]
    async fn proposal_expired_not_resolvable_and_hidden() {
        let store = seeded_store().await;
        let mut row = proposal_row("p1", "t1");
        row.expires_at = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        store.create_proposal(&row).await.unwrap();
        assert!(!store
            .resolve_proposal("t1", "p1", "approved", "x@x.com")
            .await
            .unwrap());
        assert!(store
            .list_proposals_for_team("t1", Some("pending"))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn proposal_count_pending_for_agent() {
        let store = seeded_store().await;
        store
            .create_proposal(&proposal_row("p1", "t1"))
            .await
            .unwrap();
        store
            .create_proposal(&proposal_row("p2", "t1"))
            .await
            .unwrap();
        assert_eq!(
            store
                .count_pending_proposals_for_agent("t1", "agent-1")
                .await
                .unwrap(),
            2
        );
        store
            .resolve_proposal("t1", "p1", "denied", "x@x.com")
            .await
            .unwrap();
        assert_eq!(
            store
                .count_pending_proposals_for_agent("t1", "agent-1")
                .await
                .unwrap(),
            1
        );
    }

    /// Distributed State Rule: create on one store, resolve on a second store
    /// sharing the same DB schema, observe the result on the first.
    #[tokio::test]
    async fn proposal_resolve_on_other_instance_is_observed() {
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        store_a.create_team("t1", "T1").await.unwrap();
        let store_b = ConfigStore::new(&url, test_key()).await.unwrap();
        store_a
            .create_proposal(&proposal_row("p1", "t1"))
            .await
            .unwrap();
        // Resolve on B.
        assert!(store_b
            .resolve_proposal("t1", "p1", "approved", "mgr@x.com")
            .await
            .unwrap());
        // Observed on A.
        assert_eq!(
            store_a
                .get_proposal("t1", "p1")
                .await
                .unwrap()
                .unwrap()
                .status,
            "approved"
        );
    }

    #[tokio::test]
    async fn relay_lease_single_holder_and_lifecycle() {
        let store = test_store().await;
        let key = "team-a:telegram";
        // First process claims the lease.
        assert!(store.claim_relay_session(key, "proc-A", 30).await.unwrap());
        // A live foreign holder blocks a second process — single-holder invariant.
        assert!(!store.claim_relay_session(key, "proc-B", 30).await.unwrap());
        assert_eq!(
            store.live_relay_holder(key, 30).await.unwrap().as_deref(),
            Some("proc-A")
        );
        // The holder keeps it alive; can idempotently re-claim on reconnect.
        assert!(store.heartbeat_relay_session(key, "proc-A").await.unwrap());
        assert!(store.claim_relay_session(key, "proc-A", 30).await.unwrap());
        // A non-holder's heartbeat is a no-op.
        assert!(!store.heartbeat_relay_session(key, "proc-B").await.unwrap());
        // Clean release frees it; only then can B claim.
        store.release_relay_session(key, "proc-A").await.unwrap();
        assert!(store.live_relay_holder(key, 30).await.unwrap().is_none());
        assert!(store.claim_relay_session(key, "proc-B", 30).await.unwrap());
    }

    #[tokio::test]
    async fn relay_lease_stale_takeover() {
        let store = test_store().await;
        let key = "team-a:telegram";
        assert!(store.claim_relay_session(key, "proc-A", 30).await.unwrap());
        // ttl_secs = -1 pushes the stale cutoff into the future, so any existing
        // lease counts as stale — deterministic takeover without sleeping.
        assert!(store.claim_relay_session(key, "proc-B", -1).await.unwrap());
        assert_eq!(
            store.live_relay_holder(key, 30).await.unwrap().as_deref(),
            Some("proc-B")
        );
        // A lost the lease and can no longer heartbeat it.
        assert!(!store.heartbeat_relay_session(key, "proc-A").await.unwrap());
    }

    #[tokio::test]
    async fn relay_lease_spans_instances() {
        // Begin on one app state, resolve on another sharing the same DB.
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&url, test_key()).await.unwrap();
        let key = "team-a:telegram";
        assert!(store_a
            .claim_relay_session(key, "proc-A", 30)
            .await
            .unwrap());
        // Instance B sees the live holder and is refused a competing claim.
        assert_eq!(
            store_b.live_relay_holder(key, 30).await.unwrap().as_deref(),
            Some("proc-A")
        );
        assert!(!store_b
            .claim_relay_session(key, "proc-B", 30)
            .await
            .unwrap());
        // Released on A, reclaimed on B — no shared in-memory state.
        store_a.release_relay_session(key, "proc-A").await.unwrap();
        assert!(store_b
            .claim_relay_session(key, "proc-B", 30)
            .await
            .unwrap());
    }

    // -- Time-boxed approval grants (#49) -----------------------------------

    async fn seed_grant_credential(store: &ConfigStore) {
        store.create_team("t1", "team").await.unwrap();
        store
            .create_credential("t1", "cred", "c", "direct", None, false, None, None, None)
            .await
            .unwrap();
    }

    fn test_grant(id: &str, expires_at: String, max_uses: Option<i64>) -> GrantRow {
        GrantRow {
            id: id.to_string(),
            team_id: "t1".into(),
            credential_name: "cred".into(),
            methods: vec!["POST".into()],
            route_scope: vec!["/v1/messages".into()],
            expires_at,
            granted_by: "owner@example.com".into(),
            max_uses,
            uses: 0,
            revoked: false,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[tokio::test]
    async fn grant_claim_spans_instances() {
        // Created on instance A, consumed on instance B — no shared memory.
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&url, test_key()).await.unwrap();
        seed_grant_credential(&store_a).await;

        let now = chrono::Utc::now();
        let expires = (now + chrono::Duration::minutes(30)).to_rfc3339();
        store_a
            .create_approval_grant(&test_grant("g1", expires, Some(2)))
            .await
            .unwrap();

        let now_s = now.to_rfc3339();
        let live = store_b
            .live_grants_for_credential("t1", "cred", &now_s)
            .await
            .unwrap();
        assert_eq!(live.len(), 1);
        assert!(store_b.claim_approval_grant("g1", &now_s).await.unwrap());

        // The consumed use is visible back on instance A.
        let on_a = store_a.list_approval_grants("t1").await.unwrap();
        assert_eq!(on_a[0].uses, 1);
    }

    #[tokio::test]
    async fn grant_expired_never_claims() {
        let store = test_store().await;
        seed_grant_credential(&store).await;
        let past = (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        store
            .create_approval_grant(&test_grant("g-exp", past, None))
            .await
            .unwrap();

        let now_s = chrono::Utc::now().to_rfc3339();
        assert!(store
            .live_grants_for_credential("t1", "cred", &now_s)
            .await
            .unwrap()
            .is_empty());
        assert!(!store.claim_approval_grant("g-exp", &now_s).await.unwrap());
    }

    #[tokio::test]
    async fn grant_revoked_mid_window_never_claims() {
        // Revoked on instance B between candidate lookup and claim on A —
        // the claim's own WHERE re-checks revocation, so it misses cleanly.
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&url, test_key()).await.unwrap();
        seed_grant_credential(&store_a).await;

        let expires = (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
        store_a
            .create_approval_grant(&test_grant("g-rev", expires, None))
            .await
            .unwrap();
        let now_s = chrono::Utc::now().to_rfc3339();
        // Instance A sees it live…
        assert_eq!(
            store_a
                .live_grants_for_credential("t1", "cred", &now_s)
                .await
                .unwrap()
                .len(),
            1
        );
        // …B revokes…
        assert!(store_b.revoke_approval_grant("t1", "g-rev").await.unwrap());
        // …and A's claim misses.
        assert!(!store_a.claim_approval_grant("g-rev", &now_s).await.unwrap());
        // Revocation is team-scoped: a foreign team can't kill it.
        assert!(!store_b.revoke_approval_grant("t2", "g-rev").await.unwrap());
    }

    #[tokio::test]
    async fn grant_max_uses_atomic_under_concurrency() {
        // 20 concurrent claims against max_uses=5 across two instances:
        // exactly 5 must win — the conditional UPDATE re-checks the cap under
        // the row lock, so the count can never overshoot.
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = std::sync::Arc::new(ConfigStore::new(&url, test_key()).await.unwrap());
        let store_a = std::sync::Arc::new(store_a);
        seed_grant_credential(&store_a).await;

        let expires = (chrono::Utc::now() + chrono::Duration::minutes(30)).to_rfc3339();
        store_a
            .create_approval_grant(&test_grant("g-cap", expires, Some(5)))
            .await
            .unwrap();

        let now_s = chrono::Utc::now().to_rfc3339();
        let mut handles = Vec::new();
        for i in 0..20 {
            let store = if i % 2 == 0 {
                store_a.clone()
            } else {
                store_b.clone()
            };
            let now_c = now_s.clone();
            handles.push(tokio::spawn(async move {
                store.claim_approval_grant("g-cap", &now_c).await.unwrap()
            }));
        }
        let mut wins = 0;
        for h in handles {
            if h.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 5, "concurrent claims must never exceed max_uses");
        let rows = store_a.list_approval_grants("t1").await.unwrap();
        assert_eq!(rows[0].uses, 5);
    }

    #[tokio::test]
    async fn push_subscriptions_crud_and_team_scoped() {
        let store = test_store().await;
        store
            .save_push_subscription("https://push.example/ep1", "team-a", "u@a.com", "p1", "a1")
            .await
            .unwrap();
        store
            .save_push_subscription("https://push.example/ep2", "team-a", "u2@a.com", "p2", "a2")
            .await
            .unwrap();
        store
            .save_push_subscription("https://push.example/ep3", "team-b", "u@b.com", "p3", "a3")
            .await
            .unwrap();

        // Team-scoped listing.
        let a = store
            .list_push_subscriptions_for_team("team-a")
            .await
            .unwrap();
        assert_eq!(a.len(), 2);
        let b = store
            .list_push_subscriptions_for_team("team-b")
            .await
            .unwrap();
        assert_eq!(b.len(), 1);

        // Re-subscribe same endpoint updates keys, does not duplicate.
        store
            .save_push_subscription("https://push.example/ep1", "team-a", "u@a.com", "P1", "A1")
            .await
            .unwrap();
        let a = store
            .list_push_subscriptions_for_team("team-a")
            .await
            .unwrap();
        assert_eq!(a.len(), 2, "re-subscribe must upsert, not duplicate");
        assert!(a
            .iter()
            .any(|s| s.endpoint == "https://push.example/ep1" && s.p256dh == "P1"));

        // Delete by endpoint.
        store
            .delete_push_subscription("https://push.example/ep1")
            .await
            .unwrap();
        let a = store
            .list_push_subscriptions_for_team("team-a")
            .await
            .unwrap();
        assert_eq!(a.len(), 1);
    }

    #[tokio::test]
    async fn pending_approvals_team_scoped_and_excludes_resolved() {
        let store = test_store().await;
        let future = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        store
            .save_pending_approval_with_team(
                "txn-1",
                "{\"target_url\":\"x\"}",
                &future,
                Some("team-a"),
            )
            .await
            .unwrap();
        store
            .save_pending_approval_with_team(
                "txn-2",
                "{\"target_url\":\"y\"}",
                &future,
                Some("team-a"),
            )
            .await
            .unwrap();
        store
            .save_pending_approval_with_team(
                "txn-3",
                "{\"target_url\":\"z\"}",
                &future,
                Some("team-b"),
            )
            .await
            .unwrap();

        assert_eq!(
            store
                .list_pending_approvals_for_team("team-a")
                .await
                .unwrap()
                .len(),
            2
        );

        // Resolving one removes it from the pending list.
        store
            .resolve_pending_approval("txn-1", "approved", Some("u@a.com"))
            .await
            .unwrap();
        assert_eq!(
            store
                .list_pending_approvals_for_team("team-a")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn rate_counter_increments_atomically_across_instances() {
        // Two ConfigStore handles on the same schema simulate two stateless
        // proxy instances. The DB counter must accumulate across both (a
        // process-local counter would give each its own count).
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&url, test_key()).await.unwrap();

        let window = 1_700_000_000i64; // fixed bucket
        assert_eq!(
            store_a
                .increment_rate_counter("agent-x", window)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store_b
                .increment_rate_counter("agent-x", window)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            store_a
                .increment_rate_counter("agent-x", window)
                .await
                .unwrap(),
            3
        );

        // A different agent has an independent counter.
        assert_eq!(
            store_a
                .increment_rate_counter("agent-y", window)
                .await
                .unwrap(),
            1
        );

        // A new window resets the count and prunes the old window for the agent.
        let next_window = window + 3600;
        assert_eq!(
            store_a
                .increment_rate_counter("agent-x", next_window)
                .await
                .unwrap(),
            1
        );
    }

    // ---- Device authorization flow (`tap login`) — distributed-state tests ----
    //
    // Two `ConfigStore` handles on the same schema (`store_a`/`store_b`) simulate
    // two stateless proxy instances, per the repo's Distributed State Rule: the
    // CLI may poll instance A while the human confirms on instance B, and a
    // double-poll must claim a session exactly once.

    /// Seed a user + team so a device row can be bound (the row's user_id/team_id
    /// are FKs into users/teams).
    async fn seed_device_identity(store: &ConfigStore, user_id: &str, team_id: &str) {
        store.create_team(team_id, team_id).await.unwrap();
        store
            .create_user(user_id, &format!("{user_id}@example.com"), "hash")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn device_approve_on_one_instance_claim_on_another() {
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&url, test_key()).await.unwrap();
        seed_device_identity(&store_a, "u1", "t1").await;

        let expires = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        store_a
            .create_device_authorization("dh-1", "CODE1AAA", &expires)
            .await
            .unwrap();

        // Human confirms on instance B...
        assert!(store_b
            .approve_device_authorization("CODE1AAA", "u1", "t1")
            .await
            .unwrap());

        // ...and the CLI's poll on instance A retrieves the bound identity.
        match store_a.claim_device_authorization("dh-1").await.unwrap() {
            DeviceClaim::Approved { user_id, team_id } => {
                assert_eq!(user_id, "u1");
                assert_eq!(team_id, "t1");
            }
            other => panic!("expected Approved, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn device_concurrent_double_poll_claims_exactly_once() {
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&url, test_key()).await.unwrap();
        seed_device_identity(&store_a, "u1", "t1").await;

        let expires = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        store_a
            .create_device_authorization("dh-2", "CODE2AAA", &expires)
            .await
            .unwrap();
        store_a
            .approve_device_authorization("CODE2AAA", "u1", "t1")
            .await
            .unwrap();

        // Two instances race to claim the same approved code.
        let (r1, r2) = tokio::join!(
            store_a.claim_device_authorization("dh-2"),
            store_b.claim_device_authorization("dh-2"),
        );
        let approved = [r1.unwrap(), r2.unwrap()]
            .into_iter()
            .filter(|c| matches!(c, DeviceClaim::Approved { .. }))
            .count();
        assert_eq!(approved, 1, "exactly one poll must claim the session");
    }

    #[tokio::test]
    async fn device_already_claimed_code_rejected() {
        let (store_a, url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&url, test_key()).await.unwrap();
        seed_device_identity(&store_a, "u1", "t1").await;

        let expires = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        store_a
            .create_device_authorization("dh-3", "CODE3AAA", &expires)
            .await
            .unwrap();
        store_a
            .approve_device_authorization("CODE3AAA", "u1", "t1")
            .await
            .unwrap();

        // First claim succeeds; a replay on the other instance is rejected.
        assert!(matches!(
            store_a.claim_device_authorization("dh-3").await.unwrap(),
            DeviceClaim::Approved { .. }
        ));
        assert!(matches!(
            store_b.claim_device_authorization("dh-3").await.unwrap(),
            DeviceClaim::ExpiredOrUnknown
        ));
    }

    #[tokio::test]
    async fn device_expired_code_rejected() {
        let store = test_store().await;
        seed_device_identity(&store, "u1", "t1").await;

        let past = (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        store
            .create_device_authorization("dh-4", "CODE4AAA", &past)
            .await
            .unwrap();

        // An expired code can neither be approved nor claimed.
        assert!(!store
            .approve_device_authorization("CODE4AAA", "u1", "t1")
            .await
            .unwrap());
        assert!(matches!(
            store.claim_device_authorization("dh-4").await.unwrap(),
            DeviceClaim::ExpiredOrUnknown
        ));
    }

    #[tokio::test]
    async fn device_denied_code_rejected() {
        let store = test_store().await;
        seed_device_identity(&store, "u1", "t1").await;

        let expires = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        store
            .create_device_authorization("dh-5", "CODE5AAA", &expires)
            .await
            .unwrap();
        // Simulate a denial (no deny endpoint exists yet; the claim path already
        // handles the 'denied' status, so exercise it directly).
        sqlx::query("UPDATE device_authorizations SET status = 'denied' WHERE device_code_hash = $1")
            .bind("dh-5")
            .execute(store.pool())
            .await
            .unwrap();

        assert!(matches!(
            store.claim_device_authorization("dh-5").await.unwrap(),
            DeviceClaim::Denied
        ));
    }

    #[tokio::test]
    async fn device_unknown_code_rejected() {
        let store = test_store().await;
        assert!(matches!(
            store
                .claim_device_authorization("never-created")
                .await
                .unwrap(),
            DeviceClaim::ExpiredOrUnknown
        ));
    }

    #[tokio::test]
    async fn test_create_and_get_credential() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_credential(
                "team-1",
                "slack",
                "Slack bot",
                "direct",
                Some("https://slack.com"),
                false,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let cred = store
            .get_credential("team-1", "slack")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cred.name, "slack");
        assert_eq!(cred.team_id, "team-1");
        assert_eq!(cred.description, "Slack bot");
        assert_eq!(cred.connector, "direct");
        assert_eq!(cred.api_base.as_deref(), Some("https://slack.com"));
    }

    #[tokio::test]
    async fn update_credential_config_edits_auth_bindings() {
        // A credential imported with the WRONG auth wiring (default Bearer here)
        // can be corrected in place — the gap that made "edit the credential"
        // dead-end at delete-and-recreate for header-scheme vendors like
        // Anthropic (x-api-key).
        let store = test_store().await;
        store.create_team("t", "team").await.unwrap();
        store
            .create_credential(
                "t",
                "anthropic",
                "Claude",
                "direct",
                None,
                false,
                None,
                Some(r#"[{"header":"Authorization","format":"Bearer {value}"}]"#),
                None,
            )
            .await
            .unwrap();

        // Set: fix the binding to x-api-key. Every other field left untouched.
        let changed = store
            .update_credential_config(
                "t",
                "anthropic",
                None,
                None,
                None,
                false,
                None,
                None,
                false,
                Some(r#"[{"header":"x-api-key","format":"{value}"}]"#),
                false,
            )
            .await
            .unwrap();
        assert!(changed);
        let cred = store.get_credential("t", "anthropic").await.unwrap().unwrap();
        let bindings = cred.auth_bindings_json.as_deref().unwrap_or("");
        assert!(bindings.contains("x-api-key"), "binding should be updated: {bindings}");
        assert!(!bindings.contains("Authorization"), "old binding should be gone: {bindings}");

        // Leave untouched: a description-only patch must not disturb the binding.
        store
            .update_credential_config(
                "t",
                "anthropic",
                Some("Anthropic Claude"),
                None,
                None,
                false,
                None,
                None,
                false,
                None,
                false,
            )
            .await
            .unwrap();
        let cred = store.get_credential("t", "anthropic").await.unwrap().unwrap();
        assert!(cred.auth_bindings_json.as_deref().unwrap_or("").contains("x-api-key"));
        assert_eq!(cred.description, "Anthropic Claude");

        // Clear: reset back to the default (no bindings → default Bearer).
        store
            .update_credential_config(
                "t", "anthropic", None, None, None, false, None, None, false, None, true,
            )
            .await
            .unwrap();
        let cred = store.get_credential("t", "anthropic").await.unwrap().unwrap();
        assert_eq!(cred.auth_bindings_json, None, "clear should NULL the bindings");
    }

    #[tokio::test]
    async fn test_end_user_upsert_list_and_scoped_credentials() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        // Lazy upsert is idempotent and records the display name.
        store
            .upsert_end_user("team-1", "alice", Some("Alice"))
            .await
            .unwrap();
        store
            .upsert_end_user("team-1", "alice", None)
            .await
            .unwrap();
        store.upsert_end_user("team-1", "bob", None).await.unwrap();

        let users = store.list_end_users("team-1").await.unwrap();
        assert_eq!(users.len(), 2);
        let alice = users.iter().find(|u| u.ext_id == "alice").unwrap();
        // A later upsert with None display_name must not clobber the prior one.
        assert_eq!(alice.display_name.as_deref(), Some("Alice"));
        assert!(alice.last_seen_at.is_some());

        // Two end-users each get a "wallet" key; the namespaced name keeps them
        // unique under the (team_id, name) PK while end_user_id is authoritative.
        store
            .create_credential_scoped(
                "team-1",
                "eu:alice/wallet",
                "Alice wallet",
                "sidecar",
                Some("tap:sign"),
                false,
                None,
                None,
                Some(b"{\"algorithm\":\"secp256k1\"}"),
                Some("alice"),
            )
            .await
            .unwrap();
        store
            .create_credential_scoped(
                "team-1",
                "eu:bob/wallet",
                "Bob wallet",
                "sidecar",
                Some("tap:sign"),
                false,
                None,
                None,
                Some(b"{\"algorithm\":\"secp256k1\"}"),
                Some("bob"),
            )
            .await
            .unwrap();

        let alice_creds = store
            .list_end_user_credentials("team-1", "alice")
            .await
            .unwrap();
        assert_eq!(alice_creds.len(), 1);
        assert_eq!(alice_creds[0].name, "eu:alice/wallet");
        assert_eq!(alice_creds[0].end_user_id.as_deref(), Some("alice"));

        // Isolation: bob's listing never includes alice's key.
        let bob_creds = store
            .list_end_user_credentials("team-1", "bob")
            .await
            .unwrap();
        assert_eq!(bob_creds.len(), 1);
        assert_eq!(bob_creds[0].name, "eu:bob/wallet");

        // A team-scoped credential has no end_user_id and is excluded.
        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();
        let team_cred = store
            .get_credential("team-1", "slack")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(team_cred.end_user_id, None);
        assert_eq!(
            store
                .list_end_user_credentials("team-1", "alice")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_create_and_get_agent() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_agent("team-1", "bot-1", Some("Test bot"), "hash123", Some(100))
            .await
            .unwrap();

        let agent = store.get_agent("team-1", "bot-1").await.unwrap().unwrap();
        assert_eq!(agent.id, "bot-1");
        assert_eq!(agent.team_id, "team-1");
        assert_eq!(agent.description.as_deref(), Some("Test bot"));
        assert!(agent.enabled);
        assert_eq!(agent.rate_limit_per_hour, Some(100));
    }

    #[tokio::test]
    async fn test_create_role_and_assign_to_agent() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        // Create credentials
        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();
        store
            .create_credential(
                "team-1", "notion", "Notion", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();

        // Create role with credentials
        store
            .create_role("team-1", "marketing", Some("Marketing team"), Some(200))
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "marketing", "slack")
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "marketing", "notion")
            .await
            .unwrap();

        // Create agent and assign role
        store
            .create_agent("team-1", "mkt-bot", None, "hash456", None)
            .await
            .unwrap();
        store
            .assign_role_to_agent("team-1", "mkt-bot", "marketing")
            .await
            .unwrap();

        // Verify effective credentials
        let creds = store
            .get_agent_effective_credentials("team-1", "mkt-bot")
            .await
            .unwrap();
        assert!(creds.contains("slack"));
        assert!(creds.contains("notion"));
        assert_eq!(creds.len(), 2);
    }

    #[tokio::test]
    async fn test_effective_credentials_union() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        // Create credentials
        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();
        store
            .create_credential(
                "team-1", "exa", "Exa", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();
        store
            .create_credential(
                "team-1", "mercury", "Mercury", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();

        // Role gives slack + exa
        store
            .create_role("team-1", "team", None, None)
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "team", "slack")
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "team", "exa")
            .await
            .unwrap();

        // Agent gets role + direct mercury
        store
            .create_agent("team-1", "bot", None, "hash", None)
            .await
            .unwrap();
        store
            .assign_role_to_agent("team-1", "bot", "team")
            .await
            .unwrap();
        store
            .add_direct_credential("team-1", "bot", "mercury")
            .await
            .unwrap();

        // Union should be all three
        let creds = store
            .get_agent_effective_credentials("team-1", "bot")
            .await
            .unwrap();
        assert_eq!(creds.len(), 3);
        assert!(creds.contains("slack"));
        assert!(creds.contains("exa"));
        assert!(creds.contains("mercury"));
    }

    #[tokio::test]
    async fn test_credential_encryption_roundtrip() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_credential(
                "team-1",
                "secret",
                "Secret API",
                "direct",
                None,
                false,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let plaintext = b"super-secret-api-key-12345";
        store
            .set_credential_value("team-1", "secret", plaintext)
            .await
            .unwrap();

        let decrypted = store
            .get_credential_value("team-1", "secret")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_agent_enable_disable() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_agent("team-1", "bot", None, "hash", None)
            .await
            .unwrap();

        // Starts enabled
        let agent = store.get_agent("team-1", "bot").await.unwrap().unwrap();
        assert!(agent.enabled);

        // Disable
        store.disable_agent("team-1", "bot").await.unwrap();
        let agent = store.get_agent("team-1", "bot").await.unwrap().unwrap();
        assert!(!agent.enabled);

        // Authenticate returns the agent even when disabled (caller checks enabled)
        let auth = store.authenticate_agent("hash").await.unwrap();
        assert!(auth.is_some());
        assert!(!auth.unwrap().enabled);

        // Re-enable
        store.enable_agent("team-1", "bot").await.unwrap();
        let auth = store.authenticate_agent("hash").await.unwrap();
        assert!(auth.is_some());
        assert!(auth.unwrap().enabled);
    }

    #[tokio::test]
    async fn test_rotate_agent_api_key_invalidates_old_hash() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_agent("team-1", "bot", None, "old-hash", None)
            .await
            .unwrap();

        store
            .rotate_agent_api_key("team-1", "bot", "new-hash")
            .await
            .unwrap();

        assert!(store
            .authenticate_agent("old-hash")
            .await
            .unwrap()
            .is_none());

        let agent = store
            .authenticate_agent("new-hash")
            .await
            .unwrap()
            .expect("new hash should authenticate");
        assert_eq!(agent.id, "bot");
        assert_eq!(agent.api_key_hash, "new-hash");
    }

    #[tokio::test]
    async fn test_delete_role_cascades() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();
        store
            .create_role("team-1", "team", None, None)
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "team", "slack")
            .await
            .unwrap();

        store
            .create_agent("team-1", "bot", None, "hash", None)
            .await
            .unwrap();
        store
            .assign_role_to_agent("team-1", "bot", "team")
            .await
            .unwrap();

        // Before delete: bot has slack via role
        let creds = store
            .get_agent_effective_credentials("team-1", "bot")
            .await
            .unwrap();
        assert!(creds.contains("slack"));

        // Delete role -- cascades to agent_roles and role_credentials
        store.delete_role("team-1", "team").await.unwrap();

        // After delete: bot has nothing
        let creds = store
            .get_agent_effective_credentials("team-1", "bot")
            .await
            .unwrap();
        assert!(creds.is_empty());
    }

    #[tokio::test]
    async fn test_policy_crud() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();

        let policy = PolicyRow {
            credential_name: "slack".to_string(),
            team_id: "team-1".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string(), "DELETE".to_string()],
            auto_approve_urls: vec!["/v1/search".to_string()],
            require_approval_urls: vec![],
            allowed_approvers: vec!["user123".to_string()],
            approval_channel: Some("telegram".to_string()),
            telegram_chat_id: Some("-12345".to_string()),
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: true,
            min_approvals: 1,
        };

        store.set_policy(&policy).await.unwrap();

        let fetched = store.get_policy("team-1", "slack").await.unwrap().unwrap();
        assert_eq!(fetched.team_id, "team-1");
        assert_eq!(fetched.auto_approve_methods, vec!["GET"]);
        assert_eq!(fetched.require_approval_methods, vec!["POST", "DELETE"]);
        assert_eq!(fetched.auto_approve_urls, vec!["/v1/search"]);
        assert_eq!(fetched.allowed_approvers, vec!["user123"]);
        assert_eq!(fetched.approval_channel.as_deref(), Some("telegram"));
        assert_eq!(fetched.telegram_chat_id.as_deref(), Some("-12345"));
        assert!(fetched.require_passkey);
    }

    #[tokio::test]
    async fn test_admin_flag() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        // Regular agent
        store
            .create_agent("team-1", "bot", None, "hash1", None)
            .await
            .unwrap();
        let agent = store.get_agent("team-1", "bot").await.unwrap().unwrap();
        assert!(!agent.is_admin);

        // Admin agent
        store
            .create_admin_agent("team-1", "admin", Some("Admin user"), "hash2")
            .await
            .unwrap();
        let admin = store.get_agent("team-1", "admin").await.unwrap().unwrap();
        assert!(admin.is_admin);
        assert_eq!(admin.team_id, "team-1");

        // Auth returns is_admin flag and team_id
        let authed = store.authenticate_agent("hash2").await.unwrap().unwrap();
        assert!(authed.is_admin);
        assert_eq!(authed.id, "admin");
        assert_eq!(authed.team_id, "team-1");
    }

    #[tokio::test]
    async fn test_authenticate_agent() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_agent("team-1", "bot", None, "correct-hash", None)
            .await
            .unwrap();

        // Correct hash
        let agent = store.authenticate_agent("correct-hash").await.unwrap();
        assert!(agent.is_some());
        let agent = agent.unwrap();
        assert_eq!(agent.id, "bot");
        assert_eq!(agent.team_id, "team-1");

        // Wrong hash
        let agent = store.authenticate_agent("wrong-hash").await.unwrap();
        assert!(agent.is_none());
    }

    #[tokio::test]
    async fn test_notification_channel_crud() {
        let store = test_store().await;
        store.create_team("t1", "test-team").await.unwrap();

        // Create a telegram channel
        let config = r#"{"chat_id": "-100123"}"#;
        let id = store
            .create_notification_channel("t1", "telegram", "approvals", config)
            .await
            .unwrap();
        assert!(!id.is_empty());

        // Get by name
        let channel = store
            .get_notification_channel("t1", "approvals")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(channel.channel_type, "telegram");
        assert_eq!(channel.name, "approvals");
        assert_eq!(channel.config_json, config);
        assert!(channel.enabled);

        // List
        let channels = store.list_notification_channels("t1").await.unwrap();
        assert_eq!(channels.len(), 1);

        // Delete
        store
            .delete_notification_channel("t1", "approvals")
            .await
            .unwrap();
        let channels = store.list_notification_channels("t1").await.unwrap();
        assert_eq!(channels.len(), 0);

        // Delete nonexistent fails
        let result = store.delete_notification_channel("t1", "nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_notification_channel_unique_name() {
        let store = test_store().await;
        store.create_team("t1", "test-team").await.unwrap();

        let config = r#"{"chat_id": "-100123"}"#;
        store
            .create_notification_channel("t1", "telegram", "main", config)
            .await
            .unwrap();

        // Same name should fail
        let result = store
            .create_notification_channel("t1", "telegram", "main", config)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_default_telegram_chat_id() {
        let store = test_store().await;
        store.create_team("t1", "test-team").await.unwrap();

        // No channels -> None
        let chat_id = store.get_default_telegram_chat_id("t1").await.unwrap();
        assert!(chat_id.is_none());

        // Create telegram channel
        store
            .create_notification_channel("t1", "telegram", "main", r#"{"chat_id": "-999"}"#)
            .await
            .unwrap();

        let chat_id = store.get_default_telegram_chat_id("t1").await.unwrap();
        assert_eq!(chat_id.as_deref(), Some("-999"));

        // Different team has no channels
        store.create_team("t2", "other-team").await.unwrap();
        let chat_id = store.get_default_telegram_chat_id("t2").await.unwrap();
        assert!(chat_id.is_none());
    }

    #[tokio::test]
    async fn test_approver_passkey_save_and_list() {
        let store = test_store().await;

        // Empty initially
        let rows = store.list_all_approver_passkeys().await.unwrap();
        assert!(rows.is_empty());

        // Save two passkeys for different approvers
        store
            .save_approver_passkey("cred-1", "alice", "Alice Smith", r#"{"key":"pk1"}"#)
            .await
            .unwrap();
        store
            .save_approver_passkey("cred-2", "bob", "Bob Jones", r#"{"key":"pk2"}"#)
            .await
            .unwrap();

        let rows = store.list_all_approver_passkeys().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].credential_id, "cred-1");
        assert_eq!(rows[0].approver_name, "alice");
        assert_eq!(rows[0].display_name, "Alice Smith");
        assert_eq!(rows[0].public_key_json, r#"{"key":"pk1"}"#);
        assert!(!rows[0].created_at.is_empty());
        assert_eq!(rows[1].credential_id, "cred-2");
        assert_eq!(rows[1].approver_name, "bob");
    }

    #[tokio::test]
    async fn test_approver_passkey_duplicate_credential_id_rejected() {
        let store = test_store().await;
        store
            .save_approver_passkey("cred-1", "alice", "Alice", r#"{"k":"v"}"#)
            .await
            .unwrap();
        // Same credential_id should fail (PK constraint)
        let result = store
            .save_approver_passkey("cred-1", "bob", "Bob", r#"{"k":"v2"}"#)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_approver_passkey_multiple_per_user() {
        let store = test_store().await;
        // One approver can have multiple passkeys (e.g., phone + YubiKey)
        store
            .save_approver_passkey("cred-a", "alice", "Alice", r#"{"device":"phone"}"#)
            .await
            .unwrap();
        store
            .save_approver_passkey("cred-b", "alice", "Alice", r#"{"device":"yubikey"}"#)
            .await
            .unwrap();

        let rows = store.list_all_approver_passkeys().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.approver_name == "alice"));
    }

    #[tokio::test]
    async fn test_resolve_pending_approval_reports_row_presence() {
        let store = test_store().await;
        assert!(store
            .resolve_pending_approval("missing-txn", "approved", Some("alice"))
            .await
            .unwrap());
        assert_eq!(
            store
                .get_pending_approval_status("missing-txn")
                .await
                .unwrap()
                .as_deref(),
            Some("approved")
        );
        store.delete_pending_approval("missing-txn").await.unwrap();

        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store
            .save_pending_approval("txn-present", "{}", &expires_at)
            .await
            .unwrap();

        assert!(store
            .resolve_pending_approval("txn-present", "approved", Some("alice"))
            .await
            .unwrap());
        assert_eq!(
            store
                .get_pending_approval_status("txn-present")
                .await
                .unwrap()
                .as_deref(),
            Some("approved")
        );
    }

    #[tokio::test]
    async fn test_late_pending_save_does_not_overwrite_resolved_approval() {
        let store = test_store().await;
        let txn_id = "txn-approved-before-save";
        store.delete_pending_approval(txn_id).await.unwrap();

        assert!(store
            .resolve_pending_approval(txn_id, "approved", Some("alice"))
            .await
            .unwrap());

        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store
            .save_pending_approval(txn_id, r#"{"detail":"late"}"#, &expires_at)
            .await
            .unwrap();

        assert_eq!(
            store
                .get_pending_approval_status(txn_id)
                .await
                .unwrap()
                .as_deref(),
            Some("approved")
        );

        store.delete_pending_approval(txn_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_matrix_metadata_can_arrive_before_pending_save() {
        let store = test_store().await;
        let txn_id = "txn-matrix-before-save";
        store.delete_pending_approval(txn_id).await.unwrap();

        store
            .set_pending_approval_matrix_data(
                txn_id,
                "!room:example.org",
                "$event",
                "[\"alice\"]",
                2,
            )
            .await
            .unwrap();

        let row = store
            .get_pending_approval_by_matrix_event("$event")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.txn_id, txn_id);
        assert_eq!(row.room_id, "!room:example.org");
        assert_eq!(row.min_approvals, 2);

        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store
            .save_pending_approval(txn_id, r#"{"detail":"late"}"#, &expires_at)
            .await
            .unwrap();

        let row = store
            .get_pending_approval_by_matrix_event("$event")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "pending");
        assert_eq!(row.event_id, "$event");

        store.delete_pending_approval(txn_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_telegram_message_metadata_survives_late_pending_save_and_resolution() {
        let store = test_store().await;
        let txn_id = "txn-telegram-message-metadata";
        store.delete_pending_approval(txn_id).await.unwrap();

        store
            .set_pending_approval_telegram_message(txn_id, "-100123", 98765)
            .await
            .unwrap();

        assert_eq!(
            store
                .get_pending_approval_telegram_message(txn_id)
                .await
                .unwrap(),
            Some(("-100123".to_string(), 98765))
        );

        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store
            .save_pending_approval(txn_id, r#"{"detail":"late"}"#, &expires_at)
            .await
            .unwrap();

        assert_eq!(
            store
                .get_pending_approval_telegram_message(txn_id)
                .await
                .unwrap(),
            Some(("-100123".to_string(), 98765))
        );

        assert!(store
            .resolve_pending_approval(txn_id, "approved", Some("alice"))
            .await
            .unwrap());
        assert_eq!(
            store
                .get_pending_approval_telegram_message(txn_id)
                .await
                .unwrap(),
            Some(("-100123".to_string(), 98765))
        );

        store.delete_pending_approval(txn_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_pending_approval_challenge_is_cross_instance_and_single_use() {
        // Instance A and instance B are separate ConfigStores sharing one DB.
        let (store_a, db_url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&db_url, test_key()).await.unwrap();
        let txn_id = "txn-passkey-cross-instance";
        store_a.delete_pending_approval(txn_id).await.unwrap();

        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store_a
            .save_pending_approval(txn_id, r#"{"detail":"test"}"#, &expires_at)
            .await
            .unwrap();
        store_a
            .set_pending_approval_challenge(txn_id, r#"{"challenge":"state-from-instance-a"}"#)
            .await
            .unwrap();

        assert_eq!(
            store_b
                .take_pending_approval_challenge(txn_id)
                .await
                .unwrap()
                .as_deref(),
            Some(r#"{"challenge":"state-from-instance-a"}"#)
        );
        assert!(store_a
            .take_pending_approval_challenge(txn_id)
            .await
            .unwrap()
            .is_none());

        store_a.delete_pending_approval(txn_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_login_challenge_is_cross_instance_and_single_use() {
        // begin on instance A, finish on instance B (separate ConfigStore, same DB).
        // Instance A and instance B are separate ConfigStores sharing one DB.
        let (store_a, db_url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&db_url, test_key()).await.unwrap();
        let passkey_token = "login-token-cross-instance";

        store_a
            .set_login_challenge(passkey_token, "user-123", r#"{"state":"from-instance-a"}"#)
            .await
            .unwrap();

        // Instance B claims the challenge written by instance A.
        assert_eq!(
            store_b.take_login_challenge(passkey_token).await.unwrap(),
            Some((
                "user-123".to_string(),
                r#"{"state":"from-instance-a"}"#.to_string()
            ))
        );

        // Single-use: a second claim (from either instance) finds nothing.
        assert!(store_a
            .take_login_challenge(passkey_token)
            .await
            .unwrap()
            .is_none());

        // Unknown token also yields None rather than an error.
        assert!(store_b
            .take_login_challenge("no-such-token")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_login_challenge_expired_is_not_claimable() {
        let store = test_store().await;
        let passkey_token = "login-token-expired";
        let past = (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        sqlx::query(
            "INSERT INTO user_login_challenges
                 (passkey_token, user_id, challenge_json, created_at, expires_at)
             VALUES ($1, 'user-x', '{}', $2, $2)",
        )
        .bind(passkey_token)
        .bind(&past)
        .execute(&store.pool)
        .await
        .unwrap();

        assert!(store
            .take_login_challenge(passkey_token)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_registration_challenge_is_cross_instance_and_single_use() {
        // setup-passkey begin on instance A, finish on instance B.
        // Instance A and instance B are separate ConfigStores sharing one DB.
        let (store_a, db_url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&db_url, test_key()).await.unwrap();
        let user_id = "reg-user-cross-instance";

        store_a
            .set_registration_challenge(user_id, r#"{"reg":"from-instance-a"}"#)
            .await
            .unwrap();

        assert_eq!(
            store_b
                .take_registration_challenge(user_id)
                .await
                .unwrap()
                .as_deref(),
            Some(r#"{"reg":"from-instance-a"}"#)
        );
        // Single-use.
        assert!(store_a
            .take_registration_challenge(user_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_scoped_oauth_state_roundtrips_end_user_and_return_url() {
        let store = test_store().await;
        store.create_team("t1", "T1").await.unwrap();
        let exp = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        store
            .create_oauth_state_scoped(
                "sh",
                "agent-1",
                "t1",
                "eu:alice/google",
                "desc",
                "scope",
                "google",
                "alice",
                "https://partner.example/done",
                &exp,
            )
            .await
            .unwrap();
        let st = store.take_oauth_state("sh").await.unwrap().unwrap();
        assert_eq!(st.end_user_id.as_deref(), Some("alice"));
        assert_eq!(
            st.return_url.as_deref(),
            Some("https://partner.example/done")
        );
        assert_eq!(st.flow_type, "create");
        assert_eq!(st.credential_name, "eu:alice/google");
        // Single-use.
        assert!(store.take_oauth_state("sh").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_end_user_usage_aggregates_by_end_user_scoped_to_team() {
        use crate::types::{AuditEntry, HttpMethod};
        let store = test_store().await;
        store.create_team("t1", "T1").await.unwrap();
        store
            .create_agent("t1", "bot", None, "hash-usage", None)
            .await
            .unwrap();

        let mk = |eu: Option<&str>| AuditEntry {
            request_id: uuid::Uuid::new_v4(),
            agent_id: "bot".to_string(),
            credential_names: vec!["c".to_string()],
            target_url: "https://x".to_string(),
            method: HttpMethod::Post,
            approval_status: None,
            upstream_status: Some(200),
            total_latency_ms: 1,
            approval_latency_ms: None,
            upstream_latency_ms: None,
            response_sanitized: false,
            end_user_id: eu.map(|s| s.to_string()),
            request_headers: vec![],
            request_body: None,
            request_body_truncated: false,
            policy_reason: None,
            require_passkey: false,
            approver_identity: None,
            timestamp: chrono::Utc::now(),
        };
        store.write_audit_entry(&mk(Some("alice"))).await.unwrap();
        store.write_audit_entry(&mk(Some("alice"))).await.unwrap();
        store.write_audit_entry(&mk(Some("bob"))).await.unwrap();
        store.write_audit_entry(&mk(None)).await.unwrap(); // team request: excluded

        let from = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        let to = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let usage = store.end_user_usage("t1", &from, &to).await.unwrap();
        assert_eq!(usage.len(), 2, "two distinct end-users");
        assert_eq!(usage[0], ("alice".to_string(), 2), "busiest first");
        assert!(usage.contains(&("bob".to_string(), 1)));

        // A different team sees none of t1's usage.
        store.create_team("t2", "T2").await.unwrap();
        assert!(store
            .end_user_usage("t2", &from, &to)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_end_user_approval_gate_blocks_team_and_admits_only_owner() {
        // The default-deny gate: a row reserved for end-user "alice" can be
        // APPROVED only by alice's own authenticated approval — never by the
        // team/messaging/dashboard path, and never by another end-user.
        let store = test_store().await;
        store.create_team("t1", "T1").await.unwrap();
        let exp = (chrono::Utc::now() + chrono::Duration::minutes(20)).to_rfc3339();

        store
            .save_pending_approval_scoped("eu-txn", "{}", &exp, Some("t1"), Some("alice"))
            .await
            .unwrap();

        // Team/messaging path may NOT approve an end-user row.
        assert!(
            !store
                .resolve_pending_approval("eu-txn", "approved", Some("team-admin"))
                .await
                .unwrap(),
            "team path must not approve an end-user-reserved row"
        );
        assert_eq!(
            store
                .get_pending_approval_status("eu-txn")
                .await
                .unwrap()
                .as_deref(),
            Some("pending"),
            "row must still be pending after the blocked team approval"
        );

        // The wrong end-user may not approve it either.
        assert!(!store
            .resolve_pending_approval_as_end_user("eu-txn", "approved", "bob", Some("bob"))
            .await
            .unwrap());

        // The owning end-user can.
        assert!(store
            .resolve_pending_approval_as_end_user("eu-txn", "approved", "alice", Some("alice"))
            .await
            .unwrap());
        assert_eq!(
            store
                .get_pending_approval_status("eu-txn")
                .await
                .unwrap()
                .as_deref(),
            Some("approved")
        );

        // Denials are always allowed from the team path (fail-closed is safe).
        store
            .save_pending_approval_scoped("eu-txn2", "{}", &exp, Some("t1"), Some("alice"))
            .await
            .unwrap();
        assert!(store
            .resolve_pending_approval("eu-txn2", "denied", Some("team-admin"))
            .await
            .unwrap());

        // A team member's inbox never lists end-user-reserved rows.
        store
            .save_pending_approval_scoped("eu-txn3", "{}", &exp, Some("t1"), Some("alice"))
            .await
            .unwrap();
        store
            .save_pending_approval_scoped("team-txn", "{}", &exp, Some("t1"), None)
            .await
            .unwrap();
        let inbox = store.list_pending_approvals_for_team("t1").await.unwrap();
        let ids: Vec<&str> = inbox.iter().map(|r| r.txn_id.as_str()).collect();
        assert!(ids.contains(&"team-txn"), "team row must be visible");
        assert!(
            !ids.contains(&"eu-txn3"),
            "end-user row must be hidden from the team inbox"
        );

        // Ordinary team rows are still approvable by the team path (regression).
        assert!(store
            .resolve_pending_approval("team-txn", "approved", Some("team-admin"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_approver_registration_challenge_cross_instance_and_single_use() {
        // End-user passkey register-begin on instance A, finish on instance B
        // (TAP for Platforms headless ceremony). Carries the display_name too.
        let (store_a, db_url) = ConfigStore::new_isolated_test(test_key()).await;
        let store_b = ConfigStore::new(&db_url, test_key()).await.unwrap();
        let approver = "eu:team-1:alice";

        store_a
            .set_approver_registration_challenge(approver, r#"{"reg":"from-a"}"#, "alice")
            .await
            .unwrap();

        let claimed = store_b
            .take_approver_registration_challenge(approver)
            .await
            .unwrap();
        assert_eq!(
            claimed,
            Some((r#"{"reg":"from-a"}"#.to_string(), "alice".to_string()))
        );
        // Single-use: a second claim (on either instance) finds nothing.
        assert!(store_a
            .take_approver_registration_challenge(approver)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_credential_value_hint_plain() {
        assert_eq!(credential_value_hint(b"xoxb-abc-123-xyz"), "xo***yz");
        assert_eq!(credential_value_hint(b"shor"), "***"); // ≤4 chars
        assert_eq!(credential_value_hint(b"12345"), "12***45");
    }

    #[test]
    fn test_credential_value_hint_json_object() {
        let val = br#"{"api_key":"abc","app_key":"def"}"#;
        let h = credential_value_hint(val);
        assert!(h.starts_with('{') && h.ends_with('}'));
        assert!(h.contains("api_key") && h.contains("app_key"));
    }

    #[test]
    fn test_credential_value_hint_trims_whitespace() {
        assert_eq!(credential_value_hint(b"  xoxb-abc-123-xyz  "), "xo***yz");
    }

    // -- Password reset tests -------------------------------------------------

    #[tokio::test]
    async fn test_password_reset_happy_path() {
        let store = test_store().await;
        store.create_team("t1", "team").await.unwrap();
        store
            .create_user_with_membership("a1", "t1", "user@example.com", "oldhash", "owner")
            .await
            .unwrap();

        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        store
            .create_password_reset("tokenhash1", "a1", &expires_at, 0)
            .await
            .unwrap();

        // Valid token is consumed and returns the admin_id.
        let result = store
            .validate_and_consume_password_reset("tokenhash1")
            .await
            .unwrap();
        assert_eq!(result, Some("a1".to_string()));

        // Second use of the same token returns None (one-time use).
        let result2 = store
            .validate_and_consume_password_reset("tokenhash1")
            .await
            .unwrap();
        assert!(result2.is_none());
    }

    #[tokio::test]
    async fn test_password_reset_expired_token() {
        let store = test_store().await;
        store.create_team("t1", "team").await.unwrap();
        store
            .create_user_with_membership("a1", "t1", "user@example.com", "oldhash", "owner")
            .await
            .unwrap();

        // Create an already-expired token.
        let expires_at = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        store
            .create_password_reset("expiredhash", "a1", &expires_at, 0)
            .await
            .unwrap();

        let result = store
            .validate_and_consume_password_reset("expiredhash")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_password_reset_unknown_token() {
        let store = test_store().await;
        let result = store
            .validate_and_consume_password_reset("doesnotexist")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_password_reset_invalidates_sessions() {
        let store = test_store().await;
        store.create_team("t1", "team").await.unwrap();
        store
            .create_user_with_membership("a1", "t1", "user@example.com", "oldhash", "owner")
            .await
            .unwrap();

        // Create a session for this admin.
        let session_expires = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        store
            .create_session("sessionhash", "a1", "t1", &session_expires)
            .await
            .unwrap();

        // Verify session exists.
        let session = store.validate_session("sessionhash").await.unwrap();
        assert!(session.is_some());

        // Create and consume a reset token.
        let reset_expires = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        store
            .create_password_reset("resethash", "a1", &reset_expires, 0)
            .await
            .unwrap();
        store
            .validate_and_consume_password_reset("resethash")
            .await
            .unwrap();

        // Session must now be gone.
        let session_after = store.validate_session("sessionhash").await.unwrap();
        assert!(session_after.is_none());
    }

    /// Switching a session's active team is reflected by validate_session, which
    /// resolves the role/identity for the session's CURRENT team.
    #[tokio::test]
    async fn test_session_team_switch() {
        let store = test_store().await;
        store.create_team("t1", "team-one").await.unwrap();
        store.create_team("t2", "team-two").await.unwrap();
        // One person, owner in t1 and approver in t2.
        store
            .create_user_with_membership("u1", "t1", "p@example.com", "h", "owner")
            .await
            .unwrap();
        store
            .create_user_with_membership("u1", "t2", "p@example.com", "h", "approver")
            .await
            .unwrap();

        let expires = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        store
            .create_session("sess", "u1", "t1", &expires)
            .await
            .unwrap();

        // Active team t1 → owner.
        let before = store.validate_session("sess").await.unwrap().unwrap();
        assert_eq!(before.team_id, "t1");
        assert_eq!(before.member_role, "owner");

        // Switch to t2 → approver, same user/session.
        assert!(store.update_session_team("sess", "t2").await.unwrap());
        let after = store.validate_session("sess").await.unwrap().unwrap();
        assert_eq!(after.team_id, "t2");
        assert_eq!(after.member_role, "approver");
        assert_eq!(after.id, "u1");
    }

    /// SECURITY: a session is bound to (user, active team) via a JOIN through
    /// memberships, so revoking the membership invalidates the session even
    /// though the session row still exists. (Backs the team-switch trust model:
    /// you cannot keep acting in a team you were removed from.)
    #[tokio::test]
    async fn test_session_invalidated_when_membership_revoked() {
        let store = test_store().await;
        store.create_team("t1", "team-one").await.unwrap();
        store.create_team("t2", "team-two").await.unwrap();
        store
            .create_user_with_membership("u1", "t1", "p@example.com", "h", "owner")
            .await
            .unwrap();
        store
            .create_user_with_membership("u1", "t2", "p@example.com", "h", "admin")
            .await
            .unwrap();

        let expires = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        store
            .create_session("sess", "u1", "t1", &expires)
            .await
            .unwrap();
        assert!(store.validate_session("sess").await.unwrap().is_some());

        // Remove the user from t1 (their active team). The session row remains,
        // but it must no longer validate.
        store.delete_membership("u1", "t1").await.unwrap();
        assert!(store.validate_session("sess").await.unwrap().is_none());

        // The user still exists and is still a member of t2.
        assert!(store.get_user("u1").await.unwrap().is_some());
        assert!(store.get_member("u1", "t2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn list_invites_by_email_filters_expired_and_scopes_by_email() {
        let store = test_store().await;
        store.create_team("t1", "team-one").await.unwrap();
        let owner = store
            .create_user_with_membership("u-owner", "t1", "owner@x.com", "h", "owner")
            .await
            .unwrap();

        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

        store
            .create_invite(
                "i1",
                "t1",
                "invitee@x.com",
                "admin",
                "hash1",
                &owner,
                &future,
            )
            .await
            .unwrap();
        // Expired — must be excluded.
        store
            .create_invite(
                "i2",
                "t1",
                "invitee@x.com",
                "approver",
                "hash2",
                &owner,
                &past,
            )
            .await
            .unwrap();
        // Different email — must be excluded.
        store
            .create_invite("i3", "t1", "other@x.com", "admin", "hash3", &owner, &future)
            .await
            .unwrap();

        let got = store.list_invites_by_email("invitee@x.com").await.unwrap();
        assert_eq!(got.len(), 1, "only the unexpired invite for this email");
        assert_eq!(got[0].id, "i1");
        assert_eq!(got[0].role, "admin");

        assert!(store
            .list_invites_by_email("nobody@x.com")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn add_membership_idempotent_and_create_user_reuses_identity() {
        let store = test_store().await;
        store.create_team("t1", "team-one").await.unwrap();
        store.create_team("t2", "team-two").await.unwrap();

        // Same email → same identity, regardless of the proposed id/hash.
        let id1 = store.create_user("u1", "p@x.com", "h").await.unwrap();
        let id2 = store.create_user("u2", "p@x.com", "h2").await.unwrap();
        assert_eq!(
            id1, id2,
            "create_user reuses the existing identity by email"
        );

        store.add_membership(&id1, "t1", "owner").await.unwrap();
        // Re-adding is a no-op and must not change the existing role.
        store.add_membership(&id1, "t1", "approver").await.unwrap();
        store.add_membership(&id1, "t2", "admin").await.unwrap();

        let teams = store.list_user_teams(&id1).await.unwrap();
        assert_eq!(teams.len(), 2);
        let t1 = teams.iter().find(|t| t.0 == "t1").unwrap();
        assert_eq!(
            t1.2, "owner",
            "first role wins under ON CONFLICT DO NOTHING"
        );
    }

    #[tokio::test]
    async fn create_user_strict_never_adopts_and_link_refuses_repoint() {
        let store = test_store().await;
        let id1 = store.create_user("u1", "race@x.com", "h").await.unwrap();

        // Strict insert refuses a taken email and touches nothing — no
        // adoption, unlike create_user above.
        assert!(
            !store
                .create_user_strict("u2", "race@x.com", "h2")
                .await
                .unwrap(),
            "strict create must report the email conflict"
        );
        assert_eq!(
            store
                .get_user_by_email("race@x.com")
                .await
                .unwrap()
                .unwrap()
                .id,
            id1,
            "existing row untouched"
        );
        assert!(
            store
                .create_user_strict("u3", "fresh@x.com", "h3")
                .await
                .unwrap(),
            "fresh email inserts"
        );

        // Identity link: idempotent for the same user, refuses a repoint.
        assert!(store
            .link_user_identity(&id1, "google", "sub-1", "race@x.com")
            .await
            .unwrap());
        assert!(store
            .link_user_identity(&id1, "google", "sub-1", "race@x.com")
            .await
            .unwrap());
        assert!(
            !store
                .link_user_identity("u3", "google", "sub-1", "fresh@x.com")
                .await
                .unwrap(),
            "identity already linked to a different user must be refused"
        );
        assert_eq!(
            store
                .get_identity_user("google", "sub-1")
                .await
                .unwrap()
                .as_deref(),
            Some(id1.as_str()),
            "existing link wins"
        );
    }

    #[tokio::test]
    async fn test_password_reset_replaces_prior_token() {
        let store = test_store().await;
        store.create_team("t1", "team").await.unwrap();
        store
            .create_user_with_membership("a1", "t1", "user@example.com", "oldhash", "owner")
            .await
            .unwrap();

        let expires = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        store
            .create_password_reset("first", "a1", &expires, 0)
            .await
            .unwrap();
        // Creating a second token for the same admin replaces the first.
        store
            .create_password_reset("second", "a1", &expires, 0)
            .await
            .unwrap();

        // First token is gone.
        let r1 = store
            .validate_and_consume_password_reset("first")
            .await
            .unwrap();
        assert!(r1.is_none());

        // Second token works.
        let r2 = store
            .validate_and_consume_password_reset("second")
            .await
            .unwrap();
        assert_eq!(r2, Some("a1".to_string()));
    }

    #[tokio::test]
    async fn test_update_admin_password() {
        let store = test_store().await;
        store.create_team("t1", "team").await.unwrap();
        store
            .create_user_with_membership("a1", "t1", "user@example.com", "oldhash", "owner")
            .await
            .unwrap();

        store.update_user_password("a1", "newhash").await.unwrap();

        let admin = store
            .get_user_by_email("user@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin.password_hash, "newhash");
    }

    /// The identity/membership backfill collapses a person who appears on
    /// multiple teams (same email, two admin rows) into ONE user with TWO
    /// memberships, and picks the oldest admin row as the canonical user id.
    #[tokio::test]
    async fn test_backfill_identity_from_admins() {
        let store = test_store().await;
        store.create_team("t1", "team-one").await.unwrap();
        store.create_team("t2", "team-two").await.unwrap();

        // The legacy `admins` table is no longer in SCHEMA (and `new()` drops it
        // during test_store setup), so recreate it here to prove the migration
        // path still works against pre-existing admin data.
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS admins (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                email_verified BOOLEAN NOT NULL DEFAULT FALSE,
                is_owner BOOLEAN NOT NULL DEFAULT FALSE,
                member_role TEXT NOT NULL DEFAULT 'admin',
                display_name TEXT,
                matrix_user_id TEXT,
                telegram_user_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(store.pool())
        .await
        .unwrap();

        // Insert legacy `admins` rows directly via raw SQL — the high-level
        // `create_admin` helper has been removed in the identity/membership
        // cutover, but the backfill must still process pre-existing admin rows.
        // created_at ordering matters: a1 (oldest) is the canonical identity.
        let insert_admin = |id: &'static str,
                            team: &'static str,
                            email: &'static str,
                            hash: &'static str,
                            role: &'static str,
                            created_at: String| {
            let pool = store.pool().clone();
            async move {
                sqlx::query(
                    "INSERT INTO admins (id, team_id, email, password_hash, email_verified, is_owner, member_role, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, FALSE, $5, $6, $7, $7)",
                )
                .bind(id)
                .bind(team)
                .bind(email)
                .bind(hash)
                .bind(role == "owner")
                .bind(role)
                .bind(created_at)
                .execute(&pool)
                .await
                .unwrap();
            }
        };
        // a1 (team-one) is created first → canonical identity for the email.
        insert_admin(
            "a1",
            "t1",
            "person@example.com",
            "hash-one",
            "owner",
            "2020-01-01T00:00:00Z".to_string(),
        )
        .await;
        insert_admin(
            "a2",
            "t2",
            "person@example.com",
            "hash-two",
            "approver",
            "2020-02-01T00:00:00Z".to_string(),
        )
        .await;
        // A distinct person on a single team.
        insert_admin(
            "b1",
            "t1",
            "solo@example.com",
            "hash-solo",
            "admin",
            "2020-01-01T00:00:00Z".to_string(),
        )
        .await;

        store.backfill_identity_from_admins().await.unwrap();
        // Idempotent: a second run must not duplicate or change anything.
        store.backfill_identity_from_admins().await.unwrap();

        // One user per email; canonical id = oldest admin row; password from it.
        let person = store
            .get_user_by_email("person@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(person.id, "a1");
        assert_eq!(person.password_hash, "hash-one");

        // Two memberships for that one user, with the per-team roles preserved.
        let mut teams = store.list_user_teams("a1").await.unwrap();
        teams.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(teams.len(), 2);
        assert_eq!(teams[0], ("t1".into(), "team-one".into(), "owner".into()));
        assert_eq!(
            teams[1],
            ("t2".into(), "team-two".into(), "approver".into())
        );

        // Resolving the member in team-two yields the team-two role.
        let in_t2 = store.get_member("a1", "t2").await.unwrap().unwrap();
        assert_eq!(in_t2.member_role, "approver");
        assert_eq!(in_t2.email, "person@example.com");

        // The solo person is unaffected.
        let solo = store
            .get_user_by_email("solo@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(solo.id, "b1");
        assert_eq!(store.list_user_teams("b1").await.unwrap().len(), 1);
    }

    /// Regression for #34: `email_verified` proves ownership of the *email*, not
    /// a team membership, so the backfill must OR it across ALL of a person's
    /// legacy admin rows — not read it off the oldest row. A multi-team user
    /// whose OLDEST row is unverified but who verified on a LATER team must
    /// migrate to `email_verified = true`, or they get locked out at login.
    #[tokio::test]
    async fn test_backfill_or_s_email_verified_across_teams() {
        let store = test_store().await;
        store.create_team("t1", "team-one").await.unwrap();
        store.create_team("t2", "team-two").await.unwrap();
        store.create_team("t3", "team-three").await.unwrap();

        // The legacy `admins` table is no longer in SCHEMA (dropped in the
        // identity/membership cutover), so recreate it to exercise the backfill
        // against pre-existing admin data.
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS admins (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                email_verified BOOLEAN NOT NULL DEFAULT FALSE,
                is_owner BOOLEAN NOT NULL DEFAULT FALSE,
                member_role TEXT NOT NULL DEFAULT 'admin',
                display_name TEXT,
                matrix_user_id TEXT,
                telegram_user_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(store.pool())
        .await
        .unwrap();

        // Raw inserts so we control email_verified per row (the high-level
        // helper hardcodes it). created_at ordering: the FIRST row is oldest.
        let insert = |id: &'static str,
                      team: &'static str,
                      email: &'static str,
                      verified: bool,
                      created_at: &'static str| {
            let pool = store.pool().clone();
            async move {
                sqlx::query(
                    "INSERT INTO admins (id, team_id, email, password_hash, email_verified, is_owner, member_role, created_at, updated_at)
                     VALUES ($1, $2, $3, 'h', $4, TRUE, 'owner', $5, $5)",
                )
                .bind(id).bind(team).bind(email).bind(verified).bind(created_at)
                .execute(&pool).await.unwrap();
            }
        };

        // multi@: oldest row (t1) UNVERIFIED, later row (t2) VERIFIED.
        // Pre-#34 this migrated to email_verified=false (the prod bug).
        insert(
            "m1",
            "t1",
            "multi@example.com",
            false,
            "2020-01-01T00:00:00Z",
        )
        .await;
        insert(
            "m2",
            "t2",
            "multi@example.com",
            true,
            "2020-02-01T00:00:00Z",
        )
        .await;
        // never@: on two teams, never verified anywhere → must stay false.
        insert(
            "n1",
            "t1",
            "never@example.com",
            false,
            "2020-01-01T00:00:00Z",
        )
        .await;
        insert(
            "n2",
            "t3",
            "never@example.com",
            false,
            "2020-03-01T00:00:00Z",
        )
        .await;

        store.backfill_identity_from_admins().await.unwrap();

        let multi = store
            .get_user_by_email("multi@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(multi.id, "m1", "identity still comes from the oldest row");
        assert!(
            multi.email_verified,
            "verified on a later team ⇒ user is verified (#34)"
        );

        let never = store
            .get_user_by_email("never@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !never.email_verified,
            "unverified on every team ⇒ stays unverified"
        );
    }

    /// Regression test: every column that was historically INTEGER (int4) but is
    /// read via try_get::<i64> must be BIGINT in the schema.  If a column stays
    /// int4, sqlx silently decodes NULL fine but panics/errors on any non-NULL
    /// value because int4 sends 4 bytes while i64 expects 8.
    ///
    /// This test inserts non-NULL values into every such column and reads them
    /// back, catching type mismatches at test time instead of in production.
    #[tokio::test]
    async fn schema_integer_columns_decode_as_i64() {
        use crate::types::{AuditEntry, HttpMethod};
        use uuid::Uuid;

        let store = test_store().await;
        store.create_team("t1", "Test").await.unwrap();

        // agents.rate_limit_per_hour (BIGINT, Option<i64>)
        store
            .create_agent("t1", "bot", None, "hash1", Some(100))
            .await
            .unwrap();
        let agent = store.get_agent("t1", "bot").await.unwrap().unwrap();
        assert_eq!(
            agent.rate_limit_per_hour,
            Some(100i64),
            "agents.rate_limit_per_hour must be BIGINT"
        );

        // roles.rate_limit_per_hour (BIGINT, Option<i64>)
        store.create_role("t1", "r1", None, Some(50)).await.unwrap();
        let roles = store.list_roles("t1").await.unwrap();
        let role = roles.iter().find(|r| r.name == "r1").unwrap();
        assert_eq!(
            role.rate_limit_per_hour,
            Some(50i64),
            "roles.rate_limit_per_hour must be BIGINT"
        );

        // audit_log — total_latency_ms (NOT NULL i64), upstream_status/latency (Option<i64>)
        let entry = AuditEntry {
            request_id: Uuid::new_v4(),
            agent_id: "bot".to_string(),
            credential_names: vec!["c1".to_string()],
            target_url: "https://example.com".to_string(),
            method: HttpMethod::Get,
            approval_status: None,
            upstream_status: Some(200),
            total_latency_ms: 999,
            approval_latency_ms: Some(500),
            upstream_latency_ms: Some(300),
            response_sanitized: false,
            end_user_id: None,
            request_headers: vec![],
            request_body: None,
            request_body_truncated: false,
            policy_reason: None,
            require_passkey: false,
            approver_identity: None,
            timestamp: chrono::Utc::now(),
        };
        store.write_audit_entry(&entry).await.unwrap();
        let entries = store.read_audit_entries("bot", 10).await.unwrap();
        let found = entries
            .iter()
            .find(|e| e.request_id == entry.request_id)
            .unwrap();
        assert_eq!(
            found.total_latency_ms, 999,
            "audit_log.total_latency_ms must be BIGINT"
        );
        assert_eq!(
            found.upstream_status,
            Some(200),
            "audit_log.upstream_status must be BIGINT"
        );
        assert_eq!(
            found.approval_latency_ms,
            Some(500),
            "audit_log.approval_latency_ms must be BIGINT"
        );
        assert_eq!(
            found.upstream_latency_ms,
            Some(300),
            "audit_log.upstream_latency_ms must be BIGINT"
        );

        // async_approvals.response_status (BIGINT, decoded as Option<i64> → cast to u16)
        let now = chrono::Utc::now();
        let expires = (now + chrono::Duration::seconds(60)).to_rfc3339();
        store
            .create_async_approval("txn1", "bot", "t1", &expires)
            .await
            .unwrap();
        store
            .resolve_async_approval("txn1", "forwarded", Some(201), None, None, None)
            .await
            .unwrap();
        let approval = store.get_async_approval("txn1").await.unwrap().unwrap();
        assert_eq!(
            approval.response_status,
            Some(201),
            "async_approvals.response_status must be BIGINT"
        );

        // pending_approvals.approval_count and min_approvals (BIGINT NOT NULL)
        // Save a pending approval and read the raw columns directly.
        store
            .save_pending_approval("txn2", r#"{"detail":"test"}"#, &expires)
            .await
            .unwrap();
        let row = sqlx::query(
            "SELECT approval_count, min_approvals FROM pending_approvals WHERE txn_id = $1",
        )
        .bind("txn2")
        .fetch_one(store.pool())
        .await
        .unwrap();
        let count: i64 = row
            .try_get::<i64, _>("approval_count")
            .expect("pending_approvals.approval_count must be BIGINT");
        let min: i64 = row
            .try_get::<i64, _>("min_approvals")
            .expect("pending_approvals.min_approvals must be BIGINT");
        assert_eq!(count, 0);
        assert_eq!(min, 1);
    }

    /// The Telegram ⏳ grant guard reads persisted `min_approvals` on an
    /// instance that never held the in-memory pending row, so it must hold
    /// cross-instance.
    #[tokio::test]
    async fn get_pending_approval_min_approvals_reads_persisted_value() {
        let store = test_store().await;
        let expires = (chrono::Utc::now() + chrono::Duration::minutes(20)).to_rfc3339();

        // A single-approval request defaults to min_approvals = 1.
        store
            .save_pending_approval("txn-solo", r#"{"detail":"x"}"#, &expires)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_pending_approval_min_approvals("txn-solo")
                .await
                .unwrap(),
            Some(1)
        );

        // A multi-approval request persists min_approvals > 1 — the value a
        // fresh replica must see to refuse a single-manager grant.
        store
            .set_pending_approval_matrix_data("txn-multi", "!room:x", "$evt", "[]", 3)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_pending_approval_min_approvals("txn-multi")
                .await
                .unwrap(),
            Some(3)
        );

        // A missing row is None (guard falls through to allow, same as before).
        assert_eq!(
            store
                .get_pending_approval_min_approvals("txn-absent")
                .await
                .unwrap(),
            None
        );
    }

    /// cleanup_expired_rows deletes resolved pending_approvals and all expired
    /// async_approvals, leaving pending rows and unexpired async rows intact.
    /// New signups start autonomous, but this must NOT reach back and change
    /// teams that already exist — they keep whatever posture is stored, and the
    /// unknown/missing-row path still fails safe. All three halves are asserted
    /// together because the risk here is silently flipping existing customers
    /// from gated to autonomous.
    #[tokio::test]
    async fn new_teams_are_autonomous_but_existing_and_unknown_stay_gated() {
        let store = test_store().await;

        // 1. A genuinely new team (the signup path) is autonomous.
        store.create_team("t-new", "New Team").await.unwrap();
        assert_eq!(
            store.get_team_default_approval_mode("t-new").await.unwrap(),
            crate::config::ApprovalMode::Autonomous,
            "a newly created team should start autonomous"
        );

        // 2. A team that predates this change — i.e. a row already carrying the
        //    backfilled 'gated' — is untouched. Simulated by writing the value
        //    an existing row would hold.
        store.create_team("t-old", "Old Team").await.unwrap();
        sqlx::raw_sql("UPDATE teams SET default_approval_mode = 'gated' WHERE id = 't-old'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store.get_team_default_approval_mode("t-old").await.unwrap(),
            crate::config::ApprovalMode::Gated,
            "an existing gated team must keep its posture"
        );

        // 3. Fail-safe paths are unchanged: an unknown value and a missing row
        //    both resolve to Gated, never autonomous.
        sqlx::raw_sql("UPDATE teams SET default_approval_mode = 'bogus' WHERE id = 't-old'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store.get_team_default_approval_mode("t-old").await.unwrap(),
            crate::config::ApprovalMode::Gated,
            "an unrecognized stored value must fail safe to gated"
        );
        assert_eq!(
            store
                .get_team_default_approval_mode("t-does-not-exist")
                .await
                .unwrap(),
            crate::config::ApprovalMode::Gated,
            "a missing team row must fail safe to gated"
        );
    }

    #[tokio::test]
    async fn cleanup_expired_rows_removes_stale_data() {
        let store = test_store().await;
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let future = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();

        // pending_approvals: resolved + expired → should be deleted
        store
            .save_pending_approval("pa-resolved-expired", "{}", &past)
            .await
            .unwrap();
        store
            .resolve_pending_approval("pa-resolved-expired", "approved", None)
            .await
            .unwrap();

        // pending_approvals: still pending + expired → must NOT be deleted
        // (wait_for_decision needs to atomically claim it as timed-out first)
        store
            .save_pending_approval("pa-pending-expired", "{}", &past)
            .await
            .unwrap();

        // pending_approvals: resolved + not yet expired → must NOT be deleted
        store
            .save_pending_approval("pa-resolved-fresh", "{}", &future)
            .await
            .unwrap();
        store
            .resolve_pending_approval("pa-resolved-fresh", "denied", None)
            .await
            .unwrap();

        // async_approvals: expired → should be deleted (holds response body)
        store
            .create_async_approval("aa-expired", "bot", "team", &past)
            .await
            .unwrap();
        store
            .resolve_async_approval(
                "aa-expired",
                "forwarded",
                Some(200),
                None,
                Some(b"secret AI response"),
                None,
            )
            .await
            .unwrap();

        // async_approvals: not yet expired → must NOT be deleted
        store
            .create_async_approval("aa-fresh", "bot", "team", &future)
            .await
            .unwrap();

        let (pending_deleted, async_deleted) = store.cleanup_expired_rows().await.unwrap();
        assert_eq!(
            pending_deleted, 1,
            "only the resolved+expired pending row deleted"
        );
        assert_eq!(async_deleted, 1, "only the expired async row deleted");

        // Verify surviving rows are still there
        assert!(store
            .get_pending_approval_status("pa-pending-expired")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_pending_approval_status("pa-resolved-fresh")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_async_approval("aa-fresh")
            .await
            .unwrap()
            .is_some());

        // Verify deleted rows are gone
        assert!(store
            .get_pending_approval_status("pa-resolved-expired")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get_async_approval("aa-expired")
            .await
            .unwrap()
            .is_none());
    }
}
