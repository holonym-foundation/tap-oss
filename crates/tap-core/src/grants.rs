//! Shared "create a time-boxed grant from an approved request" core (#49).
//!
//! The dashboard inbox, the Telegram button, and the Matrix reaction all mint
//! grants the same way: the scope is DERIVED from the request the human just
//! reviewed (this credential, this method, host-pinned route) — never typed —
//! and the same guardrails apply everywhere. This module is in `tap-core` so
//! `tap-bot` can reach it without depending on `tap-proxy`.
//!
//! Callers resolve the pending approval FIRST (the atomic claim), then call
//! [`create_grant_for_request`]: a concurrent deny wins and no grant appears
//! on top of it; a grant failure after a successful claim leaves the request
//! approved with no window (fail toward fewer auto-approvals).

use crate::error::AgentSecError;
use crate::store::{ConfigStore, GrantRow};

/// Hard cap on a grant's TTL. A grant is a temporary exception, not a policy —
/// anything that should outlive a day belongs in `auto_approve_urls` where it
/// is visible as standing configuration.
pub const GRANT_MAX_TTL_MINUTES: i64 = 24 * 60;

/// TTL used by the one-tap messaging surfaces (the Telegram button and the
/// Matrix reaction). The dashboard inbox offers a duration picker; the
/// messaging surfaces keep one sensible default.
pub const GRANT_DEFAULT_TTL_MINUTES: i64 = 30;

/// Why a grant could not be minted for an otherwise-approvable request.
/// Callers surface `message()` to the human; the request itself may still be
/// approved normally.
#[derive(Debug)]
pub enum GrantRefused {
    /// `eu:` end-user credentials are governed by the passkey-lock ceremony —
    /// a manager-issued grant would loosen enforcement without the end-user's
    /// consent.
    EndUserCredential,
    /// The credential's live policy demands passkey approval; if a write is
    /// worth a passkey ceremony, it is worth a human on every request.
    PasskeyRequired,
    /// No concrete scope could be derived from the target URL (unparseable,
    /// or a dotless host that can't be expressed as a concrete pattern).
    ScopeUnderivable,
    /// TTL outside 1..=GRANT_MAX_TTL_MINUTES, or max_uses < 1.
    BadBounds,
    Store(AgentSecError),
}

impl GrantRefused {
    pub fn message(&self) -> String {
        match self {
            GrantRefused::EndUserCredential => {
                "End-user credentials cannot be time-boxed".to_string()
            }
            GrantRefused::PasskeyRequired => {
                "This credential requires passkey approval and cannot be time-boxed".to_string()
            }
            GrantRefused::ScopeUnderivable => {
                "Could not derive a route scope from this request's target URL".to_string()
            }
            GrantRefused::BadBounds => format!(
                "Grant TTL must be between 1 and {GRANT_MAX_TTL_MINUTES} minutes (and max uses at least 1)"
            ),
            GrantRefused::Store(e) => format!("Grant could not be stored: {e}"),
        }
    }
}

/// Derive the narrowest useful grant scope from a concrete target URL:
/// `host/path` (host-pinned path prefix), or just `host` when the path is `/`.
/// Returns None for unparseable or hostless/dotless URLs (no scope → no
/// grant, fail closed). The query string is deliberately dropped: it never
/// participates in pattern matching.
pub fn scope_from_target(target_url: &str) -> Option<String> {
    let parsed = url::Url::parse(target_url).ok()?;
    let host = parsed.host_str()?;
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    let path = parsed.path();
    if path == "/" || path.is_empty() {
        Some(host.to_string())
    } else {
        Some(format!("{host}{path}"))
    }
}

/// Mint a grant scoped to exactly one reviewed request. Re-checks every
/// guardrail regardless of caller (defense-in-depth): `eu:` exclusion, the
/// LIVE `require_passkey` policy flag (the pending row's snapshot could be
/// stale), scope derivability, and TTL/use bounds. Does NOT resolve the
/// pending approval — the caller claims that first.
#[allow(clippy::too_many_arguments)]
pub async fn create_grant_for_request(
    store: &ConfigStore,
    team_id: &str,
    credential_name: &str,
    method: &str,
    target_url: &str,
    granted_by: &str,
    ttl_minutes: i64,
    max_uses: Option<i64>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<GrantRow, GrantRefused> {
    if credential_name.starts_with("eu:") {
        return Err(GrantRefused::EndUserCredential);
    }
    if !(1..=GRANT_MAX_TTL_MINUTES).contains(&ttl_minutes) {
        return Err(GrantRefused::BadBounds);
    }
    if let Some(n) = max_uses {
        if n < 1 {
            return Err(GrantRefused::BadBounds);
        }
    }
    match store.get_policy(team_id, credential_name).await {
        Ok(Some(p)) if p.require_passkey => return Err(GrantRefused::PasskeyRequired),
        Ok(_) => {}
        Err(e) => return Err(GrantRefused::Store(e)),
    }
    let Some(scope) = scope_from_target(target_url) else {
        return Err(GrantRefused::ScopeUnderivable);
    };

    let grant = GrantRow {
        id: uuid::Uuid::new_v4().to_string(),
        team_id: team_id.to_string(),
        credential_name: credential_name.to_string(),
        methods: vec![method.trim().to_uppercase()],
        route_scope: vec![scope],
        expires_at: (now + chrono::Duration::minutes(ttl_minutes)).to_rfc3339(),
        granted_by: granted_by.to_string(),
        max_uses,
        uses: 0,
        revoked: false,
        created_at: now.to_rfc3339(),
    };
    store
        .create_approval_grant(&grant)
        .await
        .map_err(GrantRefused::Store)?;
    Ok(grant)
}
