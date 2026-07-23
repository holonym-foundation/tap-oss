//! Internal service endpoints backing `tap-mcp`'s durable OAuth token state.
//!
//! # Why these exist
//!
//! `tap-proxy` runs inside an Azure confidential container group whose workload
//! is attested and measured — the KEK that decrypts credential blobs is released
//! only to that measured workload. `tap-mcp` is a *separate*, non-enclave,
//! internet-facing OAuth server (its own image, its own ACI).
//!
//! Giving `tap-mcp` a direct `POSTGRES_DATABASE_URL` put DB credentials for the
//! database holding encrypted credential blobs into a process outside the
//! enclave boundary. That is the wrong trust boundary regardless of what the
//! process *intends* to query — the connection string is the capability.
//!
//! So `tap-mcp` keeps zero DB access and calls the proxy (which it already talks
//! to for `/forward`) over two narrow, authenticated endpoints:
//!
//! | endpoint                            | when                 |
//! |-------------------------------------|----------------------|
//! | `POST /internal/mcp/token/issue`    | `authorization_code` grant |
//! | `POST /internal/mcp/token/refresh`  | `refresh_token` grant      |
//!
//! Both are **low-frequency OAuth ceremony operations** (connect + refresh),
//! never the per-request hot path, so the added hop costs nothing that matters.
//! The two hot-path operations deliberately stay on the direct DB path *inside*
//! the proxy: `mcp_tokens::family_is_active` (per `/forward`, in
//! `mcp_auth::resolve_mcp_agent`) and `revoke_families_for_agent` (dashboard
//! disconnect).
//!
//! # These endpoints MINT — they do not merely record
//!
//! Earlier revisions exposed `token-family` (record), `token-family/rotate` and
//! `auth-code/consume`, and `tap-mcp` minted the tokens itself with a copy of
//! `TAP_MCP_SIGNING_KEY`. That handed an internet-facing service outside the
//! enclave the authority to forge an access token for **any** team and agent —
//! the token payload carries `team_id`/`agent_id`, and the proxy verified it
//! with the same symmetric key. Those three endpoints are gone; issuing is now
//! the proxy's, and the code-consume / family-record / family-rotate steps
//! happen *inside* issue and refresh, where they belong.
//!
//! **Identity is never caller-supplied.** `/token/issue` takes the proxy's own
//! authorization assertion — signed with the proxy-only key after a fresh
//! passkey ceremony — re-verifies it, and derives `subject`/`team_id` from it,
//! then re-derives `agent_id` via `ensure_mcp_agent`. `tap-mcp` cannot assert
//! who the user is; it can only relay an assertion the proxy already made.
//! `/token/refresh` likewise reads identity out of a refresh token the proxy
//! itself signed.
//!
//! # Atomicity is preserved verbatim
//!
//! The HTTP layer adds no read-then-write. `rotate_family` remains a single
//! `UPDATE … WHERE current_jti = $old AND NOT revoked … RETURNING` and
//! `consume_code` a single `INSERT … ON CONFLICT DO NOTHING`; issue consumes the
//! authorization code **before** recording a family, so a replayed code cannot
//! open a second one. A rejection is reported as `{"issued": false, "reason":
//! …}` with a **200** — "rejected" is a normal, expected outcome, not a
//! transport error, so replay detection stays distinguishable from a network
//! blip (which `tap-mcp` treats as fail-closed).
//!
//! # Authentication
//!
//! A shared secret in `TAP_MCP_SERVICE_KEY`, presented as `X-TAP-Service-Key`
//! and compared in constant time. **Fail closed:** when the variable is unset or
//! empty on the proxy these routes return 404 and do nothing — they are never
//! open. This is deliberately *not* `TAP_MCP_SIGNING_KEY`: that key mints
//! tokens and `tap-mcp` must never hold it. The service key is an *identity*
//! for calling these endpoints, nothing more — presenting it proves only that
//! the caller is tap-mcp, never who the end user is.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::proxy::AppState;

/// Header carrying the shared service secret.
pub(crate) const SERVICE_KEY_HEADER: &str = "X-TAP-Service-Key";
/// Env var holding it, on BOTH the proxy and tap-mcp.
pub(crate) const SERVICE_KEY_ENV: &str = "TAP_MCP_SERVICE_KEY";

/// The configured service key, or `None` when unset/empty (⇒ endpoints disabled).
fn configured_service_key() -> Option<String> {
    let key = std::env::var(SERVICE_KEY_ENV).ok()?;
    let key = key.trim().to_string();
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

/// Constant-time secret comparison. Both sides are hashed to a fixed 32 bytes
/// first (mirroring `auth::hash_api_key`), so neither the content nor the
/// *length* of the presented value leaks through timing.
fn secrets_match(presented: &str, expected: &str) -> bool {
    let presented = Sha256::digest(presented.as_bytes());
    let expected = Sha256::digest(expected.as_bytes());
    presented
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Gate every internal endpoint. `Some(response)` is a rejection that
/// short-circuits the handler; `None` means the caller is authorized.
///
/// - No key configured ⇒ **404**: the surface does not exist at all, so a
///   misconfigured deploy cannot silently expose an unauthenticated write path.
/// - Missing/wrong key ⇒ **401**.
fn reject_unauthorized_service(headers: &HeaderMap) -> Option<Response> {
    let Some(expected) = configured_service_key() else {
        tracing::warn!(
            "rejected an /internal/mcp request: {SERVICE_KEY_ENV} is not configured on the proxy"
        );
        return Some(
            (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
        );
    };
    let presented = headers
        .get(SERVICE_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if presented.is_empty() || !secrets_match(presented, &expected) {
        tracing::warn!("rejected an /internal/mcp request: invalid or missing service key");
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid service key"})),
            )
                .into_response(),
        );
    }
    None
}

fn store_error(context: &'static str, error: tap_core::error::AgentSecError) -> Response {
    tracing::error!(%error, "{context}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": context})),
    )
        .into_response()
}

/// A fresh, unguessable id (128 bits, base64url) for a refresh-token family or
/// its rotating jti. Generated **by the proxy**, so `tap-mcp` cannot choose a
/// family id and collide with or overwrite another connection's.
fn new_random_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A rejection that is a normal OAuth outcome, not a fault: 200 with
/// `{"issued": false, "reason": …}`. `tap-mcp` maps these to `invalid_grant`.
fn rejected(reason: &'static str) -> Response {
    tracing::warn!(reason, "refused an MCP token issuance");
    Json(json!({"issued": false, "reason": reason})).into_response()
}

fn issued(tokens: crate::mcp_auth::IssuedTokens) -> Response {
    Json(json!({
        "issued": true,
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_in": tokens.expires_in,
    }))
    .into_response()
}

/// A signing/configuration fault on the proxy — never the caller's doing.
fn signing_error(error: crate::mcp_auth::McpAuthError) -> Response {
    tracing::error!(%error, "could not mint MCP tokens");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "Could not mint MCP tokens"})),
    )
        .into_response()
}

/// `POST /internal/mcp/token/issue` — the `authorization_code` grant's minting
/// step.
///
/// The request carries the **proxy's own authorization assertion** (relayed by
/// `tap-mcp` from the authorization code it issued), the OAuth `client_id`, and
/// the authorization code's `jti` for single-use consumption.
///
/// Deliberately **absent** from this body: `team_id`, `agent_id`, `scope`. Those
/// are authority. `team_id`/`subject` come from the re-verified assertion,
/// `agent_id` from `ensure_mcp_agent`, and `scope` is the fixed `tap:full`.
/// `client_id` *is* accepted — `tap-mcp` owns Dynamic Client Registration, so it
/// is authoritative for client identity, and the value only binds the refresh
/// token to that OAuth client.
#[derive(Debug, Deserialize)]
pub(crate) struct IssueTokenRequest {
    pub assertion: String,
    pub client_id: String,
    pub code_jti: String,
    pub code_expires_at: i64,
}

pub(crate) async fn handle_issue_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueTokenRequest>,
) -> Response {
    if let Some(rejection) = reject_unauthorized_service(&headers) {
        return rejection;
    }
    let now = Utc::now().timestamp();

    // 1. Re-verify the assertion with the proxy-only key. This is what makes the
    //    caller unable to assert an identity of its own choosing.
    let assertion = match crate::mcp_auth::verify_assertion_for_redemption(&request.assertion, now)
    {
        Ok(assertion) => assertion,
        Err(_) => return rejected("assertion_invalid"),
    };
    if request.code_jti.is_empty() {
        return rejected("code_jti_missing");
    }

    // 2. Derive the agent from the verified subject/team — never from the body.
    let agent_id = match crate::mcp_auth::ensure_mcp_agent(
        state.db_state.store(),
        &assertion.team_id,
        &assertion.subject,
    )
    .await
    {
        Ok(agent_id) => agent_id,
        Err(error) => return store_error("Could not provision the MCP agent", error),
    };

    // 3. Consume the authorization code exactly once, BEFORE opening a family,
    //    so a replayed code can never yield a second live family.
    match tap_core::mcp_tokens::consume_code(
        state.db_state.store().pool(),
        &request.code_jti,
        request.code_expires_at,
        now,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return rejected("code_already_used"),
        Err(error) => return store_error("Could not consume the MCP authorization code", error),
    }

    // 4. Record the revocable refresh-token family, then mint.
    let family_id = new_random_id();
    let refresh_jti = new_random_id();
    let refresh_expires_at = now + REFRESH_TOKEN_FAMILY_LIFETIME_SECONDS;
    if let Err(error) = tap_core::mcp_tokens::record_family(
        state.db_state.store().pool(),
        &family_id,
        &assertion.subject,
        &assertion.team_id,
        &agent_id,
        &request.client_id,
        &refresh_jti,
        now,
        refresh_expires_at,
    )
    .await
    {
        return store_error("Could not record the MCP token family", error);
    }

    match crate::mcp_auth::mint_token_pair(
        &assertion.subject,
        &assertion.team_id,
        &agent_id,
        &request.client_id,
        &family_id,
        &refresh_jti,
        refresh_expires_at,
        now,
    ) {
        Ok(tokens) => {
            tracing::info!(
                family_id = %family_id,
                team_id = %assertion.team_id,
                agent_id = %agent_id,
                "issued MCP token pair"
            );
            issued(tokens)
        }
        Err(error) => signing_error(error),
    }
}

/// Absolute lifetime of a refresh-token *family*. Rotated tokens carry the
/// original expiry forward, so a connection renews silently for this long and
/// then requires a fresh login + passkey. Mirrors tap-mcp's former constant; the
/// proxy is now authoritative for it.
const REFRESH_TOKEN_FAMILY_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

/// `POST /internal/mcp/token/refresh` — the `refresh_token` grant.
///
/// The proxy verifies the token it signed itself (expiry, client binding, RFC
/// 8707 audience), then atomically rotates the family in a single
/// `UPDATE … RETURNING`. A replayed, superseded, revoked or expired token
/// matches no row ⇒ `{"issued": false}`. Identity for the new pair is read out
/// of the old token's proxy-signed claims, so a refresh cannot escalate to a
/// different team or agent.
///
/// `now` is deliberately not accepted from the caller: the proxy stamps its own
/// clock, so `tap-mcp` cannot extend a family past its expiry by lying.
#[derive(Debug, Deserialize)]
pub(crate) struct RefreshTokenRequest {
    pub refresh_token: String,
    pub client_id: String,
    #[serde(default)]
    pub resource: Option<String>,
}

pub(crate) async fn handle_refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RefreshTokenRequest>,
) -> Response {
    if let Some(rejection) = reject_unauthorized_service(&headers) {
        return rejection;
    }
    let now = Utc::now().timestamp();
    let claims = match crate::mcp_auth::verify_refresh_token(
        &request.refresh_token,
        &request.client_id,
        request.resource.as_deref(),
        now,
    ) {
        Ok(claims) => claims,
        Err(_) => return rejected("refresh_token_invalid"),
    };

    let new_jti = new_random_id();
    match tap_core::mcp_tokens::rotate_family(
        state.db_state.store().pool(),
        &claims.family_id,
        &claims.jti,
        &new_jti,
        now,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => return rejected("refresh_token_superseded"),
        Err(error) => return store_error("Could not rotate the MCP token family", error),
    }

    match crate::mcp_auth::mint_token_pair(
        &claims.subject,
        &claims.team_id,
        &claims.agent_id,
        &claims.client_id,
        &claims.family_id,
        &new_jti,
        // Keep the family expiry — rotation renews the token, not the family.
        claims.expires_at,
        now,
    ) {
        Ok(tokens) => {
            tracing::info!(family_id = %claims.family_id, "rotated MCP token pair");
            issued(tokens)
        }
        Err(error) => signing_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_comparison_accepts_only_the_exact_value() {
        assert!(secrets_match("s3cret-value", "s3cret-value"));
        assert!(!secrets_match("s3cret-value", "s3cret-valuf"));
        // A prefix must not pass — the hash step also hides the length.
        assert!(!secrets_match("s3cret", "s3cret-value"));
        assert!(!secrets_match("", "s3cret-value"));
    }
}
