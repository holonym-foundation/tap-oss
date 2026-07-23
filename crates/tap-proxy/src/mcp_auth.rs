//! TAP-backed authorization for the remote MCP server.
//!
//! The dashboard keeps the user's full TAP session. After a fresh passkey
//! ceremony the proxy emits a short-lived, narrowly scoped **authorization
//! assertion**. The dashboard session token never crosses into the MCP service
//! or appears in a browser redirect.
//!
//! # Two keys, two trust domains
//!
//! `tap-mcp` is an internet-facing OAuth server running *outside* the attested
//! Azure confidential container group that `tap-proxy` runs in. HMAC is
//! symmetric, so holding a signing key is the authority to mint under **every**
//! domain label it covers — domain separation constrains a *value*, never a
//! *key holder*. The keys are therefore split by who must be trusted:
//!
//! | key | held by | signs / verifies |
//! |-----|---------|------------------|
//! | `TAP_MCP_SIGNING_KEY` | **tap-proxy only** | authorization assertions, OAuth **access tokens**, OAuth **refresh tokens** |
//! | `TAP_MCP_LOCAL_KEY`   | tap-mcp (+ proxy, verify-only) | tap-mcp's own artifacts: `authorization-request`, `dynamic-client`, `authorization-code` |
//!
//! Everything the proxy *acts on* — "this bearer is agent X of team Y" — is
//! signed by a key `tap-mcp` does not have, so a compromised `tap-mcp` cannot
//! forge a token for any team/agent. It must run the real ceremony and ask the
//! proxy to mint (`/internal/mcp/token/issue`), where identity is re-derived
//! from the proxy's own assertion.
//!
//! The proxy also holds `TAP_MCP_LOCAL_KEY`, but **verify-only and only** in
//! [`describe_authorization_request`], which turns a signed OAuth request into
//! display facts for the connect screen ("Claude (claude.ai) is asking"). That
//! is not a trust downgrade: `tap-mcp` owns Dynamic Client Registration, so it
//! is already authoritative for client identity — a compromised `tap-mcp` could
//! register any name with any redirect regardless of which key signed the blob.
//! The local key grants no authority over tokens.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use thiserror::Error;
use url::Url;

use crate::admin::authenticate_user;
use crate::proxy::AppState;
use tap_core::error::AgentSecError;
use tap_core::store::ConfigStore;

type HmacSha256 = Hmac<Sha256>;

const ASSERTION_KIND: &str = "tap-authorization-assertion";
/// HMAC domain of the OAuth access token. **The proxy is the sole issuer** (see
/// module docs) and the sole verifier, at `/forward`.
const ACCESS_TOKEN_KIND: &str = "access-token";
/// HMAC domain of the OAuth refresh token — likewise proxy-issued and
/// proxy-verified, so a rotation cannot be forged by `tap-mcp`.
const REFRESH_TOKEN_KIND: &str = "refresh-token";
const ASSERTION_LIFETIME_SECONDS: i64 = 2 * 60;
/// How long after issue an assertion may still be *redeemed* for tokens at
/// `/internal/mcp/token/issue`.
///
/// [`ASSERTION_LIFETIME_SECONDS`] bounds the browser-facing hop (dashboard →
/// tap-mcp callback). Redemption happens later in the same ceremony — the
/// client must still round-trip its redirect and POST `/token` — so enforcing
/// the 2-minute expiry there would reject legitimate flows. The anti-replay
/// control at redemption is not this window but the **single-use authorization
/// code**: `handle_issue_token` atomically consumes the code's `jti` before
/// minting, so one assertion yields at most one token family no matter how
/// often it is presented. This bound only caps how stale a ceremony may be.
const ASSERTION_REDEMPTION_WINDOW_SECONDS: i64 = 10 * 60;
/// Tolerance for clock skew between instances when judging `issued_at`.
const ASSERTION_CLOCK_SKEW_SECONDS: i64 = 30;
/// Access-token lifetime, surfaced to the OAuth client as `expires_in`. The
/// refresh-token *family* lifetime lives in `mcp_internal.rs`, next to the
/// issuing path that stamps it.
const ACCESS_TOKEN_LIFETIME_SECONDS: i64 = 60 * 60;
/// The only scope TAP issues (mirrors tap-mcp's `FULL_SCOPE`). Deliberately a
/// constant rather than a caller-supplied field: scope is authority, so it is
/// never taken from the `tap-mcp` request body.
const FULL_SCOPE: &str = "tap:full";
const MAX_AUTHORIZATION_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Error)]
pub(crate) enum McpAuthError {
    #[error("TAP_MCP_SIGNING_KEY is missing")]
    MissingSigningKey,
    #[error("TAP_MCP_SIGNING_KEY must contain at least 32 bytes")]
    SigningKeyTooShort,
    #[error("TAP_MCP_LOCAL_KEY is missing")]
    MissingLocalKey,
    #[error("TAP_MCP_LOCAL_KEY must contain at least 32 bytes")]
    LocalKeyTooShort,
    #[error("TAP_MCP_PUBLIC_URL is missing")]
    MissingPublicUrl,
    #[error("TAP_MCP_PUBLIC_URL is invalid: {0}")]
    InvalidPublicUrl(String),
    #[error("failed to serialize MCP authorization assertion")]
    Serialization,
    #[error("failed to sign MCP authorization assertion")]
    Signing,
    #[error("MCP authorization request is empty or too large")]
    InvalidRequest,
    #[error("MCP access token is invalid or expired")]
    InvalidToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TapAuthorizationAssertion {
    request: String,
    pub subject: String,
    pub team_id: String,
    /// The agent provisioned for this connection at ceremony time (see
    /// `ensure_mcp_agent`). **Advisory only.** At redemption the proxy calls
    /// `ensure_mcp_agent` again and uses *that* result, so the agent identity
    /// never depends on a value carried across the wire.
    #[serde(default)]
    agent_id: String,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct McpAuthorizationResponse {
    pub callback_url: String,
    pub assertion: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BeginAuthorizationRequest {
    request: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FinishAuthorizationRequest {
    request: String,
    passkey_token: String,
    credential: webauthn_rs_proto::PublicKeyCredential,
}

fn callback_url_from_env() -> Result<Url, McpAuthError> {
    let raw = std::env::var("TAP_MCP_PUBLIC_URL").map_err(|_| McpAuthError::MissingPublicUrl)?;
    let mut url =
        Url::parse(&raw).map_err(|error| McpAuthError::InvalidPublicUrl(error.to_string()))?;
    if url.cannot_be_a_base()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https"
            && !(url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))))
    {
        return Err(McpAuthError::InvalidPublicUrl(
            "expected an HTTPS origin (HTTP is allowed only on loopback)".to_string(),
        ));
    }
    url.set_path("/");
    url.join("authorize/callback")
        .map_err(|error| McpAuthError::InvalidPublicUrl(error.to_string()))
}

/// The proxy-only authority key. Signs and verifies assertions, access tokens
/// and refresh tokens. **Never set on tap-mcp** — that is the whole point of
/// the split (see module docs).
fn signing_key_from_env() -> Result<Arc<[u8]>, McpAuthError> {
    let key = std::env::var("TAP_MCP_SIGNING_KEY").map_err(|_| McpAuthError::MissingSigningKey)?;
    if key.len() < 32 {
        return Err(McpAuthError::SigningKeyTooShort);
    }
    Ok(Arc::from(key.into_bytes()))
}

/// tap-mcp's own key, held here **verify-only** and used solely by
/// [`describe_authorization_request`]. It confers no authority over tokens.
fn local_key_from_env() -> Result<Arc<[u8]>, McpAuthError> {
    let key = std::env::var("TAP_MCP_LOCAL_KEY").map_err(|_| McpAuthError::MissingLocalKey)?;
    if key.len() < 32 {
        return Err(McpAuthError::LocalKeyTooShort);
    }
    Ok(Arc::from(key.into_bytes()))
}

/// Sign `payload` under `kind` with `key`, producing tap-mcp's `body.signature`
/// wire format. The `kind` byte-stuffed prefix is the domain separator that
/// keeps value families mutually unusable *for a given key*.
fn sign_value<T: Serialize>(key: &[u8], kind: &str, payload: &T) -> Result<String, McpAuthError> {
    let payload = serde_json::to_vec(payload).map_err(|_| McpAuthError::Serialization)?;
    let body = URL_SAFE_NO_PAD.encode(payload);
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| McpAuthError::Signing)?;
    mac.update(kind.as_bytes());
    mac.update(&[0]);
    mac.update(body.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{body}.{signature}"))
}

fn sign_assertion(
    key: &[u8],
    assertion: &TapAuthorizationAssertion,
) -> Result<String, McpAuthError> {
    sign_value(key, ASSERTION_KIND, assertion)
}

/// Issue the short-lived assertion consumed by `tap-mcp` after a passkey has
/// authenticated `subject` for `team_id`.
pub(crate) fn issue_authorization_assertion(
    request: &str,
    subject: &str,
    team_id: &str,
    agent_id: &str,
) -> Result<McpAuthorizationResponse, McpAuthError> {
    if request.is_empty() || request.len() > MAX_AUTHORIZATION_REQUEST_BYTES {
        return Err(McpAuthError::InvalidRequest);
    }
    let now = Utc::now().timestamp();
    let assertion = TapAuthorizationAssertion {
        request: request.to_string(),
        subject: subject.to_string(),
        team_id: team_id.to_string(),
        agent_id: agent_id.to_string(),
        issued_at: now,
        expires_at: now + ASSERTION_LIFETIME_SECONDS,
    };
    let key = signing_key_from_env()?;
    Ok(McpAuthorizationResponse {
        callback_url: callback_url_from_env()?.to_string(),
        assertion: sign_assertion(&key, &assertion)?,
    })
}

/// Claims carried by the OAuth access token tap-mcp issues to the MCP client.
/// A subset of tap-mcp's `AccessTokenClaims` — only the fields the proxy needs
/// to act as the connection's agent.
#[derive(Debug, Deserialize)]
pub(crate) struct McpAccessClaims {
    pub subject: String,
    pub team_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub audience: String,
    /// Refresh-token family this access token belongs to. Checked for revocation
    /// at `/forward` time in [`resolve_mcp_agent`]. Empty only for the stateless
    /// demo path (no token store).
    #[serde(default)]
    pub family_id: String,
    #[serde(default)]
    pub expires_at: i64,
}

/// The MCP resource URL this proxy protects: `{TAP_MCP_PUBLIC_URL}/mcp`. The
/// access token's `audience` must equal it (RFC 8707) — mirrors tap-mcp's own
/// middleware, which rejects a token minted for a different resource.
fn resource_url_from_env() -> Result<String, McpAuthError> {
    let raw = std::env::var("TAP_MCP_PUBLIC_URL").map_err(|_| McpAuthError::MissingPublicUrl)?;
    let mut url =
        Url::parse(&raw).map_err(|error| McpAuthError::InvalidPublicUrl(error.to_string()))?;
    url.set_path("/");
    url.join("mcp")
        .map(|u| u.to_string())
        .map_err(|error| McpAuthError::InvalidPublicUrl(error.to_string()))
}

/// Verify an MCP OAuth access token (minted by tap-mcp with the shared signing
/// key under the `access-token` HMAC domain) and return its claims. Byte-for-
/// byte mirror of tap-mcp's `TokenSigner::verify`; fails closed on any mismatch,
/// expiry, missing agent/team, or absent `tap:full` scope. The `access-token`
/// domain separator makes an authorization assertion unusable here and vice
/// versa.
pub(crate) fn verify_mcp_access_token(token: &str) -> Result<McpAccessClaims, McpAuthError> {
    let key = signing_key_from_env()?;
    let claims: McpAccessClaims = verify_signed(&key, ACCESS_TOKEN_KIND, token)?;
    if claims.expires_at < Utc::now().timestamp() {
        return Err(McpAuthError::InvalidToken);
    }
    if claims.agent_id.is_empty() || claims.team_id.is_empty() {
        return Err(McpAuthError::InvalidToken);
    }
    if !claims.scope.split_ascii_whitespace().any(|s| s == "tap:full") {
        return Err(McpAuthError::InvalidToken);
    }
    // Audience binding (RFC 8707): a token minted for a different resource must
    // not be replayable at this proxy. Fail closed if the resource can't be
    // resolved (MCP is misconfigured).
    if claims.audience != resource_url_from_env()? {
        return Err(McpAuthError::InvalidToken);
    }
    Ok(claims)
}

/// HMAC domains of tap-mcp's signed authorization request and DCR client id.
/// Signed with **`TAP_MCP_LOCAL_KEY`** (tap-mcp's own artifacts); mirrored here
/// only so the connect screen can tell the user WHO is asking.
const AUTHORIZATION_REQUEST_KIND: &str = "authorization-request";
const DYNAMIC_CLIENT_KIND: &str = "dynamic-client";

/// Verify a signed value under an explicit `key` (byte-for-byte mirror of
/// tap-mcp's `TokenSigner::verify`). The `kind` domain separator keeps the value
/// families (access token, refresh token, authorization request, client id,
/// assertion) mutually unusable; the `key` argument keeps the two *trust
/// domains* separate, which the domain label alone cannot do.
fn verify_signed<T: serde::de::DeserializeOwned>(
    key: &[u8],
    kind: &str,
    token: &str,
) -> Result<T, McpAuthError> {
    let (body, signature) = token.split_once('.').ok_or(McpAuthError::InvalidToken)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| McpAuthError::InvalidToken)?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| McpAuthError::InvalidToken)?;
    mac.update(kind.as_bytes());
    mac.update(&[0]);
    mac.update(body.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| McpAuthError::InvalidToken)?;
    let payload = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| McpAuthError::InvalidToken)?;
    serde_json::from_slice(&payload).map_err(|_| McpAuthError::InvalidToken)
}

/// The fields of tap-mcp's signed `AuthorizationRequest` the proxy needs to
/// describe (extra fields are ignored by serde).
#[derive(Debug, Deserialize)]
struct McpAuthorizationRequestClaims {
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    expires_at: i64,
}

/// tap-mcp's DCR registration payload — the `client_id` IS this, signed.
#[derive(Debug, Deserialize)]
struct McpDynamicClient {
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    expires_at: i64,
}

pub(crate) struct McpClientDescription {
    pub client_name: String,
    pub client_origin: String,
    pub deny_url: String,
}

/// Resolve a signed MCP authorization request to the REGISTERED identity of
/// the client behind it — name and redirect origin from the signed DCR blob,
/// never from anything the browser could tamper with — plus a ready-made
/// deny URL (`redirect_uri?error=access_denied`, per RFC 6749 §4.1.2.1).
/// This is what lets the connect screen show "Claude (claude.ai) is asking"
/// instead of "this app", closing the OAuth-phishing gap where any link could
/// impersonate the user's own client.
pub(crate) fn describe_authorization_request(
    request: &str,
) -> Result<McpClientDescription, McpAuthError> {
    if request.is_empty() || request.len() > MAX_AUTHORIZATION_REQUEST_BYTES {
        return Err(McpAuthError::InvalidRequest);
    }
    let now = Utc::now().timestamp();
    // tap-mcp's own artifacts ⇒ its own key, held here verify-only.
    let key = local_key_from_env()?;
    let claims: McpAuthorizationRequestClaims =
        verify_signed(&key, AUTHORIZATION_REQUEST_KIND, request)?;
    if claims.expires_at < now {
        return Err(McpAuthError::InvalidRequest);
    }
    let client: McpDynamicClient = verify_signed(&key, DYNAMIC_CLIENT_KIND, &claims.client_id)?;
    if client.expires_at < now || !client.redirect_uris.contains(&claims.redirect_uri) {
        return Err(McpAuthError::InvalidRequest);
    }

    let redirect = Url::parse(&claims.redirect_uri).map_err(|_| McpAuthError::InvalidRequest)?;
    let host = redirect
        .host_str()
        .ok_or(McpAuthError::InvalidRequest)?
        .to_string();
    let client_origin = match redirect.port() {
        Some(port) => format!("{}://{host}:{port}", redirect.scheme()),
        None => format!("{}://{host}", redirect.scheme()),
    };

    let mut deny = redirect;
    deny.query_pairs_mut().append_pair("error", "access_denied");
    if let Some(state) = &claims.state {
        deny.query_pairs_mut().append_pair("state", state);
    }

    Ok(McpClientDescription {
        client_name: client
            .client_name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(host),
        client_origin,
        deny_url: deny.into(),
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct DescribeAuthorizationBody {
    request: String,
}

/// POST /mcp/authorization/describe — public: the signed request itself is the
/// capability; this only turns it into display facts (who is asking + a deny
/// URL) and mints nothing.
pub(crate) async fn handle_describe_authorization(
    Json(body): Json<DescribeAuthorizationBody>,
) -> Response {
    match describe_authorization_request(&body.request) {
        Ok(description) => Json(json!({
            "client_name": description.client_name,
            "client_origin": description.client_origin,
            "deny_url": description.deny_url,
        }))
        .into_response(),
        Err(
            error @ (McpAuthError::MissingSigningKey
            | McpAuthError::SigningKeyTooShort
            | McpAuthError::MissingLocalKey
            | McpAuthError::LocalKeyTooShort),
        ) => configuration_error(error),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "This connection request is invalid or has expired. Start the connection again from your MCP client."})),
        )
            .into_response(),
    }
}

/// Full claim set of a proxy-minted OAuth access token. `McpAccessClaims` is the
/// read-side subset used at `/forward`; this is the write side.
#[derive(Debug, Serialize)]
pub(crate) struct IssuedAccessClaims {
    pub subject: String,
    pub team_id: String,
    pub agent_id: String,
    pub client_id: String,
    pub audience: String,
    pub scope: String,
    pub family_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Claims of a proxy-minted refresh token. `family_id` names the durable,
/// revocable family row and `jti` is *this* token's position in it; a rotation
/// supersedes the old `jti`, so a replayed refresh matches no row.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RefreshClaims {
    pub subject: String,
    pub team_id: String,
    pub agent_id: String,
    pub client_id: String,
    pub audience: String,
    pub scope: String,
    pub family_id: String,
    pub jti: String,
    pub issued_at: i64,
    /// Fixed family expiry, carried unchanged through every rotation.
    pub expires_at: i64,
}

/// A freshly minted access/refresh pair.
pub(crate) struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// Mint an access/refresh pair under the proxy-only key. Both carry the same
/// `family_id`, so revoking the family kills the access token at `/forward`
/// (`resolve_mcp_agent`) and blocks rotation at once.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint_token_pair(
    subject: &str,
    team_id: &str,
    agent_id: &str,
    client_id: &str,
    family_id: &str,
    refresh_jti: &str,
    refresh_expires_at: i64,
    now: i64,
) -> Result<IssuedTokens, McpAuthError> {
    let key = signing_key_from_env()?;
    let audience = resource_url_from_env()?;
    let access = IssuedAccessClaims {
        subject: subject.to_string(),
        team_id: team_id.to_string(),
        agent_id: agent_id.to_string(),
        client_id: client_id.to_string(),
        audience: audience.clone(),
        scope: FULL_SCOPE.to_string(),
        family_id: family_id.to_string(),
        issued_at: now,
        expires_at: now + ACCESS_TOKEN_LIFETIME_SECONDS,
    };
    let refresh = RefreshClaims {
        subject: subject.to_string(),
        team_id: team_id.to_string(),
        agent_id: agent_id.to_string(),
        client_id: client_id.to_string(),
        audience,
        scope: FULL_SCOPE.to_string(),
        family_id: family_id.to_string(),
        jti: refresh_jti.to_string(),
        issued_at: now,
        expires_at: refresh_expires_at,
    };
    Ok(IssuedTokens {
        access_token: sign_value(&key, ACCESS_TOKEN_KIND, &access)?,
        refresh_token: sign_value(&key, REFRESH_TOKEN_KIND, &refresh)?,
        expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
    })
}

/// Verify a refresh token the proxy itself minted, and check the bindings that
/// do not depend on the database: expiry, the OAuth client it was issued to, and
/// the RFC 8707 audience. Family liveness is a separate atomic DB rotation.
pub(crate) fn verify_refresh_token(
    token: &str,
    client_id: &str,
    resource: Option<&str>,
    now: i64,
) -> Result<RefreshClaims, McpAuthError> {
    let key = signing_key_from_env()?;
    let claims: RefreshClaims = verify_signed(&key, REFRESH_TOKEN_KIND, token)?;
    if claims.expires_at < now
        || claims.client_id != client_id
        || claims.audience != resource_url_from_env()?
        || resource.is_some_and(|resource| resource != claims.audience)
        // A family-less token predates revocable families: force a fresh
        // connection rather than honour an unrevocable one.
        || claims.family_id.is_empty()
        || claims.jti.is_empty()
    {
        return Err(McpAuthError::InvalidToken);
    }
    Ok(claims)
}

/// Verify an authorization assertion presented for **redemption** at
/// `/internal/mcp/token/issue`.
///
/// This is the load-bearing step of the trust split: the proxy signed this
/// assertion itself after a fresh passkey ceremony, so re-verifying it here
/// re-derives `subject`/`team_id` from its own signature rather than trusting
/// anything `tap-mcp` asserts. See [`ASSERTION_REDEMPTION_WINDOW_SECONDS`] for
/// why the window differs from the browser-hop expiry.
pub(crate) fn verify_assertion_for_redemption(
    assertion: &str,
    now: i64,
) -> Result<TapAuthorizationAssertion, McpAuthError> {
    if assertion.is_empty() || assertion.len() > MAX_AUTHORIZATION_REQUEST_BYTES {
        return Err(McpAuthError::InvalidRequest);
    }
    let key = signing_key_from_env()?;
    let claims: TapAuthorizationAssertion = verify_signed(&key, ASSERTION_KIND, assertion)?;
    if claims.issued_at > now + ASSERTION_CLOCK_SKEW_SECONDS
        || now - claims.issued_at > ASSERTION_REDEMPTION_WINDOW_SECONDS
        || claims.subject.is_empty()
        || claims.team_id.is_empty()
    {
        return Err(McpAuthError::InvalidToken);
    }
    Ok(claims)
}

/// Ensure a dedicated **Account key** agent exists for this user's MCP
/// connection and return its id — Nanak's "full account scope = an API key with
/// all credentials". As an Account key (`all_credentials = true`) it is
/// authorized for every team credential, including ones added *after* the
/// connection (the per-credential whitelist is bypassed). Idempotent: re-login
/// reuses the same agent and re-asserts the flag.
///
/// The agent's `api_key_hash` is random with no known preimage, so it can never
/// be authenticated with a raw `X-TAP-Key` — the only way to act as it is the
/// MCP OAuth token verified by [`verify_mcp_access_token`]. So no TAP API key
/// ever leaves the proxy.
pub(crate) async fn ensure_mcp_agent(
    store: &ConfigStore,
    team_id: &str,
    subject: &str,
) -> Result<String, AgentSecError> {
    let agent_id = format!("mcp-{subject}");
    if store.get_agent(team_id, &agent_id).await?.is_none() {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        // Not a SHA-256 hex hash, so it matches no `hash_api_key` output ⇒ unusable.
        let unusable_hash = format!("mcp-no-key-{}", URL_SAFE_NO_PAD.encode(raw));
        store
            .create_agent(team_id, &agent_id, Some("MCP"), &unusable_hash, None)
            .await?;
    }
    store
        .set_agent_all_credentials(team_id, &agent_id, true)
        .await?;
    Ok(agent_id)
}

/// Resolve the agent behind an MCP OAuth bearer, if the request carries a valid
/// one. Returns `None` (never an error) when there is no bearer, the token does
/// not verify, or the provisioned agent is gone/disabled — callers then fall
/// back to the ordinary `X-TAP-Key` path or reject. This is the single seam that
/// lets an MCP connection use `/forward` + `/agent/services` as its provisioned
/// agent without ever holding a TAP API key.
pub(crate) async fn resolve_mcp_agent(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<crate::auth::AuthenticatedAgent> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .trim();
    let claims = verify_mcp_access_token(token).ok()?;
    tracing::debug!(
        subject = %claims.subject,
        agent_id = %claims.agent_id,
        "resolving MCP bearer to its provisioned agent"
    );
    // Refresh-token-family revocation: even though the short-lived access token
    // still verifies, a revoked (or expired) family means the connection was
    // disconnected — reject. Empty family_id is the stateless demo path (nothing
    // to check). A DB error fails closed (reject).
    if !claims.family_id.is_empty() {
        let active = tap_core::mcp_tokens::family_is_active(
            state.db_state.store().pool(),
            &claims.family_id,
            Utc::now().timestamp(),
        )
        .await
        .ok()?;
        if !active {
            tracing::debug!(family_id = %claims.family_id, "MCP token family revoked/expired");
            return None;
        }
    }
    let row = state
        .db_state
        .store()
        .get_agent(&claims.team_id, &claims.agent_id)
        .await
        .ok()??;
    if !row.enabled {
        return None;
    }
    let is_app = row.is_app();
    let all_credentials = row.all_credentials;
    Some(crate::auth::AuthenticatedAgent {
        id: row.id,
        team_id: row.team_id,
        is_app,
        end_user_id: None,
        all_credentials,
    })
}

fn configuration_error(error: McpAuthError) -> Response {
    tracing::error!(%error, "TAP MCP authorization is not configured");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "TAP MCP authorization is not configured"})),
    )
        .into_response()
}

/// POST /mcp/authorization/begin — begin a fresh passkey ceremony for an
/// already-authenticated dashboard session.
pub(crate) async fn handle_begin_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BeginAuthorizationRequest>,
) -> Response {
    if request.request.is_empty() || request.request.len() > MAX_AUTHORIZATION_REQUEST_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing MCP authorization request"})),
        )
            .into_response();
    }
    let user = match authenticate_user(&headers, &state.db_state).await {
        Ok(user) => user,
        Err(response) => return response.into_response(),
    };
    let Some(webauthn) = state.webauthn_state.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Passkey authentication is not configured"})),
        )
            .into_response();
    };
    match webauthn.begin_user_login(&user.id).await {
        Ok((challenge, passkey_token)) => Json(json!({
            "challenge": challenge,
            "passkey_token": passkey_token,
        }))
        .into_response(),
        Err(error) => {
            tracing::warn!(user_id = %user.id, %error, "failed to begin MCP passkey authorization");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to start passkey verification"})),
            )
                .into_response()
        }
    }
}

/// POST /mcp/authorization/finish — verify the passkey belongs to the current
/// dashboard user, then return a short-lived assertion for `tap-mcp`.
pub(crate) async fn handle_finish_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FinishAuthorizationRequest>,
) -> Response {
    let user = match authenticate_user(&headers, &state.db_state).await {
        Ok(user) => user,
        Err(response) => return response.into_response(),
    };
    let Some(webauthn) = state.webauthn_state.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Passkey authentication is not configured"})),
        )
            .into_response();
    };
    let verified_user_id = match webauthn
        .finish_user_login(&request.passkey_token, &request.credential)
        .await
    {
        Ok(user_id) => user_id,
        Err(error) => {
            tracing::warn!(user_id = %user.id, %error, "MCP passkey authorization failed");
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Security key verification failed"})),
            )
                .into_response();
        }
    };
    if verified_user_id != user.id {
        tracing::warn!(session_user_id = %user.id, %verified_user_id, "MCP passkey user mismatch");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Security key does not belong to this TAP account"})),
        )
            .into_response();
    }

    let agent_id = match ensure_mcp_agent(state.db_state.store(), &user.team_id, &user.id).await {
        Ok(agent_id) => agent_id,
        Err(error) => {
            tracing::error!(user_id = %user.id, %error, "failed to provision MCP agent");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Could not provision the MCP connection"})),
            )
                .into_response();
        }
    };

    match issue_authorization_assertion(&request.request, &user.id, &user.team_id, &agent_id) {
        Ok(response) => Json(response).into_response(),
        Err(McpAuthError::InvalidRequest) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid MCP authorization request"})),
        )
            .into_response(),
        Err(error) => configuration_error(error),
    }
}

/// POST /mcp/authorization/disconnect — session-auth. Revoke this user's MCP
/// connection: flip the `revoked` flag on every live refresh-token family for
/// their provisioned `mcp-{user}` agent. Deliberately does NOT delete the agent
/// (that would also break a fresh reconnect and orphan history) — the agent
/// stays, but every outstanding token that names its family stops working at
/// `/forward` and no refresh can rotate. Idempotent.
pub(crate) async fn handle_mcp_disconnect(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let user = match authenticate_user(&headers, &state.db_state).await {
        Ok(user) => user,
        Err(response) => return response.into_response(),
    };
    let agent_id = format!("mcp-{}", user.id);
    match tap_core::mcp_tokens::revoke_families_for_agent(
        state.db_state.store().pool(),
        &user.team_id,
        &agent_id,
        Utc::now().timestamp(),
    )
    .await
    {
        Ok(revoked) => {
            tracing::info!(user_id = %user.id, revoked, "MCP connection disconnected");
            Json(json!({"disconnected": true, "revoked_families": revoked})).into_response()
        }
        Err(error) => {
            tracing::error!(user_id = %user.id, %error, "failed to revoke MCP token families");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Could not disconnect this MCP connection"})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_uses_the_shared_tap_mcp_wire_format() {
        let claims = TapAuthorizationAssertion {
            request: "signed-request".to_string(),
            subject: "user-1".to_string(),
            team_id: "team-1".to_string(),
            agent_id: "mcp-user-1".to_string(),
            issued_at: 100,
            expires_at: 220,
        };
        let token =
            sign_assertion(b"0123456789abcdef0123456789abcdef", &claims).expect("assertion signs");
        let (body, signature) = token.split_once('.').expect("token has two parts");
        assert!(!body.is_empty());
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(signature)
                .expect("signature is base64url")
                .len(),
            32
        );
        let decoded: TapAuthorizationAssertion =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).expect("payload is base64url"))
                .expect("payload is JSON");
        assert_eq!(decoded.subject, "user-1");
        assert_eq!(decoded.team_id, "team-1");
        assert_eq!(decoded.agent_id, "mcp-user-1");
    }

    /// Sign an access token exactly the way tap-mcp's `TokenSigner` does, then
    /// prove the proxy verifier accepts it and rejects tampering / wrong domain.
    /// This is the contract that lets `/forward` trust the MCP OAuth token.
    fn sign_like_tap_mcp(key: &[u8], kind: &str, payload: &serde_json::Value) -> String {
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(kind.as_bytes());
        mac.update(&[0]);
        mac.update(body.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{body}.{signature}")
    }

    #[test]
    fn verify_mcp_access_token_matches_tap_mcp_wire_format() {
        let key = b"0123456789abcdef0123456789abcdef";
        std::env::set_var("TAP_MCP_SIGNING_KEY", std::str::from_utf8(key).unwrap());
        // The audience check (RFC 8707) resolves the resource from this env.
        std::env::set_var("TAP_MCP_PUBLIC_URL", "https://mcp.example");
        let future = Utc::now().timestamp() + 3600;
        let payload = json!({
            "subject": "user-9", "team_id": "team-9", "agent_id": "mcp-user-9",
            "client_id": "c", "audience": "https://mcp.example/mcp",
            "scope": "tap:full", "issued_at": 0, "expires_at": future,
        });
        let token = sign_like_tap_mcp(key, ACCESS_TOKEN_KIND, &payload);
        let claims = verify_mcp_access_token(&token).expect("valid token verifies");
        assert_eq!(claims.team_id, "team-9");
        assert_eq!(claims.agent_id, "mcp-user-9");

        // Tampered signature is rejected.
        let mut tampered = token.clone();
        tampered.pop();
        tampered.push(if token.ends_with('A') { 'B' } else { 'A' });
        assert!(verify_mcp_access_token(&tampered).is_err());

        // An authorization assertion (wrong HMAC domain) cannot be used as an access token.
        let as_assertion = sign_like_tap_mcp(key, ASSERTION_KIND, &payload);
        assert!(verify_mcp_access_token(&as_assertion).is_err());

        // Expired token is rejected.
        let expired_payload = json!({
            "subject": "u", "team_id": "t", "agent_id": "a",
            "scope": "tap:full", "expires_at": Utc::now().timestamp() - 1,
        });
        let expired = sign_like_tap_mcp(key, ACCESS_TOKEN_KIND, &expired_payload);
        assert!(verify_mcp_access_token(&expired).is_err());

        // Missing tap:full scope is rejected.
        let unscoped = json!({
            "subject": "u", "team_id": "t", "agent_id": "a",
            "scope": "", "expires_at": future,
        });
        let unscoped = sign_like_tap_mcp(key, ACCESS_TOKEN_KIND, &unscoped);
        assert!(verify_mcp_access_token(&unscoped).is_err());
    }

    /// The connect screen must show the REGISTERED client identity (from the
    /// signed DCR blob) and offer a standards-shaped deny redirect — never
    /// anything a crafted link could control.
    #[test]
    fn describe_resolves_registered_client_and_deny_url() {
        // The connect screen reads tap-mcp's OWN artifacts, so they are signed
        // with tap-mcp's local key — never the proxy's token-signing key.
        let key = b"local-key-aaaaaaaaaaaaaaaaaaaaaa";
        std::env::set_var("TAP_MCP_LOCAL_KEY", std::str::from_utf8(key).unwrap());
        let future = Utc::now().timestamp() + 300;

        let client_id = sign_like_tap_mcp(
            key,
            DYNAMIC_CLIENT_KIND,
            &json!({
                "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                "client_name": "Claude",
                "issued_at": 0, "expires_at": future,
            }),
        );
        let request = sign_like_tap_mcp(
            key,
            AUTHORIZATION_REQUEST_KIND,
            &json!({
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "state": "xyz-1",
                "code_challenge": "c", "code_challenge_method": "S256",
                "resource": "https://mcp.example/mcp",
                "expires_at": future,
            }),
        );

        let description =
            describe_authorization_request(&request).expect("valid request describes");
        assert_eq!(description.client_name, "Claude");
        assert_eq!(description.client_origin, "https://claude.ai");
        assert!(description
            .deny_url
            .starts_with("https://claude.ai/api/mcp/auth_callback?error=access_denied"));
        assert!(description.deny_url.contains("state=xyz-1"));

        // A redirect_uri outside the registration is refused — a phisher can't
        // splice a registered client's name onto their own callback.
        let spliced = sign_like_tap_mcp(
            key,
            AUTHORIZATION_REQUEST_KIND,
            &json!({
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://evil.example/callback",
                "code_challenge": "c", "code_challenge_method": "S256",
                "resource": "https://mcp.example/mcp",
                "expires_at": future,
            }),
        );
        assert!(describe_authorization_request(&spliced).is_err());

        // Expired request is refused.
        let expired = sign_like_tap_mcp(
            key,
            AUTHORIZATION_REQUEST_KIND,
            &json!({
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "code_challenge": "c", "code_challenge_method": "S256",
                "resource": "https://mcp.example/mcp",
                "expires_at": Utc::now().timestamp() - 1,
            }),
        );
        assert!(describe_authorization_request(&expired).is_err());

        // An unsigned/tampered request is refused outright.
        assert!(describe_authorization_request("not-a-signed-request").is_err());

        // A registration without a name falls back to the redirect host.
        let unnamed_client = sign_like_tap_mcp(
            key,
            DYNAMIC_CLIENT_KIND,
            &json!({
                "redirect_uris": ["http://127.0.0.1:33418/callback"],
                "client_name": null,
                "issued_at": 0, "expires_at": future,
            }),
        );
        let unnamed = sign_like_tap_mcp(
            key,
            AUTHORIZATION_REQUEST_KIND,
            &json!({
                "response_type": "code",
                "client_id": unnamed_client,
                "redirect_uri": "http://127.0.0.1:33418/callback",
                "code_challenge": "c", "code_challenge_method": "S256",
                "resource": "https://mcp.example/mcp",
                "expires_at": future,
            }),
        );
        let description = describe_authorization_request(&unnamed).expect("unnamed describes");
        assert_eq!(description.client_name, "127.0.0.1");
        assert_eq!(description.client_origin, "http://127.0.0.1:33418");
    }

    /// **The point of the trust split.** `tap-mcp` holds only
    /// `TAP_MCP_LOCAL_KEY`. If it were compromised it could sign whatever it
    /// liked with that key — including a payload naming any `team_id`/`agent_id`
    /// under the `access-token` domain — and the proxy must still refuse it.
    ///
    /// Before the split both services shared `TAP_MCP_SIGNING_KEY`, so this
    /// exact forgery WOULD have been accepted and would have let an
    /// internet-facing, non-enclave service act as any agent on `/forward`,
    /// bypassing the passkey consent flow entirely.
    #[test]
    fn token_minted_with_the_tap_mcp_local_key_is_not_accepted_by_the_proxy() {
        let proxy_key = b"proxy-signing-key-aaaaaaaaaaaaaaa";
        let local_key = b"tap-mcp-local-key-bbbbbbbbbbbbbbb";
        assert_ne!(
            proxy_key, local_key,
            "the two trust domains must use different key material"
        );
        std::env::set_var("TAP_MCP_SIGNING_KEY", std::str::from_utf8(proxy_key).unwrap());
        std::env::set_var("TAP_MCP_LOCAL_KEY", std::str::from_utf8(local_key).unwrap());
        std::env::set_var("TAP_MCP_PUBLIC_URL", "https://mcp.example");

        let future = Utc::now().timestamp() + 3600;
        // A payload that is valid in every respect EXCEPT the key it is signed
        // with — right domain, right audience, right scope, live expiry.
        let forged_payload = json!({
            "subject": "victim", "team_id": "victim-team", "agent_id": "mcp-victim",
            "client_id": "c", "audience": "https://mcp.example/mcp",
            "scope": "tap:full", "issued_at": 0, "expires_at": future,
        });

        let forged = sign_like_tap_mcp(local_key, ACCESS_TOKEN_KIND, &forged_payload);
        assert!(
            verify_mcp_access_token(&forged).is_err(),
            "a token minted with tap-mcp's local key MUST NOT authenticate at the proxy"
        );

        // Nor can it forge a refresh token to bootstrap a real pair...
        let forged_refresh = sign_like_tap_mcp(local_key, REFRESH_TOKEN_KIND, &forged_payload);
        assert!(verify_refresh_token(&forged_refresh, "c", None, Utc::now().timestamp()).is_err());

        // ...nor an authorization assertion, which is what /internal/mcp/token/issue
        // re-verifies to derive identity. This is the seam that stops tap-mcp
        // from naming its own subject/team.
        let forged_assertion = sign_like_tap_mcp(
            local_key,
            ASSERTION_KIND,
            &json!({
                "request": "r", "subject": "victim", "team_id": "victim-team",
                "agent_id": "mcp-victim", "issued_at": Utc::now().timestamp(),
                "expires_at": future,
            }),
        );
        assert!(
            verify_assertion_for_redemption(&forged_assertion, Utc::now().timestamp()).is_err(),
            "tap-mcp must not be able to mint the assertion the proxy derives identity from"
        );

        // The proxy's own key still works — this is a key-domain check, not a
        // blanket rejection.
        let genuine = sign_like_tap_mcp(proxy_key, ACCESS_TOKEN_KIND, &forged_payload);
        assert!(verify_mcp_access_token(&genuine).is_ok());
    }

    /// A proxy-minted pair round-trips through its own verifiers, and the
    /// domain separation between the two token families holds.
    #[test]
    fn minted_tokens_round_trip_and_keep_their_domains_separate() {
        std::env::set_var(
            "TAP_MCP_SIGNING_KEY",
            "round-trip-signing-key-aaaaaaaaaaa",
        );
        std::env::set_var("TAP_MCP_PUBLIC_URL", "https://mcp.example");
        let now = Utc::now().timestamp();

        let tokens = mint_token_pair(
            "user-1", "team-1", "mcp-user-1", "client-1", "fam-1", "jti-1",
            now + 1000, now,
        )
        .expect("proxy mints");

        let access = verify_mcp_access_token(&tokens.access_token).expect("access verifies");
        assert_eq!(access.team_id, "team-1");
        assert_eq!(access.agent_id, "mcp-user-1");
        assert_eq!(access.family_id, "fam-1");

        let refresh = verify_refresh_token(&tokens.refresh_token, "client-1", None, now)
            .expect("refresh verifies");
        assert_eq!(refresh.family_id, "fam-1");
        assert_eq!(refresh.jti, "jti-1");
        assert_eq!(refresh.agent_id, "mcp-user-1");

        // Cross-family replay is refused in both directions.
        assert!(verify_mcp_access_token(&tokens.refresh_token).is_err());
        assert!(verify_refresh_token(&tokens.access_token, "client-1", None, now).is_err());

        // A refresh token is bound to its OAuth client and its audience.
        assert!(verify_refresh_token(&tokens.refresh_token, "other-client", None, now).is_err());
        assert!(verify_refresh_token(
            &tokens.refresh_token,
            "client-1",
            Some("https://elsewhere.example/mcp"),
            now
        )
        .is_err());
    }

    /// Redemption accepts a fresh, proxy-signed assertion and rejects a stale or
    /// future-dated one. Anti-replay is the single-use code, not this window.
    #[test]
    fn assertion_redemption_window_bounds_ceremony_staleness() {
        std::env::set_var("TAP_MCP_SIGNING_KEY", "redemption-signing-key-aaaaaaaaaa");
        let key = b"redemption-signing-key-aaaaaaaaaa";
        let now = Utc::now().timestamp();

        let fresh = sign_like_tap_mcp(
            key,
            ASSERTION_KIND,
            &json!({
                "request": "r", "subject": "u", "team_id": "t", "agent_id": "a",
                "issued_at": now, "expires_at": now + 120,
            }),
        );
        let claims = verify_assertion_for_redemption(&fresh, now).expect("fresh assertion redeems");
        assert_eq!(claims.subject, "u");
        assert_eq!(claims.team_id, "t");

        // Still redeemable after the 2-minute browser-hop expiry: the client
        // still has to round-trip its redirect and POST /token.
        assert!(verify_assertion_for_redemption(&fresh, now + 180).is_ok());

        // But not indefinitely.
        assert!(
            verify_assertion_for_redemption(&fresh, now + ASSERTION_REDEMPTION_WINDOW_SECONDS + 1)
                .is_err()
        );
        // Nor from the future (clock-skew tolerance is bounded).
        assert!(verify_assertion_for_redemption(
            &fresh,
            now - ASSERTION_CLOCK_SKEW_SECONDS - 1
        )
        .is_err());

        // An assertion with no subject/team grants nothing.
        let empty = sign_like_tap_mcp(
            key,
            ASSERTION_KIND,
            &json!({
                "request": "r", "subject": "", "team_id": "",
                "issued_at": now, "expires_at": now + 120,
            }),
        );
        assert!(verify_assertion_for_redemption(&empty, now).is_err());
    }
}
