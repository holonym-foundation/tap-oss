//! Google **sign-in** for the TAP dashboard ("Continue with Google").
//!
//! Distinct from `oauth.rs` (which mints Google *credentials* for agents):
//! this flow authenticates the *dashboard user*, replacing only the password
//! factor — the mandatory passkey 2FA (Decision #6) still runs after it.
//!
//! Flow: `GET /auth/google/start` (public) redirects to Google with an
//! `openid email profile` scope and a DB-backed single-use `state`;
//! `GET /auth/google/callback` exchanges the code, reads the identity from the
//! id_token, and resolves it to an account:
//!
//! - identity already linked           → login continuation
//! - account with that email exists    → **auto-link only if** Google verified
//!   the email AND the TAP account's email is verified AND the account has a
//!   passkey to prove ownership with; the link is *staged* and persists only
//!   after the passkey login completes (`pending_identity_links`)
//! - no account                        → signup continuation (the SPA collects
//!   the project name, then `POST /auth/google/complete` creates the account)
//!
//! The continuation token bridges the browser redirect to the SPA's
//! `POST /auth/google/complete`, which lands in the same
//! `finish_first_factor_login` tail as the password login — invites, team
//! resolution, and the passkey setup/challenge branches all behave identically.
//!
//! The identity key is the Google `sub` claim, never the email (emails can
//! change; `sub` is permanent). All flow state is DB-backed and single-use
//! (atomic DELETE … RETURNING), per the Distributed State Rule.
//!
//! Everything downstream of "the provider asserted this verified identity" is
//! provider-agnostic and shared with `github_login.rs`: identity resolution
//! (`resolve_social_login`), the continuation bridge, and the signup
//! completion (`handle_social_login_complete`). Only obtaining the identity —
//! OIDC id_token here, REST API calls for GitHub — is per-provider.

use axum::extract::{Query, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use crate::admin::{
    consume_pending_invites, finish_first_factor_login, generate_session_token, hash_password,
    hash_session_token, ROLE_OWNER,
};
use crate::oauth::dashboard_url;
use crate::proxy::AppState;

pub(crate) const STATE_TTL_SECS: i64 = 600; // 10 minutes: start → provider → callback
const CONTINUATION_TTL_SECS: i64 = 300; // 5 minutes: callback → SPA complete
const PENDING_LINK_TTL_SECS: i64 = 600; // callback → passkey completion
const PROVIDER_GOOGLE: &str = "google";

/// Name of the HttpOnly cookie carrying the per-browser OAuth-binding nonce.
/// Provider-agnostic — every social-login provider reuses these helpers so the
/// login-CSRF / session-fixation defense is inherited, not re-implemented.
pub const OAUTH_BIND_COOKIE: &str = "tap_oauth_bind";

/// Generate a fresh browser-binding nonce for a social-login `/start`.
/// Returns `(raw_nonce, nonce_hash)` — the raw nonce goes to the browser in an
/// HttpOnly cookie via [`set_oauth_bind_cookie`]; only the hash is persisted
/// alongside the login-state row, so a leaked DB row can't be replayed without
/// the cookie the initiating browser holds.
pub fn new_oauth_browser_bind() -> (String, String) {
    let nonce = generate_session_token();
    let hash = hash_session_token(&nonce);
    (nonce, hash)
}

/// Whether the binding cookie should carry the `Secure` attribute. Derived from
/// the configured public URL so production (https) is `Secure` while local
/// http dev still works (a `Secure` cookie is not returned over plain http).
fn oauth_cookie_secure() -> bool {
    crate::proxy::configured_proxy_url().starts_with("https://")
}

/// Attach the `Set-Cookie` header that binds this browser to the login flow.
/// HttpOnly (JS can't read it), SameSite=Lax (survives the top-level redirect
/// back from the provider but not silent cross-site sub-requests), short-lived.
pub fn set_oauth_bind_cookie(resp: &mut Response, nonce: &str) {
    let secure = if oauth_cookie_secure() { "; Secure" } else { "" };
    let cookie = format!(
        "{OAUTH_BIND_COOKIE}={nonce}; Path=/; Max-Age={STATE_TTL_SECS}; HttpOnly{secure}; SameSite=Lax"
    );
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

/// Clear the binding cookie once the callback has consumed it (single-use).
fn clear_oauth_bind_cookie(resp: &mut Response) {
    let secure = if oauth_cookie_secure() { "; Secure" } else { "" };
    let cookie =
        format!("{OAUTH_BIND_COOKIE}=; Path=/; Max-Age=0; HttpOnly{secure}; SameSite=Lax");
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
}

/// Read the raw binding nonce from the request's `Cookie` header, if present.
pub fn read_oauth_bind_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix(&format!("{OAUTH_BIND_COOKIE}=")) {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Verify the browser-binding cookie against the hash stored on the claimed
/// login-state row. `stored` is `browser_bind_hash` returned by
/// `take_login_oauth_state`. Returns `Ok(())` when the presented cookie hashes
/// to the stored value (or, for backward compatibility, when the row carries no
/// stored hash — legacy rows / tests). A missing or mismatched cookie against a
/// bound row fails closed. Provider-agnostic.
pub fn verify_oauth_browser_bind(
    headers: &HeaderMap,
    stored: Option<&str>,
) -> Result<(), &'static str> {
    let Some(stored) = stored else {
        // Row predates the binding column (or a test inserted it directly). No
        // hash to compare — nothing to enforce.
        warn!("login OAuth state has no browser-binding hash; skipping bind check");
        return Ok(());
    };
    let Some(nonce) = read_oauth_bind_cookie(headers) else {
        return Err("missing_bind");
    };
    if hash_session_token(&nonce) == stored {
        Ok(())
    } else {
        Err("bind_mismatch")
    }
}

/// Google's token endpoint. Overridable so integration tests can stand in a
/// local mock — production never sets this.
fn google_token_url() -> String {
    std::env::var("TAP_GOOGLE_LOGIN_TOKEN_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string())
}

fn login_redirect_uri() -> String {
    match std::env::var("GOOGLE_LOGIN_REDIRECT_URI") {
        Ok(v) if !v.is_empty() => v,
        _ => format!(
            "{}/auth/google/callback",
            crate::proxy::configured_proxy_url()
        ),
    }
}

/// The identity a sign-in provider asserted (Google: id_token claims;
/// GitHub: `/user` + `/user/emails`). `sub` is the provider's PERMANENT id.
#[derive(Debug)]
pub(crate) struct ProviderIdentity {
    pub(crate) sub: String,
    pub(crate) email: String,
    pub(crate) email_verified: bool,
}

/// The issuers a Google-signed id_token may legitimately carry.
const GOOGLE_ISSUERS: [&str; 2] = ["accounts.google.com", "https://accounts.google.com"];

/// Does the id_token's `aud` claim (string, or array of strings) name the
/// expected client id? Google's OIDC id_token carries `aud` as the client id
/// string; we also tolerate the array form the spec allows.
fn id_token_aud_matches(aud: Option<&serde_json::Value>, expected: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(s)) => s == expected,
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .any(|v| v.as_str().map(|s| s == expected).unwrap_or(false)),
        _ => false,
    }
}

/// Extract the claims from an id_token **without** signature verification.
/// Sound here only because the token arrives on the direct TLS exchange with
/// Google's token endpoint (confidential client) — never from the browser.
///
/// As cheap defense-in-depth (not a substitute for signature verification,
/// which the server-to-server fetch already stands in for) the `aud`, `iss`,
/// and `exp` claims are checked: `aud` must equal our own client id
/// (`expected_aud`), `iss` must be a Google issuer, and `exp` must be in the
/// future. Any mismatch — or a missing claim — rejects the token (fail closed).
///
/// Returns the shared `ProviderIdentity` (this branch's Google/GitHub
/// refactor); the aud/iss/exp checks are Google-OIDC specific, and GitHub's
/// OAuth path does not use id_tokens at all.
fn parse_id_token_claims(id_token: &str, expected_aud: &str) -> Option<ProviderIdentity> {
    // An empty expected audience means we cannot bind the token to this client
    // — refuse rather than accept an unaudienced token.
    if expected_aud.is_empty() {
        return None;
    }
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;

    // aud: must be this exact client id (not another Google OAuth client).
    if !id_token_aud_matches(claims.get("aud"), expected_aud) {
        warn!("Google id_token rejected: aud does not match configured client id");
        return None;
    }
    // iss: must be a Google issuer.
    let iss_ok = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|iss| GOOGLE_ISSUERS.contains(&iss))
        .unwrap_or(false);
    if !iss_ok {
        warn!("Google id_token rejected: unexpected iss");
        return None;
    }
    // exp: must be in the future. Google emits a numeric Unix timestamp; the
    // string form some IdPs use is tolerated.
    let exp = claims.get("exp").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
    })?;
    if exp <= chrono::Utc::now().timestamp() {
        warn!("Google id_token rejected: token is expired");
        return None;
    }

    let sub = claims.get("sub")?.as_str()?.trim().to_string();
    let email = claims.get("email")?.as_str()?.trim().to_lowercase();
    if sub.is_empty() || !email.contains('@') {
        return None;
    }
    // Google emits a bool, but tolerate the string form some IdPs use.
    let email_verified = match claims.get("email_verified") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => s == "true",
        _ => false,
    };
    Some(ProviderIdentity {
        sub,
        email,
        email_verified,
    })
}

/// Client id/secret for **"Sign in with Google"**.
///
/// Deliberately separate from the connector client (`GOOGLE_OAUTH_CLIENT_ID`,
/// used by `oauth.rs` to connect Gmail/Drive/Calendar credentials). Login needs
/// only `openid email profile` — non-sensitive scopes that require **no** Google
/// verification. The connector client requests RESTRICTED scopes
/// (`gmail.readonly`, `drive`), which drag the whole client through OAuth
/// verification plus an annual CASA security assessment, and cap it at 100 users
/// until that clears.
///
/// Sharing one client meant sign-up — which needs no review at all — inherited
/// that entire burden. Splitting them lets login ship immediately with a clean,
/// unverified, uncapped client while the connector goes through review on its
/// own timeline.
///
/// Falls back to the connector client when the login-specific vars are unset, so
/// existing deployments keep working unchanged until they provision a second
/// client. Each returns an empty string if neither is set; callers already treat
/// empty as "not configured".
fn login_client_id() -> String {
    std::env::var("GOOGLE_LOGIN_CLIENT_ID")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("GOOGLE_OAUTH_CLIENT_ID").ok())
        .unwrap_or_default()
}

fn login_client_secret() -> String {
    std::env::var("GOOGLE_LOGIN_CLIENT_SECRET")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("GOOGLE_OAUTH_CLIENT_SECRET").ok())
        .unwrap_or_default()
}

/// GET /auth/google/start — public. Redirects the browser to Google's consent
/// screen with a DB-backed CSRF `state`.
pub async fn handle_google_login_start(State(state): State<AppState>) -> Response {
    let client_id = match Some(login_client_id()) {
        Some(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Google sign-in is not configured"})),
            )
                .into_response();
        }
    };

    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);
    // Browser-binding: the cookie nonce ties this /start to the browser that
    // must later present it at /callback (login-CSRF / session-fixation guard).
    let (bind_nonce, bind_hash) = new_oauth_browser_bind();
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS)).to_rfc3339();
    if let Err(e) = state
        .db_state
        .store()
        .create_login_oauth_state(&state_hash, PROVIDER_GOOGLE, &expires_at, Some(&bind_hash))
        .await
    {
        warn!("Failed to persist Google login state: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Could not start Google sign-in"})),
        )
            .into_response();
    }

    let mut auth_url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
        .expect("static Google authorize URL parses");
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &login_redirect_uri())
        .append_pair("response_type", "code")
        // Identity only — no offline access, no API scopes, no refresh token.
        .append_pair("scope", "openid email profile")
        .append_pair("prompt", "select_account")
        .append_pair("state", &state_token);
    let mut resp = Redirect::to(auth_url.as_str()).into_response();
    set_oauth_bind_cookie(&mut resp, &bind_nonce);
    resp
}

#[derive(Debug, Deserialize)]
pub struct GoogleLoginCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// GET /auth/google/callback — consume the state, exchange the code, resolve
/// the Google identity to a TAP account, and hand the browser back to the SPA
/// with a single-use continuation token.
pub async fn handle_google_login_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<GoogleLoginCallbackQuery>,
) -> Response {
    // The SPA login screen reads ?google_login_error=… and shows the message.
    // Every error redirect clears the one-time binding cookie so a stale nonce
    // can't linger and be reused.
    let err_redirect = |reason: &str| {
        let mut resp =
            Redirect::to(&dashboard_url(&format!("?google_login_error={reason}"))).into_response();
        clear_oauth_bind_cookie(&mut resp);
        resp
    };

    if q.error.is_some() {
        return err_redirect("access_denied");
    }
    let state_token = match q.state {
        Some(ref s) if !s.is_empty() => s,
        _ => return err_redirect("missing_state"),
    };

    let store = state.db_state.store();
    let state_hash = hash_session_token(state_token);
    // Atomically claim the state row (single-use, cross-instance), then verify
    // the browser-binding cookie against the hash stored at /start BEFORE doing
    // anything with the identity. A callback URL replayed in a different browser
    // (login-CSRF / session fixation) has no matching cookie and is rejected —
    // the claim has already burned the attacker's state, so it can't be reused.
    match store.take_login_oauth_state(&state_hash).await {
        Ok(Some((provider, expires_at, bind_hash))) if provider == PROVIDER_GOOGLE => {
            if expires_at < chrono::Utc::now() {
                return err_redirect("expired_state");
            }
            if let Err(reason) = verify_oauth_browser_bind(&headers, bind_hash.as_deref()) {
                warn!("Google login callback failed browser-binding check: {reason}");
                return err_redirect(reason);
            }
        }
        Ok(Some(_)) | Ok(None) => return err_redirect("invalid_state"),
        Err(e) => {
            warn!("Failed to load Google login state: {e}");
            return err_redirect("server_error");
        }
    }

    let code = match q.code {
        Some(ref c) if !c.is_empty() => c,
        _ => return err_redirect("missing_code"),
    };

    let client_id = login_client_id();
    let client_secret = login_client_secret();
    if client_id.is_empty() || client_secret.is_empty() {
        warn!("Google login env vars missing during callback");
        return err_redirect("server_error");
    }

    let client = match tap_core::http_client::build_client(
        tap_core::http_client::ClientRoute::EgressProxy,
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build HTTP client for Google login exchange: {e}");
            return err_redirect("token_exchange_failed");
        }
    };
    let token_resp = client
        .post(google_token_url())
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", login_redirect_uri().as_str()),
        ])
        .send()
        .await;
    let token_body: serde_json::Value = match token_resp {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse Google login token response: {e}");
                return err_redirect("token_exchange_failed");
            }
        },
        Ok(resp) => {
            let status = resp.status();
            warn!("Google login token exchange failed ({status})");
            return err_redirect("token_exchange_failed");
        }
        Err(e) => {
            warn!("Google login token exchange request failed: {e}");
            return err_redirect("token_exchange_failed");
        }
    };

    let identity = match token_body
        .get("id_token")
        .and_then(|v| v.as_str())
        .and_then(|t| parse_id_token_claims(t, &client_id))
    {
        Some(identity) => identity,
        None => {
            warn!("Google login token response missing/invalid id_token");
            return err_redirect("token_exchange_failed");
        }
    };
    // An unverified Google email proves nothing about mailbox ownership —
    // refuse rather than seed an account (or a link) from it.
    if !identity.email_verified {
        return err_redirect("google_email_unverified");
    }

    resolve_social_login(&state, PROVIDER_GOOGLE, &identity).await
}

/// Resolve a provider-asserted (and provider-verified) identity to a TAP
/// account and hand the browser back to the SPA. Provider-agnostic: the SPA
/// query params are derived from the provider name (`{provider}_login`,
/// `{provider}_signup`, `{provider}_login_error`).
pub(crate) async fn resolve_social_login(
    state: &AppState,
    provider: &str,
    identity: &ProviderIdentity,
) -> Response {
    let err_redirect = |reason: &str| {
        Redirect::to(&dashboard_url(&format!("?{provider}_login_error={reason}"))).into_response()
    };
    let login_param = format!("{provider}_login");
    let store = state.db_state.store();

    // (a) Already linked → plain login.
    match store.get_identity_user(provider, &identity.sub).await {
        Ok(Some(user_id)) => {
            return issue_continuation(
                state,
                "login",
                Some(&user_id),
                provider,
                identity,
                &login_param,
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => {
            warn!("Identity lookup failed: {e}");
            return err_redirect("server_error");
        }
    }

    // (b) An account with this email exists → stage a link, never auto-link.
    match store.get_user_by_email(&identity.email).await {
        Ok(Some(user)) => {
            if !user.email_verified {
                // Pre-verification takeover guard: an attacker could have
                // squatted this email with an unverified signup — a social
                // login must not inherit (or verify) that account.
                return err_redirect("account_email_unverified");
            }
            let has_passkeys = match state.webauthn_state.as_ref() {
                Some(wa) => wa.user_has_passkeys(&user.id).await,
                // WebAuthn-less deployment: the full-session path persists the
                // staged link immediately after this continuation completes.
                None => true,
            };
            if !has_passkeys {
                // No passkey to prove ownership with — require a password
                // login first (which forces passkey setup) rather than linking
                // on the email match alone.
                return err_redirect("password_login_required");
            }
            let link_expires = (chrono::Utc::now()
                + chrono::Duration::seconds(PENDING_LINK_TTL_SECS))
            .to_rfc3339();
            if let Err(e) = store
                .create_pending_identity_link(
                    &user.id,
                    provider,
                    &identity.sub,
                    &identity.email,
                    &link_expires,
                )
                .await
            {
                warn!("Failed to stage identity link: {e}");
                return err_redirect("server_error");
            }
            return issue_continuation(
                state,
                "login",
                Some(&user.id),
                provider,
                identity,
                &login_param,
            )
            .await;
        }
        Ok(None) => {}
        Err(e) => {
            warn!("User lookup failed: {e}");
            return err_redirect("server_error");
        }
    }

    // (c) No account → signup continuation. The SPA collects the project name
    // (or joins pending invites) and completes the signup.
    let join_only_possible = !store
        .list_invites_by_email(&identity.email)
        .await
        .unwrap_or_default()
        .is_empty();
    let response = issue_continuation(
        state,
        "signup",
        None,
        provider,
        identity,
        &format!("{provider}_signup"),
    )
    .await;
    // Tell the SPA whether a project name is required (no pending invites) —
    // it cannot ask the server without spending the single-use token.
    if let Some(location) = response
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
    {
        let with_join = format!(
            "{location}&join={}",
            if join_only_possible { "1" } else { "0" }
        );
        // Rebuilding the redirect drops the Set-Cookie issue_continuation added,
        // so re-clear the one-time binding cookie here.
        let mut resp = Redirect::to(&with_join).into_response();
        clear_oauth_bind_cookie(&mut resp);
        return resp;
    }
    response
}

/// Store a continuation row and redirect the browser back to the SPA with the
/// raw token in `?{param}=`.
async fn issue_continuation(
    state: &AppState,
    kind: &str,
    user_id: Option<&str>,
    provider: &str,
    identity: &ProviderIdentity,
    param: &str,
) -> Response {
    let token = generate_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(CONTINUATION_TTL_SECS)).to_rfc3339();
    if let Err(e) = state
        .db_state
        .store()
        .create_login_continuation(
            &token_hash,
            kind,
            user_id,
            Some(provider),
            Some(&identity.sub),
            Some(&identity.email),
            &expires_at,
        )
        .await
    {
        warn!("Failed to persist login continuation: {e}");
        // Keep this branch's provider-generic error param, and clear the
        // one-time binding cookie as the google-login path does.
        let mut resp = Redirect::to(&dashboard_url(&format!(
            "?{provider}_login_error=server_error"
        )))
        .into_response();
        clear_oauth_bind_cookie(&mut resp);
        return resp;
    }
    // The binding cookie has done its job (state consumed) — clear it.
    let mut resp = Redirect::to(&dashboard_url(&format!("?{param}={token}"))).into_response();
    clear_oauth_bind_cookie(&mut resp);
    resp
}

#[derive(Debug, Deserialize)]
pub struct SocialLoginCompleteRequest {
    pub token: String,
    /// Project name for a signup continuation (create-team mode). Ignored for
    /// logins. Optional when the email has pending invites (join-only mode).
    #[serde(default)]
    pub team_name: Option<String>,
}

/// POST /auth/google/complete and POST /auth/github/complete — the SPA
/// exchanges the continuation token for the same response shapes as
/// POST /login (session / passkey setup / passkey challenge), so everything
/// downstream of the password step is shared. Provider-agnostic: the
/// continuation row itself carries the provider.
pub async fn handle_social_login_complete(
    State(state): State<AppState>,
    Json(req): Json<SocialLoginCompleteRequest>,
) -> Response {
    let store = state.db_state.store();
    let token_hash = hash_session_token(req.token.trim());
    let (kind, user_id, provider, provider_sub, email, expires_at) = match store
        .take_login_continuation(&token_hash)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "This sign-in link is invalid or was already used. Start again."})),
                )
                    .into_response();
        }
        Err(e) => {
            warn!("Failed to take login continuation: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Sign-in failed"})),
            )
                .into_response();
        }
    };
    if expires_at < chrono::Utc::now() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "This sign-in expired. Start again."})),
        )
            .into_response();
    }

    match kind.as_str() {
        "login" => {
            let Some(user_id) = user_id else {
                warn!("login continuation without user_id");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Sign-in failed"})),
                )
                    .into_response();
            };
            let user = match store.get_user(&user_id).await {
                Ok(Some(u)) if u.email_verified => u,
                _ => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "Account not found or inactive"})),
                    )
                        .into_response();
                }
            };
            finish_first_factor_login(&state, user).await
        }
        "signup" => {
            let (Some(provider), Some(provider_sub), Some(email)) = (provider, provider_sub, email)
            else {
                warn!("signup continuation missing identity fields");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Sign-in failed"})),
                )
                    .into_response();
            };
            complete_social_signup(
                &state,
                &provider,
                &provider_sub,
                &email,
                req.team_name,
                &token_hash,
                expires_at,
            )
            .await
        }
        other => {
            warn!("unknown login continuation kind: {other}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Sign-in failed"})),
            )
                .into_response()
        }
    }
}

/// Create the account for a social signup continuation — the social twin of
/// `handle_signup`: same project-name validation, whitelist gate, join-only
/// invite mode; but the email arrives provider-verified (no code email) and
/// the account has no usable password (a random throwaway — password reset can
/// set a real one later).
///
/// Validation failures that had no side effects RE-ARM the single-use
/// continuation (same hash, original expiry) so a typo'd project name doesn't
/// force the user back through the provider.
async fn complete_social_signup(
    state: &AppState,
    provider: &str,
    provider_sub: &str,
    email: &str,
    team_name: Option<String>,
    token_hash: &str,
    token_expires_at: chrono::DateTime<chrono::Utc>,
) -> Response {
    let store = state.db_state.store();
    let rearm_and = |response: Response| async move {
        if let Err(e) = store
            .create_login_continuation(
                token_hash,
                "signup",
                None,
                Some(provider),
                Some(provider_sub),
                Some(email),
                &token_expires_at.to_rfc3339(),
            )
            .await
        {
            warn!("Failed to re-arm signup continuation: {e}");
        }
        response
    };

    // The account may have appeared since the callback (double window) —
    // treat as a conflict rather than duplicating handle_signup's guards.
    if let Ok(Some(_)) = store.get_user_by_email(email).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "An account with this email already exists. Sign in instead."})),
        )
            .into_response();
    }

    let team_name = team_name
        .as_deref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    if let Some(name) = &team_name {
        if name.len() < 3 || name.len() > 64 {
            return rearm_and(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Project name must be 3-64 characters"})),
                )
                    .into_response(),
            )
            .await;
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return rearm_and(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Project name must be lowercase alphanumeric with hyphens"})),
                )
                    .into_response(),
            )
            .await;
        }
    }

    let has_pending_invite = !store
        .list_invites_by_email(email)
        .await
        .unwrap_or_default()
        .is_empty();
    if team_name.is_none() && !has_pending_invite {
        return rearm_and(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Enter a project name to create your own team.",
                    "needs_team_name": true,
                })),
            )
                .into_response(),
        )
        .await;
    }

    // Whitelist (managed hosting MVP) gates creating a new team, exactly as in
    // the password signup.
    let signup_tier = if team_name.is_some() {
        match store.get_whitelist_entry(email).await.unwrap_or(None) {
            Some((_, tier)) => tier,
            None => {
                if std::env::var("TAP_REQUIRE_WHITELIST").unwrap_or_default() == "true" {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": "Managed hosting is in early access. Request access at tap.human.tech"})),
                    )
                        .into_response();
                }
                "free".to_string()
            }
        }
    } else {
        "free".to_string()
    };

    if let Some(name) = &team_name {
        if let Ok(Some(_)) = store.get_team_by_name(name).await {
            return rearm_and(
                (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "Project name already taken"})),
                )
                    .into_response(),
            )
            .await;
        }
    }

    // No password on social signups: hash a random 32-byte throwaway so the
    // column holds a valid-but-unguessable argon2 hash. Reset-password remains
    // the supported way to add a password later.
    let password_hash = match hash_password(&generate_session_token()) {
        Ok(h) => h,
        Err(e) => {
            warn!("Sentinel password hash error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal error"})),
            )
                .into_response();
        }
    };

    let user_id = uuid::Uuid::new_v4().to_string();
    let team_id = if let Some(name) = &team_name {
        let team_id = uuid::Uuid::new_v4().to_string();
        if let Err(e) = store.create_team(&team_id, name).await {
            warn!("Team creation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create team"})),
            )
                .into_response();
        }
        if signup_tier != "free" {
            let _ = store.update_team_tier(&team_id, &signup_tier).await;
        }
        Some(team_id)
    } else {
        None
    };

    // Strict insert — never adopt an existing row. The email pre-check above
    // is only advisory: an account created in the window (e.g. a password
    // signup racing this callback) must NOT be handed this flow's verified
    // email + provider identity, or whoever holds that account's password
    // captures the social login.
    match store.create_user_strict(&user_id, email, &password_hash).await {
        Ok(true) => {}
        Ok(false) => {
            if let Some(team_id) = &team_id {
                warn!(%team_id, "Signup email conflict after team creation; team left unowned");
            }
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "An account with this email already exists. Sign in instead."})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Social signup user creation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create account"})),
            )
                .into_response();
        }
    }
    if let Some(team_id) = &team_id {
        if let Err(e) = store.add_membership(&user_id, team_id, ROLE_OWNER).await {
            warn!("Social signup membership error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create account"})),
            )
                .into_response();
        }
    }

    // The provider verified the email — no verification-code round trip. Safe
    // only because the row above is freshly ours (strict insert).
    if let Err(e) = store.set_user_email_verified(&user_id).await {
        warn!("Failed to mark social signup verified: {e}");
    }
    // The account was created BY this provider identity — link immediately.
    match store
        .link_user_identity(&user_id, provider, provider_sub, email)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            // A concurrent flow linked this provider identity to another
            // account in the window — do not sign the user into an account
            // their identity isn't actually linked to.
            warn!(%user_id, %provider, "Signup identity already linked to a different account");
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "This sign-in identity is already linked to another account. Sign in instead."})),
            )
                .into_response();
        }
        Err(e) => warn!("Failed to link identity on signup: {e}"),
    }

    // Join-only signups must land in at least one team (invite may have
    // expired in the window since the callback).
    let joined = consume_pending_invites(store, &user_id, email).await;
    if team_name.is_none() && joined.is_empty() {
        return (
            StatusCode::GONE,
            Json(json!({"error": "Your invitation expired. Ask the team owner to invite you again."})),
        )
            .into_response();
    }

    info!(%user_id, %provider, "Account created via social sign-in");

    let user = match store.get_user(&user_id).await {
        Ok(Some(u)) => u,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Sign-in failed"})),
            )
                .into_response();
        }
    };
    finish_first_factor_login(state, user).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_AUD: &str = "client-123.apps.googleusercontent.com";

    /// Login must be able to use its OWN OAuth client, and must still work on
    /// deployments that have not provisioned one. The split exists so sign-up
    /// (non-sensitive `openid email profile`) is not gated behind the connector
    /// client's restricted-scope verification; the fallback exists so nobody
    /// has to provision a second client before upgrading.
    ///
    /// This test mutates process env, so it lives with the other serial
    /// (`--test-threads=1`) unit tests in this crate.
    #[test]
    fn login_client_prefers_its_own_vars_and_falls_back_to_the_connector() {
        for k in [
            "GOOGLE_LOGIN_CLIENT_ID",
            "GOOGLE_LOGIN_CLIENT_SECRET",
            "GOOGLE_OAUTH_CLIENT_ID",
            "GOOGLE_OAUTH_CLIENT_SECRET",
        ] {
            std::env::remove_var(k);
        }

        // Nothing set at all → empty, and callers treat that as "not configured".
        assert_eq!(login_client_id(), "");
        assert_eq!(login_client_secret(), "");

        // Only the connector client exists → login falls back to it, so an
        // existing deployment keeps working after this change.
        std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "connector-id");
        std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "connector-secret");
        assert_eq!(login_client_id(), "connector-id");
        assert_eq!(login_client_secret(), "connector-secret");

        // A dedicated login client wins, so login can run on an unverified,
        // uncapped client while the connector goes through CASA separately.
        std::env::set_var("GOOGLE_LOGIN_CLIENT_ID", "login-id");
        std::env::set_var("GOOGLE_LOGIN_CLIENT_SECRET", "login-secret");
        assert_eq!(login_client_id(), "login-id");
        assert_eq!(login_client_secret(), "login-secret");

        // An empty login var is treated as unset, not as a blank client id.
        std::env::set_var("GOOGLE_LOGIN_CLIENT_ID", "");
        assert_eq!(login_client_id(), "connector-id");

        for k in [
            "GOOGLE_LOGIN_CLIENT_ID",
            "GOOGLE_LOGIN_CLIENT_SECRET",
            "GOOGLE_OAUTH_CLIENT_ID",
            "GOOGLE_OAUTH_CLIENT_SECRET",
        ] {
            std::env::remove_var(k);
        }
    }

    /// A valid, unexpired, correctly-audienced Google id_token body, with the
    /// supplied fields merged in (so a test can override or drop a claim).
    fn id_token_with(payload: serde_json::Value) -> String {
        let future = chrono::Utc::now().timestamp() + 3600;
        let mut body = json!({
            "aud": TEST_AUD,
            "iss": "https://accounts.google.com",
            "exp": future,
        });
        // Merge caller-supplied claims over the valid defaults.
        if let (Some(base), Some(extra)) = (body.as_object_mut(), payload.as_object()) {
            for (k, v) in extra {
                base.insert(k.clone(), v.clone());
            }
        }
        raw_id_token(body)
    }

    /// Encode a JWT with exactly the given payload (no defaults merged in) —
    /// for the aud/iss/exp rejection tests that need to omit or corrupt claims.
    fn raw_id_token(payload: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        format!("{header}.{body}.unverified-signature")
    }

    #[test]
    fn id_token_claims_parse_and_normalize() {
        let token = id_token_with(json!({
            "sub": "108236457461",
            "email": "Person@Example.COM ",
            "email_verified": true
        }));
        let identity = parse_id_token_claims(&token, TEST_AUD).expect("claims parse");
        assert_eq!(identity.sub, "108236457461");
        assert_eq!(identity.email, "person@example.com");
        assert!(identity.email_verified);
    }

    #[test]
    fn id_token_string_email_verified_tolerated() {
        let token = id_token_with(json!({
            "sub": "1",
            "email": "a@b.c",
            "email_verified": "true"
        }));
        assert!(parse_id_token_claims(&token, TEST_AUD).unwrap().email_verified);
    }

    #[test]
    fn id_token_missing_claims_rejected() {
        // Missing email_verified defaults to false (never trusted).
        let token = id_token_with(json!({"sub": "1", "email": "a@b.c"}));
        assert!(!parse_id_token_claims(&token, TEST_AUD).unwrap().email_verified);
        // Missing sub/email → None.
        assert!(parse_id_token_claims(&id_token_with(json!({"email": "a@b.c"})), TEST_AUD).is_none());
        assert!(parse_id_token_claims(&id_token_with(json!({"sub": "1"})), TEST_AUD).is_none());
        // Garbage input → None.
        assert!(parse_id_token_claims("not-a-jwt", TEST_AUD).is_none());
    }

    #[test]
    fn id_token_wrong_aud_rejected() {
        let token = id_token_with(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true
        }));
        // A token minted for a different Google OAuth client is rejected.
        assert!(parse_id_token_claims(&token, "other-client.apps.googleusercontent.com").is_none());
        // aud present but naming a different client.
        let wrong = id_token_with(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true,
            "aud": "attacker-client.apps.googleusercontent.com"
        }));
        assert!(parse_id_token_claims(&wrong, TEST_AUD).is_none());
        // Missing aud entirely → rejected.
        let no_aud = raw_id_token(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true,
            "iss": "https://accounts.google.com",
            "exp": chrono::Utc::now().timestamp() + 3600
        }));
        assert!(parse_id_token_claims(&no_aud, TEST_AUD).is_none());
        // Empty expected aud (misconfiguration) → fail closed.
        assert!(parse_id_token_claims(&token, "").is_none());
        // aud as an array containing the expected client id → accepted.
        let arr = id_token_with(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true,
            "aud": [TEST_AUD, "other"]
        }));
        assert!(parse_id_token_claims(&arr, TEST_AUD).is_some());
    }

    #[test]
    fn id_token_wrong_iss_rejected() {
        let bad = id_token_with(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true,
            "iss": "https://accounts.evil.example"
        }));
        assert!(parse_id_token_claims(&bad, TEST_AUD).is_none());
        // Missing iss → rejected.
        let no_iss = raw_id_token(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true,
            "aud": TEST_AUD,
            "exp": chrono::Utc::now().timestamp() + 3600
        }));
        assert!(parse_id_token_claims(&no_iss, TEST_AUD).is_none());
        // The bare-host issuer form is accepted.
        let bare = id_token_with(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true,
            "iss": "accounts.google.com"
        }));
        assert!(parse_id_token_claims(&bare, TEST_AUD).is_some());
    }

    #[test]
    fn id_token_expired_rejected() {
        let expired = id_token_with(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true,
            "exp": chrono::Utc::now().timestamp() - 60
        }));
        assert!(parse_id_token_claims(&expired, TEST_AUD).is_none());
        // Missing exp → rejected.
        let no_exp = raw_id_token(json!({
            "sub": "1", "email": "a@b.c", "email_verified": true,
            "aud": TEST_AUD,
            "iss": "https://accounts.google.com"
        }));
        assert!(parse_id_token_claims(&no_exp, TEST_AUD).is_none());
    }
}
