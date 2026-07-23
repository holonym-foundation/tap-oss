//! GitHub **sign-in** for the TAP dashboard ("Continue with GitHub").
//!
//! Mirrors `google_login.rs` and reuses its shared machinery — identity
//! resolution (`resolve_social_login`), the continuation bridge, and
//! `handle_social_login_complete` (re-exported below for the github route).
//! Only obtaining the identity differs: GitHub is plain OAuth2, not OIDC —
//! there is no id_token, so the callback exchanges the code for an
//! access_token and reads the identity from the GitHub API
//! (`GET /user` + `GET /user/emails`).
//!
//! The identity key is the **numeric user id** (stringified) — never the
//! login name (renameable) and never the email. The email is the entry the
//! user marked `primary`, and its GitHub-side `verified` flag is REQUIRED:
//! an unverified GitHub email proves nothing about mailbox ownership, so it
//! must never mint or link a TAP account (same takeover guard as the Google
//! `email_verified` claim).

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::admin::{generate_session_token, hash_session_token};
use crate::google_login::{
    new_oauth_browser_bind, resolve_social_login, set_oauth_bind_cookie, verify_oauth_browser_bind,
    ProviderIdentity, STATE_TTL_SECS,
};
use crate::oauth::dashboard_url;
use crate::proxy::AppState;

/// The github route shares the provider-agnostic complete handler.
pub use crate::google_login::handle_social_login_complete as handle_github_login_complete;

const PROVIDER_GITHUB: &str = "github";

/// GitHub's token endpoint. Overridable so integration tests can stand in a
/// local mock — production never sets this.
fn github_token_url() -> String {
    std::env::var("TAP_GITHUB_LOGIN_TOKEN_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://github.com/login/oauth/access_token".to_string())
}

/// GitHub's API base (`/user`, `/user/emails`). Same test-only override trick.
fn github_api_url() -> String {
    std::env::var("TAP_GITHUB_LOGIN_API_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string())
}

fn login_redirect_uri() -> String {
    match std::env::var("GITHUB_LOGIN_REDIRECT_URI") {
        Ok(v) if !v.is_empty() => v,
        _ => format!(
            "{}/auth/github/callback",
            crate::proxy::configured_proxy_url()
        ),
    }
}

/// The permanent numeric user id from a `GET /user` body, stringified.
/// `login` is deliberately ignored — GitHub usernames are renameable.
fn github_user_id(user: &serde_json::Value) -> Option<String> {
    user.get("id")?.as_u64().map(|id| id.to_string())
}

/// The `primary: true` entry of a `GET /user/emails` body → `(email, verified)`.
/// A missing `verified` flag counts as unverified (never trusted).
fn primary_email(emails: &serde_json::Value) -> Option<(String, bool)> {
    emails.as_array()?.iter().find_map(|entry| {
        if !entry.get("primary")?.as_bool()? {
            return None;
        }
        let email = entry.get("email")?.as_str()?.trim().to_lowercase();
        if !email.contains('@') {
            return None;
        }
        let verified = entry
            .get("verified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Some((email, verified))
    })
}

/// GET /auth/github/start — public. Redirects the browser to GitHub's consent
/// screen with a DB-backed CSRF `state`.
pub async fn handle_github_login_start(State(state): State<AppState>) -> Response {
    // Require the secret too: with only the client id set, the user would sail
    // through GitHub's consent screen and bounce off the callback with a
    // retriable-looking server_error for what is a permanent misconfiguration.
    let client_id = match (
        std::env::var("GITHUB_LOGIN_CLIENT_ID"),
        std::env::var("GITHUB_LOGIN_CLIENT_SECRET"),
    ) {
        (Ok(id), Ok(secret)) if !id.is_empty() && !secret.is_empty() => id,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "GitHub sign-in is not configured"})),
            )
                .into_response();
        }
    };

    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);
    // Browser-binding: the cookie nonce ties this /start to the browser that
    // must later present it at /callback (login-CSRF / session-fixation guard).
    // Same shared machinery as the Google path.
    let (bind_nonce, bind_hash) = new_oauth_browser_bind();
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS)).to_rfc3339();
    if let Err(e) = state
        .db_state
        .store()
        .create_login_oauth_state(&state_hash, PROVIDER_GITHUB, &expires_at, Some(&bind_hash))
        .await
    {
        warn!("Failed to persist GitHub login state: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Could not start GitHub sign-in"})),
        )
            .into_response();
    }

    let mut auth_url = url::Url::parse("https://github.com/login/oauth/authorize")
        .expect("static GitHub authorize URL parses");
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &login_redirect_uri())
        // Identity only: profile read + email list (the primary email is not
        // in /user for private-email accounts). No repo/org access.
        .append_pair("scope", "read:user user:email")
        .append_pair("state", &state_token);
    let mut resp = Redirect::to(auth_url.as_str()).into_response();
    set_oauth_bind_cookie(&mut resp, &bind_nonce);
    resp
}

#[derive(Debug, Deserialize)]
pub struct GithubLoginCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// GET /auth/github/callback — consume the state, exchange the code, read the
/// identity from the GitHub API, and resolve it to a TAP account via the
/// shared social-login machinery.
pub async fn handle_github_login_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<GithubLoginCallbackQuery>,
) -> Response {
    // The SPA login screen reads ?github_login_error=… and shows the message.
    let err_redirect = |reason: &str| {
        Redirect::to(&dashboard_url(&format!("?github_login_error={reason}"))).into_response()
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
    // anything with the identity — mirrors the Google path. A callback URL
    // replayed in a different browser has no matching cookie and is rejected.
    match store.take_login_oauth_state(&state_hash).await {
        Ok(Some((provider, expires_at, bind_hash))) if provider == PROVIDER_GITHUB => {
            if expires_at < chrono::Utc::now() {
                return err_redirect("expired_state");
            }
            if let Err(reason) = verify_oauth_browser_bind(&headers, bind_hash.as_deref()) {
                warn!("GitHub login callback failed browser-binding check: {reason}");
                return err_redirect(reason);
            }
        }
        Ok(Some(_)) | Ok(None) => return err_redirect("invalid_state"),
        Err(e) => {
            warn!("Failed to load GitHub login state: {e}");
            return err_redirect("server_error");
        }
    }

    let code = match q.code {
        Some(ref c) if !c.is_empty() => c,
        _ => return err_redirect("missing_code"),
    };

    let client_id = std::env::var("GITHUB_LOGIN_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("GITHUB_LOGIN_CLIENT_SECRET").unwrap_or_default();
    if client_id.is_empty() || client_secret.is_empty() {
        warn!("GitHub login env vars missing during callback");
        return err_redirect("server_error");
    }

    let client = match tap_core::http_client::build_client(
        tap_core::http_client::ClientRoute::EgressProxy,
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build HTTP client for GitHub login exchange: {e}");
            return err_redirect("token_exchange_failed");
        }
    };
    let token_resp = client
        .post(github_token_url())
        // Without this GitHub answers form-encoded, not JSON.
        .header(axum::http::header::ACCEPT, "application/json")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code),
            ("redirect_uri", login_redirect_uri().as_str()),
        ])
        .send()
        .await;
    let token_body: serde_json::Value = match token_resp {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse GitHub login token response: {e}");
                return err_redirect("token_exchange_failed");
            }
        },
        Ok(resp) => {
            let status = resp.status();
            warn!("GitHub login token exchange failed ({status})");
            return err_redirect("token_exchange_failed");
        }
        Err(e) => {
            warn!("GitHub login token exchange request failed: {e}");
            return err_redirect("token_exchange_failed");
        }
    };
    // GitHub returns 200 with an `error` field on a bad/expired code.
    let access_token = match token_body.get("access_token").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => {
            warn!(
                "GitHub login token response missing access_token (error: {:?})",
                token_body.get("error")
            );
            return err_redirect("token_exchange_failed");
        }
    };

    // --- Identity fetch (the OIDC-id_token stand-in) -----------------------

    let api = github_api_url();
    let github_get = |path: &str| {
        client
            .get(format!("{api}{path}"))
            .bearer_auth(&access_token)
            .header(axum::http::header::ACCEPT, "application/vnd.github+json")
            // GitHub rejects requests without a User-Agent.
            .header(axum::http::header::USER_AGENT, "tap-proxy")
            .send()
    };

    let user_body: serde_json::Value = match github_get("/user").await {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse GitHub /user response: {e}");
                return err_redirect("identity_fetch_failed");
            }
        },
        other => {
            warn!("GitHub /user fetch failed: {other:?}");
            return err_redirect("identity_fetch_failed");
        }
    };
    let sub = match github_user_id(&user_body) {
        Some(id) => id,
        None => {
            warn!("GitHub /user response missing numeric id");
            return err_redirect("identity_fetch_failed");
        }
    };

    // /user's `email` field is unusable (null for private-email accounts and
    // carries no verified flag) — the emails endpoint is authoritative.
    let emails_body: serde_json::Value = match github_get("/user/emails").await {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse GitHub /user/emails response: {e}");
                return err_redirect("identity_fetch_failed");
            }
        },
        other => {
            warn!("GitHub /user/emails fetch failed: {other:?}");
            return err_redirect("identity_fetch_failed");
        }
    };
    // An unverified (or absent) primary GitHub email proves nothing about
    // mailbox ownership — refuse rather than seed an account (or a link,
    // which would be an account takeover) from it.
    let email = match primary_email(&emails_body) {
        Some((email, true)) => email,
        _ => return err_redirect("github_email_unverified"),
    };

    let identity = ProviderIdentity {
        sub,
        email,
        email_verified: true, // enforced above — GitHub verified the primary email
    };
    resolve_social_login(&state, PROVIDER_GITHUB, &identity).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_is_the_stringified_numeric_id() {
        let user = json!({"id": 5814972, "login": "octocat", "email": null});
        assert_eq!(github_user_id(&user).as_deref(), Some("5814972"));
        // login/email must never stand in for a missing id.
        assert!(github_user_id(&json!({"login": "octocat"})).is_none());
        assert!(github_user_id(&json!({"id": "not-a-number"})).is_none());
    }

    #[test]
    fn primary_email_selected_among_others() {
        let emails = json!([
            {"email": "Old@Example.net", "primary": false, "verified": true},
            {"email": " Person@Example.COM ", "primary": true, "verified": true},
        ]);
        assert_eq!(
            primary_email(&emails),
            Some(("person@example.com".to_string(), true))
        );
    }

    #[test]
    fn primary_email_verified_flag_never_defaults_true() {
        let unverified = json!([{"email": "a@b.c", "primary": true, "verified": false}]);
        assert_eq!(
            primary_email(&unverified),
            Some(("a@b.c".to_string(), false))
        );
        // Missing flag counts as unverified.
        let missing = json!([{"email": "a@b.c", "primary": true}]);
        assert_eq!(primary_email(&missing), Some(("a@b.c".to_string(), false)));
    }

    #[test]
    fn primary_email_absent_or_garbage_rejected() {
        assert!(primary_email(&json!([])).is_none());
        assert!(
            primary_email(&json!([{"email": "a@b.c", "primary": false, "verified": true}]))
                .is_none()
        );
        assert!(primary_email(
            &json!([{"email": "not-an-email", "primary": true, "verified": true}])
        )
        .is_none());
        assert!(primary_email(&json!({"not": "an array"})).is_none());
    }
}
