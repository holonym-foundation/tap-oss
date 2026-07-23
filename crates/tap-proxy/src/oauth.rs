//! Server-side Google OAuth 2.0 consent flow.
//!
//! Two endpoints:
//! - `POST /team/oauth/google/start` (authenticated) — returns Google auth URL
//! - `POST /team/oauth/google/reauthorize` (authenticated) — returns Google auth URL for repairing an existing credential
//! - `GET /oauth/google/callback` (public) — receives redirect, exchanges code, stores/updates credential

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

pub(crate) fn dashboard_url(path: &str) -> String {
    format!("{}/dashboard{}", crate::proxy::configured_app_url(), path)
}

use crate::admin::{
    authenticate_user, generate_session_token, get_tier_limits, hash_session_token,
    user_can_manage_workspace,
};
use crate::proxy::AppState;

const STATE_TTL_SECS: i64 = 600; // 10 minutes
const GOOGLE_OAUTH_FLOW_CREATE: &str = "create";
const GOOGLE_OAUTH_FLOW_REAUTHORIZE: &str = "reauthorize";

/// Host binding (Decision #17) for newly-created Google credentials. The proxy
/// injects a fresh `Authorization: Bearer` token and forwards to the
/// agent-controlled `X-TAP-Target`; without this pin a prompt-injected agent
/// could point the target at an attacker host and silently exfiltrate a live
/// Gmail/Calendar token. `*.googleapis.com` is a dot-boundary-safe suffix
/// wildcard (see `host_is_allowed`) covering `www.googleapis.com`,
/// `gmail.googleapis.com`, etc. — and the bare apex — while excluding
/// look-alikes like `googleapis.com.evil.com`. Mirrors the Microsoft path's
/// pin to `graph.microsoft.com`.
const GOOGLE_ALLOWED_HOST: &str = "*.googleapis.com";

/// Server-side catalog of selectable scope bundles. The dashboard sends bundle
/// ids, never raw scope strings — unknown ids are rejected, so a client can't
/// smuggle arbitrary scopes into the consent URL.
const GOOGLE_SCOPE_BUNDLES: &[(&str, &[&str])] = &[
    ("gmail", &["https://mail.google.com/"]),
    // Read-only Gmail — least privilege for "read my inbox" use cases that only
    // need to scan messages, never send or delete.
    (
        "gmail-readonly",
        &["https://www.googleapis.com/auth/gmail.readonly"],
    ),
    ("calendar", &["https://www.googleapis.com/auth/calendar"]),
    ("drive", &["https://www.googleapis.com/auth/drive"]),
    ("sheets", &["https://www.googleapis.com/auth/spreadsheets"]),
    ("contacts", &["https://www.googleapis.com/auth/contacts"]),
    ("tasks", &["https://www.googleapis.com/auth/tasks"]),
    (
        "workspace-admin",
        &[
            "https://www.googleapis.com/auth/admin.directory.user",
            "https://www.googleapis.com/auth/admin.directory.group",
            "https://www.googleapis.com/auth/admin.directory.orgunit",
            "https://www.googleapis.com/auth/apps.groups.settings",
        ],
    ),
    (
        "admin-reports",
        &[
            "https://www.googleapis.com/auth/admin.reports.audit.readonly",
            "https://www.googleapis.com/auth/admin.reports.usage.readonly",
        ],
    ),
    // Full Google Cloud Platform access (Service Usage, IAM, Compute, …) on
    // projects the consenting user can reach. Deliberately one broad scope:
    // GCP's own IAM limits what the user can actually do, and TAP's approval
    // gating covers the writes.
    (
        "google-cloud",
        &["https://www.googleapis.com/auth/cloud-platform"],
    ),
];

/// Bundles requested when the client doesn't specify any — matches the
/// pre-selection behavior (Gmail, Calendar, Drive, Sheets) for back-compat.
const DEFAULT_GOOGLE_BUNDLES: &[&str] = &["gmail", "calendar", "drive", "sheets"];

/// Scopes that were requested at consent time but absent from the granted set
/// (the user unchecked them on Google's granular consent screen). Both args
/// are space-separated scope strings.
fn missing_scopes(requested: &str, granted: &str) -> Vec<String> {
    let granted: std::collections::HashSet<&str> = granted.split_whitespace().collect();
    requested
        .split_whitespace()
        .filter(|s| !granted.contains(s))
        .map(|s| s.to_string())
        .collect()
}

/// Resolve bundle ids to a space-separated scope string for the consent URL.
/// Returns `Err(unknown_id)` on the first id not in the catalog.
fn resolve_google_scopes(bundle_ids: &[String]) -> Result<String, String> {
    let mut scopes: Vec<&str> = Vec::new();
    for id in bundle_ids {
        let bundle = GOOGLE_SCOPE_BUNDLES
            .iter()
            .find(|(name, _)| name == id)
            .ok_or_else(|| id.clone())?;
        for s in bundle.1 {
            if !scopes.contains(s) {
                scopes.push(s);
            }
        }
    }
    Ok(scopes.join(" "))
}

// ---------------------------------------------------------------------------
// POST /admin/oauth/google/start
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OAuthStartRequest {
    pub credential_name: String,
    pub credential_description: String,
    /// Scope bundle ids from `GOOGLE_SCOPE_BUNDLES`. Omitted ⇒ the default
    /// bundle set (back-compat with clients that predate scope selection).
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Agent key ids to grant the created credential to once consent completes,
    /// chosen on the connect page. Optional — empty ⇒ created unassigned. The
    /// assignment is carried through the OAuth round-trip and applied in the
    /// callback (see `handle_google_oauth_callback`).
    #[serde(default)]
    pub assign_agents: Vec<String>,
    /// Optional passkey step-up. When present (the connect-with-passkey flow),
    /// the assertion is bound to `challenge_id` (from `/start/begin`) and must
    /// belong to the acting user before the flow starts. Absent ⇒ the legacy
    /// session-authed modal path (unchanged).
    #[serde(default)]
    pub assertion: Option<webauthn_rs_proto::PublicKeyCredential>,
    #[serde(default)]
    pub challenge_id: Option<String>,
}

#[derive(Deserialize)]
pub struct OAuthReauthorizeRequest {
    pub credential_name: String,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

fn google_auth_url(client_id: &str, redirect_uri: &str, scope_string: &str, state: &str) -> String {
    let mut auth_url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", scope_string)
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("state", state);
    auth_url.to_string()
}

/// POST /team/oauth/google/start/begin — start the passkey ceremony that gates
/// the connect-with-passkey flow. Returns `{challenge_id, options}`; the browser
/// runs `navigator.credentials.get(options)` then calls `/start` with the
/// assertion + this `challenge_id`. Workspace-manager only (same gate as start),
/// so a scoped agent session can never begin it.
pub async fn handle_google_oauth_start_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(resp) => return resp.into_response(),
    };
    if !user_can_manage_workspace(&admin) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners and admins can create credentials"})),
        )
            .into_response();
    }
    let wa = match &state.webauthn_state {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "passkey not configured on this server"})),
            )
                .into_response()
        }
    };
    // The challenge id is an opaque token the begin/finish pair are bound to; it
    // is persisted with the challenge (DB-backed), so begin can land on one
    // instance and finish on another (Distributed State Rule).
    let challenge_id = format!("goauth:{}", generate_session_token());
    match wa.begin_approval(&challenge_id).await {
        Ok(options) => Json(json!({ "challenge_id": challenge_id, "options": options })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("could not start passkey: {e}")})),
        )
            .into_response(),
    }
}

pub async fn handle_google_oauth_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<OAuthStartRequest>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(resp) => return resp.into_response(),
    };
    if !user_can_manage_workspace(&admin) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners and admins can create credentials"})),
        )
            .into_response();
    }
    let store = state.db_state.store();

    let name = match crate::admin::validate_credential_name(&req.credential_name) {
        Ok(n) => n,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response(),
    };

    // Resolve scope bundles before any side effects
    let bundle_ids: Vec<String> = match req.scopes {
        Some(ids) if ids.is_empty() => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Select at least one scope"})),
            )
                .into_response()
        }
        Some(ids) => ids,
        None => DEFAULT_GOOGLE_BUNDLES
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    let scope_string = match resolve_google_scopes(&bundle_ids) {
        Ok(s) => s,
        Err(unknown) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Unknown scope bundle: {unknown}")})),
            )
                .into_response()
        }
    };

    // Check credential doesn't already exist
    if let Ok(Some(_)) = store.get_credential(&admin.team_id, &name).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Credential name already exists"})),
        )
            .into_response();
    }

    // Check tier limits
    if let Ok(Some(team)) = store.get_team(&admin.team_id).await {
        let limits = get_tier_limits(&team.tier);
        if let Some(max) = limits.max_credentials {
            if let Ok(creds) = store.list_credentials(&admin.team_id).await {
                if creds.len() >= max {
                    return (StatusCode::PAYMENT_REQUIRED, Json(json!({"error": format!("Credential limit reached ({}). Upgrade your plan.", max)}))).into_response();
                }
            }
        }
    }

    // Read env
    let client_id = match std::env::var("GOOGLE_OAUTH_CLIENT_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Google OAuth not configured"})),
            )
                .into_response()
        }
    };
    let redirect_uri = match std::env::var("GOOGLE_OAUTH_REDIRECT_URI") {
        Ok(v) if !v.is_empty() => v,
        _ => format!(
            "{}/oauth/google/callback",
            crate::proxy::configured_proxy_url()
        ),
    };

    // Carrying an agent assignment through this flow REQUIRES the passkey step-up
    // — it is a hard gate, not just UX. Without this, a bare session (e.g. a
    // stolen localStorage token) could POST `assign_agents` with no assertion and
    // ride the legacy path. The legacy modal never sends `assign_agents`, so it is
    // unaffected; the connect-with-passkey page always sends the assertion.
    if !req.assign_agents.is_empty() && req.assertion.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "a passkey is required to assign this credential to agents",
                "error_code": "passkey_required"
            })),
        )
            .into_response();
    }

    // Optional passkey step-up (connect-with-passkey flow). When the client sent
    // an assertion, verify it — bound to the challenge id from `/start/begin` and
    // owned by the acting user — BEFORE starting the flow. This is the security
    // boundary that lets the human authorize the connect + agent-assignment up
    // front (a hijacked browser session alone can't drive it). The legacy modal
    // path sends no assertion and is unchanged (session auth only).
    if let Some(assertion) = req.assertion {
        // The challenge id must be one we minted for THIS flow (`goauth:` prefix,
        // from `/start/begin`) — so a live challenge from another passkey flow
        // (proposal-resolve, cred-setup) can't be replayed to satisfy this gate.
        let challenge_id = match req.challenge_id.as_deref() {
            Some(c) if c.starts_with("goauth:") => c,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "a valid challenge_id from /start/begin is required with a passkey assertion"})),
                )
                    .into_response()
            }
        };
        let wa = match &state.webauthn_state {
            Some(wa) => wa,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "passkey not configured on this server"})),
                )
                    .into_response()
            }
        };
        match wa.finish_approval(challenge_id, &assertion).await {
            Ok(owner_email) => {
                if owner_email != admin.email {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": "passkey does not belong to the acting user"})),
                    )
                        .into_response();
                }
            }
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": format!("passkey verification failed: {e}")})),
                )
                    .into_response()
            }
        }
    }

    // Generate state token
    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);

    // Persist the pending flow in the DB so the public callback can be served by
    // ANY stateless instance (and survive a restart) — not just this one. (Was an
    // instance-local in-memory map, a Distributed State Rule violation.)
    let expires_at = (Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS)).to_rfc3339();
    if let Err(e) = store
        .create_oauth_state(
            &state_hash,
            &admin.id,
            &admin.team_id,
            &name,
            &req.credential_description,
            &scope_string,
            "google",
            &req.assign_agents,
            &expires_at,
        )
        .await
    {
        warn!("Failed to persist OAuth state: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Failed to start OAuth flow"})),
        )
            .into_response();
    }

    let auth_url = google_auth_url(&client_id, &redirect_uri, &scope_string, &state_token);

    Json(json!({ "auth_url": auth_url })).into_response()
}

#[derive(Deserialize)]
pub struct AppOAuthStartRequest {
    /// Logical credential name (e.g. `google`); stored namespaced per end-user.
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Where to send the end-user's browser after consent completes.
    pub return_url: String,
}

/// POST /app/users/{ext_id}/credentials/oauth/google/start — TAP-mediated
/// per-end-user Google OAuth. The app relays the returned consent URL to
/// its user; TAP's existing callback stores the refresh-token bundle scoped to
/// the end-user and redirects to `return_url`. **The OAuth tokens never touch
/// the app backend.**
pub async fn handle_app_google_oauth_start(
    State(state): State<AppState>,
    axum::extract::Path(ext_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<AppOAuthStartRequest>,
) -> Response {
    let agent = match crate::proxy::authenticate_agent_from_headers(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !agent.is_app {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Not an app key", "error_code": "not_an_app_key"})),
        )
            .into_response();
    }
    if !(req.return_url.starts_with("https://") || req.return_url.starts_with("http://")) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "return_url must be an http(s) URL"})),
        )
            .into_response();
    }
    let store = state.db_state.store();

    let bundle_ids: Vec<String> = match req.scopes {
        Some(ids) if ids.is_empty() => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Select at least one scope"})),
            )
                .into_response()
        }
        Some(ids) => ids,
        None => DEFAULT_GOOGLE_BUNDLES
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    let scope_string = match resolve_google_scopes(&bundle_ids) {
        Ok(s) => s,
        Err(unknown) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Unknown scope bundle: {unknown}")})),
            )
                .into_response()
        }
    };

    let cred_name = crate::proxy::end_user_cred_name(&ext_id, req.name.trim());
    if let Ok(Some(_)) = store.get_credential(&agent.team_id, &cred_name).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Credential already exists for this end-user", "error_code": "credential_exists"})),
        )
            .into_response();
    }

    let client_id = match std::env::var("GOOGLE_OAUTH_CLIENT_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Google OAuth not configured"})),
            )
                .into_response()
        }
    };
    let redirect_uri = std::env::var("GOOGLE_OAUTH_REDIRECT_URI").unwrap_or_else(|_| {
        format!(
            "{}/oauth/google/callback",
            crate::proxy::configured_proxy_url()
        )
    });

    let _ = store.upsert_end_user(&agent.team_id, &ext_id, None).await;

    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);
    let description = req
        .description
        .clone()
        .unwrap_or_else(|| format!("{} (Google, end-user {ext_id})", req.name.trim()));
    let expires_at = (Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS)).to_rfc3339();
    if let Err(e) = store
        .create_oauth_state_scoped(
            &state_hash,
            &agent.id,
            &agent.team_id,
            &cred_name,
            &description,
            &scope_string,
            "google",
            &ext_id,
            &req.return_url,
            &expires_at,
        )
        .await
    {
        warn!("Failed to persist scoped OAuth state: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Failed to start OAuth flow"})),
        )
            .into_response();
    }

    let auth_url = google_auth_url(&client_id, &redirect_uri, &scope_string, &state_token);
    Json(json!({ "consent_url": auth_url, "ext_id": ext_id, "name": req.name.trim() }))
        .into_response()
}

pub async fn handle_google_oauth_reauthorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<OAuthReauthorizeRequest>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(resp) => return resp.into_response(),
    };
    if !user_can_manage_workspace(&admin) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners and admins can reauthorize credentials"})),
        )
            .into_response();
    }
    let store = state.db_state.store();

    let name = req.credential_name.trim().to_lowercase();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Credential name must be 1-64 characters"})),
        )
            .into_response();
    }

    let existing = match store.get_credential(&admin.team_id, &name).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Credential '{name}' not found")})),
            )
                .into_response()
        }
        Err(e) => {
            warn!("Failed to load credential for Google reauthorization: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to load credential"})),
            )
                .into_response();
        }
    };

    if existing.connector != "sidecar" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Only Google OAuth sidecar credentials can be reauthorized"})),
        )
            .into_response();
    }

    let existing_value = match store.get_credential_value(&admin.team_id, &name).await {
        Ok(Some(v)) => String::from_utf8(v).unwrap_or_default(),
        Ok(None) => String::new(),
        Err(e) => {
            warn!("Failed to load credential value for Google reauthorization: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to load credential value"})),
            )
                .into_response();
        }
    };
    let existing_google = match crate::google_oauth::parse_google_oauth(&existing_value) {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Credential is not a Google OAuth credential"})),
            )
                .into_response()
        }
    };

    let scope_string = match req.scopes {
        Some(ids) if ids.is_empty() => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Select at least one scope"})),
            )
                .into_response()
        }
        Some(ids) => match resolve_google_scopes(&ids) {
            Ok(s) => s,
            Err(unknown) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Unknown scope bundle: {unknown}")})),
                )
                    .into_response()
            }
        },
        None => match existing_google.scopes {
            Some(s) if !s.trim().is_empty() => s,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Credential does not have stored Google scopes; choose permissions before reconnecting",
                        "reason": "scopes_required"
                    })),
                )
                    .into_response()
            }
        },
    };

    let client_id = match std::env::var("GOOGLE_OAUTH_CLIENT_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Google OAuth not configured"})),
            )
                .into_response()
        }
    };
    let redirect_uri = match std::env::var("GOOGLE_OAUTH_REDIRECT_URI") {
        Ok(v) if !v.is_empty() => v,
        _ => format!(
            "{}/oauth/google/callback",
            crate::proxy::configured_proxy_url()
        ),
    };

    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);
    let expires_at = (Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS)).to_rfc3339();
    if let Err(e) = store
        .create_oauth_state_with_flow(
            &state_hash,
            &admin.id,
            &admin.team_id,
            &name,
            &existing.description,
            &scope_string,
            GOOGLE_OAUTH_FLOW_REAUTHORIZE,
            "google",
            &[],
            &expires_at,
        )
        .await
    {
        warn!("Failed to persist Google reauthorization state: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Failed to start Google reauthorization flow"})),
        )
            .into_response();
    }

    let auth_url = google_auth_url(&client_id, &redirect_uri, &scope_string, &state_token);
    Json(json!({ "auth_url": auth_url })).into_response()
}

// ---------------------------------------------------------------------------
// GET /oauth/google/callback
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn handle_google_oauth_callback(
    State(state): State<AppState>,
    Query(q): Query<OAuthCallbackQuery>,
) -> Response {
    // Helper to redirect with error — absolute URL so the user always lands on
    // the configured public domain, regardless of which callback URL Google used.
    let err_redirect = |reason: &str| {
        // Append #/credentials so AppShell's hash router mounts Credentials.svelte,
        // which reads ?oauth=… and shows the result toast (mirrors ca86b42).
        Redirect::to(&dashboard_url(&format!(
            "?oauth=error&reason={reason}#/credentials"
        )))
        .into_response()
    };

    // User denied
    if q.error.is_some() {
        return err_redirect("access_denied");
    }

    let state_token = match q.state {
        Some(ref s) if !s.is_empty() => s,
        _ => return err_redirect("missing_state"),
    };

    // Validate + atomically consume state. Single-statement DELETE…RETURNING in
    // the DB, so a replayed callback can't double-spend and the callback works on
    // any instance regardless of where the flow started.
    let store = state.db_state.store();
    let pending = {
        let state_hash = hash_session_token(state_token);
        match store.take_oauth_state(&state_hash).await {
            Ok(Some(p)) if p.expires_at > Utc::now() => p,
            Ok(Some(_)) => return err_redirect("expired_state"),
            Ok(None) => return err_redirect("invalid_state"),
            Err(e) => {
                warn!("Failed to load OAuth state: {e}");
                return err_redirect("server_error");
            }
        }
    };

    // Provider guard: this callback only handles Google flows. A Microsoft state
    // (wrong redirect_uri would be misconfigured anyway) must not be consumed here.
    if pending.provider != "google" {
        warn!(
            "Google callback received non-google provider state: {}",
            pending.provider
        );
        return err_redirect("invalid_state");
    }

    let code = match q.code {
        Some(ref c) if !c.is_empty() => c,
        _ => return err_redirect("missing_code"),
    };

    // Read server-side secrets
    let client_id = std::env::var("GOOGLE_OAUTH_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("GOOGLE_OAUTH_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = match std::env::var("GOOGLE_OAUTH_REDIRECT_URI") {
        Ok(v) if !v.is_empty() => v,
        _ => format!(
            "{}/oauth/google/callback",
            crate::proxy::configured_proxy_url()
        ),
    };
    if client_id.is_empty() || client_secret.is_empty() {
        warn!("Google OAuth env vars missing during callback");
        return err_redirect("server_error");
    }

    // Exchange code for tokens
    let client =
        tap_core::http_client::build_client(tap_core::http_client::ClientRoute::EgressProxy);
    let token_resp = match client {
        Ok(client) => {
            client
                .post("https://oauth2.googleapis.com/token")
                .form(&[
                    ("client_id", client_id.as_str()),
                    ("client_secret", client_secret.as_str()),
                    ("code", code),
                    ("grant_type", "authorization_code"),
                    ("redirect_uri", redirect_uri.as_str()),
                ])
                .send()
                .await
        }
        Err(e) => {
            warn!("Failed to create HTTP client for Google token exchange: {e}");
            return err_redirect("token_exchange_failed");
        }
    };

    let token_body: serde_json::Value = match token_resp {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse Google token response: {e}");
                return err_redirect("token_exchange_failed");
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("Google token exchange failed ({status}): {body}");
            return err_redirect("token_exchange_failed");
        }
        Err(e) => {
            warn!("Google token exchange request failed: {e}");
            return err_redirect("token_exchange_failed");
        }
    };

    let refresh_token = match token_body.get("refresh_token").and_then(|v| v.as_str()) {
        Some(rt) => rt.to_string(),
        None => {
            warn!("No refresh_token in Google response");
            return err_redirect("no_refresh_token");
        }
    };

    // Reject partial grants: Google's granular consent screen lets the user
    // uncheck individual scopes. Storing the token anyway would create a
    // credential that silently 403s on the missing scopes — fail the flow so
    // the user can retry (or deselect the scope in the dashboard picker).
    // `pending.scopes` is empty only for rows created before scope tracking.
    if !pending.scopes.is_empty() {
        let granted = token_body
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // If Google ever omits `scope`, assume the full grant rather than
        // failing a flow we can't actually judge.
        if !granted.is_empty() {
            let missing = missing_scopes(&pending.scopes, granted);
            if !missing.is_empty() {
                warn!(
                    "Google OAuth partial grant for credential '{}': missing {missing:?}",
                    pending.credential_name
                );
                return err_redirect("scopes_declined");
            }
        }
    }

    // Store value with server-side secrets bundled
    let cred_value = json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "scopes": pending.scopes,
    })
    .to_string();

    if pending.flow_type == GOOGLE_OAUTH_FLOW_CREATE {
        // Create credential (reuses the `store` bound above for the state claim).
        // For a TAP-mediated per-end-user flow, scope it to the end-user (the
        // name is already namespaced); the OAuth tokens never touch the partner.
        if let Err(e) = store
            .create_credential_scoped(
                &pending.team_id,
                &pending.credential_name,
                &pending.credential_description,
                "sidecar",
                Some("http://127.0.0.1:8081"),
                false,
                None,
                None,
                None,
                pending.end_user_id.as_deref(),
            )
            .await
        {
            warn!("Failed to create credential: {e}");
            return err_redirect("credential_exists");
        }
        // Pin the injected Bearer token to Google's API host (Decision #17).
        // Best-effort: a failure here shouldn't strand a freshly-created
        // credential, but log it.
        if let Err(e) = store
            .set_credential_allowed_hosts(
                &pending.team_id,
                &pending.credential_name,
                &[GOOGLE_ALLOWED_HOST.to_string()],
            )
            .await
        {
            warn!("Failed to set allowed_hosts for Google credential: {e}");
        }
    } else if pending.flow_type != GOOGLE_OAUTH_FLOW_REAUTHORIZE {
        warn!("Unknown Google OAuth flow type: {}", pending.flow_type);
        return err_redirect("server_error");
    }

    if let Err(e) = store
        .set_credential_value(
            &pending.team_id,
            &pending.credential_name,
            cred_value.as_bytes(),
        )
        .await
    {
        warn!("Failed to store credential value: {e}");
        if pending.flow_type == GOOGLE_OAUTH_FLOW_CREATE {
            // Clean up the half-created credential
            let _ = store
                .delete_credential(&pending.team_id, &pending.credential_name)
                .await;
        }
        return err_redirect("server_error");
    }

    // Grant the freshly-created credential to the agent keys the human chose on
    // the connect page (carried through the OAuth round-trip in `assign_agents`),
    // under the same passkey that started the flow. Team-scoped `create` only —
    // never for a reauthorize (the credential already has its attachments) or a
    // per-end-user flow (end-user creds aren't team-agent assignable). Only
    // assign to agents that actually belong to this team; ignore unknown ids.
    if pending.flow_type == GOOGLE_OAUTH_FLOW_CREATE
        && pending.end_user_id.is_none()
        && !pending.assign_agents.is_empty()
    {
        let team_agent_ids: std::collections::HashSet<String> = store
            .list_agents(&pending.team_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.id)
            .collect();
        for agent_id in &pending.assign_agents {
            if team_agent_ids.contains(agent_id) {
                if let Err(e) = store
                    .add_direct_credential(&pending.team_id, agent_id, &pending.credential_name)
                    .await
                {
                    warn!("assign oauth credential to agent {agent_id}: {e}");
                }
            }
        }
    }

    let result = if pending.flow_type == GOOGLE_OAUTH_FLOW_REAUTHORIZE {
        "reauthorized"
    } else {
        "success"
    };
    // TAP-mediated per-end-user flow: return to the partner's app, not the TAP
    // dashboard. Only redirect to a return_url with a safe scheme.
    if let Some(ref return_url) = pending.return_url {
        if return_url.starts_with("https://") || return_url.starts_with("http://") {
            let sep = if return_url.contains('?') { '&' } else { '?' };
            return Redirect::to(&format!("{return_url}{sep}oauth={result}")).into_response();
        }
        warn!("Ignoring unsafe OAuth return_url scheme; falling back to dashboard");
    }
    Redirect::to(&dashboard_url(&format!(
        "?oauth={result}&cred={}#/credentials",
        pending.credential_name
    )))
    .into_response()
}

// ===========================================================================
// Microsoft (Entra / Graph) OAuth 2.0 consent flow
//
// Mirrors the Google flow above: team-level + per-end-user app-mediated consent,
// a shared public callback, and inline per-request token refresh (in
// `microsoft_oauth.rs`). Tenant `common` covers multi-tenant orgs + consumer
// accounts. `offline_access` is always requested so we receive a refresh token.
// ===========================================================================

const MICROSOFT_AUTHORIZE_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
pub(crate) const MICROSOFT_TOKEN_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/token";
/// Always requested alongside the resource scopes: `offline_access` yields the
/// refresh token; the OIDC scopes identify the user for the consent screen.
const MICROSOFT_BASE_SCOPES: &str = "offline_access openid email profile";

/// Selectable Graph scope bundles (issue #80). Only the Graph resource scopes
/// live here — `MICROSOFT_BASE_SCOPES` is appended for consent.
const MICROSOFT_SCOPE_BUNDLES: &[(&str, &[&str])] = &[
    ("mail-read", &["https://graph.microsoft.com/Mail.Read"]),
    ("mail-send", &["https://graph.microsoft.com/Mail.Send"]),
    ("calendar-read", &["https://graph.microsoft.com/Calendars.Read"]),
    (
        "calendar-readwrite",
        &["https://graph.microsoft.com/Calendars.ReadWrite"],
    ),
    ("contacts-read", &["https://graph.microsoft.com/Contacts.Read"]),
];

/// Default bundle set when the caller doesn't specify scopes.
const DEFAULT_MICROSOFT_BUNDLES: &[&str] = &[
    "mail-read",
    "mail-send",
    "calendar-read",
    "calendar-readwrite",
    "contacts-read",
];

/// The Graph upstream host a Microsoft credential is pinned to (Decision #17).
const MICROSOFT_GRAPH_HOST: &str = "graph.microsoft.com";

/// Resolve bundle ids to a space-separated **Graph resource** scope string
/// (without the base OIDC/offline scopes). `Err(id)` on the first unknown id.
fn resolve_microsoft_scopes(bundle_ids: &[String]) -> Result<String, String> {
    let mut scopes: Vec<&str> = Vec::new();
    for id in bundle_ids {
        let bundle = MICROSOFT_SCOPE_BUNDLES
            .iter()
            .find(|(name, _)| name == id)
            .ok_or_else(|| id.clone())?;
        for s in bundle.1 {
            if !scopes.contains(s) {
                scopes.push(s);
            }
        }
    }
    Ok(scopes.join(" "))
}

/// Full consent scope string = Graph resource scopes + base OIDC/offline scopes.
fn microsoft_consent_scopes(graph_scopes: &str) -> String {
    format!("{graph_scopes} {MICROSOFT_BASE_SCOPES}")
}

/// The trailing permission name of a scope (`https://graph.microsoft.com/Mail.Read`
/// → `Mail.Read`), so the partial-grant check matches regardless of whether
/// Microsoft echoes fully-qualified or short-form scopes in the token response.
fn microsoft_permission_name(scope: &str) -> &str {
    scope.rsplit('/').next().unwrap_or(scope)
}

/// Graph resource scopes requested but absent from the granted set. Compared by
/// permission name (see `microsoft_permission_name`). Base OIDC/offline scopes
/// are not in `requested` (we only store Graph scopes) so they never false-flag.
fn microsoft_missing_scopes(requested: &str, granted: &str) -> Vec<String> {
    let granted: std::collections::HashSet<&str> = granted
        .split_whitespace()
        .map(microsoft_permission_name)
        .collect();
    requested
        .split_whitespace()
        .filter(|s| !granted.contains(microsoft_permission_name(s)))
        .map(|s| s.to_string())
        .collect()
}

fn microsoft_auth_url(client_id: &str, redirect_uri: &str, consent_scopes: &str, state: &str) -> String {
    let mut auth_url = url::Url::parse(MICROSOFT_AUTHORIZE_URL).unwrap();
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("response_mode", "query")
        .append_pair("scope", consent_scopes)
        .append_pair("prompt", "consent")
        .append_pair("state", state);
    auth_url.to_string()
}

fn microsoft_redirect_uri() -> String {
    std::env::var("MICROSOFT_OAUTH_REDIRECT_URI")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}/oauth/microsoft/callback",
                crate::proxy::configured_proxy_url()
            )
        })
}

/// Resolve requested bundle ids (or the default set) to a Graph scope string.
#[allow(clippy::result_large_err)]
fn microsoft_graph_scopes_from_request(scopes: Option<Vec<String>>) -> Result<String, Response> {
    let bundle_ids: Vec<String> = match scopes {
        Some(ids) if ids.is_empty() => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Select at least one scope"})),
            )
                .into_response())
        }
        Some(ids) => ids,
        None => DEFAULT_MICROSOFT_BUNDLES
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    resolve_microsoft_scopes(&bundle_ids).map_err(|unknown| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Unknown scope bundle: {unknown}")})),
        )
            .into_response()
    })
}

// ---------------------------------------------------------------------------
// POST /team/oauth/microsoft/start
// ---------------------------------------------------------------------------

pub async fn handle_microsoft_oauth_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<OAuthStartRequest>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(resp) => return resp.into_response(),
    };
    if !user_can_manage_workspace(&admin) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners and admins can create credentials"})),
        )
            .into_response();
    }
    let store = state.db_state.store();

    let name = match crate::admin::validate_credential_name(&req.credential_name) {
        Ok(n) => n,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response(),
    };

    let graph_scopes = match microsoft_graph_scopes_from_request(req.scopes) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    if let Ok(Some(_)) = store.get_credential(&admin.team_id, &name).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Credential name already exists"})),
        )
            .into_response();
    }

    if let Ok(Some(team)) = store.get_team(&admin.team_id).await {
        let limits = get_tier_limits(&team.tier);
        if let Some(max) = limits.max_credentials {
            if let Ok(creds) = store.list_credentials(&admin.team_id).await {
                if creds.len() >= max {
                    return (StatusCode::PAYMENT_REQUIRED, Json(json!({"error": format!("Credential limit reached ({}). Upgrade your plan.", max)}))).into_response();
                }
            }
        }
    }

    let client_id = match std::env::var("MICROSOFT_OAUTH_CLIENT_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Microsoft OAuth not configured"})),
            )
                .into_response()
        }
    };
    let redirect_uri = microsoft_redirect_uri();

    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);
    let expires_at = (Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS)).to_rfc3339();
    if let Err(e) = store
        .create_oauth_state(
            &state_hash,
            &admin.id,
            &admin.team_id,
            &name,
            &req.credential_description,
            &graph_scopes,
            "microsoft",
            &[],
            &expires_at,
        )
        .await
    {
        warn!("Failed to persist Microsoft OAuth state: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Failed to start OAuth flow"})),
        )
            .into_response();
    }

    let auth_url = microsoft_auth_url(
        &client_id,
        &redirect_uri,
        &microsoft_consent_scopes(&graph_scopes),
        &state_token,
    );
    Json(json!({ "auth_url": auth_url })).into_response()
}

// ---------------------------------------------------------------------------
// POST /app/users/{ext_id}/credentials/oauth/microsoft/start
// ---------------------------------------------------------------------------

/// TAP-mediated per-end-user Microsoft OAuth. The app relays the returned consent
/// URL to its user; the callback stores the refresh-token bundle scoped to the
/// end-user and redirects to `return_url`. Tokens never touch the app backend.
pub async fn handle_app_microsoft_oauth_start(
    State(state): State<AppState>,
    axum::extract::Path(ext_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<AppOAuthStartRequest>,
) -> Response {
    let agent = match crate::proxy::authenticate_agent_from_headers(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if !agent.is_app {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Not an app key", "error_code": "not_an_app_key"})),
        )
            .into_response();
    }
    if !(req.return_url.starts_with("https://") || req.return_url.starts_with("http://")) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "return_url must be an http(s) URL"})),
        )
            .into_response();
    }
    let store = state.db_state.store();

    let graph_scopes = match microsoft_graph_scopes_from_request(req.scopes) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let cred_name = crate::proxy::end_user_cred_name(&ext_id, req.name.trim());
    if let Ok(Some(_)) = store.get_credential(&agent.team_id, &cred_name).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Credential already exists for this end-user", "error_code": "credential_exists"})),
        )
            .into_response();
    }

    let client_id = match std::env::var("MICROSOFT_OAUTH_CLIENT_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Microsoft OAuth not configured"})),
            )
                .into_response()
        }
    };
    let redirect_uri = microsoft_redirect_uri();

    let _ = store.upsert_end_user(&agent.team_id, &ext_id, None).await;

    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);
    let description = req
        .description
        .clone()
        .unwrap_or_else(|| format!("{} (Microsoft, end-user {ext_id})", req.name.trim()));
    let expires_at = (Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS)).to_rfc3339();
    if let Err(e) = store
        .create_oauth_state_scoped(
            &state_hash,
            &agent.id,
            &agent.team_id,
            &cred_name,
            &description,
            &graph_scopes,
            "microsoft",
            &ext_id,
            &req.return_url,
            &expires_at,
        )
        .await
    {
        warn!("Failed to persist scoped Microsoft OAuth state: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Failed to start OAuth flow"})),
        )
            .into_response();
    }

    let auth_url = microsoft_auth_url(
        &client_id,
        &redirect_uri,
        &microsoft_consent_scopes(&graph_scopes),
        &state_token,
    );
    Json(json!({ "consent_url": auth_url, "ext_id": ext_id, "name": req.name.trim() }))
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /team/oauth/microsoft/reauthorize
// ---------------------------------------------------------------------------

pub async fn handle_microsoft_oauth_reauthorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<OAuthReauthorizeRequest>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(resp) => return resp.into_response(),
    };
    if !user_can_manage_workspace(&admin) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners and admins can reauthorize credentials"})),
        )
            .into_response();
    }
    let store = state.db_state.store();

    let name = req.credential_name.trim().to_lowercase();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Credential name must be 1-64 characters"})),
        )
            .into_response();
    }

    let existing = match store.get_credential(&admin.team_id, &name).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Credential '{name}' not found")})),
            )
                .into_response()
        }
        Err(e) => {
            warn!("Failed to load credential for Microsoft reauthorization: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to load credential"})),
            )
                .into_response();
        }
    };

    let existing_value = match store.get_credential_value(&admin.team_id, &name).await {
        Ok(Some(v)) => String::from_utf8(v).unwrap_or_default(),
        Ok(None) => String::new(),
        Err(e) => {
            warn!("Failed to load credential value for Microsoft reauthorization: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to load credential value"})),
            )
                .into_response();
        }
    };
    let existing_ms = match crate::microsoft_oauth::parse_microsoft_oauth(&existing_value) {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Credential is not a Microsoft OAuth credential"})),
            )
                .into_response()
        }
    };

    let graph_scopes = match req.scopes {
        Some(ids) if ids.is_empty() => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Select at least one scope"})),
            )
                .into_response()
        }
        Some(ids) => match resolve_microsoft_scopes(&ids) {
            Ok(s) => s,
            Err(unknown) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Unknown scope bundle: {unknown}")})),
                )
                    .into_response()
            }
        },
        None => match existing_ms.scopes {
            Some(s) if !s.trim().is_empty() => s,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Credential does not have stored Microsoft scopes; choose permissions before reconnecting",
                        "reason": "scopes_required"
                    })),
                )
                    .into_response()
            }
        },
    };

    let client_id = match std::env::var("MICROSOFT_OAUTH_CLIENT_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Microsoft OAuth not configured"})),
            )
                .into_response()
        }
    };
    let redirect_uri = microsoft_redirect_uri();

    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);
    let expires_at = (Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS)).to_rfc3339();
    if let Err(e) = store
        .create_oauth_state_with_flow(
            &state_hash,
            &admin.id,
            &admin.team_id,
            &name,
            &existing.description,
            &graph_scopes,
            GOOGLE_OAUTH_FLOW_REAUTHORIZE,
            "microsoft",
            &[],
            &expires_at,
        )
        .await
    {
        warn!("Failed to persist Microsoft reauthorization state: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Failed to start Microsoft reauthorization flow"})),
        )
            .into_response();
    }

    let auth_url = microsoft_auth_url(
        &client_id,
        &redirect_uri,
        &microsoft_consent_scopes(&graph_scopes),
        &state_token,
    );
    Json(json!({ "auth_url": auth_url })).into_response()
}

// ---------------------------------------------------------------------------
// GET /oauth/microsoft/callback
// ---------------------------------------------------------------------------

pub async fn handle_microsoft_oauth_callback(
    State(state): State<AppState>,
    Query(q): Query<OAuthCallbackQuery>,
) -> Response {
    let err_redirect = |reason: &str| {
        Redirect::to(&dashboard_url(&format!(
            "?oauth=error&reason={reason}#/credentials"
        )))
        .into_response()
    };

    if q.error.is_some() {
        return err_redirect("access_denied");
    }

    let state_token = match q.state {
        Some(ref s) if !s.is_empty() => s,
        _ => return err_redirect("missing_state"),
    };

    let store = state.db_state.store();
    let pending = {
        let state_hash = hash_session_token(state_token);
        match store.take_oauth_state(&state_hash).await {
            Ok(Some(p)) if p.expires_at > Utc::now() => p,
            Ok(Some(_)) => return err_redirect("expired_state"),
            Ok(None) => return err_redirect("invalid_state"),
            Err(e) => {
                warn!("Failed to load OAuth state: {e}");
                return err_redirect("server_error");
            }
        }
    };

    // Provider guard: only Microsoft flows are handled here.
    if pending.provider != "microsoft" {
        warn!(
            "Microsoft callback received non-microsoft provider state: {}",
            pending.provider
        );
        return err_redirect("invalid_state");
    }

    let code = match q.code {
        Some(ref c) if !c.is_empty() => c,
        _ => return err_redirect("missing_code"),
    };

    let client_id = std::env::var("MICROSOFT_OAUTH_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("MICROSOFT_OAUTH_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = microsoft_redirect_uri();
    if client_id.is_empty() || client_secret.is_empty() {
        warn!("Microsoft OAuth env vars missing during callback");
        return err_redirect("server_error");
    }

    let client =
        tap_core::http_client::build_client(tap_core::http_client::ClientRoute::EgressProxy);
    let token_resp = match client {
        Ok(client) => {
            client
                .post(MICROSOFT_TOKEN_URL)
                .form(&[
                    ("client_id", client_id.as_str()),
                    ("client_secret", client_secret.as_str()),
                    ("code", code.as_str()),
                    ("grant_type", "authorization_code"),
                    ("redirect_uri", redirect_uri.as_str()),
                ])
                .send()
                .await
        }
        Err(e) => {
            warn!("Failed to create HTTP client for Microsoft token exchange: {e}");
            return err_redirect("token_exchange_failed");
        }
    };

    let token_body: serde_json::Value = match token_resp {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse Microsoft token response: {e}");
                return err_redirect("token_exchange_failed");
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("Microsoft token exchange failed ({status}): {body}");
            return err_redirect("token_exchange_failed");
        }
        Err(e) => {
            warn!("Microsoft token exchange request failed: {e}");
            return err_redirect("token_exchange_failed");
        }
    };

    let refresh_token = match token_body.get("refresh_token").and_then(|v| v.as_str()) {
        Some(rt) => rt.to_string(),
        None => {
            warn!("No refresh_token in Microsoft response (offline_access not granted?)");
            return err_redirect("no_refresh_token");
        }
    };

    // Reject partial grants: if the user unchecked a requested Graph scope, storing
    // the token would silently 403 later. `pending.scopes` holds Graph scopes only.
    if !pending.scopes.is_empty() {
        let granted = token_body
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !granted.is_empty() {
            let missing = microsoft_missing_scopes(&pending.scopes, granted);
            if !missing.is_empty() {
                warn!(
                    "Microsoft OAuth partial grant for credential '{}': missing {missing:?}",
                    pending.credential_name
                );
                return err_redirect("scopes_declined");
            }
        }
    }

    let cred_value = json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "token_url": MICROSOFT_TOKEN_URL,
        "scopes": pending.scopes,
    })
    .to_string();

    if pending.flow_type == GOOGLE_OAUTH_FLOW_CREATE {
        if let Err(e) = store
            .create_credential_scoped(
                &pending.team_id,
                &pending.credential_name,
                &pending.credential_description,
                "sidecar",
                Some("https://graph.microsoft.com"),
                false,
                None,
                None,
                None,
                pending.end_user_id.as_deref(),
            )
            .await
        {
            warn!("Failed to create Microsoft credential: {e}");
            return err_redirect("credential_exists");
        }
        // Pin the injected token to Graph (Decision #17). Best-effort: a failure
        // here shouldn't strand a freshly-created credential, but log it.
        if let Err(e) = store
            .set_credential_allowed_hosts(
                &pending.team_id,
                &pending.credential_name,
                &[MICROSOFT_GRAPH_HOST.to_string()],
            )
            .await
        {
            warn!("Failed to set allowed_hosts for Microsoft credential: {e}");
        }
    } else if pending.flow_type != GOOGLE_OAUTH_FLOW_REAUTHORIZE {
        warn!("Unknown Microsoft OAuth flow type: {}", pending.flow_type);
        return err_redirect("server_error");
    }

    if let Err(e) = store
        .set_credential_value(
            &pending.team_id,
            &pending.credential_name,
            cred_value.as_bytes(),
        )
        .await
    {
        warn!("Failed to store Microsoft credential value: {e}");
        if pending.flow_type == GOOGLE_OAUTH_FLOW_CREATE {
            let _ = store
                .delete_credential(&pending.team_id, &pending.credential_name)
                .await;
        }
        return err_redirect("server_error");
    }

    let result = if pending.flow_type == GOOGLE_OAUTH_FLOW_REAUTHORIZE {
        "reauthorized"
    } else {
        "success"
    };
    if let Some(ref return_url) = pending.return_url {
        if return_url.starts_with("https://") || return_url.starts_with("http://") {
            let sep = if return_url.contains('?') { '&' } else { '?' };
            return Redirect::to(&format!("{return_url}{sep}oauth={result}")).into_response();
        }
        warn!("Ignoring unsafe OAuth return_url scheme; falling back to dashboard");
    }
    Redirect::to(&dashboard_url(&format!(
        "?oauth={result}&cred={}#/credentials",
        pending.credential_name
    )))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bundles_match_legacy_scope_set() {
        let ids: Vec<String> = DEFAULT_GOOGLE_BUNDLES
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            resolve_google_scopes(&ids).unwrap(),
            "https://mail.google.com/ \
             https://www.googleapis.com/auth/calendar \
             https://www.googleapis.com/auth/drive \
             https://www.googleapis.com/auth/spreadsheets"
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    #[test]
    fn workspace_admin_bundle_resolves_directory_scopes() {
        let scopes = resolve_google_scopes(&["workspace-admin".to_string()]).unwrap();
        assert!(scopes.contains("admin.directory.user"));
        assert!(scopes.contains("admin.directory.group"));
        assert!(scopes.contains("admin.directory.orgunit"));
        assert!(scopes.contains("apps.groups.settings"));
        // Selecting only admin must not drag in Gmail/Drive
        assert!(!scopes.contains("mail.google.com"));
        assert!(!scopes.contains("auth/drive"));
    }

    #[test]
    fn unknown_bundle_id_rejected() {
        let err = resolve_google_scopes(&[
            "gmail".to_string(),
            "https://www.googleapis.com/auth/cloud-platform".to_string(),
        ])
        .unwrap_err();
        assert_eq!(err, "https://www.googleapis.com/auth/cloud-platform");
    }

    #[test]
    fn duplicate_bundles_deduplicate() {
        let scopes = resolve_google_scopes(&["gmail".to_string(), "gmail".to_string()]).unwrap();
        assert_eq!(scopes, "https://mail.google.com/");
    }

    #[test]
    fn all_catalog_bundles_resolve() {
        for (id, _) in GOOGLE_SCOPE_BUNDLES {
            resolve_google_scopes(&[id.to_string()]).unwrap();
        }
    }

    #[test]
    fn missing_scopes_full_grant_is_empty() {
        let req = "https://mail.google.com/ https://www.googleapis.com/auth/drive";
        assert!(missing_scopes(req, req).is_empty());
        // Extra granted scopes (e.g. openid) don't count as missing.
        assert!(missing_scopes(req, &format!("{req} openid")).is_empty());
    }

    #[test]
    fn missing_scopes_partial_grant_detected() {
        let missing = missing_scopes(
            "https://mail.google.com/ https://www.googleapis.com/auth/drive",
            "https://mail.google.com/",
        );
        assert_eq!(missing, vec!["https://www.googleapis.com/auth/drive"]);
    }

    #[test]
    fn missing_scopes_empty_requested_is_empty() {
        assert!(missing_scopes("", "anything").is_empty());
    }

    // -- Microsoft scope helpers --------------------------------------------

    #[test]
    fn microsoft_default_bundles_include_outlook_write_scopes() {
        let ids: Vec<String> = DEFAULT_MICROSOFT_BUNDLES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let scopes = resolve_microsoft_scopes(&ids).unwrap();
        assert!(scopes.contains("Mail.Read"));
        assert!(scopes.contains("Mail.Send"));
        assert!(scopes.contains("Calendars.Read"));
        assert!(scopes.contains("Calendars.ReadWrite"));
        assert!(scopes.contains("Contacts.Read"));
    }

    #[test]
    fn microsoft_consent_scopes_append_offline_and_oidc() {
        let consent = microsoft_consent_scopes("https://graph.microsoft.com/Mail.Read");
        assert!(consent.contains("Mail.Read"));
        assert!(consent.contains("offline_access"));
        assert!(consent.contains("openid"));
    }

    #[test]
    fn microsoft_unknown_bundle_rejected() {
        let err = resolve_microsoft_scopes(&["mail-read".to_string(), "drive-full".to_string()])
            .unwrap_err();
        assert_eq!(err, "drive-full");
    }

    #[test]
    fn microsoft_all_bundles_resolve() {
        for (id, _) in MICROSOFT_SCOPE_BUNDLES {
            resolve_microsoft_scopes(&[id.to_string()]).unwrap();
        }
    }

    #[test]
    fn microsoft_missing_scopes_matches_by_permission_name() {
        // Requested is fully-qualified; granted is short-form. Must NOT be flagged
        // as missing — Microsoft may echo either form.
        let requested = "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Calendars.Read";
        let granted = "Mail.Read Calendars.Read";
        assert!(microsoft_missing_scopes(requested, granted).is_empty());
    }

    #[test]
    fn microsoft_missing_scopes_partial_grant_detected() {
        let requested = "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Calendars.Read";
        let granted = "https://graph.microsoft.com/Mail.Read";
        let missing = microsoft_missing_scopes(requested, granted);
        assert_eq!(missing, vec!["https://graph.microsoft.com/Calendars.Read"]);
    }

    // A newly-created Google credential is host-pinned to `GOOGLE_ALLOWED_HOST`
    // (Decision #17) so the injected Bearer token can only ever be forwarded to
    // Google's API host. Guard the constant against a regression that would let
    // it match the wrong hosts, evaluated by the same `host_is_allowed` the
    // proxy enforces at forward time.
    #[test]
    fn google_allowed_host_pin_covers_google_apis_and_excludes_lookalikes() {
        assert_eq!(GOOGLE_ALLOWED_HOST, "*.googleapis.com");
        // Real Google API hosts the injected token legitimately reaches.
        assert!(crate::routing::host_is_allowed(GOOGLE_ALLOWED_HOST, "www.googleapis.com"));
        assert!(crate::routing::host_is_allowed(GOOGLE_ALLOWED_HOST, "gmail.googleapis.com"));
        assert!(crate::routing::host_is_allowed(GOOGLE_ALLOWED_HOST, "calendar.googleapis.com"));
        // Bare apex is covered by the dot-boundary-safe suffix wildcard.
        assert!(crate::routing::host_is_allowed(GOOGLE_ALLOWED_HOST, "googleapis.com"));
        // Exfiltration look-alikes must NOT match.
        assert!(!crate::routing::host_is_allowed(GOOGLE_ALLOWED_HOST, "googleapis.com.evil.com"));
        assert!(!crate::routing::host_is_allowed(GOOGLE_ALLOWED_HOST, "attacker.com"));
        assert!(!crate::routing::host_is_allowed(GOOGLE_ALLOWED_HOST, "notgoogleapis.com"));
    }
}
