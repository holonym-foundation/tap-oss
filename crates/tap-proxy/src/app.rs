//! TAP for Platforms — headless provisioning API.
//!
//! A partner registers one or more **apps** (a TAP team holding an `agents` row
//! with `kind='app'` — an **app key**). An app provisions and manages
//! credentials on behalf of its own end-users, who never hold a TAP account. All
//! endpoints authenticate with `X-TAP-Key` (which must be an app key), are
//! strictly team-scoped, and take the end-user's external id from the path.
//! Credentials are stored under the namespaced name `eu:{ext_id}/{logical}` with
//! the authoritative `end_user_id` column set, so the `/forward` + `/sign`
//! isolation checks apply uniformly.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use axum::extract::Query;
use std::collections::HashMap;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::auth::AuthenticatedAgent;
use crate::proxy::{authenticate_agent_from_headers, end_user_cred_name, AppState};
use tap_core::types::ApprovalStatus;

/// The free-form passkey identifier for a managed end-user. Team-qualified so
/// the same `ext_id` under two partners can never share a passkey, and so an
/// end-user can only ever approve their own team's requests.
pub fn end_user_approver_name(team_id: &str, ext_id: &str) -> String {
    format!("eu:{team_id}:{ext_id}")
}

/// Authenticate the caller and require that it is an app key. Returns the app
/// agent on success, or a ready-to-return error response.
async fn require_app(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedAgent, Response> {
    let agent = authenticate_agent_from_headers(state, headers).await?;
    if !agent.is_app {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "This API key is not an app key. Create an app key under Apps in the dashboard, or use an existing one.",
                "error_code": "not_an_app_key",
            })),
        )
            .into_response());
    }
    Ok(agent)
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub ext_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// POST /app/users — provision (or refresh) a managed end-user. Idempotent.
pub async fn handle_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if req.ext_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ext_id is required", "error_code": "invalid_end_user"})),
        )
            .into_response();
    }
    match state
        .db_state
        .store()
        .upsert_end_user(
            &agent.team_id,
            req.ext_id.trim(),
            req.display_name.as_deref(),
        )
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"ext_id": req.ext_id.trim(), "status": "active"})),
        )
            .into_response(),
        Err(e) => {
            warn!("create end-user failed: {e}");
            internal_error()
        }
    }
}

/// GET /app/users — list managed end-users for the partner team.
pub async fn handle_list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match state.db_state.store().list_end_users(&agent.team_id).await {
        Ok(users) => {
            let out: Vec<_> = users
                .iter()
                .map(|u| {
                    json!({
                        "ext_id": u.ext_id,
                        "display_name": u.display_name,
                        "status": u.status,
                        "created_at": u.created_at,
                        "last_seen_at": u.last_seen_at,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({"users": out}))).into_response()
        }
        Err(e) => {
            warn!("list end-users failed: {e}");
            internal_error()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateKeyRequest {
    /// Logical key name the partner/agent uses (e.g. `wallet`). Stored namespaced.
    pub name: String,
    /// `secp256k1` | `ed25519` | `p256`.
    pub algorithm: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Optional pre-existing private key to import instead of generating one.
    /// Shape: `{ "algorithm": "...", "private_key": "<hex>", "key_encoding"?: "hex"|"base64" }`
    /// (object, or its JSON string). When present the key is validated (parsed +
    /// pubkey derived, and a probe is signed) before storage; it is then stored
    /// AES-GCM-encrypted exactly like a generated key and never returned. Used to
    /// bring an externally-reconstructed key under TAP custody.
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

/// POST /app/users/{ext_id}/keys — provision a signing key for the end-user,
/// either generated in-proxy or imported from a caller-supplied `value` bundle.
/// The private key is stored AES-GCM-encrypted and never leaves TAP; only the
/// public identity is returned.
pub async fn handle_create_key(
    State(state): State<AppState>,
    Path(ext_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateKeyRequest>,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if let Some(resp) = validate_logical_name(&req.name) {
        return resp;
    }
    let algorithm = match crate::signing::Algorithm::parse(&req.algorithm) {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Unsupported algorithm '{}' (use secp256k1, ed25519, or p256)", req.algorithm),
                    "error_code": "invalid_algorithm",
                })),
            )
                .into_response();
        }
    };
    // Either import a caller-supplied private key or generate a fresh one. Both
    // yield a bundle string to store (AES-GCM-encrypted, never returned) plus the
    // public identity to surface. Import mirrors the admin credential-create
    // path: parse → validate (parses, derives the pubkey, and signs a probe —
    // fails on a bad key) → store as-is.
    let (bundle, public_json) = match req.value {
        Some(ref value) => {
            let supplied = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Object(_) => value.to_string(),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "value must be a signing-key bundle object (or its JSON string)",
                            "error_code": "invalid_value",
                        })),
                    )
                        .into_response();
                }
            };
            let cred = match crate::signing::parse_signing_credential(&supplied) {
                Some(c) => c,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "value is not a signing-key bundle {algorithm, private_key}",
                            "error_code": "invalid_signing_bundle",
                        })),
                    )
                        .into_response();
                }
            };
            if cred.algorithm != algorithm {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!(
                            "value.algorithm ({}) does not match the request algorithm ({})",
                            cred.algorithm.as_str(),
                            algorithm.as_str()
                        ),
                        "error_code": "algorithm_mismatch",
                    })),
                )
                    .into_response();
            }
            if let Err(e) = crate::signing::validate_import(&cred) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!("Invalid signing key: {e}"),
                        "error_code": "invalid_signing_key",
                    })),
                )
                    .into_response();
            }
            let public_json = match crate::signing::public_identity(&cred) {
                Ok(p) => p,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": format!("Invalid signing key: {e}"),
                            "error_code": "invalid_signing_key",
                        })),
                    )
                        .into_response();
                }
            };
            (supplied, public_json)
        }
        None => {
            let gen = match crate::signing::generate(algorithm) {
                Ok(g) => g,
                Err(e) => {
                    warn!("keygen failed: {e}");
                    return internal_error();
                }
            };
            let public_json = gen.public_json();
            (gen.bundle, public_json)
        }
    };

    let store = state.db_state.store();
    // Idempotently ensure the end-user exists before attaching a key.
    if let Err(e) = store.upsert_end_user(&agent.team_id, &ext_id, None).await {
        warn!("upsert end-user failed: {e}");
        return internal_error();
    }

    let stored_name = end_user_cred_name(&ext_id, &req.name);
    let description = req
        .description
        .clone()
        .unwrap_or_else(|| format!("{} signing key ({})", req.name, algorithm.as_str()));
    match store
        .create_credential_scoped_for_app(
            &agent.team_id,
            &stored_name,
            &description,
            "sidecar",
            Some("tap:sign"),
            false,
            None,
            None,
            Some(bundle.as_bytes()),
            Some(&ext_id),
            Some(&agent.id),
        )
        .await
    {
        Ok(()) => {
            if let Err(resp) = set_default_app_policy(&state, &agent, &stored_name).await {
                return resp;
            }
            let mut body = json!({ "ext_id": ext_id, "name": req.name });
            // Merge the public identity (address / public_key / algorithm).
            if let serde_json::Value::Object(ref mut map) = body {
                if let serde_json::Value::Object(pub_map) = public_json {
                    map.extend(pub_map);
                }
            }
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(tap_core::error::AgentSecError::AlreadyExists(_)) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": format!("Key '{}' already exists for this end-user", req.name),
                "error_code": "key_exists",
            })),
        )
            .into_response(),
        Err(e) => {
            warn!("create key failed: {e}");
            internal_error()
        }
    }
}

/// GET /app/users/{ext_id}/keys — list the end-user's signing keys with
/// their public addresses (never the private key).
pub async fn handle_list_keys(
    State(state): State<AppState>,
    Path(ext_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let creds = match state
        .db_state
        .store()
        .list_end_user_credentials(&agent.team_id, &ext_id)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!("list keys failed: {e}");
            return internal_error();
        }
    };
    let mut keys = Vec::new();
    for c in creds {
        // Only signing-key credentials are "keys"; others (OAuth/API) are
        // listed via the credentials endpoint.
        if c.api_base.as_deref() != Some("tap:sign") {
            continue;
        }
        let logical = strip_namespace(&ext_id, &c.name);
        let mut entry =
            json!({ "name": logical, "description": c.description, "created_at": c.created_at });
        if let Ok(Some(val)) = state.get_credential_value(&agent.team_id, &c.name).await {
            if let Some(sig) = crate::signing::parse_signing_credential(&val) {
                if let Ok(pub_id) = crate::signing::public_identity(&sig) {
                    if let (serde_json::Value::Object(ref mut m), serde_json::Value::Object(p)) =
                        (&mut entry, pub_id)
                    {
                        m.extend(p);
                    }
                }
            }
        }
        keys.push(entry);
    }
    (
        StatusCode::OK,
        Json(json!({ "ext_id": ext_id, "keys": keys })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CreateCredentialRequest {
    /// Logical credential name (e.g. `github`). Stored namespaced per end-user.
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub connector: Option<String>,
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default)]
    pub auth_header_format: Option<String>,
    /// The secret value — a JSON string (single secret) or object (multi-secret),
    /// mirroring the admin credential API. Signing bundles are rejected here.
    pub value: serde_json::Value,
}

/// POST /app/users/{ext_id}/credentials — backend provisioning of a
/// non-signing credential (API key, OAuth bundle the partner already holds,
/// multi-secret). For OAuth flows TAP can mediate instead (see oauth module);
/// this path is for secrets the partner already possesses.
pub async fn handle_create_credential(
    State(state): State<AppState>,
    Path(ext_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateCredentialRequest>,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if let Some(resp) = validate_logical_name(&req.name) {
        return resp;
    }

    // Normalize the value to the stored string form (string passes through;
    // object is serialized — the multi-secret shape the substitution path reads).
    let plaintext = match &req.value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(_) => req.value.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "value must be a JSON string (single secret) or object (multi-secret)",
                    "error_code": "invalid_value",
                })),
            )
                .into_response();
        }
    };
    // A signing-key bundle must be created via the keys endpoint so the private
    // key is generated in-proxy and never supplied over the wire.
    if crate::signing::parse_signing_credential(&plaintext).is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Signing keys must be created via POST /app/users/{ext_id}/keys, not supplied here.",
                "error_code": "signing_bundle_rejected",
            })),
        )
            .into_response();
    }

    let store = state.db_state.store();
    if let Err(e) = store.upsert_end_user(&agent.team_id, &ext_id, None).await {
        warn!("upsert end-user failed: {e}");
        return internal_error();
    }
    let stored_name = end_user_cred_name(&ext_id, &req.name);
    let connector = req.connector.as_deref().unwrap_or("direct");
    let description = req
        .description
        .clone()
        .unwrap_or_else(|| format!("{} credential", req.name));
    match store
        .create_credential_scoped_for_app(
            &agent.team_id,
            &stored_name,
            &description,
            connector,
            req.api_base.as_deref(),
            false,
            req.auth_header_format.as_deref(),
            None,
            Some(plaintext.as_bytes()),
            Some(&ext_id),
            Some(&agent.id),
        )
        .await
    {
        Ok(()) => {
            if let Err(resp) = set_default_app_policy(&state, &agent, &stored_name).await {
                return resp;
            }
            (
                StatusCode::CREATED,
                Json(json!({ "ext_id": ext_id, "name": req.name, "created": true })),
            )
                .into_response()
        }
        Err(tap_core::error::AgentSecError::AlreadyExists(_)) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": format!("Credential '{}' already exists for this end-user", req.name),
                "error_code": "credential_exists",
            })),
        )
            .into_response(),
        Err(e) => {
            warn!("create end-user credential failed: {e}");
            internal_error()
        }
    }
}

/// App-provisioned managed credentials default to app-mediated approval. TAP
/// still records a pending approval for write-equivalent actions, but the
/// corresponding app may approve it until the credential is upgraded to
/// passkey-required policy.
async fn set_default_app_policy(
    state: &AppState,
    agent: &AuthenticatedAgent,
    credential_name: &str,
) -> Result<(), Response> {
    let policy = tap_core::store::PolicyRow {
        credential_name: credential_name.to_string(),
        team_id: agent.team_id.clone(),
        auto_approve_methods: vec!["GET".to_string(), "HEAD".to_string()],
        require_approval_methods: vec![
            "POST".to_string(),
            "PUT".to_string(),
            "PATCH".to_string(),
            "DELETE".to_string(),
            "OPTIONS".to_string(),
        ],
        auto_approve_urls: vec![],
        require_approval_urls: vec![],
        allowed_approvers: vec![],
        approval_channel: Some("app".to_string()),
        telegram_chat_id: None,
        matrix_room_id: None,
        matrix_allowed_approvers: vec![],
        require_passkey: false,
        min_approvals: 1,
    };
    match state.db_state.store().set_policy(&policy).await {
        Ok(()) => {
            state
                .db_state
                .invalidate_policy_cache(&agent.team_id, credential_name)
                .await;
            Ok(())
        }
        Err(e) => {
            warn!("set default app policy failed: {e}");
            Err(internal_error())
        }
    }
}

/// Strip the `eu:{ext_id}/` prefix to recover the logical name for display.
fn strip_namespace(ext_id: &str, stored: &str) -> String {
    let prefix = format!("eu:{ext_id}/");
    stored
        .strip_prefix(&prefix)
        .map(|s| s.to_string())
        .unwrap_or_else(|| stored.to_string())
}

/// Reject logical names that would break or escape the `eu:{ext}/` namespace.
fn validate_logical_name(name: &str) -> Option<Response> {
    if name.trim().is_empty() || name.contains('/') || name.starts_with("eu:") {
        return Some(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid credential name (must be non-empty and must not contain '/' or start with 'eu:')",
                    "error_code": "invalid_credential_name",
                })),
            )
                .into_response(),
        );
    }
    None
}

fn internal_error() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "Service temporarily unavailable", "safe_to_retry": true})),
    )
        .into_response()
}

/// GET /app/usage?from=&to= — per-end-user request counts (the billing /
/// metering dimension), derived from the audit log. `from`/`to` are RFC3339;
/// default to the last 30 days.
pub async fn handle_usage(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let to = q
        .get("to")
        .cloned()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let from = q
        .get("from")
        .cloned()
        .unwrap_or_else(|| (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339());
    match state
        .db_state
        .store()
        .end_user_usage(&agent.team_id, &from, &to)
        .await
    {
        Ok(rows) => {
            let total_requests: i64 = rows.iter().map(|(_, n)| *n).sum();
            let by_end_user: Vec<_> = rows
                .iter()
                .map(|(ext, n)| json!({ "ext_id": ext, "requests": n }))
                .collect();
            Json(json!({
                "from": from,
                "to": to,
                "active_end_users": rows.len(),
                "total_requests": total_requests,
                "by_end_user": by_end_user,
            }))
            .into_response()
        }
        Err(e) => {
            warn!("usage query failed: {e}");
            internal_error()
        }
    }
}

// ---------------------------------------------------------------------------
// Account-less end-user passkey ceremony (high-stakes approval tier).
//
// The partner relays the WebAuthn challenge/assertion between TAP and the
// end-user's authenticator (the partner owns the UI — headless). Registration
// and approval challenges are persisted durably so begin/finish can land on
// different proxy instances. The approval is scoped to the end-user's own
// passkey identity, so end-user A can never approve end-user B's request.
// ---------------------------------------------------------------------------

#[allow(clippy::result_large_err)]
fn require_webauthn(
    state: &AppState,
) -> Result<std::sync::Arc<crate::webauthn::WebAuthnState>, Response> {
    match &state.webauthn_state {
        Some(w) => Ok(w.clone()),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Passkey support is not configured on this server",
                "error_code": "webauthn_unavailable",
            })),
        )
            .into_response()),
    }
}

/// POST /app/users/{ext_id}/passkey/register/begin
pub async fn handle_passkey_register_begin(
    State(state): State<AppState>,
    Path(ext_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let webauthn = match require_webauthn(&state) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let approver = end_user_approver_name(&agent.team_id, &ext_id);
    match webauthn.begin_registration(&approver, &ext_id).await {
        Ok(ccr) => Json(ccr).into_response(),
        Err(e) => {
            warn!("passkey register begin failed: {e}");
            internal_error()
        }
    }
}

/// POST /app/users/{ext_id}/passkey/register/finish
pub async fn handle_passkey_register_finish(
    State(state): State<AppState>,
    Path(ext_id): Path<String>,
    headers: HeaderMap,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let webauthn = match require_webauthn(&state) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    // Ensure the end-user exists (idempotent) so a registered passkey always
    // corresponds to a known end-user row.
    let _ = state
        .db_state
        .store()
        .upsert_end_user(&agent.team_id, &ext_id, None)
        .await;
    let approver = end_user_approver_name(&agent.team_id, &ext_id);
    match webauthn.finish_registration(&approver, &reg).await {
        Ok(_) => (
            StatusCode::CREATED,
            Json(json!({ "ext_id": ext_id, "registered": true })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "passkey_registration_failed", "message": e.to_string()})),
        )
            .into_response(),
    }
}

/// Verify the pending approval `txn_id` belongs to the app's team.
async fn require_team_txn(
    state: &AppState,
    agent: &AuthenticatedAgent,
    txn_id: &str,
) -> Result<(), Response> {
    match state.db_state.store().get_async_approval(txn_id).await {
        Ok(Some(row)) if row.team_id == agent.team_id => Ok(()),
        Ok(_) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No such pending approval for this team", "error_code": "txn_not_found"})),
        )
            .into_response()),
        Err(e) => {
            warn!("async approval lookup failed: {e}");
            Err(internal_error())
        }
    }
}

/// POST /app/users/{ext_id}/approvals/{txn_id}/passkey/begin
pub async fn handle_approval_passkey_begin(
    State(state): State<AppState>,
    Path((ext_id, txn_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_team_txn(&state, &agent, &txn_id).await {
        return resp;
    }
    let webauthn = match require_webauthn(&state) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let approver = end_user_approver_name(&agent.team_id, &ext_id);
    match webauthn
        .begin_approval_for_approver(&txn_id, &approver)
        .await
    {
        Ok(rcr) => Json(rcr).into_response(),
        Err(e) if e.to_string().contains("No passkey registered") => (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "error": "no_passkey",
                "message": "This end-user has no registered passkey. Register one first.",
            })),
        )
            .into_response(),
        Err(e) => {
            warn!("approval passkey begin failed: {e}");
            internal_error()
        }
    }
}

/// POST /app/users/{ext_id}/approvals/{txn_id}/passkey/finish
pub async fn handle_approval_passkey_finish(
    State(state): State<AppState>,
    Path((ext_id, txn_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(auth): Json<PublicKeyCredential>,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_team_txn(&state, &agent, &txn_id).await {
        return resp;
    }
    let webauthn = match require_webauthn(&state) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let approver = end_user_approver_name(&agent.team_id, &ext_id);
    match webauthn
        .finish_approval_for_approver(&txn_id, &approver, &auth)
        .await
    {
        Ok(()) => {
            // Resolve through the identity-scoped gate: this only approves a row
            // whose required_end_user matches this end-user, then signals the
            // /sign + /forward waiter. A team/messaging path cannot do this.
            let resolved = webauthn
                .resolve_approval_for_end_user(&txn_id, ApprovalStatus::Approved, &ext_id)
                .await;
            if !resolved {
                return (
                    StatusCode::GONE,
                    Json(json!({
                        "error": "session_expired",
                        "message": "This approval timed out or was already resolved. Ask the agent to retry.",
                    })),
                )
                    .into_response();
            }
            Json(json!({ "approved": true, "ext_id": ext_id })).into_response()
        }
        Err(e) if e.to_string().contains("No pending approval challenge") => (
            StatusCode::CONFLICT,
            Json(
                json!({"error": "stale_challenge", "message": "Begin the passkey ceremony again."}),
            ),
        )
            .into_response(),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "passkey_verification_failed", "message": e.to_string()})),
        )
            .into_response(),
    }
}

/// POST /app/users/{ext_id}/approvals/{txn_id}/approve — approve on behalf of
/// the managed end-user when, and only when, the credential was created by this
/// app and its policy explicitly permits app-mediated approval.
pub async fn handle_approval_approve(
    State(state): State<AppState>,
    Path((ext_id, txn_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_team_txn(&state, &agent, &txn_id).await {
        return resp;
    }

    let details_json = match state
        .db_state
        .store()
        .get_pending_approval_details(&txn_id)
        .await
    {
        Ok(Some(details)) => details,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "No pending approval for this transaction",
                    "error_code": "approval_not_found",
                })),
            )
                .into_response();
        }
        Err(e) => {
            warn!("pending approval lookup failed: {e}");
            return internal_error();
        }
    };
    let details: crate::webauthn::ApprovalDetails = match serde_json::from_str(&details_json) {
        Ok(d) => d,
        Err(e) => {
            warn!("pending approval details are malformed: {e}");
            return internal_error();
        }
    };
    if details.team_id != agent.team_id {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No such pending approval for this team", "error_code": "txn_not_found"})),
        )
            .into_response();
    }

    let cred = match state
        .db_state
        .store()
        .get_credential(&agent.team_id, &details.credential_name)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(
                    json!({"error": "Credential not found", "error_code": "credential_not_found"}),
                ),
            )
                .into_response();
        }
        Err(e) => {
            warn!("credential lookup failed: {e}");
            return internal_error();
        }
    };
    if cred.end_user_id.as_deref() != Some(ext_id.as_str()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Approval is not owned by the asserted end-user",
                "error_code": "end_user_mismatch",
            })),
        )
            .into_response();
    }
    if cred.app_id.as_deref() != Some(agent.id.as_str()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Only the app that created this managed credential may approve it",
                "error_code": "app_mismatch",
            })),
        )
            .into_response();
    }

    let policy = match state
        .db_state
        .store()
        .get_policy(&agent.team_id, &details.credential_name)
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "Credential policy does not allow app approval",
                    "error_code": "app_approval_not_allowed",
                })),
            )
                .into_response();
        }
        Err(e) => {
            warn!("policy lookup failed: {e}");
            return internal_error();
        }
    };
    if policy.require_passkey {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "This credential requires end-user passkey approval",
                "error_code": "passkey_required",
            })),
        )
            .into_response();
    }
    if policy.approval_channel.as_deref() != Some("app") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Credential policy does not allow app approval",
                "error_code": "app_approval_not_allowed",
            })),
        )
            .into_response();
    }

    let resolved = if let Some(ref webauthn) = state.webauthn_state {
        webauthn
            .resolve_approval_for_end_user(&txn_id, ApprovalStatus::Approved, &ext_id)
            .await
    } else {
        match state
            .db_state
            .store()
            .resolve_pending_approval_as_end_user(&txn_id, "approved", &ext_id, Some(&agent.id))
            .await
        {
            Ok(resolved) => resolved,
            Err(e) => {
                warn!("app approval resolve failed: {e}");
                return internal_error();
            }
        }
    };
    if !resolved {
        return (
            StatusCode::GONE,
            Json(json!({
                "error": "session_expired",
                "message": "This approval timed out or was already resolved. Ask the app to retry.",
            })),
        )
            .into_response();
    }
    Json(json!({ "approved": true, "ext_id": ext_id })).into_response()
}

// ---------------------------------------------------------------------------
// Passkey-lock (R2): a *permissive* policy change to a passkey-protected
// end-user credential must be authorized by the end-user's passkey, not the
// partner's session. Tightening is always allowed. The same check also gates
// the admin policy endpoint (see admin::handle_set_policy) so the namespaced
// name can't be used to bypass it.
// ---------------------------------------------------------------------------

/// If `cred_name` is an end-user credential whose CURRENT policy requires a
/// passkey and `proposed` would loosen it, returns `Some(ext_id)` — the change
/// is locked behind that end-user's passkey. Otherwise `None` (apply directly).
pub(crate) async fn end_user_policy_lock(
    state: &AppState,
    team_id: &str,
    cred_name: &str,
    proposed: &tap_core::store::PolicyRow,
) -> Result<Option<String>, tap_core::error::AgentSecError> {
    let store = state.db_state.store();
    let cred = match store.get_credential(team_id, cred_name).await? {
        Some(c) => c,
        None => return Ok(None),
    };
    let Some(ext) = cred.end_user_id else {
        return Ok(None);
    };
    let current = store.get_policy(team_id, cred_name).await?;
    let current_view = current.as_ref().map(crate::proposals::policy_view_from_row);
    // The lock only applies while the credential is currently passkey-protected.
    if !current_view
        .as_ref()
        .map(|v| v.require_passkey)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    let proposed_view = crate::proposals::policy_view_from_row(proposed);
    let permissive =
        tap_core::policy_diff::permissive_changes(current_view.as_ref(), &proposed_view);
    Ok((!permissive.is_empty()).then_some(ext))
}

#[derive(Deserialize)]
pub struct AppPolicyUpdate {
    #[serde(default)]
    pub auto_approve_methods: Vec<String>,
    #[serde(default)]
    pub require_approval_methods: Vec<String>,
    #[serde(default)]
    pub auto_approve_urls: Vec<String>,
    #[serde(default)]
    pub require_approval_urls: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_approvers: Vec<String>,
    #[serde(default = "default_true_policy")]
    pub require_passkey: bool,
    #[serde(default = "default_min_approvals")]
    pub min_approvals: u32,
}

fn default_true_policy() -> bool {
    true
}
fn default_min_approvals() -> u32 {
    1
}

/// PUT /app/users/{ext_id}/credentials/{name}/policy — set an end-user
/// credential's policy. Tightening (and any change while not passkey-protected)
/// applies immediately; a permissive change to a passkey-protected credential
/// is staged and returns a txn the end-user must approve with their passkey.
pub async fn handle_set_end_user_policy(
    State(state): State<AppState>,
    Path((ext_id, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<AppPolicyUpdate>,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let cred_name = end_user_cred_name(&ext_id, &name);
    let require_approval_urls = match req.require_approval_urls {
        Some(urls) => urls,
        None => match state
            .db_state
            .store()
            .get_policy(&agent.team_id, &cred_name)
            .await
        {
            Ok(Some(current)) => current.require_approval_urls,
            Ok(None) => Vec::new(),
            Err(e) => return crate::proxy::error_response(e),
        },
    };
    let proposed = tap_core::store::PolicyRow {
        credential_name: cred_name.clone(),
        team_id: agent.team_id.clone(),
        auto_approve_methods: req.auto_approve_methods,
        require_approval_methods: req.require_approval_methods,
        auto_approve_urls: req.auto_approve_urls,
        require_approval_urls,
        allowed_approvers: req.allowed_approvers,
        approval_channel: if req.require_passkey {
            None
        } else {
            Some("app".to_string())
        },
        telegram_chat_id: None,
        matrix_room_id: None,
        matrix_allowed_approvers: vec![],
        require_passkey: req.require_passkey,
        min_approvals: req.min_approvals.max(1),
    };

    let locked = match end_user_policy_lock(&state, &agent.team_id, &cred_name, &proposed).await {
        Ok(l) => l,
        Err(e) => {
            warn!("policy lock check failed: {e}");
            return internal_error();
        }
    };

    if locked.is_none() {
        return match state.db_state.store().set_policy(&proposed).await {
            Ok(()) => {
                state
                    .db_state
                    .invalidate_policy_cache(&agent.team_id, &cred_name)
                    .await;
                Json(json!({ "ext_id": ext_id, "name": name, "policy_set": true })).into_response()
            }
            Err(e) => {
                warn!("set end-user policy failed: {e}");
                internal_error()
            }
        };
    }

    // Permissive change to a passkey-protected credential: stage it.
    let txn_id = uuid::Uuid::new_v4().to_string();
    let proposed_json = match serde_json::to_string(&proposed) {
        Ok(j) => j,
        Err(e) => {
            warn!("serialize proposed policy failed: {e}");
            return internal_error();
        }
    };
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();
    if let Err(e) = state
        .db_state
        .store()
        .create_pending_policy_change(
            &txn_id,
            &agent.team_id,
            &cred_name,
            &ext_id,
            &proposed_json,
            &expires_at,
        )
        .await
    {
        warn!("stage policy change failed: {e}");
        return internal_error();
    }
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "txn_id": txn_id,
            "requires_end_user_passkey": true,
            "message": "This change loosens a passkey-protected credential and must be approved with the end-user's passkey.",
        })),
    )
        .into_response()
}

/// POST /app/users/{ext_id}/policy-changes/{txn_id}/passkey/begin
pub async fn handle_policy_change_passkey_begin(
    State(state): State<AppState>,
    Path((ext_id, txn_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match state
        .db_state
        .store()
        .get_pending_policy_change(&txn_id)
        .await
    {
        Ok(Some(c))
            if c.team_id == agent.team_id
                && c.required_end_user == ext_id
                && c.status == "pending" => {}
        Ok(_) => return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No such pending policy change", "error_code": "txn_not_found"})),
        )
            .into_response(),
        Err(e) => {
            warn!("policy change lookup failed: {e}");
            return internal_error();
        }
    }
    let webauthn = match require_webauthn(&state) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let approver = end_user_approver_name(&agent.team_id, &ext_id);
    match webauthn
        .begin_approval_for_approver(&txn_id, &approver)
        .await
    {
        Ok(rcr) => Json(rcr).into_response(),
        Err(e) if e.to_string().contains("No passkey registered") => (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({"error": "no_passkey", "message": "Register an end-user passkey first."})),
        )
            .into_response(),
        Err(e) => {
            warn!("policy change passkey begin failed: {e}");
            internal_error()
        }
    }
}

/// POST /app/users/{ext_id}/policy-changes/{txn_id}/passkey/finish
pub async fn handle_policy_change_passkey_finish(
    State(state): State<AppState>,
    Path((ext_id, txn_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(auth): Json<PublicKeyCredential>,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let change = match state
        .db_state
        .store()
        .get_pending_policy_change(&txn_id)
        .await
    {
        Ok(Some(c)) if c.team_id == agent.team_id && c.required_end_user == ext_id => c,
        Ok(_) => return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No such pending policy change", "error_code": "txn_not_found"})),
        )
            .into_response(),
        Err(e) => {
            warn!("policy change lookup failed: {e}");
            return internal_error();
        }
    };
    let webauthn = match require_webauthn(&state) {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let approver = end_user_approver_name(&agent.team_id, &ext_id);
    if let Err(e) = webauthn
        .finish_approval_for_approver(&txn_id, &approver, &auth)
        .await
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "passkey_verification_failed", "message": e.to_string()})),
        )
            .into_response();
    }
    // Atomically claim (single-use) then apply the staged policy.
    match state.db_state.store().claim_pending_policy_change(&txn_id, &ext_id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "already_resolved", "message": "This change was already applied or expired."})),
            )
                .into_response()
        }
        Err(e) => {
            warn!("claim policy change failed: {e}");
            return internal_error();
        }
    }
    let proposed: tap_core::store::PolicyRow =
        match serde_json::from_str(&change.proposed_policy_json) {
            Ok(p) => p,
            Err(e) => {
                warn!("deserialize staged policy failed: {e}");
                return internal_error();
            }
        };
    match state.db_state.store().set_policy(&proposed).await {
        Ok(()) => {
            state
                .db_state
                .invalidate_policy_cache(&agent.team_id, &change.credential_name)
                .await;
            Json(json!({ "ext_id": ext_id, "applied": true })).into_response()
        }
        Err(e) => {
            warn!("apply staged policy failed: {e}");
            internal_error()
        }
    }
}

/// POST /app/users/{ext_id}/approvals/{txn_id}/deny — deny on the
/// end-user's behalf (fail-closed; no passkey required to deny).
pub async fn handle_approval_deny(
    State(state): State<AppState>,
    Path((ext_id, txn_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let agent = match require_app(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_team_txn(&state, &agent, &txn_id).await {
        return resp;
    }
    if let Some(ref w) = state.webauthn_state {
        w.resolve_approval(&txn_id, ApprovalStatus::Denied).await;
    } else {
        let _ = state
            .db_state
            .store()
            .resolve_pending_approval(&txn_id, "denied", Some(&ext_id))
            .await;
    }
    Json(json!({ "denied": true, "ext_id": ext_id })).into_response()
}
