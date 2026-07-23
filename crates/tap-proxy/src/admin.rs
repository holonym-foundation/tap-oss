//! Admin authentication and management API.
//!
//! Admins are humans — separate from agents. They authenticate with
//! email + password + passkey (WebAuthn). Agents use API keys.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tap_core::config::AuthBinding;
use tap_core::error::AgentSecError;
use tap_core::store::{AdminInviteRow, AgentRow, ConfigStore};
use tracing::{info, warn};

use crate::analytics;
use crate::db_state::DbState;

const INVITE_ACTION_CREATE_ACCOUNT: &str = "create_account";
const INVITE_ACTION_LOGIN_TO_ACCEPT: &str = "login_to_accept";
const INVITE_ACTION_ALREADY_MEMBER: &str = "already_member";
pub(crate) const ROLE_OWNER: &str = "owner";
const ROLE_ADMIN: &str = "admin";
const ROLE_APPROVER: &str = "approver";
const DEFAULT_INVITE_ROLE: &str = ROLE_APPROVER;
const ALL_CAPABILITIES: &[&str] = &[
    "view_profile",
    "manage_profile",
    "manage_passkeys",
    "view_team",
    "approve_requests",
    "view_assigned_credentials",
    "manage_credentials",
    "manage_agents",
    "manage_own_agents",
    "manage_roles",
    "manage_policies",
    "manage_members",
    "manage_notification_channels",
    "manage_billing",
    "manage_owners",
];

struct InviteResolution {
    team_name: String,
    already_member: bool,
    has_account: bool,
    action: &'static str,
}

// ---------------------------------------------------------------------------
// Password hashing (argon2)
// ---------------------------------------------------------------------------

/// Hash a password with argon2id.
pub fn hash_password(password: &str) -> Result<String, AgentSecError> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AgentSecError::Internal(format!("Password hash failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a password against an argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Session tokens
// ---------------------------------------------------------------------------

/// Generate a random 32-byte hex session token.
pub fn generate_session_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 hash of a session token (stored in DB, never the raw token).
pub fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Email verification codes
// ---------------------------------------------------------------------------

/// Generate a 6-digit verification code.
pub fn generate_verification_code() -> String {
    use rand::Rng;
    let code: u32 = rand::thread_rng().gen_range(100_000..1_000_000);
    format!("{code}")
}

/// SHA-256 hash of a verification code.
pub fn hash_verification_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Admin session extractor
// ---------------------------------------------------------------------------

/// Authenticated user resolved in the context of their session's active team.
/// This is the store `Member` shape: `.id` is the user id, `.team_id` the active
/// team, `.member_role`/`.is_owner()`/`.email` as before.
pub type AuthUser = tap_core::store::Member;

pub fn user_can_manage_workspace(user: &AuthUser) -> bool {
    role_can_manage_workspace(&user.member_role)
}

pub fn role_can_manage_workspace(role: &str) -> bool {
    matches!(role, ROLE_OWNER | ROLE_ADMIN)
}

pub fn user_capabilities(user: &AuthUser) -> Vec<&'static str> {
    capabilities_for_role(&user.member_role, user.is_owner())
}

fn capabilities_for_role(role: &str, is_owner: bool) -> Vec<&'static str> {
    let mut caps = vec![
        "view_profile",
        "manage_profile",
        "manage_passkeys",
        "view_team",
        "approve_requests",
    ];
    if role == ROLE_APPROVER {
        caps.push("view_assigned_credentials");
        caps.push("manage_own_agents");
        return caps;
    }
    if matches!(role, ROLE_OWNER | ROLE_ADMIN) {
        caps.extend([
            "manage_credentials",
            "manage_agents",
            "manage_roles",
            "manage_policies",
            "manage_members",
            "manage_notification_channels",
            "manage_billing",
        ]);
    }
    if is_owner {
        caps.push("manage_owners");
    }
    caps
}

fn role_contract(
    role: &'static str,
    label: &'static str,
    description: &'static str,
) -> serde_json::Value {
    json!({
        "id": role,
        "label": label,
        "description": description,
        "capabilities": capabilities_for_role(role, role == ROLE_OWNER),
        "invitable": true,
        "credential_access": if role == ROLE_APPROVER { "assigned" } else { "all" },
    })
}

fn login_env_configured(var: &str) -> bool {
    std::env::var(var).map(|v| !v.is_empty()).unwrap_or(false)
}

pub fn dashboard_contract_json() -> serde_json::Value {
    json!({
        "version": 1,
        // Which social sign-in buttons the SPA should render. Visibility only —
        // the /auth/{provider}/start endpoints independently 503 when unset.
        "auth_providers": {
            "google": login_env_configured("GOOGLE_OAUTH_CLIENT_ID")
                && login_env_configured("GOOGLE_OAUTH_CLIENT_SECRET"),
            "github": login_env_configured("GITHUB_LOGIN_CLIENT_ID")
                && login_env_configured("GITHUB_LOGIN_CLIENT_SECRET"),
        },
        "capabilities": ALL_CAPABILITIES,
        "roles": [
            role_contract(ROLE_OWNER, "Owner", "Full workspace access, including owner management."),
            role_contract(ROLE_ADMIN, "Admin", "Can manage workspace credentials, agents, policies, billing, and members."),
            role_contract(ROLE_APPROVER, "Approver", "Can view assigned credential metadata, create API keys for assigned credentials, and approve matching requests."),
        ],
        "invite": {
            "default_role": DEFAULT_INVITE_ROLE,
            "owner_role": ROLE_OWNER,
            "owner_invite_requires_capability": "manage_owners",
        },
        "credential_access": {
            "assigned_role": ROLE_APPROVER,
        },
        "nav": [
            { "id": "overview", "label": "Overview", "capabilities_any": ["manage_credentials"] },
            { "id": "recipes", "label": "Recipes", "capabilities_any": ["manage_credentials"] },
            { "id": "credentials", "label": "Credentials", "capabilities_any": ["manage_credentials", "view_assigned_credentials"] },
            { "id": "api-keys", "label": "API Keys", "capabilities_any": ["manage_agents", "manage_own_agents"] },
            { "id": "roles", "label": "Roles", "capabilities_any": ["manage_roles"] },
            { "id": "policies", "label": "Policies", "capabilities_any": ["manage_policies"] },
            { "id": "end-users", "label": "End Users", "capabilities_any": ["manage_credentials"] },
            { "id": "approvals", "label": "Approvals", "capabilities_any": ["approve_requests"] },
            { "id": "team", "label": "Team", "capabilities_any": ["view_team"] },
            { "id": "profile", "label": "Profile", "capabilities_any": [] },
            { "id": "security", "label": "Security", "capabilities_any": [] },
            { "id": "apps", "label": "Apps", "capabilities_any": ["manage_agents"] },
        ],
    })
}

/// GET /dashboard/config — frontend contract for roles, capabilities, and nav.
pub async fn handle_dashboard_config() -> Response {
    Json(dashboard_contract_json()).into_response()
}

// Err is an axum Response (intentionally — these helpers short-circuit handlers
// with a ready response); the size is fine for a non-hot auth path.
#[allow(clippy::result_large_err)]
pub(crate) fn require_workspace_manager(user: &AuthUser, action: &str) -> Result<(), Response> {
    if user_can_manage_workspace(user) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": format!("Only owners and admins can {action}")})),
        )
            .into_response())
    }
}

fn user_can_manage_own_agents(user: &AuthUser) -> bool {
    user.member_role == ROLE_APPROVER
}

fn user_can_access_agent(user: &AuthUser, agent: &AgentRow) -> bool {
    user_can_manage_workspace(user) || agent.owner_user_id.as_deref() == Some(user.id.as_str())
}

#[allow(clippy::result_large_err)]
fn require_agent_access(user: &AuthUser, agent: &AgentRow, action: &str) -> Result<(), Response> {
    if user_can_access_agent(user, agent) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": format!("You can only {action} API keys you created")})),
        )
            .into_response())
    }
}

#[allow(clippy::result_large_err)]
fn require_agent_manager(user: &AuthUser, action: &str) -> Result<(), Response> {
    if user_can_manage_workspace(user) || user_can_manage_own_agents(user) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": format!("You do not have permission to {action}")})),
        )
            .into_response())
    }
}

#[allow(clippy::result_large_err)]
async fn validate_approver_agent_scope(
    store: &ConfigStore,
    admin: &AuthUser,
    credentials: Option<&Vec<String>>,
    roles: Option<&Vec<String>>,
) -> Result<(), Response> {
    if roles.is_some_and(|values| !values.is_empty()) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Approvers can assign only direct credentials, not roles"})),
        )
            .into_response());
    }

    let Some(credentials) = credentials else {
        return Ok(());
    };
    if credentials.is_empty() {
        return Ok(());
    }

    let assigned = match store
        .list_approver_credentials(&admin.team_id, &admin.id)
        .await
    {
        Ok(values) => values.into_iter().collect::<std::collections::HashSet<_>>(),
        Err(e) => {
            warn!("Failed to list approver credential assignments: {e}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to validate credential assignments"})),
            )
                .into_response());
        }
    };

    if let Some(name) = credentials.iter().find(|name| !assigned.contains(*name)) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": format!("Credential '{name}' is not assigned to you")})),
        )
            .into_response());
    }

    Ok(())
}

/// Extract the raw bearer session token from the Authorization header.
fn extract_session_token(
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing Authorization: Bearer <token> header"})),
            )
        })
}

/// Extract and validate a user session from the Authorization header. Returns
/// the user resolved in their session's active team (a `Member`).
pub async fn authenticate_user(
    headers: &HeaderMap,
    db_state: &DbState,
) -> Result<AuthUser, (StatusCode, Json<serde_json::Value>)> {
    let token = extract_session_token(headers)?;

    let token_hash = hash_session_token(&token);
    let member = db_state
        .store()
        .validate_session(&token_hash)
        .await
        .map_err(|e| {
            warn!("Session validation error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Session validation failed"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired session"})),
            )
        })?;

    if !member.email_verified {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Email not verified"})),
        ));
    }

    Ok(member)
}

// ---------------------------------------------------------------------------
// Request/response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignupRequest {
    /// The team to create and own. Optional: when omitted (or blank) the signup
    /// is "join-only" — the account is created with no team of its own and is
    /// enrolled into whatever team(s) it was invited to. Join-only requires at
    /// least one pending invite for the email.
    #[serde(default)]
    pub team_name: Option<String>,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    pub email: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateCheckoutRequest {
    pub tier: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

use crate::proxy::AppState;

/// POST /signup — create an account, optionally with a team of its own.
///
/// Two modes, distinguished by whether `team_name` is provided:
///  - **create-team** (project name given): the account creates and owns that
///    team, and *also* auto-joins any team it was invited to.
///  - **join-only** (no project name): the account is created with no team of
///    its own and joins whatever it was invited to. Requires ≥1 pending invite.
///
/// Either way, pending invites for the email are consumed here so an invited
/// person is never stranded outside the inviting team — the bug this fixes was
/// signup silently ignoring invites and dropping the user into a lone new team.
pub async fn handle_signup(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Response {
    let store = state.db_state.store();

    // Validate email (basic check)
    let email = req.email.trim().to_lowercase();
    if !email.contains('@') || !email.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid email format"})),
        )
            .into_response();
    }

    // Validate password
    if req.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password must be at least 8 characters"})),
        )
            .into_response();
    }

    // Normalize the optional project name. Blank ⇒ join-only mode.
    let team_name = req
        .team_name
        .as_deref()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());

    if let Some(name) = &team_name {
        if name.len() < 3 || name.len() > 64 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Project name must be 3-64 characters"})),
            )
                .into_response();
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Project name must be lowercase alphanumeric with hyphens"})),
            )
                .into_response();
        }
    }

    // Check if email already exists (globally — email is unique per person)
    if let Ok(Some(existing)) = store.get_user_by_email(&email).await {
        if !existing.email_verified {
            // Account exists but unverified — let the user resend verification
            return (StatusCode::CONFLICT, Json(json!({
                "error": "Account already exists but is unverified. Use 'Resend Code' to get a new verification code.",
                "email": email,
                "unverified": true,
            }))).into_response();
        }
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Email already registered"})),
        )
            .into_response();
    }

    // Pending invites for this email drive both join-only mode and the auto-join
    // below. Join-only signup needs at least one team to land in.
    let has_pending_invite = !store
        .list_invites_by_email(&email)
        .await
        .unwrap_or_default()
        .is_empty();
    if team_name.is_none() && !has_pending_invite {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Enter a project name to create your own team."})),
        )
            .into_response();
    }

    // Whitelist (managed hosting MVP) gates *creating a new team* only. Joining
    // a team you were invited to is always allowed — the inviting team already
    // passed the gate, and the emailed invite-link flow has never been gated.
    let signup_tier = if team_name.is_some() {
        match store.get_whitelist_entry(&email).await.unwrap_or(None) {
            Some((_, tier)) => tier,
            None => {
                if std::env::var("TAP_REQUIRE_WHITELIST").unwrap_or_default() == "true" {
                    return (StatusCode::FORBIDDEN, Json(json!({"error": "Managed hosting is in early access. Request access at tap.human.tech"}))).into_response();
                }
                "free".to_string()
            }
        }
    } else {
        "free".to_string()
    };

    // Check project name uniqueness (create-team mode only)
    if let Some(name) = &team_name {
        if let Ok(Some(_)) = store.get_team_by_name(name).await {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "Project name already taken"})),
            )
                .into_response();
        }
    }

    // Hash password
    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            warn!("Password hash error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal error"})),
            )
                .into_response();
        }
    };

    // Create the account — with its own team in create-team mode, identity-only
    // in join-only mode (the invite consumption below adds its memberships).
    let (admin_id, own_team) = if let Some(name) = &team_name {
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
        let new_user_id = uuid::Uuid::new_v4().to_string();
        let id = match store
            .create_user_with_membership(&new_user_id, &team_id, &email, &password_hash, ROLE_OWNER)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                warn!("User creation error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to create account"})),
                )
                    .into_response();
            }
        };
        (id, Some((team_id, name.clone())))
    } else {
        let new_user_id = uuid::Uuid::new_v4().to_string();
        let id = match store
            .create_user(&new_user_id, &email, &password_hash)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                warn!("User creation error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to create account"})),
                )
                    .into_response();
            }
        };
        (id, None)
    };

    // Auto-join (and consume) any teams this email was invited to.
    let joined = consume_pending_invites(store, &admin_id, &email).await;

    // Join-only signup must end up in at least one team. If the invite expired
    // in the narrow window since the check above, the account is left teamless
    // and unverified (harmless, same as an abandoned signup) — surface a clear
    // error so the user re-requests an invite.
    if own_team.is_none() && joined.is_empty() {
        return (
            StatusCode::GONE,
            Json(json!({"error": "Your invitation expired. Ask the team owner to invite you again."})),
        )
            .into_response();
    }

    // The team to surface in the response and verification email: the user's own
    // team if they created one, else the first team they joined via invite.
    let (resp_team_id, resp_team_name) = match &own_team {
        Some((id, name)) => (Some(id.clone()), name.clone()),
        None => match joined.first() {
            Some((id, name, _)) => (Some(id.clone()), name.clone()),
            None => (None, String::new()),
        },
    };

    // Generate and send verification code (always — even whitelisted users must verify email ownership)
    let code = generate_verification_code();
    let code_hash = hash_verification_code(&code);
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();

    if let Err(e) = store
        .create_email_verification(&code_hash, &admin_id, &expires_at)
        .await
    {
        warn!("Verification creation error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create verification"})),
        )
            .into_response();
    }

    // Send verification email via Resend
    let email_team_label = if resp_team_name.is_empty() {
        "your team".to_string()
    } else {
        resp_team_name.clone()
    };
    let email_error =
        match crate::email::send_verification_email(&email, &code, &email_team_label).await {
            Ok(()) => None,
            Err(e) => {
                warn!("Email send error: {e}");
                Some(format!("{e}"))
            }
        };

    let message = if email_error.is_some() {
        format!("Verification code could not be delivered to {email}. Please contact support.")
    } else {
        format!("Verification code sent to {email}. Check your inbox.")
    };

    let joined_json: Vec<serde_json::Value> = joined
        .iter()
        .map(|(_, name, role)| json!({"team_name": name, "role": role}))
        .collect();

    let mut resp = json!({
        "team_id": resp_team_id,
        "team_name": resp_team_name,
        "admin_id": admin_id,
        "email": email,
        "tier": signup_tier,
        "email_verified": false,
        "joined_teams": joined_json,
        "message": message,
    });
    if let Some(err) = email_error {
        resp["email_error"] = serde_json::Value::String(err);
    }

    (StatusCode::CREATED, Json(resp)).into_response()
}

/// POST /verify-email — verify email with 6-digit code.
/// Returns a passkey_setup_token for mandatory passkey registration.
pub async fn handle_verify_email(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
) -> Response {
    let code_hash = hash_verification_code(&req.code);

    match state
        .db_state
        .store()
        .validate_email_verification(&code_hash)
        .await
    {
        Ok(Some(admin_id)) => {
            // Generate a passkey_setup_token (10 min TTL) for mandatory passkey registration
            let setup_token = generate_session_token();
            let setup_token_hash = hash_session_token(&setup_token);
            let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

            // The setup token is a short-lived session and must carry an active
            // team so validate_session can resolve it. Use the user's first team.
            let active_team_id = match resolve_active_team(state.db_state.store(), &admin_id).await
            {
                Ok(Some((tid, _, _, _))) => tid,
                Ok(None) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Account has no team membership"})),
                    )
                        .into_response();
                }
                Err(e) => {
                    warn!("Verify-email team resolution error: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Verification failed"})),
                    )
                        .into_response();
                }
            };

            // Store as a short-lived session (same table, short TTL)
            if let Err(e) = state
                .db_state
                .store()
                .create_session(&setup_token_hash, &admin_id, &active_team_id, &expires_at)
                .await
            {
                warn!("Setup token creation error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to create setup token"})),
                )
                    .into_response();
            }

            Json(json!({
                "verified": true,
                "passkey_setup_token": setup_token,
                "admin_id": admin_id,
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid or expired code"})),
        )
            .into_response(),
        Err(e) => {
            warn!("Verification error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Verification failed"})),
            )
                .into_response()
        }
    }
}

/// POST /resend-verification — resend a verification code to an unverified email.
pub async fn handle_resend_verification(
    State(state): State<AppState>,
    Json(req): Json<ResendVerificationRequest>,
) -> Response {
    let email = req.email.trim().to_lowercase();
    let store = state.db_state.store();

    let admin = match store.get_user_by_email(&email).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "No account found with that email"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Resend lookup error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Lookup failed"})),
            )
                .into_response();
        }
    };

    if admin.email_verified {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Email already verified. You can log in."})),
        )
            .into_response();
    }

    let code = generate_verification_code();
    let code_hash = hash_verification_code(&code);
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();

    if let Err(e) = store
        .create_email_verification(&code_hash, &admin.id, &expires_at)
        .await
    {
        warn!("Verification creation error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create verification"})),
        )
            .into_response();
    }

    // Get team name for the email (use the user's first/oldest team).
    let team_name = store
        .list_user_teams(&admin.id)
        .await
        .ok()
        .and_then(|teams| teams.into_iter().next())
        .map(|(_, name, _)| name)
        .unwrap_or_else(|| "your team".to_string());

    match crate::email::send_verification_email(&email, &code, &team_name).await {
        Ok(()) => Json(json!({
            "message": format!("Verification code sent to {email}."),
            "email": email,
        }))
        .into_response(),
        Err(e) => {
            warn!("Email resend error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Failed to send email: {e}"),
                })),
            )
                .into_response()
        }
    }
}

/// Minimum time between reset emails for the same account. Requests inside
/// the window return the same 200 without creating a token or sending mail,
/// so a caller who knows a registered email can't spam its inbox (#19).
const RESET_REQUEST_COOLDOWN_MINUTES: i64 = 5;

/// POST /forgot-password — send a password reset link to the given email.
/// Always returns 200 regardless of whether the email exists (no oracle).
pub async fn handle_forgot_password(
    State(state): State<AppState>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Response {
    let email = req.email.trim().to_lowercase();
    let store = state.db_state.store();

    // Look up user silently — do not reveal existence to the caller.
    if let Ok(Some(admin)) = store.get_user_by_email(&email).await {
        let token = generate_session_token();
        let token_hash = hash_session_token(&token);
        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

        match store
            .create_password_reset(
                &token_hash,
                &admin.id,
                &expires_at,
                RESET_REQUEST_COOLDOWN_MINUTES,
            )
            .await
        {
            Err(e) => warn!("Password reset creation error: {e}"),
            Ok(false) => {
                // Cooldown: a reset email went out recently — the earlier
                // token stays valid and no new email is sent.
                info!("Password reset throttled (cooldown) for {email}");
            }
            Ok(true) => {
                let base_url = std::env::var("TAP_BASE_URL")
                    .unwrap_or_else(|_| "https://app.tap.human.tech".to_string());
                let reset_url = format!("{base_url}/dashboard?reset_token={token}");
                if let Err(e) = crate::email::send_password_reset_email(&email, &reset_url).await {
                    warn!("Password reset email error: {e}");
                }
            }
        }
    }

    // Always return the same response to avoid leaking whether the email exists.
    Json(json!({
        "message": "If an account with that email exists, a reset link has been sent. Check your inbox."
    }))
    .into_response()
}

/// POST /reset-password — set a new password using a reset token from the email link.
pub async fn handle_reset_password(
    State(state): State<AppState>,
    Json(req): Json<ResetPasswordRequest>,
) -> Response {
    if req.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password must be at least 8 characters"})),
        )
            .into_response();
    }

    let token_hash = hash_session_token(&req.token);
    let store = state.db_state.store();

    let admin_id = match store.validate_and_consume_password_reset(&token_hash).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid or expired reset link"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Password reset validation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Reset failed"})),
            )
                .into_response();
        }
    };

    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            warn!("Password hash error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Reset failed"})),
            )
                .into_response();
        }
    };

    if let Err(e) = store.update_user_password(&admin_id, &password_hash).await {
        warn!("Password update error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Reset failed"})),
        )
            .into_response();
    }

    info!(admin_id, "Password reset successfully");
    Json(json!({"message": "Password reset successfully. You can now log in."})).into_response()
}

/// Enroll a user into every team they currently hold an unexpired invite for,
/// then consume those invites. Idempotent and best-effort: a failure on one
/// invite is logged and skipped rather than failing the whole auth flow. This
/// is what guarantees an invited person lands in the inviting team no matter
/// which door they came through — the emailed invite link, self-serve signup,
/// or simply logging into an account they already had.
///
/// Trust: the invite was addressed to this email, and the caller has already
/// proven control of the account (password + verified email on login, or the
/// email-verification step that gates signup). This is the same email-ownership
/// anchor the invite-link flow relies on.
///
/// Returns the teams that were joined as `(team_id, team_name, role)`.
pub(crate) async fn consume_pending_invites(
    store: &tap_core::store::ConfigStore,
    user_id: &str,
    email: &str,
) -> Vec<(String, String, String)> {
    let invites = match store.list_invites_by_email(email).await {
        Ok(v) => v,
        Err(e) => {
            warn!("consume_pending_invites: list failed for {email}: {e}");
            return Vec::new();
        }
    };
    let mut joined = Vec::new();
    for inv in invites {
        if let Err(e) = store.add_membership(user_id, &inv.team_id, &inv.role).await {
            warn!("consume_pending_invites: add_membership failed: {e}");
            continue;
        }
        let team_name = store
            .get_team(&inv.team_id)
            .await
            .ok()
            .flatten()
            .map(|t| t.name)
            .unwrap_or_default();
        let _ = store.delete_invite(&inv.id).await;
        info!(email = %email, team_id = %inv.team_id, role = %inv.role, "auto-joined invited team");
        joined.push((inv.team_id, team_name, inv.role));
    }
    joined
}

/// Resolve a user's active team and the full teams list for login/switch
/// responses. The active team defaults to the oldest membership. Returns
/// `Ok(None)` when the user belongs to no teams.
///
/// Yields `(active_team_id, active_team_name, active_role, teams_json)` where `teams_json`
/// is an array of `{team_id, team_name, role}`.
async fn resolve_active_team(
    store: &tap_core::store::ConfigStore,
    user_id: &str,
) -> Result<Option<(String, String, String, serde_json::Value)>, AgentSecError> {
    let teams = store.list_user_teams(user_id).await?;
    let Some((active_id, active_name, active_role)) = teams.first().cloned() else {
        return Ok(None);
    };
    let teams_json = serde_json::Value::Array(
        teams
            .iter()
            .map(|(tid, tname, role)| json!({"team_id": tid, "team_name": tname, "role": role}))
            .collect(),
    );
    Ok(Some((active_id, active_name, active_role, teams_json)))
}

/// POST /login — authenticate with email + password.
/// Always returns a WebAuthn challenge (passkey is mandatory 2FA).
/// Frontend must complete the challenge via POST /login/passkey.
pub async fn handle_login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Response {
    let email = req.email.trim().to_lowercase();
    let store = state.db_state.store();

    // Find user by email (globally unique)
    let admin = match store.get_user_by_email(&email).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid credentials"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Login lookup error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Login failed"})),
            )
                .into_response();
        }
    };

    // Verify password
    if !verify_password(&req.password, &admin.password_hash) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentials"})),
        )
            .into_response();
    }

    // Check email verified
    if !admin.email_verified {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Email not verified. Check your inbox.",
                "unverified": true,
                "email": email,
            })),
        )
            .into_response();
    }

    finish_first_factor_login(&state, admin).await
}

/// Shared tail of every first-factor login (password or social login): consume
/// pending invites, resolve the active team, then branch on passkey state —
/// full session (WebAuthn unconfigured), passkey setup, or passkey challenge.
/// The caller has already verified the first factor AND `email_verified`.
pub(crate) async fn finish_first_factor_login(
    state: &AppState,
    admin: tap_core::store::User,
) -> Response {
    let store = state.db_state.store();

    // Auto-join any teams this email was invited to since the account was
    // created. This is what lets a person who already had an account simply log
    // in to pick up a new invite — no second account, no orphaned invite. It
    // runs at the first-factor step (which precedes the passkey challenge), so
    // by the time /login/passkey resolves teams the new memberships are present.
    let joined_teams = consume_pending_invites(store, &admin.id, &admin.email).await;

    // Pick the active team. Default to the oldest membership, but when this
    // login just accepted an invite, land the user in the invited workspace so
    // the "Log In to Accept" path does not look like it failed.
    let (mut active_team_id, mut active_team_name, mut active_team_role, teams_json) =
        match resolve_active_team(store, &admin.id).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "Your account is not a member of any team"})),
                )
                    .into_response();
            }
            Err(e) => {
                warn!("Login team resolution error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Login failed"})),
                )
                    .into_response();
            }
        };
    if let Some((team_id, team_name, role)) = joined_teams.first() {
        active_team_id = team_id.clone();
        active_team_name = team_name.clone();
        active_team_role = role.clone();
    }
    let joined_teams_json: Vec<serde_json::Value> = joined_teams
        .iter()
        .map(|(_, name, role)| json!({"team_name": name, "role": role}))
        .collect();

    // Check if admin has passkeys — if not, they need to set up first
    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            // WebAuthn not configured — fall back to password-only (legacy/self-hosted).
            // This IS a full login on such deployments, so staged social-identity
            // links become permanent here (see persist_pending_identity_links).
            persist_pending_identity_links(store, &admin.id).await;
            let token = generate_session_token();
            let token_hash = hash_session_token(&token);
            let expires_at = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
            if let Err(e) = store
                .create_session(&token_hash, &admin.id, &active_team_id, &expires_at)
                .await
            {
                warn!("Session creation error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to create session"})),
                )
                    .into_response();
            }
            return Json(json!({
                "session_token": token,
                "admin_id": admin.id,
                "email": admin.email,
                "team_id": active_team_id,
                "team_name": active_team_name,
                "member_role": active_team_role.clone(),
                "capabilities": capabilities_for_role(&active_team_role, active_team_role == ROLE_OWNER),
                "teams": teams_json,
                "joined_teams": joined_teams_json,
                "expires_at": expires_at,
            }))
            .into_response();
        }
    };

    if !wa.user_has_passkeys(&admin.id).await {
        // Admin has no passkeys — they need to set up. Issue a setup token.
        let setup_token = generate_session_token();
        let setup_token_hash = hash_session_token(&setup_token);
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        if let Err(e) = store
            .create_session(&setup_token_hash, &admin.id, &active_team_id, &expires_at)
            .await
        {
            warn!("Setup token creation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal error"})),
            )
                .into_response();
        }
        return Json(json!({
            "needs_passkey_setup": true,
            "passkey_setup_token": setup_token,
            "admin_id": admin.id,
            "email": admin.email,
            "team_id": active_team_id,
            "team_name": active_team_name,
            "member_role": active_team_role,
            "joined_teams": joined_teams_json,
        }))
        .into_response();
    }

    // Generate WebAuthn challenge
    match wa.begin_user_login(&admin.id).await {
        Ok((challenge, passkey_token)) => Json(json!({
            "requires_passkey": true,
            "challenge": challenge,
            "passkey_token": passkey_token,
            "admin_id": admin.id,
            "email": admin.email,
            "team_id": active_team_id,
            "team_name": active_team_name,
            "member_role": active_team_role,
            "joined_teams": joined_teams_json,
        }))
        .into_response(),
        Err(e) => {
            warn!("WebAuthn challenge error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to generate security key challenge"})),
            )
                .into_response()
        }
    }
}

/// POST /logout — invalidate the current session.
pub async fn handle_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing token"})),
            )
                .into_response();
        }
    };

    let token_hash = hash_session_token(&token);
    let _ = state.db_state.store().delete_session(&token_hash).await;

    Json(json!({"logged_out": true})).into_response()
}

// ---------------------------------------------------------------------------
// Admin CRUD helpers
// ---------------------------------------------------------------------------

/// Macro-like helper to authenticate admin and extract team_id, or return error response.
macro_rules! require_admin {
    ($state:expr, $headers:expr) => {
        match authenticate_user(&$headers, &$state.db_state).await {
            Ok(admin) => admin,
            Err(resp) => return resp.into_response(),
        }
    };
}

// ---------------------------------------------------------------------------
// Credential management
// ---------------------------------------------------------------------------

/// GET /admin/credentials — list team's credentials (never returns values).
/// GET /admin/end-users — read-only list of the team's managed end-users (TAP
/// for Platforms) with last-seen and 30-day request counts, for the dashboard
/// "End Users" tab. Workspace-manager only.
pub async fn handle_list_end_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "view end users") {
        return resp;
    }
    let store = state.db_state.store();
    let users = match store.list_end_users(&admin.team_id).await {
        Ok(u) => u,
        Err(e) => return crate::proxy::error_response(e),
    };
    let from = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
    let to = chrono::Utc::now().to_rfc3339();
    let counts: std::collections::HashMap<String, i64> = store
        .end_user_usage(&admin.team_id, &from, &to)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    let list: Vec<_> = users
        .iter()
        .map(|u| {
            json!({
                "ext_id": u.ext_id,
                "display_name": u.display_name,
                "status": u.status,
                "last_seen_at": u.last_seen_at,
                "created_at": u.created_at,
                "requests_30d": counts.get(&u.ext_id).copied().unwrap_or(0),
            })
        })
        .collect();
    Json(json!({ "end_users": list })).into_response()
}

/// GET /admin/end-users/{ext_id}/credentials — the credentials/keys owned by one
/// managed end-user (addresses only for signing keys; never secret values).
pub async fn handle_list_end_user_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(ext_id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "view end users") {
        return resp;
    }
    let store = state.db_state.store();
    let creds = match store
        .list_end_user_credentials(&admin.team_id, &ext_id)
        .await
    {
        Ok(c) => c,
        Err(e) => return crate::proxy::error_response(e),
    };
    let prefix = format!("eu:{ext_id}/");
    let mut out = Vec::new();
    for c in creds {
        let logical = c.name.strip_prefix(&prefix).unwrap_or(&c.name).to_string();
        let is_signing = c.api_base.as_deref() == Some("tap:sign");
        let mut entry = json!({
            "name": logical,
            "description": c.description,
            "type": if is_signing { "signing_key" } else { "credential" },
            "created_at": c.created_at,
        });
        if is_signing {
            if let Ok(Some(val)) = state.get_credential_value(&admin.team_id, &c.name).await {
                if let Some(sig) = crate::signing::parse_signing_credential(&val) {
                    if let Ok(pub_id) = crate::signing::public_identity(&sig) {
                        if let (serde_json::Value::Object(m), serde_json::Value::Object(p)) =
                            (&mut entry, pub_id)
                        {
                            m.extend(p);
                        }
                    }
                }
            }
        }
        out.push(entry);
    }
    Json(json!({ "ext_id": ext_id, "credentials": out })).into_response()
}

pub async fn handle_list_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    let mut creds = match store.list_credentials(&admin.team_id).await {
        Ok(c) => c,
        Err(e) => {
            warn!("List credentials error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list credentials"})),
            )
                .into_response();
        }
    };
    // Approvers only see credentials explicitly assigned to them.
    if admin.member_role == ROLE_APPROVER {
        let allowed = store
            .list_approver_credentials(&admin.team_id, &admin.id)
            .await
            .unwrap_or_default();
        let allowed_set: std::collections::HashSet<&str> =
            allowed.iter().map(|s| s.as_str()).collect();
        creds.retain(|c| allowed_set.contains(c.name.as_str()));
    }
    let hints = store
        .list_credential_value_hints(&admin.team_id)
        .await
        .unwrap_or_default();
    let list: Vec<serde_json::Value> = creds
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "description": c.description,
                "connector": c.connector,
                "api_base": c.api_base,
                "relative_target": c.relative_target,
                "auth_header_format": c.auth_header_format,
                "auth_bindings": c.auth_bindings_json.as_deref().and_then(|raw| serde_json::from_str::<Vec<AuthBinding>>(raw).ok()).unwrap_or_default(),
                "allowed_hosts": c.allowed_hosts_json.as_deref().and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok()).unwrap_or_default(),
                "value_hint": hints.get(&c.name),
            })
        })
        .collect();
    Json(json!({"credentials": list})).into_response()
}

/// Canonical credential-name constraint: 1-64 chars, lowercase ASCII
/// alphanumeric plus hyphens. Enforced on every path that can create/name a
/// credential — the dashboard's own create-form input carries the matching
/// HTML5 `pattern="[a-z0-9-]+"`, so a name that fails this can never be
/// submitted there; without server-side enforcement here and in
/// `handle_agent_credential_link`, an agent-generated prefill link could
/// (and did) hand a human a form pre-filled with a name their own browser
/// would then refuse to submit. Critically, this is also the sole gate
/// rejecting `:` and `/`, so it prevents a caller from smuggling an
/// `eu:{ext}/{logical}` name past a create path and colliding with /
/// masquerading as an end-user credential (`end_user_id = NULL`), breaking
/// the `eu:` isolation invariant. Also protects `<CREDENTIAL:name.field>`
/// placeholder parsing, which splits on `:` and `.` and would misparse a
/// name containing either.
pub fn validate_credential_name(name: &str) -> Result<String, &'static str> {
    let name = name.trim().to_lowercase();
    if name.is_empty() || name.len() > 64 {
        return Err("Credential name must be 1-64 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("Credential name must be lowercase alphanumeric with hyphens");
    }
    Ok(name)
}

#[derive(Deserialize)]
pub struct CreateCredentialRequest {
    pub name: String,
    pub description: String,
    pub connector: Option<String>,
    pub api_base: Option<String>,
    pub relative_target: Option<bool>,
    pub auth_header_format: Option<String>,
    pub auth_bindings: Option<Vec<AuthBinding>>,
    /// Destination host allowlist. When set and non-empty, `/forward` only
    /// sends this credential to a listed host (exact `api.stripe.com` or
    /// `*.googleapis.com` wildcard). Empty/absent = unrestricted (the agent may
    /// target any host — a credential-exfiltration risk the dashboard warns
    /// about). See `routing::host_is_allowed`.
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Credential value. Two shapes accepted:
    /// - A plain JSON string for single-secret credentials (e.g. `"xoxb-abc123"`).
    /// - A JSON object for multi-secret credentials (e.g. Datadog, AWS):
    ///   `{"api_key":"...","app_key":"..."}`. The auth_bindings format strings
    ///   then reference each field via `{value.api_key}` / `{value.app_key}`.
    pub value: Option<serde_json::Value>,
    /// Generate a signing keypair in-proxy instead of importing a value. When
    /// set, the proxy creates the private key (never exposed) and returns the
    /// public key/address. Mutually exclusive with a meaningful `value`.
    #[serde(default)]
    pub generate: Option<GenerateSpec>,
}

fn normalize_credential_value(
    value: &serde_json::Value,
    connector: &str,
) -> Result<String, Box<Response>> {
    let normalized = match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(_) => value.to_string(),
        _ => {
            return Err(Box::new((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid credential value",
                    "detail": "value must be a string (single-secret) or a JSON object (multi-secret like Datadog/AWS). Numbers, arrays, and booleans are not allowed.",
                })),
            )
                .into_response()));
        }
    };

    // For Google OAuth credentials the client sends only the refresh token.
    // Bundle the platform's OAuth client_id/secret server-side so they never
    // appear in client code or transit.
    if connector == "sidecar" {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&normalized) {
            if parsed.get("refresh_token").is_some() && parsed.get("client_id").is_none() {
                let cid = std::env::var("GOOGLE_OAUTH_CLIENT_ID").unwrap_or_default();
                let csec = std::env::var("GOOGLE_OAUTH_CLIENT_SECRET").unwrap_or_default();
                if !cid.is_empty() && !csec.is_empty() {
                    return Ok(serde_json::json!({
                        "client_id": cid,
                        "client_secret": csec,
                        "refresh_token": parsed["refresh_token"],
                    })
                    .to_string());
                }
            }
        }
    }

    Ok(normalized)
}

fn validate_signing_value(plaintext: &str) -> Result<(), Box<Response>> {
    if let Some(sig_cred) = crate::signing::parse_signing_credential(plaintext) {
        if let Err(e) = crate::signing::validate_import(&sig_cred) {
            return Err(Box::new(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Invalid signing key: {e}")})),
                )
                    .into_response(),
            ));
        }
    }
    Ok(())
}

/// Request to generate a signing keypair server-side.
#[derive(Deserialize)]
pub struct GenerateSpec {
    /// "secp256k1", "ed25519", or "p256".
    pub algorithm: String,
}

/// POST /admin/credentials — create a credential (optionally with value).
pub async fn handle_create_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCredentialRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "create credentials") {
        return resp;
    }
    // Same charset gate as the CLI setup path — rejects `:`/`/` names that would
    // collide with the `eu:{ext}/{logical}` end-user namespace (#126 invariant).
    let name = match validate_credential_name(&req.name) {
        Ok(n) => n,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response(),
    };
    let store = state.db_state.store();

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

    // Signing-key generation: create the keypair server-side so the private key
    // never reaches the browser/agent. Returns the public identity to surface.
    let mut connector = req.connector.as_deref().unwrap_or("direct").to_string();
    let mut api_base = req.api_base.clone();
    let mut generated_value: Option<String> = None;
    let mut generated_public: Option<serde_json::Value> = None;
    if let Some(ref spec) = req.generate {
        let algorithm = match spec.algorithm.as_str() {
            "secp256k1" => crate::signing::Algorithm::Secp256k1,
            "ed25519" => crate::signing::Algorithm::Ed25519,
            "p256" => crate::signing::Algorithm::P256,
            other => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Unsupported signing algorithm '{other}' (use secp256k1, ed25519, or p256)")})),
                )
                    .into_response();
            }
        };
        match crate::signing::generate(algorithm) {
            Ok(gen) => {
                generated_value = Some(gen.bundle.clone());
                generated_public = Some(json!({
                    "algorithm": gen.algorithm.as_str(),
                    "public_key": gen.public_key,
                    "public_key_uncompressed": gen.public_key_uncompressed,
                    "address": gen.address,
                }));
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Key generation failed: {e}")})),
                )
                    .into_response();
            }
        }
        // Signing keys have no HTTP upstream; mark sidecar so /forward rejects
        // them (the routing guard redirects to POST /sign), and use a non-HTTP
        // sentinel api_base.
        connector = "sidecar".to_string();
        api_base = Some("tap:sign".to_string());
    }
    let connector = connector.as_str();

    // Enforced host binding (Decision #17). A credential whose secret is
    // injected and forwarded to an agent-controlled `X-TAP-Target` MUST declare
    // `allowed_hosts`, so a compromised/prompt-injected agent can't point the
    // target at an attacker host and exfiltrate the secret. Required for every
    // new credential EXCEPT the two shapes that have no agent-controlled
    // destination host: `relative_target` sidecars (pinned to the operator's
    // `api_base`) and signing keys (`api_base = "tap:sign"`, no HTTP forward).
    // Existing credentials are grandfathered — this gate is create-time only.
    let is_relative_target = req.relative_target.unwrap_or(false);
    let is_signing = api_base.as_deref() == Some("tap:sign");
    if !is_relative_target && !is_signing {
        let has_hosts = req
            .allowed_hosts
            .as_ref()
            .is_some_and(|h| h.iter().any(|s| !s.trim().is_empty()));
        if !has_hosts {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "allowed_hosts is required: list the upstream host(s) this credential may be sent to (e.g. [\"api.stripe.com\"] or [\"*.googleapis.com\"]). This binds the injected secret to those hosts so a compromised agent can't exfiltrate it elsewhere."})),
            )
                .into_response();
        }
    }

    let auth_bindings_json = req
        .auth_bindings
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Invalid auth_bindings: {e}")})),
            )
                .into_response()
        });
    let auth_bindings_json = match auth_bindings_json {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Validate and prepare the credential value before writing anything to the
    // DB. This way the INSERT is atomic — either both the row and value land,
    // or nothing does. No orphaned rows with a missing value.
    let plaintext_value: Option<String> = if let Some(gen_bundle) = generated_value.clone() {
        // Server-generated signing key: store the bundle as-is.
        Some(gen_bundle)
    } else if let Some(ref value) = req.value {
        match normalize_credential_value(value, connector) {
            Ok(v) => Some(v),
            Err(resp) => return *resp,
        }
    } else {
        None
    };

    // Validate an imported signing-key bundle (parses + key matches algorithm).
    if generated_value.is_none() {
        if let Some(pt) = plaintext_value.as_deref() {
            if let Err(resp) = validate_signing_value(pt) {
                return *resp;
            }
        }
    }

    if let Err(e) = store
        .create_credential(
            &admin.team_id,
            &name,
            &req.description,
            connector,
            api_base.as_deref(),
            req.relative_target.unwrap_or(false),
            req.auth_header_format.as_deref(),
            auth_bindings_json.as_deref(),
            plaintext_value.as_deref().map(|s| s.as_bytes()),
        )
        .await
    {
        let (status, msg) = match &e {
            AgentSecError::AlreadyExists(_) => (
                StatusCode::CONFLICT,
                format!("A credential named '{name}' already exists."),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create credential.".to_string(),
            ),
        };
        return (status, Json(json!({"error": msg}))).into_response();
    }

    // Apply the destination host allowlist as a focused follow-up write (keeps
    // the create_credential signature — and its many callers — untouched).
    if let Some(hosts) = req.allowed_hosts.as_deref() {
        let cleaned = match validate_allowed_hosts(hosts) {
            Ok(c) => c,
            Err(msg) => {
                // The credential row already exists; roll it back so a bad host
                // list doesn't leave a half-configured credential behind.
                let _ = store.delete_credential(&admin.team_id, &name).await;
                return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
            }
        };
        if !cleaned.is_empty() {
            if let Err(e) = store
                .set_credential_allowed_hosts(&admin.team_id, &name, &cleaned)
                .await
            {
                return crate::proxy::error_response(e);
            }
        }
    }

    analytics::capture(
        "tap.credential_created",
        &analytics::agent_distinct_id(&admin.team_id),
        json!({"service_name": name.clone(), "auth_type": req.connector.as_deref().unwrap_or("direct")}),
    );

    let mut resp_body = json!({"name": name, "created": true});
    if let Some(public) = generated_public {
        // Surface the public identity so the dashboard can show it. The private
        // key is stored encrypted and never returned.
        resp_body["generated"] = public;
    }
    (StatusCode::CREATED, Json(resp_body)).into_response()
}

/// Validate and normalize a destination host allowlist. Each entry must be a
/// bare host (optionally a `*.` wildcard) — not a URL, path, or port. Returns
/// the trimmed/lowercased list (empty entries dropped). Rejects anything that
/// looks like a URL so a mistake (`https://api.foo.com/x`) can't silently widen
/// the binding to never match (and thus block all traffic) or be misread.
pub fn validate_allowed_hosts(hosts: &[String]) -> Result<Vec<String>, String> {
    let mut cleaned = Vec::new();
    for raw in hosts {
        let h = raw.trim().to_ascii_lowercase();
        if h.is_empty() {
            continue;
        }
        if h.contains("://")
            || h.contains('/')
            || h.contains(':')
            || h.contains(char::is_whitespace)
        {
            return Err(format!(
                "allowed_hosts: '{raw}' must be a bare host like 'api.stripe.com' or '*.googleapis.com' — no scheme, path, port, or spaces."
            ));
        }
        // A wildcard is only valid as a leading '*.' label.
        if h.contains('*') && !h.starts_with("*.") {
            return Err(format!(
                "allowed_hosts: '{raw}' — wildcards are only allowed as a leading '*.' (e.g. '*.googleapis.com')."
            ));
        }
        cleaned.push(h);
    }
    Ok(cleaned)
}

#[derive(Deserialize)]
pub struct PatchCredentialRequest {
    pub description: Option<String>,
    pub connector: Option<String>,
    pub api_base: Option<serde_json::Value>,
    pub relative_target: Option<bool>,
    pub auth_header_format: Option<serde_json::Value>,
    /// Replace the field→header auth bindings. `Some([])` clears them (back to
    /// the default Bearer / unbound); `Some([..])` replaces them; `None` leaves
    /// them unchanged. This is the editable counterpart of the create-time
    /// `auth_bindings`, so a header-scheme credential (Anthropic `x-api-key`,
    /// Datadog) whose binding was imported wrong can be fixed in place.
    #[serde(default)]
    pub auth_bindings: Option<Vec<AuthBinding>>,
    /// Replace the destination host allowlist. `Some([])` clears it (back to
    /// unrestricted); `None` leaves it unchanged.
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct UpdateCredentialSecretRequest {
    /// Replace the stored secret value. The old value is never returned by any
    /// API; callers must provide the full replacement value.
    pub value: Option<serde_json::Value>,
    /// Merge fields into an existing JSON-object secret without returning the
    /// existing secret to the browser. Useful for adding one X bearer_token to
    /// an existing OAuth 1.0a bundle.
    #[serde(default)]
    pub value_patch: Option<serde_json::Map<String, serde_json::Value>>,
}

async fn build_credential_secret_update(
    store: &ConfigStore,
    team_id: &str,
    name: &str,
    connector: &str,
    req: &UpdateCredentialSecretRequest,
) -> Result<String, Box<Response>> {
    if req.value.is_some() && req.value_patch.is_some() {
        return Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Use either value or value_patch, not both"})),
            )
                .into_response(),
        ));
    }

    let plaintext = if let Some(ref value) = req.value {
        normalize_credential_value(value, connector)?
    } else if let Some(patch) = req.value_patch.as_ref() {
        if patch.is_empty() {
            return Err(Box::new(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "value_patch must contain at least one field"})),
                )
                    .into_response(),
            ));
        }
        let current =
            match store.get_credential_value(team_id, name).await {
                Ok(Some(bytes)) => match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => return Err(Box::new(
                        (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "Existing credential value is not valid UTF-8"})),
                        )
                            .into_response(),
                    )),
                },
                Ok(None) => "{}".to_string(),
                Err(e) => return Err(Box::new(crate::proxy::error_response(e))),
            };
        let mut merged = match serde_json::from_str::<serde_json::Value>(&current) {
            Ok(serde_json::Value::Object(obj)) => obj,
            _ => {
                return Err(Box::new((
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "value_patch requires the existing credential value to be a JSON object",
                        "detail": "Use value to replace single-secret credentials, or recreate the credential as a multi-field credential.",
                    })),
                )
                    .into_response()))
            }
        };
        for (key, value) in patch {
            if key.trim().is_empty() {
                return Err(Box::new(
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "value_patch field names cannot be empty"})),
                    )
                        .into_response(),
                ));
            }
            if matches!(value, serde_json::Value::Null) {
                merged.remove(key);
            } else {
                merged.insert(key.clone(), value.clone());
            }
        }
        serde_json::Value::Object(merged).to_string()
    } else {
        return Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Provide value or value_patch"})),
            )
                .into_response(),
        ));
    };

    validate_signing_value(&plaintext)?;
    Ok(plaintext)
}

/// PATCH /admin/credentials/:name — update config fields without touching the stored secret.
pub async fn handle_patch_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(req): Json<PatchCredentialRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "update credentials") {
        return resp;
    }
    let store = state.db_state.store();

    // api_base and auth_header_format accept either a string value or explicit null to clear.
    let (api_base_val, clear_api_base) = match &req.api_base {
        Some(serde_json::Value::String(s)) => (Some(s.as_str()), false),
        Some(serde_json::Value::Null) => (None, true),
        None => (None, false),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "api_base must be a string or null"})),
            )
                .into_response()
        }
    };
    let (ahf_val, clear_ahf) = match &req.auth_header_format {
        Some(serde_json::Value::String(s)) => (Some(s.as_str()), false),
        Some(serde_json::Value::Null) => (None, true),
        None => (None, false),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "auth_header_format must be a string or null"})),
            )
                .into_response()
        }
    };

    // auth_bindings: Some([]) clears (→ default Bearer / unbound); Some([..])
    // replaces; None leaves untouched. Serialize up front so a malformed body
    // is rejected before any field is written.
    let (auth_bindings_json, clear_auth_bindings) = match &req.auth_bindings {
        None => (None, false),
        Some(bindings) if bindings.is_empty() => (None, true),
        Some(bindings) => match serde_json::to_string(bindings) {
            Ok(s) => (Some(s), false),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Invalid auth_bindings: {e}")})),
                )
                    .into_response()
            }
        },
    };

    // Apply the host allowlist first so a validation failure doesn't leave the
    // other fields updated with a rejected host list.
    if let Some(hosts) = req.allowed_hosts.as_deref() {
        let cleaned = match validate_allowed_hosts(hosts) {
            Ok(c) => c,
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
            }
        };
        match store
            .set_credential_allowed_hosts(&admin.team_id, &name, &cleaned)
            .await
        {
            Ok(false) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Credential not found"})),
                )
                    .into_response()
            }
            Err(e) => return crate::proxy::error_response(e),
            Ok(true) => {}
        }
    }

    match store
        .update_credential_config(
            &admin.team_id,
            &name,
            req.description.as_deref(),
            req.connector.as_deref(),
            api_base_val,
            clear_api_base,
            req.relative_target,
            ahf_val,
            clear_ahf,
            auth_bindings_json.as_deref(),
            clear_auth_bindings,
        )
        .await
    {
        Ok(true) => Json(json!({"updated": true})).into_response(),
        Ok(false) => {
            // update_credential_config returns false when no config field
            // changed; if we already applied a host-list change, that's still a
            // successful update.
            if req.allowed_hosts.is_some() {
                Json(json!({"updated": true})).into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Credential not found"})),
                )
                    .into_response()
            }
        }
        Err(e) => crate::proxy::error_response(e),
    }
}

/// PATCH /admin/credentials/:name/secret — update the write-only stored secret.
pub async fn handle_update_credential_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(req): Json<UpdateCredentialSecretRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "update credentials") {
        return resp;
    }
    let store = state.db_state.store();
    let existing = match store.get_credential(&admin.team_id, &name).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Credential not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };

    let plaintext = match build_credential_secret_update(
        store,
        &admin.team_id,
        &name,
        &existing.connector,
        &req,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    if let Err(e) = store
        .set_credential_value(&admin.team_id, &name, plaintext.as_bytes())
        .await
    {
        return crate::proxy::error_response(e);
    }
    Json(json!({"updated": true})).into_response()
}

/// DELETE /admin/credentials/:name
pub async fn handle_delete_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "delete credentials") {
        return resp;
    }
    match state
        .db_state
        .store()
        .delete_credential(&admin.team_id, &name)
        .await
    {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Agent management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateAgentRequest {
    pub id: String,
    pub description: Option<String>,
    pub rate_limit_per_hour: Option<i64>,
    pub roles: Option<Vec<String>>,
    pub credentials: Option<Vec<String>>,
    /// Create an **Account key**: authorized for every team credential,
    /// including ones added later, instead of the `credentials` whitelist
    /// above (ignored when this is true). Workspace-manager only.
    #[serde(default)]
    pub all_credentials: bool,
}

#[derive(Deserialize)]
pub struct UpdateAgentRequest {
    pub roles: Option<Vec<String>>,
    pub credentials: Option<Vec<String>>,
    /// Toggle Account-key status. Workspace-manager only.
    #[serde(default)]
    pub all_credentials: Option<bool>,
}

fn app_not_found_on_agent_route(agent: &tap_core::store::AgentRow) -> Option<Response> {
    if agent.is_app() {
        Some(
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response(),
        )
    } else {
        None
    }
}

/// GET /admin/agents — list agents.
pub async fn handle_list_agents(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_agent_manager(&admin, "manage API keys") {
        return resp;
    }
    let store = state.db_state.store();
    let agents_result = if user_can_manage_workspace(&admin) {
        store.list_agents(&admin.team_id).await
    } else {
        store.list_agents_for_owner(&admin.team_id, &admin.id).await
    };
    match agents_result {
        Ok(agents) => {
            let list: Vec<serde_json::Value> = agents
                .iter()
                .map(|a| {
                    json!({
                        "id": a.id,
                        "description": a.description,
                        "enabled": a.enabled,
                        "rate_limit_per_hour": a.rate_limit_per_hour,
                        "owner_user_id": a.owner_user_id,
                        "created_at": a.created_at,
                        "all_credentials": a.all_credentials,
                    })
                })
                .collect();
            Json(json!({"agents": list})).into_response()
        }
        Err(e) => {
            warn!("List agents error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list agents"})),
            )
                .into_response()
        }
    }
}

/// POST /admin/agents — create an agent. Returns the API key (shown once).
pub async fn handle_create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAgentRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_agent_manager(&admin, "create API keys") {
        return resp;
    }
    let store = state.db_state.store();
    let workspace_manager = user_can_manage_workspace(&admin);

    // Account keys (all team credentials, present and future) are a
    // workspace-manager-only capability — an approver is restricted to their
    // own `approver_credentials` and must not be able to grant themselves
    // (or a key they create) access to every team credential.
    if req.all_credentials && !workspace_manager {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners and admins can create an Account key"})),
        )
            .into_response();
    }

    if !workspace_manager {
        if let Err(resp) = validate_approver_agent_scope(
            store,
            &admin,
            req.credentials.as_ref(),
            req.roles.as_ref(),
        )
        .await
        {
            return resp;
        }
    }

    // Check tier limits
    if let Ok(Some(team)) = store.get_team(&admin.team_id).await {
        let limits = get_tier_limits(&team.tier);
        if let Some(max) = limits.max_agents {
            if let Ok(agents) = store.list_agents(&admin.team_id).await {
                if agents.len() >= max {
                    return (StatusCode::PAYMENT_REQUIRED, Json(json!({"error": format!("Agent limit reached ({}). Upgrade your plan.", max)}))).into_response();
                }
            }
        }
    }

    // Generate API key and hash
    let api_key = generate_session_token(); // Same random generation
    let key_hash = crate::auth::hash_api_key(&api_key);

    // An Account key is created atomically (`all_credentials` rides in the
    // INSERT) — a create-then-flag UPDATE would leave a Scoped key with an
    // empty whitelist (a dead key the caller was told is an Account key)
    // whenever the follow-up write failed.
    let create_result = if workspace_manager {
        if req.all_credentials {
            store
                .create_agent_all_credentials(
                    &admin.team_id,
                    &req.id,
                    req.description.as_deref(),
                    &key_hash,
                    req.rate_limit_per_hour,
                )
                .await
        } else {
            store
                .create_agent(
                    &admin.team_id,
                    &req.id,
                    req.description.as_deref(),
                    &key_hash,
                    req.rate_limit_per_hour,
                )
                .await
        }
    } else {
        store
            .create_agent_owned(
                &admin.team_id,
                &req.id,
                req.description.as_deref(),
                &key_hash,
                req.rate_limit_per_hour,
                &admin.id,
            )
            .await
    };

    if let Err(e) = create_result {
        let msg = format!("Failed to create agent: {e}");
        return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
    }

    // Assign roles
    if workspace_manager {
        if let Some(ref roles) = req.roles {
            for role in roles {
                if let Err(e) = store
                    .assign_role_to_agent(&admin.team_id, &req.id, role)
                    .await
                {
                    warn!("Role assignment error: {e}");
                }
            }
        }
    }

    // Assign direct credentials — irrelevant for an Account key (it already
    // bypasses the per-credential whitelist), so skip the no-op writes.
    if !req.all_credentials {
        if let Some(ref creds) = req.credentials {
            for cred in creds {
                if let Err(e) = store
                    .add_direct_credential(&admin.team_id, &req.id, cred)
                    .await
                {
                    warn!("Credential assignment error: {e}");
                }
            }
        }
    }

    analytics::capture(
        "tap.agent_key_created",
        &analytics::agent_distinct_id(&admin.team_id),
        json!({"team_id": admin.team_id}),
    );

    (
        StatusCode::CREATED,
        Json(json!({
            "id": req.id,
            "api_key": api_key,
            "message": "Save this API key — it will not be shown again."
        })),
    )
        .into_response()
}

/// GET /admin/agents/:id — get agent details + effective credentials.
pub async fn handle_get_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_agent_manager(&admin, "manage API keys") {
        return resp;
    }
    let store = state.db_state.store();

    match store.get_agent(&admin.team_id, &id).await {
        Ok(Some(agent)) => {
            if let Some(resp) = app_not_found_on_agent_route(&agent) {
                return resp;
            }
            if let Err(resp) = require_agent_access(&admin, &agent, "view") {
                return resp;
            }
            // An Account key can use every team credential (present + future),
            // so report those as its effective set rather than its (empty)
            // whitelist — otherwise the API misleadingly shows "no access".
            let effective = if agent.all_credentials {
                store
                    .list_credentials(&admin.team_id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|c| c.end_user_id.is_none())
                    .map(|c| c.name)
                    .collect::<std::collections::HashSet<_>>()
            } else {
                store
                    .get_agent_effective_credentials(&admin.team_id, &id)
                    .await
                    .unwrap_or_default()
            };
            let mut sorted: Vec<_> = effective.into_iter().collect();
            sorted.sort();
            let direct_creds = store
                .get_agent_direct_credentials(&admin.team_id, &id)
                .await
                .unwrap_or_default();
            let roles = store
                .get_agent_roles(&admin.team_id, &id)
                .await
                .unwrap_or_default();

            Json(json!({
                "id": agent.id,
                "description": agent.description,
                "enabled": agent.enabled,
                "rate_limit_per_hour": agent.rate_limit_per_hour,
                "owner_user_id": agent.owner_user_id,
                "created_at": agent.created_at,
                "all_credentials": agent.all_credentials,
                "effective_credentials": sorted,
                "credentials": direct_creds,
                "roles": roles,
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Agent not found"})),
        )
            .into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// PUT /admin/agents/:id — update an agent's credentials and roles.
pub async fn handle_update_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_agent_manager(&admin, "update API keys") {
        return resp;
    }
    let store = state.db_state.store();
    let workspace_manager = user_can_manage_workspace(&admin);

    if req.all_credentials.is_some() && !workspace_manager {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners and admins can change Account-key status"})),
        )
            .into_response();
    }

    let agent = match store.get_agent(&admin.team_id, &id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    if let Some(resp) = app_not_found_on_agent_route(&agent) {
        return resp;
    }
    if let Err(resp) = require_agent_access(&admin, &agent, "update") {
        return resp;
    }
    if !workspace_manager {
        if let Err(resp) = validate_approver_agent_scope(
            store,
            &admin,
            req.credentials.as_ref(),
            req.roles.as_ref(),
        )
        .await
        {
            return resp;
        }
    }

    if let Some(all_credentials) = req.all_credentials {
        // This flag IS the authorization boundary — a swallowed failure would
        // report "updated" while the key keeps its previous scope. Fail loud.
        if let Err(e) = store
            .set_agent_all_credentials(&admin.team_id, &id, all_credentials)
            .await
        {
            warn!("Failed to update Account-key status: {e}");
            return crate::proxy::error_response(e);
        }
        // Promotion to an Account key supersedes the per-credential
        // whitelist: purge it so a later demotion falls back to "no access"
        // (explicitly re-granted) instead of silently resurrecting a stale
        // ghost whitelist nobody has reviewed since the promotion.
        if all_credentials && !agent.all_credentials {
            let current = store
                .get_agent_direct_credentials(&admin.team_id, &id)
                .await
                .unwrap_or_default();
            for cred in &current {
                if let Err(e) = store
                    .remove_direct_credential(&admin.team_id, &id, cred)
                    .await
                {
                    warn!("Failed to purge whitelist entry {cred} on Account-key promotion: {e}");
                }
            }
        }
    }
    // An Account key bypasses the per-credential whitelist, so syncing
    // `credentials` is a no-op for it — skip the writes.
    let is_account_key = req.all_credentials.unwrap_or(agent.all_credentials);

    // Sync credentials: diff current vs desired
    if !is_account_key {
        if let Some(ref desired_creds) = req.credentials {
            let current = store
                .get_agent_direct_credentials(&admin.team_id, &id)
                .await
                .unwrap_or_default();
            let desired: std::collections::HashSet<&str> =
                desired_creds.iter().map(|s| s.as_str()).collect();
            let current_set: std::collections::HashSet<&str> =
                current.iter().map(|s| s.as_str()).collect();
            for add in desired.difference(&current_set) {
                let _ = store.add_direct_credential(&admin.team_id, &id, add).await;
            }
            for remove in current_set.difference(&desired) {
                let _ = store
                    .remove_direct_credential(&admin.team_id, &id, remove)
                    .await;
            }
        }
    }

    // Sync roles
    if workspace_manager {
        if let Some(ref desired_roles) = req.roles {
            let current = store
                .get_agent_roles(&admin.team_id, &id)
                .await
                .unwrap_or_default();
            let desired: std::collections::HashSet<&str> =
                desired_roles.iter().map(|s| s.as_str()).collect();
            let current_set: std::collections::HashSet<&str> =
                current.iter().map(|s| s.as_str()).collect();
            for add in desired.difference(&current_set) {
                let _ = store.assign_role_to_agent(&admin.team_id, &id, add).await;
            }
            for remove in current_set.difference(&desired) {
                let _ = store
                    .remove_role_from_agent(&admin.team_id, &id, remove)
                    .await;
            }
        }
    }

    Json(json!({"updated": true})).into_response()
}

/// DELETE /admin/agents/:id
pub async fn handle_delete_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_agent_manager(&admin, "delete API keys") {
        return resp;
    }
    let store = state.db_state.store();
    let agent = match store.get_agent(&admin.team_id, &id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    if let Some(resp) = app_not_found_on_agent_route(&agent) {
        return resp;
    }
    if let Err(resp) = require_agent_access(&admin, &agent, "delete") {
        return resp;
    }
    match store.delete_agent(&admin.team_id, &id).await {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// POST /admin/agents/:id/enable
pub async fn handle_enable_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_agent_manager(&admin, "enable API keys") {
        return resp;
    }
    let store = state.db_state.store();
    let agent = match store.get_agent(&admin.team_id, &id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    if let Some(resp) = app_not_found_on_agent_route(&agent) {
        return resp;
    }
    if let Err(resp) = require_agent_access(&admin, &agent, "enable") {
        return resp;
    }
    match store.enable_agent(&admin.team_id, &id).await {
        Ok(()) => Json(json!({"enabled": true})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// POST /admin/agents/:id/disable
pub async fn handle_disable_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_agent_manager(&admin, "disable API keys") {
        return resp;
    }
    let store = state.db_state.store();
    let agent = match store.get_agent(&admin.team_id, &id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    if let Some(resp) = app_not_found_on_agent_route(&agent) {
        return resp;
    }
    if let Err(resp) = require_agent_access(&admin, &agent, "disable") {
        return resp;
    }
    match store.disable_agent(&admin.team_id, &id).await {
        Ok(()) => Json(json!({"disabled": true})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

#[derive(serde::Deserialize)]
pub struct CreateAppRequest {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// GET /team/apps — list the team's **app keys** (TAP for Platforms). These are
/// `agents` rows with `kind='app'` and never appear in the agents list.
/// Workspace-manager only.
pub async fn handle_list_apps(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage apps") {
        return resp;
    }
    let store = state.db_state.store();
    match store.list_apps(&admin.team_id).await {
        Ok(apps) => {
            let list: Vec<serde_json::Value> = apps
                .iter()
                .map(|a| {
                    json!({
                        "id": a.id,
                        "description": a.description,
                        "created_at": a.created_at,
                    })
                })
                .collect();
            Json(json!({"apps": list})).into_response()
        }
        Err(e) => {
            warn!("List apps error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list apps"})),
            )
                .into_response()
        }
    }
}

/// POST /team/apps — register an **app** (TAP for Platforms) and mint its app
/// key. An app key manages end-users and may assert `X-TAP-End-User`; it is
/// stored as an `agents` row with `kind='app'`. Returns the API key (shown
/// once). Workspace-manager only: this capability bypasses the per-credential
/// whitelist for end-user-scoped credentials.
pub async fn handle_create_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAppRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage apps") {
        return resp;
    }
    let id = req.id.trim();
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "App id must be non-empty and contain only letters, digits, '-' or '_'",
            })),
        )
            .into_response();
    }
    let store = state.db_state.store();

    // Generate API key and hash (same generation as agent keys).
    let api_key = generate_session_token();
    let key_hash = crate::auth::hash_api_key(&api_key);

    match store
        .create_app(
            &admin.team_id,
            id,
            req.description.as_deref(),
            &key_hash,
            None,
        )
        .await
    {
        Ok(()) => {
            analytics::capture(
                "tap.app_key_created",
                &analytics::agent_distinct_id(&admin.team_id),
                json!({"team_id": admin.team_id}),
            );
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": id,
                    "api_key": api_key,
                    "message": "Save this app key — it will not be shown again."
                })),
            )
                .into_response()
        }
        Err(e) => {
            let msg = format!("Failed to create app: {e}");
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
    }
}

/// POST /admin/agents/:id/rotate-key
pub async fn handle_rotate_agent_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_agent_manager(&admin, "rotate API keys") {
        return resp;
    }
    let store = state.db_state.store();
    let agent = match store.get_agent(&admin.team_id, &id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Agent not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    if let Some(resp) = app_not_found_on_agent_route(&agent) {
        return resp;
    }
    if let Err(resp) = require_agent_access(&admin, &agent, "rotate") {
        return resp;
    }
    let api_key = generate_session_token();
    let key_hash = crate::auth::hash_api_key(&api_key);

    match store.rotate_agent_api_key(&admin.team_id, &id, &key_hash).await {
        Ok(()) => Json(json!({
            "id": id,
            "api_key": api_key,
            "message": "Old API key invalidated. Save this replacement key now — it will not be shown again."
        }))
        .into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Role management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub credentials: Option<Vec<String>>,
    pub rate_limit_per_hour: Option<i64>,
}

/// GET /admin/roles
pub async fn handle_list_roles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage roles") {
        return resp;
    }
    let store = state.db_state.store();
    match store.list_roles(&admin.team_id).await {
        Ok(roles) => {
            let mut list: Vec<serde_json::Value> = Vec::new();
            for r in &roles {
                let creds = store
                    .list_role_credentials(&admin.team_id, &r.name)
                    .await
                    .unwrap_or_default();
                list.push(json!({
                    "name": r.name,
                    "description": r.description,
                    "rate_limit_per_hour": r.rate_limit_per_hour,
                    "credentials": creds,
                }));
            }
            Json(json!({"roles": list})).into_response()
        }
        Err(e) => crate::proxy::error_response(e),
    }
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub description: Option<String>,
    pub rate_limit_per_hour: Option<i64>,
    pub credentials: Option<Vec<String>>,
}

/// PUT /admin/roles/:name — update description, rate limit, and credential assignments.
pub async fn handle_update_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(req): Json<UpdateRoleRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "update roles") {
        return resp;
    }
    let store = state.db_state.store();

    if let Err(e) = store
        .update_role(
            &admin.team_id,
            &name,
            req.description.as_deref(),
            req.rate_limit_per_hour,
        )
        .await
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Failed to update role: {e}")})),
        )
            .into_response();
    }

    if let Some(creds) = req.credentials {
        let existing = store
            .list_role_credentials(&admin.team_id, &name)
            .await
            .unwrap_or_default();
        for c in &existing {
            if !creds.contains(c) {
                let _ = store
                    .remove_credential_from_role(&admin.team_id, &name, c)
                    .await;
            }
        }
        for c in &creds {
            if !existing.contains(c) {
                let _ = store.add_credential_to_role(&admin.team_id, &name, c).await;
            }
        }
    }

    Json(json!({"name": name, "updated": true})).into_response()
}

/// POST /admin/roles — create role with optional initial credentials.
pub async fn handle_create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateRoleRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "create roles") {
        return resp;
    }
    let store = state.db_state.store();

    if let Err(e) = store
        .create_role(
            &admin.team_id,
            &req.name,
            req.description.as_deref(),
            req.rate_limit_per_hour,
        )
        .await
    {
        let msg = format!("Failed to create role: {e}");
        return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
    }

    if let Some(ref creds) = req.credentials {
        for cred in creds {
            if let Err(e) = store
                .add_credential_to_role(&admin.team_id, &req.name, cred)
                .await
            {
                warn!("Add credential to role error: {e}");
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(json!({"name": req.name, "created": true})),
    )
        .into_response()
}

/// DELETE /admin/roles/:name
pub async fn handle_delete_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "delete roles") {
        return resp;
    }
    match state
        .db_state
        .store()
        .delete_role(&admin.team_id, &name)
        .await
    {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Policy management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetPolicyRequest {
    pub auto_approve_methods: Option<Vec<String>>,
    pub require_approval_methods: Option<Vec<String>>,
    pub auto_approve_urls: Option<Vec<String>>,
    pub require_approval_urls: Option<Vec<String>>,
    pub allowed_approvers: Option<Vec<String>>,
    pub approval_channel: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub matrix_room_id: Option<String>,
    pub matrix_allowed_approvers: Option<Vec<String>>,
    pub require_passkey: Option<bool>,
    pub min_approvals: Option<u32>,
}

#[allow(clippy::result_large_err)]
fn normalize_policy_approval_channel(channel: Option<String>) -> Result<Option<String>, Response> {
    let Some(channel) = channel
        .map(|c| c.trim().to_lowercase())
        .filter(|c| !c.is_empty())
    else {
        return Ok(None);
    };
    const SUPPORTED: &[&str] = &["telegram", "matrix", "dashboard", "agent_reflected", "app"];
    if !SUPPORTED.contains(&channel.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Unsupported approval channel '{}'. Supported: {}", channel, SUPPORTED.join(", "))})),
        )
            .into_response());
    }
    Ok(Some(channel))
}

/// Validate that every entry in an `allowed_approvers` list is a team member email.
/// Returns an error response if any entry is invalid.
async fn validate_approver_emails(
    emails: &[String],
    team_id: &str,
    store: &tap_core::store::ConfigStore,
) -> Result<(), Response> {
    for email in emails {
        if !email.contains('@') || email.starts_with('@') {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("allowed_approvers: '{}' is not a valid email. Only team member emails are accepted.", email)})),
            ).into_response());
        }
        match store.get_member_by_email_and_team(email, team_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("allowed_approvers: '{}' is not a member of this team", email)})),
                ).into_response());
            }
            Err(e) => {
                warn!("Error validating approver email {email}: {e}");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to validate approver"})),
                )
                    .into_response());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Time-boxed approval grants (#49)
// ---------------------------------------------------------------------------

/// Hard cap on a grant's TTL. A grant is a temporary exception, not a policy —
/// anything that should outlive a day belongs in `auto_approve_urls` where it
/// is visible as standing configuration.
const GRANT_MAX_TTL_MINUTES: i64 = 24 * 60;

const GRANT_ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    pub methods: Vec<String>,
    pub route_scope: Vec<String>,
    pub ttl_minutes: i64,
    #[serde(default)]
    pub max_uses: Option<i64>,
}

/// Guardrails (#49, non-negotiable): non-empty concrete scope, short TTL,
/// bounded uses. Returns normalized (uppercased) methods + trimmed patterns.
/// Also used by the inbox approve-with-grant path (webauthn.rs) so a grant
/// created from a pending request obeys exactly the same rules.
pub(crate) fn validate_grant_request(
    req: &CreateGrantRequest,
) -> Result<(Vec<String>, Vec<String>), String> {
    if req.methods.is_empty() {
        return Err("Select at least one HTTP method".into());
    }
    let mut methods = Vec::new();
    for m in &req.methods {
        let up = m.trim().to_uppercase();
        if !GRANT_ALLOWED_METHODS.contains(&up.as_str()) {
            return Err(format!("Unknown HTTP method: {m}"));
        }
        if !methods.contains(&up) {
            methods.push(up);
        }
    }
    if req.route_scope.is_empty() {
        return Err("A grant needs at least one route pattern — a grant with no scope would auto-approve every URL, which defeats TAP".into());
    }
    let mut routes = Vec::new();
    for p in &req.route_scope {
        let pat = p.trim().to_string();
        if pat.is_empty() {
            continue;
        }
        // No match-everything and no host-agnostic scopes. A bare "/" is the
        // "POST *" the issue forbids — and a '/'-prefixed path-only pattern is
        // nearly as bad: per policy::url_matches_policy_pattern it anchors to
        // the *path* on ANY host, so a grant scoped to "/v1/messages" would
        // auto-approve POST https://evil.com/v1/messages and silently forward
        // the injected secret off-host (the exact exfil e619816 closed for
        // recipe auto-approve URLs). A grant must name the concrete host it
        // covers; auto_approve_urls keeps the path-only form for standing,
        // human-reviewed policy.
        if pat.starts_with('/') {
            return Err(format!(
                "Route pattern \"{pat}\" must start with a concrete host (api.example.com/v1/...) — a path-only pattern would cover that path on every host"
            ));
        }
        let host = pat.split('/').next().unwrap_or("");
        if host.contains('*') || !host.contains('.') {
            return Err(format!(
                "Route pattern \"{pat}\" must start with a concrete host (api.example.com/...)"
            ));
        }
        // Require a concrete path component. A host-only pattern
        // ("api.example.com") would auto-approve EVERY path on that host+method
        // — far broader than the request an approver reviewed (F2). Grants are
        // narrow, temporary exceptions; a specific path (or `*` segment) is
        // mandatory.
        match pat.split_once('/') {
            Some((_, path)) if !path.trim().is_empty() => {}
            _ => {
                return Err(format!(
                    "Route pattern \"{pat}\" needs a concrete path (api.example.com/v1/...) — a host-only scope would auto-approve every path on that host"
                ));
            }
        }
        routes.push(pat);
    }
    if routes.is_empty() {
        return Err("A grant needs at least one route pattern".into());
    }
    if req.ttl_minutes < 1 || req.ttl_minutes > GRANT_MAX_TTL_MINUTES {
        return Err(format!(
            "ttl_minutes must be between 1 and {GRANT_MAX_TTL_MINUTES} (a grant is a temporary exception; permanent rules belong in auto-approve URL patterns)"
        ));
    }
    if let Some(n) = req.max_uses {
        if n < 1 {
            return Err("max_uses must be at least 1".into());
        }
    }
    Ok((methods, routes))
}

/// POST /team/credentials/{name}/grants — create a time-boxed grant.
pub async fn handle_create_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(cred_name): axum::extract::Path<String>,
    Json(req): Json<CreateGrantRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage grants") {
        return resp;
    }
    // End-user credentials are governed by the passkey-lock ceremony (R2) —
    // a manager-issued grant would loosen enforcement without the end-user's
    // consent, so they are never grant-eligible (mirrors proposals).
    if cred_name.starts_with("eu:") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "End-user credentials cannot be time-boxed", "error_code": "grant_not_allowed_end_user"})),
        )
            .into_response();
    }

    let store = state.db_state.store();
    match store.get_credential(&admin.team_id, &cred_name).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Credential not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    }

    // require_passkey credentials can never be time-boxed: if a write is
    // worth a passkey ceremony, it is worth a human on every request. The
    // claim path re-checks this via its call-site guard (defense-in-depth).
    match store.get_policy(&admin.team_id, &cred_name).await {
        Ok(Some(p)) if p.require_passkey => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "This credential requires passkey approval and cannot be time-boxed", "error_code": "grant_not_allowed_passkey"})),
            )
                .into_response()
        }
        Ok(_) => {}
        Err(e) => return crate::proxy::error_response(e),
    }

    let (methods, route_scope) = match validate_grant_request(&req) {
        Ok(v) => v,
        Err(msg) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
    };

    let now = chrono::Utc::now();
    let grant = tap_core::store::GrantRow {
        id: uuid::Uuid::new_v4().to_string(),
        team_id: admin.team_id.clone(),
        credential_name: cred_name,
        methods,
        route_scope,
        expires_at: (now + chrono::Duration::minutes(req.ttl_minutes)).to_rfc3339(),
        granted_by: admin.email.clone(),
        max_uses: req.max_uses,
        uses: 0,
        revoked: false,
        created_at: now.to_rfc3339(),
    };
    if let Err(e) = store.create_approval_grant(&grant).await {
        return crate::proxy::error_response(e);
    }

    // Grant creation is a control-loosening event (it authors a temporary
    // auto-approve rule), so it must land in the immutable audit log — not just
    // tracing. Consumption is already audited via `policy_reason = "grant:<id>"`;
    // this records the authoring event. The grant metadata is non-secret, so we
    // stash the scope/TTL/cap/source in `request_body` for the audit reader.
    let grant_summary = json!({
        "grant_id": grant.id,
        "credential": grant.credential_name,
        "methods": grant.methods,
        "route_scope": grant.route_scope,
        "expires_at": grant.expires_at,
        "max_uses": grant.max_uses,
        "source": "dashboard",
    });
    let entry = tap_core::types::AuditEntry {
        request_id: uuid::Uuid::parse_str(&grant.id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
        agent_id: admin.id.clone(),
        credential_names: vec![grant.credential_name.clone()],
        target_url: "tap:grant-create".to_string(),
        method: tap_core::types::HttpMethod::Post,
        approval_status: None,
        upstream_status: None,
        total_latency_ms: 0,
        approval_latency_ms: None,
        upstream_latency_ms: None,
        response_sanitized: false,
        end_user_id: None,
        request_headers: vec![],
        request_body: Some(grant_summary.to_string()),
        request_body_truncated: false,
        policy_reason: Some(format!("grant_created:{}", grant.id)),
        require_passkey: false,
        // The workspace manager who authored the grant.
        approver_identity: Some(admin.email.clone()),
        timestamp: chrono::Utc::now(),
    };
    state.audit_logger.write_entry(&entry);

    (StatusCode::CREATED, Json(json!({"grant": grant}))).into_response()
}

/// GET /team/grants — all grants for the team (dashboard derives state).
pub async fn handle_list_grants(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "view grants") {
        return resp;
    }
    match state.db_state.store().list_approval_grants(&admin.team_id).await {
        Ok(grants) => Json(json!({"grants": grants, "now": chrono::Utc::now().to_rfc3339()})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// POST /team/grants/{id}/revoke — one-click kill. The row is kept for audit.
pub async fn handle_revoke_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(grant_id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "revoke grants") {
        return resp;
    }
    match state
        .db_state
        .store()
        .revoke_approval_grant(&admin.team_id, &grant_id)
        .await
    {
        Ok(true) => Json(json!({"revoked": true})).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Grant not found"})),
        )
            .into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// PUT /admin/policies/:cred_name
pub async fn handle_set_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(cred_name): axum::extract::Path<String>,
    Json(req): Json<SetPolicyRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage policies") {
        return resp;
    }

    let store = state.db_state.store();
    let allowed_approvers = req.allowed_approvers.unwrap_or_default();
    let matrix_allowed_approvers = req.matrix_allowed_approvers.unwrap_or_default();
    if let Err(e) = validate_approver_emails(&allowed_approvers, &admin.team_id, store).await {
        return e;
    }
    if let Err(e) = validate_approver_emails(&matrix_allowed_approvers, &admin.team_id, store).await
    {
        return e;
    }
    let approval_channel = match normalize_policy_approval_channel(req.approval_channel) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let require_approval_urls = match req.require_approval_urls {
        Some(urls) => urls,
        None => match store.get_policy(&admin.team_id, &cred_name).await {
            Ok(Some(current)) => current.require_approval_urls,
            Ok(None) => Vec::new(),
            Err(e) => return crate::proxy::error_response(e),
        },
    };

    use tap_core::store::PolicyRow;
    let row = PolicyRow {
        team_id: admin.team_id.clone(),
        credential_name: cred_name.clone(),
        auto_approve_methods: req.auto_approve_methods.unwrap_or_default(),
        require_approval_methods: req.require_approval_methods.unwrap_or_default(),
        auto_approve_urls: req.auto_approve_urls.unwrap_or_default(),
        require_approval_urls,
        allowed_approvers,
        approval_channel,
        telegram_chat_id: req.telegram_chat_id,
        matrix_room_id: req.matrix_room_id,
        matrix_allowed_approvers,
        require_passkey: req.require_passkey.unwrap_or(false),
        min_approvals: req.min_approvals.unwrap_or(1).max(1),
    };

    // Passkey-lock (R2): a workspace manager cannot loosen a passkey-protected
    // end-user credential via the admin API (using its namespaced name) — only
    // the end-user's passkey can, through the app policy-change ceremony.
    // Tightening is always allowed.
    match crate::app::end_user_policy_lock(&state, &admin.team_id, &cred_name, &row).await {
        Ok(Some(ext)) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "This change loosens a passkey-protected end-user credential and requires the end-user's passkey.",
                    "error_code": "end_user_passkey_required",
                    "end_user": ext,
                })),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(e) => return crate::proxy::error_response(e),
    }

    match state.db_state.store().set_policy(&row).await {
        Ok(()) => {
            // Invalidate the cached policy so the proxy picks up the change on the
            // next request rather than waiting for the cache TTL to expire.
            state
                .db_state
                .invalidate_policy_cache(&admin.team_id, &cred_name)
                .await;
            Json(json!({"credential": cred_name, "policy_set": true})).into_response()
        }
        Err(e) => crate::proxy::error_response(e),
    }
}

/// GET /admin/policies/:cred_name
pub async fn handle_get_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(cred_name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "view policies") {
        return resp;
    }
    match state
        .db_state
        .store()
        .get_policy(&admin.team_id, &cred_name)
        .await
    {
        Ok(Some(p)) => Json(json!({
            "credential": cred_name,
            "auto_approve_methods": p.auto_approve_methods,
            "require_approval_methods": p.require_approval_methods,
            "auto_approve_urls": p.auto_approve_urls,
            "require_approval_urls": p.require_approval_urls,
            "allowed_approvers": p.allowed_approvers,
            "approval_channel": p.approval_channel,
            "telegram_chat_id": p.telegram_chat_id,
            "matrix_room_id": p.matrix_room_id,
            "matrix_allowed_approvers": p.matrix_allowed_approvers,
            "require_passkey": p.require_passkey,
            "min_approvals": p.min_approvals,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No policy set for this credential"})),
        )
            .into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

// --- Agent-originated proposals (policy_change) ----------------------------

/// GET /team/proposals — list pending proposals for the team, each annotated
/// with the permissive changes it would introduce. Workspace-manager only.
pub async fn handle_list_proposals(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "review proposals") {
        return resp;
    }
    let store = state.db_state.store();
    let rows = match store
        .list_proposals_for_team(&admin.team_id, Some("pending"))
        .await
    {
        Ok(r) => r,
        Err(e) => return crate::proxy::error_response(e),
    };
    let mut out = Vec::new();
    for row in rows {
        // Only policy_change proposals are stored; skip anything malformed.
        let payload: crate::proposals::PolicyChangePayload =
            match serde_json::from_str(&row.payload_json) {
                Ok(p) => p,
                Err(_) => continue,
            };
        let current_row = store
            .get_policy(&admin.team_id, &payload.credential_name)
            .await
            .ok()
            .flatten();
        let current_view = current_row
            .as_ref()
            .map(crate::proposals::policy_view_from_row);
        let merged = payload.merged_view(current_view.as_ref());
        let permissive = tap_core::policy_diff::permissive_changes(current_view.as_ref(), &merged);
        out.push(json!({
            "id": row.id,
            "agent_id": row.agent_id,
            "proposal_type": row.proposal_type,
            "created_at": row.created_at,
            "expires_at": row.expires_at,
            "payload": payload,
            "credential_exists": current_row.is_some(),
            "permissive_changes": permissive,
        }));
    }
    Json(json!({ "proposals": out })).into_response()
}

/// POST /team/proposals/{id}/approve/begin — start the WebAuthn step-up for
/// approving a proposal. Returns the assertion challenge. Workspace-manager only.
pub async fn handle_begin_proposal_approval(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "approve proposals") {
        return resp;
    }
    let store = state.db_state.store();
    match store.get_proposal(&admin.team_id, &id).await {
        Ok(Some(p)) if p.status == "pending" => {}
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "proposal already resolved"})),
            )
                .into_response()
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "proposal not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
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
    // Scope the challenge to THIS manager's passkeys (defence in depth):
    // the unscoped variant offers every passkey in the deployment, leaving a
    // post-hoc email comparison as the only authorization.
    match wa.begin_approval_for_user(&id, &admin.id, &admin.email).await {
        Ok(rcr) => Json(rcr).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

#[derive(Deserialize)]
pub struct ResolveProposalRequest {
    /// "approve" | "deny"
    pub decision: String,
    /// WebAuthn assertion (required for approve when passkeys are configured).
    #[serde(default)]
    pub assertion: Option<webauthn_rs_proto::PublicKeyCredential>,
}

/// POST /team/proposals/{id}/resolve — approve (passkey-gated) or deny a
/// proposal. Approve applies the policy change then atomically claims the
/// proposal; deny just claims it. Workspace-manager only.
pub async fn handle_resolve_proposal(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<ResolveProposalRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "resolve proposals") {
        return resp;
    }
    let store = state.db_state.store();

    let proposal = match store.get_proposal(&admin.team_id, &id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "proposal not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    if proposal.status != "pending" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "proposal already resolved", "status": proposal.status})),
        )
            .into_response();
    }

    match req.decision.as_str() {
        "deny" => match store
            .resolve_proposal(&admin.team_id, &id, "denied", &admin.email)
            .await
        {
            Ok(true) => Json(json!({"status": "denied"})).into_response(),
            Ok(false) => (
                StatusCode::CONFLICT,
                Json(json!({"error": "proposal already resolved"})),
            )
                .into_response(),
            Err(e) => crate::proxy::error_response(e),
        },
        "approve" => {
            // Passkey gate (enforced when WebAuthn is configured on this
            // instance — mirrors system-wide passkey behavior). The assertion
            // is bound to this proposal id and must belong to the acting manager.
            if let Some(wa) = &state.webauthn_state {
                let assertion = match req.assertion {
                    Some(a) => a,
                    None => {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(json!({
                                "error": "passkey assertion required to approve",
                                "error_code": "passkey_required"
                            })),
                        )
                            .into_response()
                    }
                };
                match wa
                    .finish_approval_for_user(&id, &admin.id, &admin.email, &assertion)
                    .await
                {
                    Ok(verified_user_id) => {
                        // Scoped ceremony: the credential lookup is already restricted to
                        // this user's passkeys, and the fn returns the user_id it was
                        // scoped to. Re-assert it so a future contract change fails closed.
                        if verified_user_id != admin.id {
                            return (
                                StatusCode::FORBIDDEN,
                                Json(json!({"error": "passkey does not belong to the approving manager"})),
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
            // Future delegation hook (#49-adjacent): when a per-credential
            // `policy_change_authority='approvers'` setting exists, swap the
            // require_workspace_manager gate above for an allowed_approvers
            // check on the target credential.

            let payload: crate::proposals::PolicyChangePayload =
                match serde_json::from_str(&proposal.payload_json) {
                    Ok(p) => p,
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": format!("corrupt proposal payload: {e}")})),
                        )
                            .into_response()
                    }
                };

            // The target credential must still exist (it may have been deleted
            // between propose and approve). Authoritative check at approve time.
            match state
                .get_credential_config(&admin.team_id, &payload.credential_name)
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({
                            "error": format!("credential '{}' no longer exists", payload.credential_name)
                        })),
                    )
                        .into_response()
                }
                Err(e) => return crate::proxy::error_response(e),
            }

            let current_row = store
                .get_policy(&admin.team_id, &payload.credential_name)
                .await
                .ok()
                .flatten();
            let new_row = build_merged_policy_row(&admin.team_id, &payload, current_row.as_ref());

            // End-user passkey-lock (R2): a permissive change to a
            // passkey-protected end-user credential must not be applied by a
            // workspace manager — not even through the proposal path. Loosening
            // an end-user's own protection requires that end-user's passkey
            // (the `/app/users/{ext}/policy-changes/...` flow). This mirrors the
            // guard on `handle_set_policy` (admin.rs) and the agent
            // self-proposal path (app.rs); without it, approving a proposal that
            // names an `eu:{ext}/…` credential would silently weaken the
            // end-user's protection with only the manager's own passkey.
            match crate::app::end_user_policy_lock(
                &state,
                &admin.team_id,
                &payload.credential_name,
                &new_row,
            )
            .await
            {
                Ok(Some(ext)) => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": "end_user_policy_locked",
                            "message": format!(
                                "Credential '{}' is protected by end-user '{}'. Loosening its policy requires that end-user's passkey approval and cannot be applied via a workspace proposal.",
                                payload.credential_name, ext
                            )
                        })),
                    )
                        .into_response();
                }
                Ok(None) => {}
                Err(e) => return crate::proxy::error_response(e),
            }

            if let Err(e) = store.set_policy(&new_row).await {
                return crate::proxy::error_response(e);
            }
            state
                .db_state
                .invalidate_policy_cache(&admin.team_id, &payload.credential_name)
                .await;

            // Claim the proposal last; set_policy is an idempotent upsert so a
            // lost claim race (another manager approved concurrently) is safe.
            match store
                .resolve_proposal(&admin.team_id, &id, "approved", &admin.email)
                .await
            {
                Ok(true) => {
                    Json(json!({"status": "approved", "credential": payload.credential_name}))
                        .into_response()
                }
                Ok(false) => (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "proposal already resolved by another manager"})),
                )
                    .into_response(),
                Err(e) => crate::proxy::error_response(e),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "decision must be 'approve' or 'deny'"})),
        )
            .into_response(),
    }
}

/// Build the `PolicyRow` to write when approving a policy_change: start from the
/// current policy (preserving channel/matrix fields the proposal doesn't carry),
/// then override each field the proposal specifies.
fn build_merged_policy_row(
    team_id: &str,
    payload: &crate::proposals::PolicyChangePayload,
    current: Option<&tap_core::store::PolicyRow>,
) -> tap_core::store::PolicyRow {
    tap_core::store::PolicyRow {
        team_id: team_id.to_string(),
        credential_name: payload.credential_name.clone(),
        auto_approve_methods: payload.auto_approve_methods.clone().unwrap_or_else(|| {
            current
                .map(|c| c.auto_approve_methods.clone())
                .unwrap_or_default()
        }),
        require_approval_methods: payload.require_approval_methods.clone().unwrap_or_else(|| {
            current
                .map(|c| c.require_approval_methods.clone())
                .unwrap_or_default()
        }),
        auto_approve_urls: payload.auto_approve_urls.clone().unwrap_or_else(|| {
            current
                .map(|c| c.auto_approve_urls.clone())
                .unwrap_or_default()
        }),
        require_approval_urls: payload.require_approval_urls.clone().unwrap_or_else(|| {
            current
                .map(|c| c.require_approval_urls.clone())
                .unwrap_or_default()
        }),
        allowed_approvers: payload.allowed_approvers.clone().unwrap_or_else(|| {
            current
                .map(|c| c.allowed_approvers.clone())
                .unwrap_or_default()
        }),
        approval_channel: current.and_then(|c| c.approval_channel.clone()),
        telegram_chat_id: current.and_then(|c| c.telegram_chat_id.clone()),
        matrix_room_id: current.and_then(|c| c.matrix_room_id.clone()),
        matrix_allowed_approvers: current
            .map(|c| c.matrix_allowed_approvers.clone())
            .unwrap_or_default(),
        require_passkey: payload
            .require_passkey
            .unwrap_or_else(|| current.map(|c| c.require_passkey).unwrap_or(false)),
        min_approvals: payload
            .min_approvals
            .unwrap_or_else(|| current.map(|c| c.min_approvals).unwrap_or(1))
            .max(1),
    }
}

// ---------------------------------------------------------------------------
// Policy template management
// ---------------------------------------------------------------------------

/// GET /admin/policy-templates — list all template names for the authenticated team.
pub async fn handle_list_policy_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage policy templates") {
        return resp;
    }
    match state
        .db_state
        .store()
        .list_policy_templates(&admin.team_id)
        .await
    {
        Ok(names) => Json(json!({ "templates": names })).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// GET /admin/policy-templates/:name — fetch one template.
pub async fn handle_get_policy_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage policy templates") {
        return resp;
    }
    match state
        .db_state
        .store()
        .get_policy_template(&admin.team_id, &name)
        .await
    {
        Ok(Some(p)) => Json(json!({
            "template_name": name,
            "auto_approve_methods": p.auto_approve_methods,
            "require_approval_methods": p.require_approval_methods,
            "auto_approve_urls": p.auto_approve_urls,
            "require_approval_urls": p.require_approval_urls,
            "allowed_approvers": p.allowed_approvers,
            "approval_channel": p.approval_channel,
            "telegram_chat_id": p.telegram_chat_id,
            "matrix_room_id": p.matrix_room_id,
            "matrix_allowed_approvers": p.matrix_allowed_approvers,
            "require_passkey": p.require_passkey,
            "min_approvals": p.min_approvals,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Template not found"})),
        )
            .into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// PUT /admin/policy-templates/:name — create or update a named template.
pub async fn handle_set_policy_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(req): Json<SetPolicyRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage policy templates") {
        return resp;
    }

    let store = state.db_state.store();
    let allowed_approvers = req.allowed_approvers.unwrap_or_default();
    let matrix_allowed_approvers = req.matrix_allowed_approvers.unwrap_or_default();
    if let Err(e) = validate_approver_emails(&allowed_approvers, &admin.team_id, store).await {
        return e;
    }
    if let Err(e) = validate_approver_emails(&matrix_allowed_approvers, &admin.team_id, store).await
    {
        return e;
    }
    let approval_channel = match normalize_policy_approval_channel(req.approval_channel) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let require_approval_urls = match req.require_approval_urls {
        Some(urls) => urls,
        None => match store.get_policy_template(&admin.team_id, &name).await {
            Ok(Some(current)) => current.require_approval_urls,
            Ok(None) => Vec::new(),
            Err(e) => return crate::proxy::error_response(e),
        },
    };

    use tap_core::store::PolicyRow;
    let row = PolicyRow {
        team_id: admin.team_id.clone(),
        credential_name: name.clone(),
        auto_approve_methods: req.auto_approve_methods.unwrap_or_default(),
        require_approval_methods: req.require_approval_methods.unwrap_or_default(),
        auto_approve_urls: req.auto_approve_urls.unwrap_or_default(),
        require_approval_urls,
        allowed_approvers,
        approval_channel,
        telegram_chat_id: req.telegram_chat_id,
        matrix_room_id: req.matrix_room_id,
        matrix_allowed_approvers,
        require_passkey: req.require_passkey.unwrap_or(false),
        min_approvals: req.min_approvals.unwrap_or(1).max(1),
    };

    match state
        .db_state
        .store()
        .set_policy_template(&admin.team_id, &name, &row)
        .await
    {
        Ok(()) => Json(json!({"template_name": name, "saved": true})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// DELETE /admin/policy-templates/:name — delete a named template.
pub async fn handle_delete_policy_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage policy templates") {
        return resp;
    }
    match state
        .db_state
        .store()
        .delete_policy_template(&admin.team_id, &name)
        .await
    {
        Ok(()) => Json(json!({"template_name": name, "deleted": true})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Team info
// ---------------------------------------------------------------------------

/// GET /admin/team — get team info.
pub async fn handle_get_team(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    // Posture governs credentials with no explicit policy; fail safe to gated.
    let approval_mode = state
        .db_state
        .store()
        .get_team_default_approval_mode(&admin.team_id)
        .await
        .unwrap_or_default();
    match state.db_state.store().get_team(&admin.team_id).await {
        Ok(Some(team)) => Json(json!({
            "id": team.id,
            "name": team.name,
            "tier": team.tier,
            "default_approval_mode": approval_mode.as_str(),
            "created_at": team.created_at,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Team not found"})),
        )
            .into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

#[derive(Deserialize)]
pub struct SetTeamSettingsRequest {
    /// "gated" | "autonomous" — the team-wide default approval posture.
    pub default_approval_mode: String,
}

/// PUT /team/settings — set the team's default approval posture. Workspace
/// managers only (owner/admin). Governs credentials with no explicit policy;
/// per-credential policies still override it, and it never touches existing
/// policy rows.
pub async fn handle_set_team_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetTeamSettingsRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage team settings") {
        return resp;
    }
    let mode = match req.default_approval_mode.as_str() {
        "autonomous" => tap_core::config::ApprovalMode::Autonomous,
        "gated" => tap_core::config::ApprovalMode::Gated,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("invalid default_approval_mode: {other}"),
                    "error_code": "invalid_approval_mode",
                })),
            )
                .into_response();
        }
    };
    match state
        .db_state
        .store()
        .set_team_default_approval_mode(&admin.team_id, mode)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "default_approval_mode": mode.as_str() })),
        )
            .into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Notification channel management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateNotificationChannelRequest {
    pub channel_type: String,
    pub name: String,
    pub config: serde_json::Value,
}

/// POST /admin/notification-channels — create a notification channel.
pub async fn handle_create_notification_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut req): Json<CreateNotificationChannelRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage notification channels") {
        return resp;
    }

    // Validate channel type
    let channel_type = req.channel_type.trim().to_lowercase();
    const SUPPORTED: &[&str] = &["telegram", "matrix", "dashboard", "agent_reflected"];
    if !SUPPORTED.contains(&channel_type.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Unsupported channel type '{}'. Supported: {}", channel_type, SUPPORTED.join(", "))})),
        )
            .into_response();
    }

    // Validate name
    let name = req.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Channel name must be 1-64 characters"})),
        )
            .into_response();
    }

    // dashboard and agent_reflected require no external config
    if channel_type == "dashboard" || channel_type == "agent_reflected" {
        let config_json = "{}".to_string();
        return match state
            .db_state
            .store()
            .create_notification_channel(&admin.team_id, &channel_type, &name, &config_json)
            .await
        {
            Ok(id) => (
                StatusCode::CREATED,
                Json(
                    json!({"id": id, "name": name, "channel_type": channel_type, "created": true}),
                ),
            )
                .into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Failed to create notification channel: {e}")})),
            )
                .into_response(),
        };
    }

    // Validate config shape per channel type
    if channel_type == "telegram" {
        let chat_id = req.config.get("chat_id").and_then(|v| v.as_str());
        if chat_id.is_none() || chat_id.unwrap().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Telegram config requires a non-empty 'chat_id' field"})),
            )
                .into_response();
        }
    } else if channel_type == "matrix" {
        // Matrix uses a single global bot: access_token is loaded via
        // key_provider::load_secret (env-bootstrapped, then KMS-encrypted
        // in the `config` table), mirroring the Telegram bot_token pattern.
        // Per-team channel rows only carry the public routing fields.

        if req.config.get("access_token").is_some() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Matrix 'access_token' is a global secret — do not send it in the channel config"})),
            )
                .into_response();
        }

        // homeserver_url is optional: if omitted, default to the global bot's homeserver.
        let effective_homeserver = req
            .config
            .get("homeserver_url")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                state
                    .matrix_channel_raw
                    .as_ref()
                    .map(|ch| ch.homeserver_url().to_string())
            });
        match &effective_homeserver {
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Matrix bot is not configured on this server"})),
                )
                    .into_response();
            }
            Some(h) if !h.starts_with("http://") && !h.starts_with("https://") => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "homeserver_url must start with http:// or https://"})),
                )
                    .into_response();
            }
            _ => {}
        }

        let room_id = req.config.get("room_id").and_then(|v| v.as_str());
        if !room_id.map(|r| r.starts_with('!')).unwrap_or(false) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Matrix config requires 'room_id' starting with '!'"})),
            )
                .into_response();
        }

        // Persist the resolved homeserver so the row is self-contained.
        if let Some(obj) = req.config.as_object_mut() {
            obj.insert(
                "homeserver_url".to_string(),
                serde_json::Value::String(effective_homeserver.unwrap()),
            );
        }
    }

    let config_json = serde_json::to_string(&req.config).unwrap_or_default();

    match state
        .db_state
        .store()
        .create_notification_channel(&admin.team_id, &channel_type, &name, &config_json)
        .await
    {
        Ok(id) => (
            StatusCode::CREATED,
            Json(json!({"id": id, "name": name, "channel_type": channel_type, "created": true})),
        )
            .into_response(),
        Err(e) => {
            let msg = format!("Failed to create notification channel: {e}");
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
    }
}

/// GET /admin/notification-channels — list team's notification channels.
pub async fn handle_list_notification_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage notification channels") {
        return resp;
    }

    match state
        .db_state
        .store()
        .list_notification_channels(&admin.team_id)
        .await
    {
        Ok(channels) => {
            let list: Vec<serde_json::Value> = channels
                .iter()
                .enumerate()
                .map(|(idx, c)| {
                    let is_default = c.enabled
                        && channels
                            .iter()
                            .position(|candidate| candidate.enabled)
                            == Some(idx);
                    json!({
                        "id": c.id,
                        "channel_type": c.channel_type,
                        "name": c.name,
                        "config": serde_json::from_str::<serde_json::Value>(&c.config_json).unwrap_or_default(),
                        "enabled": c.enabled,
                        "is_default": is_default,
                        "created_at": c.created_at,
                    })
                })
                .collect();
            Json(json!({"notification_channels": list})).into_response()
        }
        Err(e) => {
            warn!("List notification channels error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list notification channels"})),
            )
                .into_response()
        }
    }
}

/// POST /admin/notification-channels/:name/default
pub async fn handle_set_default_notification_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage notification channels") {
        return resp;
    }

    match state
        .db_state
        .store()
        .set_default_notification_channel(&admin.team_id, &name)
        .await
    {
        Ok(()) => Json(json!({"updated": true, "default": name})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// DELETE /admin/notification-channels/:name
pub async fn handle_delete_notification_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage notification channels") {
        return resp;
    }
    match state
        .db_state
        .store()
        .delete_notification_channel(&admin.team_id, &name)
        .await
    {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

// ---------------------------------------------------------------------------
// Matrix bot info
// ---------------------------------------------------------------------------

/// GET /admin/matrix/bot — return the TAP Matrix bot user ID and homeserver URL.
/// The dashboard uses this to tell teams which bot to invite rather than asking
/// them to enter the bot's homeserver themselves.
pub async fn handle_matrix_bot_info(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage notification channels") {
        return resp;
    }
    match &state.matrix_channel_raw {
        None => Json(json!({ "configured": false })).into_response(),
        Some(ch) => {
            let homeserver_url = ch.homeserver_url().to_string();
            let user_id = ch.fetch_user_id().await;
            Json(json!({
                "configured": true,
                "homeserver_url": homeserver_url,
                "user_id": user_id,
            }))
            .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Telegram session string generation (dashboard wizard)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TgSessionRequestCodeReq {
    pub api_id: String,
    pub api_hash: String,
    pub phone: String,
}

#[derive(Deserialize)]
pub struct TgSessionConfirmCodeReq {
    pub api_id: String,
    pub api_hash: String,
    pub phone: String,
    pub phone_code_hash: String,
    pub code: String,
    pub password: Option<String>,
    pub session_string: Option<String>,
}

/// Spawn `telegram_session.py <cmd>` with JSON on stdin, return its stdout as JSON.
async fn run_telegram_session_script(cmd: &str, args: serde_json::Value) -> Response {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    let python =
        std::env::var("TAP_EMBEDDED_TELEGRAM_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let script = std::env::var("TAP_TELEGRAM_SESSION_SCRIPT")
        .unwrap_or_else(|_| "/opt/tap/telegram_session.py".to_string());

    let mut child = match Command::new(&python)
        .arg(&script)
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, script = %script, "Failed to spawn telegram_session.py");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to start session helper: {e}")})),
            )
                .into_response();
        }
    };

    let input = serde_json::to_string(&args).unwrap_or_default();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes()).await;
    }

    match child.wait_with_output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                Ok(result) => Json(result).into_response(),
                Err(_) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!(stdout = %stdout, stderr = %stderr, "Unexpected telegram_session.py output");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Unexpected output from session helper"})),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Session helper failed: {e}")})),
        )
            .into_response(),
    }
}

/// POST /admin/telegram/session/request-code
/// Body: {api_id, api_hash, phone}
/// Returns: {phone_code_hash} or {error}
pub async fn handle_telegram_session_request_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TgSessionRequestCodeReq>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "create credentials") {
        return resp;
    }
    run_telegram_session_script(
        "request-code",
        json!({ "api_id": req.api_id, "api_hash": req.api_hash, "phone": req.phone }),
    )
    .await
}

/// POST /admin/telegram/session/confirm-code
/// Body: {api_id, api_hash, phone, phone_code_hash, code, password?}
/// Returns: {session_string} or {error: "2fa_required"} or {error: "..."}
pub async fn handle_telegram_session_confirm_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TgSessionConfirmCodeReq>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "create credentials") {
        return resp;
    }
    run_telegram_session_script(
        "confirm-code",
        json!({
            "api_id": req.api_id,
            "api_hash": req.api_hash,
            "phone": req.phone,
            "phone_code_hash": req.phone_code_hash,
            "code": req.code,
            "password": req.password,
            "session_string": req.session_string,
        }),
    )
    .await
}

// ---------------------------------------------------------------------------
// Notification channel test
// ---------------------------------------------------------------------------

/// POST /admin/notification-channels/:name/test — send a test message to verify the channel works.
pub async fn handle_test_notification_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "manage notification channels") {
        return resp;
    }

    let channels = match state
        .db_state
        .store()
        .list_notification_channels(&admin.team_id)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to list channels: {e}")})),
            )
                .into_response()
        }
    };

    let channel = match channels.iter().find(|c| c.name == name) {
        Some(c) => c,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Channel not found"})),
            )
                .into_response()
        }
    };

    let config: serde_json::Value = serde_json::from_str(&channel.config_json).unwrap_or_default();

    match channel.channel_type.as_str() {
        "telegram" => {
            let bot_token = match crate::key_provider::load_secret(
                "TELEGRAM_BOT_TOKEN",
                "telegram_bot_token_ciphertext",
            )
            .await
            {
                Ok(token) if !token.is_empty() => token,
                Ok(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "TELEGRAM_BOT_TOKEN is empty"})),
                    )
                        .into_response()
                }
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": format!("Telegram bot token not configured: {e}")})),
                    )
                        .into_response()
                }
            };
            let chat_id = match config.get("chat_id").and_then(|v| v.as_str()) {
                Some(c) => c.to_string(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "Channel config is missing chat_id"})),
                    )
                        .into_response()
                }
            };

            let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
            let client = match tap_core::http_client::build_client(
                tap_core::http_client::ClientRoute::Direct,
            ) {
                Ok(c) => c,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("HTTP client error: {e}")})),
                    )
                        .into_response()
                }
            };

            match client
                .post(&url)
                .json(&json!({
                    "chat_id": chat_id,
                    "text": "\u{2705} TAP approval channel connected. This chat will receive approval requests when your agents make write operations.",
                }))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => Json(json!({"ok": true})).into_response(),
                Ok(r) => {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"error": format!("Telegram API error ({status}): {body}")})),
                    )
                        .into_response()
                }
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": format!("Failed to reach Telegram: {e}")})),
                )
                    .into_response(),
            }
        }
        "matrix" => {
            let homeserver_url = match &state.matrix_channel_raw {
                Some(ch) => ch.homeserver_url().to_string(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "Matrix is not configured on this server"})),
                    )
                        .into_response()
                }
            };
            let access_token =
                match crate::key_provider::load_secret(
                    "MATRIX_ACCESS_TOKEN",
                    "matrix_access_token_ciphertext",
                )
                .await
                {
                    Ok(token) if !token.is_empty() => token,
                    Ok(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "MATRIX_ACCESS_TOKEN is empty"})),
                        )
                            .into_response()
                    }
                    Err(e) => return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": format!("Matrix access token not configured: {e}")})),
                    )
                        .into_response(),
                };
            let room_id = match config.get("room_id").and_then(|v| v.as_str()) {
                Some(r) => r.to_string(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "Channel config is missing room_id"})),
                    )
                        .into_response()
                }
            };

            let txn_id = uuid::Uuid::new_v4();
            let encoded_room: String = room_id
                .bytes()
                .flat_map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        vec![b as char]
                    }
                    b => vec![
                        '%',
                        char::from_digit((b >> 4) as u32, 16)
                            .unwrap()
                            .to_ascii_uppercase(),
                        char::from_digit((b & 0xf) as u32, 16)
                            .unwrap()
                            .to_ascii_uppercase(),
                    ],
                })
                .collect();
            let url = format!(
                "{homeserver_url}/_matrix/client/v3/rooms/{encoded_room}/send/m.room.message/{txn_id}"
            );

            let client = match tap_core::http_client::build_client(
                tap_core::http_client::ClientRoute::Direct,
            ) {
                Ok(c) => c,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("HTTP client error: {e}")})),
                    )
                        .into_response()
                }
            };

            match client
                .put(&url)
                .bearer_auth(&access_token)
                .json(&json!({
                    "msgtype": "m.text",
                    "body": "\u{2705} TAP approval channel connected. This room will receive approval requests when your agents make write operations.",
                }))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => Json(json!({"ok": true})).into_response(),
                Ok(r) => {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"error": format!("Matrix API error ({status}): {body}")})),
                    )
                        .into_response()
                }
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": format!("Failed to reach Matrix: {e}")})),
                )
                    .into_response(),
            }
        }
        "dashboard" | "agent_reflected" => {
            // No external service to ping — these channels are self-contained.
            Json(json!({"ok": true, "note": "No external service to test; channel is self-contained"})).into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Unsupported channel type for test"})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Tier limits
// ---------------------------------------------------------------------------

/// Tier limits for managed hosting.
pub struct TierLimits {
    pub max_agents: Option<usize>, // None = unlimited
    pub max_credentials: Option<usize>,
    pub max_requests_per_month: Option<u64>,
}

pub fn get_tier_limits(tier: &str) -> TierLimits {
    match tier {
        "starter" => TierLimits {
            max_agents: Some(2),
            max_credentials: Some(5),
            max_requests_per_month: Some(5_000),
        },
        "pro" => TierLimits {
            max_agents: None,
            max_credentials: None,
            max_requests_per_month: Some(50_000),
        },
        "enterprise" => TierLimits {
            max_agents: None,
            max_credentials: None,
            max_requests_per_month: None,
        },
        _ => TierLimits {
            // "free" and self-hosted — no limits enforced by proxy
            max_agents: None,
            max_credentials: None,
            max_requests_per_month: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Stripe billing
// ---------------------------------------------------------------------------

/// POST /billing/create-checkout-session — create a Stripe Checkout session for the authenticated admin.
/// Body: { "tier": "starter" | "pro" }
/// Returns: { "checkout_url": "https://checkout.stripe.com/..." }
pub async fn handle_create_checkout_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCheckoutRequest>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(resp) = require_workspace_manager(&admin, "manage billing") {
        return resp;
    }

    let stripe_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Billing not configured"})),
            )
                .into_response()
        }
    };

    // Map tier to Stripe price ID
    let price_id = match req.tier.as_str() {
        "starter" => match std::env::var("STRIPE_PRICE_STARTER") {
            Ok(p) => p,
            _ => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "Starter price not configured"})),
                )
                    .into_response()
            }
        },
        "pro" => match std::env::var("STRIPE_PRICE_PRO") {
            Ok(p) => p,
            _ => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "Pro price not configured"})),
                )
                    .into_response()
            }
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid tier. Use 'starter' or 'pro'"})),
            )
                .into_response()
        }
    };

    // Check if team already has a Stripe customer
    let team = match state.db_state.store().get_team(&admin.team_id).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Team not found"})),
            )
                .into_response()
        }
    };

    // Create or reuse Stripe customer
    let customer_id = if let Some(cid) = team.stripe_customer_id {
        cid
    } else {
        // Create Stripe customer via API
        let client = match tap_core::http_client::build_client(
            tap_core::http_client::ClientRoute::EgressProxy,
        ) {
            Ok(client) => client,
            Err(e) => {
                warn!("Failed to create Stripe HTTP client: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Stripe API error"})),
                )
                    .into_response();
            }
        };
        let resp = client
            .post("https://api.stripe.com/v1/customers")
            .header("Authorization", format!("Bearer {stripe_key}"))
            .form(&[
                ("email", admin.email.as_str()),
                ("metadata[team_id]", admin.team_id.as_str()),
                ("metadata[team_name]", team.name.as_str()),
            ])
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                let cid = body["id"].as_str().unwrap_or("").to_string();
                if cid.is_empty() {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Failed to create Stripe customer"})),
                    )
                        .into_response();
                }
                // Save customer ID
                let _ = state
                    .db_state
                    .store()
                    .set_stripe_customer_id(&admin.team_id, &cid)
                    .await;
                cid
            }
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Stripe API error"})),
                )
                    .into_response()
            }
        }
    };

    // Determine success/cancel URLs
    let base_url =
        std::env::var("TAP_BASE_URL").unwrap_or_else(|_| "https://app.tap.human.tech".to_string());
    let success_url = format!("{base_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}");
    let cancel_url = format!("{base_url}/billing/cancel");

    // Create Checkout Session via Stripe API
    let client = match tap_core::http_client::build_client(
        tap_core::http_client::ClientRoute::EgressProxy,
    ) {
        Ok(client) => client,
        Err(e) => {
            warn!("Failed to create Stripe HTTP client: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Stripe API error"})),
            )
                .into_response();
        }
    };
    let resp = client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .header("Authorization", format!("Bearer {stripe_key}"))
        .form(&[
            ("customer", customer_id.as_str()),
            ("mode", "subscription"),
            ("line_items[0][price]", price_id.as_str()),
            ("line_items[0][quantity]", "1"),
            ("success_url", success_url.as_str()),
            ("cancel_url", cancel_url.as_str()),
            ("metadata[team_id]", admin.team_id.as_str()),
            ("metadata[tier]", req.tier.as_str()),
        ])
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let checkout_url = body["url"].as_str().unwrap_or("").to_string();
            Json(json!({"checkout_url": checkout_url})).into_response()
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            warn!("Stripe checkout error: {status} {body}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create checkout session"})),
            )
                .into_response()
        }
        Err(e) => {
            warn!("Stripe request error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Stripe API error"})),
            )
                .into_response()
        }
    }
}

/// POST /stripe/webhook — handle Stripe webhook events.
/// Verifies the webhook signature, then processes the event.
pub async fn handle_stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let webhook_secret = match std::env::var("STRIPE_WEBHOOK_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            warn!("STRIPE_WEBHOOK_SECRET not set, rejecting webhook");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    // Verify Stripe signature
    let sig_header = match headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing Stripe-Signature"})),
            )
                .into_response();
        }
    };

    let payload = match std::str::from_utf8(&body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Verify HMAC-SHA256 signature
    if !verify_stripe_signature(payload, &sig_header, &webhook_secret) {
        warn!("Stripe webhook signature verification failed");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Parse event
    let event: serde_json::Value = match serde_json::from_str(payload) {
        Ok(e) => e,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let event_type = event["type"].as_str().unwrap_or("");
    tracing::info!(event_type = %event_type, "Stripe webhook received");

    match event_type {
        "checkout.session.completed" => {
            let session = &event["data"]["object"];
            let team_id = session["metadata"]["team_id"].as_str().unwrap_or("");
            let tier = session["metadata"]["tier"].as_str().unwrap_or("");

            if !team_id.is_empty() && !tier.is_empty() {
                match state.db_state.store().update_team_tier(team_id, tier).await {
                    Ok(()) => {
                        tracing::info!(team_id = %team_id, tier = %tier, "Team tier upgraded via Stripe")
                    }
                    Err(e) => warn!(team_id = %team_id, "Failed to upgrade tier: {e}"),
                }
            }
        }
        "customer.subscription.deleted" | "customer.subscription.paused" => {
            // Downgrade to free
            let customer_id = event["data"]["object"]["customer"].as_str().unwrap_or("");
            if !customer_id.is_empty() {
                match state
                    .db_state
                    .store()
                    .get_team_by_stripe_customer(customer_id)
                    .await
                {
                    Ok(Some(team)) => {
                        let _ = state
                            .db_state
                            .store()
                            .update_team_tier(&team.id, "free")
                            .await;
                        tracing::info!(team_id = %team.id, "Team downgraded to free (subscription ended)");
                    }
                    _ => warn!(customer_id = %customer_id, "No team found for Stripe customer"),
                }
            }
        }
        "customer.subscription.updated" => {
            // Handle plan changes (upgrade/downgrade between starter and pro)
            let subscription = &event["data"]["object"];
            let customer_id = subscription["customer"].as_str().unwrap_or("");
            let status = subscription["status"].as_str().unwrap_or("");

            if status == "active" && !customer_id.is_empty() {
                // Get the price ID to determine tier
                let price_id = subscription["items"]["data"][0]["price"]["id"]
                    .as_str()
                    .unwrap_or("");
                let starter_price = std::env::var("STRIPE_PRICE_STARTER").unwrap_or_default();
                let pro_price = std::env::var("STRIPE_PRICE_PRO").unwrap_or_default();

                let new_tier = if price_id == starter_price {
                    "starter"
                } else if price_id == pro_price {
                    "pro"
                } else {
                    "" // unknown price
                };

                if !new_tier.is_empty() {
                    if let Ok(Some(team)) = state
                        .db_state
                        .store()
                        .get_team_by_stripe_customer(customer_id)
                        .await
                    {
                        let _ = state
                            .db_state
                            .store()
                            .update_team_tier(&team.id, new_tier)
                            .await;
                        tracing::info!(team_id = %team.id, tier = %new_tier, "Team tier changed");
                    }
                }
            }
        }
        _ => {
            // Ignore other events
        }
    }

    StatusCode::OK.into_response()
}

/// Verify Stripe webhook signature (HMAC-SHA256).
/// Note: the comparison uses `==` on lowercase hex strings, which is acceptable
/// since both sides are produced by the same hex encoding and the values are
/// not secret (they are MACs, not passwords).
fn verify_stripe_signature(payload: &str, sig_header: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};

    // Parse the signature header: t=timestamp,v1=signature
    let mut timestamp = "";
    let mut signature = "";
    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = t;
        } else if let Some(s) = part.strip_prefix("v1=") {
            signature = s;
        }
    }

    if timestamp.is_empty() || signature.is_empty() {
        return false;
    }

    // Build signed payload: timestamp.payload
    let signed_payload = format!("{timestamp}.{payload}");

    // Compute HMAC-SHA256
    type HmacSha256 = Hmac<sha2::Sha256>;
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Comparison on hex strings — see note on function doc
    expected == signature
}

/// POST /billing/portal — create a Stripe Billing Portal session for managing subscription.
pub async fn handle_billing_portal(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(resp) = require_workspace_manager(&admin, "manage billing") {
        return resp;
    }

    let stripe_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Billing not configured"})),
            )
                .into_response()
        }
    };

    let team = match state.db_state.store().get_team(&admin.team_id).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Team not found"})),
            )
                .into_response()
        }
    };

    let customer_id = match team.stripe_customer_id {
        Some(cid) => cid,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "No subscription found. Choose a plan first."})),
            )
                .into_response()
        }
    };

    let base_url =
        std::env::var("TAP_BASE_URL").unwrap_or_else(|_| "https://app.tap.human.tech".to_string());
    let return_url = format!("{base_url}/dashboard");

    let client = match tap_core::http_client::build_client(
        tap_core::http_client::ClientRoute::EgressProxy,
    ) {
        Ok(client) => client,
        Err(e) => {
            warn!("Failed to create Stripe HTTP client: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create billing portal session"})),
            )
                .into_response();
        }
    };
    let resp = client
        .post("https://api.stripe.com/v1/billing_portal/sessions")
        .header("Authorization", format!("Bearer {stripe_key}"))
        .form(&[
            ("customer", customer_id.as_str()),
            ("return_url", return_url.as_str()),
        ])
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let portal_url = body["url"].as_str().unwrap_or("").to_string();
            Json(json!({"portal_url": portal_url})).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create billing portal session"})),
        )
            .into_response(),
    }
}

/// GET /billing/status — show current billing status.
pub async fn handle_get_billing(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let team = match state.db_state.store().get_team(&admin.team_id).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Team not found"})),
            )
                .into_response()
        }
    };

    Json(json!({
        "tier": team.tier,
        "has_stripe_customer": team.stripe_customer_id.is_some(),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Admin Passkey (WebAuthn 2FA)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetupPasskeyBeginRequest {
    pub passkey_setup_token: String,
}

#[derive(Deserialize)]
pub struct SetupPasskeyFinishRequest {
    pub passkey_setup_token: String,
    pub credential: webauthn_rs_proto::RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub struct LoginPasskeyRequest {
    pub passkey_token: String,
    pub team_id: Option<String>,
    /// Opaque, signed OAuth request from `tap-mcp`. When present, the passkey
    /// that completes login also authorizes the MCP connection, avoiding a
    /// redundant second passkey prompt.
    pub mcp_request: Option<String>,
    pub credential: webauthn_rs_proto::PublicKeyCredential,
}

/// POST /setup-passkey/begin — start passkey registration during signup.
/// Requires a passkey_setup_token (issued after email verification).
pub async fn handle_setup_passkey_begin(
    State(state): State<AppState>,
    Json(req): Json<SetupPasskeyBeginRequest>,
) -> Response {
    let token_hash = hash_session_token(&req.passkey_setup_token);
    let store = state.db_state.store();

    // Validate setup token (stored as a short-lived session)
    let admin = match store.validate_session(&token_hash).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired setup token"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Setup token validation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Validation failed"})),
            )
                .into_response();
        }
    };

    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    match wa.begin_user_registration(&admin.id, &admin.email).await {
        Ok(ccr) => Json(json!({
            "challenge": ccr,
            "admin_id": admin.id,
        }))
        .into_response(),
        Err(e) => {
            warn!("Passkey setup begin error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to start passkey setup"})),
            )
                .into_response()
        }
    }
}

/// POST /setup-passkey/finish — complete passkey registration during signup.
pub async fn handle_setup_passkey_finish(
    State(state): State<AppState>,
    Json(req): Json<SetupPasskeyFinishRequest>,
) -> Response {
    let token_hash = hash_session_token(&req.passkey_setup_token);
    let store = state.db_state.store();

    let admin = match store.validate_session(&token_hash).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired setup token"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Setup token validation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Validation failed"})),
            )
                .into_response();
        }
    };

    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    match wa
        .finish_user_registration(&admin.id, &req.credential)
        .await
    {
        Ok(_passkey) => {
            info!(admin_id = %admin.id, "Admin passkey registered during setup");
            // Invalidate the setup token
            let _ = store.delete_session(&token_hash).await;
            Json(json!({"status": "registered"})).into_response()
        }
        Err(e) => {
            warn!("Passkey setup finish error: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Passkey registration failed: {e}")})),
            )
                .into_response()
        }
    }
}

/// POST /login/passkey — complete login with WebAuthn assertion.
pub async fn handle_login_passkey(
    State(state): State<AppState>,
    Json(req): Json<LoginPasskeyRequest>,
) -> Response {
    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    let admin_id = match wa
        .finish_user_login(&req.passkey_token, &req.credential)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!("Passkey login error: {e}");
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Security key verification failed"})),
            )
                .into_response();
        }
    };

    let store = state.db_state.store();

    // Verify the user still exists and is active.
    let admin = match store.get_user(&admin_id).await {
        Ok(Some(a)) if a.email_verified => a,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Account not found or inactive"})),
            )
                .into_response();
        }
    };

    // Resolve the active team (oldest membership unless the password step
    // supplied a verified team from a just-accepted invite) + the full teams list.
    let (mut active_team_id, mut active_team_name, mut active_team_role, teams_json) =
        match resolve_active_team(store, &admin.id).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "Your account is not a member of any team"})),
                )
                    .into_response();
            }
            Err(e) => {
                warn!("Passkey login team resolution error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Login failed"})),
                )
                    .into_response();
            }
        };
    if let Some(requested_team_id) = req.team_id.as_deref() {
        if let Ok(Some(member)) = store.get_member(&admin.id, requested_team_id).await {
            if let Ok(Some(team)) = store.get_team(requested_team_id).await {
                active_team_id = requested_team_id.to_string();
                active_team_name = team.name;
                active_team_role = member.member_role;
            }
        }
    }

    // Create session token
    let token = generate_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

    if let Err(e) = store
        .create_session(&token_hash, &admin.id, &active_team_id, &expires_at)
        .await
    {
        warn!("Session creation error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create session"})),
        )
            .into_response();
    }

    info!(admin_id = %admin.id, "Admin login completed with passkey");

    // Issued before any identity link is made permanent: a failure here aborts
    // the login (the session is deleted below), so the staged link must not
    // survive an aborted login.
    let mcp_authorization = match req.mcp_request.as_deref() {
        Some(request) => {
            let agent_id =
                match crate::mcp_auth::ensure_mcp_agent(store, &active_team_id, &admin.id).await {
                    Ok(agent_id) => agent_id,
                    Err(provision_error) => {
                        warn!(%provision_error, "Passkey login succeeded but MCP agent could not be provisioned");
                        if let Err(delete_error) = store.delete_session(&token_hash).await {
                            warn!(%delete_error, "Failed to clean up session after MCP provisioning error");
                        }
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({"error": "Could not provision the MCP connection"})),
                        )
                            .into_response();
                    }
                };
            match crate::mcp_auth::issue_authorization_assertion(
                request,
                &admin.id,
                &active_team_id,
                &agent_id,
            ) {
                Ok(authorization) => Some(authorization),
            Err(crate::mcp_auth::McpAuthError::InvalidRequest) => {
                if let Err(delete_error) = store.delete_session(&token_hash).await {
                    warn!(%delete_error, "Failed to clean up session after invalid MCP request");
                }
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Invalid MCP authorization request"})),
                )
                    .into_response();
            }
            Err(error) => {
                warn!(%error, "Passkey login succeeded but MCP authorization could not be issued");
                if let Err(delete_error) = store.delete_session(&token_hash).await {
                    warn!(%delete_error, "Failed to clean up session after MCP authorization error");
                }
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error": "TAP MCP authorization is not configured"})),
                    )
                        .into_response();
                }
            }
        }
        None => None,
    };

    // A social-login identity staged for this account becomes permanent only
    // now — the completed passkey login proved account ownership; the verified
    // email match alone never links.
    persist_pending_identity_links(store, &admin.id).await;

    Json(json!({
        "session_token": token,
        "admin_id": admin.id,
        "team_id": active_team_id,
        "team_name": active_team_name,
        "member_role": active_team_role.clone(),
        "capabilities": capabilities_for_role(&active_team_role, active_team_role == ROLE_OWNER),
        "teams": teams_json,
        "expires_at": expires_at,
        "mcp_authorization": mcp_authorization,
    }))
    .into_response()
}

/// Persist any staged social-identity links for a user who just completed a
/// FULL login (passkey step included, or password on a WebAuthn-less
/// deployment). Best-effort: a failure only delays linking to the next login.
pub(crate) async fn persist_pending_identity_links(
    store: &tap_core::store::ConfigStore,
    user_id: &str,
) {
    match store.take_pending_identity_links(user_id).await {
        Ok(links) => {
            for (provider, provider_sub, email) in links {
                match store
                    .link_user_identity(user_id, &provider, &provider_sub, &email)
                    .await
                {
                    Ok(true) => {
                        info!(%user_id, %provider, "Linked social identity after full login")
                    }
                    Ok(false) => warn!(
                        %user_id, %provider,
                        "Staged identity already linked to a different account; dropping staged link"
                    ),
                    Err(e) => warn!("Failed to persist identity link: {e}"),
                }
            }
        }
        Err(e) => warn!("Failed to consume pending identity links: {e}"),
    }
}

/// POST /admin/passkey/register/begin — add an additional passkey (authenticated).
pub async fn handle_admin_passkey_register_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);

    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    match wa.begin_user_registration(&admin.id, &admin.email).await {
        Ok(ccr) => Json(json!({"challenge": ccr})).into_response(),
        Err(e) => {
            warn!("Admin passkey reg begin error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to start registration"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct AdminPasskeyRegisterFinish {
    pub credential: webauthn_rs_proto::RegisterPublicKeyCredential,
}

/// POST /admin/passkey/register/finish — complete additional passkey registration.
pub async fn handle_admin_passkey_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminPasskeyRegisterFinish>,
) -> Response {
    let admin = require_admin!(state, headers);

    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    match wa
        .finish_user_registration(&admin.id, &req.credential)
        .await
    {
        Ok(_passkey) => {
            info!(admin_id = %admin.id, "Additional admin passkey registered");
            Json(json!({"status": "registered"})).into_response()
        }
        Err(e) => {
            warn!("Admin passkey reg finish error: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Registration failed: {e}")})),
            )
                .into_response()
        }
    }
}

/// GET /admin/passkeys — list admin's registered passkeys.
pub async fn handle_list_admin_passkeys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);

    match state.db_state.store().list_user_passkeys(&admin.id).await {
        Ok(passkeys) => {
            let list: Vec<serde_json::Value> = passkeys
                .iter()
                .map(|p| {
                    json!({
                        "credential_id": p.credential_id,
                        "created_at": p.created_at,
                    })
                })
                .collect();
            Json(json!({"passkeys": list})).into_response()
        }
        Err(e) => {
            warn!("List admin passkeys error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list passkeys"})),
            )
                .into_response()
        }
    }
}

/// DELETE /admin/passkeys/:credential_id — remove a passkey (must keep at least one).
pub async fn handle_delete_admin_passkey(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(credential_id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    // Check count — must keep at least one
    match store.count_user_passkeys(&admin.id).await {
        Ok(count) if count <= 1 => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "Cannot delete your last security key. You must have at least one."}))).into_response();
        }
        Err(e) => {
            warn!("Count admin passkeys error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to check passkey count"})),
            )
                .into_response();
        }
        _ => {}
    }

    match store.delete_user_passkey(&admin.id, &credential_id).await {
        Ok(true) => {
            // Also remove from in-memory WebAuthn state
            if let Some(ref wa) = state.webauthn_state {
                wa.remove_user_credential(&admin.id, &credential_id).await;
            }
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Passkey not found"})),
        )
            .into_response(),
        Err(e) => {
            warn!("Delete admin passkey error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to delete passkey"})),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Admin identity (profile)
// ---------------------------------------------------------------------------

/// GET /admin/me — return the current admin's profile.
pub async fn handle_get_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    match store.get_user(&admin.id).await {
        Ok(Some(row)) => Json(json!({
            "id": row.id,
            "email": row.email,
            "display_name": row.display_name,
            "matrix_user_id": row.matrix_user_id,
            "telegram_user_id": row.telegram_user_id,
            "team_id": admin.team_id,
            "member_role": admin.member_role,
            "capabilities": user_capabilities(&admin),
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        )
            .into_response(),
        Err(e) => {
            warn!("Get user error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to fetch profile"})),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Device authorization flow (`tap login`) — web auth for the CLI.
//
// The CLI never holds a password or a long-lived key: the human authenticates
// in the browser (existing dashboard login + passkey) and confirms a short
// user_code. The CLI polls with an opaque device_code and receives a freshly
// minted session. The raw device_code / session token are never persisted.
// ---------------------------------------------------------------------------

/// Human-typable code: 8 chars from an unambiguous alphabet (no O/0/I/1).
fn generate_user_code() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

// Abuse caps for the device flow, evaluated over a fixed one-hour window and
// enforced with the same DB-backed atomic counter the agent rate limit uses
// (`store::increment_rate_counter`), so the cap holds across stateless proxy
// instances (Distributed State Rule). All three fail *open* on a counter error
// — the login gate (dashboard auth + passkey), not the rate limit, is the
// security boundary; the caps only blunt enumeration/flooding.
//
// `/device/confirm` is the enumeration vector: the 8-char user_code is ~39.6
// bits, so an authenticated user is capped to a handful of code guesses/hour.
// `/device/token` gets an RFC 8628 `slow_down` bound per device_code, and
// `/device/authorize` is bounded per client IP so the public, unauthenticated
// insert can't flood the table.
const DEVICE_AUTHORIZE_MAX_PER_IP_PER_HOUR: i64 = 60;
const DEVICE_CONFIRM_MAX_PER_USER_PER_HOUR: i64 = 20;
const DEVICE_POLL_MAX_PER_CODE_PER_HOUR: i64 = 300;

/// Start (unix seconds) of the current fixed one-hour rate-limit window. A fixed
/// window makes the DB counter a simple atomic upsert keyed by `(key, window)`
/// that any stateless instance can claim. Mirrors
/// `proxy::current_rate_window_start` (kept local rather than cross-module pub).
fn device_rate_window() -> i64 {
    let now = chrono::Utc::now().timestamp();
    now - now.rem_euclid(3600)
}

/// Best-effort client IP from the reverse-proxy headers. Behind the production
/// TLS load balancer `X-Forwarded-For` is always set by a trusted hop; in
/// local/dev (no proxy) it's absent and the request simply isn't IP-limited.
/// Used ONLY for abuse rate-limiting, never as a security boundary, so a
/// spoofed or missing value can at worst let a caller share/skip a flood
/// bucket — it can never bypass auth.
fn device_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

/// POST /device/authorize — start a device login (no auth). Returns the opaque
/// device_code (the CLI keeps it and polls with it) and the user_code (the
/// human enters it in the dashboard).
pub async fn handle_device_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let store = state.db_state.store();

    // Per-IP flood cap on this unauthenticated, row-inserting endpoint. Only
    // applied when a client IP is derivable (always true behind the prod LB).
    if let Some(ip) = device_client_ip(&headers) {
        let key = format!("dev-authz-ip:{ip}");
        match store.increment_rate_counter(&key, device_rate_window()).await {
            Ok(count) if count > DEVICE_AUTHORIZE_MAX_PER_IP_PER_HOUR => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "error": "slow_down",
                        "error_description": "too many device authorizations from this client; try again later",
                    })),
                )
                    .into_response();
            }
            Ok(_) => {}
            // Fail open: never let a counter blip block legitimate logins.
            Err(e) => warn!("device authorize rate counter: {e}"),
        }
    }

    let device_code = generate_session_token();
    let device_code_hash = hash_session_token(&device_code);
    let user_code = generate_user_code();
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

    if let Err(e) = store
        .create_device_authorization(&device_code_hash, &user_code, &expires_at)
        .await
    {
        warn!("device authorize: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to start device authorization"})),
        )
            .into_response();
    }

    Json(json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_path": "/dashboard#/device",
        "interval": 3,
        "expires_in": 600,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct DeviceConfirmRequest {
    pub user_code: String,
}

/// POST /device/confirm — the logged-in human approves a user_code, binding
/// their identity + active team to the pending device authorization.
pub async fn handle_device_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeviceConfirmRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();
    let code: String = req
        .user_code
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if code.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "enter the code shown in your terminal"})),
        )
            .into_response();
    }
    // Per-user attempt cap: without it, an authenticated user could enumerate
    // pending user_codes and bind (approve) a stranger's device. Every confirm
    // attempt (success or miss) counts against a small hourly budget, so the
    // ~39.6-bit code space stays infeasible to brute-force. Fail open on a
    // counter error — the auth gate is the real boundary.
    let rl_key = format!("dev-confirm:{}", admin.id);
    match store
        .increment_rate_counter(&rl_key, device_rate_window())
        .await
    {
        Ok(count) if count > DEVICE_CONFIRM_MAX_PER_USER_PER_HOUR => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "Too many code attempts. Wait a bit and try again."})),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => warn!("device confirm rate counter: {e}"),
    }
    match store
        .approve_device_authorization(&code, &admin.id, &admin.team_id)
        .await
    {
        Ok(true) => Json(json!({"ok": true})).into_response(),
        Ok(false) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "That code is invalid, expired, or already used."})),
        )
            .into_response(),
        Err(e) => {
            warn!("device confirm: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "failed to confirm device"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct DeviceTokenRequest {
    pub device_code: String,
}

/// POST /device/token — the CLI polls with its device_code. Once the human has
/// confirmed, mint a fresh 30-day session and return it. The session is created
/// here, at claim time, so no raw token is ever stored in the device row.
pub async fn handle_device_token(
    State(state): State<AppState>,
    Json(req): Json<DeviceTokenRequest>,
) -> Response {
    use tap_core::store::DeviceClaim;
    let store = state.db_state.store();
    let device_code_hash = hash_session_token(&req.device_code);
    let poll_key = format!("dev-poll:{device_code_hash}");
    match store.claim_device_authorization(&device_code_hash).await {
        Ok(DeviceClaim::Approved { user_id, team_id }) => {
            let token = generate_session_token();
            let token_hash = hash_session_token(&token);
            let expires_at = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
            // Mint a SCOPED agent session (not a full dashboard session): even if
            // a hostile agent reads this token from the keychain, the router
            // restricts it to a tiny allowlist — it cannot drive the privileged
            // dashboard API.
            if let Err(e) = store
                .create_agent_session(&token_hash, &user_id, &team_id, &expires_at)
                .await
            {
                warn!("device token session: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "failed to mint session"})),
                )
                    .into_response();
            }
            let email = store
                .get_user(&user_id)
                .await
                .ok()
                .flatten()
                .map(|u| u.email)
                .unwrap_or_default();
            Json(json!({
                "session_token": token,
                "email": email,
                "team_id": team_id,
            }))
            .into_response()
        }
        Ok(DeviceClaim::Pending) => {
            // RFC 8628 `slow_down`: bound how fast a single device_code may be
            // polled. Counting only in the Pending branch means garbage/unknown
            // device_codes never create counter rows, so this doesn't open a new
            // flooding vector — and the number of live device flows is already
            // bounded by the per-IP cap on /device/authorize. Fail open.
            match store
                .increment_rate_counter(&poll_key, device_rate_window())
                .await
            {
                Ok(count) if count > DEVICE_POLL_MAX_PER_CODE_PER_HOUR => {
                    return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"status": "slow_down"})))
                        .into_response();
                }
                Ok(_) => {}
                Err(e) => warn!("device token rate counter: {e}"),
            }
            (
                StatusCode::ACCEPTED,
                Json(json!({"status": "authorization_pending"})),
            )
                .into_response()
        }
        Ok(DeviceClaim::Denied) => {
            (StatusCode::FORBIDDEN, Json(json!({"error": "access_denied"}))).into_response()
        }
        Ok(DeviceClaim::ExpiredOrUnknown) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "expired_or_unknown_code"})),
        )
            .into_response(),
        Err(e) => {
            warn!("device token: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "failed to poll device token"})),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Dashboard-free credential setup (`tap cred set`): the CLI sends the secret
// over the login session; it is stored pending + encrypted and becomes a live
// credential only after the creator approves it with a passkey on the dashboard
// (same passkey machinery as proposal-resolve). The agent never sees the secret.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateCredentialSetupRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub connector: Option<String>,
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default)]
    pub auth_header_format: Option<String>,
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Gate every agent action on the resulting credential behind a passkey
    /// approval (opt-in, `tap cred set --require-passkey`). Applied at activation.
    #[serde(default)]
    pub require_passkey: bool,
    /// The secret. A JSON string (single-secret) or a JSON object (multi-secret).
    pub value: serde_json::Value,
}

/// POST /cred/setup — stage a pending credential (secret encrypted at rest).
/// Session + workspace-manager. Returns a `setup_id` the CLI polls and a
/// dashboard path where the creator activates it with a passkey.
pub async fn handle_create_credential_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCredentialSetupRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "add credentials") {
        return resp;
    }
    let store = state.db_state.store();

    // Validate the name against the canonical charset. This is the sole gate
    // rejecting `:` and `/`; without it a caller could stage (and, after the
    // manager's own passkey, write) a credential named `eu:{ext}/{logical}`
    // with `end_user_id = NULL`, colliding with / masquerading as an end-user
    // credential and breaking the `eu:` isolation invariant (restores #126).
    let name = match validate_credential_name(&req.name) {
        Ok(n) => n,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response(),
    };

    // Normalize the secret (string or object), same rule as handle_create_credential.
    let plaintext = match &req.value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(_) => req.value.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "value must be a string (single-secret) or a JSON object (multi-secret)"})),
            )
                .into_response()
        }
    };
    if plaintext.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "the secret value is empty"})),
        )
            .into_response();
    }

    // Validate the host binding up front so a bad list fails before we store
    // anything (and encode it once for storage).
    let allowed_hosts_json = match req.allowed_hosts.as_deref() {
        Some(hosts) => match validate_allowed_hosts(hosts) {
            Ok(cleaned) if !cleaned.is_empty() => match serde_json::to_string(&cleaned) {
                Ok(s) => Some(s),
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "failed to encode allowed hosts"})),
                    )
                        .into_response()
                }
            },
            Ok(_) => None,
            Err(msg) => return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response(),
        },
        None => None,
    };

    // Enforce the tier credential cap early (fail before the round-trip).
    if let Ok(Some(team)) = store.get_team(&admin.team_id).await {
        let limits = get_tier_limits(&team.tier);
        if let Some(max) = limits.max_credentials {
            if let Ok(creds) = store.list_credentials(&admin.team_id).await {
                if creds.len() >= max {
                    return (
                        StatusCode::PAYMENT_REQUIRED,
                        Json(json!({"error": format!("Credential limit reached ({}). Upgrade your plan.", max)})),
                    )
                        .into_response();
                }
            }
        }
    }

    let connector = req.connector.as_deref().unwrap_or("direct").to_string();
    let setup_id = format!("cs-{}", generate_session_token());
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();
    if let Err(e) = store
        .create_credential_setup(
            &setup_id,
            &admin.team_id,
            &admin.id,
            &name,
            &req.description,
            &connector,
            req.api_base.as_deref(),
            req.auth_header_format.as_deref(),
            allowed_hosts_json.as_deref(),
            plaintext.as_bytes(),
            req.require_passkey,
            &expires_at,
        )
        .await
    {
        warn!("credential setup create: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to start credential setup"})),
        )
            .into_response();
    }

    Json(json!({
        "setup_id": setup_id,
        "verification_path": format!("/dashboard#/cred-setup?id={setup_id}"),
        "interval": 3,
        "expires_in": 900,
    }))
    .into_response()
}

/// GET /cred/setup/{id} — status + display metadata (NEVER the secret), for the
/// CLI poll and the dashboard page. Team-scoped (404 if not in the caller's team).
pub async fn handle_get_credential_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(setup_id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();
    match store.get_credential_setup(&setup_id).await {
        Ok(Some(info)) if info.team_id == admin.team_id => {
            let now = chrono::Utc::now().to_rfc3339();
            let expired = info.expires_at.as_str() <= now.as_str();
            let status = if expired && info.status == "pending" {
                "expired".to_string()
            } else {
                info.status
            };
            let hosts: Vec<String> = info
                .allowed_hosts_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            Json(json!({
                "name": info.name,
                "description": info.description,
                "allowed_hosts": hosts,
                "status": status,
            }))
            .into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "setup not found"})),
        )
            .into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// POST /cred/setup/{id}/activate/begin — start the passkey ceremony bound to the
/// setup id. Creator-only, while pending. Returns a WebAuthn challenge.
pub async fn handle_begin_credential_setup_activation(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(setup_id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "activate credentials") {
        return resp;
    }
    let store = state.db_state.store();
    let info = match store.get_credential_setup(&setup_id).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "setup not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    // Only the creator, in their own team, may activate their pending setup.
    if info.team_id != admin.team_id || info.created_by != admin.id {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "setup not found"})),
        )
            .into_response();
    }
    let now = chrono::Utc::now().to_rfc3339();
    if info.status != "pending" || info.expires_at.as_str() <= now.as_str() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "this setup is no longer pending"})),
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
    // Scoped to the acting manager's own passkeys (see above).
    match wa
        .begin_approval_for_user(&setup_id, &admin.id, &admin.email)
        .await
    {
        Ok(rcr) => Json(rcr).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

#[derive(Deserialize)]
pub struct ActivateCredentialSetupRequest {
    /// WebAuthn assertion (required when passkeys are configured).
    #[serde(default)]
    pub assertion: Option<webauthn_rs_proto::PublicKeyCredential>,
    /// Agent keys (ids) to grant this credential to, chosen on the activation
    /// page. Optional — leaving it empty just creates the credential unassigned.
    /// The assignment rides the same passkey approval that activates the setup.
    #[serde(default)]
    pub assign_agents: Vec<String>,
}

/// POST /cred/setup/{id}/activate — verify the creator's passkey (bound to this
/// setup id), atomically claim the pending setup, and write the live credential.
pub async fn handle_activate_credential_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(setup_id): axum::extract::Path<String>,
    Json(req): Json<ActivateCredentialSetupRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    if let Err(resp) = require_workspace_manager(&admin, "activate credentials") {
        return resp;
    }
    let store = state.db_state.store();

    // Creator-only + still-pending guard (gives clean 404/409; the atomic claim
    // below re-checks pending+unexpired as the authoritative single-use gate).
    let info = match store.get_credential_setup(&setup_id).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "setup not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    if info.team_id != admin.team_id || info.created_by != admin.id {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "setup not found"})),
        )
            .into_response();
    }
    let now = chrono::Utc::now().to_rfc3339();
    if info.status != "pending" || info.expires_at.as_str() <= now.as_str() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "this setup is no longer pending"})),
        )
            .into_response();
    }

    // Passkey gate — the assertion is bound to this setup id and must belong to
    // the acting user (identical to the proposal-resolve gate).
    if let Some(wa) = &state.webauthn_state {
        let assertion = match req.assertion {
            Some(a) => a,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "passkey assertion required to activate",
                        "error_code": "passkey_required"
                    })),
                )
                    .into_response()
            }
        };
        match wa
            .finish_approval_for_user(&setup_id, &admin.id, &admin.email, &assertion)
            .await
        {
            Ok(verified_user_id) => {
                // Scoped ceremony: the credential lookup is already restricted to
                // this user's passkeys, and the fn returns the user_id it was
                // scoped to. Re-assert it so a future contract change fails closed.
                if verified_user_id != admin.id {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": "passkey does not belong to the activating user"})),
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
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "passkey not configured on this server"})),
        )
            .into_response();
    }

    // Claim the setup (atomic, single-use) and write the live credential.
    let data = match store.activate_credential_setup(&setup_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "this setup was already activated or expired"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };

    if let Err(e) = store
        .create_credential(
            &data.team_id,
            &data.name,
            &data.description,
            &data.connector,
            data.api_base.as_deref(),
            false,
            data.auth_header_format.as_deref(),
            None,
            Some(data.plaintext_value.as_slice()),
        )
        .await
    {
        let (status, msg) = match &e {
            AgentSecError::AlreadyExists(_) => (
                StatusCode::CONFLICT,
                format!("A credential named '{}' already exists.", data.name),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create credential.".to_string(),
            ),
        };
        return (status, Json(json!({"error": msg}))).into_response();
    }

    // Apply the host allowlist (already validated at setup time).
    if let Some(hosts_json) = data.allowed_hosts_json.as_deref() {
        if let Ok(hosts) = serde_json::from_str::<Vec<String>>(hosts_json) {
            if !hosts.is_empty() {
                if let Err(e) = store
                    .set_credential_allowed_hosts(&data.team_id, &data.name, &hosts)
                    .await
                {
                    return crate::proxy::error_response(e);
                }
            }
        }
    }

    // Passkey policy: gate every action on this credential behind a passkey
    // approval. We set the standard Gated method rules explicitly (safe reads
    // auto-approve, writes require approval) so an empty policy can't fail-closed
    // the reads — plus require_passkey. This lands under the same passkey
    // approval that activated the credential.
    if data.require_passkey {
        let policy = tap_core::store::PolicyRow {
            team_id: data.team_id.clone(),
            credential_name: data.name.clone(),
            auto_approve_methods: vec!["GET".to_string(), "HEAD".to_string()],
            require_approval_methods: vec![
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
            ],
            auto_approve_urls: vec![],
            // No URL-pattern overrides: this policy is method rules + passkey
            // only. `require_approval_urls` is a safety gate that wins over
            // broader auto-approve rules (Decision #13); an empty list here
            // leaves the method rules above as the sole policy.
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: true,
            min_approvals: 1,
        };
        if let Err(e) = store.set_policy(&policy).await {
            return crate::proxy::error_response(e);
        }
        state
            .db_state
            .invalidate_policy_cache(&data.team_id, &data.name)
            .await;
    }

    // Grant the new credential to the agent keys chosen on the activation page,
    // under the same passkey approval. Only assign to agents that actually belong
    // to this team (never trust the ids blindly). Empty = create it unassigned.
    let mut assigned: Vec<String> = Vec::new();
    if !req.assign_agents.is_empty() {
        let team_agent_ids: std::collections::HashSet<String> = store
            .list_agents(&data.team_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.id)
            .collect();
        for agent_id in &req.assign_agents {
            if team_agent_ids.contains(agent_id) {
                match store
                    .add_direct_credential(&data.team_id, agent_id, &data.name)
                    .await
                {
                    Ok(()) => assigned.push(agent_id.clone()),
                    Err(e) => warn!("assign credential to agent {agent_id}: {e}"),
                }
            }
        }
    }

    analytics::capture(
        "tap.credential_created",
        &analytics::agent_distinct_id(&data.team_id),
        json!({"service_name": data.name, "auth_type": data.connector, "via": "cli_setup"}),
    );

    Json(json!({"activated": true, "credential": data.name, "assigned_agents": assigned}))
        .into_response()
}

#[derive(Deserialize)]
pub struct UpdateIdentityRequest {
    pub display_name: Option<String>,
    pub matrix_user_id: Option<String>,
    pub telegram_user_id: Option<String>,
}

/// PUT /admin/me/identity — update own display_name, matrix_user_id, telegram_user_id.
pub async fn handle_update_my_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateIdentityRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    match store
        .update_user_identity(
            &admin.id,
            req.display_name.as_deref(),
            req.matrix_user_id.as_deref(),
            req.telegram_user_id.as_deref(),
        )
        .await
    {
        Ok(()) => Json(json!({"status": "updated"})).into_response(),
        Err(e) => {
            warn!("Update user identity error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to update identity"})),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Team members
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    /// "owner" | "admin" | "approver" — defaults to "approver"
    pub role: Option<String>,
}

#[derive(Deserialize)]
pub struct AcceptInviteRequest {
    pub token: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangeMemberRoleRequest {
    pub role: String,
}

#[derive(Deserialize)]
pub struct AssignMemberCredentialRequest {
    pub credential_name: String,
}

/// GET /admin/team/members — list current members and pending invites.
pub async fn handle_list_team_members(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let store = state.db_state.store();
    let members = match store.list_team_members(&admin.team_id).await {
        Ok(m) => m,
        Err(e) => {
            warn!("list_team_members error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list members"})),
            )
                .into_response();
        }
    };
    let pending = match store.list_pending_invites(&admin.team_id).await {
        Ok(i) => i,
        Err(e) => {
            warn!("list_pending_invites error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list invites"})),
            )
                .into_response();
        }
    };
    Json(json!({
        "members": members.iter().map(|m| json!({
            "id": m.id,
            "email": m.email,
            "member_role": m.member_role,
            "is_owner": m.is_owner(),
            "created_at": m.created_at,
        })).collect::<Vec<_>>(),
        "pending_invites": pending.iter().map(|i| json!({
            "id": i.id,
            "email": i.email,
            "role": i.role,
            "expires_at": i.expires_at,
            "created_at": i.created_at,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// POST /admin/team/members/invite — invite a new member by email.
pub async fn handle_invite_team_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<InviteMemberRequest>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(resp) = require_workspace_manager(&admin, "invite team members") {
        return resp;
    }

    let email = req.email.trim().to_lowercase();
    if !email.contains('@') || !email.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid email"})),
        )
            .into_response();
    }

    let role = req.role.as_deref().unwrap_or(DEFAULT_INVITE_ROLE);
    if !matches!(role, ROLE_OWNER | ROLE_ADMIN | ROLE_APPROVER) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Role must be 'owner', 'admin', or 'approver'"})),
        )
            .into_response();
    }
    if role == ROLE_OWNER && !admin.is_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners can invite someone as owner"})),
        )
            .into_response();
    }

    let store = state.db_state.store();

    // Reject if already a member of this team (same email may belong to other teams)
    if let Ok(Some(_)) = store
        .get_member_by_email_and_team(&email, &admin.team_id)
        .await
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "This email is already a team member"})),
        )
            .into_response();
    }

    let team = match store.get_team(&admin.team_id).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Team not found"})),
            )
                .into_response()
        }
    };

    let token = generate_session_token();
    let token_hash = hash_session_token(&token);
    let invite_id = uuid::Uuid::new_v4().to_string();
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(48)).to_rfc3339();

    if let Err(e) = store
        .create_invite(
            &invite_id,
            &admin.team_id,
            &email,
            role,
            &token_hash,
            &admin.id,
            &expires_at,
        )
        .await
    {
        warn!("create_invite error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create invite"})),
        )
            .into_response();
    }

    let base_url =
        std::env::var("TAP_BASE_URL").unwrap_or_else(|_| "https://app.tap.human.tech".to_string());
    let accept_url = format!("{base_url}/dashboard?invite_token={token}");

    if let Err(e) =
        crate::email::send_invite_email(&email, &admin.email, &team.name, &accept_url).await
    {
        warn!("send_invite_email error: {e}");
        return Json(json!({
            "message": "Invite created but email delivery failed. Share the accept URL manually.",
            "accept_url": accept_url,
        }))
        .into_response();
    }

    info!("Invite sent to {} by {}", email, admin.email);
    Json(json!({"message": "Invitation sent", "email": email})).into_response()
}

/// GET /signup/invite-check?email= — does this email have pending invites?
///
/// Powers the signup form's "you've been invited to X" banner and the
/// join-only fork, so an invited person isn't silently dropped into a brand-new
/// team. Returns only team name + role (never tokens or ids). No auth required;
/// the existence leak is no worse than signup's existing "email already
/// registered" response and is bounded to email-squatting, which is already
/// possible via the unique-email constraint.
pub async fn handle_signup_invite_check(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let email = match params.get("email") {
        Some(e) => e.trim().to_lowercase(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing email"})),
            )
                .into_response()
        }
    };
    let store = state.db_state.store();

    // Only surface invites for an email with no account yet — once you have an
    // account, invites are picked up automatically on login, so the signup-form
    // banner would be misleading.
    if matches!(store.get_user_by_email(&email).await, Ok(Some(_))) {
        return Json(json!({"invites": []})).into_response();
    }

    let invites = store
        .list_invites_by_email(&email)
        .await
        .unwrap_or_default();
    let mut out = Vec::with_capacity(invites.len());
    for inv in invites {
        let team_name = store
            .get_team(&inv.team_id)
            .await
            .ok()
            .flatten()
            .map(|t| t.name)
            .unwrap_or_default();
        out.push(json!({"team_name": team_name, "role": inv.role}));
    }
    Json(json!({"invites": out})).into_response()
}

async fn resolve_invite_action(
    store: &ConfigStore,
    invite: &AdminInviteRow,
) -> Result<InviteResolution, AgentSecError> {
    let team_name = store
        .get_team(&invite.team_id)
        .await?
        .map(|t| t.name)
        .unwrap_or_default();
    let already_member = store
        .get_member_by_email_and_team(&invite.email, &invite.team_id)
        .await?
        .is_some();
    let has_account = store.get_user_by_email(&invite.email).await?.is_some();
    let action = if already_member {
        INVITE_ACTION_ALREADY_MEMBER
    } else if has_account {
        INVITE_ACTION_LOGIN_TO_ACCEPT
    } else {
        INVITE_ACTION_CREATE_ACCOUNT
    };
    Ok(InviteResolution {
        team_name,
        already_member,
        has_account,
        action,
    })
}

/// GET /invite/info?token= — return invite metadata without consuming it.
/// No session auth required.
pub async fn handle_invite_info(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let token = match params.get("token") {
        Some(t) => t.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing token"})),
            )
                .into_response()
        }
    };

    let token_hash = hash_session_token(&token);
    let store = state.db_state.store();

    let invite = match store.get_invite_by_token_hash(&token_hash).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Invalid or expired invite token"})),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up invite"})),
            )
                .into_response()
        }
    };

    let expires = chrono::DateTime::parse_from_rfc3339(&invite.expires_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
    if chrono::Utc::now() > expires {
        return (
            StatusCode::GONE,
            Json(json!({"error": "Invite has expired"})),
        )
            .into_response();
    }

    let resolution = match resolve_invite_action(store, &invite).await {
        Ok(r) => r,
        Err(e) => {
            warn!("resolve_invite_action error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to resolve invite"})),
            )
                .into_response();
        }
    };

    Json(json!({
        "email": invite.email,
        "team_name": resolution.team_name,
        "role": invite.role,
        "already_member": resolution.already_member,
        "has_account": resolution.has_account,
        "invite_action": resolution.action,
    }))
    .into_response()
}

/// POST /admin/team/members/accept — accept an invite and set a password.
/// No session auth required — uses the invite token.
pub async fn handle_accept_invite(
    State(state): State<AppState>,
    Json(req): Json<AcceptInviteRequest>,
) -> Response {
    if req.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password must be at least 8 characters"})),
        )
            .into_response();
    }

    let token_hash = hash_session_token(&req.token);
    let store = state.db_state.store();

    let invite = match store.get_invite_by_token_hash(&token_hash).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Invalid or expired invite token"})),
            )
                .into_response()
        }
        Err(e) => {
            warn!("get_invite error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up invite"})),
            )
                .into_response();
        }
    };

    let expires = chrono::DateTime::parse_from_rfc3339(&invite.expires_at)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
    if chrono::Utc::now() > expires {
        let _ = store.delete_invite(&invite.id).await;
        return (
            StatusCode::GONE,
            Json(json!({"error": "Invite has expired"})),
        )
            .into_response();
    }

    let resolution = match resolve_invite_action(store, &invite).await {
        Ok(r) => r,
        Err(e) => {
            warn!("resolve_invite_action (accept) error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to resolve invite"})),
            )
                .into_response();
        }
    };
    match resolution.action {
        INVITE_ACTION_CREATE_ACCOUNT => {}
        INVITE_ACTION_ALREADY_MEMBER => {
            let _ = store.delete_invite(&invite.id).await;
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "This email is already a team member",
                    "email": invite.email,
                    "invite_action": resolution.action,
                })),
            )
                .into_response();
        }
        INVITE_ACTION_LOGIN_TO_ACCEPT => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "This email already has an account. Log in to accept the invitation.",
                    "email": invite.email,
                    "existing_account": true,
                    "invite_action": resolution.action,
                })),
            )
                .into_response();
        }
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Unknown invite action"})),
            )
                .into_response();
        }
    }

    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            warn!("hash_password error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to hash password"})),
            )
                .into_response();
        }
    };

    // Create the user identity and add the membership with the invite's role.
    // Existing accounts must log in instead; login consumes pending invites.
    let new_user_id = uuid::Uuid::new_v4().to_string();
    let user_id = match store
        .create_user_with_membership(
            &new_user_id,
            &invite.team_id,
            &invite.email,
            &password_hash,
            &invite.role,
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!("create_user_with_membership (invite) error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create account"})),
            )
                .into_response();
        }
    };

    let _ = store.set_user_email_verified(&user_id).await;
    let _ = store.delete_invite(&invite.id).await;

    info!("Invite accepted by {}", invite.email);
    Json(json!({"message": "Account created. You can now log in.", "email": invite.email}))
        .into_response()
}

/// DELETE /admin/team/members/{id} — remove a team member.
/// Owner cannot be removed. Callers cannot remove themselves.
pub async fn handle_remove_team_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(target_id): axum::extract::Path<String>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(resp) = require_workspace_manager(&admin, "remove team members") {
        return resp;
    }

    if admin.id == target_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Cannot remove yourself"})),
        )
            .into_response();
    }

    let store = state.db_state.store();
    let target = match store.get_member(&target_id, &admin.team_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Member not found"})),
            )
                .into_response()
        }
        Err(e) => {
            warn!("get_member error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up member"})),
            )
                .into_response();
        }
    };

    if target.is_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Cannot remove the team owner"})),
        )
            .into_response();
    }

    if let Err(e) = store.delete_membership(&target_id, &admin.team_id).await {
        warn!("delete_membership error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to remove member"})),
        )
            .into_response();
    }

    info!("Member {} removed by {}", target.email, admin.email);
    Json(json!({"message": "Member removed"})).into_response()
}

/// Challenge id for a member-passkey-reset step-up ceremony.
///
/// Bound to `(team, target member)` so an assertion minted for one reset can't
/// be replayed against a different member, or against the same member id in a
/// different team. The `tap:passkey-reset:` prefix keeps it clear of the
/// `txn_id` namespace used by real `/forward` + `/sign` approval requests
/// (both live in `pending_approvals`).
fn passkey_reset_challenge_id(team_id: &str, target_id: &str) -> String {
    format!("tap:passkey-reset:{team_id}:{target_id}")
}

/// Body for `POST /team/members/{id}/passkeys/reset`.
#[derive(Deserialize, Default)]
pub struct ResetMemberPasskeysRequest {
    /// WebAuthn assertion from the acting workspace manager. Required whenever
    /// WebAuthn is configured on this instance.
    #[serde(default)]
    pub assertion: Option<webauthn_rs_proto::PublicKeyCredential>,
}

/// Everything the reset needs after the *authorization* guards have passed:
/// the acting manager and the (non-owner, not-self) target member.
///
/// Guards run here, BEFORE any WebAuthn challenge is issued or consumed, so a
/// forbidden target never gets a challenge handed out for it.
async fn authorize_member_passkey_reset(
    state: &AppState,
    headers: &HeaderMap,
    target_id: &str,
) -> Result<(AuthUser, tap_core::store::Member), Response> {
    let admin = match authenticate_user(headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return Err(e.into_response()),
    };
    require_workspace_manager(&admin, "reset member passkeys")?;
    if admin.id == target_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Use DELETE /user/passkeys/{id} to manage your own passkeys"})),
        )
            .into_response());
    }

    let store = state.db_state.store();
    let target = match store.get_member(target_id, &admin.team_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Member not found"})),
            )
                .into_response())
        }
        Err(e) => {
            warn!("get_member error: {e}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up member"})),
            )
                .into_response());
        }
    };
    if target.is_owner() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Cannot reset the team owner's passkeys"})),
        )
            .into_response());
    }
    Ok((admin, target))
}

/// POST /team/members/{id}/passkeys/reset/begin — WebAuthn challenge for the
/// step-up that gates the reset below.
///
/// All authorization guards (workspace-manager, not-self, not-the-owner) run
/// first: we never mint a challenge for a target the caller may not reset.
pub async fn handle_reset_member_passkeys_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(target_id): axum::extract::Path<String>,
) -> Response {
    let (admin, _target) =
        match authorize_member_passkey_reset(&state, &headers, &target_id).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let wa = match &state.webauthn_state {
        Some(wa) => wa,
        None => {
            // WebAuthn isn't configured on this instance (local dev, the Rust
            // test harness). The reset endpoint keeps today's session-only
            // behaviour there, so tell the client to skip the ceremony rather
            // than erroring out and making the action unreachable.
            return Json(json!({"passkey_required": false})).into_response();
        }
    };
    match wa
        .begin_approval_for_user(
            &passkey_reset_challenge_id(&admin.team_id, &target_id),
            &admin.id,
            &admin.email,
        )
        .await
    {
        Ok(rcr) => Json(rcr).into_response(),
        Err(e) => crate::proxy::error_response(e),
    }
}

/// POST /admin/team/members/{id}/passkeys/reset — clear all of a teammate's
/// registered passkeys (owner/admin recovery action), gated on a fresh passkey
/// step-up from the acting manager.
///
/// A member locked out by a broken/stale passkey (e.g. registered against a
/// domain the team no longer serves from) can't reach the self-service
/// `DELETE /user/passkeys/{id}` path at all — that requires a session, and a
/// non-functional passkey blocks login before a session ever exists. This
/// endpoint breaks that deadlock: once their passkey count reaches zero,
/// the existing login flow (`handle_login`'s `user_has_passkeys` check)
/// already auto-detects it and issues a `passkey_setup_token`, routing them
/// into fresh enrollment with no other new code needed. Never targets the
/// team owner (mirrors `handle_remove_team_member`) — an owner's own broken
/// passkey isn't a case a workspace manager should be able to act on.
///
/// **This is a 2FA-stripping primitive**: it removes the second factor from
/// another person's account, and the next login on that account enrolls
/// whatever authenticator answers. A stolen dashboard session alone must not be
/// enough. So, exactly like the proposal-resolve path, it requires a WebAuthn
/// assertion bound to *this* reset (`passkey_reset_challenge_id`) whose owner
/// email equals the acting manager's, and it writes an immutable audit row
/// (`target_url = "tap:passkey-reset"`) recording who reset whom, and how many
/// keys went away.
pub async fn handle_reset_member_passkeys_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(target_id): axum::extract::Path<String>,
    body: Option<Json<ResetMemberPasskeysRequest>>,
) -> Response {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    reset_member_passkeys(state, headers, target_id, req.assertion).await
}

/// DELETE /admin/team/members/{id}/passkeys — legacy bodyless alias for the
/// POST above, kept so existing clients keep working. It can't carry an
/// assertion, so on an instance with WebAuthn configured it now fails closed
/// with `passkey_required`; callers should move to the POST route.
pub async fn handle_reset_member_passkeys(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(target_id): axum::extract::Path<String>,
) -> Response {
    reset_member_passkeys(state, headers, target_id, None).await
}

async fn reset_member_passkeys(
    state: AppState,
    headers: HeaderMap,
    target_id: String,
    assertion: Option<webauthn_rs_proto::PublicKeyCredential>,
) -> Response {
    let (admin, target) = match authorize_member_passkey_reset(&state, &headers, &target_id).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Passkey step-up. Enforced whenever WebAuthn is configured on this
    // instance — the same convention as `handle_resolve_proposal`, so a
    // deployment without WebAuthn (local dev, the Rust test harness) keeps
    // today's session-only behaviour rather than becoming unusable.
    if let Some(wa) = &state.webauthn_state {
        let assertion = match assertion {
            Some(a) => a,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "passkey assertion required to reset a member's passkeys",
                        "error_code": "passkey_required"
                    })),
                )
                    .into_response()
            }
        };
        let challenge_id = passkey_reset_challenge_id(&admin.team_id, &target_id);
        match wa
            .finish_approval_for_user(&challenge_id, &admin.id, &admin.email, &assertion)
            .await
        {
            // Fail closed: the assertion must belong to the manager performing
            // the reset, not merely to *someone* with a registered passkey.
            Ok(verified_user_id) => {
                // Scoped ceremony: the credential lookup is already restricted to
                // this user's passkeys, and the fn returns the user_id it was
                // scoped to. Re-assert it so a future contract change fails closed.
                if verified_user_id != admin.id {
                    warn!(
                        "passkey reset for {} rejected: assertion resolved to user {} not to acting manager {} ({})",
                        target.email, verified_user_id, admin.id, admin.email
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": "passkey does not belong to the acting workspace manager"})),
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

    let store = state.db_state.store();
    let passkeys = match store.list_user_passkeys(&target_id).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!("list_user_passkeys error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up passkeys"})),
            )
                .into_response();
        }
    };

    let mut removed = 0u32;
    for pk in &passkeys {
        match store
            .delete_user_passkey(&target_id, &pk.credential_id)
            .await
        {
            Ok(true) => {
                removed += 1;
                if let Some(ref wa) = state.webauthn_state {
                    wa.remove_user_credential(&target_id, &pk.credential_id)
                        .await;
                }
            }
            Ok(false) => {}
            Err(e) => warn!(
                "delete_user_passkey error for {} / {}: {e}",
                target_id, pk.credential_id
            ),
        }
    }

    // Stripping someone else's second factor is a security-relevant admin
    // action, so it lands in the immutable audit log — not just tracing.
    // Mirrors the grant-creation audit row (`tap:grant-create`): sentinel
    // target, the acting manager as both `agent_id` and `approver_identity`,
    // and the non-secret who/what/how-many in `request_body`.
    let reset_summary = json!({
        "target_member_email": target.email,
        "target_member_id": target_id,
        "removed_count": removed,
        "source": "dashboard",
    });
    let entry = tap_core::types::AuditEntry {
        request_id: uuid::Uuid::new_v4(),
        agent_id: admin.id.clone(),
        credential_names: vec![],
        target_url: "tap:passkey-reset".to_string(),
        method: tap_core::types::HttpMethod::Delete,
        approval_status: None,
        upstream_status: None,
        total_latency_ms: 0,
        approval_latency_ms: None,
        upstream_latency_ms: None,
        response_sanitized: false,
        end_user_id: None,
        request_headers: vec![],
        request_body: Some(reset_summary.to_string()),
        request_body_truncated: false,
        policy_reason: Some(format!("passkey_reset:{target_id}")),
        require_passkey: false,
        // The workspace manager who performed the reset.
        approver_identity: Some(admin.email.clone()),
        timestamp: chrono::Utc::now(),
    };
    state.audit_logger.write_entry(&entry);

    info!(
        "Passkeys reset for member {} ({} removed) by {}",
        target.email, removed, admin.email
    );
    Json(json!({"reset": true, "removed_count": removed})).into_response()
}

/// DELETE /admin/team/members/invites/{id} — cancel a pending invite.
pub async fn handle_cancel_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(invite_id): axum::extract::Path<String>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(resp) = require_workspace_manager(&admin, "cancel invites") {
        return resp;
    }

    let store = state.db_state.store();
    let pending = match store.list_pending_invites(&admin.team_id).await {
        Ok(list) => list,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up invite"})),
            )
                .into_response()
        }
    };
    if !pending.iter().any(|i| i.id == invite_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Invite not found"})),
        )
            .into_response();
    }
    let _ = store.delete_invite(&invite_id).await;
    Json(json!({"message": "Invite cancelled"})).into_response()
}

/// PUT /admin/team/members/{id}/role — change a member's role.
/// Only owners can change roles. Cannot change your own role or another owner's role.
pub async fn handle_change_member_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(target_id): axum::extract::Path<String>,
    Json(req): Json<ChangeMemberRoleRequest>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    if !admin.is_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Only owners can change member roles"})),
        )
            .into_response();
    }
    if admin.id == target_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Cannot change your own role"})),
        )
            .into_response();
    }
    if !matches!(req.role.as_str(), ROLE_OWNER | ROLE_ADMIN | ROLE_APPROVER) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Role must be 'owner', 'admin', or 'approver'"})),
        )
            .into_response();
    }

    let store = state.db_state.store();
    let target = match store.get_member(&target_id, &admin.team_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Member not found"})),
            )
                .into_response()
        }
        Err(e) => {
            warn!("get_member error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up member"})),
            )
                .into_response();
        }
    };

    if let Err(e) = store
        .update_member_role(&target_id, &admin.team_id, &req.role)
        .await
    {
        warn!("update_member_role error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to update role"})),
        )
            .into_response();
    }

    info!(
        "Member {} role changed to {} by {}",
        target.email, req.role, admin.email
    );
    Json(json!({"message": "Role updated", "member_id": target_id, "role": req.role}))
        .into_response()
}

/// POST /admin/team/members/{id}/credentials — assign a credential to a member.
/// Owner and admin only.
pub async fn handle_assign_approver_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(target_id): axum::extract::Path<String>,
    Json(req): Json<AssignMemberCredentialRequest>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(resp) = require_workspace_manager(&admin, "assign credentials") {
        return resp;
    }

    let store = state.db_state.store();
    let _target = match store.get_member(&target_id, &admin.team_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Member not found"})),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up member"})),
            )
                .into_response()
        }
    };

    // Verify the credential exists for this team.
    match store
        .get_credential(&admin.team_id, &req.credential_name)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Credential not found"})),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up credential"})),
            )
                .into_response()
        }
    }

    if let Err(e) = store
        .assign_credential_to_approver(&admin.team_id, &target_id, &req.credential_name)
        .await
    {
        warn!("assign_credential_to_approver error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to assign credential"})),
        )
            .into_response();
    }

    Json(json!({"message": "Credential assigned"})).into_response()
}

/// DELETE /admin/team/members/{id}/credentials/{name} — remove a credential from a member.
/// Owner and admin only.
pub async fn handle_remove_approver_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path((target_id, cred_name)): axum::extract::Path<(String, String)>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(resp) = require_workspace_manager(&admin, "remove credential assignments") {
        return resp;
    }

    let store = state.db_state.store();
    let _target = match store.get_member(&target_id, &admin.team_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Member not found"})),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up member"})),
            )
                .into_response()
        }
    };

    if let Err(e) = store
        .remove_credential_from_approver(&admin.team_id, &target_id, &cred_name)
        .await
    {
        warn!("remove_credential_from_approver error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to remove credential"})),
        )
            .into_response();
    }

    Json(json!({"message": "Credential removed"})).into_response()
}

/// GET /admin/team/members/{id}/credentials — list credentials assigned to a member.
/// Owner and admin only.
pub async fn handle_list_approver_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(target_id): axum::extract::Path<String>,
) -> Response {
    let admin = match authenticate_user(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(resp) = require_workspace_manager(&admin, "view credential assignments") {
        return resp;
    }

    let store = state.db_state.store();
    let _target = match store.get_member(&target_id, &admin.team_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Member not found"})),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up member"})),
            )
                .into_response()
        }
    };

    let creds = store
        .list_approver_credentials(&admin.team_id, &target_id)
        .await
        .unwrap_or_default();
    Json(json!({"credentials": creds, "member_id": target_id})).into_response()
}

// ---------------------------------------------------------------------------
// Dev auto-login (DANGEROUS_TAP_DEV_SKIP_AUTH=true only)
// ---------------------------------------------------------------------------

/// GET /dev/auto-login — returns 404 unless DANGEROUS_TAP_DEV_SKIP_AUTH=true.
/// Finds the first owner admin in the DB, creates a real 24-hour session,
/// and serves a tiny HTML page that writes it to localStorage and redirects
/// to /dashboard. Lets developers browse the dashboard locally without
/// having to go through the full auth + passkey flow.
pub async fn handle_dev_auto_login(State(state): State<AppState>) -> Response {
    if std::env::var("DANGEROUS_TAP_DEV_SKIP_AUTH").as_deref() != Ok("true") {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let store = state.db_state.store();
    let admin = match store.first_owner_member().await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "No owner account found. Sign up at /dashboard first.",
            )
                .into_response()
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")).into_response()
        }
    };

    let token = generate_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

    if let Err(e) = store
        .create_session(&token_hash, &admin.id, &admin.team_id, &expires_at)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create session: {e}"),
        )
            .into_response();
    }

    let team_name = store
        .get_team(&admin.team_id)
        .await
        .ok()
        .flatten()
        .map(|t| t.name)
        .unwrap_or_else(|| "Dev".to_string());

    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Dev Auto-Login</title></head>
<body><script>
localStorage.setItem('agentsec_session', JSON.stringify({{
  token: {token:?},
  admin_id: {admin_id:?},
  team_id: {team_id:?},
  email: {email:?},
  team_name: {team_name:?}
}}));
window.location.replace('/dashboard');
</script><p>Logging in as {email}…</p></body></html>"#,
        token = token,
        admin_id = admin.id,
        team_id = admin.team_id,
        email = admin.email,
        team_name = team_name,
    );

    axum::response::Html(html).into_response()
}

// ---------------------------------------------------------------------------
// Multi-team: list my teams + switch active team
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SwitchTeamRequest {
    pub team_id: String,
}

/// GET /user/teams — list all teams the authenticated user belongs to.
pub async fn handle_list_my_teams(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    match store.list_user_teams(&admin.id).await {
        Ok(teams) => {
            let teams_json: Vec<serde_json::Value> = teams
                .iter()
                .map(|(tid, tname, role)| json!({"team_id": tid, "team_name": tname, "role": role}))
                .collect();
            Json(json!({
                "teams": teams_json,
                "active_team_id": admin.team_id,
            }))
            .into_response()
        }
        Err(e) => {
            warn!("list_user_teams error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list teams"})),
            )
                .into_response()
        }
    }
}

/// POST /session/team — switch the active team of the current session.
/// Verifies the user has a membership in the target team, then atomically
/// updates the session's active team (single DB UPDATE — safe across instances).
pub async fn handle_switch_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SwitchTeamRequest>,
) -> Response {
    // Authenticate first (also yields the raw token we need to update the
    // exact session row).
    let admin = require_admin!(state, headers);
    let token = match extract_session_token(&headers) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let store = state.db_state.store();

    // Verify membership in the target team.
    match store.get_member(&admin.id, &req.team_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "You are not a member of that team"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("switch_team membership lookup error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to switch team"})),
            )
                .into_response();
        }
    }

    // Atomically switch the session's active team.
    let token_hash = hash_session_token(&token);
    match store.update_session_team(&token_hash, &req.team_id).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired session"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("update_session_team error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to switch team"})),
            )
                .into_response();
        }
    }

    // Return the updated active team + full teams list.
    let (active_team_id, active_team_name, _default_role, teams_json) =
        match resolve_active_team(store, &admin.id).await {
            Ok(Some(t)) => t,
            _ => (req.team_id.clone(), String::new(), String::new(), json!([])),
        };
    // The active team is now req.team_id; resolve its name from the list.
    let active_team_name = teams_json
        .as_array()
        .and_then(|arr| arr.iter().find(|t| t["team_id"] == json!(req.team_id)))
        .and_then(|t| t["team_name"].as_str().map(|s| s.to_string()))
        .unwrap_or(active_team_name);
    let active_team_role = teams_json
        .as_array()
        .and_then(|arr| arr.iter().find(|t| t["team_id"] == json!(req.team_id)))
        .and_then(|t| t["role"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| admin.member_role.clone());
    let _ = active_team_id;

    Json(json!({
        "team_id": req.team_id,
        "team_name": active_team_name,
        "member_role": active_team_role.clone(),
        "capabilities": capabilities_for_role(&active_team_role, active_team_role == ROLE_OWNER),
        "teams": teams_json,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_password_produces_argon2_hash() {
        let hash = hash_password("test-password-123").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(hash.len() > 50);
    }

    #[test]
    fn validate_allowed_hosts_normalizes_and_filters() {
        let cleaned = validate_allowed_hosts(&[
            "  API.Stripe.com ".to_string(),
            "".to_string(),
            "*.googleapis.com".to_string(),
        ])
        .unwrap();
        assert_eq!(cleaned, vec!["api.stripe.com", "*.googleapis.com"]);
    }

    #[test]
    fn validate_allowed_hosts_rejects_urls_and_paths() {
        assert!(validate_allowed_hosts(&["https://api.foo.com".to_string()]).is_err());
        assert!(validate_allowed_hosts(&["api.foo.com/v1".to_string()]).is_err());
        assert!(validate_allowed_hosts(&["api.foo.com:443".to_string()]).is_err());
        assert!(validate_allowed_hosts(&["two hosts".to_string()]).is_err());
        // Wildcard only valid as a leading label.
        assert!(validate_allowed_hosts(&["api.*.com".to_string()]).is_err());
        assert!(validate_allowed_hosts(&["*.googleapis.com".to_string()]).is_ok());
    }

    #[test]
    fn validate_credential_name_accepts_lowercase_alphanumeric_hyphens() {
        assert_eq!(
            validate_credential_name("google-workspace-admin").unwrap(),
            "google-workspace-admin"
        );
        assert_eq!(validate_credential_name("  Notion  ").unwrap(), "notion");
        assert_eq!(validate_credential_name("STRIPE-2").unwrap(), "stripe-2");
    }

    #[test]
    fn validate_credential_name_rejects_colon_slash_and_eu_namespace() {
        // The core regression guard: an `eu:{ext}/{logical}` name must never
        // pass a create path, or it collides with the end-user namespace.
        assert!(validate_credential_name("eu:victim-ext/gmail").is_err());
        // Plus the shapes an agent might invent for a namespaced service name,
        // which the dashboard's `pattern="[a-z0-9-]+"` input could never submit.
        assert!(validate_credential_name("google:workspace-admin").is_err());
        assert!(validate_credential_name("notion/api").is_err());
    }

    #[test]
    fn validate_credential_name_rejects_empty_and_too_long() {
        assert!(validate_credential_name("").is_err());
        assert!(validate_credential_name("   ").is_err());
        assert!(validate_credential_name(&"a".repeat(65)).is_err());
        assert!(validate_credential_name(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn hash_password_different_inputs_differ() {
        let h1 = hash_password("password1").unwrap();
        let h2 = hash_password("password2").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_password_same_input_different_salts() {
        let h1 = hash_password("same-password").unwrap();
        let h2 = hash_password("same-password").unwrap();
        // Different salts → different hashes
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_password_correct() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(verify_password("correct-horse", &hash));
    }

    #[test]
    fn verify_password_incorrect() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(!verify_password("wrong-horse", &hash));
    }

    #[test]
    fn verify_password_invalid_hash_format() {
        assert!(!verify_password("anything", "not-a-valid-hash"));
    }

    #[test]
    fn verify_password_empty_string() {
        assert!(!verify_password("", "not-a-valid-hash"));
    }

    #[test]
    fn generate_session_token_length() {
        let token = generate_session_token();
        // 32 bytes → 64 hex chars
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn generate_session_token_is_hex() {
        let token = generate_session_token();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_session_token_unique() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn hash_session_token_deterministic() {
        let h1 = hash_session_token("my-token");
        let h2 = hash_session_token("my-token");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_session_token_different_inputs_differ() {
        let h1 = hash_session_token("token-a");
        let h2 = hash_session_token("token-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_session_token_is_sha256_hex() {
        let hash = hash_session_token("test");
        // SHA-256 → 64 hex chars
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_verification_code_is_6_digits() {
        for _ in 0..100 {
            let code = generate_verification_code();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            let num: u32 = code.parse().unwrap();
            assert!((100_000..1_000_000).contains(&num));
        }
    }

    #[test]
    fn hash_verification_code_deterministic() {
        let h1 = hash_verification_code("123456");
        let h2 = hash_verification_code("123456");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_verification_code_different_codes_differ() {
        let h1 = hash_verification_code("123456");
        let h2 = hash_verification_code("654321");
        assert_ne!(h1, h2);
    }

    // -- validate_approver_emails integration tests ----------------------------

    fn test_db_url() -> String {
        std::env::var("POSTGRES_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://tap:tap@localhost:5434/tap".to_string())
    }

    fn test_enc_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i + 13) as u8;
        }
        key
    }

    // These tests reuse the already-migrated schema (unique team IDs per test).
    // No schema drop — avoids racing with tap-bot tests in the concurrent binary.

    #[tokio::test]
    async fn validate_approver_emails_accepts_team_member() {
        let store = tap_core::store::ConfigStore::new(&test_db_url(), test_enc_key())
            .await
            .unwrap();
        store
            .create_team("vae-accept", "VAE Accept Team")
            .await
            .unwrap();
        store
            .create_user_with_membership(
                "vae-a1",
                "vae-accept",
                "alice@vae.test",
                "hash",
                "approver",
            )
            .await
            .unwrap();
        let result =
            validate_approver_emails(&["alice@vae.test".to_string()], "vae-accept", &store).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn validate_approver_emails_rejects_nonmember_email() {
        let store = tap_core::store::ConfigStore::new(&test_db_url(), test_enc_key())
            .await
            .unwrap();
        store
            .create_team("vae-reject-nm", "VAE Reject NM Team")
            .await
            .unwrap();
        let result =
            validate_approver_emails(&["stranger@vae.test".to_string()], "vae-reject-nm", &store)
                .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_approver_emails_rejects_raw_matrix_id() {
        let store = tap_core::store::ConfigStore::new(&test_db_url(), test_enc_key())
            .await
            .unwrap();
        store
            .create_team("vae-reject-mx", "VAE Reject MX Team")
            .await
            .unwrap();
        let result =
            validate_approver_emails(&["@alice:matrix.org".to_string()], "vae-reject-mx", &store)
                .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_approver_emails_rejects_raw_telegram_id() {
        let store = tap_core::store::ConfigStore::new(&test_db_url(), test_enc_key())
            .await
            .unwrap();
        store
            .create_team("vae-reject-tg", "VAE Reject TG Team")
            .await
            .unwrap();
        let result =
            validate_approver_emails(&["12345678".to_string()], "vae-reject-tg", &store).await;
        assert!(result.is_err());
    }
}
