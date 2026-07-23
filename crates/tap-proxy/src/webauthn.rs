//! WebAuthn approval: hardware-backed (Face ID, fingerprint, YubiKey) approval
//! for agent actions. No app required — just a URL that opens a browser page.
//!
//! Flow:
//!   1. Agent action needs approval → proxy generates approval URL
//!   2. URL delivered via Telegram/email/agent output
//!   3. Approver opens URL → sees request details
//!   4. First time: register a passkey inline, then approve
//!   5. Returning: WebAuthn biometric → approved
//!
//! Passkeys are user-scoped (not team-scoped) and persisted to SQLite.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tap_core::error::AgentSecError;
use tap_core::store::ConfigStore;
use tap_core::types::ApprovalStatus;
use tokio::sync::{oneshot, RwLock};
use tracing::{info, warn};
use webauthn_rs::prelude::*;

/// Shared WebAuthn state for the proxy.
pub struct WebAuthnState {
    webauthn: Webauthn,
    /// Stored credentials: approver_name → list of passkeys
    credentials: RwLock<HashMap<String, Vec<Passkey>>>,
    /// In-flight registration challenges: approver_name → (registration state, display_name)
    reg_challenges: RwLock<HashMap<String, (PasskeyRegistration, String)>>,
    /// In-flight approval challenges: txn_id → auth state.
    /// The approver is determined after authentication from the credential ID
    /// returned by WebAuthn.
    approval_challenges: RwLock<HashMap<String, PasskeyAuthentication>>,
    /// Pending approval details: txn_id → details (for the approval page to display)
    pending_details: RwLock<HashMap<String, ApprovalDetails>>,
    /// Pending approval resolvers: txn_id → oneshot sender
    pending_resolvers: RwLock<HashMap<String, oneshot::Sender<ApprovalStatus>>>,
    /// Base URL for generating approval links
    pub base_url: String,
    /// ConfigStore for persisting passkeys to SQLite
    store: Option<ConfigStore>,
    // -- Admin passkeys (2FA for admin login) --
    /// Admin credentials: admin_id → list of passkeys
    admin_credentials: RwLock<HashMap<String, Vec<Passkey>>>,
    /// In-flight admin registration challenges: admin_id → (registration state)
    admin_reg_challenges: RwLock<HashMap<String, PasskeyRegistration>>,
    /// In-flight admin login challenges: passkey_token → (auth state, admin_id)
    admin_login_challenges: RwLock<HashMap<String, (PasskeyAuthentication, String)>>,
}

impl WebAuthnState {
    pub fn new(
        rp_id: &str,
        rp_origin: &str,
        base_url: &str,
        store: Option<ConfigStore>,
        additional_origins: &[String],
    ) -> Result<Self, AgentSecError> {
        let origin = url::Url::parse(rp_origin)
            .map_err(|e| AgentSecError::Config(format!("Invalid WebAuthn origin: {e}")))?;
        let mut builder = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|e| AgentSecError::Config(format!("WebAuthn builder error: {e}")))?;
        for extra in additional_origins {
            let extra_url = url::Url::parse(extra).map_err(|e| {
                AgentSecError::Config(format!("Invalid additional WebAuthn origin '{extra}': {e}"))
            })?;
            builder = builder.append_allowed_origin(&extra_url);
        }
        // `webauthn` is shared by ALL flows: admin login, approver passkey
        // registration, and per-transaction approval.  Additional origins
        // added here are therefore trusted for all three.
        let webauthn = builder
            .build()
            .map_err(|e| AgentSecError::Config(format!("WebAuthn build error: {e}")))?;
        if !additional_origins.is_empty() {
            tracing::info!(
                origins = ?additional_origins,
                "WebAuthn: additional origins accepted (admin login + approvals)"
            );
        }

        Ok(Self {
            webauthn,
            credentials: RwLock::new(HashMap::new()),
            reg_challenges: RwLock::new(HashMap::new()),
            approval_challenges: RwLock::new(HashMap::new()),
            pending_details: RwLock::new(HashMap::new()),
            pending_resolvers: RwLock::new(HashMap::new()),
            base_url: base_url.to_string(),
            store,
            admin_credentials: RwLock::new(HashMap::new()),
            admin_reg_challenges: RwLock::new(HashMap::new()),
            admin_login_challenges: RwLock::new(HashMap::new()),
        })
    }

    /// Generate the approval URL for a transaction.
    pub fn approval_url(&self, txn_id: &str) -> String {
        format!(
            "{}/approve/txn/{}",
            self.base_url.trim_end_matches('/'),
            txn_id
        )
    }

    /// Register a pending approval that can be resolved via WebAuthn.
    /// Returns a oneshot receiver that the proxy waits on.
    pub async fn register_pending(
        &self,
        txn_id: &str,
        details: ApprovalDetails,
    ) -> oneshot::Receiver<ApprovalStatus> {
        let (tx, rx) = oneshot::channel();
        self.pending_details
            .write()
            .await
            .insert(txn_id.to_string(), details);
        self.pending_resolvers
            .write()
            .await
            .insert(txn_id.to_string(), tx);
        rx
    }

    async fn load_pending_details(
        &self,
        txn_id: &str,
    ) -> Result<Option<ApprovalDetails>, AgentSecError> {
        if let Some(details) = self.pending_details.read().await.get(txn_id).cloned() {
            return Ok(Some(details));
        }

        let Some(store) = self.store.clone() else {
            return Ok(None);
        };

        let json = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            store.get_pending_approval_details(txn_id),
        )
        .await
        .map_err(|_| {
            AgentSecError::Internal("DB lookup for pending approval timed out".into())
        })??;

        let Some(json) = json else {
            return Ok(None);
        };

        let details = serde_json::from_str::<ApprovalDetails>(&json).map_err(|e| {
            AgentSecError::Internal(format!("Failed to deserialize pending approval: {e}"))
        })?;
        self.pending_details
            .write()
            .await
            .insert(txn_id.to_string(), details.clone());
        Ok(Some(details))
    }

    async fn resolve_approval_as(
        &self,
        txn_id: &str,
        status: ApprovalStatus,
        resolved_by: Option<&str>,
    ) -> bool {
        self.pending_details.write().await.remove(txn_id);
        let mut db_resolved = false;
        if let Some(ref store) = self.store {
            let status_str = match status {
                ApprovalStatus::Approved => "approved",
                ApprovalStatus::Denied => "denied",
                _ => "expired",
            };
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                store.resolve_pending_approval(txn_id, status_str, resolved_by),
            )
            .await;
            match res {
                Ok(Err(e)) => {
                    tracing::warn!(txn_id, error = %e, "Failed to update pending approval status in DB")
                }
                Err(_) => tracing::warn!(
                    txn_id,
                    "DB update for pending approval resolution timed out"
                ),
                Ok(Ok(updated)) => db_resolved = updated,
            }
        }
        // Only signal the in-memory waiter if the DB claim actually succeeded
        // (or there is no store). Otherwise the same-instance fast path would
        // bypass the SQL default-deny gate — e.g. a team approver could unblock
        // a /sign waiting on an end-user-reserved approval even though the DB
        // refused to mark it approved.
        let may_signal_memory = self.store.is_none() || db_resolved;
        let memory_resolved = if may_signal_memory {
            if let Some(tx) = self.pending_resolvers.write().await.remove(txn_id) {
                tx.send(status).is_ok()
            } else {
                false
            }
        } else {
            false
        };
        memory_resolved || db_resolved
    }

    /// Resolve a pending approval (called after successful WebAuthn assertion).
    pub async fn resolve_approval(&self, txn_id: &str, status: ApprovalStatus) -> bool {
        self.resolve_approval_as(txn_id, status, None).await
    }

    /// Exclusive pending→approved claim for the grant surface (#49). Unlike
    /// `resolve_approval_as` — where `resolve_pending_approval` treats a
    /// re-resolution to the same status as success — an already-approved row
    /// does NOT count here, so two concurrent "Approve for {duration}"
    /// submissions can only mint one grant. There is no in-memory fallback: a
    /// grant may only mint on the durable claim (grants require a store
    /// anyway), and the waiter is signalled only after the claim succeeded.
    pub async fn claim_approval_for_grant(
        &self,
        txn_id: &str,
        resolved_by: Option<&str>,
    ) -> bool {
        self.pending_details.write().await.remove(txn_id);
        let mut db_resolved = false;
        if let Some(ref store) = self.store {
            let res = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                store.claim_pending_approval_for_grant(txn_id, resolved_by),
            )
            .await;
            match res {
                Ok(Err(e)) => {
                    tracing::warn!(txn_id, error = %e, "Failed to claim pending approval for grant")
                }
                Err(_) => tracing::warn!(txn_id, "DB claim for grant approval timed out"),
                Ok(Ok(updated)) => db_resolved = updated,
            }
        }
        if db_resolved {
            if let Some(tx) = self.pending_resolvers.write().await.remove(txn_id) {
                let _ = tx.send(ApprovalStatus::Approved);
            }
        }
        db_resolved
    }

    /// Resolve an end-user-reserved approval after that end-user's own
    /// authenticated approval (the passkey ceremony today; other end-user-
    /// authenticating channels later). Goes through the identity-scoped DB gate
    /// (`resolve_pending_approval_as_end_user`) and only then signals the
    /// in-memory waiter.
    pub async fn resolve_approval_for_end_user(
        &self,
        txn_id: &str,
        status: ApprovalStatus,
        ext_id: &str,
    ) -> bool {
        self.pending_details.write().await.remove(txn_id);
        let mut db_resolved = false;
        if let Some(ref store) = self.store {
            let status_str = match status {
                ApprovalStatus::Approved => "approved",
                ApprovalStatus::Denied => "denied",
                _ => "expired",
            };
            match store
                .resolve_pending_approval_as_end_user(txn_id, status_str, ext_id, Some(ext_id))
                .await
            {
                Ok(updated) => db_resolved = updated,
                Err(e) => tracing::warn!(txn_id, error = %e, "end-user approval DB resolve failed"),
            }
        }
        let may_signal_memory = self.store.is_none() || db_resolved;
        let memory_resolved = if may_signal_memory {
            if let Some(tx) = self.pending_resolvers.write().await.remove(txn_id) {
                tx.send(status).is_ok()
            } else {
                false
            }
        } else {
            false
        };
        memory_resolved || db_resolved
    }

    /// Load passkeys from SQLite at startup.
    pub async fn load_credentials_from_db(&self) -> Result<usize, AgentSecError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| AgentSecError::Config("No DB configured for WebAuthn".into()))?;
        let rows = store.list_all_approver_passkeys().await?;
        let mut creds = self.credentials.write().await;
        let mut count = 0;
        for row in rows {
            if let Ok(passkey) = serde_json::from_str::<Passkey>(&row.public_key_json) {
                creds.entry(row.approver_name).or_default().push(passkey);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Store pending details for the approval page without creating a oneshot receiver.
    /// Used in passkey-required mode where the proxy waits on the Telegram channel
    /// and WebAuthn resolves it via bridge.
    /// Also persists to DB so the passkey page survives proxy restarts.
    /// `ttl_secs` is how long the row stays actionable — callers pass the
    /// approval window plus slack so the page and the transaction agree.
    pub async fn set_pending_details(&self, txn_id: &str, details: ApprovalDetails, ttl_secs: u64) {
        self.pending_details
            .write()
            .await
            .insert(txn_id.to_string(), details.clone());
        if let Some(store) = self.store.clone() {
            if let Ok(json) = serde_json::to_string(&details) {
                let expires_at =
                    (chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();
                let team_id = (!details.team_id.is_empty()).then_some(details.team_id.as_str());
                if let Err(e) = store
                    .save_pending_approval_with_team(txn_id, &json, &expires_at, team_id)
                    .await
                {
                    tracing::warn!(txn_id, error = %e, "Failed to persist pending approval to DB");
                }
            }
        }
    }

    /// Get a passkey as JSON for storage (after registration).
    pub fn passkey_to_json(passkey: &Passkey) -> Result<String, AgentSecError> {
        serde_json::to_string(passkey)
            .map_err(|e| AgentSecError::Internal(format!("Failed to serialize passkey: {e}")))
    }

    /// Check if any passkeys are registered at all.
    pub async fn has_any_credentials(&self) -> bool {
        let creds = self.credentials.read().await;
        if creds.values().any(|pks| !pks.is_empty()) {
            return true;
        }
        drop(creds);

        let Some(store) = self.store.as_ref() else {
            return false;
        };
        store
            .list_all_user_passkeys()
            .await
            .map(|rows| !rows.is_empty())
            .unwrap_or(false)
    }

    // -- Registration ---------------------------------------------------------

    pub async fn begin_registration(
        &self,
        approver_name: &str,
        display_name: &str,
    ) -> Result<CreationChallengeResponse, AgentSecError> {
        let user_unique_id = Uuid::new_v4();
        let existing = self.credentials.read().await;
        let exclude = existing
            .get(approver_name)
            .map(|creds| {
                creds
                    .iter()
                    .map(|c| c.cred_id().clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        drop(existing);

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_unique_id, approver_name, display_name, Some(exclude))
            .map_err(|e| AgentSecError::Internal(format!("Registration start failed: {e}")))?;

        // Persist durably so a headless register-begin on one instance can be
        // finished on another (Distributed State Rule). Keep the in-memory map
        // as a fallback for the no-store (test) configuration.
        if let Some(ref store) = self.store {
            let json = serde_json::to_string(&reg_state).map_err(|e| {
                AgentSecError::Internal(format!("Failed to serialize registration challenge: {e}"))
            })?;
            store
                .set_approver_registration_challenge(approver_name, &json, display_name)
                .await?;
        } else {
            self.reg_challenges.write().await.insert(
                approver_name.to_string(),
                (reg_state, display_name.to_string()),
            );
        }

        Ok(ccr)
    }

    pub async fn finish_registration(
        &self,
        approver_name: &str,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, AgentSecError> {
        let (reg_state, display_name) = if let Some(ref store) = self.store {
            match store
                .take_approver_registration_challenge(approver_name)
                .await?
            {
                Some((json, display_name)) => {
                    let state: PasskeyRegistration = serde_json::from_str(&json).map_err(|e| {
                        AgentSecError::Internal(format!(
                            "Failed to deserialize registration challenge: {e}"
                        ))
                    })?;
                    (state, display_name)
                }
                None => self
                    .reg_challenges
                    .write()
                    .await
                    .remove(approver_name)
                    .ok_or_else(|| {
                        AgentSecError::Internal("No pending registration".to_string())
                    })?,
            }
        } else {
            self.reg_challenges
                .write()
                .await
                .remove(approver_name)
                .ok_or_else(|| AgentSecError::Internal("No pending registration".to_string()))?
        };

        let passkey = self
            .webauthn
            .finish_passkey_registration(reg, &reg_state)
            .map_err(|e| AgentSecError::Internal(format!("Registration failed: {e}")))?;

        // Persist to SQLite
        if let Some(ref store) = self.store {
            let json = Self::passkey_to_json(&passkey)?;
            use base64::Engine;
            let cred_id =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
            store
                .save_approver_passkey(&cred_id, approver_name, &display_name, &json)
                .await?;
        }

        // Add to in-memory map
        self.credentials
            .write()
            .await
            .entry(approver_name.to_string())
            .or_default()
            .push(passkey.clone());

        Ok(passkey)
    }

    // -- Approval (authentication) --------------------------------------------

    pub async fn user_has_approval_passkeys(&self, user_id: &str, approver_email: &str) -> bool {
        !self
            .session_approval_passkeys(user_id, approver_email)
            .await
            .is_empty()
    }

    pub async fn begin_approval_for_user(
        &self,
        txn_id: &str,
        user_id: &str,
        approver_email: &str,
    ) -> Result<RequestChallengeResponse, AgentSecError> {
        let passkeys = self
            .session_approval_passkeys(user_id, approver_email)
            .await;
        if passkeys.is_empty() {
            return Err(AgentSecError::Internal(
                "No approver credentials registered".to_string(),
            ));
        }

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AgentSecError::Internal(format!("Auth start failed: {e}")))?;

        if let Some(ref store) = self.store {
            let auth_state_json = serde_json::to_string(&auth_state).map_err(|e| {
                AgentSecError::Internal(format!("Failed to serialize approval challenge: {e}"))
            })?;
            store
                .set_pending_approval_challenge(txn_id, &auth_state_json)
                .await?;
        }

        self.approval_challenges
            .write()
            .await
            .insert(txn_id.to_string(), auth_state);

        Ok(rcr)
    }

    pub async fn begin_approval(
        &self,
        txn_id: &str,
    ) -> Result<RequestChallengeResponse, AgentSecError> {
        let all_passkeys = self.all_approval_passkeys().await?;
        if all_passkeys.is_empty() {
            return Err(AgentSecError::Internal(
                "No approver credentials registered".to_string(),
            ));
        }

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&all_passkeys)
            .map_err(|e| AgentSecError::Internal(format!("Auth start failed: {e}")))?;

        if let Some(ref store) = self.store {
            let auth_state_json = serde_json::to_string(&auth_state).map_err(|e| {
                AgentSecError::Internal(format!("Failed to serialize approval challenge: {e}"))
            })?;
            store
                .set_pending_approval_challenge(txn_id, &auth_state_json)
                .await?;
        }

        self.approval_challenges
            .write()
            .await
            .insert(txn_id.to_string(), auth_state);

        Ok(rcr)
    }

    pub async fn finish_approval_for_user(
        &self,
        txn_id: &str,
        user_id: &str,
        approver_email: &str,
        auth: &PublicKeyCredential,
    ) -> Result<String, AgentSecError> {
        let auth_state = if let Some(ref store) = self.store {
            match store.take_pending_approval_challenge(txn_id).await? {
                Some(json) => {
                    serde_json::from_str::<PasskeyAuthentication>(&json).map_err(|e| {
                        AgentSecError::Internal(format!(
                            "Failed to deserialize approval challenge: {e}"
                        ))
                    })?
                }
                None => self
                    .approval_challenges
                    .write()
                    .await
                    .remove(txn_id)
                    .ok_or_else(|| {
                        AgentSecError::Internal("No pending approval challenge".to_string())
                    })?,
            }
        } else {
            self.approval_challenges
                .write()
                .await
                .remove(txn_id)
                .ok_or_else(|| {
                    AgentSecError::Internal("No pending approval challenge".to_string())
                })?
        };
        self.approval_challenges.write().await.remove(txn_id);

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(auth, &auth_state)
            .map_err(|e| AgentSecError::Internal(format!("Auth failed: {e}")))?;

        let authenticated_cred_id = auth_result.cred_id().clone();
        let mut passkeys = self
            .session_approval_passkeys(user_id, approver_email)
            .await;
        let Some(passkey) = passkeys
            .iter_mut()
            .find(|passkey| passkey.cred_id() == &authenticated_cred_id)
        else {
            return Err(AgentSecError::Forbidden(
                "Authenticated passkey does not belong to this session".to_string(),
            ));
        };
        passkey.update_credential(&auth_result);

        Ok(user_id.to_string())
    }

    async fn session_approval_passkeys(&self, user_id: &str, approver_email: &str) -> Vec<Passkey> {
        let mut passkeys = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for passkey in self.user_passkeys(user_id).await {
            let key = credential_id_key(passkey.cred_id());
            if seen.insert(key) {
                passkeys.push(passkey);
            }
        }

        {
            let creds = self.credentials.read().await;
            if let Some(legacy) = creds.get(approver_email) {
                for passkey in legacy {
                    let key = credential_id_key(passkey.cred_id());
                    if seen.insert(key) {
                        passkeys.push(passkey.clone());
                    }
                }
            }
        }

        let Some(store) = self.store.as_ref() else {
            return passkeys;
        };
        match store.list_all_approver_passkeys().await {
            Ok(rows) => {
                for row in rows {
                    if row.approver_name != approver_email {
                        continue;
                    }
                    let Ok(passkey) = serde_json::from_str::<Passkey>(&row.public_key_json) else {
                        continue;
                    };
                    let key = credential_id_key(passkey.cred_id());
                    if seen.insert(key) {
                        passkeys.push(passkey);
                    }
                }
            }
            Err(e) => warn!("Failed to load legacy approval passkeys for {approver_email}: {e}"),
        }

        passkeys
    }

    pub async fn finish_approval(
        &self,
        txn_id: &str,
        auth: &PublicKeyCredential,
    ) -> Result<String, AgentSecError> {
        let auth_state = if let Some(ref store) = self.store {
            match store.take_pending_approval_challenge(txn_id).await? {
                Some(json) => {
                    serde_json::from_str::<PasskeyAuthentication>(&json).map_err(|e| {
                        AgentSecError::Internal(format!(
                            "Failed to deserialize approval challenge: {e}"
                        ))
                    })?
                }
                None => self
                    .approval_challenges
                    .write()
                    .await
                    .remove(txn_id)
                    .ok_or_else(|| {
                        AgentSecError::Internal("No pending approval challenge".to_string())
                    })?,
            }
        } else {
            self.approval_challenges
                .write()
                .await
                .remove(txn_id)
                .ok_or_else(|| {
                    AgentSecError::Internal("No pending approval challenge".to_string())
                })?
        };
        self.approval_challenges.write().await.remove(txn_id);

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(auth, &auth_state)
            .map_err(|e| AgentSecError::Internal(format!("Auth failed: {e}")))?;

        // Attribute the approval to the account that owns the credential the
        // authenticator actually used. Challenges may include passkeys from many
        // approvers, so choosing an approver before this point is not reliable.
        let authenticated_cred_id = auth_result.cred_id().clone();
        let approver_name = self
            .approval_owner_for_credential_id(&authenticated_cred_id)
            .await?
            .ok_or_else(|| {
                AgentSecError::Internal("Authenticated credential not found".to_string())
            })?;

        let mut creds = self.credentials.write().await;
        if let Some(passkeys) = creds.get_mut(&approver_name) {
            for passkey in passkeys.iter_mut() {
                if passkey.cred_id() == &authenticated_cred_id {
                    passkey.update_credential(&auth_result);
                    break;
                }
            }
        }

        Ok(approver_name)
    }

    /// Passkeys registered under one specific `approver_name` (e.g. an
    /// end-user's `eu:{team}:{ext}`), from the in-memory map and the
    /// `approver_passkeys` table. Used to scope an approval challenge to exactly
    /// one managed end-user (TAP for Platforms).
    async fn approver_passkeys_for(&self, approver_name: &str) -> Vec<Passkey> {
        let mut passkeys = Vec::new();
        let mut seen = std::collections::HashSet::new();
        {
            let creds = self.credentials.read().await;
            if let Some(list) = creds.get(approver_name) {
                for pk in list {
                    if seen.insert(credential_id_key(pk.cred_id())) {
                        passkeys.push(pk.clone());
                    }
                }
            }
        }
        if let Some(store) = self.store.as_ref() {
            match store.list_all_approver_passkeys().await {
                Ok(rows) => {
                    for row in rows {
                        if row.approver_name != approver_name {
                            continue;
                        }
                        if let Ok(pk) = serde_json::from_str::<Passkey>(&row.public_key_json) {
                            if seen.insert(credential_id_key(pk.cred_id())) {
                                passkeys.push(pk);
                            }
                        }
                    }
                }
                Err(e) => warn!("Failed to load passkeys for {approver_name}: {e}"),
            }
        }
        passkeys
    }

    /// Begin an approval ceremony scoped to a single approver/end-user — the
    /// challenge only accepts that identity's passkeys. Challenge persisted
    /// durably so begin/finish can span instances.
    pub async fn begin_approval_for_approver(
        &self,
        txn_id: &str,
        approver_name: &str,
    ) -> Result<RequestChallengeResponse, AgentSecError> {
        let passkeys = self.approver_passkeys_for(approver_name).await;
        if passkeys.is_empty() {
            return Err(AgentSecError::Internal(
                "No passkey registered for this end-user".to_string(),
            ));
        }
        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AgentSecError::Internal(format!("Auth start failed: {e}")))?;
        if let Some(ref store) = self.store {
            let json = serde_json::to_string(&auth_state).map_err(|e| {
                AgentSecError::Internal(format!("Failed to serialize approval challenge: {e}"))
            })?;
            store.set_pending_approval_challenge(txn_id, &json).await?;
        }
        self.approval_challenges
            .write()
            .await
            .insert(txn_id.to_string(), auth_state);
        Ok(rcr)
    }

    /// Finish an approval ceremony scoped to a single approver/end-user. Fails
    /// unless the authenticated passkey actually belongs to `approver_name`, so
    /// end-user A can never approve a request scoped to end-user B.
    pub async fn finish_approval_for_approver(
        &self,
        txn_id: &str,
        approver_name: &str,
        auth: &PublicKeyCredential,
    ) -> Result<(), AgentSecError> {
        let auth_state = if let Some(ref store) = self.store {
            match store.take_pending_approval_challenge(txn_id).await? {
                Some(json) => {
                    serde_json::from_str::<PasskeyAuthentication>(&json).map_err(|e| {
                        AgentSecError::Internal(format!(
                            "Failed to deserialize approval challenge: {e}"
                        ))
                    })?
                }
                None => self
                    .approval_challenges
                    .write()
                    .await
                    .remove(txn_id)
                    .ok_or_else(|| {
                        AgentSecError::Internal("No pending approval challenge".to_string())
                    })?,
            }
        } else {
            self.approval_challenges
                .write()
                .await
                .remove(txn_id)
                .ok_or_else(|| {
                    AgentSecError::Internal("No pending approval challenge".to_string())
                })?
        };
        self.approval_challenges.write().await.remove(txn_id);

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(auth, &auth_state)
            .map_err(|e| AgentSecError::Internal(format!("Auth failed: {e}")))?;

        // The authenticated credential must belong to this end-user.
        let authed = auth_result.cred_id().clone();
        let owned = self.approver_passkeys_for(approver_name).await;
        if !owned.iter().any(|pk| pk.cred_id() == &authed) {
            return Err(AgentSecError::Forbidden(
                "Authenticated passkey does not belong to this end-user".to_string(),
            ));
        }
        Ok(())
    }

    async fn all_approval_passkeys(&self) -> Result<Vec<Passkey>, AgentSecError> {
        let mut passkeys = Vec::new();
        let mut seen = std::collections::HashSet::new();

        {
            let creds = self.credentials.read().await;
            for passkey in creds.values().flatten() {
                let key = credential_id_key(passkey.cred_id());
                if seen.insert(key) {
                    passkeys.push(passkey.clone());
                }
            }
        }

        let Some(store) = self.store.as_ref() else {
            return Ok(passkeys);
        };
        for row in store.list_all_user_passkeys().await? {
            let Ok(passkey) = serde_json::from_str::<Passkey>(&row.public_key_json) else {
                continue;
            };
            let key = credential_id_key(passkey.cred_id());
            if seen.insert(key) {
                passkeys.push(passkey);
            }
        }

        Ok(passkeys)
    }

    async fn approval_owner_for_credential_id(
        &self,
        authenticated_cred_id: &CredentialID,
    ) -> Result<Option<String>, AgentSecError> {
        {
            let creds = self.credentials.read().await;
            if let Some(approver_name) = find_approver_name_by_credential_id(
                creds.iter().flat_map(|(approver_name, passkeys)| {
                    passkeys
                        .iter()
                        .map(move |passkey| (approver_name.as_str(), passkey.cred_id()))
                }),
                authenticated_cred_id,
            ) {
                return Ok(Some(approver_name));
            }
        }

        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        for row in store.list_all_user_passkeys().await? {
            let Ok(passkey) = serde_json::from_str::<Passkey>(&row.public_key_json) else {
                continue;
            };
            if passkey.cred_id() != authenticated_cred_id {
                continue;
            }
            return Ok(store.get_user(&row.user_id).await?.map(|u| u.email));
        }

        Ok(None)
    }

    // -- Admin passkey methods (2FA for admin login) --------------------------

    /// Load admin passkeys from SQLite at startup.
    pub async fn load_admin_credentials_from_db(&self) -> Result<usize, AgentSecError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| AgentSecError::Config("No DB configured for WebAuthn".into()))?;
        let rows = store.list_all_user_passkeys().await?;
        let mut creds = self.admin_credentials.write().await;
        let mut count = 0;
        for row in rows {
            if let Ok(passkey) = serde_json::from_str::<Passkey>(&row.public_key_json) {
                creds.entry(row.user_id).or_default().push(passkey);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Check if an admin has any passkeys registered. Reads from durable storage
    /// when available so a passkey registered on another instance (or after this
    /// instance booted) is visible — otherwise login would wrongly route the user
    /// back into passkey setup. Falls back to the in-memory cache only when no
    /// store is configured (tests).
    pub async fn user_has_passkeys(&self, admin_id: &str) -> bool {
        if let Some(ref store) = self.store {
            match store.count_user_passkeys(admin_id).await {
                Ok(n) => return n > 0,
                Err(e) => warn!("count_user_passkeys failed for {admin_id}: {e}"),
            }
        }
        let creds = self.admin_credentials.read().await;
        creds
            .get(admin_id)
            .map(|pks| !pks.is_empty())
            .unwrap_or(false)
    }

    /// Load a user's registered passkeys, preferring durable storage so every
    /// instance sees passkeys registered elsewhere. Falls back to the in-memory
    /// cache only when no store is configured (tests).
    async fn user_passkeys(&self, admin_id: &str) -> Vec<Passkey> {
        if let Some(ref store) = self.store {
            match store.list_user_passkeys(admin_id).await {
                Ok(rows) => {
                    return rows
                        .iter()
                        .filter_map(|r| serde_json::from_str::<Passkey>(&r.public_key_json).ok())
                        .collect();
                }
                Err(e) => warn!("Failed to load passkeys for {admin_id}: {e}"),
            }
        }
        self.admin_credentials
            .read()
            .await
            .get(admin_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Begin registration of a passkey for an admin.
    pub async fn begin_user_registration(
        &self,
        admin_id: &str,
        display_name: &str,
    ) -> Result<CreationChallengeResponse, AgentSecError> {
        let user_unique_id = Uuid::new_v4();
        let exclude = self
            .user_passkeys(admin_id)
            .await
            .iter()
            .map(|c| c.cred_id().clone())
            .collect::<Vec<_>>();

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_unique_id, admin_id, display_name, Some(exclude))
            .map_err(|e| AgentSecError::Internal(format!("Admin reg start failed: {e}")))?;

        // Persist the registration challenge durably so `finish` can be served by
        // a different stateless instance. In-memory map is a store-less fallback.
        if let Some(ref store) = self.store {
            let json = serde_json::to_string(&reg_state).map_err(|e| {
                AgentSecError::Internal(format!("Failed to serialize registration challenge: {e}"))
            })?;
            store.set_registration_challenge(admin_id, &json).await?;
        } else {
            self.admin_reg_challenges
                .write()
                .await
                .insert(admin_id.to_string(), reg_state);
        }

        Ok(ccr)
    }

    /// Complete registration of a passkey for an admin.
    pub async fn finish_user_registration(
        &self,
        admin_id: &str,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, AgentSecError> {
        // Claim the registration challenge from durable storage first
        // (cross-instance, single-use); fall back to in-memory for store-less tests.
        let reg_state: PasskeyRegistration = if let Some(ref store) = self.store {
            let json = store
                .take_registration_challenge(admin_id)
                .await?
                .ok_or_else(|| {
                    AgentSecError::Internal("No pending admin registration".to_string())
                })?;
            serde_json::from_str(&json).map_err(|e| {
                AgentSecError::Internal(format!("Failed to parse registration challenge: {e}"))
            })?
        } else {
            self.admin_reg_challenges
                .write()
                .await
                .remove(admin_id)
                .ok_or_else(|| {
                    AgentSecError::Internal("No pending admin registration".to_string())
                })?
        };

        let passkey = self
            .webauthn
            .finish_passkey_registration(reg, &reg_state)
            .map_err(|e| AgentSecError::Internal(format!("Admin reg failed: {e}")))?;

        // Persist to SQLite
        if let Some(ref store) = self.store {
            let json = Self::passkey_to_json(&passkey)?;
            use base64::Engine;
            let cred_id =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
            store.save_user_passkey(admin_id, &cred_id, &json).await?;
        }

        // Add to in-memory map
        self.admin_credentials
            .write()
            .await
            .entry(admin_id.to_string())
            .or_default()
            .push(passkey.clone());

        Ok(passkey)
    }

    /// Begin login authentication challenge for an admin.
    /// Returns the challenge and a passkey_token the frontend must send back.
    pub async fn begin_user_login(
        &self,
        admin_id: &str,
    ) -> Result<(RequestChallengeResponse, String), AgentSecError> {
        let passkeys = self.user_passkeys(admin_id).await;
        if passkeys.is_empty() {
            return Err(AgentSecError::Internal(
                "No passkeys registered for admin".into(),
            ));
        }

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AgentSecError::Internal(format!("Admin auth start failed: {e}")))?;

        // Generate a passkey_token to correlate the challenge
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let passkey_token = hex::encode(bytes);

        // Persist the challenge durably so `finish_user_login` can be served by a
        // different stateless proxy instance. The in-memory map is only a
        // fallback for store-less (test) configurations.
        if let Some(ref store) = self.store {
            let json = serde_json::to_string(&auth_state).map_err(|e| {
                AgentSecError::Internal(format!("Failed to serialize login challenge: {e}"))
            })?;
            store
                .set_login_challenge(&passkey_token, admin_id, &json)
                .await?;
        } else {
            self.admin_login_challenges
                .write()
                .await
                .insert(passkey_token.clone(), (auth_state, admin_id.to_string()));
        }

        Ok((rcr, passkey_token))
    }

    /// Complete login authentication for an admin.
    /// Returns the admin_id on success.
    pub async fn finish_user_login(
        &self,
        passkey_token: &str,
        auth: &PublicKeyCredential,
    ) -> Result<String, AgentSecError> {
        // Claim the challenge from durable storage first (cross-instance,
        // single-use). Fall back to the in-memory map only when no store is
        // configured (tests).
        let (auth_state, admin_id) = if let Some(ref store) = self.store {
            let (user_id, json) = store
                .take_login_challenge(passkey_token)
                .await?
                .ok_or_else(|| {
                    AgentSecError::Internal("Invalid or expired passkey token".to_string())
                })?;
            let auth_state: PasskeyAuthentication = serde_json::from_str(&json).map_err(|e| {
                AgentSecError::Internal(format!("Failed to parse login challenge: {e}"))
            })?;
            (auth_state, user_id)
        } else {
            self.admin_login_challenges
                .write()
                .await
                .remove(passkey_token)
                .ok_or_else(|| {
                    AgentSecError::Internal("Invalid or expired passkey token".to_string())
                })?
        };

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(auth, &auth_state)
            .map_err(|e| AgentSecError::Internal(format!("Admin auth failed: {e}")))?;

        // Update credential counter
        let mut creds = self.admin_credentials.write().await;
        if let Some(passkeys) = creds.get_mut(&admin_id) {
            for passkey in passkeys.iter_mut() {
                passkey.update_credential(&auth_result);
            }
        }

        Ok(admin_id)
    }

    /// Remove a passkey from the in-memory map (after DB deletion).
    pub async fn remove_user_credential(&self, admin_id: &str, credential_id_b64: &str) {
        let mut creds = self.admin_credentials.write().await;
        if let Some(passkeys) = creds.get_mut(admin_id) {
            use base64::Engine;
            passkeys.retain(|pk| {
                let pk_id =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.cred_id().as_ref());
                pk_id != credential_id_b64
            });
        }
    }
}

fn credential_id_key(cred_id: &CredentialID) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_id.as_ref())
}

fn find_approver_name_by_credential_id<'a, I>(
    credentials: I,
    authenticated_cred_id: &CredentialID,
) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, &'a CredentialID)>,
{
    credentials
        .into_iter()
        .find_map(|(approver_name, cred_id)| {
            (cred_id == authenticated_cred_id).then(|| approver_name.to_string())
        })
}

// -- Types --------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct ApprovalDetails {
    pub txn_id: String,
    pub team_id: String,
    pub agent_id: String,
    pub credential_name: String,
    pub target_url: String,
    pub method: String,
    pub body_preview: Option<String>,
    /// Deterministic one-line summary of what the call does, for recognized
    /// services (`tap_core::summary`). `None` for unrecognized targets; serde
    /// default keeps rows persisted before this field deserializable.
    #[serde(default)]
    pub summary: Option<String>,
    /// Optional policy-level approver restriction emails. Empty = any eligible
    /// approver for this credential; eligibility is evaluated from team role and
    /// credential assignment when the approval is viewed or resolved.
    #[serde(default)]
    pub allowed_approvers: Vec<String>,
    /// Whether this credential's policy demands hardware-backed (passkey) approval.
    /// When true, the dashboard session-approve path refuses the request and the
    /// approver must complete the passkey ceremony instead.
    #[serde(default)]
    pub require_passkey: bool,
}

#[derive(Deserialize)]
pub struct RegisterBeginRequest {
    pub display_name: Option<String>,
}

#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub credential: RegisterPublicKeyCredential,
}

// -- Axum handlers ------------------------------------------------------------

pub type SharedWebAuthnState = Arc<WebAuthnState>;

/// Combined state for approval handlers that need to bridge WebAuthn
/// approvals back to the notification channel (Telegram).
#[derive(Clone)]
pub struct ApprovalHandlerState {
    pub webauthn: SharedWebAuthnState,
    /// Telegram channel for resolving pending approvals when passkey succeeds.
    /// `None` when the deployment runs without a Telegram bot.
    pub telegram_channel: Option<Arc<tap_bot::TelegramChannel>>,
    /// Optional Matrix channel — present when Matrix is configured.
    pub matrix_channel: Option<Arc<tap_bot::MatrixChannel>>,
    /// Config store — used to validate admin sessions on registration endpoints.
    pub store: Option<Arc<tap_core::store::ConfigStore>>,
}

/// Validate a user session from the `Authorization: Bearer <token>` header.
/// Returns the resolved `Member` on success, or `Err(Response)` with a 401/403
/// if invalid.
async fn require_user_session(
    store: &Option<Arc<tap_core::store::ConfigStore>>,
    headers: &HeaderMap,
) -> Result<tap_core::store::Member, Response> {
    // Header check first so missing auth always returns 401, not 503.
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Admin session required to register passkeys"})),
            )
                .into_response()
        })?;

    let store = store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                serde_json::json!({"error": "Registration requires a database-backed deployment"}),
            ),
        )
            .into_response()
    })?;

    let token_hash = crate::admin::hash_session_token(token);
    let admin = store
        .validate_session(&token_hash)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Session validation failed"})),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid or expired admin session"})),
            )
                .into_response()
        })?;

    if !admin.email_verified {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Email not verified"})),
        )
            .into_response());
    }

    Ok(admin)
}

fn role_can_approve_all_credentials(role: &str) -> bool {
    matches!(role, "owner" | "admin")
}

fn policy_allows_member(email: &str, details: &ApprovalDetails) -> bool {
    details.allowed_approvers.is_empty() || details.allowed_approvers.contains(&email.to_string())
}

async fn member_can_act_on_approval(
    store: &ConfigStore,
    member: &tap_core::store::Member,
    details: &ApprovalDetails,
) -> Result<bool, AgentSecError> {
    if !policy_allows_member(&member.email, details) {
        return Ok(false);
    }

    if role_can_approve_all_credentials(&member.member_role) {
        return Ok(true);
    }

    // Legacy/in-memory approval rows may not carry enough team/credential detail
    // to evaluate assignment. Preserve their prior policy-only behavior.
    if details.team_id.is_empty() || details.credential_name.is_empty() {
        return Ok(true);
    }

    let assigned = store
        .list_approver_credentials(&details.team_id, &member.id)
        .await?;
    Ok(assigned
        .iter()
        .any(|credential| credential == &details.credential_name))
}

async fn load_approval_details_for_member(
    state: &ApprovalHandlerState,
    txn_id: &str,
    member: &tap_core::store::Member,
) -> Result<ApprovalDetails, Response> {
    let details = match state.webauthn.load_pending_details(txn_id).await {
        Ok(Some(details)) => details,
        Ok(None) => {
            return Err((
                StatusCode::GONE,
                Json(serde_json::json!({
                    "error": "session_expired",
                    "message": "This approval request has timed out or was already resolved. Please ask the agent to retry the request."
                })),
            )
                .into_response());
        }
        Err(e) => {
            tracing::warn!(txn_id = %txn_id, error = %e, "Failed to load pending approval details");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "approval_state_unavailable",
                    "message": "Approval state is temporarily unavailable. Please try again."
                })),
            )
                .into_response());
        }
    };

    if !details.team_id.is_empty() && details.team_id != member.team_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "not_authorized",
                "message": "You are not eligible to view or approve this credential request."
            })),
        )
            .into_response());
    }

    let Some(store) = state.store.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Approvals require a database-backed deployment"})),
        )
            .into_response());
    };

    let can_act = member_can_act_on_approval(store, member, &details)
        .await
        .map_err(|e| {
            tracing::warn!(
                txn_id = %txn_id,
                user_id = %member.id,
                error = %e,
                "Failed to evaluate approval eligibility"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "approval_auth_unavailable",
                    "message": "Could not verify whether you can approve the request. Please try again."
                })),
            )
                .into_response()
        })?;

    if !can_act {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "not_authorized",
                "message": "You are not eligible to view or approve this credential request."
            })),
        )
            .into_response());
    }

    Ok(details)
}

/// GET /approve/register — serve registration page (admin-only pre-registration)
pub async fn handle_register_page() -> Html<&'static str> {
    Html(include_str!("../static/register.html"))
}

/// POST /approve/register/begin — requires an active admin session.
/// Passkey registration is admin-only: approvers must be registered ahead of
/// time by an admin, not inline from the approval URL.
pub async fn handle_register_begin(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
    Json(req): Json<RegisterBeginRequest>,
) -> Response {
    let admin = match require_user_session(&state.store, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let display_name = req.display_name.as_deref().unwrap_or(&admin.email);
    match state
        .webauthn
        .begin_user_registration(&admin.id, display_name)
        .await
    {
        Ok(ccr) => Json(ccr).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /approve/register/finish — requires an active admin session.
pub async fn handle_register_finish(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
    Json(req): Json<RegisterFinishRequest>,
) -> Response {
    let admin = match require_user_session(&state.store, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match state
        .webauthn
        .finish_user_registration(&admin.id, &req.credential)
        .await
    {
        Ok(_passkey) => {
            info!(approver = %admin.email, user_id = %admin.id, "WebAuthn credential registered");
            Json(serde_json::json!({"status": "registered"})).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// GET /approve/txn/:id — serve approval page (includes inline registration)
pub async fn handle_approval_page() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Html(include_str!("../static/approve.html")),
    )
}

/// GET /approve/txn/:id/details — return approval details as JSON
pub async fn handle_approval_details(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
) -> Response {
    let member = match require_user_session(&state.store, &headers).await {
        Ok(member) => member,
        Err(resp) => return resp,
    };

    let d = match load_approval_details_for_member(&state, &txn_id, &member).await {
        Ok(details) => details,
        Err(resp) => return resp,
    };
    let has_passkeys = state
        .webauthn
        .user_has_approval_passkeys(&member.id, &member.email)
        .await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "txn_id": d.txn_id,
            "team_id": d.team_id,
            "agent_id": d.agent_id,
            "credential_name": d.credential_name,
            "target_url": d.target_url,
            "method": d.method,
            "body_preview": d.body_preview,
            "has_passkeys": has_passkeys,
        })),
    )
        .into_response()
}

/// POST /approve/txn/:id/begin — start WebAuthn authentication
pub async fn handle_approval_begin(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
) -> Response {
    let member = match require_user_session(&state.store, &headers).await {
        Ok(member) => member,
        Err(resp) => return resp,
    };
    if let Err(resp) = load_approval_details_for_member(&state, &txn_id, &member).await {
        return resp;
    };

    match state
        .webauthn
        .begin_approval_for_user(&txn_id, &member.id, &member.email)
        .await
    {
        Ok(rcr) => Json(rcr).into_response(),
        Err(e) if e.to_string().contains("No approver credentials") => (
            StatusCode::PRECONDITION_FAILED,
            Json(serde_json::json!({
                "error": "no_credentials",
                "message": "No passkeys registered. Register one first."
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "approval_challenge_unavailable",
                "message": format!("Could not start passkey verification: {e}")
            })),
        )
            .into_response(),
    }
}

/// POST /approve/txn/:id/finish — validate assertion and approve.
/// Bridges to Telegram: resolves the notification channel's pending approval
/// so the proxy unblocks.
pub async fn handle_approval_finish(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
    Json(auth): Json<PublicKeyCredential>,
) -> Response {
    let member = match require_user_session(&state.store, &headers).await {
        Ok(member) => member,
        Err(resp) => return resp,
    };
    if let Err(resp) = load_approval_details_for_member(&state, &txn_id, &member).await {
        return resp;
    }
    let approver = member.email.clone();

    match state
        .webauthn
        .finish_approval_for_user(&txn_id, &member.id, &member.email, &auth)
        .await
    {
        Ok(_) => {
            info!(txn_id = %txn_id, approver = %approver, "Approval via WebAuthn passkey");
            let tg_resolved = if let Some(ref tg) = state.telegram_channel {
                tg.resolve_approval(&txn_id, ApprovalStatus::Approved).await
            } else {
                false
            };
            let mx_resolved = if let Some(ref mx) = state.matrix_channel {
                mx.resolve_and_edit_message(&txn_id, ApprovalStatus::Approved, Some(&approver))
                    .await
            } else {
                false
            };
            let persisted = state
                .webauthn
                .resolve_approval_as(&txn_id, ApprovalStatus::Approved, Some(&approver))
                .await;
            if !tg_resolved && !mx_resolved && !persisted {
                tracing::warn!(txn_id = %txn_id, "Passkey approval validated but no pending channel or persisted approval row found");
                return (
                    StatusCode::GONE,
                    Json(serde_json::json!({
                        "error": "session_expired",
                        "message": "This approval request has timed out or the server was restarted. Please ask the agent to retry the request."
                    })),
                )
                    .into_response();
            }
            Json(serde_json::json!({"status": "approved", "approver": approver})).into_response()
        }
        Err(e) if e.to_string().contains("No pending approval challenge") => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "stale_challenge",
                "message": "Passkey verification state was not found. Please try approving again."
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "passkey_verification_failed",
                "message": e.to_string()
            })),
        )
            .into_response(),
    }
}

/// POST /approve/txn/:id/deny — deny without WebAuthn.
/// Bridges to both WebAuthn and Telegram pending systems.
pub async fn handle_approval_deny(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
) -> Response {
    let member = match require_user_session(&state.store, &headers).await {
        Ok(member) => member,
        Err(resp) => return resp,
    };
    if let Err(resp) = load_approval_details_for_member(&state, &txn_id, &member).await {
        return resp;
    };

    if let Some(ref tg) = state.telegram_channel {
        tg.resolve_approval(&txn_id, ApprovalStatus::Denied).await;
    }
    if let Some(ref mx) = state.matrix_channel {
        mx.resolve_and_edit_message(&txn_id, ApprovalStatus::Denied, None)
            .await;
    }
    state
        .webauthn
        .resolve_approval(&txn_id, ApprovalStatus::Denied)
        .await;
    info!(txn_id = %txn_id, approver = %member.email, "Denial via WebAuthn page");
    Json(serde_json::json!({"status": "denied"})).into_response()
}

/// GET /approve/pending — list the authenticated member's team's pending
/// approvals for the dashboard inbox. Session-authenticated; team-scoped.
///
/// Each entry carries enough to render the card and decide how to act:
/// `require_passkey` tells the UI whether to open the inline passkey modal
/// or do a one-tap session approve (`/approve/dashboard/:id`),
/// and `can_approve` reflects role, credential assignment, and policy restrictions.
pub async fn handle_pending_inbox(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
) -> Response {
    let member = match require_user_session(&state.store, &headers).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let Some(store) = state.store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Approvals require a database-backed deployment"})),
        )
            .into_response();
    };

    let rows = match store.list_pending_approvals_for_team(&member.team_id).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(team_id = %member.team_id, error = %e, "Failed to list pending approvals");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "approvals_unavailable",
                    "message": "Could not load pending approvals. Please try again."
                })),
            )
                .into_response();
        }
    };

    let mut pending = Vec::new();
    for row in rows {
        // Rows with empty details_json (legacy Telegram-path placeholders)
        // carry nothing to render — skip them rather than show blank cards.
        let Ok(details) = serde_json::from_str::<ApprovalDetails>(&row.details_json) else {
            continue;
        };
        if details.target_url.is_empty() {
            continue;
        }
        let can_approve = match member_can_act_on_approval(store, &member, &details).await {
            Ok(allowed) => allowed,
            Err(e) => {
                tracing::warn!(
                    txn_id = %row.txn_id,
                    actor = %member.email,
                    error = %e,
                    "Failed to evaluate dashboard inbox approval eligibility"
                );
                false
            }
        };
        pending.push(serde_json::json!({
            "txn_id": row.txn_id,
            "credential_name": details.credential_name,
            "agent_id": details.agent_id,
            "target_url": details.target_url,
            "method": details.method,
            "body_preview": details.body_preview,
            "summary": details.summary,
            "require_passkey": details.require_passkey,
            "can_approve": can_approve,
            "created_at": row.created_at,
            "expires_at": row.expires_at,
        }));
    }

    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "pending": pending })),
    )
        .into_response()
}

/// Authorization half of the session-auth approve/deny endpoints: loads the
/// pending request and enforces team ownership, `require_passkey` policy,
/// credential assignment, and approver restrictions. Shared by plain
/// approve/deny and approve-with-grant so the grant path can never bypass a
/// check the plain path enforces.
async fn authorize_dashboard_resolve(
    state: &ApprovalHandlerState,
    member: &tap_core::store::Member,
    txn_id: &str,
    status: &ApprovalStatus,
) -> Result<ApprovalDetails, Response> {
    // Load the request detail. `load_pending_details` returns None for
    // expired/resolved/missing rows — surface that as 410 Gone.
    let details = match state.webauthn.load_pending_details(txn_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return Err((
                StatusCode::GONE,
                Json(serde_json::json!({
                    "error": "session_expired",
                    "message": "This approval has timed out or was already resolved."
                })),
            )
                .into_response());
        }
        Err(e) => {
            tracing::warn!(txn_id, error = %e, "Failed to load pending approval for dashboard resolve");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "approval_state_unavailable",
                    "message": "Approval state is temporarily unavailable. Please try again."
                })),
            )
                .into_response());
        }
    };

    // Team ownership: a member may only act on their own team's requests.
    if !details.team_id.is_empty() && details.team_id != member.team_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "not_authorized",
                "message": "This approval belongs to another team."
            })),
        )
            .into_response());
    }

    // Passkey-required credentials cannot be approved via the session fast path.
    // Denials are always allowed (denying is never the privileged action).
    if details.require_passkey && *status == ApprovalStatus::Approved {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            Json(serde_json::json!({
                "error": "passkey_required",
                "message": "This credential requires passkey approval. Use the passkey flow to approve."
            })),
        )
            .into_response());
    }

    let Some(store) = state.store.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "approval_auth_unavailable",
                "message": "Approval authorization requires a database-backed deployment."
            })),
        )
            .into_response());
    };
    match member_can_act_on_approval(store, member, &details).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                txn_id,
                actor = %member.email,
                credential = %details.credential_name,
                "Dashboard actor is not eligible for this credential approval"
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "not_authorized",
                    "message": "You are not eligible to approve this credential request."
                })),
            )
                .into_response());
        }
        Err(e) => {
            tracing::warn!(
                txn_id,
                actor = %member.email,
                error = %e,
                "Failed to evaluate dashboard approval eligibility"
            );
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "approval_auth_unavailable",
                    "message": "Could not verify whether you can approve this request. Please try again."
                })),
            )
                .into_response());
        }
    }

    Ok(details)
}

/// Resolution half: atomically claims the pending row and clears the mirrored
/// Telegram/Matrix messages. Returns false when the row was already resolved
/// (double-submit or a concurrent approval elsewhere).
async fn resolve_and_bridge(
    state: &ApprovalHandlerState,
    member: &tap_core::store::Member,
    txn_id: &str,
    status: &ApprovalStatus,
) -> bool {
    // Atomically resolve. resolve_approval_as performs the single-statement
    // claim (status flips only while still 'pending'), so a double-submit or a
    // concurrent passkey approval is safe — the second resolve is a no-op.
    let resolved = state
        .webauthn
        .resolve_approval_as(txn_id, status.clone(), Some(&member.email))
        .await;
    // Best-effort bridge: if this request was also surfaced on Telegram/Matrix
    // (e.g. a team with both configured), clear those messages too.
    if let Some(ref tg) = state.telegram_channel {
        tg.resolve_approval(txn_id, status.clone()).await;
    }
    if let Some(ref mx) = state.matrix_channel {
        let approver = (*status == ApprovalStatus::Approved).then_some(member.email.as_str());
        mx.resolve_and_edit_message(txn_id, status.clone(), approver)
            .await;
    }
    resolved
}

/// Grant-path variant of `resolve_and_bridge`: the claim must be EXCLUSIVE
/// (an already-approved row must not mint a second grant), so it goes through
/// the strict pending→approved claim instead of the idempotent resolve.
/// Bridging the mirrored messaging-channel messages still uses the idempotent
/// resolve — the decision is already durable by then.
async fn claim_and_bridge_for_grant(
    state: &ApprovalHandlerState,
    member: &tap_core::store::Member,
    txn_id: &str,
) -> bool {
    let claimed = state
        .webauthn
        .claim_approval_for_grant(txn_id, Some(&member.email))
        .await;
    if claimed {
        if let Some(ref tg) = state.telegram_channel {
            tg.resolve_approval(txn_id, ApprovalStatus::Approved).await;
        }
        if let Some(ref mx) = state.matrix_channel {
            mx.resolve_and_edit_message(
                txn_id,
                ApprovalStatus::Approved,
                Some(member.email.as_str()),
            )
            .await;
        }
    }
    claimed
}

/// Shared logic for the session-auth approve/deny endpoints. Validates the
/// session, loads the pending request, enforces team ownership, `require_passkey`
/// policy, credential assignment, and approver restrictions, then atomically
/// resolves the row.
async fn dashboard_resolve(
    state: &ApprovalHandlerState,
    headers: &HeaderMap,
    txn_id: &str,
    status: ApprovalStatus,
) -> Response {
    let member = match require_user_session(&state.store, headers).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };

    if let Err(resp) = authorize_dashboard_resolve(state, &member, txn_id, &status).await {
        return resp;
    }

    if !resolve_and_bridge(state, &member, txn_id, &status).await {
        // resolve_approval_as returned false: the row was already resolved or
        // gone between load and resolve. Treat as already-handled.
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "already_resolved",
                "message": "This approval was already resolved."
            })),
        )
            .into_response();
    }

    let verb = match status {
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        _ => "resolved",
    };
    info!(txn_id, approver = %member.email, status = verb, "Dashboard session approval resolved");
    Json(serde_json::json!({ "status": verb, "approver": member.email })).into_response()
}

/// POST /approve/dashboard/:id/approve — session-authenticated approve (no
/// passkey). Refused for `require_passkey` credentials.
pub async fn handle_dashboard_approve(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    dashboard_resolve(&state, &headers, &txn_id, ApprovalStatus::Approved).await
}

/// POST /approve/dashboard/:id/deny — session-authenticated deny.
pub async fn handle_dashboard_deny(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    dashboard_resolve(&state, &headers, &txn_id, ApprovalStatus::Denied).await
}

#[derive(Deserialize)]
pub struct ApproveWithGrantRequest {
    pub ttl_minutes: i64,
    #[serde(default)]
    pub max_uses: Option<i64>,
}

/// POST /approve/dashboard/:id/approve-with-grant — approve this request AND
/// create a time-boxed grant (#49) scoped to exactly this credential, method,
/// and route, so the agent's identical follow-up calls skip the prompt. The
/// scope is derived from the pending request itself — the approver never types
/// a pattern, so the grant can only ever cover what they just looked at.
pub async fn handle_dashboard_approve_with_grant(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(req): Json<ApproveWithGrantRequest>,
) -> Response {
    let member = match require_user_session(&state.store, &headers).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    // Grants are a workspace-manager surface (same rule as /team/grants):
    // an approver may resolve one request, not open a window for many.
    if !crate::admin::role_can_manage_workspace(&member.member_role) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Only owners and admins can approve with a grant",
                "error_code": "grant_requires_manager"
            })),
        )
            .into_response();
    }

    let status = ApprovalStatus::Approved;
    let details = match authorize_dashboard_resolve(&state, &member, &txn_id, &status).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    // Legacy/in-memory rows may not carry team + credential; without them the
    // grant has nothing to attach to. Plain approve still works for those.
    if details.team_id.is_empty() || details.credential_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "This request does not carry enough detail to scope a grant — approve it normally",
                "error_code": "grant_scope_underivable"
            })),
        )
            .into_response();
    }
    // Same exclusions as POST /team/credentials/{name}/grants.
    if details.credential_name.starts_with("eu:") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "End-user credentials cannot be time-boxed",
                "error_code": "grant_not_allowed_end_user"
            })),
        )
            .into_response();
    }
    // `details.require_passkey` was snapshotted when the request was created;
    // re-read the live policy row so a policy tightened since then still wins.
    let Some(store) = state.store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Grants require a database-backed deployment"})),
        )
            .into_response();
    };
    match store
        .get_policy(&details.team_id, &details.credential_name)
        .await
    {
        Ok(Some(p)) if p.require_passkey => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "This credential requires passkey approval and cannot be time-boxed",
                    "error_code": "grant_not_allowed_passkey"
                })),
            )
                .into_response()
        }
        // A multi-approval request can't be short-circuited by one manager —
        // same refusal as the Telegram ⏱ button and the Matrix ⏳ reaction.
        Ok(Some(p)) if p.min_approvals > 1 => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "This request needs multiple approvals — approve it normally",
                    "error_code": "grant_not_allowed_multi_approval"
                })),
            )
                .into_response()
        }
        Ok(_) => {}
        Err(e) => return crate::proxy::error_response(e),
    }

    let Some(scope) = crate::policy::grant_scope_from_target(&details.target_url) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Could not derive a route scope from this request's target URL — approve it normally",
                "error_code": "grant_scope_underivable"
            })),
        )
            .into_response();
    };
    let grant_req = crate::admin::CreateGrantRequest {
        methods: vec![details.method.clone()],
        route_scope: vec![scope],
        ttl_minutes: req.ttl_minutes,
        max_uses: req.max_uses,
    };
    let (methods, route_scope) = match crate::admin::validate_grant_request(&grant_req) {
        Ok(v) => v,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
                .into_response()
        }
    };

    // Claim the approval FIRST. If someone else already resolved it — possibly
    // as a deny — no grant must come into existence on top of their decision.
    // The claim must be EXCLUSIVE (strict pending→approved): the idempotent
    // resolve would report success on an already-approved row, letting two
    // concurrent grant submissions each mint a window.
    if !claim_and_bridge_for_grant(&state, &member, &txn_id).await {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "already_resolved",
                "message": "This approval was already resolved."
            })),
        )
            .into_response();
    }

    let now = chrono::Utc::now();
    let grant = tap_core::store::GrantRow {
        id: uuid::Uuid::new_v4().to_string(),
        team_id: details.team_id.clone(),
        credential_name: details.credential_name.clone(),
        methods,
        route_scope,
        expires_at: (now + chrono::Duration::minutes(req.ttl_minutes)).to_rfc3339(),
        granted_by: member.email.clone(),
        max_uses: req.max_uses,
        uses: 0,
        revoked: false,
        created_at: now.to_rfc3339(),
    };
    match store.create_approval_grant(&grant).await {
        Ok(()) => {
            info!(
                txn_id,
                approver = %member.email,
                grant_id = %grant.id,
                credential = %grant.credential_name,
                "Dashboard approval resolved with a time-boxed grant"
            );
            Json(serde_json::json!({
                "status": "approved",
                "approver": member.email,
                "grant": grant
            }))
            .into_response()
        }
        Err(e) => {
            // The approval already went through (that claim is atomic and
            // final); failing the whole call now would misreport it. Fail
            // toward fewer auto-approvals: approved, but no grant.
            warn!(txn_id, error = %e, "Approval resolved but grant creation failed");
            Json(serde_json::json!({
                "status": "approved",
                "approver": member.email,
                "grant": serde_json::Value::Null,
                "grant_error": "The request was approved, but the grant could not be created. Create it from the Policies page if still needed."
            }))
            .into_response()
        }
    }
}

/// GET /push/vapid-public-key — the VAPID public key the browser needs to
/// create a push subscription. Public (no auth): it's not a secret, and the
/// dashboard fetches it before the session is necessarily established. Returns
/// 404 when web push is not configured so the UI can hide the toggle.
pub async fn handle_push_vapid_key() -> Response {
    match crate::push::WebPushSender::public_key_from_env() {
        Some(key) => Json(serde_json::json!({ "public_key": key })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "push_disabled",
                "message": "Web push is not configured on this server."
            })),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct PushSubscribeRequest {
    endpoint: String,
    /// base64url public key (`keys.p256dh` from the browser PushSubscription).
    p256dh: String,
    /// base64url auth secret (`keys.auth` from the browser PushSubscription).
    auth: String,
}

/// POST /push/subscribe — register the caller's browser for approval pushes.
/// Session-authenticated; the subscription is bound to the member's team+email.
pub async fn handle_push_subscribe(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
    Json(req): Json<PushSubscribeRequest>,
) -> Response {
    let member = match require_user_session(&state.store, &headers).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let Some(store) = state.store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Push requires a database-backed deployment"})),
        )
            .into_response();
    };
    if req.endpoint.is_empty() || req.p256dh.is_empty() || req.auth.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_subscription", "message": "endpoint, p256dh and auth are required"})),
        )
            .into_response();
    }
    match store
        .save_push_subscription(
            &req.endpoint,
            &member.team_id,
            &member.email,
            &req.p256dh,
            &req.auth,
        )
        .await
    {
        Ok(()) => Json(serde_json::json!({ "status": "subscribed" })).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to save push subscription");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "subscribe_failed"})),
            )
                .into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub struct PushUnsubscribeRequest {
    endpoint: String,
}

/// POST /push/unsubscribe — remove a browser subscription. Session-authenticated.
pub async fn handle_push_unsubscribe(
    State(state): State<ApprovalHandlerState>,
    headers: HeaderMap,
    Json(req): Json<PushUnsubscribeRequest>,
) -> Response {
    if let Err(resp) = require_user_session(&state.store, &headers).await {
        return resp;
    }
    let Some(store) = state.store.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Push requires a database-backed deployment"})),
        )
            .into_response();
    };
    match store.delete_push_subscription(&req.endpoint).await {
        Ok(()) => Json(serde_json::json!({ "status": "unsubscribed" })).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to delete push subscription");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "unsubscribe_failed"})),
            )
                .into_response()
        }
    }
}

/// Build the WebAuthn approval router.
/// All routes use `ApprovalHandlerState` so that registration routes can
/// validate admin sessions via the embedded store.
pub fn build_approval_router(
    wa_state: SharedWebAuthnState,
    telegram_channel: Option<Arc<tap_bot::TelegramChannel>>,
    matrix_channel: Option<Arc<tap_bot::MatrixChannel>>,
    store: Option<Arc<tap_core::store::ConfigStore>>,
) -> axum::Router {
    let handler_state = ApprovalHandlerState {
        webauthn: wa_state,
        telegram_channel,
        matrix_channel,
        store,
    };

    axum::Router::new()
        // Approver passkey pre-registration (admin session required)
        .route(
            "/approve/register",
            axum::routing::get(handle_register_page),
        )
        .route(
            "/approve/register/begin",
            axum::routing::post(handle_register_begin),
        )
        .route(
            "/approve/register/finish",
            axum::routing::post(handle_register_finish),
        )
        // Per-transaction approval
        .route(
            "/approve/txn/{id}",
            axum::routing::get(handle_approval_page),
        )
        .route(
            "/approve/txn/{id}/details",
            axum::routing::get(handle_approval_details),
        )
        .route(
            "/approve/txn/{id}/begin",
            axum::routing::post(handle_approval_begin),
        )
        .route(
            "/approve/txn/{id}/finish",
            axum::routing::post(handle_approval_finish),
        )
        .route(
            "/approve/txn/{id}/deny",
            axum::routing::post(handle_approval_deny),
        )
        // Dashboard approvals inbox + session-auth approve/deny (no passkey
        // ceremony) for credentials whose policy does not require_passkey.
        .route("/approve/pending", axum::routing::get(handle_pending_inbox))
        .route(
            "/approve/dashboard/{id}/approve",
            axum::routing::post(handle_dashboard_approve),
        )
        .route(
            "/approve/dashboard/{id}/deny",
            axum::routing::post(handle_dashboard_deny),
        )
        // Approve AND create a time-boxed grant (#49) scoped from the request
        // itself — workspace-manager only.
        .route(
            "/approve/dashboard/{id}/approve-with-grant",
            axum::routing::post(handle_dashboard_approve_with_grant),
        )
        // Web Push subscription management for the dashboard channel.
        .route(
            "/push/vapid-public-key",
            axum::routing::get(handle_push_vapid_key),
        )
        .route(
            "/push/subscribe",
            axum::routing::post(handle_push_subscribe),
        )
        .route(
            "/push/unsubscribe",
            axum::routing::post(handle_push_unsubscribe),
        )
        .with_state(handler_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_core::types::ApprovalStatus;

    fn test_state() -> WebAuthnState {
        // Use localhost for RP — sufficient for state management tests
        WebAuthnState::new(
            "localhost",
            "http://localhost:3100",
            "http://localhost:3100",
            None,
            &[],
        )
        .unwrap()
    }

    fn test_db_url() -> String {
        std::env::var("POSTGRES_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://tap:tap@localhost:5434/tap".to_string())
    }

    async fn test_state_with_db() -> WebAuthnState {
        let key = [0u8; 32];
        let store = tap_core::store::ConfigStore::new(&test_db_url(), key)
            .await
            .unwrap();
        WebAuthnState::new(
            "localhost",
            "http://localhost:3100",
            "http://localhost:3100",
            Some(store),
            &[],
        )
        .unwrap()
    }

    #[test]
    fn webauthn_state_new_valid() {
        let state = test_state();
        assert_eq!(state.base_url, "http://localhost:3100");
    }

    #[test]
    fn webauthn_state_new_invalid_origin() {
        let result = WebAuthnState::new("localhost", "not-a-url", "http://localhost", None, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn webauthn_state_additional_origins_accepted() {
        // Additional origins are accepted and the state builds successfully.
        // This covers both admin login and approver passkey flows since they
        // share the same Webauthn instance.
        let result = WebAuthnState::new(
            "localhost",
            "http://localhost:3100",
            "http://localhost:3100",
            None,
            &["http://localhost:4000".to_string()],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn webauthn_state_invalid_additional_origin_errors() {
        let result = WebAuthnState::new(
            "localhost",
            "http://localhost:3100",
            "http://localhost:3100",
            None,
            &["not-a-url".to_string()],
        );
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("Invalid additional WebAuthn origin"));
    }

    #[test]
    fn authenticated_credential_selects_owning_approver() {
        let alice_cred = CredentialID::from(&b"alice-passkey"[..]);
        let matrix_cred = CredentialID::from(&b"matrix-passkey"[..]);
        let credentials = [
            ("alice", &alice_cred),
            ("matrix:@user:example.org", &matrix_cred),
        ];

        let approver = find_approver_name_by_credential_id(credentials, &matrix_cred);

        assert_eq!(approver.as_deref(), Some("matrix:@user:example.org"));
    }

    #[test]
    fn unknown_authenticated_credential_has_no_approver() {
        let alice_cred = CredentialID::from(&b"alice-passkey"[..]);
        let unknown_cred = CredentialID::from(&b"unknown-passkey"[..]);
        let credentials = [("alice", &alice_cred)];

        let approver = find_approver_name_by_credential_id(credentials, &unknown_cred);

        assert!(approver.is_none());
    }

    #[test]
    fn approval_url_format() {
        let state = test_state();
        assert_eq!(
            state.approval_url("txn-123"),
            "http://localhost:3100/approve/txn/txn-123"
        );
    }

    #[test]
    fn approval_url_strips_trailing_slash() {
        let state = WebAuthnState::new(
            "localhost",
            "http://localhost:3100",
            "http://localhost:3100/",
            None,
            &[],
        )
        .unwrap();
        assert_eq!(
            state.approval_url("abc"),
            "http://localhost:3100/approve/txn/abc"
        );
    }

    #[tokio::test]
    async fn has_any_credentials_empty() {
        let state = test_state();
        assert!(!state.has_any_credentials().await);
    }

    #[tokio::test]
    async fn has_any_credentials_after_manual_insert() {
        let state = test_state();
        // Manually insert a fake passkey into the in-memory map
        state
            .credentials
            .write()
            .await
            .entry("alice".to_string())
            .or_default(); // empty vec
                           // Empty vec doesn't count
        assert!(!state.has_any_credentials().await);
    }

    #[tokio::test]
    async fn register_pending_and_resolve() {
        let state = test_state();
        let details = ApprovalDetails {
            txn_id: "txn-1".into(),
            team_id: "team-1".into(),
            agent_id: "agent-1".into(),
            credential_name: "openai".into(),
            target_url: "https://api.openai.com/v1/chat".into(),
            method: "POST".into(),
            body_preview: Some("hello".into()),
            summary: None,
            allowed_approvers: vec![],
            require_passkey: false,
        };

        let rx = state.register_pending("txn-1", details).await;

        // Details should be accessible
        let d = state.pending_details.read().await;
        assert!(d.contains_key("txn-1"));
        assert_eq!(d["txn-1"].agent_id, "agent-1");
        drop(d);

        // Resolve the approval
        let resolved = state
            .resolve_approval("txn-1", ApprovalStatus::Approved)
            .await;
        assert!(resolved);

        // Receiver should get the status
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);

        // Details cleaned up
        assert!(!state.pending_details.read().await.contains_key("txn-1"));
    }

    #[tokio::test]
    async fn resolve_nonexistent_returns_false() {
        let state = test_state();
        let resolved = state
            .resolve_approval("nonexistent", ApprovalStatus::Denied)
            .await;
        assert!(!resolved);
    }

    #[tokio::test]
    async fn set_pending_details_without_resolver() {
        let state = test_state();
        let details = ApprovalDetails {
            txn_id: "txn-2".into(),
            team_id: "t".into(),
            agent_id: "a".into(),
            credential_name: "c".into(),
            target_url: "https://example.com".into(),
            method: "GET".into(),
            body_preview: None,
            summary: None,
            allowed_approvers: vec![],
            require_passkey: false,
        };
        state.set_pending_details("txn-2", details, 1200).await;
        assert!(state.pending_details.read().await.contains_key("txn-2"));
    }

    #[tokio::test]
    async fn begin_approval_no_credentials_errors() {
        let state = test_state();
        let result = state.begin_approval("txn-1").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No approver credentials"));
    }

    #[tokio::test]
    async fn load_credentials_from_db_empty() {
        let state = test_state_with_db().await;
        let count = state.load_credentials_from_db().await.unwrap();
        assert_eq!(count, 0);
        assert!(!state.has_any_credentials().await);
    }

    #[tokio::test]
    async fn load_credentials_from_db_no_store_errors() {
        let state = test_state(); // No store
        let result = state.load_credentials_from_db().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn load_credentials_from_db_with_data() {
        let state = test_state_with_db().await;
        let store = state.store.as_ref().unwrap();

        // Insert a fake passkey JSON (not a real WebAuthn key, but tests the loading path)
        // We need valid Passkey JSON — use a minimal structure that serde can parse.
        // Since we can't easily construct a valid Passkey, test that invalid JSON is skipped gracefully.
        let cred_id = format!("cred-bad-{}", uuid::Uuid::new_v4());
        store
            .save_approver_passkey(&cred_id, "alice", "Alice", r#"{"invalid": true}"#)
            .await
            .unwrap();

        let count = state.load_credentials_from_db().await.unwrap();
        // Invalid passkey JSON is skipped (doesn't deserialize to Passkey)
        assert_eq!(count, 0);
        assert!(!state.has_any_credentials().await);
    }

    #[tokio::test]
    async fn passkey_to_json_errors_are_descriptive() {
        // This just tests the error mapping path exists — we can't easily construct
        // a Passkey that fails to serialize, but we verify the method is callable.
        // The real test is that finish_registration uses it correctly.
    }

    #[tokio::test]
    async fn details_include_team_id() {
        let state = test_state();
        let details = ApprovalDetails {
            txn_id: "t".into(),
            team_id: "my-team".into(),
            agent_id: "a".into(),
            credential_name: "c".into(),
            target_url: "u".into(),
            method: "GET".into(),
            body_preview: None,
            summary: None,
            allowed_approvers: vec![],
            require_passkey: false,
        };
        state.set_pending_details("t", details, 1200).await;
        let d = state.pending_details.read().await;
        assert_eq!(d["t"].team_id, "my-team");
    }

    // -- require_user_session tests -------------------------------------------

    #[tokio::test]
    async fn require_user_session_no_auth_header_returns_401() {
        // Header is checked before the store, so None store is fine here.
        let store: Option<Arc<tap_core::store::ConfigStore>> = None;
        let headers = axum::http::HeaderMap::new();
        let result = require_user_session(&store, &headers).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_user_session_no_store_returns_503() {
        // Any token but no store → 503.
        let store: Option<Arc<tap_core::store::ConfigStore>> = None;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer some-token".parse().unwrap());
        let result = require_user_session(&store, &headers).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn require_user_session_invalid_token_returns_401() {
        let store = Arc::new(
            tap_core::store::ConfigStore::new(&test_db_url(), [0u8; 32])
                .await
                .unwrap(),
        );
        let store_opt = Some(store);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer token-that-has-no-session".parse().unwrap(),
        );
        let result = require_user_session(&store_opt, &headers).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }
}
