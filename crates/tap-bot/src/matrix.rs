//! Matrix approval channel implementing the ApprovalChannel trait.
//!
//! UX model: the bot posts an approval request message to a room, then a
//! sibling prompt "react ✅ to approve, ❌ to deny" (plus ⏳ to approve with a
//! 30-minute grant where one can be minted, #49). The sync loop watches
//! for `m.reaction` events whose `m.relates_to.event_id` matches a pending
//! request, and resolves the oneshot.
//!
//! Uses plain reqwest against the Client-Server API — no matrix-sdk dep.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tap_core::approval::{ApprovalChannel, ApprovalContext};
use tap_core::error::AgentSecError;
use tap_core::http_client::{build_client, ClientRoute};
use tap_core::store::ConfigStore;
use tap_core::types::{ApprovalStatus, ProxyRequest};
use tokio::sync::{oneshot, Mutex};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::MatrixConfig;

const APPROVE_REACTION: &str = "\u{2705}"; // ✅
const DENY_REACTION: &str = "\u{274c}"; // ❌
/// Approve AND open a 30-minute grant scoped to the reviewed request (#49).
const GRANT_REACTION: &str = "\u{23f3}"; // ⏳

/// Session trust key: (agent_id, credential_name)
type TrustKey = (String, String);

pub struct MatrixChannel {
    config: MatrixConfig,
    http: reqwest::Client,
    /// Pending approvals: channel_request_id -> oneshot sender
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<ApprovalStatus>>>>,
    /// Receivers held until wait_for_decision: channel_request_id -> oneshot receiver
    receivers: Arc<Mutex<HashMap<String, oneshot::Receiver<ApprovalStatus>>>>,
    /// Trusted sessions: (agent_id, credential_name) that have been trust-approved
    trusted_sessions: Arc<Mutex<HashMap<TrustKey, bool>>>,
    /// Per-request allowed approvers: channel_request_id -> list of allowed
    /// Matrix user IDs (`@alice:matrix.org`). Empty = anyone.
    allowed_approvers: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// Reverse lookup: request_message_event_id -> channel_request_id.
    /// Reactions target event IDs, not our request IDs, so we need to translate.
    event_to_request: Arc<Mutex<HashMap<String, String>>>,
    /// Sent message references: request_id -> (room_id, event_id) for edit-after-decision
    sent_messages: Arc<Mutex<HashMap<String, (String, String)>>>,
    /// N-of-M approval tracking: request_id -> (approved_count, min_needed).
    /// Only present for requests with min_approvals > 1.
    pending_approval_counts: Arc<Mutex<HashMap<String, (usize, usize)>>>,
    /// Optional DB store for persisting matrix state across restarts.
    store: Option<Arc<ConfigStore>>,
}

impl MatrixChannel {
    pub fn homeserver_url(&self) -> &str {
        &self.config.homeserver_url
    }

    /// Fetch the bot's own Matrix user ID via `/_matrix/client/v3/account/whoami`.
    /// Returns `None` if the request fails (logged as a warning).
    pub async fn fetch_user_id(&self) -> Option<String> {
        let url = format!(
            "{}/_matrix/client/v3/account/whoami",
            self.config.homeserver_url
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.config.access_token)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .ok()?;
        let body: serde_json::Value = resp.json().await.ok()?;
        body.get("user_id")?.as_str().map(str::to_string)
    }

    pub fn new(
        config: MatrixConfig,
        store: Option<Arc<ConfigStore>>,
    ) -> Result<Self, AgentSecError> {
        let http = build_client(ClientRoute::Direct)
            .map_err(|e| AgentSecError::Config(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            config,
            http,
            pending: Arc::new(Mutex::new(HashMap::new())),
            receivers: Arc::new(Mutex::new(HashMap::new())),
            trusted_sessions: Arc::new(Mutex::new(HashMap::new())),
            allowed_approvers: Arc::new(Mutex::new(HashMap::new())),
            event_to_request: Arc::new(Mutex::new(HashMap::new())),
            sent_messages: Arc::new(Mutex::new(HashMap::new())),
            pending_approval_counts: Arc::new(Mutex::new(HashMap::new())),
            store,
        })
    }

    async fn register_pending(&self, request_id: &str) {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id.to_string(), tx);
        self.receivers
            .lock()
            .await
            .insert(request_id.to_string(), rx);
    }

    async fn resolve_approval_as(
        &self,
        request_id: &str,
        status: ApprovalStatus,
        resolved_by: Option<&str>,
    ) -> bool {
        let mut db_resolved = false;
        if let Some(ref store) = self.store {
            let status_str = match &status {
                ApprovalStatus::Approved => "approved",
                ApprovalStatus::Denied => "denied",
                ApprovalStatus::Timeout => "expired",
                ApprovalStatus::Pending => "pending",
            };
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                store.resolve_pending_approval(request_id, status_str, resolved_by),
            )
            .await;
            match result {
                Ok(Ok(updated)) => db_resolved = updated,
                Ok(Err(e)) => {
                    warn!(request_id, error = %e, "Failed to persist Matrix approval resolution")
                }
                Err(_) => warn!(
                    request_id,
                    "Timed out persisting Matrix approval resolution"
                ),
            }
        }

        if let Some(tx) = self.pending.lock().await.remove(request_id) {
            self.allowed_approvers.lock().await.remove(request_id);
            self.pending_approval_counts.lock().await.remove(request_id);
            tx.send(status).is_ok() || db_resolved
        } else {
            db_resolved
        }
    }

    /// Resolve a pending approval. Used by tests and by the sync loop.
    pub async fn resolve_approval(&self, request_id: &str, status: ApprovalStatus) -> bool {
        self.resolve_approval_as(request_id, status, None).await
    }

    /// Exclusive pending→approved claim for the ⏳ grant reaction (#49).
    /// Unlike `resolve_approval_as` — which treats an already-resolved row or
    /// a live in-memory oneshot as success — a grant may only be minted on
    /// the actual durable pending→approved transition: the strict DB claim
    /// runs first, and the same-process waiter is signalled only after it
    /// succeeded (mirrors webauthn's `may_signal_memory = db_resolved`).
    async fn claim_approval_for_grant(
        &self,
        store: &Arc<ConfigStore>,
        request_id: &str,
        resolved_by: &str,
    ) -> bool {
        let db_resolved = match tokio::time::timeout(
            Duration::from_secs(5),
            store.claim_pending_approval_for_grant(request_id, Some(resolved_by)),
        )
        .await
        {
            Ok(Ok(updated)) => updated,
            Ok(Err(e)) => {
                warn!(request_id, error = %e, "Failed to claim Matrix approval for grant");
                false
            }
            Err(_) => {
                warn!(request_id, "Timed out claiming Matrix approval for grant");
                false
            }
        };
        if db_resolved {
            if let Some(tx) = self.pending.lock().await.remove(request_id) {
                self.allowed_approvers.lock().await.remove(request_id);
                self.pending_approval_counts.lock().await.remove(request_id);
                let _ = tx.send(ApprovalStatus::Approved);
            }
        }
        db_resolved
    }

    /// Resolve a pending approval AND edit the Matrix message to show the outcome.
    /// Used by the passkey handler so the room sees the same ✅/❌ update as a reaction.
    pub async fn resolve_and_edit_message(
        &self,
        request_id: &str,
        status: ApprovalStatus,
        approver: Option<&str>,
    ) -> bool {
        let msg_ref = self.sent_messages.lock().await.remove(request_id);
        let resolved_ref = if msg_ref.is_some() {
            msg_ref
        } else if let Some(ref store) = self.store {
            // DB fallback: fetch (room_id, event_id) from DB.
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                store.get_pending_approval_matrix_message(request_id),
            )
            .await;
            result.ok().and_then(|r| r.ok()).and_then(|v| v)
        } else {
            None
        };
        let message_found = if let Some((room_id, event_id)) = resolved_ref {
            let (status_emoji, status_word) = match &status {
                ApprovalStatus::Approved => ("\u{2705}", "APPROVED"),
                ApprovalStatus::Denied => ("\u{274c}", "DENIED"),
                _ => ("\u{2139}\u{fe0f}", "PROCESSED"),
            };
            let approver_info = approver.map(|a| format!(" by {a}")).unwrap_or_default();
            let plain = format!("{status_emoji} {status_word}{approver_info}");
            let html = format!(
                "<b>{status_emoji} {status_word}</b>{}",
                escape_html(&approver_info)
            );
            let _ = self
                .edit_matrix_message(&room_id, &event_id, &plain, &html)
                .await;
            true
        } else {
            false
        };
        self.resolve_approval_as(request_id, status, approver).await || message_found
    }

    /// The original approval message's (room_id, event_id) — in-memory first,
    /// then the DB (survives restarts / other-instance callbacks).
    async fn message_ref_for_request(&self, request_id: &str) -> Option<(String, String)> {
        let in_mem = self.sent_messages.lock().await.get(request_id).cloned();
        if in_mem.is_some() {
            return in_mem;
        }
        let store = self.store.as_ref()?;
        tokio::time::timeout(
            Duration::from_secs(5),
            store.get_pending_approval_matrix_message(request_id),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten()
    }

    /// Tell the room why a ⏳ grant reaction was refused. Matrix has no
    /// private toast, so this is a plain room message.
    async fn send_grant_refusal(&self, msg_ref: &Option<(String, String)>, text: &str) {
        if let Some((room_id, _)) = msg_ref {
            let _ = self
                .send_matrix_message(room_id, &escape_html(text), text)
                .await;
        }
    }

    /// Handle the ⏳ "approve for 30 min" reaction (#49): approve the request
    /// AND mint a time-boxed grant derived from it. Guardrails mirror the
    /// Telegram button and the dashboard endpoint — workspace managers only
    /// (resolved from the reactor's linked Matrix account), no passkey/`eu:`
    /// credentials, concrete derivable scope. Any refusal BEFORE the resolve
    /// leaves the request pending, so the human can still react ✅ normally.
    async fn handle_grant_reaction(
        &self,
        request_id: &str,
        user_id: Option<&str>,
        min_gt_one: bool,
    ) {
        let msg_ref = self.message_ref_for_request(request_id).await;

        let Some(store) = self.store.clone() else {
            self.send_grant_refusal(
                &msg_ref,
                "Time-boxed grants need a database-backed deployment — react ✅ to approve normally.",
            )
            .await;
            return;
        };
        let Some(uid) = user_id else {
            self.send_grant_refusal(
                &msg_ref,
                "Could not identify the reacting Matrix account — react ✅ to approve normally.",
            )
            .await;
            return;
        };
        // A multi-approval request can't be short-circuited by one manager.
        if min_gt_one {
            self.send_grant_refusal(
                &msg_ref,
                "This request needs multiple approvals — approve it normally.",
            )
            .await;
            return;
        }

        // Load the reviewed request's details BEFORE resolving — the pending
        // row stops being readable once it is resolved.
        let details_json = match store.get_pending_approval_details(request_id).await {
            Ok(Some(json)) => json,
            Ok(None) => {
                self.send_grant_refusal(&msg_ref, "This request is no longer pending.")
                    .await;
                return;
            }
            Err(e) => {
                warn!(request_id, error = %e, "Failed to load approval details for grant");
                self.send_grant_refusal(&msg_ref, "Could not load this request — try again.")
                    .await;
                return;
            }
        };
        let details: serde_json::Value = serde_json::from_str(&details_json).unwrap_or_default();
        let team_id = details["team_id"].as_str().unwrap_or_default().to_string();
        let credential_name = details["credential_name"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let method = details["method"].as_str().unwrap_or_default().to_string();
        let target_url = details["target_url"].as_str().unwrap_or_default().to_string();
        if team_id.is_empty()
            || credential_name.is_empty()
            || method.is_empty()
            || target_url.is_empty()
        {
            self.send_grant_refusal(
                &msg_ref,
                "This request doesn't carry enough detail for a grant — react ✅ to approve normally.",
            )
            .await;
            return;
        }

        // Grants are a workspace-manager surface (same rule as the dashboard):
        // an approver may resolve one request, not open a window for many.
        let member = match store.get_member_by_matrix_id(&team_id, uid).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                self.send_grant_refusal(
                    &msg_ref,
                    "Your Matrix account is not linked to a team member — link it in the dashboard first.",
                )
                .await;
                return;
            }
            Err(e) => {
                warn!(request_id, error = %e, "Failed to resolve Matrix user to a team member");
                self.send_grant_refusal(&msg_ref, "Could not verify your team role — try again.")
                    .await;
                return;
            }
        };
        if !matches!(member.member_role.as_str(), "owner" | "admin") {
            self.send_grant_refusal(
                &msg_ref,
                "Only owners and admins can approve with a grant — react ✅ to approve normally.",
            )
            .await;
            return;
        }

        // Claim the approval FIRST — a concurrent deny wins, and no grant may
        // come into existence on top of it. The claim must be EXCLUSIVE:
        // `resolve_approval_as` counts an already-resolved row (or a live
        // in-memory oneshot) as success, so two concurrent ⏳ reactions — or
        // one racing a dashboard deny — could both report "resolved" and mint
        // grants. Only the durable pending→approved transition may mint one.
        let resolved = self.claim_approval_for_grant(&store, request_id, uid).await;
        if !resolved {
            self.send_grant_refusal(&msg_ref, "Approval was not recorded — please try again.")
                .await;
            return;
        }

        let grant_result = tap_core::grants::create_grant_for_request(
            &store,
            &team_id,
            &credential_name,
            &method,
            &target_url,
            &member.email,
            tap_core::grants::GRANT_DEFAULT_TTL_MINUTES,
            None,
            chrono::Utc::now(),
        )
        .await;

        let (plain, html) = match &grant_result {
            Ok(grant) => {
                info!(
                    request_id,
                    grant_id = %grant.id,
                    approver = %member.email,
                    "Matrix approval resolved with a time-boxed grant"
                );
                let ttl = tap_core::grants::GRANT_DEFAULT_TTL_MINUTES;
                let scope = grant.route_scope.join(", ");
                let methods = grant.methods.join("/");
                (
                    format!(
                        "\u{2705} APPROVED for {ttl} min by {} — identical {methods} calls to {scope} skip approval until then. Revoke from the Policies page.",
                        member.email
                    ),
                    format!(
                        "<b>\u{2705} APPROVED for {ttl} min</b> by {} — identical {} calls to {} skip approval until then. Revoke from the Policies page.",
                        escape_html(&member.email),
                        escape_html(&methods),
                        escape_html(&scope)
                    ),
                )
            }
            Err(refused) => {
                // The approval already went through (that claim is atomic and
                // final). Fail toward fewer auto-approvals: approved, no window.
                warn!(request_id, reason = %refused.message(), "Approval resolved but Matrix grant was refused");
                (
                    format!(
                        "\u{2705} APPROVED by {} (no time-boxed window: {})",
                        member.email,
                        refused.message()
                    ),
                    format!(
                        "<b>\u{2705} APPROVED</b> by {} (no time-boxed window: {})",
                        escape_html(&member.email),
                        escape_html(&refused.message())
                    ),
                )
            }
        };

        // Stamp the outcome onto the original approval message.
        let final_ref = self.sent_messages.lock().await.remove(request_id).or(msg_ref);
        if let Some((room_id, event_id)) = final_ref {
            let _ = self
                .edit_matrix_message(&room_id, &event_id, &plain, &html)
                .await;
        }
    }

    pub async fn is_pending(&self, request_id: &str) -> bool {
        self.pending.lock().await.contains_key(request_id)
    }

    async fn cleanup_pending_request(&self, request_id: &str) {
        self.pending.lock().await.remove(request_id);
        self.allowed_approvers.lock().await.remove(request_id);
        self.pending_approval_counts.lock().await.remove(request_id);
    }

    async fn persisted_decision(&self, request_id: &str) -> Option<ApprovalStatus> {
        let store = self.store.as_ref()?;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            store.get_pending_approval_status(request_id),
        )
        .await;
        match result {
            Ok(Ok(Some(status))) => match status.as_str() {
                "approved" => Some(ApprovalStatus::Approved),
                "denied" => Some(ApprovalStatus::Denied),
                "expired" | "timed_out" | "timeout" => Some(ApprovalStatus::Timeout),
                "pending" => None,
                other => {
                    warn!(
                        request_id,
                        status = other,
                        "Unknown persisted approval status"
                    );
                    None
                }
            },
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                warn!(request_id, error = %e, "Failed to read persisted approval status");
                None
            }
            Err(_) => {
                warn!(request_id, "Timed out reading persisted approval status");
                None
            }
        }
    }

    pub async fn trust_session(&self, agent_id: &str, credential_name: &str) {
        self.trusted_sessions
            .lock()
            .await
            .insert((agent_id.to_string(), credential_name.to_string()), true);
    }

    pub async fn should_auto_trust(&self, agent_id: &str, credential_name: &str) -> bool {
        self.trusted_sessions
            .lock()
            .await
            .contains_key(&(agent_id.to_string(), credential_name.to_string()))
    }

    /// Handle a reaction event. `reaction_key` is the emoji/string the user
    /// reacted with; `target_event_id` is the event the reaction points at.
    pub async fn handle_reaction(
        &self,
        target_event_id: &str,
        reaction_key: &str,
        user_id: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let request_id = {
            let map = self.event_to_request.lock().await;
            match map.get(target_event_id) {
                Some(id) => id.clone(),
                None => {
                    // In-memory miss — try DB fallback (survives restart)
                    if self.store.is_none() {
                        warn!(
                            target_event_id,
                            "Matrix event_id not found in pending map and no DB configured — \
                             reply may have arrived before the approval message was stored, \
                             or the room may have E2E encryption enabled (encrypted messages \
                             are invisible to the bot; use ✅/❌ reactions instead)"
                        );
                    }
                    if let Some(ref store) = self.store {
                        let store = store.clone();
                        let target_event_id = target_event_id.to_string();
                        let reaction_key = reaction_key.to_string();
                        let user_id_owned = user_id.map(|s| s.to_string());
                        let self_clone = {
                            // We need a clone-able handle; use the individual Arc fields.
                            // We'll do the DB lookup inline since we're already holding &self.
                            drop(map); // release the lock before the async call
                            None::<()>
                        };
                        let _ = self_clone; // suppress warning
                        let lookup_result = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            store.get_pending_approval_by_matrix_event(&target_event_id),
                        )
                        .await;
                        if !matches!(lookup_result, Ok(Ok(Some(_)))) {
                            warn!(
                                target_event_id,
                                "Matrix event_id not found in DB either — \
                                 if the room has E2E encryption, replies are invisible; \
                                 use ✅/❌ reactions instead"
                            );
                        }
                        if let Ok(Ok(Some(data))) = lookup_result {
                            if data.status != "pending" {
                                return Ok(());
                            }
                            let status = match reaction_key.as_str() {
                                APPROVE_REACTION | GRANT_REACTION => ApprovalStatus::Approved,
                                DENY_REACTION => ApprovalStatus::Denied,
                                _ => return Ok(()),
                            };
                            // Check allowed approvers from DB.
                            if let Some(uid) = &user_id_owned {
                                if !data.allowed_approvers_json.is_empty()
                                    && data.allowed_approvers_json != "[]"
                                {
                                    let allowed: Vec<String> =
                                        serde_json::from_str(&data.allowed_approvers_json)
                                            .unwrap_or_default();
                                    if !allowed.is_empty() && !allowed.contains(uid) {
                                        warn!(
                                            request_id = %data.txn_id,
                                            user_id = %uid,
                                            "DB fallback: user not in allowed_approvers"
                                        );
                                        let _ = self.send_matrix_message(
                                            &data.room_id,
                                            &format!("{} is not authorised to approve or deny this request.", escape_html(uid)),
                                            &format!("{uid} is not authorised to approve or deny this request."),
                                        ).await;
                                        return Ok(());
                                    }
                                }
                            }
                            // ⏳ grant reaction, DB-fallback path (#49).
                            if reaction_key == GRANT_REACTION {
                                self.handle_grant_reaction(
                                    &data.txn_id,
                                    user_id_owned.as_deref(),
                                    data.min_approvals > 1,
                                )
                                .await;
                                return Ok(());
                            }
                            // Handle N-of-M via DB increment.
                            if matches!(status, ApprovalStatus::Approved) && data.min_approvals > 1
                            {
                                let inc_result = tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    store.increment_pending_approval_count(&data.txn_id),
                                )
                                .await;
                                if let Ok(Ok((new_count, min_needed))) = inc_result {
                                    if new_count < min_needed {
                                        info!(
                                            request_id = %data.txn_id,
                                            approved = new_count,
                                            needed = min_needed,
                                            user_id = user_id_owned.as_deref().unwrap_or("unknown"),
                                            "DB fallback: partial approval — waiting for more"
                                        );
                                        // Try to edit the Matrix message if in-memory has it.
                                        if let Some((room_id, event_id)) =
                                            self.sent_messages.lock().await.get(&data.txn_id)
                                        {
                                            let plain = format!(
                                                "{new_count}/{min_needed} approved — waiting for more approvals"
                                            );
                                            let html = format!(
                                                "<b>{new_count}/{min_needed} approved</b> — waiting for more approvals"
                                            );
                                            let _ = self
                                                .edit_matrix_message(
                                                    room_id, event_id, &plain, &html,
                                                )
                                                .await;
                                        } else {
                                            // Also try DB for the room/event_id.
                                            let plain = format!(
                                                "{new_count}/{min_needed} approved — waiting for more approvals"
                                            );
                                            let html = format!(
                                                "<b>{new_count}/{min_needed} approved</b> — waiting for more approvals"
                                            );
                                            let _ = self
                                                .edit_matrix_message(
                                                    &data.room_id,
                                                    &data.event_id,
                                                    &plain,
                                                    &html,
                                                )
                                                .await;
                                        }
                                        return Ok(());
                                    }
                                }
                            }
                            // Resolve via the in-memory pending map (request must still be in-flight).
                            let approver_info = user_id_owned
                                .as_deref()
                                .map(|u| format!(" by {u}"))
                                .unwrap_or_default();
                            let (status_emoji, status_word) = match &status {
                                ApprovalStatus::Approved => ("\u{2705}", "APPROVED"),
                                ApprovalStatus::Denied => ("\u{274c}", "DENIED"),
                                _ => ("\u{2139}\u{fe0f}", "PROCESSED"),
                            };
                            let plain = format!("{status_emoji} {status_word}{approver_info}");
                            let html = format!(
                                "<b>{status_emoji} {status_word}</b>{}",
                                escape_html(&approver_info)
                            );
                            // Edit the original message (use in-memory first, then DB).
                            let msg_ref = self.sent_messages.lock().await.remove(&data.txn_id);
                            let (edit_room, edit_event) = msg_ref
                                .unwrap_or_else(|| (data.room_id.clone(), data.event_id.clone()));
                            let _ = self
                                .edit_matrix_message(&edit_room, &edit_event, &plain, &html)
                                .await;
                            self.resolve_approval_as(
                                &data.txn_id,
                                status,
                                user_id_owned.as_deref(),
                            )
                            .await;
                            info!(
                                request_id = %data.txn_id,
                                "Matrix reaction processed via DB fallback"
                            );
                        }
                    }
                    return Ok(());
                }
            }
        };

        let status = match reaction_key {
            APPROVE_REACTION | GRANT_REACTION => ApprovalStatus::Approved,
            DENY_REACTION => ApprovalStatus::Denied,
            _ => return Ok(()),
        };

        if let Some(uid) = user_id {
            let not_authorized = {
                let approvers = self.allowed_approvers.lock().await;
                approvers.get(&request_id).is_some_and(|allowed| {
                    !allowed.is_empty() && !allowed.contains(&uid.to_string())
                })
            };
            if not_authorized {
                warn!(
                    request_id,
                    user_id = uid,
                    "User not in allowed_approvers list"
                );
                let _ = self.notify_unauthorized(&request_id, uid).await;
                return Ok(());
            }
        }

        // ⏳ "approve for 30 min" (#49): own path — it needs the pending row's
        // details and the reactor's workspace role before resolving.
        if reaction_key == GRANT_REACTION {
            let min_gt_one = self
                .pending_approval_counts
                .lock()
                .await
                .contains_key(&request_id);
            self.handle_grant_reaction(&request_id, user_id, min_gt_one)
                .await;
            self.event_to_request.lock().await.remove(target_event_id);
            return Ok(());
        }

        // For Approved reactions, check if N-of-M threshold is in effect.
        if matches!(status, ApprovalStatus::Approved) {
            let mut counts = self.pending_approval_counts.lock().await;
            if let Some((approved_count, min_needed)) = counts.get_mut(&request_id) {
                *approved_count += 1;
                let current = *approved_count;
                let needed = *min_needed;
                if current < needed {
                    // Not enough approvals yet — update the message and wait for more.
                    info!(
                        request_id,
                        approved = current,
                        needed,
                        user_id = user_id.unwrap_or("unknown"),
                        "Partial approval — waiting for more"
                    );
                    if let Some((room_id, event_id)) =
                        self.sent_messages.lock().await.get(&request_id)
                    {
                        let plain =
                            format!("{current}/{needed} approved — waiting for more approvals");
                        let html = format!(
                            "<b>{current}/{needed} approved</b> — waiting for more approvals"
                        );
                        let _ = self
                            .edit_matrix_message(room_id, event_id, &plain, &html)
                            .await;
                    }
                    return Ok(());
                }
                // Threshold met — remove from count map and proceed to resolve.
                counts.remove(&request_id);
            }
        }

        if let Some((room_id, event_id)) = self.sent_messages.lock().await.remove(&request_id) {
            let (status_emoji, status_word) = match &status {
                ApprovalStatus::Approved => ("\u{2705}", "APPROVED"),
                ApprovalStatus::Denied => ("\u{274c}", "DENIED"),
                _ => ("\u{2139}\u{fe0f}", "PROCESSED"),
            };
            let approver_info = user_id.map(|u| format!(" by {u}")).unwrap_or_default();
            let plain = format!("{status_emoji} {status_word}{approver_info}");
            let html = format!(
                "<b>{status_emoji} {status_word}</b>{}",
                escape_html(&approver_info)
            );
            let _ = self
                .edit_matrix_message(&room_id, &event_id, &plain, &html)
                .await;
        }

        let resolved = self
            .resolve_approval_as(&request_id, status.clone(), user_id)
            .await;
        self.event_to_request.lock().await.remove(target_event_id);
        if !resolved {
            warn!(
                request_id,
                "Approval receiver already dropped or pending row was missing"
            );
        }

        info!(request_id, ?status, "Matrix reaction processed");
        Ok(())
    }

    /// Start a long-polling sync loop. Spawns a background tokio task.
    /// Mirrors `TelegramChannel::start_polling`.
    ///
    /// Uses a filtered sync restricted to the configured room and
    /// `m.reaction` events only, so payloads stay small. On the first
    /// request (no `since` token) we discard events and only capture
    /// `next_batch` — this prevents re-processing historical reactions
    /// on bot restart.
    pub fn start_syncing(self: &Arc<Self>) {
        let channel = self.clone();
        tokio::spawn(async move {
            let filter = build_reaction_filter(&channel.config.room_id);
            let filter_encoded = urlencoding_encode(&filter);
            let mut since: Option<String> = None;
            info!("Matrix sync loop started");
            loop {
                let is_initial = since.is_none();
                let mut url = format!(
                    "{}/_matrix/client/v3/sync?timeout=30000&filter={}",
                    channel.config.homeserver_url, filter_encoded,
                );
                if let Some(ref token) = since {
                    url.push_str(&format!("&since={token}"));
                }

                let resp = match channel
                    .http
                    .get(&url)
                    .bearer_auth(&channel.config.access_token)
                    .timeout(Duration::from_secs(35))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Matrix sync error: {e}");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };

                let body: serde_json::Value = match resp.json().await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Matrix sync parse error: {e}");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };

                if let Some(next) = body.get("next_batch").and_then(|v| v.as_str()) {
                    since = Some(next.to_string());
                }

                // Auto-accept any pending invites, even on the initial sync.
                for room_id in parse_invites(&body) {
                    info!(%room_id, "Accepting Matrix room invite");
                    if let Err(e) = channel.join_room(&room_id).await {
                        warn!(error = %e, %room_id, "Failed to join invited room");
                    }
                }

                if is_initial {
                    // Discard backlog — only dispatch events from requests
                    // made AFTER we have a baseline since-token.
                    continue;
                }

                for reaction in parse_reactions(&body) {
                    if let Err(e) = channel
                        .handle_reaction(
                            &reaction.target_event_id,
                            &reaction.reaction_key,
                            Some(&reaction.sender),
                        )
                        .await
                    {
                        warn!(error = %e, "Matrix reaction handling failed");
                    }
                }

                for reply in parse_text_replies(&body) {
                    let key = if reply.approve {
                        APPROVE_REACTION
                    } else {
                        DENY_REACTION
                    };
                    if let Err(e) = channel
                        .handle_reaction(&reply.in_reply_to, key, Some(&reply.sender))
                        .await
                    {
                        warn!(error = %e, "Matrix text reply handling failed");
                    }
                }
            }
        });
    }

    /// Send the approval-request message. Returns the Matrix event_id of the
    /// posted message, which is what reactions will target.
    /// Join a room (accepts a pending invite or rejoins after kick/leave).
    async fn join_room(&self, room_id: &str) -> Result<(), AgentSecError> {
        let url = format!(
            "{}/_matrix/client/v3/join/{}",
            self.config.homeserver_url,
            urlencoding_encode(room_id),
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.config.access_token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| AgentSecError::Internal(format!("Matrix join error: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(AgentSecError::Internal(format!(
                "Matrix join {room_id} returned {status}: {body}"
            )));
        }
        info!(%room_id, "Joined Matrix room");
        Ok(())
    }

    async fn send_matrix_message(
        &self,
        room_id: &str,
        html_body: &str,
        plain_body: &str,
    ) -> Result<String, AgentSecError> {
        match self
            .send_matrix_message_inner(room_id, html_body, plain_body)
            .await
        {
            Ok(id) => Ok(id),
            Err(e)
                if {
                    let s = e.to_string();
                    s.contains("403") && s.contains("not in room")
                } =>
            {
                info!(%room_id, "Bot not in room — joining and retrying");
                self.join_room(room_id).await?;
                self.send_matrix_message_inner(room_id, html_body, plain_body)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    async fn send_matrix_message_inner(
        &self,
        room_id: &str,
        html_body: &str,
        plain_body: &str,
    ) -> Result<String, AgentSecError> {
        let txn_id = Uuid::new_v4().to_string();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.config.homeserver_url,
            urlencoding_encode(room_id),
            txn_id,
        );

        let payload = serde_json::json!({
            "msgtype": "m.text",
            "body": plain_body,
            "format": "org.matrix.custom.html",
            "formatted_body": html_body,
        });

        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.config.access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AgentSecError::Internal(format!("Matrix send error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            error!(%status, %body, "Matrix send failed");
            return Err(AgentSecError::Internal(format!(
                "Matrix API returned {status}: {body}"
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AgentSecError::Internal(format!("Matrix send parse error: {e}")))?;
        body.get("event_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| AgentSecError::Internal("Matrix response missing event_id".to_string()))
    }

    /// Edit an existing message in place (m.replace) — used to stamp
    /// APPROVED / DENIED onto the original approval-request message.
    async fn edit_matrix_message(
        &self,
        room_id: &str,
        original_event_id: &str,
        new_plain: &str,
        new_html: &str,
    ) -> Result<(), AgentSecError> {
        let txn_id = Uuid::new_v4().to_string();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.config.homeserver_url,
            urlencoding_encode(room_id),
            txn_id,
        );

        let payload = serde_json::json!({
            "msgtype": "m.text",
            "body": format!("* {new_plain}"),
            "format": "org.matrix.custom.html",
            "formatted_body": new_html,
            "m.new_content": {
                "msgtype": "m.text",
                "body": new_plain,
                "format": "org.matrix.custom.html",
                "formatted_body": new_html,
            },
            "m.relates_to": {
                "rel_type": "m.replace",
                "event_id": original_event_id,
            },
        });

        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.config.access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AgentSecError::Internal(format!("Matrix edit error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            return Err(AgentSecError::Internal(format!(
                "Matrix edit returned {status}: {body}"
            )));
        }
        Ok(())
    }

    /// Send a threaded reply (uses `m.relates_to` with `m.thread`) — used for
    /// the decision status message after approval/denial.
    #[allow(dead_code)]
    async fn send_threaded_reply(
        &self,
        room_id: &str,
        parent_event_id: &str,
        text: &str,
    ) -> Result<(), AgentSecError> {
        let txn_id = Uuid::new_v4().to_string();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
            self.config.homeserver_url,
            urlencoding_encode(room_id),
            txn_id,
        );

        let payload = serde_json::json!({
            "msgtype": "m.text",
            "body": text,
            "m.relates_to": {
                "rel_type": "m.thread",
                "event_id": parent_event_id,
            },
        });

        self.http
            .put(&url)
            .bearer_auth(&self.config.access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AgentSecError::Internal(format!("Matrix threaded reply error: {e}")))?;
        Ok(())
    }
}

/// Format a human-readable approval message (HTML + plain-text fallback).
pub fn format_messages(
    request: &ProxyRequest,
    credential_description: &str,
    context: &ApprovalContext,
) -> (String, String) {
    let mut html = String::new();
    let mut plain = String::new();

    html.push_str("<b>\u{1f511} Approval Request</b><br><br>");
    plain.push_str("🔑 Approval Request\n\n");

    // Deterministic one-line summary for recognized services (tap-core).
    if let Some(summary) = tap_core::summary::summarize_request(
        &request.target_url,
        &request.method,
        request.body.as_deref(),
    ) {
        html.push_str(&format!("<b>Action:</b> {}<br>", escape_html(&summary)));
        plain.push_str(&format!("Action: {summary}\n"));
    }

    html.push_str(&format!(
        "<b>Agent:</b> {}<br>",
        escape_html(&request.agent_id)
    ));
    plain.push_str(&format!("Agent: {}\n", request.agent_id));

    for placeholder in &request.placeholders {
        html.push_str(&format!(
            "<b>Credential:</b> {}<br>",
            escape_html(&placeholder.credential_name)
        ));
        plain.push_str(&format!("Credential: {}\n", placeholder.credential_name));
    }

    html.push_str(&format!(
        "<b>Description:</b> {}<br>",
        escape_html(credential_description)
    ));
    plain.push_str(&format!("Description: {credential_description}\n"));

    html.push_str(&format!("<b>Method:</b> {:?}<br>", request.method));
    plain.push_str(&format!("Method: {:?}\n", request.method));

    html.push_str(&format!(
        "<b>Target:</b> {}<br>",
        escape_html(&request.target_url)
    ));
    plain.push_str(&format!("Target: {}\n", request.target_url));

    if let Some(body) = &request.body {
        if let Ok(body_str) = std::str::from_utf8(body) {
            let truncated = if body_str.len() > 1500 {
                format!("{}...", &body_str[..1500])
            } else {
                body_str.to_string()
            };
            html.push_str(&format!(
                "<br><b>Body:</b><br><pre>{}</pre>",
                escape_html(&truncated)
            ));
            plain.push_str(&format!("\nBody:\n{truncated}\n"));
        }
    }

    if context.require_passkey {
        if let Some(url) = &context.approval_url {
            html.push_str(&format!(
                "<br><br>\u{1f510} <b>Passkey required.</b> <a href=\"{}\">Tap here to approve with biometric/YubiKey.</a> React \u{274c} or reply <b>deny</b> to reject.",
                escape_html(url)
            ));
            plain.push_str(&format!(
                "\n\n🔐 Passkey required: {url}\nReact ❌ or reply 'deny' to reject."
            ));
        } else {
            html.push_str(
                "<br><br>\u{1f510} <b>Passkey required</b> but no approval URL configured.",
            );
            plain.push_str("\n\n🔐 Passkey required but no approval URL configured.");
        }
    } else if let Some(url) = &context.approval_url {
        html.push_str(&format!(
            "<br><br><a href=\"{}\">Secure approval (biometric/YubiKey)</a> — or react \u{2705}/\u{274c} or reply <b>approve</b>/<b>deny</b>.",
            escape_html(url)
        ));
        plain.push_str(&format!(
            "\n\nSecure approval: {url}\nOr react ✅/❌ or reply 'approve'/'deny'."
        ));
    } else {
        let min_approvals = context
            .routing
            .as_ref()
            .map(|r| r.min_approvals.max(1))
            .unwrap_or(1);
        if min_approvals > 1 {
            html.push_str(&format!(
                "<br><br>React \u{2705}/\u{274c} or reply <b>approve</b>/<b>deny</b> (requires {min_approvals} approvals)."
            ));
            plain.push_str(&format!(
                "\n\nReact ✅/❌ or reply 'approve'/'deny' (requires {min_approvals} approvals)."
            ));
        } else {
            html.push_str("<br><br>React \u{2705}/\u{274c} or reply <b>approve</b>/<b>deny</b>.");
            plain.push_str("\n\nReact ✅/❌ or reply 'approve'/'deny'.");
        }
    }

    (html, plain)
}

/// A reaction event extracted from a Matrix `/sync` response.
#[derive(Debug, PartialEq)]
struct ReactionEvent {
    target_event_id: String,
    reaction_key: String,
    sender: String,
}

/// Walk a `/sync` response body and pull out every `m.reaction` event in
/// any joined room. Silently skips malformed or unrelated events.
fn parse_reactions(sync_body: &serde_json::Value) -> Vec<ReactionEvent> {
    let mut out = Vec::new();
    let Some(rooms) = sync_body.pointer("/rooms/join").and_then(|v| v.as_object()) else {
        return out;
    };
    for (_room_id, room) in rooms {
        let Some(events) = room.pointer("/timeline/events").and_then(|v| v.as_array()) else {
            continue;
        };
        for event in events {
            if event.get("type").and_then(|v| v.as_str()) != Some("m.reaction") {
                continue;
            }
            let Some(relates) = event.pointer("/content/m.relates_to") else {
                continue;
            };
            // Reactions MUST be annotations per MSC2677 — skip edits/replies etc.
            if relates.get("rel_type").and_then(|v| v.as_str()) != Some("m.annotation") {
                continue;
            }
            let Some(target_event_id) = relates.get("event_id").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(reaction_key) = relates.get("key").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(sender) = event.get("sender").and_then(|v| v.as_str()) else {
                continue;
            };
            out.push(ReactionEvent {
                target_event_id: target_event_id.to_string(),
                reaction_key: reaction_key.to_string(),
                sender: sender.to_string(),
            });
        }
    }
    out
}

/// Walk a `/sync` response body and return the room IDs the bot has been invited to.
fn parse_invites(sync_body: &serde_json::Value) -> Vec<String> {
    sync_body
        .pointer("/rooms/invite")
        .and_then(|v| v.as_object())
        .map(|rooms| rooms.keys().cloned().collect())
        .unwrap_or_default()
}

struct TextReply {
    /// event_id of the message being replied to
    in_reply_to: String,
    sender: String,
    approve: bool,
}

/// Walk a `/sync` response and extract text replies that say "approve"/"deny".
fn parse_text_replies(sync_body: &serde_json::Value) -> Vec<TextReply> {
    let mut out = Vec::new();
    let Some(rooms) = sync_body.pointer("/rooms/join").and_then(|v| v.as_object()) else {
        return out;
    };
    for (_room_id, room) in rooms {
        let Some(events) = room.pointer("/timeline/events").and_then(|v| v.as_array()) else {
            continue;
        };
        for event in events {
            if event.get("type").and_then(|v| v.as_str()) != Some("m.room.message") {
                continue;
            }
            let msgtype = event
                .pointer("/content/msgtype")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if msgtype != "m.text" {
                continue;
            }
            let Some(body) = event.pointer("/content/body").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(sender) = event.get("sender").and_then(|v| v.as_str()) else {
                continue;
            };

            // Determine the target event ID this reply addresses.
            // Thread replies (rel_type: "m.thread"): use the thread root event_id — that
            // is the TAP approval message, regardless of which reply in the thread the
            // user directly replied to.
            // Quote replies (m.in_reply_to): use m.in_reply_to/event_id.
            let relates_to = event.pointer("/content/m.relates_to");
            let rel_type = relates_to
                .and_then(|r| r.get("rel_type"))
                .and_then(|v| v.as_str());
            let in_reply_to = if rel_type == Some("m.thread") {
                relates_to
                    .and_then(|r| r.get("event_id"))
                    .and_then(|v| v.as_str())
            } else {
                relates_to
                    .and_then(|r| r.pointer("/m.in_reply_to/event_id"))
                    .and_then(|v| v.as_str())
            };
            let Some(in_reply_to) = in_reply_to else {
                continue;
            };

            // Matrix quote-reply clients (Element etc.) include the original message as
            // "> " prefixed lines before the actual reply text, separated by a blank line:
            //   > <@bot:server> Approval Request
            //   > ...
            //
            //   approve
            // Strip that prefix before matching so "approve" is recognised.
            let effective = strip_matrix_quote_prefix(body);
            let trimmed = effective.trim().to_lowercase();
            let approve = matches!(trimmed.as_str(), "approve" | "yes" | "y");
            let deny = matches!(trimmed.as_str(), "deny" | "no" | "n");
            if approve || deny {
                out.push(TextReply {
                    in_reply_to: in_reply_to.to_string(),
                    sender: sender.to_string(),
                    approve,
                });
            }
        }
    }
    out
}

/// Strip the Matrix quote-reply fallback prefix from a message body.
///
/// Quote replies prepend the original message as `> `-prefixed lines followed
/// by a blank line before the actual reply text.  We find the last `\n\n`
/// separator that follows quoted lines and return only the text after it.
fn strip_matrix_quote_prefix(body: &str) -> &str {
    if let Some(pos) = body.rfind("\n\n") {
        let before = &body[..pos];
        // Only strip if the content before the separator contains at least one
        // ">" line — confirming this is actually a quote-reply block.
        if before.lines().any(|l| l.starts_with('>')) {
            return &body[pos + 2..];
        }
    }
    body
}

/// Build a sync filter for reactions and text replies. No "rooms" allowlist
/// so invite events from any room flow through for auto-accept.
fn build_reaction_filter(_room_id: &str) -> String {
    serde_json::json!({
        "presence": { "types": [] },
        "account_data": { "types": [] },
        "room": {
            "timeline": { "types": ["m.reaction", "m.room.message"], "limit": 50 },
            "state": { "types": [] },
            "ephemeral": { "types": [] },
            "account_data": { "types": [] },
        },
    })
    .to_string()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Percent-encode a Matrix room ID for inclusion in a URL path.
/// Room IDs contain `!` and `:` which must be encoded.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[async_trait::async_trait]
impl ApprovalChannel for MatrixChannel {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        credential_description: &str,
        context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        let channel_request_id = request.id.to_string();

        self.register_pending(&channel_request_id).await;

        if let Some(routing) = &context.routing {
            // Prefer matrix-specific approvers; fall back to generic allowed_approvers.
            let approvers = routing
                .matrix
                .as_ref()
                .filter(|m| !m.allowed_approvers.is_empty())
                .map(|m| m.allowed_approvers.clone())
                .or_else(|| {
                    if !routing.allowed_approvers.is_empty() {
                        Some(routing.allowed_approvers.clone())
                    } else {
                        None
                    }
                });
            if let Some(list) = approvers {
                self.allowed_approvers
                    .lock()
                    .await
                    .insert(channel_request_id.clone(), list);
            }

            // Initialize N-of-M tracking if min_approvals > 1.
            let min_approvals = routing.min_approvals.max(1) as usize;
            if min_approvals > 1 {
                self.pending_approval_counts
                    .lock()
                    .await
                    .insert(channel_request_id.clone(), (0, min_approvals));
            }
        }

        // Per-credential room override (mirrors telegram.chat_id).
        let room_id = context
            .routing
            .as_ref()
            .and_then(|r| r.matrix.as_ref())
            .and_then(|m| m.room_id.clone())
            .unwrap_or_else(|| self.config.room_id.clone());

        let (mut html, mut plain) = format_messages(request, credential_description, context);

        // Advertise the ⏳ grant reaction only where a grant can actually be
        // minted: DB-backed deployment, a team-owned non-end-user credential,
        // single-approval flow, no passkey requirement, and a target URL a
        // concrete scope can be derived from. The reaction handler re-checks
        // all of it (defense-in-depth) — this just avoids advertising a
        // gesture that can only fail.
        let min_approvals = context
            .routing
            .as_ref()
            .map(|r| r.min_approvals.max(1))
            .unwrap_or(1);
        let offer_grant = self.store.is_some()
            && !context.require_passkey
            && context.end_user_id.is_none()
            && context.team_id.as_deref().is_some_and(|t| !t.is_empty())
            && !context.credential_name.is_empty()
            && !context.credential_name.starts_with("eu:")
            && min_approvals <= 1
            && tap_core::grants::scope_from_target(&request.target_url).is_some();
        if offer_grant {
            let ttl = tap_core::grants::GRANT_DEFAULT_TTL_MINUTES;
            html.push_str(&format!(
                " Or react \u{23f3} to approve for {ttl} min (owners/admins)."
            ));
            plain.push_str(&format!(
                " Or react ⏳ to approve for {ttl} min (owners/admins)."
            ));
        }

        let event_id = match self.send_matrix_message(&room_id, &html, &plain).await {
            Ok(id) => id,
            Err(e) => {
                self.pending.lock().await.remove(&channel_request_id);
                self.receivers.lock().await.remove(&channel_request_id);
                self.allowed_approvers
                    .lock()
                    .await
                    .remove(&channel_request_id);
                return Err(e);
            }
        };

        self.sent_messages.lock().await.insert(
            channel_request_id.clone(),
            (room_id.clone(), event_id.clone()),
        );
        self.event_to_request
            .lock()
            .await
            .insert(event_id.clone(), channel_request_id.clone());

        // Persist to DB so reactions survive a proxy restart.
        if let Some(store) = self.store.clone() {
            let txn_id2 = channel_request_id.clone();
            let room_id2 = room_id.clone();
            let event_id2 = event_id.clone();
            // Collect the allowed approvers list for this request.
            let allowed_list = self
                .allowed_approvers
                .lock()
                .await
                .get(&channel_request_id)
                .cloned()
                .unwrap_or_default();
            let allowed_json =
                serde_json::to_string(&allowed_list).unwrap_or_else(|_| "[]".to_string());
            let min = context
                .routing
                .as_ref()
                .map(|r| r.min_approvals.max(1) as usize)
                .unwrap_or(1);
            if let Err(e) = store
                .set_pending_approval_matrix_data(
                    &txn_id2,
                    &room_id2,
                    &event_id2,
                    &allowed_json,
                    min,
                )
                .await
            {
                warn!(
                    request_id = %txn_id2,
                    error = %e,
                    "Failed to persist Matrix approval message metadata"
                );
            }
        }

        info!(
            request_id = %channel_request_id,
            agent_id = %request.agent_id,
            credential = %context.credential_name,
            %room_id,
            %event_id,
            "Approval request sent to Matrix"
        );

        Ok(channel_request_id)
    }

    async fn wait_for_decision(
        &self,
        channel_request_id: &str,
        timeout_seconds: u64,
    ) -> Result<ApprovalStatus, AgentSecError> {
        let rx = self
            .receivers
            .lock()
            .await
            .remove(channel_request_id)
            .ok_or_else(|| {
                AgentSecError::Internal(format!(
                    "No pending receiver for request {channel_request_id}"
                ))
            })?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);
        let timeout_sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(timeout_sleep);
        tokio::pin!(rx);
        let mut db_poll = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                result = &mut rx => {
                    return match result {
                        Ok(status) => Ok(status),
                        Err(_) => Err(AgentSecError::Internal(
                            "Approval sender dropped".to_string(),
                        )),
                    };
                }
                _ = db_poll.tick(), if self.store.is_some() => {
                    if let Some(status) = self.persisted_decision(channel_request_id).await {
                        self.cleanup_pending_request(channel_request_id).await;
                        return Ok(status);
                    }
                }
                _ = &mut timeout_sleep => {
                    self.cleanup_pending_request(channel_request_id).await;
                    return Err(AgentSecError::ApprovalTimeout(timeout_seconds));
                }
            }
        }
    }

    fn format_message(&self, request: &ProxyRequest, credential_description: &str) -> String {
        format_messages(request, credential_description, &ApprovalContext::default()).1
    }

    fn channel_name(&self) -> &str {
        "matrix"
    }

    async fn notify_unauthorized(
        &self,
        channel_request_id: &str,
        user_identifier: &str,
    ) -> Result<(), AgentSecError> {
        // Look up the room from in-memory first, then fall back to DB.
        let room_id = {
            let msgs = self.sent_messages.lock().await;
            msgs.get(channel_request_id).map(|(r, _)| r.clone())
        };
        let room_id = if let Some(r) = room_id {
            Some(r)
        } else if let Some(ref store) = self.store {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                store.get_pending_approval_matrix_message(channel_request_id),
            )
            .await
            .ok()
            .and_then(|r| r.ok())
            .and_then(|v| v)
            .map(|(r, _)| r)
        } else {
            None
        };
        if let Some(room_id) = room_id {
            let html = format!(
                "{} is not authorised to approve or deny this request.",
                escape_html(user_identifier)
            );
            let plain =
                format!("{user_identifier} is not authorised to approve or deny this request.");
            let _ = self.send_matrix_message(&room_id, &html, &plain).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tap_core::types::*;

    fn test_config() -> MatrixConfig {
        MatrixConfig {
            homeserver_url: "https://matrix.example.org".to_string(),
            access_token: "test-token".to_string(),
            room_id: "!abc:example.org".to_string(),
        }
    }

    fn test_request() -> ProxyRequest {
        ProxyRequest {
            id: Uuid::new_v4(),
            agent_id: "openclaw".to_string(),
            target_url: "https://api.twitter.com/2/tweets".to_string(),
            method: HttpMethod::Post,
            headers: vec![],
            body: Some(br#"{"text":"Hello"}"#.to_vec()),
            content_type: Some("application/json".to_string()),
            placeholders: vec![Placeholder {
                credential_name: "twitter-holonym".to_string(),
                field: None,
                position: PlaceholderPosition::Header("Authorization".to_string()),
            }],
            received_at: Utc::now(),
        }
    }

    async fn test_store() -> Arc<ConfigStore> {
        let db_url = std::env::var("POSTGRES_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://tap:tap@localhost:5434/tap".to_string());
        Arc::new(ConfigStore::new(&db_url, [0u8; 32]).await.unwrap())
    }

    #[test]
    fn format_messages_contains_fields() {
        let ctx = ApprovalContext::default();
        let (html, plain) = format_messages(&test_request(), "Twitter API for @HolonymHQ", &ctx);
        assert!(html.contains("openclaw"));
        assert!(plain.contains("openclaw"));
        assert!(html.contains("twitter-holonym"));
        assert!(plain.contains("twitter-holonym"));
        assert!(html.contains("approve"));
    }

    #[test]
    fn format_messages_include_action_summary() {
        // The default test request is a tweet post — a recognized service.
        let ctx = ApprovalContext::default();
        let (html, plain) = format_messages(&test_request(), "Twitter API", &ctx);
        assert!(
            html.contains("<b>Action:</b> Post a tweet: &quot;Hello&quot;"),
            "html: {html}"
        );
        assert!(
            plain.contains("Action: Post a tweet: \"Hello\""),
            "plain: {plain}"
        );
    }

    #[test]
    fn format_messages_omit_action_for_unknown_service() {
        let mut r = test_request();
        r.target_url = "https://api.example.com/v1/things".to_string();
        let ctx = ApprovalContext::default();
        let (html, plain) = format_messages(&r, "Test", &ctx);
        assert!(!html.contains("<b>Action:</b>"));
        assert!(!plain.contains("Action:"));
    }

    #[test]
    fn format_messages_escapes_html() {
        let mut r = test_request();
        r.body = Some(b"<script>alert('xss')</script>".to_vec());
        let ctx = ApprovalContext::default();
        let (html, _) = format_messages(&r, "Test", &ctx);
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn format_messages_shows_passkey_url() {
        let ctx = ApprovalContext {
            require_passkey: true,
            approval_url: Some("https://tap.example.com/approve/txn/abc".to_string()),
            ..Default::default()
        };
        let (html, plain) = format_messages(&test_request(), "Test", &ctx);
        assert!(html.contains("https://tap.example.com/approve/txn/abc"));
        assert!(plain.contains("https://tap.example.com/approve/txn/abc"));
        assert!(html.contains("Passkey required"));
    }

    #[test]
    fn urlencoding_room_id() {
        assert_eq!(
            urlencoding_encode("!abc:example.org"),
            "%21abc%3Aexample.org"
        );
    }

    #[test]
    fn trait_impl_compiles() {
        fn assert_impl<T: tap_core::approval::ApprovalChannel>() {}
        assert_impl::<MatrixChannel>();
    }

    #[tokio::test]
    async fn pending_approval_tracked() {
        let ch = MatrixChannel::new(test_config(), None).unwrap();
        ch.register_pending("req-1").await;
        assert!(ch.is_pending("req-1").await);
    }

    #[tokio::test]
    async fn resolve_approval_sends_status() {
        let ch = MatrixChannel::new(test_config(), None).unwrap();
        ch.register_pending("req-2").await;
        assert!(ch.resolve_approval("req-2", ApprovalStatus::Approved).await);
        assert!(!ch.is_pending("req-2").await);
        let rx = ch.receivers.lock().await.remove("req-2").unwrap();
        assert_eq!(rx.await.unwrap(), ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn wait_for_decision_observes_persisted_passkey_resolution() {
        let store = test_store().await;
        let ch = MatrixChannel::new(test_config(), Some(store.clone())).unwrap();
        let request_id = format!("req-{}", Uuid::new_v4());
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store
            .save_pending_approval(&request_id, "{}", &expires_at)
            .await
            .unwrap();

        ch.register_pending(&request_id).await;
        let store2 = store.clone();
        let request_id2 = request_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            store2
                .resolve_pending_approval(&request_id2, "approved", Some("@alice:example.org"))
                .await
                .unwrap();
        });

        let status = ch.wait_for_decision(&request_id, 2).await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
        assert!(!ch.is_pending(&request_id).await);
        store.delete_pending_approval(&request_id).await.unwrap();
    }

    // --- ⏳ "approve for 30 min" grant reaction (#49) -------------------------

    /// Isolated environment for the grant-reaction tests: a team, a member
    /// with a linked Matrix account (`@boss:example.org`), and a pending
    /// approval row carrying the reviewed request's details (as the proxy now
    /// persists for messaging-channel rows).
    async fn grant_env(role: &str) -> (Arc<ConfigStore>, MatrixChannel, String, String) {
        let store = Arc::new(ConfigStore::new_isolated_test([0u8; 32]).await.0);
        let team_id = Uuid::new_v4().to_string();
        store.create_team(&team_id, "grant-team").await.unwrap();
        // approval_grants FKs to credentials(team_id, name).
        store
            .create_credential(
                &team_id, "api-cred", "API cred", "direct", None, false, None, None, None,
            )
            .await
            .unwrap();
        let user_id = Uuid::new_v4().to_string();
        let uid = store
            .create_user_with_membership(&user_id, &team_id, "boss@example.com", "pw", role)
            .await
            .unwrap();
        store
            .update_user_identity(&uid, None, Some("@boss:example.org"), None)
            .await
            .unwrap();

        let request_id = format!("req-{}", Uuid::new_v4());
        let details = serde_json::json!({
            "txn_id": request_id,
            "team_id": team_id,
            "agent_id": "agent-1",
            "credential_name": "api-cred",
            "target_url": "https://api.example.com/v1/messages",
            "method": "POST",
        })
        .to_string();
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store
            .save_pending_approval(&request_id, &details, &expires_at)
            .await
            .unwrap();

        let channel = MatrixChannel::new(test_config(), Some(store.clone())).unwrap();
        (store, channel, team_id, request_id)
    }

    #[tokio::test]
    async fn grant_reaction_approves_and_opens_scoped_window() {
        let (store, ch, team_id, request_id) = grant_env("admin").await;
        ch.event_to_request
            .lock()
            .await
            .insert("$evt-grant".to_string(), request_id.clone());

        ch.handle_reaction("$evt-grant", GRANT_REACTION, Some("@boss:example.org"))
            .await
            .unwrap();

        assert_eq!(
            store
                .get_pending_approval_status(&request_id)
                .await
                .unwrap()
                .as_deref(),
            Some("approved")
        );
        let grants = store.list_approval_grants(&team_id).await.unwrap();
        assert_eq!(grants.len(), 1, "one grant scoped to the reviewed request");
        assert_eq!(grants[0].methods, vec!["POST".to_string()]);
        assert_eq!(
            grants[0].route_scope,
            vec!["api.example.com/v1/messages".to_string()]
        );
        assert_eq!(grants[0].granted_by, "boss@example.com");
    }

    #[tokio::test]
    async fn grant_reaction_refuses_non_manager_and_leaves_pending() {
        let (store, ch, team_id, request_id) = grant_env("approver").await;
        ch.event_to_request
            .lock()
            .await
            .insert("$evt-grant-2".to_string(), request_id.clone());

        ch.handle_reaction("$evt-grant-2", GRANT_REACTION, Some("@boss:example.org"))
            .await
            .unwrap();

        assert_eq!(
            store
                .get_pending_approval_status(&request_id)
                .await
                .unwrap()
                .as_deref(),
            Some("pending"),
            "a refused grant must not resolve the request"
        );
        assert!(store
            .list_approval_grants(&team_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn grant_reaction_refuses_unlinked_matrix_account() {
        let (store, ch, team_id, request_id) = grant_env("owner").await;
        ch.event_to_request
            .lock()
            .await
            .insert("$evt-grant-3".to_string(), request_id.clone());

        ch.handle_reaction("$evt-grant-3", GRANT_REACTION, Some("@stranger:example.org"))
            .await
            .unwrap();

        assert_eq!(
            store
                .get_pending_approval_status(&request_id)
                .await
                .unwrap()
                .as_deref(),
            Some("pending")
        );
        assert!(store
            .list_approval_grants(&team_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn handle_reaction_approve() {
        let ch = MatrixChannel::new(test_config(), None).unwrap();
        ch.register_pending("req-3").await;
        ch.event_to_request
            .lock()
            .await
            .insert("$evt1".to_string(), "req-3".to_string());

        let _ = ch
            .handle_reaction("$evt1", APPROVE_REACTION, Some("@alice:example.org"))
            .await;

        let rx = ch.receivers.lock().await.remove("req-3").unwrap();
        assert_eq!(rx.await.unwrap(), ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn handle_reaction_deny() {
        let ch = MatrixChannel::new(test_config(), None).unwrap();
        ch.register_pending("req-4").await;
        ch.event_to_request
            .lock()
            .await
            .insert("$evt2".to_string(), "req-4".to_string());

        let _ = ch
            .handle_reaction("$evt2", DENY_REACTION, Some("@bob:example.org"))
            .await;

        let rx = ch.receivers.lock().await.remove("req-4").unwrap();
        assert_eq!(rx.await.unwrap(), ApprovalStatus::Denied);
    }

    #[tokio::test]
    async fn handle_reaction_ignores_unknown_emoji() {
        let ch = MatrixChannel::new(test_config(), None).unwrap();
        ch.register_pending("req-5").await;
        ch.event_to_request
            .lock()
            .await
            .insert("$evt3".to_string(), "req-5".to_string());

        let _ = ch
            .handle_reaction("$evt3", "\u{1f4a9}", Some("@eve:x"))
            .await;

        // Unrelated reaction — request still pending.
        assert!(ch.is_pending("req-5").await);
    }

    #[tokio::test]
    async fn handle_reaction_rejects_unauthorized_approver() {
        let ch = MatrixChannel::new(test_config(), None).unwrap();
        ch.register_pending("req-6").await;
        ch.event_to_request
            .lock()
            .await
            .insert("$evt4".to_string(), "req-6".to_string());
        ch.allowed_approvers
            .lock()
            .await
            .insert("req-6".to_string(), vec!["@alice:example.org".to_string()]);

        let _ = ch
            .handle_reaction("$evt4", APPROVE_REACTION, Some("@mallory:example.org"))
            .await;

        // Unauthorized — still pending.
        assert!(ch.is_pending("req-6").await);
    }

    #[test]
    fn parse_reactions_extracts_annotation_events() {
        let body = serde_json::json!({
            "rooms": {
                "join": {
                    "!room:example.org": {
                        "timeline": {
                            "events": [
                                {
                                    "type": "m.reaction",
                                    "sender": "@alice:example.org",
                                    "content": {
                                        "m.relates_to": {
                                            "rel_type": "m.annotation",
                                            "event_id": "$evtA",
                                            "key": "\u{2705}"
                                        }
                                    }
                                },
                                {
                                    "type": "m.room.message",
                                    "sender": "@bob:example.org",
                                    "content": { "body": "hi" }
                                },
                                {
                                    "type": "m.reaction",
                                    "sender": "@carol:example.org",
                                    "content": {
                                        "m.relates_to": {
                                            "rel_type": "m.annotation",
                                            "event_id": "$evtB",
                                            "key": "\u{274c}"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        });
        let r = parse_reactions(&body);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].target_event_id, "$evtA");
        assert_eq!(r[0].reaction_key, APPROVE_REACTION);
        assert_eq!(r[0].sender, "@alice:example.org");
        assert_eq!(r[1].target_event_id, "$evtB");
        assert_eq!(r[1].reaction_key, DENY_REACTION);
    }

    #[test]
    fn parse_reactions_skips_non_annotation_relations() {
        let body = serde_json::json!({
            "rooms": {
                "join": {
                    "!room:example.org": {
                        "timeline": {
                            "events": [{
                                "type": "m.reaction",
                                "sender": "@alice:example.org",
                                "content": {
                                    "m.relates_to": {
                                        "rel_type": "m.replace",
                                        "event_id": "$evt",
                                        "key": "\u{2705}"
                                    }
                                }
                            }]
                        }
                    }
                }
            }
        });
        assert!(parse_reactions(&body).is_empty());
    }

    #[test]
    fn parse_reactions_handles_empty_body() {
        assert!(parse_reactions(&serde_json::json!({})).is_empty());
        assert!(parse_reactions(&serde_json::json!({"rooms":{}})).is_empty());
        assert!(parse_reactions(&serde_json::json!({"next_batch":"s1"})).is_empty());
    }

    #[test]
    fn parse_reactions_skips_malformed_events() {
        let body = serde_json::json!({
            "rooms": { "join": { "!r:e": { "timeline": { "events": [
                { "type": "m.reaction" },
                { "type": "m.reaction", "content": {} },
                { "type": "m.reaction", "content": { "m.relates_to": { "rel_type": "m.annotation" } } },
                { "type": "m.reaction", "content": { "m.relates_to": { "rel_type": "m.annotation", "event_id": "$x" } } }
            ]}}}}
        });
        assert!(parse_reactions(&body).is_empty());
    }

    #[test]
    fn parse_text_replies_plain_approve() {
        let body = serde_json::json!({
            "rooms": { "join": { "!r:e": { "timeline": { "events": [{
                "type": "m.room.message",
                "sender": "@alice:example.org",
                "content": {
                    "msgtype": "m.text",
                    "body": "approve",
                    "m.relates_to": {
                        "m.in_reply_to": { "event_id": "$tap_msg" }
                    }
                }
            }]}}}}
        });
        let r = parse_text_replies(&body);
        assert_eq!(r.len(), 1);
        assert!(r[0].approve);
        assert_eq!(r[0].in_reply_to, "$tap_msg");
    }

    #[test]
    fn parse_text_replies_quote_reply_with_prefix() {
        // Element quote-reply: body has "> quoted lines\n\napprove"
        let body = serde_json::json!({
            "rooms": { "join": { "!r:e": { "timeline": { "events": [{
                "type": "m.room.message",
                "sender": "@alice:example.org",
                "content": {
                    "msgtype": "m.text",
                    "body": "> <@tapbot:matrix.org> \u{1f511} Approval Request\n> Agent: openclaw\n\napprove",
                    "m.relates_to": {
                        "m.in_reply_to": { "event_id": "$tap_msg" }
                    }
                }
            }]}}}}
        });
        let r = parse_text_replies(&body);
        assert_eq!(r.len(), 1, "quote reply with prefix should be recognised");
        assert!(r[0].approve);
        assert_eq!(r[0].in_reply_to, "$tap_msg");
    }

    #[test]
    fn parse_text_replies_thread_reply_no_in_reply_to() {
        // Element "Reply in Thread" without fallback: only m.thread rel_type, no m.in_reply_to
        let body = serde_json::json!({
            "rooms": { "join": { "!r:e": { "timeline": { "events": [{
                "type": "m.room.message",
                "sender": "@alice:example.org",
                "content": {
                    "msgtype": "m.text",
                    "body": "deny",
                    "m.relates_to": {
                        "rel_type": "m.thread",
                        "event_id": "$tap_msg",
                        "is_falling_back": false
                    }
                }
            }]}}}}
        });
        let r = parse_text_replies(&body);
        assert_eq!(
            r.len(),
            1,
            "thread reply without m.in_reply_to should be recognised"
        );
        assert!(!r[0].approve);
        assert_eq!(r[0].in_reply_to, "$tap_msg");
    }

    #[test]
    fn parse_text_replies_thread_reply_uses_thread_root() {
        // Thread reply with fallback: m.in_reply_to points to a mid-thread message,
        // but event_id (thread root) is the TAP message.
        let body = serde_json::json!({
            "rooms": { "join": { "!r:e": { "timeline": { "events": [{
                "type": "m.room.message",
                "sender": "@alice:example.org",
                "content": {
                    "msgtype": "m.text",
                    "body": "> <@tapbot:matrix.org> Approval Request\n\napprove",
                    "m.relates_to": {
                        "rel_type": "m.thread",
                        "event_id": "$tap_msg",
                        "is_falling_back": true,
                        "m.in_reply_to": { "event_id": "$some_mid_thread_reply" }
                    }
                }
            }]}}}}
        });
        let r = parse_text_replies(&body);
        assert_eq!(r.len(), 1);
        assert!(r[0].approve);
        // Must use thread root ($tap_msg), not the mid-thread reply.
        assert_eq!(r[0].in_reply_to, "$tap_msg");
    }

    #[test]
    fn strip_matrix_quote_prefix_no_prefix() {
        assert_eq!(strip_matrix_quote_prefix("approve"), "approve");
        assert_eq!(strip_matrix_quote_prefix("yes\n"), "yes\n");
    }

    #[test]
    fn strip_matrix_quote_prefix_with_quote() {
        let body = "> quoted line\n> more\n\ndeny";
        assert_eq!(strip_matrix_quote_prefix(body), "deny");
    }

    #[test]
    fn strip_matrix_quote_prefix_no_strip_without_gt() {
        // Double newline but no "> " prefix — don't strip.
        let body = "paragraph one\n\napprove";
        assert_eq!(strip_matrix_quote_prefix(body), body);
    }

    #[test]
    fn reaction_filter_restricts_scope() {
        let filter = build_reaction_filter("!abc:example.org");
        let parsed: serde_json::Value = serde_json::from_str(&filter).unwrap();
        assert_eq!(
            parsed["room"]["timeline"]["types"],
            serde_json::json!(["m.reaction", "m.room.message"])
        );
        // No rooms allowlist — invite events from any room must flow through
        // so the bot can auto-accept them.
        assert_eq!(parsed["room"]["rooms"], serde_json::Value::Null);
        assert_eq!(parsed["presence"]["types"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn wait_for_decision_times_out() {
        let ch = MatrixChannel::new(test_config(), None).unwrap();
        ch.register_pending("req-timeout").await;
        let r = ch.wait_for_decision("req-timeout", 1).await;
        assert!(matches!(r, Err(AgentSecError::ApprovalTimeout(1))));
    }
}
