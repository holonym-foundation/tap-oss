//! Telegram approval channel implementing the ApprovalChannel trait.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tap_core::approval::{ApprovalChannel, ApprovalContext};
use tap_core::error::AgentSecError;
use tap_core::http_client::{build_client, ClientRoute};
use tap_core::store::ConfigStore;
use tap_core::types::{ApprovalStatus, ProxyRequest};
use tokio::sync::{oneshot, Mutex};
use tracing::{error, info, warn};

use crate::config::TelegramConfig;

/// Session trust key: (agent_id, credential_name)
type TrustKey = (String, String);

/// All per-request state owned by the approval side (handle_callback, send_telegram_message).
struct PendingApproval {
    tx: oneshot::Sender<ApprovalStatus>,
    allowed_approvers: Vec<String>,
    /// Populated by send_telegram_message once the sendMessage HTTP response arrives.
    sent_message: Option<(String, i64)>,
    approval_count: usize,
    min_approvals: usize,
}

pub struct TelegramChannel {
    config: TelegramConfig,
    http: reqwest::Client,
    /// Per-request approval state keyed by channel_request_id.
    pending: Arc<Mutex<HashMap<String, PendingApproval>>>,
    /// Oneshot receivers held until wait_for_decision consumes them.
    receivers: Arc<Mutex<HashMap<String, oneshot::Receiver<ApprovalStatus>>>>,
    /// Session-trusted (agent_id, credential_name) pairs — no re-approval needed.
    trusted_sessions: Arc<Mutex<HashSet<TrustKey>>>,
    /// Optional DB store for passkey decisions resolved by another instance.
    store: Option<Arc<ConfigStore>>,
}

impl TelegramChannel {
    pub fn new(config: TelegramConfig) -> Result<Self, AgentSecError> {
        Self::with_store(config, None)
    }

    pub fn with_store(
        config: TelegramConfig,
        store: Option<Arc<ConfigStore>>,
    ) -> Result<Self, AgentSecError> {
        let http = build_client(ClientRoute::Direct)
            .map_err(|e| AgentSecError::Config(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            config,
            http,
            pending: Arc::new(Mutex::new(HashMap::new())),
            receivers: Arc::new(Mutex::new(HashMap::new())),
            trusted_sessions: Arc::new(Mutex::new(HashSet::new())),
            store,
        })
    }

    /// Register a pending approval. Both tx and rx are created here; tx lives in `pending`,
    /// rx lives in `receivers` until wait_for_decision consumes it.
    async fn register_pending(&self, request_id: &str) {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(
            request_id.to_string(),
            PendingApproval {
                tx,
                allowed_approvers: Vec::new(),
                sent_message: None,
                approval_count: 0,
                min_approvals: 1,
            },
        );
        self.receivers
            .lock()
            .await
            .insert(request_id.to_string(), rx);
    }

    /// Handle a Telegram callback query (from webhook or polling loop).
    /// `callback_data` is "approve:{request_id}", "deny:{request_id}" or
    /// "grant:{request_id}" (approve + 30-minute time-boxed grant, #49).
    /// `user_id` is the Telegram user ID of the person who clicked the button.
    pub async fn handle_callback(
        &self,
        callback_data: &str,
        callback_query_id: &str,
        user_id: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let (action, request_id) = callback_data
            .split_once(':')
            .ok_or_else(|| AgentSecError::Internal("Invalid callback data format".to_string()))?;

        let status = match action {
            "approve" | "grant" => ApprovalStatus::Approved,
            "deny" => ApprovalStatus::Denied,
            _ => {
                return Err(AgentSecError::Internal(format!(
                    "Unknown callback action: {action}"
                )));
            }
        };

        // Auth check: read allowed_approvers, drop lock before any await.
        if let Some(uid) = user_id {
            let is_unauthorized = {
                let map = self.pending.lock().await;
                map.get(request_id)
                    .map(|a| {
                        !a.allowed_approvers.is_empty()
                            && !a.allowed_approvers.contains(&uid.to_string())
                    })
                    .unwrap_or(false)
            };
            if is_unauthorized {
                warn!(
                    request_id,
                    user_id = uid,
                    "User not in allowed_approvers list"
                );
                let answer_url = format!(
                    "https://api.telegram.org/bot{}/answerCallbackQuery",
                    self.config.bot_token
                );
                let _ = self
                    .http
                    .post(&answer_url)
                    .json(&serde_json::json!({
                        "callback_query_id": callback_query_id,
                        "text": "You are not authorized to approve this request.",
                        "show_alert": true,
                    }))
                    .send()
                    .await;
                return Ok(());
            }
        }

        // "Approve for 30 min" (#49): resolve the approval AND mint a grant
        // scoped to exactly this request. Own path — it needs the pending
        // row's details and the clicker's workspace role before resolving.
        if action == "grant" {
            return self
                .handle_grant_callback(request_id, callback_query_id, user_id)
                .await;
        }

        // N-of-M threshold check for Approved callbacks.
        if matches!(status, ApprovalStatus::Approved) {
            let partial = {
                let mut map = self.pending.lock().await;
                if let Some(approval) = map.get_mut(request_id) {
                    if approval.min_approvals > 1 {
                        approval.approval_count += 1;
                        let count = approval.approval_count;
                        let needed = approval.min_approvals;
                        if count < needed {
                            Some((count, needed, approval.sent_message.clone()))
                        } else {
                            None // threshold met — fall through to resolve
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some((current, needed, sent_message)) = partial {
                info!(
                    request_id,
                    approved = current,
                    needed,
                    user_id = user_id.unwrap_or("unknown"),
                    "Partial approval — waiting for more"
                );
                let http = self.http.clone();
                let bot_token = self.config.bot_token.clone();
                let cq_id_owned = callback_query_id.to_string();
                let request_id_owned = request_id.to_string();
                tokio::spawn(async move {
                    let answer_url =
                        format!("https://api.telegram.org/bot{bot_token}/answerCallbackQuery");
                    let _ = http
                        .post(&answer_url)
                        .json(&serde_json::json!({
                            "callback_query_id": cq_id_owned,
                            "text": format!("{current}/{needed} approved — waiting for more"),
                        }))
                        .send()
                        .await;
                    if let Some((chat_id, message_id)) = sent_message {
                        let edit_url =
                            format!("https://api.telegram.org/bot{bot_token}/sendMessage");
                        let _ = http
                            .post(&edit_url)
                            .json(&serde_json::json!({
                                "chat_id": chat_id,
                                "text": format!("{current}/{needed} approved — waiting for more approvals (request: {request_id_owned})"),
                                "reply_to_message_id": message_id,
                            }))
                            .send()
                            .await;
                    }
                });
                return Ok(());
            }
        }

        // Snapshot sent_message before resolve removes the PendingApproval entry.
        let sent_message = self.sent_message_for_request(request_id).await;

        // Resolve before acknowledging the callback as approved. Telegram's
        // answerCallbackQuery is the user's only immediate signal, so don't
        // show "Approved" unless memory or DB state actually recorded it.
        let resolved = self
            .resolve_approval_as(request_id, status.clone(), user_id)
            .await;
        if !resolved {
            warn!(
                request_id,
                "Approval receiver already dropped or pending row was missing"
            );
            let answer_url = format!(
                "https://api.telegram.org/bot{}/answerCallbackQuery",
                self.config.bot_token
            );
            let _ = self
                .http
                .post(&answer_url)
                .json(&serde_json::json!({
                    "callback_query_id": callback_query_id,
                    "text": "Approval was not recorded. Please try again.",
                    "show_alert": true,
                }))
                .send()
                .await;
            return Ok(());
        }

        info!(request_id, ?status, "Approval callback processed");

        // Telegram UI updates run in a background task — never block the polling loop.
        let http = self.http.clone();
        let bot_token = self.config.bot_token.clone();
        let cq_id_owned = callback_query_id.to_string();
        let user_id_owned = user_id.map(|s| s.to_string());

        tokio::spawn(async move {
            let answer_url = format!("https://api.telegram.org/bot{bot_token}/answerCallbackQuery");
            let answer_text = match &status {
                ApprovalStatus::Approved => "Approved",
                ApprovalStatus::Denied => "Denied",
                _ => "Processed",
            };
            let _ = http
                .post(&answer_url)
                .json(&serde_json::json!({
                    "callback_query_id": cq_id_owned,
                    "text": answer_text,
                }))
                .send()
                .await;

            if let Some((chat_id, message_id)) = sent_message {
                let status_text = match &status {
                    ApprovalStatus::Approved => "\u{2705} APPROVED",
                    ApprovalStatus::Denied => "\u{274c} DENIED",
                    _ => "PROCESSED",
                };
                let approver_info = user_id_owned
                    .as_deref()
                    .map(|uid| format!(" by user {uid}"))
                    .unwrap_or_default();
                let edit_url =
                    format!("https://api.telegram.org/bot{bot_token}/editMessageReplyMarkup");
                let _ = http
                    .post(&edit_url)
                    .json(&serde_json::json!({
                        "chat_id": chat_id,
                        "message_id": message_id,
                        "reply_markup": { "inline_keyboard": [] },
                    }))
                    .send()
                    .await;

                let reply_url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
                let _ = http
                    .post(&reply_url)
                    .json(&serde_json::json!({
                        "chat_id": chat_id,
                        "text": format!("{status_text}{approver_info}"),
                        "reply_to_message_id": message_id,
                    }))
                    .send()
                    .await;
            }
        });

        Ok(())
    }

    /// Answer a callback query with a short toast (or alert popup).
    async fn answer_callback(&self, callback_query_id: &str, text: &str, show_alert: bool) {
        let answer_url = format!(
            "https://api.telegram.org/bot{}/answerCallbackQuery",
            self.config.bot_token
        );
        let _ = self
            .http
            .post(&answer_url)
            .json(&serde_json::json!({
                "callback_query_id": callback_query_id,
                "text": text,
                "show_alert": show_alert,
            }))
            .send()
            .await;
    }

    /// Handle the "⏱ Approve for 30 min" button (#49): approve the request AND
    /// mint a time-boxed grant derived from it. Guardrails mirror the
    /// dashboard's approve-with-grant endpoint — workspace managers only
    /// (resolved from the clicker's linked Telegram account), no passkey/`eu:`
    /// credentials, concrete derivable scope. Any refusal BEFORE the resolve
    /// leaves the request pending, so the human can still use plain ✅ Approve.
    async fn handle_grant_callback(
        &self,
        request_id: &str,
        callback_query_id: &str,
        user_id: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let Some(store) = self.store.clone() else {
            self.answer_callback(
                callback_query_id,
                "Time-boxed grants need a database-backed deployment — use ✅ Approve.",
                true,
            )
            .await;
            return Ok(());
        };
        let Some(uid) = user_id else {
            self.answer_callback(
                callback_query_id,
                "Could not identify your Telegram account.",
                true,
            )
            .await;
            return Ok(());
        };

        // A multi-approval request can't be short-circuited by one manager.
        // Prefer the in-memory pending row, but on an instance that never held
        // it fall back to the persisted `min_approvals` so the guard holds
        // cross-instance (mirrors the Matrix DB-fallback path — otherwise a
        // stateless replica would read `unwrap_or(false)` and wrongly allow it).
        let in_memory_min = self
            .pending
            .lock()
            .await
            .get(request_id)
            .map(|a| a.min_approvals);
        let needs_multiple = match in_memory_min {
            Some(min) => min > 1,
            None => store
                .get_pending_approval_min_approvals(request_id)
                .await
                .ok()
                .flatten()
                .map(|min| min > 1)
                .unwrap_or(false),
        };
        if needs_multiple {
            self.answer_callback(
                callback_query_id,
                "This request needs multiple approvals — approve it normally.",
                true,
            )
            .await;
            return Ok(());
        }

        // Load the reviewed request's details BEFORE resolving — the pending
        // row stops being readable once it is resolved.
        let details_json = match store.get_pending_approval_details(request_id).await {
            Ok(Some(json)) => json,
            Ok(None) => {
                self.answer_callback(callback_query_id, "This request is no longer pending.", true)
                    .await;
                return Ok(());
            }
            Err(e) => {
                warn!(request_id, error = %e, "Failed to load approval details for grant");
                self.answer_callback(
                    callback_query_id,
                    "Could not load this request — try again.",
                    true,
                )
                .await;
                return Ok(());
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
            self.answer_callback(
                callback_query_id,
                "This request doesn't carry enough detail for a grant — use ✅ Approve.",
                true,
            )
            .await;
            return Ok(());
        }

        // Grants are a workspace-manager surface (same rule as the dashboard):
        // an approver may resolve one request, not open a window for many.
        let member = match store.get_member_by_telegram_id(&team_id, uid).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                self.answer_callback(
                    callback_query_id,
                    "Your Telegram account is not linked to a team member — link it in the dashboard first.",
                    true,
                )
                .await;
                return Ok(());
            }
            Err(e) => {
                warn!(request_id, error = %e, "Failed to resolve Telegram user to a team member");
                self.answer_callback(
                    callback_query_id,
                    "Could not verify your team role — try again.",
                    true,
                )
                .await;
                return Ok(());
            }
        };
        if !matches!(member.member_role.as_str(), "owner" | "admin") {
            self.answer_callback(
                callback_query_id,
                "Only owners and admins can approve with a grant — use ✅ Approve.",
                true,
            )
            .await;
            return Ok(());
        }

        // Claim the approval FIRST — a concurrent deny wins, and no grant may
        // come into existence on top of it. The claim must be EXCLUSIVE:
        // `resolve_approval_as` signals the in-memory waiter before the DB
        // claim and counts a duplicate resolution as success, so two
        // concurrent ⏱ clicks (or a ⏱ racing a dashboard deny) could both
        // report "resolved" and mint grants. Only the durable
        // pending→approved transition may mint one.
        let sent_message = self.sent_message_for_request(request_id).await;
        let resolved = self
            .claim_approval_for_grant(&store, request_id, uid)
            .await;
        if !resolved {
            self.answer_callback(
                callback_query_id,
                "Approval was not recorded. Please try again.",
                true,
            )
            .await;
            return Ok(());
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

        let (toast, summary) = match &grant_result {
            Ok(grant) => {
                info!(
                    request_id,
                    grant_id = %grant.id,
                    approver = %member.email,
                    "Telegram approval resolved with a time-boxed grant"
                );
                let ttl = tap_core::grants::GRANT_DEFAULT_TTL_MINUTES;
                (
                    format!("Approved — {ttl} min window opened"),
                    format!(
                        "\u{2705} APPROVED for {ttl} min by {} — identical {} calls to {} skip approval until then. Revoke from the Policies page.",
                        member.email,
                        grant.methods.join("/"),
                        grant.route_scope.join(", ")
                    ),
                )
            }
            Err(refused) => {
                // The approval already went through (that claim is atomic and
                // final). Fail toward fewer auto-approvals: approved, no window.
                warn!(request_id, reason = %refused.message(), "Approval resolved but Telegram grant was refused");
                (
                    format!("Approved, but no grant: {}", refused.message()),
                    format!(
                        "\u{2705} APPROVED by {} (no time-boxed window: {})",
                        member.email,
                        refused.message()
                    ),
                )
            }
        };

        // Telegram UI updates run in a background task — never block the polling loop.
        let http = self.http.clone();
        let bot_token = self.config.bot_token.clone();
        let cq_id_owned = callback_query_id.to_string();
        let show_alert = grant_result.is_err();
        tokio::spawn(async move {
            let answer_url = format!("https://api.telegram.org/bot{bot_token}/answerCallbackQuery");
            let _ = http
                .post(&answer_url)
                .json(&serde_json::json!({
                    "callback_query_id": cq_id_owned,
                    "text": toast,
                    "show_alert": show_alert,
                }))
                .send()
                .await;

            if let Some((chat_id, message_id)) = sent_message {
                let edit_url =
                    format!("https://api.telegram.org/bot{bot_token}/editMessageReplyMarkup");
                let _ = http
                    .post(&edit_url)
                    .json(&serde_json::json!({
                        "chat_id": chat_id,
                        "message_id": message_id,
                        "reply_markup": { "inline_keyboard": [] },
                    }))
                    .send()
                    .await;

                let reply_url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
                let _ = http
                    .post(&reply_url)
                    .json(&serde_json::json!({
                        "chat_id": chat_id,
                        "text": summary,
                        "reply_to_message_id": message_id,
                    }))
                    .send()
                    .await;
            }
        });

        Ok(())
    }

    /// Simulate receiving an approve callback (for testing / webhook handling).
    pub async fn resolve_approval(&self, request_id: &str, status: ApprovalStatus) -> bool {
        self.resolve_approval_as(request_id, status, None).await
    }

    /// Exclusive pending→approved claim for the ⏱ grant button (#49). Unlike
    /// `resolve_approval_as` — which unblocks the in-memory waiter BEFORE the
    /// DB claim and treats a duplicate resolution as success — a grant may
    /// only be minted on the actual durable pending→approved transition: the
    /// strict DB claim runs first, an already-resolved row returns false, and
    /// the same-process waiter is signalled only after the claim succeeded
    /// (mirrors webauthn's `may_signal_memory = db_resolved` gating).
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
                warn!(request_id, error = %e, "Failed to claim approval for grant");
                false
            }
            Err(_) => {
                warn!(request_id, "Timed out claiming approval for grant");
                false
            }
        };
        if db_resolved {
            if let Some(a) = self.pending.lock().await.remove(request_id) {
                let _ = a.tx.send(ApprovalStatus::Approved);
            }
        }
        db_resolved
    }

    async fn sent_message_for_request(&self, request_id: &str) -> Option<(String, i64)> {
        let sent_message = self
            .pending
            .lock()
            .await
            .get(request_id)
            .and_then(|a| a.sent_message.clone());
        if sent_message.is_some() {
            return sent_message;
        }

        if let Some(store) = self.store.clone() {
            match store
                .get_pending_approval_telegram_message(request_id)
                .await
            {
                Ok(message) => message,
                Err(e) => {
                    warn!(
                        request_id,
                        error = %e,
                        "Failed to load persisted Telegram message metadata"
                    );
                    None
                }
            }
        } else {
            None
        }
    }

    /// Send on tx immediately when local state exists, then persist to DB inline.
    /// Returning true means memory or durable DB state recorded the decision.
    async fn resolve_approval_as(
        &self,
        request_id: &str,
        status: ApprovalStatus,
        resolved_by: Option<&str>,
    ) -> bool {
        let status_str: &'static str = match &status {
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Timeout => "expired",
            ApprovalStatus::Pending => "pending",
        };

        // Send on tx first — unblocks wait_for_decision promptly when this
        // callback lands on the same process that created the approval.
        let tx_sent = self
            .pending
            .lock()
            .await
            .remove(request_id)
            .map(|a| a.tx.send(status).is_ok())
            .unwrap_or(false);

        // Persist inline so callbacks delivered to a different process still
        // durably resolve the approval before Telegram is told it succeeded.
        let mut db_resolved = false;
        if let Some(store) = self.store.clone() {
            match tokio::time::timeout(
                Duration::from_secs(5),
                store.resolve_pending_approval(request_id, status_str, resolved_by),
            )
            .await
            {
                Ok(Ok(updated)) => db_resolved = updated,
                Ok(Err(e)) => warn!(
                    request_id,
                    error = %e,
                    "Failed to persist approval resolution"
                ),
                Err(_) => warn!(request_id, "Timed out persisting approval resolution"),
            }
        }

        tx_sent || db_resolved
    }

    async fn cleanup_pending_request(&self, request_id: &str) {
        self.pending.lock().await.remove(request_id);
        self.receivers.lock().await.remove(request_id);
    }

    async fn persist_resolution(
        &self,
        request_id: &str,
        status: ApprovalStatus,
    ) -> Result<bool, AgentSecError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(false);
        };

        let status_str = match status {
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
            ApprovalStatus::Timeout => "expired",
            ApprovalStatus::Pending => "pending",
        };

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            store.resolve_pending_approval(request_id, status_str, None),
        )
        .await;

        match result {
            Ok(Ok(updated)) => Ok(updated),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(AgentSecError::Internal(
                "Timed out persisting Telegram approval resolution".to_string(),
            )),
        }
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

    /// Mark an agent+credential as trusted for this session.
    pub async fn trust_session(&self, agent_id: &str, credential_name: &str) {
        self.trusted_sessions
            .lock()
            .await
            .insert((agent_id.to_string(), credential_name.to_string()));
    }

    /// Check if an agent+credential is trusted for this session.
    pub async fn should_auto_trust(&self, agent_id: &str, credential_name: &str) -> bool {
        self.trusted_sessions
            .lock()
            .await
            .contains(&(agent_id.to_string(), credential_name.to_string()))
    }

    /// Check if a request ID is pending.
    pub async fn is_pending(&self, request_id: &str) -> bool {
        self.pending.lock().await.contains_key(request_id)
    }

    /// Register this bot as a Telegram webhook at `url`.
    /// `secret` is sent in setWebhook and Telegram will echo it back in
    /// X-Telegram-Bot-Api-Secret-Token on every incoming request so the handler
    /// can verify the caller is Telegram.
    pub async fn register_webhook(
        &self,
        url: &str,
        secret: Option<&str>,
    ) -> Result<(), AgentSecError> {
        self.register_webhook_at("https://api.telegram.org", url, secret)
            .await
    }

    async fn register_webhook_at(
        &self,
        api_base: &str,
        url: &str,
        secret: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let set_url = format!("{}/bot{}/setWebhook", api_base, self.config.bot_token);
        let mut payload = serde_json::json!({
            "url": url,
            "allowed_updates": ["callback_query", "message"],
        });
        if let Some(s) = secret {
            payload["secret_token"] = serde_json::Value::String(s.to_string());
        }
        let resp = self
            .http
            .post(&set_url)
            .json(&payload)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AgentSecError::Internal(format!("setWebhook request failed: {e}")))?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({}));

        if body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            Ok(())
        } else {
            Err(AgentSecError::Internal(format!(
                "Telegram setWebhook failed (HTTP {status}): {}",
                body.get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("unknown error")
            )))
        }
    }

    /// Start a long-polling loop that fetches Telegram updates via getUpdates.
    /// This is the alternative to webhooks — works when the proxy isn't publicly accessible.
    /// Spawns a background tokio task. Call once at startup.
    ///
    /// If `store` is provided, text commands (/whitelist, /unwhitelist) are handled.
    pub fn start_polling(self: &Arc<Self>, store: Option<Arc<tap_core::store::ConfigStore>>) {
        let channel = self.clone();
        // Read once at startup rather than on every text message.
        let allowed_user_id: Option<i64> = std::env::var("TELEGRAM_ALLOWED_USER_ID")
            .ok()
            .and_then(|s| s.parse().ok());
        tokio::spawn(async move {
            let mut offset: i64 = 0;
            // Clear any existing webhook so Telegram delivers updates via getUpdates.
            let delete_url = format!(
                "https://api.telegram.org/bot{}/deleteWebhook",
                channel.config.bot_token
            );
            let _ = channel.http.post(&delete_url).send().await;
            info!("Telegram polling started");
            loop {
                let url = format!(
                    "https://api.telegram.org/bot{}/getUpdates?offset={}&timeout=30&allowed_updates=[\"callback_query\",\"message\"]",
                    channel.config.bot_token, offset
                );
                let resp = match channel
                    .http
                    .get(&url)
                    .timeout(std::time::Duration::from_secs(35))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Telegram getUpdates error: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                };
                let body: serde_json::Value = match resp.json().await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Telegram getUpdates parse error: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                };
                if let Some(results) = body.get("result").and_then(|r| r.as_array()) {
                    for update in results {
                        // Advance offset past this update.
                        if let Some(uid) = update.get("update_id").and_then(|u| u.as_i64()) {
                            offset = uid + 1;
                        }
                        // Process callback_query (inline keyboard button press).
                        if let Some(cq) = update.get("callback_query") {
                            let data = cq.get("data").and_then(|d| d.as_str()).unwrap_or("");
                            let cq_id = cq.get("id").and_then(|d| d.as_str()).unwrap_or("");
                            let user_id = cq
                                .get("from")
                                .and_then(|f| f.get("id"))
                                .and_then(|id| id.as_i64())
                                .map(|id| id.to_string());
                            if let Err(e) = channel
                                .handle_callback(data, cq_id, user_id.as_deref())
                                .await
                            {
                                warn!(error = %e, "Telegram callback handling failed");
                            }
                        }
                        // Process text messages (admin commands).
                        if let Some(message) = update.get("message") {
                            let text = message.get("text").and_then(|t| t.as_str()).unwrap_or("");
                            let chat_id = message
                                .get("chat")
                                .and_then(|c| c.get("id"))
                                .and_then(|id| id.as_i64());
                            let user_id = message
                                .get("from")
                                .and_then(|f| f.get("id"))
                                .and_then(|id| id.as_i64());
                            let admin_chat_id = channel.config.chat_id.parse::<i64>().unwrap_or(0);

                            // Allow commands from:
                            // 1. The configured admin group chat
                            // 2. DMs from the TELEGRAM_ALLOWED_USER_ID (platform operator)
                            let is_admin_chat = chat_id == Some(admin_chat_id);
                            let is_allowed_dm =
                                allowed_user_id.is_some() && user_id == allowed_user_id;

                            if !is_admin_chat && !is_allowed_dm {
                                continue;
                            }

                            let reply_chat = chat_id.unwrap_or(admin_chat_id);
                            if let Some(ref store) = store {
                                channel.handle_text_command(text, reply_chat, store).await;
                            }
                        }
                    }
                }
            }
        });
    }

    /// Handle admin text commands from Telegram.
    async fn handle_text_command(
        &self,
        text: &str,
        chat_id: i64,
        store: &tap_core::store::ConfigStore,
    ) {
        if let Some(email) = text
            .strip_prefix("/whitelist ")
            .map(|s| s.trim().to_lowercase())
        {
            if email.contains('@') && email.contains('.') {
                match store.add_to_whitelist(&email, "pro").await {
                    Ok(()) => {
                        self.send_reply(chat_id, &format!("✓ {email} whitelisted (Pro tier)"))
                            .await
                    }
                    Err(e) => self.send_reply(chat_id, &format!("✗ Failed: {e}")).await,
                }
            } else {
                self.send_reply(chat_id, "✗ Invalid email format").await;
            }
        } else if let Some(email) = text
            .strip_prefix("/unwhitelist ")
            .map(|s| s.trim().to_lowercase())
        {
            match store.remove_from_whitelist(&email).await {
                Ok(()) => {
                    self.send_reply(chat_id, &format!("✓ {email} removed from whitelist"))
                        .await
                }
                Err(e) => self.send_reply(chat_id, &format!("✗ Failed: {e}")).await,
            }
        } else if text.trim() == "/whitelist" {
            match store.list_whitelist().await {
                Ok(entries) if entries.is_empty() => {
                    self.send_reply(chat_id, "No whitelisted emails.").await
                }
                Ok(entries) => {
                    let list = entries
                        .iter()
                        .map(|(e, t)| format!("• {e} ({t})"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.send_reply(chat_id, &format!("Whitelisted emails:\n{list}"))
                        .await;
                }
                Err(e) => self.send_reply(chat_id, &format!("✗ Failed: {e}")).await,
            }
        }
    }

    /// Send a plain text reply to a Telegram chat.
    async fn send_reply(&self, chat_id: i64, text: &str) {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.config.bot_token
        );
        let _ = self
            .http
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": text,
            }))
            .send()
            .await;
    }

    /// Send a message via Telegram Bot API with inline keyboard.
    /// `target_chat_id` overrides the default chat_id if provided.
    /// When `passkey_url` is Some, the Approve button becomes a URL button
    /// pointing to the passkey page instead of a callback. `offer_grant` adds
    /// a third "Approve for 30 min" callback button (#49) on the standard
    /// keyboard only — never on the passkey variant.
    async fn send_telegram_message(
        &self,
        text: &str,
        request_id: &str,
        target_chat_id: Option<&str>,
        passkey_url: Option<&str>,
        offer_grant: bool,
    ) -> Result<(), AgentSecError> {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.config.bot_token
        );

        let chat_id = target_chat_id.unwrap_or(&self.config.chat_id);

        let inline_keyboard = if let Some(passkey_url) = passkey_url {
            // Passkey required: URL button for approve, callback for deny.
            serde_json::json!({
                "inline_keyboard": [[
                    {
                        "text": "\u{1f510} Approve (Passkey)",
                        "url": passkey_url
                    },
                    {
                        "text": "\u{274c} Deny",
                        "callback_data": format!("deny:{request_id}")
                    }
                ]]
            })
        } else {
            // Standard: callback buttons for both, plus the optional
            // time-boxed grant button on its own row.
            let mut rows = vec![vec![
                serde_json::json!({
                    "text": "\u{2705} Approve",
                    "callback_data": format!("approve:{request_id}")
                }),
                serde_json::json!({
                    "text": "\u{274c} Deny",
                    "callback_data": format!("deny:{request_id}")
                }),
            ]];
            if offer_grant {
                rows.push(vec![serde_json::json!({
                    "text": format!(
                        "\u{23f1} Approve for {} min",
                        tap_core::grants::GRANT_DEFAULT_TTL_MINUTES
                    ),
                    "callback_data": format!("grant:{request_id}")
                })]);
            }
            serde_json::json!({ "inline_keyboard": rows })
        };

        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": inline_keyboard,
        });

        let resp = self
            .http
            .post(&url)
            .json(&payload)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| AgentSecError::Internal(format!("Telegram API error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            error!(%status, %body, "Telegram sendMessage failed");
            return Err(AgentSecError::Internal(format!(
                "Telegram API returned {status}: {body}"
            )));
        }

        // Store message_id in PendingApproval so handle_callback can edit the message later.
        match resp.json::<serde_json::Value>().await {
            Ok(body) => {
                if let Some(message_id) = body["result"]["message_id"].as_i64() {
                    if let Some(approval) = self.pending.lock().await.get_mut(request_id) {
                        approval.sent_message = Some((chat_id.to_string(), message_id));
                    }
                    if let Some(store) = self.store.clone() {
                        if let Err(e) = store
                            .set_pending_approval_telegram_message(request_id, chat_id, message_id)
                            .await
                        {
                            warn!(
                                request_id,
                                error = %e,
                                "Failed to persist Telegram message metadata; approval message may not be edited after decision"
                            );
                        }
                    }
                } else {
                    warn!(
                        request_id,
                        body = %body,
                        "Telegram sendMessage response missing result.message_id; approval message will not be edited after decision"
                    );
                }
            }
            Err(e) => {
                warn!(
                    request_id,
                    error = %e,
                    "Failed to parse Telegram sendMessage response; approval message will not be edited after decision"
                );
            }
        }

        Ok(())
    }
}

/// Format a human-readable approval message for Telegram, with optional N-of-M info.
pub fn format_message_with_context(
    request: &ProxyRequest,
    credential_description: &str,
    min_approvals: u32,
) -> String {
    let mut msg = format_message(request, credential_description);
    if min_approvals > 1 {
        msg.push_str(&format!(
            "\n\n<b>Requires {min_approvals} approvals</b> — others can also approve this request."
        ));
    }
    msg
}

/// Format a human-readable approval message for Telegram.
pub fn format_message(request: &ProxyRequest, credential_description: &str) -> String {
    let mut msg = String::new();

    msg.push_str("<b>\u{1f511} Approval Request</b>\n\n");

    // Deterministic one-line summary for recognized services (tap-core).
    if let Some(summary) = tap_core::summary::summarize_request(
        &request.target_url,
        &request.method,
        request.body.as_deref(),
    ) {
        msg.push_str(&format!("<b>Action:</b> {}\n", escape_html(&summary)));
    }

    msg.push_str(&format!(
        "<b>Agent:</b> {}\n",
        escape_html(&request.agent_id)
    ));

    for placeholder in &request.placeholders {
        msg.push_str(&format!(
            "<b>Credential:</b> {}\n",
            escape_html(&placeholder.credential_name)
        ));
    }

    msg.push_str(&format!(
        "<b>Description:</b> {}\n",
        escape_html(credential_description)
    ));
    msg.push_str(&format!("<b>Method:</b> {:?}\n", request.method));
    msg.push_str(&format!(
        "<b>Target:</b> {}\n",
        escape_html(&request.target_url)
    ));

    if let Some(body) = &request.body {
        if let Ok(body_str) = std::str::from_utf8(body) {
            let display_body = decode_base64_fields(body_str);
            let truncated = if display_body.len() > 1500 {
                format!("{}...", &display_body[..1500])
            } else {
                display_body
            };
            msg.push_str(&format!(
                "\n<b>Body:</b>\n<pre>{}</pre>",
                escape_html(&truncated)
            ));
        }
    }

    msg
}

/// If a JSON body contains string values that look like base64, decode them inline
/// so approval messages are human-readable. Works for any API (Gmail raw, etc.).
fn decode_base64_fields(body: &str) -> String {
    // Try to parse as JSON
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_string();
    };

    fn decode_value(v: &mut serde_json::Value) {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
        use base64::Engine;

        match v {
            serde_json::Value::String(s) => {
                // Heuristic: if the string is >40 chars and looks like base64, try decoding
                if s.len() > 40
                    && s.chars().all(|c| {
                        c.is_ascii_alphanumeric()
                            || c == '+'
                            || c == '/'
                            || c == '='
                            || c == '-'
                            || c == '_'
                            || c == '\n'
                            || c == '\r'
                    })
                {
                    // Try URL-safe base64 first (Gmail uses this), then standard
                    let decoded = URL_SAFE_NO_PAD
                        .decode(s.as_bytes())
                        .or_else(|_| URL_SAFE.decode(s.as_bytes()))
                        .or_else(|_| STANDARD.decode(s.as_bytes()));
                    if let Ok(bytes) = decoded {
                        if let Ok(text) = String::from_utf8(bytes) {
                            // Only replace if the result is readable text
                            if text
                                .chars()
                                .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
                            {
                                *s = text;
                            }
                        }
                    }
                }
            }
            serde_json::Value::Object(map) => {
                for (_, val) in map.iter_mut() {
                    decode_value(val);
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr.iter_mut() {
                    decode_value(val);
                }
            }
            _ => {}
        }
    }

    decode_value(&mut value);
    // Pretty-print the decoded JSON
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| body.to_string())
}

/// Escape HTML special characters for Telegram HTML parse mode.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[async_trait::async_trait]
impl ApprovalChannel for TelegramChannel {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        credential_description: &str,
        context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        let channel_request_id = request.id.to_string();

        self.register_pending(&channel_request_id).await;

        // Apply routing overrides to the newly created PendingApproval.
        if let Some(routing) = &context.routing {
            let mut map = self.pending.lock().await;
            if let Some(approval) = map.get_mut(&channel_request_id) {
                if !routing.allowed_approvers.is_empty() {
                    approval.allowed_approvers = routing.allowed_approvers.clone();
                }
                let min = routing.min_approvals.max(1) as usize;
                if min > 1 {
                    approval.min_approvals = min;
                }
            }
        }

        // Determine target chat_id: per-credential override or global default.
        let target_chat_id = context
            .routing
            .as_ref()
            .and_then(|r| r.telegram.as_ref())
            .and_then(|t| t.chat_id.as_deref());

        let min_approvals = context
            .routing
            .as_ref()
            .map(|r| r.min_approvals.max(1))
            .unwrap_or(1);
        let mut message =
            format_message_with_context(request, credential_description, min_approvals);

        // Determine passkey URL for the inline keyboard button.
        let passkey_url = if context.require_passkey {
            if context.approval_url.is_some() {
                message.push_str("\n\n\u{1f510} <b>Passkey required</b> — tap the button below to approve with biometric/YubiKey.");
            }
            context.approval_url.as_deref()
        } else if let Some(ref url) = context.approval_url {
            message.push_str(&format!(
                "\n\n\u{1f512} <a href=\"{}\">Secure approval (biometric/YubiKey)</a>",
                escape_html(url)
            ));
            None
        } else {
            None
        };

        // Offer the "Approve for 30 min" button only where a grant can
        // actually be minted: DB-backed deployment, a team-owned non-end-user
        // credential, single-approval flow, no passkey requirement, and a
        // target URL a concrete scope can be derived from. The callback
        // re-checks all of it (defense-in-depth) — this just avoids showing a
        // button that can only fail.
        let offer_grant = self.store.is_some()
            && !context.require_passkey
            && context.end_user_id.is_none()
            && context.team_id.as_deref().is_some_and(|t| !t.is_empty())
            && !context.credential_name.is_empty()
            && !context.credential_name.starts_with("eu:")
            && min_approvals <= 1
            && tap_core::grants::scope_from_target(&request.target_url).is_some();

        if let Err(e) = self
            .send_telegram_message(
                &message,
                &channel_request_id,
                target_chat_id,
                passkey_url,
                offer_grant,
            )
            .await
        {
            self.pending.lock().await.remove(&channel_request_id);
            self.receivers.lock().await.remove(&channel_request_id);
            return Err(e);
        }

        info!(
            request_id = %channel_request_id,
            agent_id = %request.agent_id,
            credential = %context.credential_name,
            chat_id = target_chat_id.unwrap_or(&self.config.chat_id),
            "Approval request sent to Telegram"
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
                    if self.store.is_some() {
                        match self
                            .persist_resolution(channel_request_id, ApprovalStatus::Timeout)
                            .await
                        {
                            Ok(false) => warn!(
                                request_id = channel_request_id,
                                "Timed out waiting for approval and found no persisted pending row"
                            ),
                            Ok(true) => {}
                            Err(e) => warn!(
                                request_id = channel_request_id,
                                error = %e,
                                "Failed to persist timed out Telegram approval"
                            ),
                        }
                    }
                    self.cleanup_pending_request(channel_request_id).await;
                    return Err(AgentSecError::ApprovalTimeout(timeout_seconds));
                }
            }
        }
    }

    fn format_message(&self, request: &ProxyRequest, credential_description: &str) -> String {
        format_message(request, credential_description)
    }

    fn channel_name(&self) -> &str {
        "telegram"
    }

    async fn notify_unauthorized(
        &self,
        channel_request_id: &str,
        user_identifier: &str,
    ) -> Result<(), AgentSecError> {
        // Look up the chat_id from the pending approval's sent message.
        let chat_id = {
            let map = self.pending.lock().await;
            map.get(channel_request_id)
                .and_then(|p| p.sent_message.as_ref().map(|(cid, _)| cid.clone()))
        };
        if let Some(chat_id) = chat_id {
            let url = format!(
                "https://api.telegram.org/bot{}/sendMessage",
                self.config.bot_token
            );
            let _ = self
                .http
                .post(&url)
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "text": format!("{user_identifier} is not authorised to approve or deny this request."),
                }))
                .send()
                .await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tap_core::types::*;
    use uuid::Uuid;

    fn test_request() -> ProxyRequest {
        ProxyRequest {
            id: Uuid::new_v4(),
            agent_id: "openclaw".to_string(),
            target_url: "https://api.twitter.com/2/tweets".to_string(),
            method: HttpMethod::Post,
            headers: vec![
                (
                    "Authorization".to_string(),
                    "Bearer <CREDENTIAL:twitter-holonym>".to_string(),
                ),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body: Some(br#"{"text":"Hello world"}"#.to_vec()),
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

    // --- register_webhook tests ---

    async fn start_mock_telegram_server(
        response: serde_json::Value,
    ) -> (
        String,
        Arc<Mutex<Option<serde_json::Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use axum::{extract::Json as AxumJson, routing::post, Router};

        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();
        let response_clone = response.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            let app = Router::new().route(
                "/{*path}",
                post(move |AxumJson(body): AxumJson<serde_json::Value>| {
                    let cap = captured_clone.clone();
                    let resp = response_clone.clone();
                    async move {
                        *cap.lock().await = Some(body);
                        AxumJson(resp)
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });

        (format!("http://127.0.0.1:{port}"), captured, handle)
    }

    fn webhook_test_channel() -> TelegramChannel {
        let config = TelegramConfig {
            bot_token: "testtoken".to_string(),
            chat_id: "-100".to_string(),
        };
        TelegramChannel::new(config).unwrap()
    }

    #[tokio::test]
    async fn register_webhook_success() {
        let (base_url, _captured, _handle) =
            start_mock_telegram_server(serde_json::json!({"ok": true})).await;
        let channel = webhook_test_channel();
        let result = channel
            .register_webhook_at(&base_url, "https://example.com/tg/webhook", None)
            .await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[tokio::test]
    async fn register_webhook_api_error_propagated() {
        let (base_url, _captured, _handle) = start_mock_telegram_server(serde_json::json!({
            "ok": false,
            "description": "Forbidden: bot was kicked from the chat"
        }))
        .await;
        let channel = webhook_test_channel();
        let result = channel
            .register_webhook_at(&base_url, "https://example.com/tg/webhook", None)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Forbidden"), "expected 'Forbidden' in: {err}");
    }

    #[tokio::test]
    async fn register_webhook_includes_secret_token_when_provided() {
        let (base_url, captured, _handle) =
            start_mock_telegram_server(serde_json::json!({"ok": true})).await;
        let channel = webhook_test_channel();
        channel
            .register_webhook_at(
                &base_url,
                "https://example.com/tg/webhook",
                Some("my-secret"),
            )
            .await
            .unwrap();

        let body = captured.lock().await.take().expect("no request captured");
        assert_eq!(
            body["secret_token"].as_str(),
            Some("my-secret"),
            "body: {body}"
        );
    }

    #[tokio::test]
    async fn register_webhook_omits_secret_token_when_none() {
        let (base_url, captured, _handle) =
            start_mock_telegram_server(serde_json::json!({"ok": true})).await;
        let channel = webhook_test_channel();
        channel
            .register_webhook_at(&base_url, "https://example.com/tg/webhook", None)
            .await
            .unwrap();

        let body = captured.lock().await.take().expect("no request captured");
        assert!(
            body.get("secret_token").is_none(),
            "expected no secret_token in body, got: {body}"
        );
    }

    // --- format_message tests ---

    #[test]
    fn format_message_contains_all_fields() {
        let request = test_request();
        let msg = format_message(&request, "Twitter API for @HolonymHQ");
        assert!(msg.contains("openclaw"));
        assert!(msg.contains("twitter-holonym"));
        assert!(msg.contains("Twitter API for @HolonymHQ"));
        assert!(msg.contains("Post")); // HttpMethod debug format
        assert!(msg.contains("api.twitter.com"));
        assert!(msg.contains("Hello world"));
    }

    #[test]
    fn format_message_includes_action_summary_for_gmail() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let raw = URL_SAFE_NO_PAD.encode("To: alice@example.com\r\nSubject: Hello\r\n\r\nHi!");
        let mut request = test_request();
        request.target_url =
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send".to_string();
        request.body = Some(serde_json::json!({ "raw": raw }).to_string().into_bytes());
        let msg = format_message(&request, "Gmail for ops");
        assert!(
            msg.contains(
                "<b>Action:</b> Send an email to alice@example.com — subject &quot;Hello&quot;"
            ),
            "msg: {msg}"
        );
    }

    #[test]
    fn format_message_omits_action_for_unknown_service() {
        let mut request = test_request();
        request.target_url = "https://api.example.com/v1/things".to_string();
        let msg = format_message(&request, "Test");
        assert!(!msg.contains("<b>Action:</b>"));
    }

    #[test]
    fn format_message_truncates_long_body() {
        let mut request = test_request();
        let long_body = "a".repeat(2000);
        request.body = Some(long_body.as_bytes().to_vec());
        let msg = format_message(&request, "Test");
        // Body preview should be truncated at 1500 chars
        let body_section = msg.split("<b>Body:</b>").nth(1).unwrap_or("");
        assert!(body_section.contains("..."));
    }

    #[test]
    fn format_message_handles_no_body() {
        let mut request = test_request();
        request.body = None;
        let msg = format_message(&request, "Test");
        // Should not contain Body section with content
        assert!(!msg.contains("<pre>"));
    }

    #[test]
    fn format_message_escapes_html() {
        let mut request = test_request();
        request.body = Some(b"<script>alert('xss')</script>".to_vec());
        let msg = format_message(&request, "Test");
        assert!(msg.contains("&lt;script&gt;"));
        assert!(!msg.contains("<script>"));
    }

    #[test]
    fn trait_implementation_compiles() {
        fn assert_impl<T: tap_core::approval::ApprovalChannel>() {}
        assert_impl::<TelegramChannel>();
    }

    #[tokio::test]
    async fn pending_approval_tracked() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config).unwrap();
        channel.register_pending("req-123").await;
        assert!(channel.is_pending("req-123").await);
    }

    #[tokio::test]
    async fn approval_resolved_removes_pending() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config).unwrap();
        channel.register_pending("req-456").await;

        assert!(channel.is_pending("req-456").await);
        channel
            .resolve_approval("req-456", ApprovalStatus::Approved)
            .await;
        assert!(!channel.is_pending("req-456").await);

        // The receiver should have the status (resolve_approval_as does not touch receivers).
        let rx = channel.receivers.lock().await.remove("req-456").unwrap();
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn deny_callback_sends_denied() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config).unwrap();
        channel.register_pending("req-789").await;

        channel
            .resolve_approval("req-789", ApprovalStatus::Denied)
            .await;

        let rx = channel.receivers.lock().await.remove("req-789").unwrap();
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Denied);
    }

    #[tokio::test]
    async fn trust_session_tracks_agent() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config).unwrap();

        assert!(
            !channel
                .should_auto_trust("openclaw", "twitter-holonym")
                .await
        );

        channel.trust_session("openclaw", "twitter-holonym").await;

        assert!(
            channel
                .should_auto_trust("openclaw", "twitter-holonym")
                .await
        );
        // Different credential should not be trusted
        assert!(!channel.should_auto_trust("openclaw", "gmail-holonym").await);
    }

    #[tokio::test]
    async fn handle_callback_parses_approve() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config).unwrap();
        channel.register_pending("req-abc").await;

        // handle_callback will try to call Telegram API (answerCallbackQuery) which will fail,
        // but the approval resolution should still work
        let _ = channel
            .handle_callback("approve:req-abc", "cq-123", None)
            .await;

        assert!(!channel.is_pending("req-abc").await);
        let rx = channel.receivers.lock().await.remove("req-abc").unwrap();
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn handle_callback_parses_deny() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config).unwrap();
        channel.register_pending("req-def").await;

        let _ = channel
            .handle_callback("deny:req-def", "cq-456", None)
            .await;

        let rx = channel.receivers.lock().await.remove("req-def").unwrap();
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Denied);
    }

    #[tokio::test]
    async fn handle_callback_invalid_format() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config).unwrap();
        let result = channel.handle_callback("invalid", "cq-789", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn wait_for_decision_times_out() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config).unwrap();
        channel.register_pending("req-timeout").await;

        // Wait with 1 second timeout — nobody resolves it
        let result = channel.wait_for_decision("req-timeout", 1).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AgentSecError::ApprovalTimeout(secs) => assert_eq!(secs, 1),
            other => panic!("Expected ApprovalTimeout, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn wait_for_decision_receives_approval() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = Arc::new(TelegramChannel::new(config).unwrap());

        channel.register_pending("req-fast").await;

        // Spawn a task that resolves the approval after a short delay
        let ch = channel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            ch.resolve_approval("req-fast", ApprovalStatus::Approved)
                .await;
        });

        let result = channel.wait_for_decision("req-fast", 5).await;
        assert_eq!(result.unwrap(), ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn wait_for_decision_observes_persisted_passkey_resolution() {
        let store = test_store().await;
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::with_store(config, Some(store.clone())).unwrap();
        let request_id = format!("req-{}", Uuid::new_v4());
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store
            .save_pending_approval(&request_id, "{}", &expires_at)
            .await
            .unwrap();

        channel.register_pending(&request_id).await;
        let store2 = store.clone();
        let request_id2 = request_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            store2
                .resolve_pending_approval(&request_id2, "approved", Some("123456"))
                .await
                .unwrap();
        });

        let status = channel.wait_for_decision(&request_id, 2).await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
        assert!(!channel.is_pending(&request_id).await);
        store.delete_pending_approval(&request_id).await.unwrap();
    }

    #[tokio::test]
    async fn handle_callback_resolves_persisted_approval_without_local_sender() {
        let store = test_store().await;
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::with_store(config, Some(store.clone())).unwrap();
        let request_id = format!("req-{}", Uuid::new_v4());
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

        store
            .save_pending_approval(&request_id, "{}", &expires_at)
            .await
            .unwrap();

        channel
            .handle_callback(&format!("approve:{request_id}"), "cq-999", Some("123456"))
            .await
            .unwrap();

        let status = store
            .get_pending_approval_status(&request_id)
            .await
            .unwrap();
        assert_eq!(status.as_deref(), Some("approved"));

        store.delete_pending_approval(&request_id).await.unwrap();
    }

    #[tokio::test]
    async fn handle_callback_before_pending_save_survives_late_save() {
        let store = test_store().await;
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::with_store(config, Some(store.clone())).unwrap();
        let request_id = format!("req-{}", Uuid::new_v4());
        store.delete_pending_approval(&request_id).await.unwrap();

        channel
            .handle_callback(&format!("approve:{request_id}"), "cq-early", Some("123456"))
            .await
            .unwrap();

        // This simulates a very fast button tap reaching a different instance
        // before the proxy writes its pending row after sendMessage returns.
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store
            .save_pending_approval(&request_id, "{}", &expires_at)
            .await
            .unwrap();

        let status = store
            .get_pending_approval_status(&request_id)
            .await
            .unwrap();
        assert_eq!(status.as_deref(), Some("approved"));

        store.delete_pending_approval(&request_id).await.unwrap();
    }

    #[tokio::test]
    async fn resolve_approval_reports_db_success_without_local_sender() {
        let store = test_store().await;
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::with_store(config, Some(store.clone())).unwrap();
        let request_id = format!("req-{}", Uuid::new_v4());
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

        store
            .save_pending_approval(&request_id, "{}", &expires_at)
            .await
            .unwrap();

        let resolved = channel
            .resolve_approval_as(&request_id, ApprovalStatus::Approved, Some("123456"))
            .await;

        assert!(resolved);
        let status = store
            .get_pending_approval_status(&request_id)
            .await
            .unwrap();
        assert_eq!(status.as_deref(), Some("approved"));

        store.delete_pending_approval(&request_id).await.unwrap();
    }

    #[tokio::test]
    async fn sent_message_for_request_loads_persisted_telegram_metadata() {
        let store = test_store().await;
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::with_store(config, Some(store.clone())).unwrap();
        let request_id = format!("req-{}", Uuid::new_v4());

        store
            .set_pending_approval_telegram_message(&request_id, "-100999", 424242)
            .await
            .unwrap();

        let sent_message = channel.sent_message_for_request(&request_id).await;
        assert_eq!(sent_message, Some(("-100999".to_string(), 424242)));

        store.delete_pending_approval(&request_id).await.unwrap();
    }

    // --- "Approve for 30 min" grant callback (#49) ---------------------------

    /// Isolated environment for the grant-button tests: a team, a member with
    /// a linked Telegram account (`777001`), and a pending approval row
    /// carrying the reviewed request's details (as the proxy now persists for
    /// messaging-channel rows).
    async fn grant_env(role: &str) -> (Arc<ConfigStore>, TelegramChannel, String, String) {
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
            .update_user_identity(&uid, None, None, Some("777001"))
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

        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::with_store(config, Some(store.clone())).unwrap();
        (store, channel, team_id, request_id)
    }

    #[tokio::test]
    async fn grant_callback_approves_and_opens_scoped_window() {
        let (store, channel, team_id, request_id) = grant_env("owner").await;

        channel
            .handle_callback(&format!("grant:{request_id}"), "cq-grant", Some("777001"))
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
    async fn grant_callback_refuses_non_manager_and_leaves_pending() {
        let (store, channel, team_id, request_id) = grant_env("approver").await;

        channel
            .handle_callback(&format!("grant:{request_id}"), "cq-grant-2", Some("777001"))
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
    async fn grant_callback_refuses_unlinked_telegram_account() {
        let (store, channel, team_id, request_id) = grant_env("owner").await;

        channel
            .handle_callback(&format!("grant:{request_id}"), "cq-grant-3", Some("999999"))
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
    async fn grant_callback_passkey_credential_approves_without_window() {
        let (store, channel, team_id, request_id) = grant_env("owner").await;
        // Tighten the live policy AFTER the request was queued — the grant
        // core re-reads it, so no window may open on a passkey credential.
        store
            .set_policy(&tap_core::store::PolicyRow {
                team_id: team_id.clone(),
                credential_name: "api-cred".to_string(),
                auto_approve_methods: vec![],
                require_approval_methods: vec!["POST".to_string()],
                auto_approve_urls: vec![],
                require_approval_urls: vec![],
                allowed_approvers: vec![],
                approval_channel: None,
                telegram_chat_id: None,
                matrix_room_id: None,
                matrix_allowed_approvers: vec![],
                require_passkey: true,
                min_approvals: 1,
            })
            .await
            .unwrap();

        channel
            .handle_callback(&format!("grant:{request_id}"), "cq-grant-4", Some("777001"))
            .await
            .unwrap();

        // The claim is atomic and final — approved, but fail toward fewer
        // auto-approvals: no window.
        assert_eq!(
            store
                .get_pending_approval_status(&request_id)
                .await
                .unwrap()
                .as_deref(),
            Some("approved")
        );
        assert!(store
            .list_approval_grants(&team_id)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn wait_for_decision_persists_timeout_status() {
        let store = test_store().await;
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::with_store(config, Some(store.clone())).unwrap();
        let request_id = format!("req-{}", Uuid::new_v4());
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

        store
            .save_pending_approval(&request_id, "{}", &expires_at)
            .await
            .unwrap();
        channel.register_pending(&request_id).await;

        let result = channel.wait_for_decision(&request_id, 1).await;
        assert!(matches!(result, Err(AgentSecError::ApprovalTimeout(1))));

        let status = store
            .get_pending_approval_status(&request_id)
            .await
            .unwrap();
        assert_eq!(status.as_deref(), Some("expired"));

        store.delete_pending_approval(&request_id).await.unwrap();
    }
}
