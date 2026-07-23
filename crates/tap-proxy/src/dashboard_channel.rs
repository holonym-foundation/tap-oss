//! First-party dashboard approval channel.
//!
//! Unlike Telegram/Matrix, this channel has **no external messaging service**.
//! It persists the pending approval to the shared `pending_approvals` table and
//! the approver acts on it inside the dashboard — passkey approvals use an
//! inline modal and session approvals use a one-tap button, both staying in
//! the dashboard (no navigation to the standalone `/approve/txn/:id` page).
//!
//! Because there is no in-process notification to wait on, `wait_for_decision`
//! is a pure DB-poll loop on the durable row. That makes this the most
//! distributed-state-correct channel: a request can begin on instance A and be
//! resolved by an approve handler on instance B with no shared in-memory state —
//! the `pending_approvals` row is the single source of truth (see the Distributed
//! State Rule in CLAUDE.md).
//!
//! The `request.id` is used as the row key, matching `TelegramChannel` and the
//! proxy's `approval_url`/`set_pending_details` path, so all three agree on one id.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{info, warn};

use tap_core::approval::{ApprovalChannel, ApprovalContext};
use tap_core::error::AgentSecError;
use tap_core::store::ConfigStore;
use tap_core::types::{ApprovalStatus, ProxyRequest};

use crate::push::PushSender;
use crate::webauthn::ApprovalDetails;

/// Cap stored body previews so the inbox/approve page render cheaply. Matches
/// the proxy's passkey-path truncation.
const BODY_PREVIEW_MAX: usize = 500;

pub struct DashboardChannel {
    store: Arc<ConfigStore>,
    /// Public base URL of the dashboard, used to build the approve link shown in
    /// agent-facing responses (e.g. `https://app.tap.human.tech`).
    dashboard_base_url: String,
    /// Optional web-push sender. When present, a best-effort push is fired to the
    /// team's subscriptions so approvers are notified without watching the tab.
    /// Push failure never fails the approval — the durable inbox is the source of truth.
    push: Option<Arc<dyn PushSender>>,
    /// How long a dashboard-routed pending row stays actionable, in seconds.
    /// Derived from the approval window (TAP_APPROVAL_TIMEOUT_SECS plus slack)
    /// so the inbox row outlives the transaction it backs.
    pending_ttl_secs: u64,
}

impl DashboardChannel {
    pub fn new(
        store: Arc<ConfigStore>,
        dashboard_base_url: String,
        push: Option<Arc<dyn PushSender>>,
        pending_ttl_secs: u64,
    ) -> Self {
        Self {
            store,
            dashboard_base_url: dashboard_base_url.trim_end_matches('/').to_string(),
            push,
            pending_ttl_secs,
        }
    }

    fn body_preview(request: &ProxyRequest) -> Option<String> {
        let body = request.body.as_ref()?;
        let s = std::str::from_utf8(body).ok()?;
        Some(if s.len() > BODY_PREVIEW_MAX {
            s[..BODY_PREVIEW_MAX].to_string()
        } else {
            s.to_string()
        })
    }

    async fn delete_row(&self, txn_id: &str) {
        if let Err(e) = self.store.delete_pending_approval(txn_id).await {
            warn!(txn_id, error = %e, "Failed to delete resolved pending_approvals row");
        }
    }
}

#[async_trait]
impl ApprovalChannel for DashboardChannel {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        credential_description: &str,
        context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        let id = request.id.to_string();
        let team_id = context.team_id.clone().unwrap_or_default();
        let action_summary = tap_core::summary::summarize_request(
            &request.target_url,
            &request.method,
            request.body.as_deref(),
        );

        // Persist the full request detail so both the dashboard inbox and the
        // passkey approve page can render it. `approver_emails` is the optional
        // policy restriction; role/credential assignment is checked at approval time.
        let details = ApprovalDetails {
            txn_id: id.clone(),
            team_id: team_id.clone(),
            agent_id: request.agent_id.clone(),
            credential_name: context.credential_name.clone(),
            target_url: request.target_url.clone(),
            method: request.method.to_string(),
            body_preview: Self::body_preview(request),
            summary: action_summary.clone(),
            allowed_approvers: context.approver_emails.clone(),
            require_passkey: context.require_passkey,
        };
        let json = serde_json::to_string(&details)
            .map_err(|e| AgentSecError::Internal(format!("Failed to serialize approval: {e}")))?;
        let expires_at = (chrono::Utc::now()
            + chrono::Duration::seconds(self.pending_ttl_secs as i64))
        .to_rfc3339();
        let team_opt = (!team_id.is_empty()).then_some(team_id.as_str());
        self.store
            .save_pending_approval_scoped(
                &id,
                &json,
                &expires_at,
                team_opt,
                context.end_user_id.as_deref(),
            )
            .await?;

        // Best-effort push notification. Never gate approval on delivery — the
        // inbox row already persisted above is the durable source of truth.
        if let Some(push) = &self.push {
            if !team_id.is_empty() {
                let summary = action_summary.unwrap_or_else(|| {
                    format!(
                        "{} {} via {}",
                        request.method, request.target_url, credential_description
                    )
                });
                if let Err(e) = push.notify_team(&team_id, &id, &summary).await {
                    warn!(txn_id = %id, error = %e, "Web push notify failed (inbox still has the request)");
                }
            }
        }

        info!(txn_id = %id, team_id = %team_id, "Dashboard approval request queued");
        Ok(id)
    }

    async fn wait_for_decision(
        &self,
        channel_request_id: &str,
        timeout_seconds: u64,
    ) -> Result<ApprovalStatus, AgentSecError> {
        // Pure DB poll — no in-memory receiver. Works across stateless instances:
        // whichever instance handles the approve POST resolves the row, and any
        // instance polling it observes the transition.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);
        let mut poll = tokio::time::interval(Duration::from_secs(1));
        loop {
            poll.tick().await;
            match self
                .store
                .get_pending_approval_status(channel_request_id)
                .await
            {
                Ok(Some(status)) => match status.as_str() {
                    "approved" => {
                        // Decision is final and the agent has it — delete the row
                        // so the request body (stored in details_json) doesn't
                        // linger in the DB. Expired rows are handled by the
                        // background cleanup job instead, so a late approver
                        // clicking the dashboard link still gets a proper
                        // "already resolved" response rather than a 404.
                        self.delete_row(channel_request_id).await;
                        return Ok(ApprovalStatus::Approved);
                    }
                    "denied" => {
                        self.delete_row(channel_request_id).await;
                        return Ok(ApprovalStatus::Denied);
                    }
                    "expired" | "timeout" => return Ok(ApprovalStatus::Timeout),
                    _ => {} // still pending
                },
                Ok(None) => {
                    // Row vanished (deleted/cleaned up). Treat as no decision.
                    warn!(
                        txn_id = %channel_request_id,
                        "Pending approval row missing while waiting — treating as timeout"
                    );
                    return Err(AgentSecError::ApprovalTimeout(timeout_seconds));
                }
                Err(e) => {
                    // Transient DB error: log and keep polling until the deadline.
                    warn!(txn_id = %channel_request_id, error = %e, "Error polling approval status");
                }
            }

            if tokio::time::Instant::now() >= deadline {
                // Atomically claim the row to Timeout so a late approver can't
                // resolve a request the agent already gave up on. resolve only
                // succeeds while status is still 'pending'.
                if let Err(e) = self
                    .store
                    .resolve_pending_approval(channel_request_id, "expired", None)
                    .await
                {
                    warn!(txn_id = %channel_request_id, error = %e, "Failed to mark dashboard approval timed out");
                }
                // Do NOT delete the expired row here — keep it so that a late
                // approver clicking the dashboard link gets a proper "already
                // resolved" response instead of a ghost "approved" insert.
                // The background cleanup job purges expired resolved rows.
                return Err(AgentSecError::ApprovalTimeout(timeout_seconds));
            }
        }
    }

    fn format_message(&self, request: &ProxyRequest, credential_description: &str) -> String {
        format!(
            "{} {} via {} — review at {}/#/approvals",
            request.method, request.target_url, credential_description, self.dashboard_base_url
        )
    }

    fn channel_name(&self) -> &str {
        "dashboard"
    }

    /// The dashboard channel writes the full `ApprovalDetails` into
    /// `pending_approvals` in `send_approval_request` (keyed by `request.id`),
    /// which the inbox and passkey page read directly. The proxy must not
    /// overwrite that row with an empty placeholder.
    fn persists_own_details(&self) -> bool {
        true
    }

    async fn notify_unauthorized(
        &self,
        _channel_request_id: &str,
        _user_identifier: &str,
    ) -> Result<(), AgentSecError> {
        // The dashboard approve endpoints (session and passkey) return a 403 with
        // an explanatory body inline, so there is no out-of-band channel to notify.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_core::types::HttpMethod;
    use uuid::Uuid;

    fn test_db_url() -> String {
        std::env::var("POSTGRES_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://tap:tap@localhost:5434/tap".to_string())
    }

    async fn store() -> Arc<ConfigStore> {
        Arc::new(
            ConfigStore::new(&test_db_url(), [0u8; 32])
                .await
                .expect("connect test db"),
        )
    }

    fn request(team_agent: &str) -> ProxyRequest {
        ProxyRequest {
            id: Uuid::new_v4(),
            agent_id: team_agent.to_string(),
            target_url: "https://api.example.com/v1/things".to_string(),
            method: HttpMethod::Post,
            headers: vec![],
            body: Some(b"{\"hello\":\"world\"}".to_vec()),
            content_type: Some("application/json".to_string()),
            placeholders: vec![],
            received_at: chrono::Utc::now(),
        }
    }

    fn ctx(team_id: &str, approvers: Vec<String>) -> ApprovalContext {
        ApprovalContext {
            team_id: Some(team_id.to_string()),
            credential_name: "stripe".to_string(),
            routing: None,
            approver_emails: approvers,
            approval_url: None,
            require_passkey: false,
            end_user_id: None,
        }
    }

    fn channel(store: Arc<ConfigStore>) -> DashboardChannel {
        DashboardChannel::new(store, "https://app.tap.test".to_string(), None, 1200)
    }

    #[tokio::test]
    async fn send_persists_pending_row_with_team_and_details() {
        let store = store().await;
        let ch = channel(store.clone());
        let team = format!("team-{}", Uuid::new_v4());
        let req = request("agent-1");
        let id = ch
            .send_approval_request(&req, "Stripe", &ctx(&team, vec!["a@b.com".into()]))
            .await
            .unwrap();

        // Details are persisted and discoverable for the approve page…
        let json = store.get_pending_approval_details(&id).await.unwrap();
        assert!(json.is_some(), "details_json should be persisted");
        let details: ApprovalDetails = serde_json::from_str(&json.unwrap()).unwrap();
        assert_eq!(details.target_url, req.target_url);
        assert_eq!(details.allowed_approvers, vec!["a@b.com".to_string()]);

        // …and team-scoped for the inbox.
        let pending = store.list_pending_approvals_for_team(&team).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].txn_id, id);
    }

    /// Distributed State Rule: begin on instance A, resolve on instance B (a
    /// separate ConfigStore over the same DB), and A observes the decision.
    #[tokio::test]
    async fn resolve_on_other_instance_is_observed() {
        let store_a = store().await;
        let store_b = store().await; // simulates a second stateless proxy instance
        let ch_a = channel(store_a.clone());
        let team = format!("team-{}", Uuid::new_v4());
        let req = request("agent-1");
        let id = ch_a
            .send_approval_request(&req, "Stripe", &ctx(&team, vec![]))
            .await
            .unwrap();

        // Approver acts on instance B.
        let claimed = store_b
            .resolve_pending_approval(&id, "approved", Some("a@b.com"))
            .await
            .unwrap();
        assert!(claimed, "resolve on B should claim the pending row");

        // Instance A's waiter observes Approved on its first poll tick.
        let status = ch_a.wait_for_decision(&id, 5).await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    /// Double-submit / concurrent approval is safe: the second resolve is a no-op
    /// and the recorded decision does not change.
    #[tokio::test]
    async fn double_submit_is_idempotent() {
        let store = store().await;
        let ch = channel(store.clone());
        let team = format!("team-{}", Uuid::new_v4());
        let id = ch
            .send_approval_request(&request("a"), "Stripe", &ctx(&team, vec![]))
            .await
            .unwrap();

        let first = store
            .resolve_pending_approval(&id, "approved", Some("a@b.com"))
            .await
            .unwrap();
        let second = store
            .resolve_pending_approval(&id, "denied", Some("evil@b.com"))
            .await
            .unwrap();
        assert!(first, "first resolve claims the row");
        assert!(!second, "second resolve must be a no-op once resolved");
        assert_eq!(
            ch.wait_for_decision(&id, 5).await.unwrap(),
            ApprovalStatus::Approved
        );
    }

    /// An already-denied request resolves to Denied, not Timeout.
    #[tokio::test]
    async fn already_resolved_denied_is_observed() {
        let store = store().await;
        let ch = channel(store.clone());
        let team = format!("team-{}", Uuid::new_v4());
        let id = ch
            .send_approval_request(&request("a"), "Stripe", &ctx(&team, vec![]))
            .await
            .unwrap();
        store
            .resolve_pending_approval(&id, "denied", Some("a@b.com"))
            .await
            .unwrap();
        assert_eq!(
            ch.wait_for_decision(&id, 5).await.unwrap(),
            ApprovalStatus::Denied
        );
    }

    /// With no decision before the deadline, wait_for_decision times out AND
    /// atomically claims the row to a terminal state so a late approver can't
    /// resolve a request the agent already abandoned.
    #[tokio::test]
    async fn timeout_claims_row_terminally() {
        let store = store().await;
        let ch = channel(store.clone());
        let team = format!("team-{}", Uuid::new_v4());
        let id = ch
            .send_approval_request(&request("a"), "Stripe", &ctx(&team, vec![]))
            .await
            .unwrap();

        let err = ch.wait_for_decision(&id, 1).await.unwrap_err();
        assert!(matches!(err, AgentSecError::ApprovalTimeout(_)));

        // A late approval cannot claim the now-expired row.
        let late = store
            .resolve_pending_approval(&id, "approved", Some("a@b.com"))
            .await
            .unwrap();
        assert!(!late, "late approval must not resolve a timed-out request");
    }

    #[tokio::test]
    async fn inbox_is_team_scoped() {
        let store = store().await;
        let ch = channel(store.clone());
        let team_a = format!("team-{}", Uuid::new_v4());
        let team_b = format!("team-{}", Uuid::new_v4());
        ch.send_approval_request(&request("a"), "Stripe", &ctx(&team_a, vec![]))
            .await
            .unwrap();
        ch.send_approval_request(&request("b"), "Stripe", &ctx(&team_b, vec![]))
            .await
            .unwrap();

        assert_eq!(
            store
                .list_pending_approvals_for_team(&team_a)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .list_pending_approvals_for_team(&team_b)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
