//! Agent-reflected approval channel.
//!
//! Returns the approval URL directly in the 202 response body so the agent can
//! show it to the user inline — no external messaging service required. The user
//! clicks the link, authenticates with their passkey, and approves.
//!
//! Like `DashboardChannel`, the pending row is persisted to `pending_approvals`
//! so the approval also appears in the dashboard inbox as a fallback (useful if
//! the agent fails to display the link or the user navigates there directly).
//!
//! This is the **default channel** for teams with no Telegram or Matrix
//! configuration. Zero setup, works immediately for interactive sessions.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{info, warn};

use tap_core::approval::{ApprovalChannel, ApprovalContext};
use tap_core::error::AgentSecError;
use tap_core::store::ConfigStore;
use tap_core::types::{ApprovalStatus, ProxyRequest};

use crate::webauthn::ApprovalDetails;

const BODY_PREVIEW_MAX: usize = 500;

pub struct AgentReflectedChannel {
    store: Arc<ConfigStore>,
    /// How long the pending inbox row stays actionable, in seconds. Derived
    /// from the approval window (TAP_APPROVAL_TIMEOUT_SECS plus slack) so the
    /// row outlives the transaction it backs.
    pending_ttl_secs: u64,
}

impl AgentReflectedChannel {
    pub fn new(store: Arc<ConfigStore>, pending_ttl_secs: u64) -> Self {
        Self {
            store,
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
}

#[async_trait]
impl ApprovalChannel for AgentReflectedChannel {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        _credential_description: &str,
        context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        let id = request.id.to_string();
        let team_id = context.team_id.clone().unwrap_or_default();

        let details = ApprovalDetails {
            txn_id: id.clone(),
            team_id: team_id.clone(),
            agent_id: request.agent_id.clone(),
            credential_name: context.credential_name.clone(),
            target_url: request.target_url.clone(),
            method: request.method.to_string(),
            body_preview: Self::body_preview(request),
            summary: tap_core::summary::summarize_request(
                &request.target_url,
                &request.method,
                request.body.as_deref(),
            ),
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

        info!(txn_id = %id, team_id = %team_id, "Agent-reflected approval request queued");
        Ok(id)
    }

    async fn wait_for_decision(
        &self,
        channel_request_id: &str,
        timeout_seconds: u64,
    ) -> Result<ApprovalStatus, AgentSecError> {
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
                    "approved" => return Ok(ApprovalStatus::Approved),
                    "denied" => return Ok(ApprovalStatus::Denied),
                    "expired" | "timeout" => return Ok(ApprovalStatus::Timeout),
                    _ => {}
                },
                Ok(None) => {
                    warn!(
                        txn_id = %channel_request_id,
                        "Pending approval row missing — treating as timeout"
                    );
                    return Err(AgentSecError::ApprovalTimeout(timeout_seconds));
                }
                Err(e) => {
                    warn!(txn_id = %channel_request_id, error = %e, "Error polling approval status");
                }
            }

            if tokio::time::Instant::now() >= deadline {
                if let Err(e) = self
                    .store
                    .resolve_pending_approval(channel_request_id, "expired", None)
                    .await
                {
                    warn!(txn_id = %channel_request_id, error = %e, "Failed to mark agent-reflected approval timed out");
                }
                return Err(AgentSecError::ApprovalTimeout(timeout_seconds));
            }
        }
    }

    fn format_message(&self, request: &ProxyRequest, credential_description: &str) -> String {
        format!(
            "{} {} via {} — approval link sent to agent",
            request.method, request.target_url, credential_description
        )
    }

    fn channel_name(&self) -> &str {
        "agent_reflected"
    }

    fn persists_own_details(&self) -> bool {
        true
    }

    /// Tells the proxy to generate a WebAuthn URL and include it in the 202
    /// response so the agent can surface it to the user.
    fn provides_approval_url(&self) -> bool {
        true
    }

    async fn notify_unauthorized(
        &self,
        _channel_request_id: &str,
        _user_identifier: &str,
    ) -> Result<(), AgentSecError> {
        Ok(())
    }
}
