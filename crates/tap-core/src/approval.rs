use async_trait::async_trait;

use crate::config::ApprovalRouting;
use crate::error::AgentSecError;
use crate::types::{ApprovalStatus, ProxyRequest};

/// Per-request approval context. Carries routing overrides from
/// the credential's policy config to the approval channel.
#[derive(Debug, Clone, Default)]
pub struct ApprovalContext {
    /// The team that owns the credential (for notification channel lookups).
    pub team_id: Option<String>,
    /// The credential name triggering the approval.
    pub credential_name: String,
    /// Per-credential routing overrides (chat_id, allowed_approvers, etc.).
    /// None = use global defaults.
    pub routing: Option<ApprovalRouting>,
    /// Policy-level approver restriction emails, captured before
    /// `resolve_approvers` rewrites routing into per-platform IDs. Dashboard and
    /// passkey approval combine this with role/credential assignment at approval
    /// time. Empty = any eligible approver for the credential.
    pub approver_emails: Vec<String>,
    /// Optional WebAuthn approval URL for secure hardware-backed approval.
    pub approval_url: Option<String>,
    /// When true, approval MUST go through passkey — notification channel
    /// suppresses inline approve buttons and shows only the passkey link.
    pub require_passkey: bool,
    /// `Some(ext_id)` when this approval is reserved for a managed end-user
    /// (TAP for Platforms): the channel stamps `required_end_user` on the row so
    /// only that end-user's own authenticated approval can resolve it (the
    /// default-deny gate in `resolve_pending_approval`). `None` = ordinary
    /// team-approvable request.
    pub end_user_id: Option<String>,
}

/// Approval channel trait. Implementations: Telegram, Matrix. Slack/ntfy/iOS for v0.2+.
#[async_trait]
pub trait ApprovalChannel: Send + Sync {
    /// Send an approval request to the human approver.
    /// Returns a channel-specific request ID for tracking.
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        credential_description: &str,
        context: &ApprovalContext,
    ) -> Result<String, AgentSecError>;

    /// Wait for an approval decision. Blocks until approved, denied, or timeout.
    async fn wait_for_decision(
        &self,
        channel_request_id: &str,
        timeout_seconds: u64,
    ) -> Result<ApprovalStatus, AgentSecError>;

    /// Format a human-readable message for the approval request.
    fn format_message(&self, request: &ProxyRequest, credential_description: &str) -> String;

    /// Short identifier for the channel type, e.g. "telegram" or "matrix".
    /// Used in agent-facing responses so agents can tell users where to approve.
    fn channel_name(&self) -> &str;

    /// Whether `send_approval_request` already persisted the full approval
    /// details to `pending_approvals` (keyed by `request.id`).
    ///
    /// Messaging channels (Telegram, Matrix) deliver the details in the chat
    /// message and only need an empty placeholder row in the DB for the proxy's
    /// poll loop — so the proxy creates that placeholder for them. The dashboard
    /// channel instead persists the rich details itself (the inbox and passkey
    /// page read them straight from the row), so the proxy must NOT overwrite
    /// that row with an empty placeholder. Channels that self-persist return
    /// `true` to opt out of the placeholder write.
    fn persists_own_details(&self) -> bool {
        false
    }

    /// Whether this channel expects the proxy to generate a WebAuthn approval
    /// URL and include it in the 202 response body, regardless of whether the
    /// credential's `require_passkey` flag is set.
    ///
    /// The agent-reflected channel returns `true` so the agent can surface the
    /// link inline to the user without any separate messaging setup.
    fn provides_approval_url(&self) -> bool {
        false
    }

    /// Notify a user that they are not authorised to approve or deny a pending request.
    /// Called when an actor attempts to approve or deny but fails the allowed_approvers check.
    /// Implementations must deliver feedback so the actor is not left silently ignored.
    async fn notify_unauthorized(
        &self,
        channel_request_id: &str,
        user_identifier: &str,
    ) -> Result<(), AgentSecError>;
}
