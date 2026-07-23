use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A proxy request from an agent, parsed from the incoming HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub id: Uuid,
    pub agent_id: String,
    pub target_url: String,
    pub method: HttpMethod,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
    /// Credential placeholders found in the request, with their positions.
    pub placeholders: Vec<Placeholder>,
    pub received_at: DateTime<Utc>,
}

/// Where a credential placeholder was found in the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Placeholder {
    pub credential_name: String,
    /// For multi-secret credentials referenced as `<CREDENTIAL:name.field>`,
    /// the field name. `None` for plain `<CREDENTIAL:name>` references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub position: PlaceholderPosition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlaceholderPosition {
    /// In an HTTP header value (always allowed).
    Header(String),
    /// In the request body (only allowed if credential config opts in).
    Body,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options)
    }

    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            _ => Self::Post, // unknown methods require approval
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of processing a proxy request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub request_id: Uuid,
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub sanitized: bool,
}

/// Status of an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Timeout,
}

/// Type of an agent-originated proposal. Currently only policy changes are
/// stored as proposals (credential creation uses the prefill-link path, which
/// keeps no record). Kept as an enum for forward-compat (e.g. #49 grants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalType {
    PolicyChange,
}

impl ProposalType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyChange => "policy_change",
        }
    }
}

/// Lifecycle status of a proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// An entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub request_id: Uuid,
    pub agent_id: String,
    pub credential_names: Vec<String>,
    pub target_url: String,
    pub method: HttpMethod,
    pub approval_status: Option<ApprovalStatus>,
    pub upstream_status: Option<u16>,
    pub total_latency_ms: u64,
    pub approval_latency_ms: Option<u64>,
    pub upstream_latency_ms: Option<u64>,
    pub response_sanitized: bool,
    /// The managed end-user this request acted for (TAP for Platforms), if any.
    /// Drives per-end-user metering; `None` for ordinary team-scoped requests.
    #[serde(default)]
    pub end_user_id: Option<String>,
    /// The request headers exactly as the agent sent them, BEFORE credential
    /// substitution/injection — placeholders like `<CREDENTIAL:name>` or the
    /// `X-TAP-Credential` selector are intact, never a real secret value.
    #[serde(default)]
    pub request_headers: Vec<(String, String)>,
    /// The request body, same pre-substitution guarantee as `request_headers`.
    /// `None` when there was no body or it was not valid UTF-8.
    #[serde(default)]
    pub request_body: Option<String>,
    /// True if `request_body` was truncated to the audit-log size cap.
    #[serde(default)]
    pub request_body_truncated: bool,
    /// Machine-readable policy rule that produced this decision (see
    /// `tap_proxy::policy::PolicyReason`), e.g. `"auto_approve_url"` or
    /// `"require_approval_method"`.
    #[serde(default)]
    pub policy_reason: Option<String>,
    /// Whether this credential's policy required passkey-strength approval.
    #[serde(default)]
    pub require_passkey: bool,
    /// Identity of whoever resolved the approval, when known — a TAP account
    /// email for dashboard/agent-reflected/passkey approvals, or a
    /// messaging-platform identity (Telegram user id, Matrix user id) for
    /// Telegram/Matrix button approvals. `None` when auto-approved or not yet
    /// resolved by a known-identity channel.
    #[serde(default)]
    pub approver_identity: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// AI safety check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCheckResult {
    pub passed: bool,
    pub risk_level: RiskLevel,
    pub concerns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}
