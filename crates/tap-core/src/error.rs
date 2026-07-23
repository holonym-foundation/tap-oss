use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentSecError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("credential not found: {0}")]
    CredentialNotFound(String),

    #[error("placeholder in non-auth position: credential '{credential}' found in {location}")]
    PlaceholderPositionViolation {
        credential: String,
        location: String,
    },

    #[error("approval denied: {0}")]
    ApprovalDenied(String),

    #[error("approval timeout after {0}s")]
    ApprovalTimeout(u64),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("internal: {0}")]
    Internal(String),
}
