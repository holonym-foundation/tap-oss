//! Agent API key authentication.

pub use tap_core::auth::hash_api_key;

/// Authenticated agent info.
#[derive(Debug, Clone)]
pub struct AuthenticatedAgent {
    pub id: String,
    pub team_id: String,
    /// Whether this is an **app key** (TAP for Platforms) that may assert a
    /// managed end-user sub-scope via `X-TAP-End-User`. Ordinary agent keys
    /// cannot.
    pub is_app: bool,
    /// The managed end-user this request is scoped to, if asserted and
    /// validated (only ever `Some` when `is_app` is true). `None` means the
    /// request operates on ordinary team-scoped credentials.
    pub end_user_id: Option<String>,
    /// An **Account key**: authorized for every credential in its team,
    /// including ones added later — the per-credential whitelist
    /// (`agent_credentials`) is bypassed entirely. The credential still goes
    /// through its own policy (approval/passkey) normally; this only changes
    /// *whether* the agent may reference it, not what it may do with it.
    pub all_credentials: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_hash_is_deterministic() {
        let h1 = hash_api_key("my-api-key-123");
        let h2 = hash_api_key("my-api-key-123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn api_key_hash_different_keys_differ() {
        let h1 = hash_api_key("key-alpha");
        let h2 = hash_api_key("key-beta");
        assert_ne!(h1, h2);
    }
}
