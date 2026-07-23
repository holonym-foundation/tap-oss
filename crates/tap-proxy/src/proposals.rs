//! Agent-originated proposals and the credential prefill-link helper.
//!
//! Two distinct shapes:
//! - **policy_change** — a durable proposal an agent submits and a workspace
//!   manager approves (with a passkey). Carried by `PolicyChangePayload`,
//!   stored in `proposals.payload_json`.
//! - **credential_create** — NOT stored. The agent asks for a prefilled link
//!   (`CredentialLinkRequest`) to the dashboard creation form; the human
//!   supplies the secret and saves via the existing `POST /team/credentials`.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tap_core::policy_diff::PolicyView;
use tap_core::store::PolicyRow;

const VALID_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// A proposed policy change. All policy fields except `credential_name` are
/// optional: an absent field is left UNCHANGED when the change is applied
/// (merge semantics), so an agent can propose a single tweak.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyChangePayload {
    pub credential_name: String,
    #[serde(default)]
    pub auto_approve_methods: Option<Vec<String>>,
    #[serde(default)]
    pub require_approval_methods: Option<Vec<String>>,
    #[serde(default)]
    pub auto_approve_urls: Option<Vec<String>>,
    #[serde(default)]
    pub require_approval_urls: Option<Vec<String>>,
    #[serde(default)]
    pub require_passkey: Option<bool>,
    #[serde(default)]
    pub min_approvals: Option<u32>,
    #[serde(default)]
    pub allowed_approvers: Option<Vec<String>>,
}

impl PolicyChangePayload {
    /// Validate shape. Returns a human-readable error on failure.
    pub fn validate(&self) -> Result<(), String> {
        if self.credential_name.trim().is_empty() {
            return Err("credential_name is required".into());
        }
        // Defense-in-depth for the end-user passkey-lock (R2): policy changes to
        // a managed end-user's namespaced credential cannot flow through the
        // agent-proposal → workspace-manager-approval path at all. Loosening an
        // end-user's protection must go through that end-user's own passkey
        // flow. The approve handler also enforces `end_user_policy_lock`, but
        // rejecting at creation keeps these inert proposals from ever existing.
        if self.credential_name.trim_start().starts_with("eu:") {
            return Err("credential_name must not target a managed end-user credential".into());
        }
        for list in [&self.auto_approve_methods, &self.require_approval_methods]
            .into_iter()
            .flatten()
        {
            for m in list {
                if !VALID_METHODS.contains(&m.to_uppercase().as_str()) {
                    return Err(format!("invalid HTTP method: {m}"));
                }
            }
        }
        if let Some(0) = self.min_approvals {
            return Err("min_approvals must be >= 1".into());
        }
        Ok(())
    }

    /// The `PolicyView` that results from applying this change on top of the
    /// current policy (`None` = no existing policy). Used for the permissiveness
    /// diff and to drive the applied write.
    pub fn merged_view(&self, current: Option<&PolicyView>) -> PolicyView {
        let cur = current
            .cloned()
            .unwrap_or_else(PolicyView::default_baseline);
        PolicyView {
            auto_approve_methods: self
                .auto_approve_methods
                .clone()
                .map(|v| v.iter().map(|m| m.to_uppercase()).collect())
                .unwrap_or(cur.auto_approve_methods),
            require_approval_methods: self
                .require_approval_methods
                .clone()
                .map(|v| v.iter().map(|m| m.to_uppercase()).collect())
                .unwrap_or(cur.require_approval_methods),
            auto_approve_urls: self
                .auto_approve_urls
                .clone()
                .unwrap_or(cur.auto_approve_urls),
            require_approval_urls: self
                .require_approval_urls
                .clone()
                .unwrap_or(cur.require_approval_urls),
            require_passkey: self.require_passkey.unwrap_or(cur.require_passkey),
            min_approvals: self.min_approvals.unwrap_or(cur.min_approvals),
            allowed_approvers: self
                .allowed_approvers
                .clone()
                .unwrap_or(cur.allowed_approvers),
        }
    }
}

/// Build a `PolicyView` from a stored `PolicyRow` (the policy-relevant fields,
/// normalized) for permissiveness diffing.
pub fn policy_view_from_row(row: &PolicyRow) -> PolicyView {
    PolicyView {
        auto_approve_methods: row
            .auto_approve_methods
            .iter()
            .map(|m| m.to_uppercase())
            .collect(),
        require_approval_methods: row
            .require_approval_methods
            .iter()
            .map(|m| m.to_uppercase())
            .collect(),
        auto_approve_urls: row.auto_approve_urls.clone(),
        require_approval_urls: row.require_approval_urls.clone(),
        require_passkey: row.require_passkey,
        min_approvals: row.min_approvals,
        allowed_approvers: row.allowed_approvers.clone(),
    }
}

/// Metadata the agent proposes for a new credential. Used ONLY to build a
/// prefill link — never stored, never contains a secret.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialLinkRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub connector: Option<String>,
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default)]
    pub relative_target: Option<bool>,
    #[serde(default)]
    pub auth_header_format: Option<String>,
    #[serde(default)]
    pub auth_bindings: Option<Vec<tap_core::config::AuthBinding>>,
    /// Destination-host exfiltration binding (`allowed_hosts`, Decision #17).
    /// Prefilled so the agent can steer its user toward binding a secret-bearing
    /// credential to its real upstream host(s). Metadata only — never a secret.
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Dashboard credential template to preselect (e.g. "signing"). Lets the
    /// prefill link open the right modal preset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// For signing-key templates, the curve to preselect ("secp256k1",
    /// "ed25519", "p256").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

/// Resolve the dashboard base URL the same way approval links do
/// (`TAP_APPROVAL_BASE_URL` / `TAP_APP_URL`, else the proxy URL).
fn dashboard_base() -> String {
    std::env::var("TAP_APPROVAL_BASE_URL")
        .or_else(|_| std::env::var("TAP_APP_URL"))
        .unwrap_or_else(|_| crate::proxy::configured_proxy_url())
        .trim_end_matches('/')
        .to_string()
}

/// Build a prefilled credential-creation link the agent can hand to its user.
/// The metadata is carried as a base64url(JSON) blob (no secret) so nothing in
/// the URL needs per-field escaping and the form can prepopulate everything.
pub fn credential_prefill_url(req: &CredentialLinkRequest) -> String {
    let json = serde_json::to_string(req).unwrap_or_else(|_| "{}".to_string());
    let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
    // The hash routes the SPA to the credentials view; the query carries the
    // prefill blob the Credentials view decodes to prepopulate the create modal.
    format!(
        "{}/dashboard?prefill_credential={}#/credentials",
        dashboard_base(),
        blob
    )
}

/// Build a minimal prefill link from just a credential name — used in
/// missing-credential error responses where we only know the attempted name.
/// `name` here is whatever the agent sent as `X-TAP-Credential` — an HTTP
/// header value, not something already constrained to the dashboard's
/// `[a-z0-9-]` naming charset — so this returns `None` rather than a link the
/// create form would refuse to submit; callers omit the field in that case.
pub fn credential_prefill_url_for_name(name: &str) -> Option<String> {
    if crate::admin::validate_credential_name(name).is_err() {
        return None;
    }
    Some(credential_prefill_url(&CredentialLinkRequest {
        name: name.to_string(),
        description: None,
        connector: None,
        api_base: None,
        relative_target: None,
        auth_header_format: None,
        auth_bindings: None,
        allowed_hosts: None,
        template: None,
        algorithm: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(cred: &str) -> PolicyChangePayload {
        PolicyChangePayload {
            credential_name: cred.to_string(),
            auto_approve_methods: None,
            require_approval_methods: None,
            auto_approve_urls: None,
            require_approval_urls: None,
            require_passkey: Some(false),
            min_approvals: None,
            allowed_approvers: None,
        }
    }

    #[test]
    fn validate_rejects_empty_credential_name() {
        assert!(payload("   ").validate().is_err());
    }

    #[test]
    fn validate_rejects_end_user_credential_name() {
        // R2 defense-in-depth: a proposal must not target an end-user's
        // namespaced credential — that would route an end-user policy loosening
        // through the manager-approval path instead of the end-user's passkey.
        let err = payload("eu:victim/wallet-signer").validate().unwrap_err();
        assert!(err.contains("end-user"));
        // Leading whitespace must not smuggle it past the check.
        assert!(payload("  eu:victim/x").validate().is_err());
    }

    #[test]
    fn validate_allows_ordinary_credential_name() {
        assert!(payload("stripe-prod").validate().is_ok());
    }

    #[test]
    fn prefill_url_round_trips_allowed_hosts() {
        let req = CredentialLinkRequest {
            name: "digitalocean".to_string(),
            description: None,
            connector: Some("direct".to_string()),
            api_base: Some("https://api.digitalocean.com".to_string()),
            relative_target: None,
            auth_header_format: Some("Bearer {value}".to_string()),
            auth_bindings: None,
            allowed_hosts: Some(vec!["api.digitalocean.com".to_string()]),
            template: None,
            algorithm: None,
        };
        let url = credential_prefill_url(&req);
        // Decode the base64url(JSON) blob the dashboard reads back.
        let blob = url
            .split("prefill_credential=")
            .nth(1)
            .unwrap()
            .split("#/credentials")
            .next()
            .unwrap();
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(blob)
            .unwrap();
        let back: CredentialLinkRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(
            back.allowed_hosts,
            Some(vec!["api.digitalocean.com".to_string()])
        );
    }

    #[test]
    fn prefill_url_for_name_omitted_when_name_invalid() {
        // A missing-credential /forward error builds this from the raw
        // X-TAP-Credential header value the agent sent — which isn't
        // constrained to the dashboard's naming charset. A name like
        // "google:workspace-admin" (colon) or "notion/api" (slash) must not
        // produce a link the create form's own `pattern="[a-z0-9-]+"` input
        // would refuse to submit.
        assert!(credential_prefill_url_for_name("google:workspace-admin").is_none());
        assert!(credential_prefill_url_for_name("notion/api").is_none());
        assert!(credential_prefill_url_for_name("stripe-prod").is_some());
    }
}
