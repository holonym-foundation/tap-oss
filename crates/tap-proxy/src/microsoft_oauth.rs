//! Inline Microsoft (Entra / Graph) OAuth2 token refresh for sidecar credentials.
//!
//! When a sidecar credential's value contains a Microsoft OAuth refresh-token
//! bundle (JSON with client_id, client_secret, refresh_token, **token_url**), the
//! proxy exchanges the refresh token for a fresh access token and injects it
//! directly — no external sidecar service needed. Mirrors `google_oauth.rs`.
//!
//! The required `token_url` field is the discriminator that distinguishes a
//! Microsoft bundle from a Google one (Google has no `token_url`) and from an
//! OAuth 2.0 client-credentials bundle (which has `token_url` but no
//! `refresh_token`). `resolve_unified_route_with_config` therefore matches
//! Microsoft **before** Google.
//!
//! Note on refresh-token rotation: Microsoft may return a new `refresh_token` on
//! redemption. TAP is a *confidential* client (it holds `client_secret`), so the
//! originally-stored refresh token remains valid across the token family's
//! lifetime and per-request refresh with the stored token is correct. Persisting
//! the rotated token back to the credential (to extend the family indefinitely)
//! is a documented follow-up; it is deliberately not done on the hot forward path
//! to avoid a per-request DB write and cross-instance race.

use serde::Deserialize;
use std::fmt;
use tap_core::http_client::{build_client, ClientRoute};

/// Parsed Microsoft OAuth credential value.
#[derive(Debug, Clone, Deserialize)]
pub struct MicrosoftOAuthCredential {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    /// Token endpoint (tenant-specific), e.g.
    /// `https://login.microsoftonline.com/common/oauth2/v2.0/token`.
    /// **Required** — this is what distinguishes the bundle from Google's.
    pub token_url: String,
    /// Space-separated scopes requested at consent time. Sent on refresh so the
    /// issued access token carries the same scopes.
    #[serde(default)]
    pub scopes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MicrosoftOAuthRefreshError {
    pub status: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub raw_body: Option<String>,
    pub message: String,
}

impl MicrosoftOAuthRefreshError {
    /// Microsoft returns `invalid_grant` when the refresh token is expired or
    /// revoked — the user must re-consent.
    pub fn reauth_required(&self) -> bool {
        self.error.as_deref() == Some("invalid_grant")
    }
}

impl fmt::Display for MicrosoftOAuthRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(status) = &self.status {
            write!(f, "Token refresh returned {status}")?;
            if let Some(error) = &self.error {
                write!(f, ": {error}")?;
            }
            if let Some(desc) = &self.error_description {
                write!(f, " - {desc}")?;
            }
            if self.error.is_none() {
                if let Some(body) = &self.raw_body {
                    write!(f, ": {body}")?;
                }
            }
            Ok(())
        } else {
            write!(f, "{}", self.message)
        }
    }
}

/// Try to parse a credential value as a Microsoft OAuth bundle. Returns None if
/// it's not valid Microsoft OAuth JSON. The required `token_url` field means a
/// Google bundle (no `token_url`) will not match here.
pub fn parse_microsoft_oauth(cred_value: &str) -> Option<MicrosoftOAuthCredential> {
    let cred: MicrosoftOAuthCredential = serde_json::from_str(cred_value).ok()?;
    // Guard against empty required fields (serde treats "" as present).
    if cred.client_id.is_empty()
        || cred.client_secret.is_empty()
        || cred.refresh_token.is_empty()
        || cred.token_url.is_empty()
    {
        return None;
    }
    Some(cred)
}

fn err_msg(message: String) -> MicrosoftOAuthRefreshError {
    MicrosoftOAuthRefreshError {
        status: None,
        error: None,
        error_description: None,
        raw_body: None,
        message,
    }
}

/// Exchange a refresh token for a fresh access token.
pub async fn refresh_access_token(
    cred: &MicrosoftOAuthCredential,
) -> Result<String, MicrosoftOAuthRefreshError> {
    let client = build_client(ClientRoute::EgressProxy)
        .map_err(|e| err_msg(format!("Failed to create HTTP client: {e}")))?;

    let mut params = vec![
        ("client_id", cred.client_id.as_str()),
        ("client_secret", cred.client_secret.as_str()),
        ("refresh_token", cred.refresh_token.as_str()),
        ("grant_type", "refresh_token"),
    ];
    if let Some(ref scopes) = cred.scopes {
        if !scopes.trim().is_empty() {
            params.push(("scope", scopes.as_str()));
        }
    }

    let resp = client
        .post(&cred.token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| err_msg(format!("Token refresh request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        return Err(MicrosoftOAuthRefreshError {
            status: Some(status.to_string()),
            error: parsed
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            error_description: parsed
                .get("error_description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            raw_body: Some(body),
            message: "Microsoft OAuth token refresh failed".to_string(),
        });
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err_msg(format!("Failed to parse token response: {e}")))?;

    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| MicrosoftOAuthRefreshError {
            status: None,
            error: None,
            error_description: None,
            raw_body: Some(body.to_string()),
            message: "Token response missing access_token".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_microsoft_bundle() {
        let json = r#"{
            "client_id": "ci",
            "client_secret": "cs",
            "refresh_token": "rt",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "scopes": "https://graph.microsoft.com/Mail.Read offline_access"
        }"#;
        let cred = parse_microsoft_oauth(json).expect("should parse");
        assert_eq!(cred.client_id, "ci");
        assert_eq!(cred.refresh_token, "rt");
        assert!(cred.token_url.contains("login.microsoftonline.com"));
        assert!(cred.scopes.unwrap().contains("Mail.Read"));
    }

    #[test]
    fn google_bundle_without_token_url_does_not_parse_as_microsoft() {
        // A Google bundle (no token_url) must NOT be picked up by the Microsoft
        // parser — otherwise routing order could send it to the wrong endpoint.
        let json = r#"{"client_id":"ci","client_secret":"cs","refresh_token":"rt"}"#;
        assert!(parse_microsoft_oauth(json).is_none());
    }

    #[test]
    fn client_credentials_bundle_without_refresh_token_does_not_parse() {
        let json = r#"{"client_id":"ci","client_secret":"cs","token_url":"https://x/token"}"#;
        assert!(parse_microsoft_oauth(json).is_none());
    }

    #[test]
    fn empty_required_field_rejected() {
        let json = r#"{"client_id":"","client_secret":"cs","refresh_token":"rt","token_url":"https://x/token"}"#;
        assert!(parse_microsoft_oauth(json).is_none());
    }

    #[test]
    fn invalid_grant_is_reauth_required() {
        let err = MicrosoftOAuthRefreshError {
            status: Some("400 Bad Request".to_string()),
            error: Some("invalid_grant".to_string()),
            error_description: Some("AADSTS700082: refresh token expired".to_string()),
            raw_body: None,
            message: "Microsoft OAuth token refresh failed".to_string(),
        };
        assert!(err.reauth_required());
    }

    #[test]
    fn non_invalid_grant_is_not_reauth_required() {
        let err = MicrosoftOAuthRefreshError {
            status: Some("503 Service Unavailable".to_string()),
            error: Some("temporarily_unavailable".to_string()),
            error_description: None,
            raw_body: None,
            message: "Microsoft OAuth token refresh failed".to_string(),
        };
        assert!(!err.reauth_required());
    }
}
