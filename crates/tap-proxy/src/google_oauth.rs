//! Inline Google OAuth2 token refresh for sidecar credentials.
//!
//! When a sidecar credential's value contains a Google OAuth refresh token
//! bundle (JSON with client_id, client_secret, refresh_token), the proxy
//! exchanges the refresh token for a fresh access token and injects it
//! directly — no external sidecar service needed.

use serde::Deserialize;
use std::fmt;
use tap_core::http_client::{build_client, ClientRoute};

/// Parsed Google OAuth credential value.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleOAuthCredential {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    #[serde(default)]
    pub scopes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GoogleOAuthRefreshError {
    pub status: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub error_subtype: Option<String>,
    pub raw_body: Option<String>,
    pub message: String,
}

impl GoogleOAuthRefreshError {
    pub fn reauth_required(&self) -> bool {
        self.error.as_deref() == Some("invalid_grant")
    }
}

impl fmt::Display for GoogleOAuthRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(status) = &self.status {
            write!(f, "Token refresh returned {status}")?;
            if let Some(error) = &self.error {
                write!(f, ": {error}")?;
            }
            if let Some(subtype) = &self.error_subtype {
                write!(f, " ({subtype})")?;
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

/// Try to parse a credential value as a Google OAuth bundle.
/// Returns None if it's not valid Google OAuth JSON.
pub fn parse_google_oauth(cred_value: &str) -> Option<GoogleOAuthCredential> {
    serde_json::from_str(cred_value).ok()
}

/// Exchange a refresh token for a fresh access token.
pub async fn refresh_access_token(
    cred: &GoogleOAuthCredential,
) -> Result<String, GoogleOAuthRefreshError> {
    let client = build_client(ClientRoute::EgressProxy).map_err(|e| GoogleOAuthRefreshError {
        status: None,
        error: None,
        error_description: None,
        error_subtype: None,
        raw_body: None,
        message: format!("Failed to create HTTP client: {e}"),
    })?;
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", cred.client_id.as_str()),
            ("client_secret", cred.client_secret.as_str()),
            ("refresh_token", cred.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|e| GoogleOAuthRefreshError {
            status: None,
            error: None,
            error_description: None,
            error_subtype: None,
            raw_body: None,
            message: format!("Token refresh request failed: {e}"),
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        return Err(GoogleOAuthRefreshError {
            status: Some(status.to_string()),
            error: parsed
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            error_description: parsed
                .get("error_description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            error_subtype: parsed
                .get("error_subtype")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            raw_body: Some(body),
            message: "Google OAuth token refresh failed".to_string(),
        });
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| GoogleOAuthRefreshError {
        status: None,
        error: None,
        error_description: None,
        error_subtype: None,
        raw_body: None,
        message: format!("Failed to parse token response: {e}"),
    })?;

    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| GoogleOAuthRefreshError {
            status: None,
            error: None,
            error_description: None,
            error_subtype: None,
            raw_body: Some(body.to_string()),
            message: "Token response missing access_token".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_rapt_is_reauth_required() {
        let err = GoogleOAuthRefreshError {
            status: Some("400 Bad Request".to_string()),
            error: Some("invalid_grant".to_string()),
            error_description: Some("reauth related error (invalid_rapt)".to_string()),
            error_subtype: Some("invalid_rapt".to_string()),
            raw_body: None,
            message: "Google OAuth token refresh failed".to_string(),
        };

        assert!(err.reauth_required());
    }

    #[test]
    fn non_invalid_grant_refresh_error_is_not_reauth_required() {
        let err = GoogleOAuthRefreshError {
            status: Some("500 Internal Server Error".to_string()),
            error: Some("temporarily_unavailable".to_string()),
            error_description: None,
            error_subtype: None,
            raw_body: None,
            message: "Google OAuth token refresh failed".to_string(),
        };

        assert!(!err.reauth_required());
    }
}
