//! Inline OAuth 2.0 Client Credentials grant for sidecar credentials.
//!
//! When a sidecar credential's value contains an OAuth 2.0 client credentials
//! JSON bundle (client_id, client_secret, token_url, optional scope), the proxy
//! exchanges the credentials for a Bearer token directly — no external sidecar
//! service needed.

use serde::Deserialize;
use tap_core::http_client::{build_client, ClientRoute};

/// Parsed OAuth 2.0 Client Credentials bundle.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthClientCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
    pub scope: Option<String>,
}

/// Try to parse a credential value as an OAuth 2.0 Client Credentials bundle.
/// Returns None if it's not valid JSON with the required fields.
pub fn parse_oauth_client_credentials(cred_value: &str) -> Option<OAuthClientCredentials> {
    serde_json::from_str(cred_value).ok()
}

/// Exchange client credentials for a Bearer access token.
pub async fn get_access_token(creds: &OAuthClientCredentials) -> Result<String, String> {
    let client = build_client(ClientRoute::EgressProxy)
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let mut params = vec![
        ("grant_type", "client_credentials"),
        ("client_id", creds.client_id.as_str()),
        ("client_secret", creds.client_secret.as_str()),
    ];
    if let Some(ref scope) = creds.scope {
        params.push(("scope", scope.as_str()));
    }

    let resp = client
        .post(&creds.token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Token request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Token endpoint returned {status}: {body}"));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Token response missing access_token".to_string())
}
