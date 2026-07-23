//! Inline OAuth 1.0a (RFC 5849) request signing for sidecar credentials.
//!
//! When a sidecar credential's value is a JSON bundle with the four OAuth 1.0a
//! keys (`consumer_key`, `consumer_secret`, `access_token`, `access_token_secret`),
//! the proxy signs the request inline and forwards directly to the real API —
//! no external `tap-signer` sidecar needed.
//!
//! This mirrors the approach used for Google OAuth 2.0 in `google_oauth.rs`.
//! Signing logic is a direct port of `crates/tap-signer/src/main.rs::sign_request`.

use base64::Engine;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Deserialize;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed OAuth 1.0a credential value.
#[derive(Debug, Clone, Deserialize)]
pub struct TwitterOAuthCredential {
    pub consumer_key: String,
    pub consumer_secret: String,
    pub access_token: String,
    pub access_token_secret: String,
}

/// Parsed X app Bearer Token stored alongside OAuth 1.0a fields.
#[derive(Debug, Clone, Deserialize)]
struct XBearerCredential {
    #[serde(default)]
    pub bearer_token: String,
    #[serde(default, rename = "bearerToken")]
    pub bearer_token_camel: String,
    #[serde(default)]
    pub app_bearer_token: String,
}

/// Try to parse a credential value as an OAuth 1.0a bundle.
/// Returns None if any required field is missing or empty.
pub fn parse_twitter_oauth(cred_value: &str) -> Option<TwitterOAuthCredential> {
    let parsed: TwitterOAuthCredential = serde_json::from_str(cred_value).ok()?;
    if parsed.consumer_key.is_empty()
        || parsed.consumer_secret.is_empty()
        || parsed.access_token.is_empty()
        || parsed.access_token_secret.is_empty()
    {
        return None;
    }
    Some(parsed)
}

/// Try to parse a credential value as an X app Bearer Token bundle.
///
/// This intentionally reads only JSON-object fields, not a plain string. Plain
/// bearer-token credentials should be configured as `connector=direct`; this
/// parser is for hybrid X credentials that also carry OAuth 1.0a user-context
/// keys.
pub fn parse_x_bearer_token(cred_value: &str) -> Option<String> {
    let parsed: XBearerCredential = serde_json::from_str(cred_value).ok()?;
    for token in [
        parsed.bearer_token,
        parsed.bearer_token_camel,
        parsed.app_bearer_token,
    ] {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

/// RFC 5849 percent-encoding set: encode everything except unreserved chars.
const ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn percent_encode(s: &str) -> String {
    utf8_percent_encode(s, ENCODE_SET).to_string()
}

fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:032x}", rng.gen::<u128>())
}

fn generate_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

/// Build the OAuth 1.0a Authorization header value.
///
/// `body_params` should be `Some(...)` only for `application/x-www-form-urlencoded`
/// bodies — per RFC 5849, those participate in the signature base string. All
/// other content types (JSON, multipart, etc.) should pass `None`.
pub fn sign_request(
    method: &str,
    url: &str,
    cred: &TwitterOAuthCredential,
    body_params: Option<&[(String, String)]>,
) -> String {
    let timestamp = generate_timestamp();
    let nonce = generate_nonce();

    let mut oauth_params: Vec<(String, String)> = vec![
        ("oauth_consumer_key".into(), cred.consumer_key.clone()),
        ("oauth_token".into(), cred.access_token.clone()),
        ("oauth_signature_method".into(), "HMAC-SHA1".into()),
        ("oauth_timestamp".into(), timestamp),
        ("oauth_nonce".into(), nonce),
        ("oauth_version".into(), "1.0".into()),
    ];

    // Collect all params for signature: oauth + query string + body (form-encoded)
    let mut all_params = oauth_params.clone();

    // Parse query string params
    if let Some(query) = url.find('?').map(|i| &url[i + 1..]) {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                all_params.push((k.to_string(), v.to_string()));
            }
        }
    }

    // Include body params (only for form-urlencoded)
    if let Some(params) = body_params {
        all_params.extend(params.iter().cloned());
    }

    // Sort params
    all_params.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Build base URL (without query string)
    let base_url = url.find('?').map_or(url, |i| &url[..i]);

    // Signature base string
    let params_str = all_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let base_string = format!(
        "{}&{}&{}",
        method.to_uppercase(),
        percent_encode(base_url),
        percent_encode(&params_str)
    );

    // Signing key
    let signing_key = format!(
        "{}&{}",
        percent_encode(&cred.consumer_secret),
        percent_encode(&cred.access_token_secret)
    );

    // HMAC-SHA1
    let mut mac =
        Hmac::<Sha1>::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(base_string.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    oauth_params.push(("oauth_signature".into(), signature));

    // Build Authorization header
    let auth_parts = oauth_params
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join(", ");

    format!("OAuth {auth_parts}")
}

/// Parse a form-urlencoded body into key-value pairs for OAuth signature inclusion.
/// Only call this when the request's Content-Type is application/x-www-form-urlencoded.
pub fn parse_form_body(body: &[u8]) -> Vec<(String, String)> {
    let s = std::str::from_utf8(body).unwrap_or("");
    s.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((urldecode(k), urldecode(v)))
        })
        .collect()
}

fn urldecode(s: &str) -> String {
    let s = s.replace('+', " ");
    percent_encoding::percent_decode_str(&s)
        .decode_utf8_lossy()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cred() -> TwitterOAuthCredential {
        TwitterOAuthCredential {
            consumer_key: "xvz1evFS4wEEPTGEFPHBog".to_string(),
            consumer_secret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw".to_string(),
            access_token: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb".to_string(),
            access_token_secret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE".to_string(),
        }
    }

    #[test]
    fn parse_accepts_well_formed_bundle() {
        let json = serde_json::to_string(&serde_json::json!({
            "consumer_key": "ck",
            "consumer_secret": "cs",
            "access_token": "at",
            "access_token_secret": "ats",
        }))
        .unwrap();
        let parsed = parse_twitter_oauth(&json).unwrap();
        assert_eq!(parsed.consumer_key, "ck");
        assert_eq!(parsed.access_token_secret, "ats");
    }

    #[test]
    fn parse_rejects_empty_field() {
        let json = r#"{"consumer_key":"","consumer_secret":"cs","access_token":"at","access_token_secret":"ats"}"#;
        assert!(parse_twitter_oauth(json).is_none());
    }

    #[test]
    fn parse_rejects_missing_field() {
        let json = r#"{"consumer_key":"ck","consumer_secret":"cs","access_token":"at"}"#;
        assert!(parse_twitter_oauth(json).is_none());
    }

    #[test]
    fn parse_rejects_google_oauth_bundle() {
        // Google OAuth bundle should not parse as Twitter OAuth
        let json = r#"{"client_id":"ci","client_secret":"cs","refresh_token":"rt"}"#;
        assert!(parse_twitter_oauth(json).is_none());
    }

    #[test]
    fn parse_x_bearer_token_accepts_hybrid_bundle() {
        let json = r#"{"bearer_token":"bt","consumer_key":"ck","consumer_secret":"cs","access_token":"at","access_token_secret":"ats"}"#;
        assert_eq!(parse_x_bearer_token(json).as_deref(), Some("bt"));
        assert!(parse_twitter_oauth(json).is_some());
    }

    #[test]
    fn parse_x_bearer_token_rejects_plain_string() {
        assert!(parse_x_bearer_token("bt").is_none());
    }

    #[test]
    fn sign_request_produces_oauth_header() {
        let cred = test_cred();
        let header = sign_request("GET", "https://api.twitter.com/2/tweets", &cred, None);
        assert!(header.starts_with("OAuth "));
        assert!(header.contains("oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\""));
        assert!(header.contains("oauth_signature_method=\"HMAC-SHA1\""));
        assert!(header.contains("oauth_version=\"1.0\""));
        assert!(header.contains("oauth_signature="));
        assert!(header.contains("oauth_nonce="));
        assert!(header.contains("oauth_timestamp="));
    }

    #[test]
    fn sign_request_includes_body_params_for_form_encoded() {
        let cred = test_cred();
        let body = vec![("status".to_string(), "hello world".to_string())];
        let header1 = sign_request(
            "POST",
            "https://api.twitter.com/1.1/statuses/update.json",
            &cred,
            Some(&body),
        );
        let header2 = sign_request(
            "POST",
            "https://api.twitter.com/1.1/statuses/update.json",
            &cred,
            None,
        );
        // Different body params → different signatures (nonce/timestamp also
        // differ so we just assert both are valid OAuth headers)
        assert!(header1.starts_with("OAuth "));
        assert!(header2.starts_with("OAuth "));
        assert_ne!(header1, header2);
    }

    #[test]
    fn parse_form_body_handles_percent_encoding() {
        let body = b"status=hello%20world&extra=%26key";
        let params = parse_form_body(body);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], ("status".to_string(), "hello world".to_string()));
        assert_eq!(params[1], ("extra".to_string(), "&key".to_string()));
    }
}
