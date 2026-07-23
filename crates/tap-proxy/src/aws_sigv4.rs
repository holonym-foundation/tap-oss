//! Inline AWS Signature Version 4 (SigV4) request signing for sidecar credentials.
//!
//! When a sidecar credential's value is a JSON bundle with `access_key_id`
//! and `secret_access_key`, the proxy signs the request inline per the SigV4
//! spec and forwards directly to the real AWS API — no external signer needed.
//!
//! Service and region are extracted from the URL hostname
//! (e.g. `sts.us-east-1.amazonaws.com` → service=sts, region=us-east-1)
//! or overridden via optional fields in the credential JSON bundle.
//!
//! This mirrors the approach used for OAuth 1.0a in `oauth1.rs`.

use chrono::Utc;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Parsed AWS credential JSON bundle.
#[derive(Debug, Clone, Deserialize)]
pub struct AwsCredential {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Optional region override. If absent, extracted from the target URL.
    pub region: Option<String>,
    /// Optional service override. If absent, extracted from the target URL.
    pub service: Option<String>,
}

/// Try to parse a credential value as an AWS SigV4 bundle.
/// Returns None if required fields (`access_key_id`, `secret_access_key`) are
/// missing or empty.
pub fn parse_aws_credential(cred_value: &str) -> Option<AwsCredential> {
    let parsed: AwsCredential = serde_json::from_str(cred_value).ok()?;
    if parsed.access_key_id.is_empty() || parsed.secret_access_key.is_empty() {
        return None;
    }
    Some(parsed)
}

/// SigV4 percent-encoding set: encode everything except unreserved chars
/// (A-Z, a-z, 0-9, -, _, ., ~). Applied per URI segment; slashes are preserved.
const ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Sign an HTTP request with AWS Signature Version 4.
///
/// Returns headers to inject: `x-amz-date`, `x-amz-content-sha256`, and
/// `Authorization`. The caller must add these to the request and remove any
/// pre-existing `Authorization`, `x-amz-date`, and `x-amz-content-sha256` headers.
pub fn sign_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    cred: &AwsCredential,
) -> Result<Vec<(String, String)>, String> {
    let parsed_url = url::Url::parse(url).map_err(|e| format!("Invalid URL: {e}"))?;
    let host = parsed_url
        .host_str()
        .ok_or("Missing host in URL")?
        .to_string();

    // Include non-standard port in the Host value used for signing.
    let host_for_signing = match parsed_url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };

    // Resolve service + region: credential fields take priority, then URL.
    let (url_service, url_region) =
        extract_service_region(&host).unwrap_or_else(|| (String::new(), String::new()));
    let service = cred
        .service
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&url_service)
        .to_string();
    let region = cred
        .region
        .as_deref()
        .filter(|r| !r.is_empty())
        .unwrap_or(&url_region)
        .to_string();

    if service.is_empty() {
        return Err(format!(
            "Cannot determine AWS service from URL '{url}'. \
             Store it in the credential JSON as a 'service' field (e.g. \"service\": \"sts\")."
        ));
    }
    if region.is_empty() {
        return Err(format!(
            "Cannot determine AWS region from URL '{url}'. \
             Store it in the credential JSON as a 'region' field (e.g. \"region\": \"us-east-1\")."
        ));
    }

    let now = Utc::now();
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();

    // Hash the payload.
    let body_bytes = body.unwrap_or(b"");
    let body_hash = hex::encode(Sha256::digest(body_bytes));

    // Canonical headers: host, x-amz-content-sha256, x-amz-date (sorted).
    let mut canonical_hdrs: Vec<(String, String)> = vec![
        ("host".to_string(), host_for_signing),
        ("x-amz-content-sha256".to_string(), body_hash.clone()),
        ("x-amz-date".to_string(), datetime.clone()),
    ];
    canonical_hdrs.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers_str: String = canonical_hdrs
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let signed_headers: String = canonical_hdrs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    // Canonical URI: percent-encode each path segment, preserve slashes.
    let raw_path = parsed_url.path();
    let canonical_uri = encode_uri(if raw_path.is_empty() { "/" } else { raw_path });

    // Canonical query string: decode, re-encode per SigV4, sort.
    let canonical_qs = encode_query(parsed_url.query().unwrap_or(""));

    // Canonical request.
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        canonical_uri,
        canonical_qs,
        canonical_headers_str,
        signed_headers,
        body_hash
    );

    // String to sign.
    let cr_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{cr_hash}");

    // Derive signing key: HMAC-SHA256 chain over date/region/service/"aws4_request".
    let signing_key = derive_signing_key(&cred.secret_access_key, &date, &region, &service);

    // Compute signature.
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    // Build Authorization header.
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        cred.access_key_id, credential_scope, signed_headers, signature
    );

    Ok(vec![
        ("x-amz-date".to_string(), datetime),
        ("x-amz-content-sha256".to_string(), body_hash),
        ("Authorization".to_string(), auth),
    ])
}

/// Extract AWS service and region from an amazonaws.com hostname.
/// Returns None for non-amazonaws.com hosts.
///
/// Examples:
///   `sts.us-east-1.amazonaws.com`       → (sts, us-east-1)
///   `s3.us-west-2.amazonaws.com`        → (s3, us-west-2)
///   `execute-api.eu-west-1.amazonaws.com` → (execute-api, eu-west-1)
///   `sts.amazonaws.com`                 → (sts, us-east-1) — global endpoint
fn extract_service_region(host: &str) -> Option<(String, String)> {
    let host = host.trim_end_matches('.');
    let without_suffix = host.strip_suffix(".amazonaws.com")?;
    match without_suffix.find('.') {
        None => Some((without_suffix.to_string(), "us-east-1".to_string())),
        Some(i) => Some((
            without_suffix[..i].to_string(),
            without_suffix[i + 1..].to_string(),
        )),
    }
}

/// Percent-encode a URI path, preserving forward slashes between segments.
fn encode_uri(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }
    path.split('/')
        .map(|seg| utf8_percent_encode(seg, ENCODE_SET).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Build the canonical query string: decode then re-encode per SigV4, sort by key then value.
fn encode_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k_dec = percent_encoding::percent_decode_str(k)
                .decode_utf8_lossy()
                .into_owned();
            let v_dec = percent_encoding::percent_decode_str(v)
                .decode_utf8_lossy()
                .into_owned();
            (
                utf8_percent_encode(&k_dec, ENCODE_SET).to_string(),
                utf8_percent_encode(&v_dec, ENCODE_SET).to_string(),
            )
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cred() -> AwsCredential {
        AwsCredential {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            region: Some("us-east-1".to_string()),
            service: Some("sts".to_string()),
        }
    }

    #[test]
    fn parse_accepts_well_formed_bundle() {
        let json = r#"{"access_key_id":"AKIA...","secret_access_key":"secret","region":"us-east-1","service":"sts"}"#;
        let parsed = parse_aws_credential(json).unwrap();
        assert_eq!(parsed.access_key_id, "AKIA...");
        assert_eq!(parsed.region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn parse_accepts_bundle_without_optional_fields() {
        let json = r#"{"access_key_id":"AKIA...","secret_access_key":"secret"}"#;
        let parsed = parse_aws_credential(json).unwrap();
        assert!(parsed.region.is_none());
        assert!(parsed.service.is_none());
    }

    #[test]
    fn parse_rejects_empty_access_key() {
        let json = r#"{"access_key_id":"","secret_access_key":"secret"}"#;
        assert!(parse_aws_credential(json).is_none());
    }

    #[test]
    fn parse_rejects_missing_secret() {
        let json = r#"{"access_key_id":"AKIA..."}"#;
        assert!(parse_aws_credential(json).is_none());
    }

    #[test]
    fn parse_rejects_twitter_bundle() {
        let json = r#"{"consumer_key":"ck","consumer_secret":"cs","access_token":"at","access_token_secret":"ats"}"#;
        assert!(parse_aws_credential(json).is_none());
    }

    #[test]
    fn parse_rejects_google_bundle() {
        let json = r#"{"client_id":"ci","client_secret":"cs","refresh_token":"rt"}"#;
        assert!(parse_aws_credential(json).is_none());
    }

    #[test]
    fn extract_service_region_regional() {
        assert_eq!(
            extract_service_region("sts.us-east-1.amazonaws.com"),
            Some(("sts".to_string(), "us-east-1".to_string()))
        );
        assert_eq!(
            extract_service_region("s3.us-west-2.amazonaws.com"),
            Some(("s3".to_string(), "us-west-2".to_string()))
        );
        assert_eq!(
            extract_service_region("execute-api.ap-southeast-1.amazonaws.com"),
            Some(("execute-api".to_string(), "ap-southeast-1".to_string()))
        );
    }

    #[test]
    fn extract_service_region_global() {
        assert_eq!(
            extract_service_region("sts.amazonaws.com"),
            Some(("sts".to_string(), "us-east-1".to_string()))
        );
    }

    #[test]
    fn extract_service_region_non_aws() {
        assert!(extract_service_region("api.example.com").is_none());
    }

    #[test]
    fn sign_request_produces_aws4_authorization_header() {
        let cred = test_cred();
        let headers = sign_request(
            "GET",
            "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            None,
            &cred,
        )
        .unwrap();

        let auth = headers.iter().find(|(n, _)| n == "Authorization").unwrap();
        assert!(
            auth.1
                .starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"),
            "unexpected auth: {}",
            auth.1
        );
        assert!(auth
            .1
            .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        assert!(auth.1.contains("Signature="));

        let date_hdr = headers.iter().find(|(n, _)| n == "x-amz-date").unwrap();
        assert_eq!(date_hdr.1.len(), 16, "datetime should be YYYYMMDDTHHMMSSZ");

        // SHA-256 of empty body
        let hash_hdr = headers
            .iter()
            .find(|(n, _)| n == "x-amz-content-sha256")
            .unwrap();
        assert_eq!(
            hash_hdr.1,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sign_request_extracts_service_region_from_url() {
        let cred = AwsCredential {
            access_key_id: "AKIA...".to_string(),
            secret_access_key: "secret".to_string(),
            region: None,
            service: None,
        };
        let headers = sign_request(
            "GET",
            "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            None,
            &cred,
        )
        .unwrap();
        let auth = headers.iter().find(|(n, _)| n == "Authorization").unwrap();
        assert!(auth.1.contains("/us-east-1/sts/aws4_request"));
    }

    #[test]
    fn sign_request_fails_for_non_aws_url_without_overrides() {
        let cred = AwsCredential {
            access_key_id: "AKIA...".to_string(),
            secret_access_key: "secret".to_string(),
            region: None,
            service: None,
        };
        let result = sign_request("GET", "https://api.example.com/resource", None, &cred);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("service"));
    }

    #[test]
    fn sign_request_uses_credential_overrides_for_non_aws_url() {
        let cred = AwsCredential {
            access_key_id: "AKIA...".to_string(),
            secret_access_key: "secret".to_string(),
            region: Some("us-west-2".to_string()),
            service: Some("execute-api".to_string()),
        };
        let headers = sign_request(
            "GET",
            "https://api.mycompany.com/prod/resource",
            None,
            &cred,
        )
        .unwrap();
        let auth = headers.iter().find(|(n, _)| n == "Authorization").unwrap();
        assert!(auth.1.contains("/us-west-2/execute-api/aws4_request"));
    }

    #[test]
    fn sign_request_hashes_body_correctly() {
        let cred = test_cred();
        let body = b"Action=GetCallerIdentity&Version=2011-06-15";
        let headers = sign_request(
            "POST",
            "https://sts.us-east-1.amazonaws.com/",
            Some(body),
            &cred,
        )
        .unwrap();
        let hash_hdr = headers
            .iter()
            .find(|(n, _)| n == "x-amz-content-sha256")
            .unwrap();
        assert_eq!(
            hash_hdr.1,
            hex::encode(Sha256::digest(body)),
            "body hash mismatch"
        );
    }

    #[test]
    fn encode_query_sorts_and_encodes() {
        // Sorted: A=1, A=3, Z=1
        assert_eq!(encode_query("Z=1&A=3&A=1"), "A=1&A=3&Z=1");
    }

    #[test]
    fn encode_query_handles_empty() {
        assert_eq!(encode_query(""), "");
    }

    #[test]
    fn routing_bypasses_sidecar_for_aws_bundle() {
        // This test validates that parse_aws_credential detects the bundle
        // while parse_google_oauth and parse_twitter_oauth do not.
        let bundle = serde_json::json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
        })
        .to_string();

        assert!(parse_aws_credential(&bundle).is_some());
        assert!(crate::google_oauth::parse_google_oauth(&bundle).is_none());
        assert!(crate::oauth1::parse_twitter_oauth(&bundle).is_none());
    }
}
