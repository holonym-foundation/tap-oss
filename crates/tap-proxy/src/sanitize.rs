//! Response sanitization: scan for credential values and redact them.
//!
//! Two modes:
//! 1. Pattern-based scrubbing (from cherry-picked sanitize.rs) for approval messages
//! 2. Exact-match credential scanning for proxy responses (new for TAP)

use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;

/// Header names that must never be forwarded to approvers or the AI safety check.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "www-authenticate",
    "x-csrf-token",
    "x-xsrf-token",
];

/// Returns true if a header name should be treated as sensitive.
///
/// Combines the explicit `SENSITIVE_HEADERS` list (well-known auth headers)
/// with pattern-based fallback for non-standard auth headers used by services
/// like Datadog (`DD-API-KEY`, `DD-APPLICATION-KEY`), Linear (`X-Linear-Token`),
/// and arbitrary multi-secret credentials. We bias toward over-redaction —
/// false positives (e.g. `Cache-Key`) are cosmetic, false negatives are
/// security holes (a real secret leaking into the AI safety payload).
fn is_sensitive_header_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    if SENSITIVE_HEADERS.contains(&lower.as_str()) {
        return true;
    }
    lower.ends_with("-key")
        || lower.ends_with("-token")
        || lower.ends_with("-secret")
        || lower.ends_with("-auth")
        || lower.contains("apikey")
        || lower.contains("api-key")
        || lower.contains("password")
        || lower.contains("credential")
}

const REDACTED: &str = "[REDACTED]";

static CREDENTIAL_PATTERNS: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "bearer_token",
            Regex::new(r"(?i)(bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*").unwrap(),
        ),
        ("aws_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        (
            "hex_secret",
            Regex::new(r"\b[0-9a-fA-F]{32,}\b").unwrap(),
        ),
        (
            "oauth_kv",
            Regex::new(r#"(?i)(oauth_token|oauth_token_secret|consumer_secret|access_token_secret|api_key|api_secret|secret_key|private_key)\s*[=:]\s*"?[^\s",}]+"?"#).unwrap(),
        ),
        (
            "jwt",
            Regex::new(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap(),
        ),
        (
            "sk_key",
            Regex::new(r"\b(sk|pk|rk)[-_](live|test|prod|proj)?[-_]?[A-Za-z0-9]{20,}\b").unwrap(),
        ),
    ]
});

/// Max response body size for sanitization (10MB).
const MAX_SANITIZE_SIZE: usize = 10 * 1024 * 1024;

/// Result of response sanitization.
pub struct SanitizeResult {
    pub body: Vec<u8>,
    pub sanitized: bool,
    pub skipped: bool,
}

/// Sanitize a response body by scanning for exact credential values.
/// Also checks base64 and URL-encoded variants.
pub fn sanitize_response(
    body: &[u8],
    credential_values: &[(&str, &str)], // (credential_name, credential_value)
) -> SanitizeResult {
    if body.len() > MAX_SANITIZE_SIZE {
        return SanitizeResult {
            body: body.to_vec(),
            sanitized: false,
            skipped: true,
        };
    }

    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            // Non-UTF-8 body: either genuinely binary, or an encoding reqwest
            // didn't transparently decode. We can't surgically redact bytes, so
            // fail closed — if any secret appears verbatim (raw or base64) in
            // the bytes, withhold the whole body; otherwise pass it through.
            // (The common gzip/brotli/deflate case is decoded upstream by
            // reqwest before reaching here, so this is the residual guard.)
            let forms = secret_byte_forms(credential_values);
            if bytes_contain_any(body, &forms) {
                return SanitizeResult {
                    body: b"[REDACTED: response withheld - a credential value appeared in a non-text response body]".to_vec(),
                    sanitized: true,
                    skipped: false,
                };
            }
            return SanitizeResult {
                body: body.to_vec(),
                sanitized: false,
                skipped: false,
            };
        }
    };

    let mut result = body_str.to_string();
    let mut any_redacted = false;

    for (cred_name, cred_value) in credential_values {
        if cred_value.is_empty() {
            continue;
        }

        // Multi-secret credentials store their value as a JSON object
        // (e.g. `{"api_key":"...","app_key":"..."}`). Scrub each string leaf
        // independently so each individual secret is caught even when the
        // raw JSON blob never appears in the response. The marker is
        // `[REDACTED:<cred>.<key>]` so leaks are traceable to the specific
        // field that leaked.
        if let Ok(serde_json::Value::Object(map)) =
            serde_json::from_str::<serde_json::Value>(cred_value)
        {
            for (key, val) in &map {
                if let Some(leaf) = val.as_str() {
                    let leaf_name = format!("{cred_name}.{key}");
                    if scrub_one(&mut result, &leaf_name, leaf) {
                        any_redacted = true;
                    }
                }
            }
        }

        // Always also scrub the raw string form. For plain-string credentials
        // this is the primary path; for JSON-object credentials it's a safety
        // net for the rare case where the whole blob (e.g. accidentally logged)
        // shows up in the response.
        if scrub_one(&mut result, cred_name, cred_value) {
            any_redacted = true;
        }
    }

    SanitizeResult {
        body: result.into_bytes(),
        sanitized: any_redacted,
        skipped: false,
    }
}

/// Collect the byte forms (raw + standard base64 + base64url) of every secret
/// in `credential_values`, including JSON-object leaves. Used by the non-UTF-8
/// fail-closed scan. Secrets shorter than 4 bytes are skipped to avoid
/// redacting on coincidental short matches in binary data.
fn secret_byte_forms(credential_values: &[(&str, &str)]) -> Vec<Vec<u8>> {
    let mut forms: Vec<Vec<u8>> = Vec::new();
    let mut push = |s: &str| {
        if s.len() < 4 {
            return;
        }
        forms.push(s.as_bytes().to_vec());
        forms.push(
            base64::engine::general_purpose::STANDARD
                .encode(s.as_bytes())
                .into_bytes(),
        );
        forms.push(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(s.as_bytes())
                .into_bytes(),
        );
    };
    for (_, cred_value) in credential_values {
        if cred_value.is_empty() {
            continue;
        }
        if let Ok(serde_json::Value::Object(map)) =
            serde_json::from_str::<serde_json::Value>(cred_value)
        {
            for (_, val) in &map {
                if let Some(leaf) = val.as_str() {
                    push(leaf);
                }
            }
        }
        push(cred_value);
    }
    forms
}

/// True if `haystack` contains any of `needles` as a contiguous byte run.
fn bytes_contain_any(haystack: &[u8], needles: &[Vec<u8>]) -> bool {
    needles.iter().any(|n| {
        !n.is_empty() && n.len() <= haystack.len() && haystack.windows(n.len()).any(|w| w == &n[..])
    })
}

/// Scrub one (name, value) pair from `result` — exact match plus base64 and
/// URL-encoded variants. Returns true if anything was redacted.
fn scrub_one(result: &mut String, name: &str, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let marker = format!("[REDACTED:{name}]");
    let mut redacted = false;

    if result.contains(value) {
        *result = result.replace(value, &marker);
        redacted = true;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
    if result.contains(&b64) {
        *result = result.replace(&b64, &marker);
        redacted = true;
    }
    // base64url (the `-_` alphabet, no padding) — common in JWT-ish contexts.
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes());
    if b64url != b64 && result.contains(&b64url) {
        *result = result.replace(&b64url, &marker);
        redacted = true;
    }
    let url = urlencod(value);
    if url != value && result.contains(&url) {
        *result = result.replace(&url, &marker);
        redacted = true;
    }
    redacted
}

/// Simple percent-encoding for credential values.
fn urlencod(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{b:02X}"));
            }
        }
    }
    result
}

/// Sanitize a list of HTTP headers: replace sensitive header values with [REDACTED].
pub fn sanitize_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            if is_sensitive_header_name(name) {
                (name.clone(), REDACTED.to_string())
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

/// Scrub credential-like patterns from a string.
pub fn scrub_credentials(text: &str) -> String {
    let mut result = text.to_string();
    for (_name, pattern) in CREDENTIAL_PATTERNS.iter() {
        result = pattern.replace_all(&result, REDACTED).to_string();
    }
    result
}

/// Recursively sanitize a JSON value.
pub fn sanitize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(scrub_credentials(s)),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sanitize_json_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (key, val) in map {
                let lower_key = key.to_lowercase();
                if is_sensitive_key(&lower_key) {
                    new_map.insert(key.clone(), serde_json::Value::String(REDACTED.to_string()));
                } else {
                    new_map.insert(key.clone(), sanitize_json_value(val));
                }
            }
            serde_json::Value::Object(new_map)
        }
        other => other.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let sensitive_keys = [
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "consumer_secret",
        "access_token_secret",
        "private_key",
        "client_secret",
        "auth_token",
        "credentials",
    ];
    sensitive_keys.contains(&key)
}

/// Sanitize a raw payload (for approval display / safety check).
pub fn sanitize_raw_payload(payload: &serde_json::Value) -> serde_json::Value {
    let mut sanitized = payload.clone();

    if let Some(obj) = sanitized.as_object_mut() {
        if let Some(headers) = obj.get("headers").cloned() {
            if let Some(arr) = headers.as_array() {
                let clean_headers: Vec<serde_json::Value> = arr
                    .iter()
                    .map(|pair| {
                        if let Some(pair_arr) = pair.as_array() {
                            if pair_arr.len() == 2 {
                                let name = pair_arr[0].as_str().unwrap_or("");
                                if is_sensitive_header_name(name) {
                                    return serde_json::json!([name, REDACTED]);
                                }
                            }
                        }
                        pair.clone()
                    })
                    .collect();
                obj.insert(
                    "headers".to_string(),
                    serde_json::Value::Array(clean_headers),
                );
            }
        }

        if let Some(body) = obj.get("body").cloned() {
            obj.insert("body".to_string(), sanitize_json_value(&body));
        }

        if let Some(url) = obj.get("url").and_then(|u| u.as_str()) {
            obj.insert(
                "url".to_string(),
                serde_json::Value::String(scrub_credentials(url)),
            );
        }
    }

    sanitized
}

pub fn sanitize_summary(summary: &str) -> String {
    scrub_credentials(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Header sanitization ────────────────────────────────────────────

    #[test]
    fn strips_authorization_header() {
        let headers = vec![
            (
                "Authorization".to_string(),
                "Bearer sk-abc123xyz".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let result = sanitize_headers(&headers);
        assert_eq!(result[0].1, REDACTED);
        assert_eq!(result[1].1, "application/json");
    }

    #[test]
    fn strips_x_api_key_header() {
        let headers = vec![("X-Api-Key".to_string(), "my-secret-key-12345".to_string())];
        let result = sanitize_headers(&headers);
        assert_eq!(result[0].1, REDACTED);
    }

    #[test]
    fn header_matching_is_case_insensitive() {
        let headers = vec![
            ("AUTHORIZATION".to_string(), "token".to_string()),
            ("x-API-KEY".to_string(), "token".to_string()),
            ("Cookie".to_string(), "session=abc".to_string()),
        ];
        let result = sanitize_headers(&headers);
        assert!(result.iter().all(|(_, v)| v == REDACTED));
    }

    #[test]
    fn non_sensitive_headers_pass_through() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
            ("X-Request-Id".to_string(), "abc-123".to_string()),
        ];
        let result = sanitize_headers(&headers);
        assert_eq!(result[0].1, "application/json");
        assert_eq!(result[1].1, "text/html");
        assert_eq!(result[2].1, "abc-123");
    }

    // ── Credential scrubbing ───────────────────────────────────────────

    #[test]
    fn scrubs_bearer_tokens() {
        let text = "Here is the token: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig please use it";
        let result = scrub_credentials(text);
        assert!(!result.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(result.contains(REDACTED));
    }

    #[test]
    fn scrubs_aws_keys() {
        let text = "AWS key: AKIAIOSFODNN7EXAMPLE";
        let result = scrub_credentials(text);
        assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn scrubs_jwt_tokens() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let text = format!("Token: {jwt}");
        let result = scrub_credentials(&text);
        assert!(!result.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn scrubs_sk_api_keys() {
        let text = "API key: sk-proj-abc123def456ghi789jkl012mno345";
        let result = scrub_credentials(text);
        assert!(!result.contains("sk-proj-abc123def456ghi789jkl012mno345"));
    }

    #[test]
    fn preserves_normal_text() {
        let text = "Post tweet as @company: \"Hello world! Check out our new product launch.\"";
        let result = scrub_credentials(text);
        assert_eq!(result, text);
    }

    #[test]
    fn preserves_short_hex_strings() {
        let text = "Like tweet 1234567890abcdef";
        let result = scrub_credentials(text);
        assert_eq!(result, text);
    }

    // ── JSON sanitization ──────────────────────────────────────────────

    #[test]
    fn sanitizes_sensitive_json_keys() {
        let value = json!({
            "text": "Hello world",
            "password": "super_secret_123",
            "api_key": "sk-test-abc123",
            "token": "Bearer xyz",
        });
        let result = sanitize_json_value(&value);
        assert_eq!(result["text"], "Hello world");
        assert_eq!(result["password"], REDACTED);
        assert_eq!(result["api_key"], REDACTED);
        assert_eq!(result["token"], REDACTED);
    }

    #[test]
    fn sanitizes_nested_json() {
        let value = json!({
            "action": "post",
            "auth": {
                "access_token": "my-token",
                "consumer_secret": "my-secret"
            },
            "body": {
                "text": "Hello"
            }
        });
        let result = sanitize_json_value(&value);
        assert_eq!(result["auth"]["access_token"], REDACTED);
        assert_eq!(result["auth"]["consumer_secret"], REDACTED);
        assert_eq!(result["body"]["text"], "Hello");
    }

    #[test]
    fn handles_empty_headers() {
        let result = sanitize_headers(&[]);
        assert!(result.is_empty());
    }

    // ── Response sanitization (exact-match credential scanning) ────────

    #[test]
    fn exact_credential_value_match_in_response() {
        let body = b"Your token is sk-live-abc123def456";
        let creds = vec![("credential-name", "sk-live-abc123def456")];
        let result = sanitize_response(body, &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(body_str.contains("[REDACTED:credential-name]"));
        assert!(!body_str.contains("sk-live-abc123def456"));
        assert!(result.sanitized);
    }

    #[test]
    fn base64url_encoded_credential_in_response() {
        // A secret whose base64url form differs from standard base64 (uses `-`/`_`).
        let cred_value = "\u{1}\u{2}\u{3}secret-bytes-ffbf";
        let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_value.as_bytes());
        let body = format!("token={b64url}");
        let creds = vec![("jwtish", cred_value)];
        let result = sanitize_response(body.as_bytes(), &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(!body_str.contains(&b64url));
        assert!(result.sanitized);
    }

    #[test]
    fn non_utf8_body_with_secret_is_withheld() {
        // A binary (non-UTF-8) body containing the raw secret bytes must be
        // withheld, not passed through (the gzip-bypass fail-closed guard).
        let secret = "sk-live-abc123def456";
        let mut body: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x01]; // invalid UTF-8 prefix
        body.extend_from_slice(secret.as_bytes());
        body.extend_from_slice(&[0x00, 0xff]);
        let creds = vec![("c", secret)];
        let result = sanitize_response(&body, &creds);
        assert!(result.sanitized);
        let out = String::from_utf8_lossy(&result.body);
        assert!(out.contains("withheld"));
        assert!(!result.body.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }

    #[test]
    fn non_utf8_body_without_secret_passes_through() {
        let body: Vec<u8> = vec![0xff, 0xfe, 0x00, 0x01, 0x02, 0x03];
        let creds = vec![("c", "sk-live-not-present-here")];
        let result = sanitize_response(&body, &creds);
        assert!(!result.sanitized);
        assert_eq!(result.body, body);
    }

    #[test]
    fn base64_encoded_credential_in_response() {
        let cred_value = "my-secret-api-key-12345";
        let b64 = base64::engine::general_purpose::STANDARD.encode(cred_value.as_bytes());
        let body = format!("encoded: {b64}");
        let creds = vec![("test-cred", cred_value)];
        let result = sanitize_response(body.as_bytes(), &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(!body_str.contains(&b64));
        assert!(body_str.contains("[REDACTED:test-cred]"));
        assert!(result.sanitized);
    }

    #[test]
    fn url_encoded_credential_in_response() {
        let cred_value = "secret key+value&special=chars";
        let url_enc = urlencod(cred_value);
        let body = format!("param={url_enc}");
        let creds = vec![("test-cred", cred_value)];
        let result = sanitize_response(body.as_bytes(), &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(!body_str.contains(&url_enc));
        assert!(body_str.contains("[REDACTED:test-cred]"));
        assert!(result.sanitized);
    }

    #[test]
    fn response_exceeds_buffer_cap() {
        let body = vec![b'A'; 11 * 1024 * 1024]; // 11MB
        let creds = vec![("cred", "secret")];
        let result = sanitize_response(&body, &creds);
        assert!(result.skipped);
        assert!(!result.sanitized);
        assert_eq!(result.body.len(), body.len());
    }

    #[test]
    fn clean_response_passthrough() {
        let body = br#"{"status": "ok", "data": [1,2,3]}"#;
        let creds = vec![("cred", "totally-different-secret")];
        let result = sanitize_response(body, &creds);
        assert!(!result.sanitized);
        assert_eq!(result.body, body);
    }

    #[test]
    fn multiple_credential_values_in_one_response() {
        let body = b"first: secret-aaa and second: secret-bbb here";
        let creds = vec![("cred-a", "secret-aaa"), ("cred-b", "secret-bbb")];
        let result = sanitize_response(body, &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(body_str.contains("[REDACTED:cred-a]"));
        assert!(body_str.contains("[REDACTED:cred-b]"));
        assert!(!body_str.contains("secret-aaa"));
        assert!(!body_str.contains("secret-bbb"));
        assert!(result.sanitized);
    }

    #[test]
    fn json_object_credential_scrubs_each_leaf() {
        // Multi-secret credential value (e.g. Datadog): JSON object with
        // multiple string fields. Each field must be scrubbed independently
        // so a Datadog response containing the API key but not the APP key
        // (or vice versa) is still sanitized.
        let body = b"{\"api\":\"AAA-secret\",\"unrelated\":\"hello\"}";
        let json_value = r#"{"api_key":"AAA-secret","app_key":"BBB-secret"}"#;
        let creds = vec![("datadog", json_value)];
        let result = sanitize_response(body, &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(
            body_str.contains("[REDACTED:datadog.api_key]"),
            "expected api_key marker, got: {body_str}"
        );
        assert!(!body_str.contains("AAA-secret"));
        // The unrelated content stays
        assert!(body_str.contains("hello"));
        assert!(result.sanitized);
    }

    #[test]
    fn json_object_credential_scrubs_both_leaves_when_both_leak() {
        let body = b"{\"a\":\"AAA-secret\",\"b\":\"BBB-secret\"}";
        let json_value = r#"{"api_key":"AAA-secret","app_key":"BBB-secret"}"#;
        let creds = vec![("datadog", json_value)];
        let result = sanitize_response(body, &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(body_str.contains("[REDACTED:datadog.api_key]"));
        assert!(body_str.contains("[REDACTED:datadog.app_key]"));
        assert!(!body_str.contains("AAA-secret"));
        assert!(!body_str.contains("BBB-secret"));
    }

    #[test]
    fn json_object_credential_scrubs_blob_form_too() {
        // Defense-in-depth: if the entire JSON blob shows up in the response
        // (e.g. accidentally logged), we still scrub it under the parent name.
        let json_value = r#"{"api_key":"AAA-secret","app_key":"BBB-secret"}"#;
        let body = format!("logged credential: {json_value}").into_bytes();
        let creds = vec![("datadog", json_value)];
        let result = sanitize_response(&body, &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        // Either way the secrets are gone
        assert!(!body_str.contains("AAA-secret"));
        assert!(!body_str.contains("BBB-secret"));
    }

    #[test]
    fn is_sensitive_header_name_explicit_list() {
        assert!(is_sensitive_header_name("Authorization"));
        assert!(is_sensitive_header_name("authorization"));
        assert!(is_sensitive_header_name("X-API-Key"));
        assert!(is_sensitive_header_name("Cookie"));
    }

    #[test]
    fn is_sensitive_header_name_pattern_matches_datadog() {
        // The bug we're fixing: DD-API-KEY and DD-APPLICATION-KEY were not
        // being scrubbed because they aren't in the explicit SENSITIVE_HEADERS
        // list. The pattern fallback catches them.
        assert!(is_sensitive_header_name("DD-API-KEY"));
        assert!(is_sensitive_header_name("dd-api-key"));
        assert!(is_sensitive_header_name("DD-APPLICATION-KEY"));
    }

    #[test]
    fn is_sensitive_header_name_pattern_matches_other_services() {
        assert!(is_sensitive_header_name("X-Linear-Token"));
        assert!(is_sensitive_header_name("X-PostHog-Key"));
        assert!(is_sensitive_header_name("X-Notion-Secret"));
        assert!(is_sensitive_header_name("Some-Custom-Auth"));
    }

    #[test]
    fn is_sensitive_header_name_does_not_redact_normal_headers() {
        // Defense against over-redaction of common non-secret headers
        assert!(!is_sensitive_header_name("Content-Type"));
        assert!(!is_sensitive_header_name("Accept"));
        assert!(!is_sensitive_header_name("User-Agent"));
        assert!(!is_sensitive_header_name("Host"));
        assert!(!is_sensitive_header_name("Accept-Encoding"));
        assert!(!is_sensitive_header_name("Notion-Version"));
    }

    #[test]
    fn sanitize_raw_payload_redacts_datadog_headers() {
        // The full integration: an approval/safety payload with Datadog-style
        // multi-secret auth headers must have BOTH headers redacted.
        let payload = json!({
            "method": "POST",
            "url": "https://api.datadoghq.com/api/v1/events",
            "headers": [
                ["DD-API-KEY", "DD-API-VALUE-AAA"],
                ["DD-APPLICATION-KEY", "DD-APP-VALUE-BBB"],
                ["Content-Type", "application/json"]
            ],
            "body": {"title": "deploy", "text": "build #42"}
        });
        let result = sanitize_raw_payload(&payload);
        let s = serde_json::to_string(&result).unwrap();
        assert!(!s.contains("DD-API-VALUE-AAA"), "api_key leaked: {s}");
        assert!(!s.contains("DD-APP-VALUE-BBB"), "app_key leaked: {s}");
        assert!(s.contains("deploy"), "non-secret body content was scrubbed");
        // Content-Type should NOT be redacted
        assert!(s.contains("application/json"));
    }

    #[test]
    fn plain_string_credential_still_works() {
        // Regression: plain-string credentials must keep working after the
        // JSON-object branch was added.
        let body = b"hello secret-token world";
        let creds = vec![("legacy", "secret-token")];
        let result = sanitize_response(body, &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(body_str.contains("[REDACTED:legacy]"));
        assert!(!body_str.contains("secret-token"));
    }

    // ── Raw payload sanitization ───────────────────────────────────────

    #[test]
    fn sanitize_raw_payload_strips_auth_headers() {
        let payload = json!({
            "method": "POST",
            "url": "https://api.x.com/2/tweets",
            "headers": [
                ["Authorization", "OAuth oauth_consumer_key=\"abc\""],
                ["Content-Type", "application/json"]
            ],
            "body": {"text": "Hello world"}
        });
        let result = sanitize_raw_payload(&payload);
        let headers = result["headers"].as_array().unwrap();
        assert_eq!(headers[0][1], REDACTED);
        assert_eq!(headers[1][1], "application/json");
    }

    #[test]
    fn sanitize_raw_payload_preserves_clean_payload() {
        let payload = json!({
            "method": "POST",
            "url": "https://api.x.com/2/tweets",
            "headers": [["Content-Type", "application/json"]],
            "body": {"text": "Hello world, this is a tweet!"}
        });
        let result = sanitize_raw_payload(&payload);
        assert_eq!(result["body"]["text"], "Hello world, this is a tweet!");
    }
}
