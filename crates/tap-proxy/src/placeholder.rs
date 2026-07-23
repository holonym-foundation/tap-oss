//! Parse <CREDENTIAL:name> and <CREDENTIAL:name.field> placeholders from headers and body.
//!
//! Two placeholder forms:
//! - `<CREDENTIAL:name>` — single-secret reference. The credential value (a plain
//!   string) is substituted directly. Position validation restricts these to
//!   recognized auth headers / auth-binding headers, since the agent has no
//!   per-request control over where they go.
//! - `<CREDENTIAL:name.field>` — multi-secret field reference. The credential
//!   value (a JSON object like `{"api_key":"...","app_key":"..."}`) is parsed
//!   and the named field is substituted. The agent is explicitly choosing
//!   which header receives which field, so these are allowed in **any** header.
//!   Body rules still apply (opt-in + recognized auth-key) to both forms.
//!
//! CRITICAL: validate placeholder positions to prevent credential exfiltration.

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;
use tap_core::config::CredentialConfig;
use tap_core::error::AgentSecError;
use tap_core::types::{Placeholder, PlaceholderPosition};

/// Captures: group 1 = credential name (required), group 2 = field name (optional, after `.`).
static PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<CREDENTIAL:([a-zA-Z0-9_-]+)(?:\.([a-zA-Z0-9_-]+))?>").unwrap());

/// Headers where single-secret credential placeholders (`<CREDENTIAL:name>`) are
/// allowed by default. Field references (`<CREDENTIAL:name.field>`) bypass this
/// list — the agent owns wiring for multi-secret credentials.
const ALLOWED_AUTH_HEADERS: &[&str] = &["authorization", "x-api-key", "x-auth-token"];

fn allowed_header_for_credential(
    credential_configs: &HashMap<String, CredentialConfig>,
    credential_name: &str,
    header_name: &str,
) -> bool {
    match credential_configs.get(credential_name) {
        Some(config) if !config.auth_bindings.is_empty() => config
            .auth_bindings
            .iter()
            .any(|binding| binding.header.eq_ignore_ascii_case(header_name)),
        _ => ALLOWED_AUTH_HEADERS.contains(&header_name.to_lowercase().as_str()),
    }
}

/// Body JSON keys recognized as auth fields (where credential placeholders are allowed).
const ALLOWED_AUTH_BODY_KEYS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "password",
    "secret",
    "credentials",
    "oauth_token",
];

/// Parse placeholders from request headers and body.
/// Returns PlaceholderPositionViolation if a placeholder appears in a non-auth position.
pub fn parse_placeholders(
    headers: &[(String, String)],
    body: Option<&[u8]>,
    content_type: Option<&str>,
    credential_configs: &HashMap<String, CredentialConfig>,
) -> Result<Vec<Placeholder>, AgentSecError> {
    let mut placeholders = Vec::new();

    // Parse from headers
    for (name, value) in headers {
        let matches: Vec<_> = PLACEHOLDER_RE.captures_iter(value).collect();
        for cap in &matches {
            let cred_name = cap[1].to_string();
            if cred_name.is_empty() {
                continue;
            }
            let field = cap.get(2).map(|m| m.as_str().to_string());

            // Field references (`<CREDENTIAL:name.field>`) are explicit
            // per-request wiring by the agent — the agent is consciously
            // choosing the header. Allow them in any header. Plain references
            // (`<CREDENTIAL:name>`) keep the existing position validation.
            if field.is_none()
                && !allowed_header_for_credential(credential_configs, &cred_name, name)
            {
                return Err(AgentSecError::PlaceholderPositionViolation {
                    credential: cred_name,
                    location: format!(
                        "header '{name}' is not an allowed auth header for this credential"
                    ),
                });
            }

            placeholders.push(Placeholder {
                credential_name: cred_name,
                field,
                position: PlaceholderPosition::Header(name.clone()),
            });
        }
    }

    // Parse from body
    if let Some(body_bytes) = body {
        let body_str = match std::str::from_utf8(body_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(placeholders),
        };

        // Check if any placeholders exist in body
        let body_matches: Vec<_> = PLACEHOLDER_RE.captures_iter(body_str).collect();
        if body_matches.is_empty() {
            return Ok(placeholders);
        }

        // For each placeholder in body, check if body substitution is enabled
        for cap in &body_matches {
            let cred_name = cap[1].to_string();
            if cred_name.is_empty() {
                continue;
            }
            let field = cap.get(2).map(|m| m.as_str().to_string());

            let config = credential_configs.get(&cred_name);
            let body_enabled = config.is_some_and(|c| c.substitution.body);

            if !body_enabled {
                return Err(AgentSecError::PlaceholderPositionViolation {
                    credential: cred_name,
                    location: "body (body substitution not enabled for this credential)"
                        .to_string(),
                });
            }

            // Check content type is allowed
            let ct = content_type.unwrap_or("");
            let allowed_types = config
                .map(|c| &c.substitution.body_content_types)
                .cloned()
                .unwrap_or_default();
            if !allowed_types.iter().any(|t| ct.starts_with(t.as_str())) {
                return Err(AgentSecError::PlaceholderPositionViolation {
                    credential: cred_name,
                    location: format!(
                        "body with content-type '{ct}' (not in allowed types: {allowed_types:?})"
                    ),
                });
            }

            // Validate the placeholder is in an auth field position. Body
            // rules apply uniformly to plain and field references — leaking
            // a single field of a multi-secret credential into a tweet body
            // is just as bad as leaking the whole thing.
            validate_body_placeholder_position(body_str, &cred_name, field.as_deref(), ct)?;

            placeholders.push(Placeholder {
                credential_name: cred_name,
                field,
                position: PlaceholderPosition::Body,
            });
        }
    }

    Ok(placeholders)
}

/// Validate that a placeholder in the body is in a recognized auth field.
fn validate_body_placeholder_position(
    body: &str,
    cred_name: &str,
    field: Option<&str>,
    content_type: &str,
) -> Result<(), AgentSecError> {
    let placeholder = match field {
        Some(f) => format!("<CREDENTIAL:{cred_name}.{f}>"),
        None => format!("<CREDENTIAL:{cred_name}>"),
    };

    // Nothing to validate if this particular placeholder isn't in the body
    // (e.g. it only appeared in a header). Avoids false rejections.
    if !body.contains(&placeholder) {
        return Ok(());
    }

    let violation = |location: &str| {
        Err(AgentSecError::PlaceholderPositionViolation {
            credential: cred_name.to_string(),
            location: location.to_string(),
        })
    };

    let ct = content_type.to_ascii_lowercase();
    if ct.contains("json") {
        // Must parse AND sit only in a recognized auth field. A body that
        // declares JSON but does not parse cannot be position-validated, so we
        // fail closed — previously the parse failure was swallowed (`if let
        // Ok`) and the placeholder passed regardless of position, letting an
        // agent land the secret in a reflectable body field via malformed JSON.
        match serde_json::from_str::<serde_json::Value>(body) {
            Ok(value) if json_placeholder_in_auth_field(&value, &placeholder) => Ok(()),
            Ok(_) => violation("body content field (not a recognized auth field)"),
            Err(_) => violation("body declared a JSON content-type but did not parse as JSON"),
        }
    } else if ct.contains("x-www-form-urlencoded") {
        if form_placeholder_in_auth_field(body, &placeholder) {
            Ok(())
        } else {
            violation("body form field (not a recognized auth field)")
        }
    } else {
        // The content-type passed the per-credential body_content_types
        // allowlist (checked by the caller) but is not a structured type we can
        // position-validate (e.g. an operator added text/plain). We can't prove
        // the secret sits in an auth field, so fail closed.
        violation("body of a content-type whose auth-field position cannot be verified")
    }
}

/// Check if a placeholder appears only in recognized auth keys in a JSON value.
fn json_placeholder_in_auth_field(value: &serde_json::Value, placeholder: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if let serde_json::Value::String(s) = val {
                    if s.contains(placeholder) {
                        let lower_key = key.to_lowercase();
                        if !ALLOWED_AUTH_BODY_KEYS.contains(&lower_key.as_str()) {
                            return false;
                        }
                    }
                }
                // Recurse into nested objects
                if val.is_object() && !json_placeholder_in_auth_field(val, placeholder) {
                    return false;
                }
            }
            true
        }
        serde_json::Value::String(s) => !s.contains(placeholder),
        serde_json::Value::Array(arr) => arr
            .iter()
            .all(|v| json_placeholder_in_auth_field(v, placeholder)),
        _ => true,
    }
}

/// Check if a placeholder in URL-encoded form data is in a recognized auth field.
fn form_placeholder_in_auth_field(body: &str, placeholder: &str) -> bool {
    for pair in body.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if value.contains(placeholder) {
                let lower_key = key.to_lowercase();
                if !ALLOWED_AUTH_BODY_KEYS.contains(&lower_key.as_str()) {
                    return false;
                }
            }
        }
    }
    true
}

/// Substitute placeholders in headers with real credential values.
pub fn substitute_headers(
    headers: &[(String, String)],
    credential_values: &HashMap<String, String>,
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.clone(), substitute_in_str(value, credential_values)))
        .collect()
}

/// Substitute placeholders in request body with real credential values.
pub fn substitute_body(body: &[u8], credential_values: &HashMap<String, String>) -> Vec<u8> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return body.to_vec(),
    };
    substitute_in_str(body_str, credential_values).into_bytes()
}

/// Substitute every `<CREDENTIAL:name>` and `<CREDENTIAL:name.field>` in `text`.
///
/// - Plain `<CREDENTIAL:name>` → looked up in `credential_values` and replaced
///   with the raw value (the existing single-secret behavior).
/// - `<CREDENTIAL:name.field>` → looked up in `credential_values`, the value is
///   parsed as a JSON object, and the `field` string is substituted.
///
/// In all unresolved cases (credential not present, value not JSON, field
/// missing) the placeholder is left **literal** in the output rather than
/// silently substituting an empty string. The proxy will then either send the
/// literal placeholder upstream (causing a clear API error) or, in policy mode,
/// reject the request earlier — both better failure modes than silent injection
/// of nothing.
fn substitute_in_str(text: &str, credential_values: &HashMap<String, String>) -> String {
    PLACEHOLDER_RE
        .replace_all(text, |caps: &regex::Captures| {
            let cred_name = &caps[1];
            let field = caps.get(2).map(|m| m.as_str());
            let original = caps[0].to_string();

            let Some(cred_value) = credential_values.get(cred_name) else {
                return original;
            };

            match field {
                Some(field_name) => match serde_json::from_str::<serde_json::Value>(cred_value) {
                    Ok(serde_json::Value::Object(map)) => map
                        .get(field_name)
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or(original),
                    _ => original,
                },
                None => {
                    // Bare `<CREDENTIAL:name>` against a multi-secret credential
                    // is almost always a bug — the agent forgot to pick a field.
                    // Substituting the raw JSON blob would inject something
                    // structurally wrong (e.g. a header containing JSON). Leave
                    // it literal so the upstream rejects with a clear error
                    // and the user can find the bug.
                    if matches!(
                        serde_json::from_str::<serde_json::Value>(cred_value),
                        Ok(serde_json::Value::Object(_))
                    ) {
                        original
                    } else {
                        cred_value.clone()
                    }
                }
            }
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_core::config::{AuthBinding, SubstitutionConfig};

    fn make_cred_config(body: bool) -> CredentialConfig {
        CredentialConfig {
            description: "test".to_string(),
            api_base: None,
            substitution: SubstitutionConfig {
                headers: true,
                body,
                body_content_types: vec![
                    "application/x-www-form-urlencoded".to_string(),
                    "application/json".to_string(),
                ],
            },
            connector: Default::default(),
            relative_target: false,
            auth_header_format: None,
            auth_bindings: Vec::new(),
            allowed_hosts: Vec::new(),
            end_user_id: None,
        }
    }

    fn configs_map(name: &str, body: bool) -> HashMap<String, CredentialConfig> {
        let mut m = HashMap::new();
        m.insert(name.to_string(), make_cred_config(body));
        m
    }

    fn config_with_binding(header: &str) -> CredentialConfig {
        let mut config = make_cred_config(false);
        config.auth_bindings = vec![AuthBinding {
            header: header.to_string(),
            format: "{value}".to_string(),
        }];
        config
    }

    #[test]
    fn parse_single_placeholder_from_header() {
        let headers = vec![(
            "Authorization".to_string(),
            "Bearer <CREDENTIAL:twitter-key>".to_string(),
        )];
        let configs = configs_map("twitter-key", false);
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "twitter-key");
        assert_eq!(
            result[0].position,
            PlaceholderPosition::Header("Authorization".to_string())
        );
    }

    #[test]
    fn parse_multiple_placeholders_from_headers() {
        let headers = vec![
            (
                "Authorization".to_string(),
                "Bearer <CREDENTIAL:twitter-key>".to_string(),
            ),
            (
                "X-Api-Key".to_string(),
                "<CREDENTIAL:backup-key>".to_string(),
            ),
        ];
        let mut configs = configs_map("twitter-key", false);
        configs.insert("backup-key".to_string(), make_cred_config(false));
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].credential_name, "twitter-key");
        assert_eq!(result[1].credential_name, "backup-key");
    }

    #[test]
    fn parse_placeholder_from_body_when_opted_in() {
        let headers = vec![];
        let body = br#"{"token": "<CREDENTIAL:oauth-refresh>"}"#;
        let configs = configs_map("oauth-refresh", true);
        let result =
            parse_placeholders(&headers, Some(body), Some("application/json"), &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].position, PlaceholderPosition::Body);
    }

    #[test]
    fn reject_body_placeholder_when_not_opted_in() {
        let headers = vec![];
        let body = br#"{"token": "<CREDENTIAL:secret>"}"#;
        let configs = configs_map("secret", false);
        let result = parse_placeholders(&headers, Some(body), Some("application/json"), &configs);
        assert!(result.is_err());
    }

    #[test]
    fn reject_body_placeholder_wrong_content_type() {
        let headers = vec![];
        let body = br#"token=<CREDENTIAL:secret>"#;
        let configs = configs_map("secret", true);
        // text/plain is not in allowed content types
        let result = parse_placeholders(&headers, Some(body), Some("text/plain"), &configs);
        assert!(result.is_err());
    }

    #[test]
    fn no_placeholders_passthrough() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
        ];
        let configs = HashMap::new();
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn malformed_placeholder_ignored() {
        // Empty name
        let headers = vec![(
            "Authorization".to_string(),
            "Bearer <CREDENTIAL:>".to_string(),
        )];
        let configs = HashMap::new();
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert!(result.is_empty());

        // Missing colon
        let headers = vec![("Authorization".to_string(), "<CREDENTIAL>".to_string())];
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert!(result.is_empty());

        // Unclosed bracket
        let headers = vec![(
            "Authorization".to_string(),
            "<CREDENTIAL:unclosed".to_string(),
        )];
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn placeholder_in_non_auth_header_rejected() {
        let headers = vec![(
            "X-Custom-Data".to_string(),
            "value <CREDENTIAL:secret>".to_string(),
        )];
        let configs = configs_map("secret", false);
        let result = parse_placeholders(&headers, None, None, &configs);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            AgentSecError::PlaceholderPositionViolation { credential, .. } => {
                assert_eq!(credential, "secret");
            }
            _ => panic!("Expected PlaceholderPositionViolation"),
        }
    }

    #[test]
    fn placeholder_in_custom_bound_header_accepted() {
        let headers = vec![(
            "DD-API-KEY".to_string(),
            "<CREDENTIAL:datadog-api>".to_string(),
        )];
        let mut configs = HashMap::new();
        configs.insert("datadog-api".to_string(), config_with_binding("DD-API-KEY"));
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "datadog-api");
    }

    #[test]
    fn placeholder_in_wrong_custom_bound_header_rejected() {
        let headers = vec![(
            "X-API-KEY".to_string(),
            "<CREDENTIAL:datadog-api>".to_string(),
        )];
        let mut configs = HashMap::new();
        configs.insert("datadog-api".to_string(), config_with_binding("DD-API-KEY"));
        let result = parse_placeholders(&headers, None, None, &configs);
        assert!(result.is_err());
    }

    #[test]
    fn placeholder_in_tweet_body_rejected() {
        let headers = vec![];
        let body = br#"{"text": "Hello <CREDENTIAL:slack-token> world"}"#;
        let configs = configs_map("slack-token", true);
        let result = parse_placeholders(&headers, Some(body), Some("application/json"), &configs);
        assert!(result.is_err());
        match result.unwrap_err() {
            AgentSecError::PlaceholderPositionViolation { credential, .. } => {
                assert_eq!(credential, "slack-token");
            }
            _ => panic!("Expected PlaceholderPositionViolation"),
        }
    }

    #[test]
    fn malformed_json_body_with_placeholder_fails_closed() {
        // application/json content-type but the body isn't valid JSON. Previously
        // the parse failure was swallowed and the placeholder passed regardless
        // of position; now it must be rejected (the secret could otherwise land
        // in a reflectable position via substitution).
        let headers = vec![];
        let body = br#"text=<CREDENTIAL:slack-token>&not=json"#;
        let configs = configs_map("slack-token", true);
        let result = parse_placeholders(&headers, Some(body), Some("application/json"), &configs);
        assert!(result.is_err(), "malformed JSON body must fail closed");
        match result.unwrap_err() {
            AgentSecError::PlaceholderPositionViolation { credential, .. } => {
                assert_eq!(credential, "slack-token");
            }
            _ => panic!("Expected PlaceholderPositionViolation"),
        }
    }

    #[test]
    fn placeholder_in_auth_body_field_accepted() {
        let headers = vec![];
        let body =
            br#"{"grant_type": "refresh_token", "refresh_token": "<CREDENTIAL:oauth-refresh>"}"#;
        let configs = configs_map("oauth-refresh", true);
        let result =
            parse_placeholders(&headers, Some(body), Some("application/json"), &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "oauth-refresh");
    }

    // ---- Field references (`<CREDENTIAL:name.field>`) ----------------------

    #[test]
    fn parse_field_reference_in_arbitrary_header() {
        // The whole point of field references: agent puts a multi-secret
        // field into a header that is NOT in ALLOWED_AUTH_HEADERS and is
        // NOT in any auth_binding. Should be allowed because the agent is
        // explicitly choosing the wiring.
        let headers = vec![
            (
                "DD-API-KEY".to_string(),
                "<CREDENTIAL:datadog.api_key>".to_string(),
            ),
            (
                "DD-APPLICATION-KEY".to_string(),
                "<CREDENTIAL:datadog.app_key>".to_string(),
            ),
        ];
        let configs = configs_map("datadog", false);
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].credential_name, "datadog");
        assert_eq!(result[0].field.as_deref(), Some("api_key"));
        assert_eq!(result[1].credential_name, "datadog");
        assert_eq!(result[1].field.as_deref(), Some("app_key"));
    }

    #[test]
    fn substitute_field_reference_resolves_named_field() {
        let headers = vec![
            (
                "DD-API-KEY".to_string(),
                "<CREDENTIAL:datadog.api_key>".to_string(),
            ),
            (
                "DD-APPLICATION-KEY".to_string(),
                "<CREDENTIAL:datadog.app_key>".to_string(),
            ),
        ];
        let mut values = HashMap::new();
        values.insert(
            "datadog".to_string(),
            r#"{"api_key":"AAA","app_key":"BBB"}"#.to_string(),
        );
        let result = substitute_headers(&headers, &values);
        assert_eq!(result[0].1, "AAA");
        assert_eq!(result[1].1, "BBB");
    }

    #[test]
    fn substitute_field_reference_two_fields_get_distinct_values() {
        // The defining property of multi-secret: same credential name,
        // two field references, two DIFFERENT substituted values.
        let headers = vec![
            (
                "DD-API-KEY".to_string(),
                "<CREDENTIAL:datadog.api_key>".to_string(),
            ),
            (
                "DD-APPLICATION-KEY".to_string(),
                "<CREDENTIAL:datadog.app_key>".to_string(),
            ),
        ];
        let mut values = HashMap::new();
        values.insert(
            "datadog".to_string(),
            r#"{"api_key":"AAA","app_key":"BBB"}"#.to_string(),
        );
        let result = substitute_headers(&headers, &values);
        assert_ne!(
            result[0].1, result[1].1,
            "two field refs must produce two distinct secrets — that's the whole point"
        );
    }

    #[test]
    fn substitute_field_reference_unknown_field_left_literal() {
        let headers = vec![(
            "DD-X".to_string(),
            "<CREDENTIAL:datadog.nonexistent>".to_string(),
        )];
        let mut values = HashMap::new();
        values.insert("datadog".to_string(), r#"{"api_key":"AAA"}"#.to_string());
        let result = substitute_headers(&headers, &values);
        // Left literal so the request fails clearly upstream rather than
        // sending an empty value.
        assert_eq!(result[0].1, "<CREDENTIAL:datadog.nonexistent>");
    }

    #[test]
    fn substitute_field_reference_on_plain_string_value_left_literal() {
        // If someone refs `<CREDENTIAL:openai.foo>` but the openai credential
        // is a plain string (not a JSON object), the field can't be resolved
        // — leave the placeholder literal.
        let headers = vec![("X".to_string(), "<CREDENTIAL:openai.foo>".to_string())];
        let mut values = HashMap::new();
        values.insert("openai".to_string(), "sk-plain-string".to_string());
        let result = substitute_headers(&headers, &values);
        assert_eq!(result[0].1, "<CREDENTIAL:openai.foo>");
    }

    #[test]
    fn substitute_bare_reference_to_multi_secret_credential_left_literal() {
        // Bare <CREDENTIAL:datadog> against a JSON-object value would inject
        // the raw JSON blob into the header — almost certainly a bug. Leave
        // the placeholder literal so the upstream surfaces a clear error.
        let headers = vec![(
            "Authorization".to_string(),
            "Bearer <CREDENTIAL:datadog>".to_string(),
        )];
        let mut values = HashMap::new();
        values.insert(
            "datadog".to_string(),
            r#"{"api_key":"AAA","app_key":"BBB"}"#.to_string(),
        );
        let result = substitute_headers(&headers, &values);
        assert_eq!(
            result[0].1, "Bearer <CREDENTIAL:datadog>",
            "bare ref to multi-secret cred must NOT inject the raw JSON blob"
        );
        assert!(!result[0].1.contains("AAA"));
        assert!(!result[0].1.contains("BBB"));
    }

    #[test]
    fn substitute_plain_reference_unchanged_by_field_support() {
        // Regression: plain single-secret references must still work exactly
        // like before, with no JSON parsing or surprise behavior.
        let headers = vec![(
            "Authorization".to_string(),
            "Bearer <CREDENTIAL:openai>".to_string(),
        )];
        let mut values = HashMap::new();
        values.insert("openai".to_string(), "sk-plain-string".to_string());
        let result = substitute_headers(&headers, &values);
        assert_eq!(result[0].1, "Bearer sk-plain-string");
    }

    #[test]
    fn parse_field_reference_in_body_still_validated() {
        // Body rules apply uniformly: a field reference in a non-auth body
        // field is rejected just like a plain reference would be.
        let headers = vec![];
        let body = br#"{"text": "leaked: <CREDENTIAL:datadog.api_key>"}"#;
        let configs = configs_map("datadog", true);
        let result = parse_placeholders(&headers, Some(body), Some("application/json"), &configs);
        assert!(result.is_err(), "field ref in tweet body must be rejected");
    }

    #[test]
    fn parse_field_reference_in_auth_body_field_accepted() {
        let headers = vec![];
        let body = br#"{"refresh_token": "<CREDENTIAL:google.refresh_token>"}"#;
        let configs = configs_map("google", true);
        let result =
            parse_placeholders(&headers, Some(body), Some("application/json"), &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "google");
        assert_eq!(result[0].field.as_deref(), Some("refresh_token"));
    }

    #[test]
    fn placeholder_in_url_encoded_body() {
        let headers = vec![];
        let body = b"grant_type=refresh_token&refresh_token=<CREDENTIAL:oauth-refresh>";
        let configs = configs_map("oauth-refresh", true);
        let result = parse_placeholders(
            &headers,
            Some(body),
            Some("application/x-www-form-urlencoded"),
            &configs,
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "oauth-refresh");
    }
}
