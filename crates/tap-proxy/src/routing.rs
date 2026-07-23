//! Unified routing: resolves X-TAP-Credential to an effective target
//! and headers based on the credential's connector type in config.

use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use base64::Engine as _;
use tap_core::config::{AgentSecConfig, ConnectorType, CredentialConfig};

/// Optional per-request selector for hybrid X/Twitter credentials that contain
/// both app Bearer Token and OAuth 1.0a account fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XAuthMode {
    Auto,
    Bearer,
    OAuth1,
}

impl XAuthMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Some(Self::Auto),
            "bearer" | "app" | "app-only" | "app_only" => Some(Self::Bearer),
            "oauth1" | "oauth1a" | "oauth-1.0a" | "user" | "user-context" | "user_context" => {
                Some(Self::OAuth1)
            }
            _ => None,
        }
    }
}

fn method_is_read_like(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS"
    )
}

/// Resolved routing information for a unified-interface request.
#[derive(Debug, Clone)]
pub struct UnifiedRoute {
    /// Where to actually send the HTTP request.
    pub effective_target: String,
    /// What to show in audit logs and approval messages (the "real" API URL).
    pub display_target: String,
    /// Headers to forward (with credential injected for direct, or X-OAuth-* for sidecar).
    pub headers: Vec<(String, String)>,
    /// If set, the proxy must do an inline Google OAuth token refresh before forwarding.
    /// Contains the parsed credential JSON (client_id, client_secret, refresh_token).
    pub google_oauth: Option<crate::google_oauth::GoogleOAuthCredential>,
    /// If set, the proxy must do an inline Microsoft (Entra/Graph) OAuth token
    /// refresh before forwarding. Contains the parsed credential JSON
    /// (client_id, client_secret, refresh_token, token_url).
    pub microsoft_oauth: Option<crate::microsoft_oauth::MicrosoftOAuthCredential>,
    /// If set, the proxy must sign the request with OAuth 1.0a (HMAC-SHA1, RFC 5849)
    /// before forwarding. Contains the parsed credential JSON with the four
    /// consumer/token key+secret pairs.
    pub twitter_oauth: Option<crate::oauth1::TwitterOAuthCredential>,
    /// If set, the proxy must sign the request with AWS Signature Version 4
    /// before forwarding. Contains the parsed credential JSON bundle.
    pub aws_sigv4: Option<crate::aws_sigv4::AwsCredential>,
    /// If set, the proxy must exchange client credentials for a Bearer token
    /// via OAuth 2.0 Client Credentials grant before forwarding.
    pub oauth_client_credentials: Option<crate::oauth_client_credentials::OAuthClientCredentials>,
}

/// Resolve routing for a unified-interface request based on credential config.
///
/// Returns the effective target URL, display target, and headers to forward.
/// The caller handles whitelist check, policy, approval, forwarding, and audit.
pub fn resolve_unified_route(
    cred_name: &str,
    target_url: &str,
    method_str: &str,
    forward_headers: &[(String, String)],
    config: &AgentSecConfig,
    credential_values: &HashMap<String, String>,
) -> Result<UnifiedRoute, RouteError> {
    resolve_unified_route_with_auth_mode(
        cred_name,
        target_url,
        method_str,
        forward_headers,
        config,
        credential_values,
        None,
    )
}

pub fn resolve_unified_route_with_auth_mode(
    cred_name: &str,
    target_url: &str,
    method_str: &str,
    forward_headers: &[(String, String)],
    config: &AgentSecConfig,
    credential_values: &HashMap<String, String>,
    x_auth_mode: Option<XAuthMode>,
) -> Result<UnifiedRoute, RouteError> {
    let cred_config = config
        .credentials
        .get(cred_name)
        .ok_or_else(|| RouteError::CredentialNotFound(cred_name.to_string()))?;

    let cred_value = credential_values.get(cred_name).map(|s| s.as_str());
    resolve_unified_route_with_config_and_auth_mode(
        cred_name,
        target_url,
        method_str,
        forward_headers,
        cred_config,
        cred_value,
        x_auth_mode,
    )
}

/// Resolve routing from an individual credential config + optional value.
/// Used by both YAML and DB modes.
pub fn resolve_unified_route_with_config(
    cred_name: &str,
    target_url: &str,
    method_str: &str,
    forward_headers: &[(String, String)],
    cred_config: &CredentialConfig,
    cred_value: Option<&str>,
) -> Result<UnifiedRoute, RouteError> {
    resolve_unified_route_with_config_and_auth_mode(
        cred_name,
        target_url,
        method_str,
        forward_headers,
        cred_config,
        cred_value,
        None,
    )
}

pub fn resolve_unified_route_with_config_and_auth_mode(
    cred_name: &str,
    target_url: &str,
    method_str: &str,
    forward_headers: &[(String, String)],
    cred_config: &CredentialConfig,
    cred_value: Option<&str>,
    x_auth_mode: Option<XAuthMode>,
) -> Result<UnifiedRoute, RouteError> {
    // A signing-key bundle has no HTTP upstream. Reject /forward use up front,
    // independent of connector type — this also prevents a signing credential
    // misconfigured as `direct` from injecting the private-key JSON bundle into
    // an Authorization header. Signing keys are used only via POST /sign.
    if cred_value
        .and_then(crate::signing::parse_signing_credential)
        .is_some()
    {
        return Err(RouteError::SigningCredential(cred_name.to_string()));
    }

    // Destination host binding. When a credential declares `allowed_hosts`, the
    // injected secret may only ever be sent to a listed host — this is what
    // prevents a compromised agent from exfiltrating it by pointing
    // `X-TAP-Target` at an attacker-controlled host. We skip `relative_target`
    // sidecars (their destination is pinned to `api_base`, not the
    // agent-supplied path). Empty `allowed_hosts` = unrestricted (warn-only,
    // for backward compatibility); the caller logs the warning at the
    // secret-injection point so the signal is tied to the leaking connectors.
    if !cred_config.relative_target && !cred_config.allowed_hosts.is_empty() {
        let host = host_of(target_url).ok_or_else(|| RouteError::HostNotAllowed {
            cred: cred_name.to_string(),
            host: target_url.to_string(),
        })?;
        if !cred_config
            .allowed_hosts
            .iter()
            .any(|pattern| host_is_allowed(pattern, &host))
        {
            return Err(RouteError::HostNotAllowed {
                cred: cred_name.to_string(),
                host,
            });
        }
    }

    match cred_config.connector {
        ConnectorType::Direct => {
            let cred_value = cred_value
                .ok_or_else(|| RouteError::CredentialValueMissing(cred_name.to_string()))?;

            let mut headers: Vec<(String, String)> = forward_headers.to_vec();
            if cred_config.auth_bindings.is_empty() {
                // A multi-secret credential (JSON-object value) with no field→header
                // bindings and no custom format has no defined wiring — the old
                // behavior injected the raw JSON blob as `Bearer {…}`, which never
                // authenticates and silently confuses (#21). Reject with a clear,
                // fixable error instead. Formats like Basic's
                // `{base64(value.username:value.password)}` keep working: they
                // define the wiring via auth_header_format.
                if cred_config.auth_header_format.is_none()
                    && matches!(
                        serde_json::from_str::<serde_json::Value>(cred_value),
                        Ok(serde_json::Value::Object(_))
                    )
                {
                    return Err(RouteError::MultiSecretUnbound(cred_name.to_string()));
                }
                let auth_value = match &cred_config.auth_header_format {
                    Some(fmt) => substitute_credential_value(fmt, cred_value),
                    None => format!("Bearer {cred_value}"),
                };

                headers.retain(|(n, _)| n.to_lowercase() != "authorization");
                headers.push(("Authorization".to_string(), auth_value));
            } else {
                let bound_headers: std::collections::HashSet<String> = cred_config
                    .auth_bindings
                    .iter()
                    .map(|binding| binding.header.to_lowercase())
                    .collect();
                headers.retain(|(n, _)| !bound_headers.contains(&n.to_lowercase()));
                for binding in &cred_config.auth_bindings {
                    let value = substitute_credential_value(&binding.format, cred_value);
                    // A leftover `{value.` means the binding references a field the
                    // stored credential doesn't have (or the value isn't a JSON
                    // object) — the header would carry the literal template. Fail
                    // with the field name rather than sending garbage upstream.
                    if value.contains("{value.") {
                        return Err(RouteError::CredentialFieldMissing {
                            cred: cred_name.to_string(),
                            binding: binding.header.clone(),
                        });
                    }
                    headers.push((binding.header.clone(), value));
                }
            }

            Ok(UnifiedRoute {
                effective_target: target_url.to_string(),
                display_target: target_url.to_string(),
                headers,
                google_oauth: None,
                microsoft_oauth: None,
                twitter_oauth: None,
                aws_sigv4: None,
                oauth_client_credentials: None,
            })
        }
        ConnectorType::Sidecar => {
            // Check if the credential value is a Microsoft (Entra/Graph) OAuth
            // refresh-token bundle. Detected BEFORE Google because a Microsoft
            // bundle also has client_id/client_secret/refresh_token and would
            // otherwise be caught by the Google parser; its required `token_url`
            // field is the discriminator. Skip the sidecar and route directly —
            // the proxy refreshes the token inline before forwarding.
            let microsoft_oauth =
                cred_value.and_then(crate::microsoft_oauth::parse_microsoft_oauth);
            if microsoft_oauth.is_some() {
                let mut headers: Vec<(String, String)> = forward_headers.to_vec();
                headers.retain(|(n, _)| n.to_lowercase() != "authorization");
                // Authorization header will be injected by the proxy after token refresh

                return Ok(UnifiedRoute {
                    effective_target: target_url.to_string(),
                    display_target: target_url.to_string(),
                    headers,
                    google_oauth: None,
                    microsoft_oauth,
                    twitter_oauth: None,
                    aws_sigv4: None,
                    oauth_client_credentials: None,
                });
            }

            // Check if the credential value is a Google OAuth 2.0 JSON bundle.
            // If so, skip the sidecar and route directly to the real API —
            // the proxy will do the token refresh inline before forwarding.
            let google_oauth = cred_value.and_then(crate::google_oauth::parse_google_oauth);
            if google_oauth.is_some() {
                let mut headers: Vec<(String, String)> = forward_headers.to_vec();
                headers.retain(|(n, _)| n.to_lowercase() != "authorization");
                // Authorization header will be injected by the proxy after token refresh

                return Ok(UnifiedRoute {
                    effective_target: target_url.to_string(),
                    display_target: target_url.to_string(),
                    headers,
                    google_oauth,
                    microsoft_oauth: None,
                    twitter_oauth: None,
                    aws_sigv4: None,
                    oauth_client_credentials: None,
                });
            }

            // X supports two auth shapes that users should not need to model as
            // two TAP credentials. A hybrid credential may carry an app Bearer
            // Token (`bearer_token`) plus OAuth 1.0a account fields. `auto`
            // deliberately avoids endpoint allowlists: read-like requests use
            // Bearer when available; writes use OAuth1 when available. Agents
            // can use X-TAP-Auth-Mode as an escape hatch.
            let x_bearer_token = cred_value.and_then(crate::oauth1::parse_x_bearer_token);
            let twitter_oauth = cred_value.and_then(crate::oauth1::parse_twitter_oauth);
            let chosen_x_mode = match x_auth_mode.unwrap_or(XAuthMode::Auto) {
                XAuthMode::Bearer => {
                    if x_bearer_token.is_none() {
                        return Err(RouteError::ConfigError(format!(
                            "credential '{cred_name}' does not contain an X bearer_token"
                        )));
                    }
                    Some(XAuthMode::Bearer)
                }
                XAuthMode::OAuth1 => {
                    if twitter_oauth.is_none() {
                        return Err(RouteError::ConfigError(format!(
                            "credential '{cred_name}' does not contain OAuth 1.0a fields"
                        )));
                    }
                    Some(XAuthMode::OAuth1)
                }
                XAuthMode::Auto => match (x_bearer_token.is_some(), twitter_oauth.is_some()) {
                    (true, true) if method_is_read_like(method_str) => Some(XAuthMode::Bearer),
                    (true, true) => Some(XAuthMode::OAuth1),
                    (true, false) => Some(XAuthMode::Bearer),
                    (false, true) => Some(XAuthMode::OAuth1),
                    (false, false) => None,
                },
            };

            if chosen_x_mode == Some(XAuthMode::Bearer) {
                let token = x_bearer_token.expect("chosen bearer requires token");
                let mut headers: Vec<(String, String)> = forward_headers.to_vec();
                headers.retain(|(n, _)| n.to_lowercase() != "authorization");
                headers.push(("Authorization".to_string(), format!("Bearer {token}")));

                return Ok(UnifiedRoute {
                    effective_target: target_url.to_string(),
                    display_target: target_url.to_string(),
                    headers,
                    google_oauth: None,
                    microsoft_oauth: None,
                    twitter_oauth: None,
                    aws_sigv4: None,
                    oauth_client_credentials: None,
                });
            }

            // Check if the credential value is an OAuth 1.0a bundle (Twitter/X).
            // If so, skip the sidecar and route directly to the real API —
            // the proxy will HMAC-SHA1 sign the request inline before forwarding.
            if twitter_oauth.is_some() {
                let mut headers: Vec<(String, String)> = forward_headers.to_vec();
                headers.retain(|(n, _)| n.to_lowercase() != "authorization");
                // Authorization header will be injected by the proxy after signing

                return Ok(UnifiedRoute {
                    effective_target: target_url.to_string(),
                    display_target: target_url.to_string(),
                    headers,
                    google_oauth: None,
                    microsoft_oauth: None,
                    twitter_oauth,
                    aws_sigv4: None,
                    oauth_client_credentials: None,
                });
            }

            // Check if the credential value is an AWS SigV4 bundle (access_key_id +
            // secret_access_key). If so, skip the sidecar and route directly to the
            // real AWS API — the proxy will sign the request inline before forwarding.
            let aws_sigv4 = cred_value.and_then(crate::aws_sigv4::parse_aws_credential);
            if aws_sigv4.is_some() {
                let mut headers: Vec<(String, String)> = forward_headers.to_vec();
                // Remove any pre-existing auth / SigV4 headers — proxy injects them after signing.
                headers.retain(|(n, _)| {
                    let nl = n.to_lowercase();
                    nl != "authorization" && nl != "x-amz-date" && nl != "x-amz-content-sha256"
                });

                return Ok(UnifiedRoute {
                    effective_target: target_url.to_string(),
                    display_target: target_url.to_string(),
                    headers,
                    google_oauth: None,
                    microsoft_oauth: None,
                    twitter_oauth: None,
                    aws_sigv4,
                    oauth_client_credentials: None,
                });
            }

            // Check if the credential value is an OAuth 2.0 Client Credentials bundle
            // (client_id, client_secret, token_url). If so, skip the sidecar and route
            // directly to the real API — the proxy will exchange credentials for a Bearer
            // token inline before forwarding.
            let oauth_cc = cred_value
                .and_then(crate::oauth_client_credentials::parse_oauth_client_credentials);
            if oauth_cc.is_some() {
                let mut headers: Vec<(String, String)> = forward_headers.to_vec();
                headers.retain(|(n, _)| n.to_lowercase() != "authorization");

                return Ok(UnifiedRoute {
                    effective_target: target_url.to_string(),
                    display_target: target_url.to_string(),
                    headers,
                    google_oauth: None,
                    microsoft_oauth: None,
                    twitter_oauth: None,
                    aws_sigv4: None,
                    oauth_client_credentials: oauth_cc,
                });
            }

            // Standard sidecar routing (non-inline OAuth)
            let sidecar_base = cred_config.api_base.as_deref().ok_or_else(|| {
                RouteError::ConfigError(format!(
                    "credential '{cred_name}' has connector=sidecar but no api_base"
                ))
            })?;
            let sidecar_base = rewrite_sidecar_base(sidecar_base);

            let (effective_target, display_target) = if cred_config.relative_target {
                // Validate: reject path traversal
                if target_url.contains("..") {
                    return Err(RouteError::PathTraversal);
                }
                // Prepend sidecar base to relative path
                let base = sidecar_base.trim_end_matches('/');
                let path = if target_url.starts_with('/') {
                    target_url.to_string()
                } else {
                    format!("/{target_url}")
                };
                (format!("{base}{path}"), target_url.to_string())
            } else {
                // Target is the real API URL, route through sidecar
                (sidecar_base.to_string(), target_url.to_string())
            };

            // Build headers for the sidecar
            let mut headers: Vec<(String, String)> = forward_headers.to_vec();
            headers.push(("X-OAuth-Credential".to_string(), cred_name.to_string()));
            if !cred_config.relative_target {
                headers.push(("X-OAuth-Target".to_string(), target_url.to_string()));
            }
            headers.push(("X-TAP-Method".to_string(), method_str.to_string()));
            // Pass credential value to sidecar (e.g. JSON with OAuth keys)
            if let Some(val) = cred_value {
                headers.push(("X-OAuth-Credential-Data".to_string(), val.to_string()));
            }

            Ok(UnifiedRoute {
                effective_target,
                display_target,
                headers,
                google_oauth: None,
                microsoft_oauth: None,
                twitter_oauth: None,
                aws_sigv4: None,
                oauth_client_credentials: None,
            })
        }
    }
}

/// Extract the lowercased host component of a full URL. Returns `None` when the
/// input is not a parseable absolute URL with a host (e.g. a relative path), so
/// the caller fails closed.
pub fn host_of(target_url: &str) -> Option<String> {
    let parsed = url::Url::parse(target_url).ok()?;
    parsed.host_str().map(|h| h.to_ascii_lowercase())
}

/// Match a single `allowed_hosts` pattern against a (already-lowercased) host.
///
/// - Exact: `api.stripe.com` matches only `api.stripe.com`.
/// - Wildcard: `*.googleapis.com` matches any subdomain (`gmail.googleapis.com`,
///   `a.b.googleapis.com`) and the bare apex (`googleapis.com`). It does **not**
///   match a different suffix (`evil-googleapis.com`) because the match requires
///   a leading dot boundary.
///
/// Patterns are trimmed and lowercased before comparison so the stored list is
/// case-insensitive.
pub fn host_is_allowed(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

fn rewrite_sidecar_base(sidecar_base: &str) -> String {
    if sidecar_base.contains("telegram-client:8082") {
        if let Ok(base) = std::env::var("TAP_EMBEDDED_TELEGRAM_BASE") {
            if !base.trim().is_empty() {
                return base;
            }
        }
        #[cfg(feature = "enclave")]
        {
            return "http://127.0.0.1:8082".to_string();
        }
    }

    sidecar_base.to_string()
}

/// Substitute credential value(s) into an auth-binding or auth-header format string.
///
/// Supports two placeholder forms:
///
/// - `{value}` — substituted with the credential value as a literal string. Always works.
/// - `{value.<key>}` — substituted with the `<key>` field of a JSON object credential
///   value. Only works when the credential value parses as a JSON object whose
///   fields are strings.
///
/// **Single-secret credentials** store a plain string value (e.g. `xoxb-abc123`)
/// and use `{value}` in their format strings — exactly the existing behavior.
///
/// **Multi-secret credentials** (e.g. Datadog, AWS) store a JSON object value like
/// `{"api_key":"...","app_key":"..."}` and use `{value.api_key}` / `{value.app_key}`
/// in their auth bindings. Each binding can pull a different field, so a single
/// credential row can populate multiple headers with independent secrets.
///
/// Edge cases:
/// - JSON object value + format with bare `{value}`: substitutes the raw JSON
///   blob. Generally not useful but consistent with the "always substitute" rule.
/// - Plain string value + format with `{value.foo}`: leaves the literal
///   `{value.foo}` in the output (no JSON object to look up). User error.
fn substitute_credential_value(format: &str, cred_value: &str) -> String {
    let substituted = if let Ok(serde_json::Value::Object(map)) =
        serde_json::from_str::<serde_json::Value>(cred_value)
    {
        let mut result = format.to_string();
        for (key, val) in &map {
            if let Some(s) = val.as_str() {
                let placeholder = format!("{{value.{key}}}");
                result = result.replace(&placeholder, s);
            }
        }
        // Bare `{value}` still substitutes the raw cred_value (the JSON blob).
        // Most multi-secret formats won't use this, but keep it consistent.
        result = result.replace("{value}", cred_value);
        result
    } else {
        // Plain-string credential: only `{value}` is meaningful.
        format.replace("{value}", cred_value)
    };

    substitute_base64_expressions(&substituted, cred_value)
}

fn substitute_base64_expressions(input: &str, cred_value: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{base64(") {
        out.push_str(&rest[..start]);
        let expr_start = start + "{base64(".len();
        let after_start = &rest[expr_start..];
        if let Some(end) = after_start.find(")}") {
            let expr = &after_start[..end];
            let resolved = resolve_value_refs(expr, cred_value);
            out.push_str(&base64::engine::general_purpose::STANDARD.encode(resolved.as_bytes()));
            rest = &after_start[end + 2..];
        } else {
            out.push_str(&rest[start..]);
            return out;
        }
    }
    out.push_str(rest);
    out
}

fn resolve_value_refs(expr: &str, cred_value: &str) -> String {
    if let Ok(serde_json::Value::Object(map)) =
        serde_json::from_str::<serde_json::Value>(cred_value)
    {
        let mut result = expr.to_string();
        for (key, val) in &map {
            if let Some(s) = val.as_str() {
                result = result.replace(&format!("value.{key}"), s);
            }
        }
        if result == "value" {
            cred_value.to_string()
        } else {
            result
        }
    } else {
        expr.replace("value", cred_value)
    }
}

#[derive(Debug)]
pub enum RouteError {
    CredentialNotFound(String),
    CredentialValueMissing(String),
    ConfigError(String),
    PathTraversal,
    /// The credential is a signing key — it has no HTTP upstream and must be
    /// used via `POST /sign`, not `/forward`.
    SigningCredential(String),
    /// The `X-TAP-Target` host is not in the credential's `allowed_hosts`
    /// binding. Blocks secret exfiltration to an attacker-controlled host.
    HostNotAllowed {
        cred: String,
        host: String,
    },
    /// A multi-secret credential (JSON-object value) was used via plain
    /// `X-TAP-Credential` but has no field→header bindings configured, so the
    /// proxy has no defined wiring for its fields (#21).
    MultiSecretUnbound(String),
    /// An auth binding references a `{value.<field>}` that the stored
    /// credential value doesn't carry.
    CredentialFieldMissing {
        cred: String,
        binding: String,
    },
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::CredentialNotFound(name) => write!(f, "Credential '{name}' not found"),
            RouteError::CredentialValueMissing(name) => {
                write!(f, "Credential '{name}' value not configured")
            }
            RouteError::ConfigError(msg) => write!(f, "Config error: {msg}"),
            RouteError::PathTraversal => write!(f, "Path traversal not allowed in relative target"),
            RouteError::SigningCredential(name) => write!(
                f,
                "Credential '{name}' is a signing key — use POST /sign, not /forward"
            ),
            RouteError::HostNotAllowed { cred, host } => write!(
                f,
                "Credential '{cred}' is not allowed to be sent to host '{host}'. \
                 Add this host to the credential's allowed_hosts in the dashboard."
            ),
            RouteError::MultiSecretUnbound(name) => write!(
                f,
                "Credential '{name}' holds multiple secret fields but has no \
                 field-to-header bindings configured, so the proxy doesn't know \
                 which header receives which field."
            ),
            RouteError::CredentialFieldMissing { cred, binding } => write!(
                f,
                "Credential '{cred}': the binding for header '{binding}' references \
                 a field the stored credential value doesn't have."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_core::config::*;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    // ---- substitute_credential_value ------------------------------------

    #[test]
    fn substitute_plain_string_substitutes_value() {
        let out = substitute_credential_value("Bearer {value}", "xoxb-abc");
        assert_eq!(out, "Bearer xoxb-abc");
    }

    #[test]
    fn substitute_plain_string_leaves_dotted_placeholder_literal() {
        // No JSON object → can't resolve {value.foo}, so it stays literal.
        // This is user error but must not panic.
        let out = substitute_credential_value("{value.foo}", "xoxb-abc");
        assert_eq!(out, "{value.foo}");
    }

    #[test]
    fn substitute_json_object_substitutes_named_field() {
        let value = r#"{"api_key":"AAA","app_key":"BBB"}"#;
        let out = substitute_credential_value("{value.api_key}", value);
        assert_eq!(out, "AAA");
    }

    #[test]
    fn substitute_json_object_supports_multiple_distinct_fields() {
        // The whole point of multi-secret support: two different bindings
        // can pull two different secrets from one credential value.
        let value = r#"{"api_key":"AAA","app_key":"BBB"}"#;
        let out_api = substitute_credential_value("{value.api_key}", value);
        let out_app = substitute_credential_value("{value.app_key}", value);
        assert_eq!(out_api, "AAA");
        assert_eq!(out_app, "BBB");
        assert_ne!(out_api, out_app);
    }

    #[test]
    fn substitute_json_object_unknown_field_stays_literal() {
        // Typo / missing key: don't crash, leave the placeholder so the
        // failure surfaces upstream rather than silently injecting empty.
        let value = r#"{"api_key":"AAA"}"#;
        let out = substitute_credential_value("{value.nonexistent}", value);
        assert_eq!(out, "{value.nonexistent}");
    }

    #[test]
    fn substitute_json_array_falls_back_to_plain_string() {
        // JSON arrays aren't object-shaped, so we treat the whole thing as
        // a plain string for `{value}`.
        let value = r#"["a","b"]"#;
        let out = substitute_credential_value("{value}", value);
        assert_eq!(out, value);
    }

    #[test]
    fn substitute_format_with_prefix_and_suffix() {
        let value = r#"{"api_key":"AAA","app_key":"BBB"}"#;
        let out = substitute_credential_value("Token {value.api_key}-suffix", value);
        assert_eq!(out, "Token AAA-suffix");
    }

    #[test]
    fn substitute_base64_expression_with_json_fields() {
        let value = r#"{"username":"public-key","password":"private-key"}"#;
        let out =
            substitute_credential_value("Basic {base64(value.username:value.password)}", value);
        assert_eq!(out, "Basic cHVibGljLWtleTpwcml2YXRlLWtleQ==");
    }

    fn make_config(cred_name: &str, cred: CredentialConfig) -> AgentSecConfig {
        let mut credentials = HashMap::new();
        credentials.insert(cred_name.to_string(), cred);
        AgentSecConfig {
            version: 1,
            credentials,
            approval: ApprovalConfig {
                channel: "mock".to_string(),
                timeout_seconds: 300,
                default_approvals_required: 1,
            },
            policies: HashMap::new(),
            agents: HashMap::new(),
        }
    }

    fn make_cred_values(name: &str, value: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(name.to_string(), value.to_string());
        m
    }

    fn direct_cred(auth_header_format: Option<&str>, auth_bindings: Vec<AuthBinding>) -> CredentialConfig {
        CredentialConfig {
            description: "test".to_string(),
            api_base: None,
            substitution: SubstitutionConfig::default(),
            connector: ConnectorType::Direct,
            relative_target: false,
            auth_header_format: auth_header_format.map(|s| s.to_string()),
            auth_bindings,
            allowed_hosts: Vec::new(),
            end_user_id: None,
        }
    }

    fn field_binding(header: &str, field: &str) -> AuthBinding {
        AuthBinding {
            header: header.to_string(),
            format: format!("{{value.{field}}}"),
        }
    }

    // ---- multi-secret auto-inject via X-TAP-Credential (#21) ---------------

    #[test]
    fn route_direct_multi_secret_bindings_inject_each_field() {
        // The #21 contract: agent sends ONLY X-TAP-Credential — the proxy
        // injects every configured field into its bound header. The agent
        // never needs to know the API's header names.
        let config = make_config(
            "datadog",
            direct_cred(
                None,
                vec![
                    field_binding("DD-API-KEY", "api_key"),
                    field_binding("DD-APPLICATION-KEY", "app_key"),
                ],
            ),
        );
        let cred_values = make_cred_values("datadog", r#"{"api_key":"AAA","app_key":"BBB"}"#);

        // An agent-supplied value for a bound header must be replaced, not kept.
        let forwarded = vec![("DD-API-KEY".to_string(), "spoofed".to_string())];
        let route = resolve_unified_route(
            "datadog",
            "https://api.datadoghq.com/api/v1/validate",
            "GET",
            &forwarded,
            &config,
            &cred_values,
        )
        .unwrap();

        let get = |name: &str| {
            route
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(get("DD-API-KEY"), vec!["AAA"]);
        assert_eq!(get("DD-APPLICATION-KEY"), vec!["BBB"]);
        assert!(get("Authorization").is_empty(), "no Bearer fallback for bound creds");
    }

    #[test]
    fn route_direct_multi_secret_without_bindings_rejected() {
        // Previously this injected `Bearer {"api_key":...}` — a silently broken
        // request. Now it's a clear, fixable error and the blob never rides in
        // a header.
        let config = make_config("datadog", direct_cred(None, Vec::new()));
        let cred_values = make_cred_values("datadog", r#"{"api_key":"AAA","app_key":"BBB"}"#);

        let err = resolve_unified_route(
            "datadog",
            "https://api.datadoghq.com/api/v1/validate",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap_err();
        assert!(matches!(err, RouteError::MultiSecretUnbound(name) if name == "datadog"));
    }

    #[test]
    fn route_direct_object_value_with_format_still_works() {
        // Basic-auth regression: a JSON-object value with NO bindings but a
        // custom auth_header_format defines its wiring via the format — must
        // keep working unchanged.
        let config = make_config(
            "mailjet",
            direct_cred(Some("Basic {base64(value.username:value.password)}"), Vec::new()),
        );
        let cred_values =
            make_cred_values("mailjet", r#"{"username":"pub","password":"priv"}"#);

        let route = resolve_unified_route(
            "mailjet",
            "https://api.mailjet.com/v3/REST/contact",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();
        let auth = route
            .headers
            .iter()
            .find(|(n, _)| n == "Authorization")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(auth, "Basic cHViOnByaXY="); // base64("pub:priv")
    }

    #[test]
    fn route_direct_binding_to_missing_field_rejected() {
        // A binding referencing a field the stored value doesn't carry would
        // send the literal `{value.nope}` upstream — fail with the header name
        // instead so the misconfiguration is findable.
        let config = make_config(
            "datadog",
            direct_cred(None, vec![field_binding("DD-API-KEY", "nope")]),
        );
        let cred_values = make_cred_values("datadog", r#"{"api_key":"AAA"}"#);

        let err = resolve_unified_route(
            "datadog",
            "https://api.datadoghq.com/api/v1/validate",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RouteError::CredentialFieldMissing { cred, binding }
                if cred == "datadog" && binding == "DD-API-KEY"
        ));
    }

    #[test]
    fn route_direct_injects_bearer_header() {
        let config = make_config(
            "slack",
            CredentialConfig {
                description: "Slack".to_string(),
                api_base: Some("https://slack.com/api".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Direct,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let cred_values = make_cred_values("slack", "xoxb-secret-token");

        let route = resolve_unified_route(
            "slack",
            "https://slack.com/api/conversations.list",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert_eq!(
            route.effective_target,
            "https://slack.com/api/conversations.list"
        );
        assert_eq!(route.display_target, route.effective_target);
        let auth = route
            .headers
            .iter()
            .find(|(n, _)| n == "Authorization")
            .unwrap();
        assert_eq!(auth.1, "Bearer xoxb-secret-token");
    }

    #[test]
    fn route_direct_custom_auth_format() {
        let config = make_config(
            "notion",
            CredentialConfig {
                description: "Notion".to_string(),
                api_base: None,
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Direct,
                relative_target: false,
                auth_header_format: Some("Bot {value}".to_string()),
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let cred_values = make_cred_values("notion", "ntn_secret");

        let route = resolve_unified_route(
            "notion",
            "https://api.notion.com/v1/pages",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        let auth = route
            .headers
            .iter()
            .find(|(n, _)| n == "Authorization")
            .unwrap();
        assert_eq!(auth.1, "Bot ntn_secret");
    }

    #[test]
    fn route_sidecar_forwards_to_api_base() {
        let config = make_config(
            "google",
            CredentialConfig {
                description: "Google".to_string(),
                api_base: Some("http://oauth2-refresher:8081".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let cred_values = HashMap::new();

        let route = resolve_unified_route(
            "google",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert_eq!(route.effective_target, "http://oauth2-refresher:8081");
        assert_eq!(
            route.display_target,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages"
        );
    }

    #[test]
    fn route_sidecar_injects_oauth_headers() {
        let config = make_config(
            "google",
            CredentialConfig {
                description: "Google".to_string(),
                api_base: Some("http://oauth2-refresher:8081".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );

        let route = resolve_unified_route(
            "google",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            "GET",
            &[],
            &config,
            &HashMap::new(),
        )
        .unwrap();

        let oauth_cred = route
            .headers
            .iter()
            .find(|(n, _)| n == "X-OAuth-Credential")
            .unwrap();
        assert_eq!(oauth_cred.1, "google");

        let oauth_target = route
            .headers
            .iter()
            .find(|(n, _)| n == "X-OAuth-Target")
            .unwrap();
        assert_eq!(
            oauth_target.1,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages"
        );
    }

    #[test]
    fn route_sidecar_relative_prepends_base() {
        let config = make_config(
            "telegram",
            CredentialConfig {
                description: "Telegram".to_string(),
                api_base: Some("http://telegram-client:8082".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: true,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );

        let route = resolve_unified_route(
            "telegram",
            "/dialogs?limit=10",
            "GET",
            &[],
            &config,
            &HashMap::new(),
        )
        .unwrap();

        assert_eq!(
            route.effective_target,
            "http://telegram-client:8082/dialogs?limit=10"
        );
        assert_eq!(route.display_target, "/dialogs?limit=10");
        // Relative target should NOT inject X-OAuth-Target
        assert!(!route.headers.iter().any(|(n, _)| n == "X-OAuth-Target"));
    }

    #[test]
    fn route_sidecar_relative_rejects_path_traversal() {
        let config = make_config(
            "telegram",
            CredentialConfig {
                description: "Telegram".to_string(),
                api_base: Some("http://telegram-client:8082".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: true,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );

        let result = resolve_unified_route(
            "telegram",
            "/../etc/passwd",
            "GET",
            &[],
            &config,
            &HashMap::new(),
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RouteError::PathTraversal));
    }

    #[test]
    fn route_signing_credential_rejected_from_forward() {
        // A signing-key bundle has no HTTP upstream — /forward must reject it
        // (redirecting to POST /sign), regardless of connector type. This also
        // guards against the private key leaking into an Authorization header.
        for connector in [ConnectorType::Direct, ConnectorType::Sidecar] {
            let config = make_config(
                "my-signer",
                CredentialConfig {
                    description: "Signing key".to_string(),
                    api_base: Some("tap:sign".to_string()),
                    substitution: SubstitutionConfig::default(),
                    connector: connector.clone(),
                    relative_target: false,
                    auth_header_format: None,
                    auth_bindings: Vec::new(),
                    allowed_hosts: Vec::new(),
                    end_user_id: None,
                },
            );
            let bundle = serde_json::json!({
                "algorithm": "secp256k1",
                "private_key": "4646464646464646464646464646464646464646464646464646464646464646",
                "key_encoding": "hex",
            })
            .to_string();
            let cred_values = make_cred_values("my-signer", &bundle);

            let result = resolve_unified_route(
                "my-signer",
                "https://api.example.com/anything",
                "POST",
                &[],
                &config,
                &cred_values,
            );
            assert!(
                matches!(result.unwrap_err(), RouteError::SigningCredential(name) if name == "my-signer"),
                "signing credential must be rejected for connector {connector:?}"
            );
        }
    }

    #[test]
    fn route_sidecar_oauth1_bypasses_sidecar_and_routes_direct() {
        // OAuth 1.0a JSON bundle in the credential value → must skip the sidecar
        // URL and route directly to the real Twitter API, with twitter_oauth set
        // so the proxy knows to sign the request inline.
        let config = make_config(
            "twitter-personal",
            CredentialConfig {
                description: "Twitter personal".to_string(),
                // This api_base used to be the (non-running) tap-signer at
                // 127.0.0.1:8080 — the whole point of the inline path is to never
                // connect to it.
                api_base: Some("http://127.0.0.1:8080".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let bundle = serde_json::json!({
            "consumer_key": "ck",
            "consumer_secret": "cs",
            "access_token": "at",
            "access_token_secret": "ats",
        })
        .to_string();
        let cred_values = make_cred_values("twitter-personal", &bundle);

        let route = resolve_unified_route(
            "twitter-personal",
            "https://api.twitter.com/2/tweets",
            "POST",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        // Effective target is the real API, NOT the sidecar URL
        assert_eq!(route.effective_target, "https://api.twitter.com/2/tweets");
        assert_eq!(route.display_target, "https://api.twitter.com/2/tweets");
        assert!(!route.effective_target.contains("127.0.0.1"));
        // twitter_oauth flag must be set so proxy.rs signs inline
        assert!(route.twitter_oauth.is_some());
        let parsed = route.twitter_oauth.as_ref().unwrap();
        assert_eq!(parsed.consumer_key, "ck");
        assert_eq!(parsed.access_token_secret, "ats");
        // Must NOT emit the X-OAuth-* sidecar headers — those would go to a
        // sidecar that isn't running.
        assert!(!route
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("X-OAuth-Credential")));
        assert!(!route
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("X-OAuth-Target")));
        // No Authorization header yet — proxy.rs injects it after signing.
        assert!(!route
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("Authorization")));
        // google_oauth must not also be set — the two inline paths are exclusive.
        assert!(route.google_oauth.is_none());
    }

    #[test]
    fn route_hybrid_x_credential_uses_bearer_for_recent_search() {
        let config = make_config(
            "x",
            CredentialConfig {
                description: "X".to_string(),
                api_base: Some("http://127.0.0.1:8080".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: vec!["api.x.com".to_string()],
                end_user_id: None,
            },
        );
        let bundle = serde_json::json!({
            "bearer_token": "bt",
            "consumer_key": "ck",
            "consumer_secret": "cs",
            "access_token": "at",
            "access_token_secret": "ats",
        })
        .to_string();
        let cred_values = make_cred_values("x", &bundle);

        let route = resolve_unified_route(
            "x",
            "https://api.x.com/2/tweets/search/recent?query=tap",
            "GET",
            &[("Authorization".to_string(), "Bearer stale".to_string())],
            &config,
            &cred_values,
        )
        .unwrap();

        assert_eq!(
            route.effective_target,
            "https://api.x.com/2/tweets/search/recent?query=tap"
        );
        assert!(route.twitter_oauth.is_none());
        let auth = route
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("Authorization"))
            .unwrap();
        assert_eq!(auth.1, "Bearer bt");
    }

    #[test]
    fn route_hybrid_x_credential_uses_oauth1_for_account_post() {
        let config = make_config(
            "x",
            CredentialConfig {
                description: "X".to_string(),
                api_base: Some("http://127.0.0.1:8080".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: vec!["api.x.com".to_string()],
                end_user_id: None,
            },
        );
        let bundle = serde_json::json!({
            "bearer_token": "bt",
            "consumer_key": "ck",
            "consumer_secret": "cs",
            "access_token": "at",
            "access_token_secret": "ats",
        })
        .to_string();
        let cred_values = make_cred_values("x", &bundle);

        let route = resolve_unified_route(
            "x",
            "https://api.x.com/2/tweets",
            "POST",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert!(route.twitter_oauth.is_some());
        assert!(!route
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("Authorization")));
    }

    #[test]
    fn route_x_bearer_only_bundle_routes_direct_for_x_api() {
        let config = make_config(
            "x-search",
            CredentialConfig {
                description: "X search".to_string(),
                api_base: Some("http://127.0.0.1:8080".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: vec!["api.x.com".to_string()],
                end_user_id: None,
            },
        );
        let bundle = serde_json::json!({ "bearer_token": "bt" }).to_string();
        let cred_values = make_cred_values("x-search", &bundle);

        let route = resolve_unified_route(
            "x-search",
            "https://api.x.com/2/tweets/counts/recent?query=tap",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        let auth = route
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("Authorization"))
            .unwrap();
        assert_eq!(auth.1, "Bearer bt");
        assert!(route.twitter_oauth.is_none());
        assert!(!route.effective_target.contains("127.0.0.1"));
    }

    #[test]
    fn route_sidecar_oauth_client_credentials_bypasses_sidecar_and_routes_direct() {
        // OAuth 2.0 Client Credentials JSON bundle → must skip the sidecar URL
        // and route directly to the real API, with oauth_client_credentials set
        // so the proxy knows to exchange credentials for a Bearer token inline.
        let config = make_config(
            "azure-admin",
            CredentialConfig {
                description: "Azure Resource Manager".to_string(),
                api_base: Some("http://unused-sidecar:9999".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let bundle = serde_json::json!({
            "client_id": "my-client-id",
            "client_secret": "my-secret",
            "token_url": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
            "scope": "https://management.azure.com/.default",
        })
        .to_string();
        let cred_values = make_cred_values("azure-admin", &bundle);

        let route = resolve_unified_route(
            "azure-admin",
            "https://management.azure.com/subscriptions?api-version=2022-12-01",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        // Routes directly to the real API, not the sidecar
        assert_eq!(
            route.effective_target,
            "https://management.azure.com/subscriptions?api-version=2022-12-01"
        );
        assert!(!route.effective_target.contains("unused-sidecar"));
        // oauth_client_credentials flag must be set so proxy.rs does the token exchange
        assert!(route.oauth_client_credentials.is_some());
        let parsed = route.oauth_client_credentials.as_ref().unwrap();
        assert_eq!(parsed.client_id, "my-client-id");
        assert_eq!(parsed.client_secret, "my-secret");
        assert_eq!(
            parsed.token_url,
            "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token"
        );
        assert_eq!(
            parsed.scope.as_deref(),
            Some("https://management.azure.com/.default")
        );
        // No Authorization header yet — proxy.rs injects after token exchange
        assert!(!route
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("Authorization")));
        // No sidecar headers
        assert!(!route
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("X-OAuth-Credential")));
        // Other inline paths must not be set
        assert!(route.google_oauth.is_none());
        assert!(route.twitter_oauth.is_none());
        assert!(route.aws_sigv4.is_none());
    }

    #[test]
    fn route_sidecar_oauth_client_credentials_optional_scope() {
        // scope is optional — credential without it must still parse correctly.
        let config = make_config(
            "salesforce",
            CredentialConfig {
                description: "Salesforce".to_string(),
                api_base: Some("http://unused-sidecar:9999".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let bundle = serde_json::json!({
            "client_id": "sf-client",
            "client_secret": "sf-secret",
            "token_url": "https://login.salesforce.com/services/oauth2/token",
        })
        .to_string();
        let cred_values = make_cred_values("salesforce", &bundle);

        let route = resolve_unified_route(
            "salesforce",
            "https://myinstance.salesforce.com/services/data/v58.0/sobjects",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert!(route.oauth_client_credentials.is_some());
        let parsed = route.oauth_client_credentials.as_ref().unwrap();
        assert!(parsed.scope.is_none());
    }

    fn microsoft_sidecar_config(name: &str) -> AgentSecConfig {
        make_config(
            name,
            CredentialConfig {
                description: "Microsoft Graph".to_string(),
                api_base: Some("https://graph.microsoft.com".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: vec!["graph.microsoft.com".to_string()],
                end_user_id: None,
            },
        )
    }

    #[test]
    fn route_microsoft_oauth_bundle_routes_direct_and_defers_injection() {
        // A Microsoft refresh-token bundle (has token_url) must set microsoft_oauth,
        // route directly to Graph, and strip Authorization for the proxy to inject
        // after refresh. google_oauth must NOT be set (detection order matters).
        let config = microsoft_sidecar_config("outlook");
        let bundle = serde_json::json!({
            "client_id": "ci",
            "client_secret": "cs",
            "refresh_token": "rt",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "scopes": "https://graph.microsoft.com/Mail.Read"
        })
        .to_string();
        let cred_values = make_cred_values("outlook", &bundle);

        let route = resolve_unified_route(
            "outlook",
            "https://graph.microsoft.com/v1.0/me/messages",
            "GET",
            &[("Authorization".to_string(), "Bearer stale".to_string())],
            &config,
            &cred_values,
        )
        .unwrap();

        assert_eq!(
            route.effective_target,
            "https://graph.microsoft.com/v1.0/me/messages"
        );
        assert!(route.microsoft_oauth.is_some());
        assert!(route.google_oauth.is_none());
        assert!(route.twitter_oauth.is_none());
        assert!(route.oauth_client_credentials.is_none());
        // No Authorization yet — proxy injects it after the token refresh.
        assert!(!route
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("Authorization")));
        let parsed = route.microsoft_oauth.as_ref().unwrap();
        assert_eq!(parsed.client_id, "ci");
        assert!(parsed.token_url.contains("login.microsoftonline.com"));
    }

    #[test]
    fn route_microsoft_host_binding_blocks_offhost_target() {
        // allowed_hosts=graph.microsoft.com must block exfiltration to an attacker
        // host BEFORE any injection (Decision #17), same as any secret-bearing cred.
        let config = microsoft_sidecar_config("outlook");
        let bundle = serde_json::json!({
            "client_id": "ci", "client_secret": "cs", "refresh_token": "rt",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        })
        .to_string();
        let cred_values = make_cred_values("outlook", &bundle);

        let err = resolve_unified_route(
            "outlook",
            "https://attacker.example/steal",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap_err();
        assert!(matches!(err, RouteError::HostNotAllowed { .. }));
    }

    #[test]
    fn route_google_bundle_unaffected_by_microsoft_branch() {
        // A Google bundle (no token_url) must still route via google_oauth even
        // though the Microsoft check runs first.
        let config = make_config(
            "gmail",
            CredentialConfig {
                description: "Google".to_string(),
                api_base: Some("http://oauth2-refresher:8081".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let bundle = r#"{"client_id":"ci","client_secret":"cs","refresh_token":"rt"}"#;
        let cred_values = make_cred_values("gmail", bundle);

        let route = resolve_unified_route(
            "gmail",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert!(route.google_oauth.is_some());
        assert!(route.microsoft_oauth.is_none());
    }

    #[test]
    fn route_sidecar_without_oauth_bundle_still_uses_sidecar() {
        // Sanity check: sidecar credentials whose value is NOT an OAuth bundle
        // (e.g., a simple bearer token) still route through the configured
        // api_base. This ensures the OAuth detection doesn't over-match.
        let config = make_config(
            "custom-sidecar",
            CredentialConfig {
                description: "Custom sidecar".to_string(),
                api_base: Some("http://my-sidecar:9999".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let cred_values = make_cred_values("custom-sidecar", "plain-string-not-json");

        let route = resolve_unified_route(
            "custom-sidecar",
            "https://api.example.com/resource",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert_eq!(route.effective_target, "http://my-sidecar:9999");
        assert!(route.twitter_oauth.is_none());
        assert!(route.google_oauth.is_none());
    }

    #[test]
    fn route_unknown_credential_404() {
        let config = make_config(
            "slack",
            CredentialConfig {
                description: "Slack".to_string(),
                api_base: None,
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Direct,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );

        let result = resolve_unified_route(
            "nonexistent",
            "https://example.com",
            "GET",
            &[],
            &config,
            &HashMap::new(),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RouteError::CredentialNotFound(_)
        ));
    }

    #[test]
    fn route_direct_custom_header_bindings() {
        let config = make_config(
            "datadog-api",
            CredentialConfig {
                description: "Datadog API".to_string(),
                api_base: None,
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Direct,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: vec![tap_core::config::AuthBinding {
                    header: "DD-API-KEY".to_string(),
                    format: "{value}".to_string(),
                }],
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
        );
        let cred_values = make_cred_values("datadog-api", "dd-secret");

        let route = resolve_unified_route(
            "datadog-api",
            "https://api.datadoghq.com/api/v1/validate",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert!(route
            .headers
            .iter()
            .any(|(n, v)| n == "DD-API-KEY" && v == "dd-secret"));
        assert!(route.headers.iter().all(|(n, _)| n != "Authorization"));
    }

    #[test]
    fn route_telegram_sidecar_can_rewrite_to_embedded_loopback() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("TAP_EMBEDDED_TELEGRAM_BASE", "http://127.0.0.1:8082");

        let route = resolve_unified_route_with_config(
            "telegram",
            "/dialogs?limit=10",
            "GET",
            &[],
            &CredentialConfig {
                description: "Telegram".to_string(),
                api_base: Some("http://telegram-client:8082".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: true,
                auth_header_format: None,
                auth_bindings: Vec::new(),
                allowed_hosts: Vec::new(),
                end_user_id: None,
            },
            Some(r#"{"api_id":"123","api_hash":"abc","session_string":"session"}"#),
        )
        .unwrap();

        assert_eq!(
            route.effective_target,
            "http://127.0.0.1:8082/dialogs?limit=10"
        );
        std::env::remove_var("TAP_EMBEDDED_TELEGRAM_BASE");
    }

    // ---- allowed_hosts destination binding ------------------------------

    #[test]
    fn host_of_extracts_lowercased_host() {
        assert_eq!(
            host_of("https://API.Stripe.com/v1/charges").as_deref(),
            Some("api.stripe.com")
        );
        assert_eq!(
            host_of("http://example.com:8080/x").as_deref(),
            Some("example.com")
        );
        // Not an absolute URL with a host → None (caller fails closed).
        assert_eq!(host_of("/relative/path"), None);
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn host_is_allowed_exact_and_wildcard() {
        // Exact match only.
        assert!(host_is_allowed("api.stripe.com", "api.stripe.com"));
        assert!(!host_is_allowed("api.stripe.com", "evil.com"));
        // Case-insensitive pattern.
        assert!(host_is_allowed("API.Stripe.com", "api.stripe.com"));
        // Wildcard matches subdomains (any depth) and the bare apex.
        assert!(host_is_allowed("*.googleapis.com", "gmail.googleapis.com"));
        assert!(host_is_allowed("*.googleapis.com", "a.b.googleapis.com"));
        assert!(host_is_allowed("*.googleapis.com", "googleapis.com"));
        // Wildcard must respect the dot boundary — no suffix smuggling.
        assert!(!host_is_allowed("*.googleapis.com", "evilgoogleapis.com"));
        assert!(!host_is_allowed("*.stripe.com", "api.stripe.com.evil.com"));
    }

    fn cred_with_hosts(hosts: &[&str], relative_target: bool) -> CredentialConfig {
        CredentialConfig {
            description: "test".to_string(),
            api_base: Some("https://api.stripe.com".to_string()),
            substitution: SubstitutionConfig::default(),
            connector: ConnectorType::Direct,
            relative_target,
            auth_header_format: None,
            auth_bindings: Vec::new(),
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            end_user_id: None,
        }
    }

    #[test]
    fn direct_credential_to_unlisted_host_rejected() {
        let cred = cred_with_hosts(&["api.stripe.com"], false);
        let err = resolve_unified_route_with_config(
            "stripe",
            "https://evil.com/exfiltrate",
            "GET",
            &[],
            &cred,
            Some("sk-live-secret"),
        )
        .unwrap_err();
        match err {
            RouteError::HostNotAllowed { cred, host } => {
                assert_eq!(cred, "stripe");
                assert_eq!(host, "evil.com");
            }
            other => panic!("expected HostNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn direct_credential_to_listed_host_allowed() {
        let cred = cred_with_hosts(&["api.stripe.com", "*.googleapis.com"], false);
        // Exact listed host.
        let route = resolve_unified_route_with_config(
            "stripe",
            "https://api.stripe.com/v1/charges",
            "GET",
            &[],
            &cred,
            Some("sk-live-secret"),
        )
        .unwrap();
        assert!(route
            .headers
            .iter()
            .any(|(n, v)| n == "Authorization" && v == "Bearer sk-live-secret"));
        // Wildcard subdomain.
        assert!(resolve_unified_route_with_config(
            "stripe",
            "https://gmail.googleapis.com/v1/x",
            "GET",
            &[],
            &cred,
            Some("sk-live-secret"),
        )
        .is_ok());
    }

    #[test]
    fn empty_allowed_hosts_permits_any_host() {
        // Backward compat: no binding ⇒ unrestricted (warn-only at the proxy).
        let cred = cred_with_hosts(&[], false);
        assert!(resolve_unified_route_with_config(
            "stripe",
            "https://anywhere.example/x",
            "GET",
            &[],
            &cred,
            Some("sk-live-secret"),
        )
        .is_ok());
    }

    #[test]
    fn relative_target_sidecar_skips_host_check() {
        // relative_target destinations are pinned to api_base, so the path-style
        // target must not be run through the host allowlist (it has no host).
        let cred = cred_with_hosts(&["api.stripe.com"], true);
        // Even with a bogus path, the host check is skipped (sidecar routing
        // then handles it). Use a sidecar connector to exercise the path.
        let mut cred = cred;
        cred.connector = ConnectorType::Sidecar;
        cred.api_base = Some("https://api.stripe.com".to_string());
        let res = resolve_unified_route_with_config(
            "stripe",
            "/v1/charges",
            "GET",
            &[],
            &cred,
            Some("plain-secret"),
        );
        assert!(res.is_ok());
    }
}
