//! LLM-assisted credential hints for the dashboard .env importer.
//!
//! `POST /team/credential-hints` takes a batch of environment-variable NAMES
//! (never values — enforced by a strict name-shape validator) and asks Claude
//! which API service each belongs to and which upstream host(s) the secret is
//! sent to. The suggestions prefill the importer's `allowed_hosts` field.
//!
//! Safety model: a wrong host guess FAILS CLOSED. `allowed_hosts` is an
//! exfiltration allowlist, so a hallucinated host can only make the credential
//! unusable (403 until the user edits the binding) — it can never cause the
//! secret to be sent somewhere unintended. The user still reviews and confirms
//! every suggestion in the modal.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tap_core::http_client::{build_client, ClientRoute};
use tracing::warn;

use crate::proxy::AppState;

const CLAUDE_API_URL: &str = "https://api.anthropic.com/v1/messages";
// Trivial name→service lookup: the small/fast tier is the right fit.
const CLAUDE_MODEL: &str = "claude-haiku-4-5-20251001";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_KEYS: usize = 30;
const MAX_KEY_LEN: usize = 64;

const HINT_SYSTEM_PROMPT: &str = r#"You identify third-party API services from environment variable names.

Input: a JSON array of environment variable names (names only, no values).
Output: STRICT JSON, no commentary, no code fences — an array of objects:
  [{"key": "<input name>", "service": "<human service name>", "hosts": ["<bare hostname>", ...], "auth": {"scheme": "bearer" | "header" | "raw", "header": "<exact header name>"}}]

Rules:
- Only include entries where you are confident which service the variable belongs to. Omit ambiguous or internal-looking names entirely.
- "hosts" are the API hostnames the secret is sent to as a request credential — bare hostnames only, no scheme, path, or port. A leading wildcard like "*.example.com" is allowed when the service uses per-account subdomains.
- Prefer the primary API host over marketing or dashboard domains.
- "auth" describes how the service expects the secret on a request: "bearer" for `Authorization: Bearer <key>`, "header" with the exact custom header name (e.g. "DD-API-KEY", "x-api-key"), "raw" when the key is the whole Authorization value with no prefix. Include "header" only for the "header" scheme. OMIT the "auth" field entirely unless you are confident — a wrong guess is worse than none.
- Never invent a service for a generic name like MY_API_KEY or INTERNAL_TOKEN.
- Output [] if nothing is confidently identifiable."#;

#[derive(Deserialize)]
pub struct HintRequest {
    pub keys: Vec<String>,
}

/// How the suggested service expects the secret on a request. Suggestions are
/// prefilled-but-flagged in the importer and confirmed by the verify probe —
/// a wrong scheme can only produce a 401 at the user-approved host, never a
/// leak (allowed_hosts still gates the destination).
#[derive(Serialize, Deserialize, Clone)]
pub struct HintAuth {
    /// "bearer" | "header" | "raw"
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialHint {
    pub key: String,
    pub service: String,
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<HintAuth>,
}

/// Env-var-name shape gate. This is the guard that keeps secrets out of the
/// LLM call: only conventional UPPER_SNAKE names pass. That rejects every
/// common token format — `sk-…` (dash), JWTs (dots), base64 (`+/=`), and
/// lowercase-prefixed tokens like `ghp_…`/`gsk_…` — so a value pasted where a
/// name belongs cannot be forwarded to the model.
fn is_env_var_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_KEY_LEN
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && !s.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// POST /team/credential-hints (session auth).
pub async fn handle_credential_hints(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<HintRequest>,
) -> Response {
    if let Err(resp) = crate::admin::authenticate_user(&headers, &state.db_state).await {
        return resp.into_response();
    }

    if req.keys.is_empty() || req.keys.len() > MAX_KEYS {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_keys",
                "message": format!("Provide between 1 and {MAX_KEYS} environment variable names."),
            })),
        )
            .into_response();
    }
    for key in &req.keys {
        if !is_env_var_name(key) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_keys",
                    "message": "Only environment variable NAMES are accepted (letters, digits, underscores). Never send values.",
                })),
            )
                .into_response();
        }
    }

    // Optional feature: no Claude key configured (typical for self-hosted) →
    // report unavailable, the importer keeps its manual host field.
    let api_key = match crate::key_provider::load_optional_secret(
        "CLAUDE_API_KEY",
        "claude_api_key_ciphertext",
    )
    .await
    {
        Ok(Some(k)) if !k.is_empty() => k,
        _ => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "available": false, "hints": [] })),
            )
                .into_response();
        }
    };

    let hints = fetch_hints(&api_key, &req.keys).await;
    match hints {
        Some(hints) => {
            // Belt and suspenders: only return hints for keys that were asked
            // about, with syntactically valid hosts.
            let asked: std::collections::HashSet<&str> =
                req.keys.iter().map(String::as_str).collect();
            let hints: Vec<CredentialHint> = hints
                .into_iter()
                .filter(|h| asked.contains(h.key.as_str()))
                .map(|mut h| {
                    h.hosts.retain(|host| is_plausible_host(host));
                    // Auth suggestions pass a strict shape gate or are dropped
                    // entirely — the importer treats a missing auth as the
                    // Bearer default, so dropping is always safe.
                    if let Some(auth) = &h.auth {
                        if !is_plausible_auth(auth) {
                            h.auth = None;
                        }
                    }
                    h
                })
                .filter(|h| !h.hosts.is_empty())
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "available": true, "hints": hints })),
            )
                .into_response()
        }
        None => (
            StatusCode::OK,
            Json(serde_json::json!({ "available": false, "hints": [] })),
        )
            .into_response(),
    }
}

/// Auth-suggestion shape gate: known scheme, and a syntactically valid header
/// name if (and only if) the scheme needs one.
fn is_plausible_auth(auth: &HintAuth) -> bool {
    match auth.scheme.as_str() {
        "bearer" | "raw" => true,
        "header" => auth.header.as_deref().is_some_and(|h| {
            !h.is_empty()
                && h.len() <= 64
                && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        }),
        _ => false,
    }
}

/// Same shape rules the create API enforces for allowed_hosts: bare host,
/// optional leading `*.` wildcard, no scheme/path/port/spaces.
fn is_plausible_host(host: &str) -> bool {
    let bare = host.strip_prefix("*.").unwrap_or(host);
    !bare.is_empty()
        && bare.len() <= 253
        && bare.contains('.')
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !bare.starts_with('.')
        && !bare.ends_with('.')
}

async fn fetch_hints(api_key: &str, keys: &[String]) -> Option<Vec<CredentialHint>> {
    let client = match build_client(ClientRoute::EgressProxy) {
        Ok(c) => c,
        Err(e) => {
            warn!("credential hints: failed to create HTTP client: {e}");
            return None;
        }
    };
    let body = serde_json::json!({
        "model": CLAUDE_MODEL,
        "max_tokens": 1024,
        "system": HINT_SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": serde_json::to_string(keys).ok()?,
        }],
    });
    let resp = client
        .post(CLAUDE_API_URL)
        .header("x-api-key", api_key)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header("content-type", "application/json")
        .json(&body)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await;
    let resp = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            warn!("credential hints: Claude API returned {}", r.status());
            return None;
        }
        Err(e) => {
            warn!("credential hints: Claude API request failed: {e}");
            return None;
        }
    };
    let json: serde_json::Value = resp.json().await.ok()?;
    let text = json
        .get("content")?
        .as_array()?
        .iter()
        .find_map(|b| b.get("text").and_then(|t| t.as_str()))?;
    parse_hints_json(text)
}

/// Parse the model's output, tolerating stray code fences.
fn parse_hints_json(text: &str) -> Option<Vec<CredentialHint>> {
    let trimmed = text
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    serde_json::from_str(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_name_gate_accepts_names_rejects_values() {
        assert!(is_env_var_name("OPENAI_API_KEY"));
        assert!(is_env_var_name("POSTHOG_KEY_2"));
        // Lowercase is rejected wholesale — the cost is skipping hints for
        // unconventional lowercase env names, the benefit is that lowercase
        // token formats (ghp_…, gsk_…, xoxb…) can never reach the model.
        assert!(!is_env_var_name("posthog_key_2"));
        // Values (and anything value-shaped) must never reach the LLM call.
        assert!(!is_env_var_name("sk-proj-abc123"));
        assert!(!is_env_var_name("FOO=bar"));
        assert!(!is_env_var_name("ghp_16chartoken1234567890"));
        assert!(!is_env_var_name(""));
        assert!(!is_env_var_name("9STARTS_WITH_DIGIT"));
        assert!(!is_env_var_name(&"A".repeat(65)));
        assert!(!is_env_var_name("has space"));
        assert!(!is_env_var_name("dot.ted"));
    }

    #[test]
    fn plausible_host_filter() {
        assert!(is_plausible_host("api.posthog.com"));
        assert!(is_plausible_host("*.amazonaws.com"));
        assert!(!is_plausible_host("https://api.posthog.com"));
        assert!(!is_plausible_host("api.posthog.com/v1"));
        assert!(!is_plausible_host("localhost"));
        assert!(!is_plausible_host(""));
        assert!(!is_plausible_host(".posthog.com"));
    }

    #[test]
    fn auth_suggestion_gate() {
        let ok = |scheme: &str, header: Option<&str>| {
            is_plausible_auth(&HintAuth {
                scheme: scheme.to_string(),
                header: header.map(String::from),
            })
        };
        assert!(ok("bearer", None));
        assert!(ok("raw", None));
        assert!(ok("header", Some("DD-API-KEY")));
        assert!(ok("header", Some("x-api-key")));
        // Header scheme without a name, bad charset, or unknown scheme → dropped.
        assert!(!ok("header", None));
        assert!(!ok("header", Some("bad header")));
        assert!(!ok("header", Some("")));
        assert!(!ok("basic", None));
        assert!(!ok("query", Some("api_key")));
    }

    #[test]
    fn hint_auth_deserializes_and_reserializes() {
        let fenced = r#"[{"key":"DATADOG_API_KEY","service":"Datadog","hosts":["api.datadoghq.com"],"auth":{"scheme":"header","header":"DD-API-KEY"}},{"key":"FOO_TOKEN","service":"Foo","hosts":["api.foo.com"]}]"#;
        let hints = parse_hints_json(fenced).unwrap();
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].auth.as_ref().unwrap().header.as_deref(), Some("DD-API-KEY"));
        assert!(hints[1].auth.is_none());
        // Absent auth stays absent on the wire (skip_serializing_if).
        let out = serde_json::to_string(&hints[1]).unwrap();
        assert!(!out.contains("auth"));
    }

    #[test]
    fn parse_hints_tolerates_code_fences() {
        let fenced = "```json\n[{\"key\":\"POSTHOG_API_KEY\",\"service\":\"PostHog\",\"hosts\":[\"us.i.posthog.com\"]}]\n```";
        let hints = parse_hints_json(fenced).unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].service, "PostHog");
        assert!(parse_hints_json("not json").is_none());
        assert_eq!(parse_hints_json("[]").unwrap().len(), 0);
    }
}
