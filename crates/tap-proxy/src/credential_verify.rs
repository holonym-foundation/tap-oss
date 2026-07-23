//! Live credential verification for the dashboard .env importer (and anywhere
//! else a "does this key actually authenticate?" answer is worth one request).
//!
//! `POST /team/credentials/{name}/verify` (workspace-manager session) fires a
//! single idempotent probe request through the SAME inject-and-forward path a
//! real `/forward` uses (`routing::resolve_unified_route_with_config` +
//! `forward::forward_request`), so it exercises the credential's actual auth
//! shape (default Bearer, `auth_header_format`, `auth_bindings`) and host
//! binding — the two things an import can get silently wrong.
//!
//! Safety model:
//! - **The probe target is server-chosen, never client-supplied**, and always
//!   within the credential's own `allowed_hosts` — verify can never be steered
//!   to send a secret anywhere the credential isn't already bound to.
//! - The response is **status-only** (`{status, http_status?, probe_url}`);
//!   the upstream body is never returned (it is parsed server-side only for
//!   the rare `okJsonField` vendors like Slack that answer HTTP 200 either way).
//! - Probes are curated in `credentials-catalog.json` (shared verbatim with
//!   the dashboard importer, like `recipes.json`). A credential with no
//!   catalog probe gets a **generic** `GET https://{host}/` fallback, which is
//!   asymmetric on purpose: a 401/403 is a definitive `auth_rejected`, but a
//!   2xx is only `inconclusive` — an unauthenticated marketing page also
//!   answers 200, so the generic probe can prove failure, never success.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::LazyLock;
use std::time::Duration;
use tap_core::config::ConnectorType;
use tracing::info;

use crate::proxy::AppState;

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

// ── Catalog (shared with the dashboard importer) ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProbe {
    pub host: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default = "default_ok")]
    pub ok: Vec<u16>,
    /// For APIs that answer 200 with `{"ok": false}` on bad auth (Slack): the
    /// JSON field that must be truthy for the probe to count as verified.
    #[serde(default)]
    pub ok_json_field: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}
fn default_ok() -> Vec<u16> {
    vec![200]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogAuth {
    pub scheme: String,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// One vendor entry. Recognition fields (`keys`, `value`, `required`) are
/// dashboard concerns and deliberately not deserialized here — the JS side
/// compiles those patterns; the proxy only needs hosts, auth shape (for the
/// contract test) and the verify probe.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogVendor {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub auth: Option<CatalogAuth>,
    #[serde(default)]
    pub verify: Option<VerifyProbe>,
}

#[derive(Deserialize)]
struct Catalog {
    vendors: Vec<CatalogVendor>,
}

/// Parsed once at first use. A malformed catalog is a build artifact bug, not
/// a runtime condition — panicking on first access surfaces it in tests/CI
/// (see `catalog_contract`) long before it could ship.
static CATALOG: LazyLock<Vec<CatalogVendor>> = LazyLock::new(|| {
    let raw = include_str!("../credentials-catalog.json");
    serde_json::from_str::<Catalog>(raw)
        .expect("credentials-catalog.json must parse — validated by the catalog_contract test")
        .vendors
});

pub fn catalog() -> &'static [CatalogVendor] {
    &CATALOG
}

// ── Probe selection ──

enum Probe {
    Curated(&'static VerifyProbe),
    Generic { host: String },
}

/// Server-side probe pick: a curated catalog probe whose host the credential
/// is already bound to, else a generic root GET against the credential's
/// first concrete (non-wildcard) allowed host. `None` when the credential has
/// no concrete bound host to safely aim at — including the unbound
/// (`allowed_hosts` empty) case, where ANY target would be "allowed" but none
/// is known to be the right one.
fn pick_probe(allowed_hosts: &[String]) -> Option<Probe> {
    for vendor in catalog() {
        if let Some(probe) = &vendor.verify {
            if allowed_hosts
                .iter()
                .any(|pattern| crate::routing::host_is_allowed(pattern, &probe.host))
            {
                return Some(Probe::Curated(probe));
            }
        }
    }
    allowed_hosts
        .iter()
        .find(|h| !h.trim().starts_with("*."))
        .map(|h| Probe::Generic {
            host: h.trim().to_ascii_lowercase(),
        })
}

fn status_only(status: &str, http_status: Option<u16>, probe_url: Option<&str>, detail: Option<String>) -> Response {
    let mut body = json!({ "status": status });
    if let Some(s) = http_status {
        body["http_status"] = json!(s);
    }
    if let Some(u) = probe_url {
        body["probe_url"] = json!(u);
    }
    if let Some(d) = detail {
        body["detail"] = json!(d);
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// Verdict of one probe execution. Deliberately carries NO body and no
/// upstream headers — whatever the vendor answered stays server-side.
struct ProbeOutcome {
    status: &'static str,
    http_status: Option<u16>,
}

/// Inject-and-fire one probe through the same path `/forward` uses, and map
/// the result to a verdict. `curated` probes can positively verify (their
/// expected statuses are vendor-specific facts); generic probes are
/// fail-only — 401/403 is definitive rejection, anything else is
/// `inconclusive` because an unauthenticated page can answer 2xx too.
#[allow(clippy::too_many_arguments)]
async fn execute_probe(
    cred_name: &str,
    cred_config: &tap_core::config::CredentialConfig,
    cred_value: &str,
    probe_url: &str,
    method: &str,
    extra_headers: &[(String, String)],
    body: Option<&[u8]>,
    ok_statuses: &[u16],
    ok_json_field: Option<&str>,
    curated: bool,
) -> ProbeOutcome {
    let route = match crate::routing::resolve_unified_route_with_config(
        cred_name,
        probe_url,
        method,
        extra_headers,
        cred_config,
        Some(cred_value),
    ) {
        Ok(route) => route,
        Err(_) => {
            // e.g. multi_secret_unbound / credential_field_missing — the
            // credential's wiring is broken; surface that as the verdict.
            return ProbeOutcome {
                status: "config_error",
                http_status: None,
            };
        }
    };

    let result = match crate::forward::forward_request(
        &route.effective_target,
        method,
        &route.headers,
        body,
        PROBE_TIMEOUT,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            info!("credential verify: probe to {probe_url} failed: {e}");
            return ProbeOutcome {
                status: "upstream_error",
                http_status: None,
            };
        }
    };

    let http_status = result.status;
    let status = if curated {
        if ok_statuses.contains(&http_status) {
            match ok_json_field {
                // Body parsed server-side ONLY — never returned.
                Some(field) => match serde_json::from_slice::<serde_json::Value>(&result.body) {
                    Ok(parsed) if parsed.get(field).and_then(|v| v.as_bool()) == Some(true) => "ok",
                    _ => "auth_rejected",
                },
                None => "ok",
            }
        } else if http_status == 401 || http_status == 403 {
            "auth_rejected"
        } else {
            "inconclusive"
        }
    } else if http_status == 401 || http_status == 403 {
        "auth_rejected"
    } else {
        "inconclusive"
    };

    ProbeOutcome {
        status,
        http_status: Some(http_status),
    }
}

/// POST /team/credentials/{name}/verify (workspace-manager session auth).
pub async fn handle_verify_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let admin = match crate::admin::authenticate_user(&headers, &state.db_state).await {
        Ok(user) => user,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = crate::admin::require_workspace_manager(&admin, "verify credentials") {
        return resp;
    }

    let store = state.db_state.store();
    let row = match store.get_credential(&admin.team_id, &name).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Credential not found"})),
            )
                .into_response()
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    let cred_config = crate::db_state::row_to_credential_config(&row);

    // Only direct credentials are verifiable this way: sidecars (OAuth
    // bundles, SigV4, protocol translators) have their own refresh/signing
    // flows that a bare probe wouldn't exercise faithfully.
    if !matches!(cred_config.connector, ConnectorType::Direct) {
        return status_only("unsupported", None, None, Some("only direct credentials can be probe-verified".into()));
    }

    let value_bytes = match store.get_credential_value(&admin.team_id, &name).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return status_only("no_value", None, None, Some("credential has no stored secret".into()))
        }
        Err(e) => return crate::proxy::error_response(e),
    };
    let Ok(cred_value) = String::from_utf8(value_bytes) else {
        return status_only("unsupported", None, None, Some("stored value is not UTF-8".into()));
    };

    let Some(probe) = pick_probe(&cred_config.allowed_hosts) else {
        return status_only(
            "no_probe",
            None,
            None,
            Some("no concrete allowed host to probe — verify with a real request".into()),
        );
    };

    let (probe_url, method, extra_headers, body, ok_statuses, ok_json_field) = match &probe {
        Probe::Curated(p) => {
            let mut hdrs: Vec<(String, String)> = p
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if let Some(ct) = &p.content_type {
                hdrs.push(("Content-Type".to_string(), ct.clone()));
            }
            (
                format!("https://{}{}", p.host, p.path),
                p.method.as_str(),
                hdrs,
                p.body.as_ref().map(|b| b.as_bytes().to_vec()),
                p.ok.clone(),
                p.ok_json_field.clone(),
            )
        }
        Probe::Generic { host } => (
            format!("https://{host}/"),
            "GET",
            Vec::new(),
            None,
            Vec::new(),
            None,
        ),
    };

    // Same SSRF guard as an agent-supplied target — a curated probe host is
    // trusted data, but defense-in-depth is cheap here.
    if let Err(e) = crate::forward::validate_public_target(&probe_url).await {
        return status_only("no_probe", None, Some(&probe_url), Some(e.to_string()));
    }

    let outcome = execute_probe(
        &name,
        &cred_config,
        &cred_value,
        &probe_url,
        method,
        &extra_headers,
        body.as_deref(),
        &ok_statuses,
        ok_json_field.as_deref(),
        matches!(probe, Probe::Curated(_)),
    )
    .await;

    info!(
        "credential verify: {} → {} verdict {} (http {:?})",
        name, probe_url, outcome.status, outcome.http_status
    );
    status_only(outcome.status, outcome.http_status, Some(&probe_url), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust half of the shared-catalog contract (the JS half lives in
    /// dashboard/src/lib/envImport.test.js): every probe must target a
    /// concrete host the vendor's imports are bound to, with a sane method
    /// and success statuses, and every auth shape must be one the importer
    /// knows how to wire.
    #[test]
    fn catalog_contract() {
        let vendors = catalog();
        assert!(vendors.len() >= 27, "catalog unexpectedly small");
        let mut ids = std::collections::HashSet::new();
        for v in vendors {
            assert!(ids.insert(v.id.as_str()), "duplicate vendor id {}", v.id);
            assert!(!v.label.is_empty(), "{}: empty label", v.id);
            assert!(!v.hosts.is_empty(), "{}: no hosts", v.id);
            if let Some(auth) = &v.auth {
                match auth.scheme.as_str() {
                    "bearer" | "basic" | "aws" | "manual" => {}
                    "header" => {
                        let header = auth.header.as_deref().unwrap_or("");
                        assert!(
                            !header.is_empty()
                                && header
                                    .chars()
                                    .all(|c| c.is_ascii_alphanumeric() || c == '-'),
                            "{}: bad header name {header:?}",
                            v.id
                        );
                    }
                    "raw" => {
                        if let Some(fmt) = &auth.format {
                            assert!(fmt.contains("{value}"), "{}: raw format without {{value}}", v.id);
                        }
                    }
                    other => panic!("{}: unknown auth scheme {other}", v.id),
                }
                if auth.scheme == "manual" {
                    assert!(
                        auth.reason.as_deref().is_some_and(|r| r.len() > 10),
                        "{}: manual entries need a user-facing reason",
                        v.id
                    );
                }
            }
            if let Some(probe) = &v.verify {
                assert!(
                    v.hosts.iter().any(|h| h == &probe.host),
                    "{}: verify.host {} must be listed verbatim in hosts",
                    v.id,
                    probe.host
                );
                assert!(
                    !probe.host.starts_with("*."),
                    "{}: verify.host must be concrete",
                    v.id
                );
                assert!(probe.path.starts_with('/'), "{}: verify.path", v.id);
                assert!(
                    matches!(probe.method.as_str(), "GET" | "POST" | "HEAD"),
                    "{}: verify.method {}",
                    v.id,
                    probe.method
                );
                assert!(
                    !probe.ok.is_empty() && probe.ok.iter().all(|s| (200..400).contains(s)),
                    "{}: verify.ok",
                    v.id
                );
                // Probes run through the credential's own host binding, so a
                // probe host that isn't allowed would 403 before sending.
                assert!(
                    v.hosts
                        .iter()
                        .any(|p| crate::routing::host_is_allowed(p, &probe.host)),
                    "{}: probe host not covered by allowed_hosts patterns",
                    v.id
                );
            }
        }
    }

    fn direct_config(
        auth_header_format: Option<&str>,
        auth_bindings: Vec<tap_core::config::AuthBinding>,
        allowed_hosts: Vec<String>,
    ) -> tap_core::config::CredentialConfig {
        tap_core::config::CredentialConfig {
            description: "test".to_string(),
            api_base: None,
            substitution: Default::default(),
            connector: ConnectorType::Direct,
            relative_target: false,
            auth_header_format: auth_header_format.map(|s| s.to_string()),
            auth_bindings,
            end_user_id: None,
            allowed_hosts,
        }
    }

    /// Mock vendor covering the probe shapes: a models endpoint gating on an
    /// x-api-key header, a Slack-style endpoint that answers 200 either way
    /// and signals in the body, and a marketing-ish root that is 200 for
    /// everyone (the generic-probe false-positive trap).
    async fn start_mock_vendor() -> String {
        use axum::routing::{get, post};
        let app = axum::Router::new()
            .route(
                "/v1/models",
                get(|headers: axum::http::HeaderMap| async move {
                    if headers.get("x-api-key").is_some_and(|v| v == "sekret-value") {
                        (StatusCode::OK, r#"{"data":[]}"#)
                    } else {
                        (StatusCode::UNAUTHORIZED, r#"{"error":"invalid api key"}"#)
                    }
                }),
            )
            .route(
                "/api/auth.test",
                post(|headers: axum::http::HeaderMap| async move {
                    let good = headers
                        .get("authorization")
                        .is_some_and(|v| v == "Bearer xoxb-good");
                    (
                        StatusCode::OK,
                        if good {
                            r#"{"ok":true}"#
                        } else {
                            r#"{"ok":false,"error":"invalid_auth"}"#
                        },
                    )
                }),
            )
            .route("/", get(|| async { (StatusCode::OK, "<html>welcome</html>") }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        url
    }

    #[tokio::test]
    async fn curated_probe_exercises_real_auth_bindings() {
        let base = start_mock_vendor().await;
        let config = direct_config(
            None,
            vec![tap_core::config::AuthBinding {
                header: "x-api-key".to_string(),
                format: "{value}".to_string(),
            }],
            vec!["127.0.0.1".to_string()],
        );

        // Right key, injected into the bound header → verified.
        let outcome = execute_probe(
            "anthro",
            &config,
            "sekret-value",
            &format!("{base}/v1/models"),
            "GET",
            &[],
            None,
            &[200],
            None,
            true,
        )
        .await;
        assert_eq!(outcome.status, "ok");
        assert_eq!(outcome.http_status, Some(200));

        // Wrong key → the vendor's 401 becomes a definitive auth_rejected.
        let outcome = execute_probe(
            "anthro",
            &config,
            "wrong-value",
            &format!("{base}/v1/models"),
            "GET",
            &[],
            None,
            &[200],
            None,
            true,
        )
        .await;
        assert_eq!(outcome.status, "auth_rejected");
        assert_eq!(outcome.http_status, Some(401));
    }

    #[tokio::test]
    async fn ok_json_field_catches_http_200_failures() {
        let base = start_mock_vendor().await;
        let config = direct_config(None, vec![], vec!["127.0.0.1".to_string()]);

        // Slack-style: HTTP 200 + {"ok":false} must NOT count as verified.
        let outcome = execute_probe(
            "slack",
            &config,
            "xoxb-bad",
            &format!("{base}/api/auth.test"),
            "POST",
            &[],
            None,
            &[200],
            Some("ok"),
            true,
        )
        .await;
        assert_eq!(outcome.status, "auth_rejected");

        let outcome = execute_probe(
            "slack",
            &config,
            "xoxb-good",
            &format!("{base}/api/auth.test"),
            "POST",
            &[],
            None,
            &[200],
            Some("ok"),
            true,
        )
        .await;
        assert_eq!(outcome.status, "ok");
    }

    #[tokio::test]
    async fn generic_probe_never_claims_success() {
        let base = start_mock_vendor().await;
        let config = direct_config(None, vec![], vec!["127.0.0.1".to_string()]);

        // A 200 from an unauthenticated-anyway page is only inconclusive.
        let outcome = execute_probe(
            "unknown",
            &config,
            "whatever-value",
            &format!("{base}/"),
            "GET",
            &[],
            None,
            &[],
            None,
            false,
        )
        .await;
        assert_eq!(outcome.status, "inconclusive");
        assert_eq!(outcome.http_status, Some(200));

        // But a 401 is a definitive rejection even without a curated probe.
        let outcome = execute_probe(
            "unknown",
            &config,
            "wrong-value",
            &format!("{base}/v1/models"),
            "GET",
            &[],
            None,
            &[],
            None,
            false,
        )
        .await;
        assert_eq!(outcome.status, "auth_rejected");
    }

    #[tokio::test]
    async fn broken_wiring_and_dead_upstream_map_to_verdicts() {
        let config = direct_config(
            None,
            vec![tap_core::config::AuthBinding {
                header: "X-Key".to_string(),
                format: "{value.api_key}".to_string(),
            }],
            vec!["127.0.0.1".to_string()],
        );
        // Binding references a field the (string) value doesn't have.
        let outcome = execute_probe(
            "broken",
            &config,
            "plain-string-value",
            "http://127.0.0.1:1/v1",
            "GET",
            &[],
            None,
            &[200],
            None,
            true,
        )
        .await;
        assert_eq!(outcome.status, "config_error");

        // Nothing listening → upstream_error, not a panic and not a verdict.
        let config = direct_config(None, vec![], vec!["127.0.0.1".to_string()]);
        let outcome = execute_probe(
            "dead",
            &config,
            "value",
            "http://127.0.0.1:1/",
            "GET",
            &[],
            None,
            &[200],
            None,
            true,
        )
        .await;
        assert_eq!(outcome.status, "upstream_error");
    }

    #[test]
    fn probe_pick_prefers_curated_and_skips_wildcards() {
        // Anthropic-bound credential → curated /v1/models probe.
        let hosts = vec!["api.anthropic.com".to_string()];
        match pick_probe(&hosts) {
            Some(Probe::Curated(p)) => assert_eq!(p.host, "api.anthropic.com"),
            _ => panic!("expected curated probe"),
        }
        // Unknown host → generic probe against that host.
        let hosts = vec!["api.unknown-vendor.example".to_string()];
        match pick_probe(&hosts) {
            Some(Probe::Generic { host }) => assert_eq!(host, "api.unknown-vendor.example"),
            _ => panic!("expected generic probe"),
        }
        // Wildcard-only binding → nothing concrete to aim at.
        assert!(pick_probe(&["*.amazonaws.com".to_string()]).is_none());
        // Unbound credential → refuse to pick any target.
        assert!(pick_probe(&[]).is_none());
    }
}
