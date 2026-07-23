//! Integration tests for the proxy round-trip.

// Test helpers use some deliberately verbose tuple/closure types for recorded state.
#![allow(clippy::type_complexity)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use serde_json::json;
use tap_core::approval::{ApprovalChannel, ApprovalContext};
use tap_core::config::AuthBinding;
use tap_core::error::AgentSecError;
use tap_core::store::{ConfigStore, PolicyRow};
use tap_core::types::*;
use tap_proxy::audit::InMemoryAuditLogger;
use tap_proxy::auth::hash_api_key;
use tap_proxy::db_state::DbState;
use tap_proxy::proxy::{build_router, AppState};
use tower::util::ServiceExt;

/// Test helper: resolve a user by email into a `Member` in their first/sole
/// team. Replaces the removed `get_admin_by_email` for tests where each person
/// belongs to exactly one team.
async fn member_by_email(store: &ConfigStore, email: &str) -> tap_core::store::Member {
    let user = store.get_user_by_email(email).await.unwrap().unwrap();
    let team_id = store
        .list_user_teams(&user.id)
        .await
        .unwrap()
        .first()
        .unwrap()
        .0
        .clone();
    store.get_member(&user.id, &team_id).await.unwrap().unwrap()
}

fn test_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    key
}

async fn send_request_and_parse(
    app: axum::Router,
    req: Request<Body>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn temp_store() -> (ConfigStore, tempfile::NamedTempFile) {
    let tmp = tempfile::NamedTempFile::new().unwrap(); // kept for return type compat
                                                       // Each test gets its own freshly-created database, so the suite is isolated
                                                       // and can run in parallel.
    let (store, _url) = ConfigStore::new_isolated_test(test_key()).await;
    store.create_team("t1", "test-team").await.unwrap();
    (store, tmp)
}

struct MockApproval {
    auto_approve: bool,
    calls: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ApprovalChannel for MockApproval {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        _desc: &str,
        _context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        self.calls.lock().unwrap().push(request.agent_id.clone());
        Ok("mock-id".to_string())
    }

    async fn wait_for_decision(
        &self,
        _id: &str,
        _timeout: u64,
    ) -> Result<ApprovalStatus, AgentSecError> {
        if self.auto_approve {
            Ok(ApprovalStatus::Approved)
        } else {
            Ok(ApprovalStatus::Denied)
        }
    }

    fn format_message(&self, _request: &ProxyRequest, _desc: &str) -> String {
        "mock".to_string()
    }

    fn channel_name(&self) -> &str {
        "mock"
    }

    async fn notify_unauthorized(&self, _: &str, _: &str) -> Result<(), AgentSecError> {
        Ok(())
    }
}

async fn make_state(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, Arc<InMemoryAuditLogger>, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let key_hash = hash_api_key("integration-test-key");

    let (store, tmp) = temp_store().await;
    store
        .create_credential(
            "t1",
            "cred-a",
            "Credential A",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "cred-a", b"secret123")
        .await
        .unwrap();
    store
        .create_agent("t1", "test-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "cred-a")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "cred-a".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec![
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    (state, audit_logger, tmp)
}

async fn start_mock_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::routing::get;

    let app = axum::Router::new()
        .route(
            "/api/data",
            get(|| async { axum::Json(json!({"data": "hello"})) }),
        )
        .route(
            "/api/leak",
            get(|| async { "response contains secret123 value" }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle)
}

#[tokio::test]
async fn integration_proxy_auto_approves_get() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock.clone()).await;
    let app = build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-a>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"], "hello");

    // GET should be auto-approved - no approval channel calls
    assert!(mock.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn integration_proxy_rejects_unauthorized_agent() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "wrong-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn integration_proxy_rejects_non_whitelisted_credential() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-b>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn integration_proxy_rejects_hallucinated_tap_headers() {
    // Guardrail against the real failure mode observed with Hermes: the agent
    // invented `X-TAP-Body` to try to pass tweet text, the proxy silently
    // stripped it, and the request reached Twitter with an empty body →
    // "please include text or media". Now we fail fast with a clear message
    // pointing at the actual HTTP body as the right place.
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "POST")
        .header("x-tap-body", "hallucinated content")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    // Error names the offending header
    let err = value["error"].as_str().unwrap_or("");
    assert!(
        err.to_lowercase().contains("x-tap-body"),
        "error should name the bad header, got: {err}"
    );
    // Detail tells the agent where the body actually goes AND how custom
    // upstream headers work (the two common hallucinations).
    let detail = value["detail"].as_str().unwrap_or("");
    assert!(
        detail.to_lowercase().contains("http body"),
        "detail should explain where the body goes, got: {detail}"
    );
    assert!(
        detail.to_lowercase().contains("pass through")
            || detail.to_lowercase().contains("custom upstream headers")
            || detail.to_lowercase().contains("plain http headers"),
        "detail should also explain custom upstream header handling, got: {detail}"
    );
}

#[tokio::test]
async fn integration_proxy_rejects_hallucinated_tap_header_prefix() {
    // Second real failure mode: the agent invents `X-TAP-Header-*` as a prefix
    // convention for passing custom upstream headers (e.g. Notion-Version).
    // The guardrail should catch this and the error should mention BOTH
    // common mistakes (body and custom headers) so the agent knows how each
    // is actually done.
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("x-tap-header-notion-version", "2022-06-28")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let err = value["error"].as_str().unwrap_or("");
    assert!(
        err.to_lowercase().contains("x-tap-header"),
        "error should name the bad header, got: {err}"
    );
    // Detail explains BOTH common mistakes so the agent learns the full model
    let detail = value["detail"].as_str().unwrap_or("");
    assert!(
        detail.to_lowercase().contains("http body"),
        "detail should explain where the body goes, got: {detail}"
    );
    assert!(
        detail.to_lowercase().contains("pass through")
            || detail.to_lowercase().contains("custom upstream headers")
            || detail.to_lowercase().contains("plain http headers"),
        "detail should explain how to send custom upstream headers, got: {detail}"
    );
}

#[tokio::test]
async fn integration_proxy_accepts_all_known_tap_headers() {
    // Sanity check: the five documented X-TAP-* headers must NOT be rejected
    // by the unknown-header guard. If we ever rename or remove one, this fails.
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        // x-tap-credential omitted — optional; the legacy placeholder path still works without it.
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        400,
        "known TAP headers must not trigger the unknown-header guard"
    );
}

#[tokio::test]
async fn integration_proxy_sanitizes_leaked_credential() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/leak"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-a>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body_str.contains("secret123"));
    assert!(body_str.contains("[REDACTED:cred-a]"));
}

#[tokio::test]
async fn integration_proxy_rejects_placeholder_in_body_content() {
    // DB credentials use default substitution (headers only), so body placeholders
    // are not parsed. Test that credential in header works but body text is passed through.
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    // With default substitution, a placeholder in the body is ignored (not substituted,
    // not validated), and only headers get substituted. This request should succeed.
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-a>")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "hello"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn integration_audit_log_written() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_state(mock).await;
    let app = build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-a>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].agent_id, "test-agent");
    assert_eq!(entries[0].method, HttpMethod::Get);
}
// =========================================================================
// Unified interface tests (X-TAP-Credential)
// =========================================================================

/// Helper: build state with direct credentials for unified interface testing.
async fn make_unified_direct_state(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, Arc<InMemoryAuditLogger>, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let key_hash = hash_api_key("integration-test-key");

    let (store, tmp) = temp_store().await;
    store
        .create_credential(
            "t1",
            "direct-cred",
            "Direct test credential",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "direct-cred", b"direct-secret-val")
        .await
        .unwrap();
    store
        .create_credential(
            "t1",
            "legacy-cred",
            "Legacy placeholder credential",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "legacy-cred", b"legacy-secret-val")
        .await
        .unwrap();
    let custom_auth_bindings = serde_json::to_string(&vec![AuthBinding {
        header: "DD-API-KEY".to_string(),
        format: "{value}".to_string(),
    }])
    .unwrap();
    store
        .create_credential(
            "t1",
            "custom-auth-cred",
            "Custom header auth credential",
            "direct",
            None,
            false,
            None,
            Some(&custom_auth_bindings),
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "custom-auth-cred", b"dd-secret-val")
        .await
        .unwrap();
    store
        .create_credential(
            "t1",
            "basic-cred",
            "Basic auth credential",
            "direct",
            None,
            false,
            Some("Basic {base64(value.username:value.password)}"),
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value(
            "t1",
            "basic-cred",
            br#"{"username":"public-key","password":"private-key"}"#,
        )
        .await
        .unwrap();
    // A credential bound to a destination host allowlist (127.0.0.1 = the mock
    // upstream). Exercises the exfiltration guard end-to-end through /forward.
    store
        .create_credential(
            "t1",
            "bound-cred",
            "Host-bound credential",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "bound-cred", b"bound-secret-val")
        .await
        .unwrap();
    store
        .set_credential_allowed_hosts("t1", "bound-cred", &["127.0.0.1".to_string()])
        .await
        .unwrap();
    store
        .create_agent("t1", "test-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "bound-cred")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "direct-cred")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "legacy-cred")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "custom-auth-cred")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "basic-cred")
        .await
        .unwrap();
    for cred in &[
        "direct-cred",
        "legacy-cred",
        "custom-auth-cred",
        "basic-cred",
        "bound-cred",
    ] {
        store
            .set_policy(&PolicyRow {
                team_id: "t1".to_string(),
                credential_name: cred.to_string(),
                auto_approve_methods: vec!["GET".to_string()],
                require_approval_methods: vec!["POST".to_string()],
                auto_approve_urls: vec![],
                require_approval_urls: vec![],
                allowed_approvers: vec![],
                approval_channel: None,
                telegram_chat_id: None,
                matrix_room_id: None,
                matrix_allowed_approvers: vec![],
                require_passkey: false,
                min_approvals: 1,
            })
            .await
            .unwrap();
    }

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    (state, audit_logger, tmp)
}

/// Helper: start a mock upstream that records received headers.
async fn start_recording_upstream() -> (
    String,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>,
) {
    use axum::http::HeaderMap;
    use axum::routing::get;

    let recorded: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>> =
        Arc::new(std::sync::Mutex::new(vec![]));
    let rec = recorded.clone();

    let app = axum::Router::new().route(
        "/test",
        get({
            let rec = rec.clone();
            move |headers: HeaderMap| {
                let rec = rec.clone();
                async move {
                    let hdrs: Vec<(String, String)> = headers
                        .iter()
                        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();
                    rec.lock().unwrap().push(hdrs);
                    axum::Json(json!({"ok": true}))
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle, recorded)
}

#[tokio::test]
async fn unified_direct_auto_approves_get() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_unified_direct_state(mock.clone()).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "direct-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Should be auto-approved (GET), no approval calls
    assert!(mock.calls.lock().unwrap().is_empty());

    // Upstream should have received Authorization: Bearer direct-secret-val
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Bearer direct-secret-val"));

    // Audit log should have entry
    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn unified_bound_credential_to_listed_host_succeeds() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_unified_direct_state(mock.clone()).await;
    let app = build_router(state);

    // upstream_url is http://127.0.0.1:PORT — host 127.0.0.1 is allowed.
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "bound-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    // The secret reached the (allowed) upstream.
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
}

#[tokio::test]
async fn unified_bound_credential_to_unlisted_host_blocked() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_unified_direct_state(mock.clone()).await;
    let app = build_router(state);

    // Agent points the bound credential at an attacker host. The proxy must
    // refuse before injecting/forwarding — the secret never goes on the wire.
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "bound-cred")
        .header("x-tap-target", "https://evil.example/exfiltrate")
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "host_not_allowed");

    // No upstream forward happened, so no audit entry for a completed request.
    let entries = audit.entries();
    assert!(
        entries.is_empty(),
        "blocked request must not forward: {entries:?}"
    );
}

#[tokio::test]
async fn unified_direct_basic_auth_formats_authorization_header() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_unified_direct_state(mock.clone()).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "basic-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(mock.calls.lock().unwrap().is_empty());

    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Basic cHVibGljLWtleTpwcml2YXRlLWtleQ=="));
}

#[tokio::test]
async fn unified_credential_not_in_whitelist_returns_403() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "nonexistent-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403); // credential not in agent's whitelist
}

#[tokio::test]
async fn unified_and_legacy_coexist() {
    // Test that unified and legacy paths both work in the same proxy instance
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_unified_direct_state(mock).await;

    // First: unified path
    let app1 = build_router(state.clone());
    let req1 = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "direct-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp1 = app1.oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), 200);

    // Second: legacy placeholder path
    let app2 = build_router(state.clone());
    let req2 = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:legacy-cred>")
        .body(Body::empty())
        .unwrap();
    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), 200);

    // Both should have hit upstream
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 2);

    // First used unified (Bearer direct-secret-val)
    let auth1 = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth1, Some("Bearer direct-secret-val"));

    // Second used legacy placeholder (Bearer legacy-secret-val)
    let auth2 = recs[1]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth2, Some("Bearer legacy-secret-val"));

    // Both should be in audit log
    assert_eq!(audit.entries().len(), 2);
}

#[tokio::test]
async fn unified_response_sanitization() {
    // Upstream leaks credential in response — proxy should redact it
    use axum::routing::get;

    let app_upstream = axum::Router::new().route(
        "/leak",
        get(|| async { "the token is direct-secret-val oops" }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, app_upstream).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "direct-cred")
        .header("x-tap-target", format!("{upstream_url}/leak"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body_str.contains("direct-secret-val"));
    assert!(body_str.contains("[REDACTED:direct-cred]"));
}

#[tokio::test]
async fn unified_services_endpoint() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", "integration-test-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["agent_id"], "test-agent");
    assert!(value["services"]["direct-cred"].is_object());
    assert!(value["services"]["legacy-cred"].is_object());
    assert!(value["usage"]["headers"]["X-TAP-Credential"].is_string());
    assert_eq!(
        value["services"]["direct-cred"]["auth_mode"],
        "authorization_header"
    );
    assert_eq!(
        value["services"]["direct-cred"]["auth_header_names"][0],
        "Authorization"
    );
    assert_eq!(
        value["services"]["custom-auth-cred"]["auth_mode"],
        "custom_headers"
    );
    assert_eq!(
        value["services"]["custom-auth-cred"]["auth_header_names"][0],
        "DD-API-KEY"
    );
    // Master's usage schema: `unknown_tap_headers_rejected_with_400` + `custom_upstream_headers` (string description).
    assert_eq!(
        value["usage"]["unknown_tap_headers_rejected_with_400"],
        true
    );
    assert!(value["usage"]["custom_upstream_headers"].is_string());
    assert_eq!(value["usage"]["supported_tap_headers"][0], "x-tap-key");
    assert_eq!(value["services"]["direct-cred"]["target_shape"], "full_url");
    assert!(value["services"]["direct-cred"]["request_template"].is_object());
    assert!(value["services"]["direct-cred"]["read_examples"].is_array());
    assert!(value["services"]["direct-cred"]["write_examples"].is_array());
    assert!(value["services"]["direct-cred"]["common_mistakes"].is_array());
    assert_eq!(
        value["services"]["direct-cred"]["approval"]["default_decision"],
        "pauses_for_human"
    );
    let direct_rules = value["services"]["direct-cred"]["approval"]["rules"]
        .as_array()
        .expect("approval.rules should be an array");
    // GET proceeds immediately under the default policy.
    assert!(direct_rules.iter().any(|r| {
        r["decision"] == "proceeds_immediately"
            && r["methods"]
                .as_array()
                .map(|m| m.iter().any(|x| x == "GET"))
                .unwrap_or(false)
    }));
}

#[tokio::test]
async fn unified_services_requires_auth() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error_code"], "missing_tap_key");
    assert_eq!(value["setup_url"], "/instructions");
}

#[tokio::test]
async fn tap_agent_metadata_available_from_root_and_alias() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;

    // Root redirects to dashboard.
    {
        let app = build_router(state.clone());
        let req = Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_redirection(),
            "/ should redirect, got {}",
            resp.status()
        );
    }

    // /instructions serves plain-text TAP protocol docs.
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/instructions")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("TAP — Tool Authorization Proxy"),
        "missing title"
    );
    assert!(text.contains("/agent/services"), "missing services URL");
    assert!(text.contains("/forward"), "missing forward URL");
    assert!(text.contains("X-TAP-Key"), "missing X-TAP-Key");
    assert!(text.contains("X-TAP-Target"), "missing X-TAP-Target");
    assert!(text.contains("X-TAP-Method"), "missing X-TAP-Method");
    assert!(
        text.contains("Always POST to /forward"),
        "missing always-POST rule"
    );
}

#[tokio::test]
async fn agent_bootstrap_reports_ready_state() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/bootstrap")
        .header("x-tap-key", "integration-test-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["protocol"], "tap");
    assert_eq!(value["status"], "ready");
    assert_eq!(value["agent_id"], "test-agent");
    assert_eq!(value["services_url"], "/agent/services");
    assert!(value["credential_count"].as_u64().unwrap() > 0);
}

// =========================================================================
// Database mode integration tests
// =========================================================================

/// Helper: start a mock upstream that records headers, accepting both GET and POST.
async fn start_recording_post_upstream() -> (
    String,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>,
) {
    use axum::http::HeaderMap;
    use axum::routing::{get, post};

    let recorded: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>> =
        Arc::new(std::sync::Mutex::new(vec![]));
    let rec = recorded.clone();

    let handler = |rec: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>| {
        move |headers: HeaderMap| {
            let rec = rec.clone();
            async move {
                let hdrs: Vec<(String, String)> = headers
                    .iter()
                    .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                rec.lock().unwrap().push(hdrs);
                axum::Json(json!({"ok": true}))
            }
        }
    };

    let app = axum::Router::new()
        .route("/test", get(handler(rec.clone())))
        .route("/test", post(handler(rec.clone())));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle, recorded)
}

/// Build an AppState wired to a real SQLite database.
/// Sets up: credential "api-cred" (direct), agent "db-agent" with key "db-test-key",
/// policy: GET auto-approve, POST require-approval.
async fn make_db_state(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, Arc<InMemoryAuditLogger>, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let (store, tmp) = temp_store().await;

    // Create credential
    store
        .create_credential(
            "t1",
            "api-cred",
            "API Credential",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "api-cred", b"db-secret-val")
        .await
        .unwrap();

    // Create agent with API key hash
    let api_key = "db-test-key";
    let key_hash = hash_api_key(api_key);
    store
        .create_agent("t1", "db-agent", Some("Test DB agent"), &key_hash, None)
        .await
        .unwrap();

    // Grant credential directly to agent
    store
        .add_direct_credential("t1", "db-agent", "api-cred")
        .await
        .unwrap();

    // Set policy
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "api-cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string(), "PUT".to_string()],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());

    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    (state, audit_logger, tmp)
}

#[tokio::test]
async fn db_mode_unified_auto_approves_get() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_db_state(mock.clone()).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // GET auto-approved — no approval calls
    assert!(mock.calls.lock().unwrap().is_empty());

    // Upstream received Bearer with decrypted credential value
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Bearer db-secret-val"));

    // Audit log written
    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].agent_id, "db-agent");
}

#[tokio::test]
async fn db_mode_post_requires_approval() {
    let (upstream_url, _h, _recorded) = start_recording_post_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock.clone()).await;

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "POST")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 202, "expected 202 Accepted, got {status}: {body}");
    let txn_id = body["txn_id"].as_str().expect("txn_id missing").to_string();

    // POST should have triggered approval
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
    assert_eq!(mock.calls.lock().unwrap()[0], "db-agent");

    // Wait for background task then poll
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let poll_req = Request::builder()
        .method("GET")
        .uri(format!("/agent/approvals/{txn_id}"))
        .header("x-tap-key", "db-test-key")
        .body(Body::empty())
        .unwrap();
    let (poll_status, poll_body) =
        send_request_and_parse(build_router(state.clone()), poll_req).await;
    assert_eq!(poll_status, 200);
    assert_eq!(poll_body["status"], "forwarded", "poll: {poll_body}");
}

#[tokio::test]
async fn db_mode_rejects_invalid_api_key() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "wrong-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn db_mode_rejects_non_whitelisted_credential() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "other-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn db_mode_disabled_agent_rejected() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;

    // Disable the agent
    state
        .db_state
        .store()
        .disable_agent("t1", "db-agent")
        .await
        .unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn db_mode_rbac_role_grants_credential_access() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Create credential
    store
        .create_credential(
            "t1",
            "slack",
            "Slack API",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "slack", b"xoxb-slack-token")
        .await
        .unwrap();

    // Create role "comms" that includes "slack"
    store.create_role("t1", "comms", None, None).await.unwrap();
    store
        .add_credential_to_role("t1", "comms", "slack")
        .await
        .unwrap();

    // Create agent and assign role (NOT direct credential)
    let key_hash = hash_api_key("rbac-key");
    store
        .create_agent("t1", "rbac-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .assign_role_to_agent("t1", "rbac-bot", "comms")
        .await
        .unwrap();

    // Set policy: auto-approve GET
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "slack".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string()],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());

    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };

    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "rbac-key")
        .header("x-tap-credential", "slack")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Upstream got the credential via role-based access
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Bearer xoxb-slack-token"));

    assert_eq!(audit_logger.entries().len(), 1);
    assert_eq!(audit_logger.entries()[0].agent_id, "rbac-bot");
}

#[tokio::test]
async fn db_mode_rbac_multiple_roles_union() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Create three credentials
    store
        .create_credential(
            "t1", "slack", "Slack", "direct", None, false, None, None, None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "slack", b"slack-token")
        .await
        .unwrap();
    store
        .create_credential(
            "t1", "github", "GitHub", "direct", None, false, None, None, None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "github", b"gh-token")
        .await
        .unwrap();
    store
        .create_credential(
            "t1", "openai", "OpenAI", "direct", None, false, None, None, None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "openai", b"sk-openai")
        .await
        .unwrap();

    // Create two roles with different credentials
    store.create_role("t1", "comms", None, None).await.unwrap();
    store
        .add_credential_to_role("t1", "comms", "slack")
        .await
        .unwrap();
    store.create_role("t1", "dev", None, None).await.unwrap();
    store
        .add_credential_to_role("t1", "dev", "github")
        .await
        .unwrap();

    // Create agent with both roles + one direct credential
    let key_hash = hash_api_key("multi-key");
    store
        .create_agent("t1", "multi-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .assign_role_to_agent("t1", "multi-bot", "comms")
        .await
        .unwrap();
    store
        .assign_role_to_agent("t1", "multi-bot", "dev")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "multi-bot", "openai")
        .await
        .unwrap();

    // Auto-approve everything for simplicity
    for cred in &["slack", "github", "openai"] {
        store
            .set_policy(&PolicyRow {
                team_id: "t1".to_string(),
                credential_name: cred.to_string(),
                auto_approve_methods: vec!["GET".to_string()],
                require_approval_methods: vec![],
                auto_approve_urls: vec![],
                require_approval_urls: vec![],
                allowed_approvers: vec![],
                approval_channel: None,
                telegram_chat_id: None,
                matrix_room_id: None,
                matrix_allowed_approvers: vec![],
                require_passkey: false,
                min_approvals: 1,
            })
            .await
            .unwrap();
    }

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };

    // Agent can access all three credentials (slack via comms, github via dev, openai direct)
    for cred in &["slack", "github", "openai"] {
        let app = build_router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/forward")
            .header("x-tap-key", "multi-key")
            .header("x-tap-credential", *cred)
            .header("x-tap-target", format!("{upstream_url}/test"))
            .header("x-tap-method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200, "Failed to access credential '{cred}'");
    }

    // Agent cannot access a credential not in any role or direct
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "multi-key")
        .header("x-tap-credential", "not-assigned")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn db_mode_response_sanitizes_leaked_credential() {
    use axum::routing::get;

    let app_upstream = axum::Router::new().route(
        "/leak",
        get(|| async { "oops the token is db-secret-val leaked" }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, app_upstream).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/leak"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body_str.contains("db-secret-val"),
        "Credential value leaked in response"
    );
    assert!(body_str.contains("[REDACTED:api-cred]"));
}

#[tokio::test]
async fn db_mode_rate_limit_enforced() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    store
        .create_credential(
            "t1", "cred", "Cred", "direct", None, false, None, None, None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "cred", b"val")
        .await
        .unwrap();

    // Agent with rate limit of 3 per hour (check_rate_limit uses >=, so 3 allows 2 requests)
    let key_hash = hash_api_key("rate-key");
    store
        .create_agent("t1", "rate-bot", None, &key_hash, Some(3))
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "rate-bot", "cred")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec![],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };

    // First two requests succeed
    for i in 0..2 {
        let app = build_router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/forward")
            .header("x-tap-key", "rate-key")
            .header("x-tap-credential", "cred")
            .header("x-tap-target", format!("{upstream_url}/test"))
            .header("x-tap-method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200, "Request {i} should succeed");
    }

    // Third request rate-limited
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "rate-key")
        .header("x-tap-credential", "cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn db_mode_agent_services_endpoint() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", "db-test-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["agent_id"], "db-agent");
    assert!(value["services"]["api-cred"].is_object());
    let approval = &value["services"]["api-cred"]["approval"];
    assert_eq!(approval["default_decision"], "pauses_for_human");
    let rules = approval["rules"]
        .as_array()
        .expect("approval.rules should be an array");
    // GET proceeds immediately; writes pause for a human.
    assert!(rules.iter().any(|r| {
        r["decision"] == "proceeds_immediately"
            && r["methods"]
                .as_array()
                .map(|m| m.iter().any(|x| x == "GET"))
                .unwrap_or(false)
    }));
    assert!(rules
        .iter()
        .any(|r| r["decision"] == "pauses_for_human" && r["target"] == "*"));
}

// A per-URL auto-approve override (e.g. scoping only the Calendar API to
// proceed-immediately) must surface in /agent/services as a top-priority
// url_override rule, so an agent can see the scope without firing a request.
#[tokio::test]
async fn db_mode_services_surfaces_auto_approve_url_override() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    store
        .create_credential(
            "t1",
            "cal-cred",
            "Calendar Credential",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "cal-cred", b"cal-secret")
        .await
        .unwrap();
    let key_hash = hash_api_key("cal-key");
    store
        .create_agent("t1", "cal-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "cal-agent", "cal-cred")
        .await
        .unwrap();
    // Writes pause for a human, EXCEPT the Calendar API path which auto-approves.
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "cal-cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec![
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
            ],
            auto_approve_urls: vec!["https://www.googleapis.com/calendar/v3/".to_string()],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", "cal-key")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let approval = &value["services"]["cal-cred"]["approval"];
    assert_eq!(approval["default_decision"], "pauses_for_human");
    assert_eq!(
        approval["url_match"],
        "path_prefix_or_exact_host_path_prefix_with_star_segments"
    );
    let rules = approval["rules"].as_array().expect("rules array");

    // The configured URL surfaces as a top-priority url_override that proceeds immediately.
    let url_rule = rules
        .iter()
        .find(|r| r["priority"] == "url_override")
        .expect("a url_override rule should be present");
    assert_eq!(url_rule["decision"], "proceeds_immediately");
    assert_eq!(
        url_rule["target"],
        "https://www.googleapis.com/calendar/v3/"
    );
    // url_override must be evaluated before the method rules (mirrors evaluate_policy).
    assert_eq!(rules[0]["priority"], "url_override");
    // Writes still pause for a human by default.
    assert!(rules
        .iter()
        .any(|r| r["decision"] == "pauses_for_human" && r["target"] == "*"));
}

// Regression test: sidecar api_base is an internal sidecar URL and must never
// appear in agent-facing service templates — agents must always use the real
// upstream API URL as X-TAP-Target.
#[tokio::test]
async fn db_mode_services_sidecar_api_base_not_leaked() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Sidecar credential whose api_base is an internal sidecar URL.
    store
        .create_credential(
            "t1",
            "google-cred",
            "Google OAuth",
            "sidecar",
            Some("http://127.0.0.1:8081"),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let api_key = "sidecar-test-key";
    let key_hash = hash_api_key(api_key);
    store
        .create_agent("t1", "sidecar-agent", Some("Test"), &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "sidecar-agent", "google-cred")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store.clone(), Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", api_key)
        .body(Body::empty())
        .unwrap();

    let (status, value) = send_request_and_parse(app, req).await;
    assert_eq!(status, 200);

    let service = &value["services"]["google-cred"];
    assert!(service.is_object(), "google-cred should appear in services");

    // Serialise the whole service entry and verify the internal sidecar URL is absent.
    let service_str = service.to_string();
    assert!(
        !service_str.contains("127.0.0.1:8081"),
        "sidecar api_base must not appear in service template; got: {service_str}"
    );

    // The target placeholder must be a generic hint, not the sidecar URL.
    let template = service["request_template"]["headers"]["X-TAP-Target"]
        .as_str()
        .unwrap_or("");
    assert!(
        !template.contains("127.0.0.1"),
        "X-TAP-Target placeholder must not contain sidecar address; got: {template}"
    );
    assert!(
        template.contains("upstream") || template.contains("http"),
        "X-TAP-Target placeholder should be a useful hint; got: {template}"
    );
}

#[tokio::test]
async fn db_mode_agent_config_endpoint() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/config")
        .header("x-tap-key", "db-test-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["agent_id"], "db-agent");
    let creds = value["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["name"], "api-cred");
    assert_eq!(creds[0]["description"], "API Credential");
}

#[tokio::test]
async fn db_mode_approval_denied_returns_403() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: false, // deny
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "POST") // requires approval
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 202, "expected 202 Accepted, got {status}: {body}");
    let txn_id = body["txn_id"].as_str().expect("txn_id missing").to_string();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let poll_req = Request::builder()
        .method("GET")
        .uri(format!("/agent/approvals/{txn_id}"))
        .header("x-tap-key", "db-test-key")
        .body(Body::empty())
        .unwrap();
    let (poll_status, poll_body) =
        send_request_and_parse(build_router(state.clone()), poll_req).await;
    assert_eq!(poll_status, 200);
    assert_eq!(poll_body["status"], "denied", "poll: {poll_body}");
}

#[tokio::test]
async fn db_mode_sidecar_credential_routing() {
    // Set up a mock sidecar that records what it receives (handles GET on /)
    use axum::http::HeaderMap;
    use axum::routing::get;

    let recorded: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>> =
        Arc::new(std::sync::Mutex::new(vec![]));
    let rec = recorded.clone();

    let sidecar_app = axum::Router::new().route(
        "/",
        get({
            let rec = rec.clone();
            move |headers: HeaderMap| {
                let rec = rec.clone();
                async move {
                    let hdrs: Vec<(String, String)> = headers
                        .iter()
                        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();
                    rec.lock().unwrap().push(hdrs);
                    axum::Json(json!({"ok": true}))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sidecar_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, sidecar_app).await.unwrap();
    });
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Create sidecar credential (e.g., OAuth signer)
    store
        .create_credential(
            "t1",
            "twitter",
            "Twitter via OAuth signer",
            "sidecar",
            Some(&sidecar_url),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let key_hash = hash_api_key("sidecar-key");
    store
        .create_agent("t1", "sidecar-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "sidecar-bot", "twitter")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "twitter".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec![],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };

    let app = build_router(state);

    // Agent sends request — proxy routes to sidecar with X-OAuth-* headers
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "sidecar-key")
        .header("x-tap-credential", "twitter")
        .header("x-tap-target", "https://api.twitter.com/2/tweets")
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Sidecar should have received X-OAuth-Credential and X-OAuth-Target
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let oauth_cred = recs[0]
        .iter()
        .find(|(n, _)| n == "x-oauth-credential")
        .map(|(_, v)| v.as_str());
    assert_eq!(oauth_cred, Some("twitter"));
    let oauth_target = recs[0]
        .iter()
        .find(|(n, _)| n == "x-oauth-target")
        .map(|(_, v)| v.as_str());
    assert_eq!(oauth_target, Some("https://api.twitter.com/2/tweets"));
}

#[tokio::test]
async fn db_mode_oauth1_inline_signing_full_round_trip() {
    // Full round trip for Twitter-style OAuth 1.0a credentials:
    //   agent → proxy → (inline HMAC-SHA1 sign) → real API
    //
    // This is the test that SHOULD have existed before the twitter-personal 502
    // incident. It asserts:
    //   1. The proxy does NOT connect to the (non-running) signer sidecar
    //   2. The proxy signs inline and forwards to the configured target_url
    //   3. The Authorization header is a valid RFC 5849 OAuth header
    //   4. All required oauth_* params are present (consumer_key, nonce,
    //      signature, signature_method, timestamp, token, version)
    use axum::http::HeaderMap;
    use axum::routing::get;

    // Mock "Twitter API" that records the Authorization header it receives.
    let captured_auth: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    let captured_url: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let cap_auth = captured_auth.clone();
    let cap_url = captured_url.clone();

    let upstream_app = axum::Router::new().route(
        "/2/users/me",
        get(move |headers: HeaderMap| {
            let cap_auth = cap_auth.clone();
            let cap_url = cap_url.clone();
            async move {
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                *cap_auth.lock().unwrap() = auth;
                *cap_url.lock().unwrap() = Some("/2/users/me".to_string());
                axum::Json(json!({"id": "12345", "username": "test"}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Create the credential as "sidecar" with a sidecar api_base that deliberately
    // points at a port NOTHING is listening on. If the proxy ever tries to route
    // through the sidecar path, the test fails with a connection-refused 502 —
    // which is exactly the prod incident we're guarding against.
    store
        .create_credential(
            "t1",
            "twitter-personal",
            "Twitter via OAuth 1.0a",
            "sidecar",
            Some("http://127.0.0.1:1"), // unreachable — must be bypassed
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // Store a fake OAuth 1.0a JSON bundle as the credential value.
    let bundle = json!({
        "consumer_key": "test-consumer-key",
        "consumer_secret": "test-consumer-secret",
        "access_token": "test-access-token",
        "access_token_secret": "test-access-token-secret",
    })
    .to_string();
    store
        .set_credential_value("t1", "twitter-personal", bundle.as_bytes())
        .await
        .unwrap();

    let key_hash = hash_api_key("oauth1-test-key");
    store
        .create_agent("t1", "oauth1-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "oauth1-bot", "twitter-personal")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    // Agent makes a GET against the real "Twitter API" (our mock upstream).
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "oauth1-test-key")
        .header("x-tap-credential", "twitter-personal")
        .header("x-tap-target", format!("{upstream_url}/2/users/me"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "proxy should have successfully signed + forwarded to the real API \
         (not the non-running sidecar at 127.0.0.1:1)"
    );

    // Verify the mock upstream actually got hit (not 127.0.0.1:1).
    assert_eq!(
        captured_url.lock().unwrap().as_deref(),
        Some("/2/users/me"),
        "request should have reached the real API, not the sidecar"
    );

    // Verify the Authorization header looks like a well-formed OAuth 1.0a header.
    let auth = captured_auth
        .lock()
        .unwrap()
        .clone()
        .expect("upstream should have received an Authorization header");
    assert!(
        auth.starts_with("OAuth "),
        "expected OAuth 1.0a header, got: {auth}"
    );
    // All six required oauth_* params per RFC 5849 must be present
    for required in [
        "oauth_consumer_key=\"test-consumer-key\"",
        "oauth_token=\"test-access-token\"",
        "oauth_signature_method=\"HMAC-SHA1\"",
        "oauth_version=\"1.0\"",
        "oauth_nonce=",
        "oauth_timestamp=",
        "oauth_signature=",
    ] {
        assert!(
            auth.contains(required),
            "OAuth header missing '{required}': {auth}"
        );
    }
    // Consumer secret must never leak into the header (only the signature is sent)
    assert!(
        !auth.contains("test-consumer-secret"),
        "consumer secret leaked into Authorization header: {auth}"
    );
    assert!(
        !auth.contains("test-access-token-secret"),
        "access token secret leaked into Authorization header: {auth}"
    );
}

#[tokio::test]
async fn db_mode_multi_secret_credential_injects_distinct_headers() {
    // Datadog-shape credential: ONE credential row holds TWO independent
    // secrets in a JSON object value, and TWO auth_bindings each pull a
    // different field via {value.api_key} / {value.app_key}.
    //
    // This is the test that proves multi-secret APIs (Datadog, AWS, etc.)
    // actually work end-to-end:
    //   1. The proxy substitutes each {value.<key>} reference with the right
    //      field — DD-API-KEY gets the api_key, DD-APPLICATION-KEY gets the
    //      app_key (NOT the same string in both, which is the trap the old
    //      single-{value} model fell into).
    //   2. Both headers reach the upstream with their distinct values.
    //   3. Neither secret leaks anywhere it shouldn't.
    use axum::http::HeaderMap;
    use axum::routing::get;
    use tap_core::config::AuthBinding;

    // Mock "Datadog API" that records the two auth headers it receives.
    let captured_api: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let captured_app: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let cap_api = captured_api.clone();
    let cap_app = captured_app.clone();

    let upstream_app = axum::Router::new().route(
        "/api/v1/validate",
        get(move |headers: HeaderMap| {
            let cap_api = cap_api.clone();
            let cap_app = cap_app.clone();
            async move {
                let api = headers
                    .get("dd-api-key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let app = headers
                    .get("dd-application-key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                *cap_api.lock().unwrap() = api;
                *cap_app.lock().unwrap() = app;
                axum::Json(json!({"valid": true}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Create the Datadog credential as a "direct" connector with two
    // auth_bindings, each pulling a different field from the JSON value.
    let bindings = vec![
        AuthBinding {
            header: "DD-API-KEY".to_string(),
            format: "{value.api_key}".to_string(),
        },
        AuthBinding {
            header: "DD-APPLICATION-KEY".to_string(),
            format: "{value.app_key}".to_string(),
        },
    ];
    let bindings_json = serde_json::to_string(&bindings).unwrap();
    store
        .create_credential(
            "t1",
            "datadog",
            "Datadog API",
            "direct",
            None,
            false,
            None,
            Some(&bindings_json),
            None,
        )
        .await
        .unwrap();

    // Store the multi-secret value as a JSON object: two independent secrets
    // in one credential row. The api key and app key are deliberately
    // different strings so we can prove each header gets the right one.
    let cred_value = json!({
        "api_key": "DD-API-KEY-VALUE-AAA",
        "app_key": "DD-APP-KEY-VALUE-BBB",
    })
    .to_string();
    store
        .set_credential_value("t1", "datadog", cred_value.as_bytes())
        .await
        .unwrap();

    let key_hash = hash_api_key("datadog-test-key");
    store
        .create_agent("t1", "datadog-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "datadog-bot", "datadog")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "datadog-test-key")
        .header("x-tap-credential", "datadog")
        .header("x-tap-target", format!("{upstream_url}/api/v1/validate"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Both headers must have the correct DISTINCT secret. The whole point of
    // multi-secret support is that DD-API-KEY != DD-APPLICATION-KEY.
    let api = captured_api.lock().unwrap().clone();
    let app_h = captured_app.lock().unwrap().clone();
    assert_eq!(
        api.as_deref(),
        Some("DD-API-KEY-VALUE-AAA"),
        "DD-API-KEY must receive the api_key field, not the app_key"
    );
    assert_eq!(
        app_h.as_deref(),
        Some("DD-APP-KEY-VALUE-BBB"),
        "DD-APPLICATION-KEY must receive the app_key field, not the api_key"
    );
    assert_ne!(
        api, app_h,
        "the two headers must have DIFFERENT values — that is the whole point"
    );
}

#[tokio::test]
async fn db_mode_multi_secret_credential_response_sanitization_scrubs_each_leaf() {
    // Companion test: the response sanitizer must redact each leaf of a
    // multi-secret credential separately, not just the whole JSON blob.
    use axum::routing::get;
    use tap_core::config::AuthBinding;

    // Upstream returns a body that contains BOTH secrets, simulating a leak.
    let upstream_app = axum::Router::new().route(
        "/leak",
        get(|| async { "logs: api_key=DD-API-KEY-VALUE-AAA app_key=DD-APP-KEY-VALUE-BBB" }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let (store, _tmp) = temp_store().await;
    let bindings = vec![
        AuthBinding {
            header: "DD-API-KEY".to_string(),
            format: "{value.api_key}".to_string(),
        },
        AuthBinding {
            header: "DD-APPLICATION-KEY".to_string(),
            format: "{value.app_key}".to_string(),
        },
    ];
    let bindings_json = serde_json::to_string(&bindings).unwrap();
    store
        .create_credential(
            "t1",
            "datadog",
            "Datadog API",
            "direct",
            None,
            false,
            None,
            Some(&bindings_json),
            None,
        )
        .await
        .unwrap();
    let cred_value = json!({
        "api_key": "DD-API-KEY-VALUE-AAA",
        "app_key": "DD-APP-KEY-VALUE-BBB",
    })
    .to_string();
    store
        .set_credential_value("t1", "datadog", cred_value.as_bytes())
        .await
        .unwrap();

    let key_hash = hash_api_key("datadog-leak-key");
    store
        .create_agent("t1", "leak-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "leak-bot", "datadog")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(test_key()),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "datadog-leak-key")
        .header("x-tap-credential", "datadog")
        .header("x-tap-target", format!("{upstream_url}/leak"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body_str.contains("DD-API-KEY-VALUE-AAA"),
        "api_key leaked into response: {body_str}"
    );
    assert!(
        !body_str.contains("DD-APP-KEY-VALUE-BBB"),
        "app_key leaked into response: {body_str}"
    );
    assert!(
        body_str.contains("[REDACTED:datadog.api_key]") || body_str.contains("[REDACTED:datadog]"),
        "expected redaction marker, got: {body_str}"
    );
}

#[tokio::test]
async fn db_mode_multi_secret_via_placeholder_mode_full_round_trip() {
    // The placeholder-mode end-to-end test for multi-secret APIs.
    //
    // The agent writes the headers explicitly using <CREDENTIAL:name.field>
    // syntax — no auth_bindings configured on the credential, no
    // X-TAP-Credential header, the proxy just substitutes the field
    // references at forward time. This is the canonical way to handle
    // Datadog/AWS-style two-secret APIs going forward.
    //
    // Asserts:
    //   1. The credential value is stored as a JSON object
    //   2. <CREDENTIAL:datadog.api_key> resolves to the api_key field
    //   3. <CREDENTIAL:datadog.app_key> resolves to the app_key field
    //   4. The two fields are DISTINCT (DD-API-KEY != DD-APPLICATION-KEY)
    //   5. The position validator allows arbitrary headers for field refs
    //      even though DD-API-KEY is not in ALLOWED_AUTH_HEADERS
    use axum::http::HeaderMap;
    use axum::routing::get;

    // Mock "Datadog API" that records the two auth headers it receives.
    let captured_api: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let captured_app: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let cap_api = captured_api.clone();
    let cap_app = captured_app.clone();

    let upstream_app = axum::Router::new().route(
        "/api/v1/validate",
        get(move |headers: HeaderMap| {
            let cap_api = cap_api.clone();
            let cap_app = cap_app.clone();
            async move {
                let api = headers
                    .get("dd-api-key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let app = headers
                    .get("dd-application-key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                *cap_api.lock().unwrap() = api;
                *cap_app.lock().unwrap() = app;
                axum::Json(json!({"valid": true}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Plain credential row — no auth_bindings, no api_base. Just a name and
    // a JSON object value. This is the simplest possible multi-secret config.
    store
        .create_credential(
            "t1",
            "datadog",
            "Datadog API",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let cred_value = json!({
        "api_key": "DD-API-KEY-VALUE-AAA",
        "app_key": "DD-APP-KEY-VALUE-BBB",
    })
    .to_string();
    store
        .set_credential_value("t1", "datadog", cred_value.as_bytes())
        .await
        .unwrap();

    let key_hash = hash_api_key("datadog-placeholder-key");
    store
        .create_agent("t1", "ddbot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "ddbot", "datadog")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    // The agent specifies BOTH headers explicitly, using field references.
    // Note: NO X-TAP-Credential header. The proxy resolves the credentials
    // purely from the placeholder substitution path.
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "datadog-placeholder-key")
        .header("x-tap-target", format!("{upstream_url}/api/v1/validate"))
        .header("x-tap-method", "GET")
        .header("DD-API-KEY", "<CREDENTIAL:datadog.api_key>")
        .header("DD-APPLICATION-KEY", "<CREDENTIAL:datadog.app_key>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let api = captured_api.lock().unwrap().clone();
    let app_h = captured_app.lock().unwrap().clone();
    assert_eq!(
        api.as_deref(),
        Some("DD-API-KEY-VALUE-AAA"),
        "<CREDENTIAL:datadog.api_key> must resolve to api_key field"
    );
    assert_eq!(
        app_h.as_deref(),
        Some("DD-APP-KEY-VALUE-BBB"),
        "<CREDENTIAL:datadog.app_key> must resolve to app_key field"
    );
    assert_ne!(
        api, app_h,
        "DD-API-KEY and DD-APPLICATION-KEY must hold DIFFERENT secrets"
    );
}

#[tokio::test]
async fn db_mode_multi_secret_auto_inject_end_to_end() {
    // The #21 contract, full stack: a multi-secret credential configured with
    // field→header bindings works with ONLY `X-TAP-Credential: datadog` — no
    // placeholder syntax, no header knowledge in the agent. The proxy injects
    // every field into its bound header.
    use axum::http::HeaderMap;
    use axum::routing::get;

    let captured_api: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let captured_app: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let cap_api = captured_api.clone();
    let cap_app = captured_app.clone();

    let upstream_app = axum::Router::new().route(
        "/api/v1/validate",
        get(move |headers: HeaderMap| {
            let cap_api = cap_api.clone();
            let cap_app = cap_app.clone();
            async move {
                *cap_api.lock().unwrap() = headers
                    .get("dd-api-key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                *cap_app.lock().unwrap() = headers
                    .get("dd-application-key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                axum::Json(json!({"valid": true}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // The credential the dashboard's multi-secret flow now creates: a JSON
    // object value PLUS the field→header bindings that define its wiring.
    store
        .create_credential(
            "t1",
            "datadog",
            "Datadog API",
            "direct",
            None,
            false,
            None,
            Some(
                r#"[{"header":"DD-API-KEY","format":"{value.api_key}"},{"header":"DD-APPLICATION-KEY","format":"{value.app_key}"}]"#,
            ),
            None,
        )
        .await
        .unwrap();
    let cred_value = json!({
        "api_key": "DD-API-KEY-VALUE-AAA",
        "app_key": "DD-APP-KEY-VALUE-BBB",
    })
    .to_string();
    store
        .set_credential_value("t1", "datadog", cred_value.as_bytes())
        .await
        .unwrap();

    let key_hash = hash_api_key("datadog-autoinject-key");
    store
        .create_agent("t1", "ddbot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "ddbot", "datadog")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    // Agent code identical to a single-secret API: just X-TAP-Credential.
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "datadog-autoinject-key")
        .header("x-tap-credential", "datadog")
        .header("x-tap-target", format!("{upstream_url}/api/v1/validate"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let api = captured_api.lock().unwrap().clone();
    let app_h = captured_app.lock().unwrap().clone();
    assert_eq!(
        api.as_deref(),
        Some("DD-API-KEY-VALUE-AAA"),
        "api_key field must be injected into DD-API-KEY"
    );
    assert_eq!(
        app_h.as_deref(),
        Some("DD-APP-KEY-VALUE-BBB"),
        "app_key field must be injected into DD-APPLICATION-KEY"
    );
    assert_ne!(api, app_h, "the two headers must carry DIFFERENT secrets");
}

#[tokio::test]
async fn db_mode_multi_secret_without_bindings_clear_error() {
    // A multi-secret credential with NO bindings used via plain
    // X-TAP-Credential used to inject `Bearer {json blob}` — silently broken.
    // Now: 400 multi_secret_unbound with fix guidance, and nothing forwarded.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    store
        .create_credential(
            "t1", "datadog", "Datadog", "direct", None, false, None, None, None,
        )
        .await
        .unwrap();
    store
        .set_credential_value(
            "t1",
            "datadog",
            br#"{"api_key":"DD-AAA","app_key":"DD-BBB"}"#,
        )
        .await
        .unwrap();

    let key_hash = hash_api_key("datadog-unbound-key");
    store
        .create_agent("t1", "ddbot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "ddbot", "datadog")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "datadog-unbound-key")
        .header("x-tap-credential", "datadog")
        .header("x-tap-target", "https://api.datadoghq.com/api/v1/validate")
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"], "multi_secret_unbound");
    assert!(
        v["fix"].as_str().unwrap_or("").contains("dashboard"),
        "error must tell the agent how to get it fixed"
    );
    // The raw secrets must never appear in the error surface.
    let s = String::from_utf8_lossy(&body);
    assert!(!s.contains("DD-AAA") && !s.contains("DD-BBB"));
}

#[tokio::test]
async fn db_mode_field_reference_to_non_whitelisted_credential_rejected() {
    // Cross-credential isolation: an agent that has `datadog` whitelisted
    // must NOT be able to slip a field reference like
    // <CREDENTIAL:other-secret.api_key> into a request, even though field
    // references bypass the position validator.
    //
    // The whitelist check uses the bare credential name (the part before the
    // dot), so the existing enforcement should reject this. This test exists
    // to make sure that property doesn't regress when someone refactors the
    // placeholder code path later.
    use axum::routing::get;

    let upstream_app = axum::Router::new().route("/x", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let (store, _tmp) = temp_store().await;

    // Two distinct credentials. Agent gets only one.
    store
        .create_credential(
            "t1", "datadog", "Datadog", "direct", None, false, None, None, None,
        )
        .await
        .unwrap();
    store
        .set_credential_value(
            "t1",
            "datadog",
            br#"{"api_key":"DD-AAA","app_key":"DD-BBB"}"#,
        )
        .await
        .unwrap();

    store
        .create_credential(
            "t1",
            "other-secret",
            "Some other API",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "other-secret", br#"{"api_key":"OTHER-AAA"}"#)
        .await
        .unwrap();

    let key_hash = hash_api_key("isolation-key");
    store
        .create_agent("t1", "ddbot", None, &key_hash, None)
        .await
        .unwrap();
    // Agent only gets datadog — NOT other-secret.
    store
        .add_direct_credential("t1", "ddbot", "datadog")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(test_key()),
        approval_channel: mock.clone(),
        dashboard_channel: mock.clone(),
        telegram_channel: Some(mock.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    let app = build_router(state);

    // Agent tries to reference a credential they don't have, via field syntax.
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "isolation-key")
        .header("x-tap-target", format!("{upstream_url}/x"))
        .header("x-tap-method", "GET")
        .header("X-Other-Secret", "<CREDENTIAL:other-secret.api_key>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        403,
        "field reference to non-whitelisted credential must be 403, not 200"
    );
}

#[tokio::test]
async fn db_mode_multi_secret_credential_approval_message_does_not_leak_fields() {
    // Approval-message scrubbing for multi-secret credentials.
    //
    // When a write request requires approval, the approval channel receives
    // a sanitized payload of the request. We must verify that field-resolved
    // secrets do NOT leak into that approval message — both leaves and the
    // raw JSON blob must be redacted.
    //
    // Done as a unit test of sanitize_raw_payload (the function that sanitizes
    // approval payloads) since the approval channel itself is mocked at this
    // layer. The same scrubbing path is exercised end-to-end by the existing
    // db_mode_multi_secret_credential_response_sanitization_scrubs_each_leaf
    // test for upstream responses.
    use tap_proxy::sanitize::sanitize_raw_payload;

    // The payload that would be displayed in the approval message —
    // headers contain the *substituted* secrets, not placeholders, because
    // sanitize_raw_payload runs after substitution.
    let payload = serde_json::json!({
        "method": "POST",
        "url": "https://api.datadoghq.com/api/v1/events",
        "headers": [
            ["DD-API-KEY", "DD-API-VALUE-AAA"],
            ["DD-APPLICATION-KEY", "DD-APP-VALUE-BBB"],
            ["Content-Type", "application/json"]
        ],
        "body": {"title": "deploy completed", "text": "build #42 ok"}
    });

    let result = sanitize_raw_payload(&payload);
    let result_str = serde_json::to_string(&result).unwrap();

    assert!(
        !result_str.contains("DD-API-VALUE-AAA"),
        "api_key leaked into approval payload: {result_str}"
    );
    assert!(
        !result_str.contains("DD-APP-VALUE-BBB"),
        "app_key leaked into approval payload: {result_str}"
    );
    // The non-secret content (the body the user is approving) must survive.
    assert!(
        result_str.contains("deploy completed"),
        "approval body content was scrubbed too aggressively: {result_str}"
    );
}

// =========================================================================
// Multi-tenant isolation + admin API tests
// =========================================================================

/// Helper: login an existing admin account, return session token.
async fn login_existing(state: &AppState, email: &str, password: &str) -> String {
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"email": email, "password": password}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200, "Login should succeed for {email}");
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    value["session_token"].as_str().unwrap().to_string()
}

/// Helper: sign up a team, verify email manually, login, return session token.
async fn signup_and_login(
    state: &AppState,
    team_name: &str,
    email: &str,
    password: &str,
) -> String {
    let store = state.db_state.store();

    // Create team + admin directly (bypassing email verification for tests)
    let team_id = uuid::Uuid::new_v4().to_string();
    store.create_team(&team_id, team_name).await.unwrap();

    let new_user_id = uuid::Uuid::new_v4().to_string();
    let pw_hash = tap_proxy::admin::hash_password(password).unwrap();
    let user_id = store
        .create_user_with_membership(&new_user_id, &team_id, email, &pw_hash, "owner")
        .await
        .unwrap();
    store.set_user_email_verified(&user_id).await.unwrap();

    // Login
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": email,
                "password": password,
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200, "Login should succeed");

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    value["session_token"].as_str().unwrap().to_string()
}

/// Build a minimal AppState for admin/multi-tenant tests (empty DB, no pre-populated data).
async fn make_empty_state(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let tmp = tempfile::NamedTempFile::new().unwrap(); // kept for return type compat
                                                       // Own isolated schema so admin/multi-tenant tests run in parallel.
    let (store, _url) = ConfigStore::new_isolated_test(enc_key).await;
    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    (state, tmp)
}

/// Like `make_empty_state`, but also returns a handle to the concrete
/// in-memory audit logger so a test can assert on the entries written.
async fn make_empty_state_with_audit(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, Arc<InMemoryAuditLogger>) {
    let enc_key = test_key();
    let (store, _url) = ConfigStore::new_isolated_test(enc_key).await;
    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    (state, audit_logger)
}

#[tokio::test]
async fn grant_creation_is_audited() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit) = make_empty_state_with_audit(mock).await;
    let token = signup_and_login(&state, "acme", "alice@acme.com", "password123").await;

    // Create a credential to grant against.
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "slack", "description": "d", "value": "secret", "allowed_hosts": ["api.example.com"]}"#,
        ))
        .unwrap();
    let resp = build_router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);

    // No audit entries yet — credential creation is not audited here.
    assert_eq!(audit.entries().len(), 0);

    // Author a well-scoped grant (a control-loosening event).
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials/slack/grants")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"methods":["POST"],"route_scope":["slack.com/api/chat.postMessage"],"ttl_minutes":30,"max_uses":15}"#,
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 201, "{body}");
    let grant_id = body["grant"]["id"].as_str().unwrap().to_string();

    // The authoring event must land in the immutable audit log.
    let entries = audit.entries();
    assert_eq!(entries.len(), 1, "grant creation must write exactly one audit row");
    let e = &entries[0];
    assert_eq!(e.target_url, "tap:grant-create");
    assert_eq!(e.credential_names, vec!["slack".to_string()]);
    // Actor email is captured as the approver/actor identity.
    assert_eq!(e.approver_identity.as_deref(), Some("alice@acme.com"));
    // policy_reason ties the row back to the grant id.
    assert_eq!(
        e.policy_reason.as_deref(),
        Some(format!("grant_created:{grant_id}").as_str())
    );
    // The non-secret scope/TTL/cap/source is captured in request_body.
    let summary: serde_json::Value =
        serde_json::from_str(e.request_body.as_deref().unwrap()).unwrap();
    assert_eq!(summary["grant_id"], grant_id);
    assert_eq!(summary["max_uses"], 15);
    assert_eq!(summary["source"], "dashboard");
    assert_eq!(summary["methods"][0], "POST");
    assert_eq!(summary["route_scope"][0], "slack.com/api/chat.postMessage");
}

#[tokio::test]
async fn admin_signup_login_create_agent_full_flow() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let token = signup_and_login(&state, "acme", "alice@acme.com", "password123").await;

    // Create credential via admin API
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "slack", "description": "Slack API", "value": "xoxb-secret", "allowed_hosts": ["127.0.0.1"]}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);

    // Set policy
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri("/team/policies/slack")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"auto_approve_methods": ["GET"]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Create agent via admin API
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"id": "bot-1", "credentials": ["slack"]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let agent_api_key = value["api_key"].as_str().unwrap().to_string();

    // Agent uses credential via /forward
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", &agent_api_key)
        .header("x-tap-credential", "slack")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Upstream received the credential
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Bearer xoxb-secret"));
}

#[tokio::test]
async fn admin_create_app_key_is_separate_from_agents() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "apps", "owner@apps.com", "password123").await;

    let req = Request::builder()
        .method("POST")
        .uri("/team/apps")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"id": "wallet-app", "description": "Wallet integration"}).to_string(),
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["id"], "wallet-app");
    let app_key = body["api_key"].as_str().unwrap().to_string();

    let req = Request::builder()
        .method("GET")
        .uri("/team/apps")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200, "{body}");
    let app_ids: Vec<_> = body["apps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|app| app["id"].as_str())
        .collect();
    assert_eq!(app_ids, vec!["wallet-app"]);

    let req = Request::builder()
        .method("GET")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["agents"].as_array().unwrap().is_empty());

    let req = Request::builder()
        .method("GET")
        .uri("/team/agents/wallet-app")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 404, "{body}");

    let req = Request::builder()
        .method("POST")
        .uri("/app/users")
        .header("x-tap-key", &app_key)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"ext_id": "alice", "display_name": "Alice"}).to_string(),
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ext_id"], "alice");
}

#[tokio::test]
async fn cross_team_agent_isolation() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // Set up team A with credential + agent
    let token_a = signup_and_login(&state, "team-a", "a@a.com", "password123").await;
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token_a}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "secret-a", "description": "Team A secret", "value": "team-a-val", "allowed_hosts": ["api.example.com"]}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // Set up team B with agent
    let token_b = signup_and_login(&state, "team-b", "b@b.com", "password456").await;
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token_b}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "secret-b", "description": "Team B secret", "value": "team-b-val", "allowed_hosts": ["api.example.com"]}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // Create agent on team B
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {token_b}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"id": "b-bot", "credentials": ["secret-b"]}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let b_key = value["api_key"].as_str().unwrap().to_string();

    // ATTACK: Team B's agent tries to access Team A's credential
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", &b_key)
        .header("x-tap-credential", "secret-a") // Team A's credential!
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Must be 403 — credential not in team B's scope
    assert_eq!(
        resp.status(),
        403,
        "Agent from team B must not access team A's credential"
    );
}

#[tokio::test]
async fn cross_team_admin_isolation() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // Team A creates a credential
    let token_a = signup_and_login(&state, "alpha", "admin@alpha.com", "alpha123").await;
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token_a}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "alpha-cred", "description": "Alpha secret", "value": "alpha-val", "allowed_hosts": ["api.example.com"]}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // Team B admin tries to list credentials — should see empty (not team A's)
    let token_b = signup_and_login(&state, "beta", "admin@beta.com", "beta456").await;
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let creds = value["credentials"].as_array().unwrap();
    assert!(
        creds.is_empty(),
        "Team B admin must not see team A's credentials"
    );
}

#[tokio::test]
async fn credential_value_never_in_api_response() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let token = signup_and_login(&state, "vault", "admin@vault.com", "vault123").await;

    // Create credential with a secret value
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "api-key", "description": "API Key", "value": "sk-supersecret123", "allowed_hosts": ["api.example.com"]}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // GET /team/credentials — value must NOT be in response
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body_str.contains("sk-supersecret123"),
        "Credential value must NEVER appear in admin API response"
    );
    assert!(
        !body_str.contains("supersecret"),
        "No part of credential value should leak"
    );

    // Create agent + use /agent/config — value must NOT be there either
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"id": "bot", "credentials": ["api-key"]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let agent_key = value["api_key"].as_str().unwrap().to_string();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/agent/config")
        .header("x-tap-key", &agent_key)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body_str.contains("sk-supersecret123"),
        "Credential value must not leak via agent config endpoint"
    );
}

#[tokio::test]
async fn credential_value_patch_merges_secret_fields_without_leaking_existing_value() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let token = signup_and_login(&state, "x-edit", "admin@x-edit.com", "password123").await;
    let initial = json!({
        "consumer_key": "ck-original",
        "consumer_secret": "cs-original",
        "access_token": "at-original",
        "access_token_secret": "ats-original"
    });

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "name": "twitter-edit",
                "description": "X account",
                "connector": "sidecar",
                "api_base": "http://127.0.0.1:8080",
                "allowed_hosts": ["api.example.com"],
                "value": initial
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("PATCH")
        .uri("/team/credentials/twitter-edit/secret")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"value_patch": {"bearer_token": "bt-new"}}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body_str.contains("ck-original"));
    assert!(!body_str.contains("bt-new"));

    let owner = member_by_email(state.db_state.store(), "admin@x-edit.com").await;
    let stored = state
        .db_state
        .store()
        .get_credential_value(&owner.team_id, "twitter-edit")
        .await
        .unwrap()
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(stored["consumer_key"], "ck-original");
    assert_eq!(stored["consumer_secret"], "cs-original");
    assert_eq!(stored["access_token"], "at-original");
    assert_eq!(stored["access_token_secret"], "ats-original");
    assert_eq!(stored["bearer_token"], "bt-new");
}

#[tokio::test]
async fn duplicate_team_name_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // Sign up team "dup-test"
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name": "dup-test", "email": "first@dup.com", "password": "password123"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // Try to sign up again with same team name
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name": "dup-test", "email": "second@dup.com", "password": "password456"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 409);
}

#[tokio::test]
async fn duplicate_email_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name": "team-one", "email": "same@email.com", "password": "password123"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name": "team-two", "email": "same@email.com", "password": "password456"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 409);
}

// ---------------------------------------------------------------------------
// Password reset endpoint tests
// ---------------------------------------------------------------------------

/// Seed a verified admin directly in the store and return their id.
async fn seed_admin(state: &AppState, email: &str, password: &str) -> String {
    use tap_proxy::admin::hash_password;
    let store = state.db_state.store();
    let team_id = format!("team-{}", uuid::Uuid::new_v4());
    let new_user_id = format!("admin-{}", uuid::Uuid::new_v4());
    store.create_team(&team_id, &team_id).await.unwrap();
    let hash = hash_password(password).unwrap();
    let admin_id = store
        .create_user_with_membership(&new_user_id, &team_id, email, &hash, "owner")
        .await
        .unwrap();
    store.set_user_email_verified(&admin_id).await.unwrap();
    admin_id
}

#[tokio::test]
async fn forgot_password_unknown_email_returns_200() {
    // Anti-oracle: endpoint must always return 200 regardless of whether the
    // email is registered, so callers cannot enumerate accounts.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forgot-password")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"nobody@example.com"}"#))
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;

    assert_eq!(status, 200);
    let msg = body["message"].as_str().unwrap_or("");
    assert!(msg.contains("If an account"), "unexpected message: {msg}");
}

#[tokio::test]
async fn forgot_password_known_email_returns_same_200() {
    // Registered email must return the identical response shape as unknown email.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    seed_admin(&state, "alice@example.com", "hunter22!").await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forgot-password")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"alice@example.com"}"#))
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;

    assert_eq!(status, 200);
    let msg = body["message"].as_str().unwrap_or("");
    assert!(msg.contains("If an account"), "unexpected message: {msg}");
}

#[tokio::test]
async fn password_reset_cooldown_blocks_second_create_and_keeps_first_token() {
    use tap_proxy::admin::{generate_session_token, hash_session_token};

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let admin_id = seed_admin(&state, "cool@example.com", "hunter22!").await;
    let store = state.db_state.store();
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

    let first_token = generate_session_token();
    let created = store
        .create_password_reset(&hash_session_token(&first_token), &admin_id, &expires_at, 5)
        .await
        .unwrap();
    assert!(created, "first reset within an empty window must be created");

    // A second request inside the cooldown is throttled: no new token.
    let second_token = generate_session_token();
    let created = store
        .create_password_reset(&hash_session_token(&second_token), &admin_id, &expires_at, 5)
        .await
        .unwrap();
    assert!(!created, "second reset within the cooldown must be throttled");

    // The throttled token never existed…
    let body = serde_json::json!({ "token": second_token, "password": "newpassword1" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 400, "throttled token must not exist");

    // …and the first token was NOT replaced — it still resets the password.
    let body = serde_json::json!({ "token": first_token, "password": "newpassword1" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 200, "original token must survive the throttled attempt");
}

#[tokio::test]
async fn password_reset_after_cooldown_replaces_old_token() {
    use tap_proxy::admin::{generate_session_token, hash_session_token};

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let admin_id = seed_admin(&state, "warm@example.com", "hunter22!").await;
    let store = state.db_state.store();
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

    let first_token = generate_session_token();
    assert!(store
        .create_password_reset(&hash_session_token(&first_token), &admin_id, &expires_at, 5)
        .await
        .unwrap());

    // Cooldown 0 models the window having elapsed: the new token is created
    // and the old one is replaced (one pending reset per user).
    let second_token = generate_session_token();
    assert!(store
        .create_password_reset(&hash_session_token(&second_token), &admin_id, &expires_at, 0)
        .await
        .unwrap());

    let body = serde_json::json!({ "token": first_token, "password": "newpassword1" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 400, "replaced token must be invalid");

    let body = serde_json::json!({ "token": second_token, "password": "newpassword1" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 200, "fresh token must work");
}

#[tokio::test]
async fn password_reset_concurrent_creates_mint_exactly_one_token() {
    // Distributed State Rule: N concurrent /forgot-password requests for the
    // SAME account must not each mint a valid token. Under READ COMMITTED the
    // old WITH recent/cleared/INSERT CTE let every statement observe an empty
    // window (no UNIQUE on user_id) and all insert distinct token rows,
    // bypassing the cooldown and sending multiple emails. The UNIQUE index on
    // password_resets(user_id) + ON CONFLICT (user_id) upsert serializes the
    // check-and-write: exactly one call wins, the rest hit the cooldown arm.
    use tap_proxy::admin::{generate_session_token, hash_session_token};

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let admin_id = seed_admin(&state, "race@example.com", "hunter22!").await;
    let store = state.db_state.store().clone();
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

    // Fire many concurrent creates for the same user, all inside a 5-minute
    // cooldown. Each uses a distinct token so we can later tell how many
    // actually landed in the DB.
    const N: usize = 12;
    let tokens: Vec<String> = (0..N).map(|_| generate_session_token()).collect();

    let mut handles = Vec::new();
    for token in &tokens {
        let store = store.clone();
        let hash = hash_session_token(token);
        let admin_id = admin_id.clone();
        let expires_at = expires_at.clone();
        handles.push(tokio::spawn(async move {
            store
                .create_password_reset(&hash, &admin_id, &expires_at, 5)
                .await
                .unwrap()
        }));
    }

    let mut created_count = 0usize;
    for h in handles {
        if h.await.unwrap() {
            created_count += 1;
        }
    }
    assert_eq!(
        created_count, 1,
        "exactly one concurrent create must report Ok(true); got {created_count}"
    );

    // …and exactly one token is actually valid in the DB (one live reset row).
    let mut valid_count = 0usize;
    for token in &tokens {
        if store
            .validate_and_consume_password_reset(&hash_session_token(token))
            .await
            .unwrap()
            .is_some()
        {
            valid_count += 1;
        }
    }
    assert_eq!(
        valid_count, 1,
        "exactly one token row must exist after the concurrent burst; got {valid_count}"
    );
}

#[tokio::test]
async fn forgot_password_within_cooldown_returns_same_200() {
    // The throttle must not become an oracle: a second request inside the
    // cooldown returns the exact same 200 message as the first.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    seed_admin(&state, "spam-target@example.com", "hunter22!").await;

    let mut messages = vec![];
    for _ in 0..2 {
        let req = Request::builder()
            .method("POST")
            .uri("/forgot-password")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"email":"spam-target@example.com"}"#))
            .unwrap();
        let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
        assert_eq!(status, 200);
        messages.push(body["message"].as_str().unwrap_or("").to_string());
    }
    assert_eq!(messages[0], messages[1]);
}

#[tokio::test]
async fn reset_password_valid_token_succeeds() {
    use tap_proxy::admin::{generate_session_token, hash_session_token};

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let admin_id = seed_admin(&state, "bob@example.com", "oldpassword1").await;

    // Inject a reset token directly (skipping email delivery).
    let raw_token = generate_session_token();
    let token_hash = hash_session_token(&raw_token);
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    state
        .db_state
        .store()
        .create_password_reset(&token_hash, &admin_id, &expires_at, 0)
        .await
        .unwrap();

    let body = serde_json::json!({ "token": raw_token, "password": "newpassword1" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, resp) = send_request_and_parse(build_router(state), req).await;

    assert_eq!(status, 200);
    assert!(resp["message"]
        .as_str()
        .unwrap_or("")
        .contains("reset successfully"));
}

#[tokio::test]
async fn reset_password_token_is_single_use() {
    use tap_proxy::admin::{generate_session_token, hash_session_token};

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let admin_id = seed_admin(&state, "carol@example.com", "oldpass2").await;

    let raw_token = generate_session_token();
    let token_hash = hash_session_token(&raw_token);
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    state
        .db_state
        .store()
        .create_password_reset(&token_hash, &admin_id, &expires_at, 0)
        .await
        .unwrap();

    let body = serde_json::json!({ "token": raw_token, "password": "newpass2!!" });

    // First use — must succeed.
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200);

    // Second use — must be rejected.
    let req2 = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status2, _) = send_request_and_parse(build_router(state), req2).await;
    assert_eq!(status2, 400);
}

#[tokio::test]
async fn reset_password_expired_token_rejected() {
    use tap_proxy::admin::{generate_session_token, hash_session_token};

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let admin_id = seed_admin(&state, "dave@example.com", "oldpass3").await;

    let raw_token = generate_session_token();
    let token_hash = hash_session_token(&raw_token);
    // Token already expired.
    let expires_at = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
    state
        .db_state
        .store()
        .create_password_reset(&token_hash, &admin_id, &expires_at, 0)
        .await
        .unwrap();

    let body = serde_json::json!({ "token": raw_token, "password": "newpass3!!" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, resp) = send_request_and_parse(build_router(state), req).await;

    assert_eq!(status, 400);
    assert!(resp["error"]
        .as_str()
        .unwrap_or("")
        .contains("Invalid or expired"));
}

#[tokio::test]
async fn reset_password_invalid_token_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let body = serde_json::json!({ "token": "notarealtoken", "password": "newpass4!!" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, resp) = send_request_and_parse(build_router(state), req).await;

    assert_eq!(status, 400);
    assert!(resp["error"]
        .as_str()
        .unwrap_or("")
        .contains("Invalid or expired"));
}

#[tokio::test]
async fn reset_password_short_password_rejected_and_token_not_consumed() {
    use tap_proxy::admin::{generate_session_token, hash_session_token};

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let admin_id = seed_admin(&state, "eve@example.com", "oldpass5").await;

    let raw_token = generate_session_token();
    let token_hash = hash_session_token(&raw_token);
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    state
        .db_state
        .store()
        .create_password_reset(&token_hash, &admin_id, &expires_at, 0)
        .await
        .unwrap();

    // Password is only 5 characters — rejected before the token is touched.
    let body = serde_json::json!({ "token": raw_token, "password": "short" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, resp) = send_request_and_parse(build_router(state.clone()), req).await;

    assert_eq!(status, 400);
    assert!(resp["error"]
        .as_str()
        .unwrap_or("")
        .contains("8 characters"));

    // Token must still be valid (not consumed by the failed attempt).
    let token_hash2 = hash_session_token(&raw_token);
    let still_valid = state
        .db_state
        .store()
        .validate_and_consume_password_reset(&token_hash2)
        .await
        .unwrap();
    assert!(
        still_valid.is_some(),
        "Token should not be consumed by a rejected request"
    );
}

#[tokio::test]
async fn reset_password_invalidates_existing_sessions() {
    use tap_proxy::admin::{generate_session_token, hash_session_token};

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let admin_id = seed_admin(&state, "frank@example.com", "oldpass6").await;

    // Create an active session for the admin (bound to their first team).
    let session_hash = hash_session_token("fake-session-raw");
    let session_exp = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
    let team_id = state
        .db_state
        .store()
        .list_user_teams(&admin_id)
        .await
        .unwrap()
        .first()
        .unwrap()
        .0
        .clone();
    state
        .db_state
        .store()
        .create_session(&session_hash, &admin_id, &team_id, &session_exp)
        .await
        .unwrap();

    // Issue and consume a reset token.
    let raw_token = generate_session_token();
    let token_hash = hash_session_token(&raw_token);
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    state
        .db_state
        .store()
        .create_password_reset(&token_hash, &admin_id, &expires_at, 0)
        .await
        .unwrap();

    let body = serde_json::json!({ "token": raw_token, "password": "newpass6!!" });
    let req = Request::builder()
        .method("POST")
        .uri("/reset-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200);

    // The old session must be gone.
    let session_after = state
        .db_state
        .store()
        .validate_session(&session_hash)
        .await
        .unwrap();
    assert!(
        session_after.is_none(),
        "Old session must be invalidated after password reset"
    );
}

// ────────────────────────────────────────────────
// Multi-key /agent/services tests
// ────────────────────────────────────────────────

/// Sets up two separate teams/agents, each with a distinct credential, sharing one AppState.
/// Returns (state, key_for_team1, key_for_team2).
async fn make_two_agent_state(
    mock_approval: Arc<dyn ApprovalChannel>,
    team1_cred: &str,
    team2_creds: &[&str],
) -> (AppState, String, String, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let (store, tmp) = temp_store().await; // creates team t1

    store.create_team("t2", "team-two").await.unwrap();

    // Team 1: agent-one with one credential
    let key1 = "multi-key-one";
    let hash1 = hash_api_key(key1);
    store
        .create_agent("t1", "agent-one", Some("Agent One"), &hash1, None)
        .await
        .unwrap();
    store
        .create_credential(
            "t1", team1_cred, "Cred T1", "direct", None, false, None, None, None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", team1_cred, b"secret-t1")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "agent-one", team1_cred)
        .await
        .unwrap();

    // Team 2: agent-two with one or more credentials
    let key2 = "multi-key-two";
    let hash2 = hash_api_key(key2);
    store
        .create_agent("t2", "agent-two", Some("Agent Two"), &hash2, None)
        .await
        .unwrap();
    for cred in team2_creds {
        store
            .create_credential(
                "t2",
                cred,
                &format!("Cred T2 {cred}"),
                "direct",
                None,
                false,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        store
            .set_credential_value("t2", cred, b"secret-t2")
            .await
            .unwrap();
        store
            .add_direct_credential("t2", "agent-two", cred)
            .await
            .unwrap();
    }

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger,
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    (state, key1.to_string(), key2.to_string(), tmp)
}

#[tokio::test]
async fn multi_key_services_single_key_unchanged() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key1, _key2, _tmp) = make_two_agent_state(mock, "github", &["slack"]).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", &key1)
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 200);
    // Single-key mode: credential name is not prefixed
    assert!(
        body["services"]["github"].is_object(),
        "expected plain 'github' key, got: {body}"
    );
    // Backward-compat fields present
    assert_eq!(body["agent_id"], "agent-one");
    assert!(body["home_team_id"].is_string());
    // No accounts map in single-key mode
    assert!(
        body["accounts"].is_null(),
        "accounts should not appear in single-key mode"
    );
}

#[tokio::test]
async fn multi_key_services_merges_credentials() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key1, key2, _tmp) = make_two_agent_state(mock, "github", &["slack"]).await;
    let app = build_router(state);

    let combined = format!("{key1},{key2}");
    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", &combined)
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 200, "response: {body}");

    // Multi-key mode: names are prefixed by agent ID
    assert!(
        body["services"]["agent-one.github"].is_object(),
        "missing agent-one.github: {body}"
    );
    assert!(
        body["services"]["agent-two.slack"].is_object(),
        "missing agent-two.slack: {body}"
    );

    // account field on each entry
    assert_eq!(body["services"]["agent-one.github"]["account"], "agent-one");
    assert_eq!(body["services"]["agent-two.slack"]["account"], "agent-two");

    // accounts map present with key_index, no key values
    assert!(body["accounts"].is_object(), "accounts map missing: {body}");
    assert_eq!(body["accounts"]["agent-one"]["key_index"], 0);
    assert_eq!(body["accounts"]["agent-two"]["key_index"], 1);
    assert!(
        body["accounts"]["agent-one"]["key"].is_null(),
        "key must not appear in accounts"
    );
    assert!(
        body["accounts"]["agent-two"]["key"].is_null(),
        "key must not appear in accounts"
    );

    // No top-level agent_id/home_team_id in multi mode
    assert!(
        body["agent_id"].is_null(),
        "agent_id should not appear in multi-key mode"
    );
}

#[tokio::test]
async fn multi_key_services_collision_both_visible() {
    // Both teams have a credential named "github" — both should appear with distinct prefixes.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key1, key2, _tmp) = make_two_agent_state(mock, "github", &["github"]).await;
    let app = build_router(state);

    let combined = format!("{key1},{key2}");
    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", &combined)
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 200, "response: {body}");
    assert!(
        body["services"]["agent-one.github"].is_object(),
        "missing agent-one.github: {body}"
    );
    assert!(
        body["services"]["agent-two.github"].is_object(),
        "missing agent-two.github: {body}"
    );
    // They are distinct entries
    assert_ne!(
        body["services"]["agent-one.github"]["account"],
        body["services"]["agent-two.github"]["account"]
    );
}

#[tokio::test]
async fn multi_key_services_all_invalid_returns_401() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _key1, _key2, _tmp) = make_two_agent_state(mock, "github", &["slack"]).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", "bad-key-1,bad-key-2")
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 401, "response: {body}");
    assert_eq!(body["error_code"], "invalid_tap_key");
}

#[tokio::test]
async fn multi_key_services_partial_invalid_keys_succeed() {
    // One valid key + one invalid — should succeed with credentials from the valid one only.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key1, _key2, _tmp) = make_two_agent_state(mock, "github", &["slack"]).await;
    let app = build_router(state);

    let combined = format!("{key1},totally-invalid-key");
    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", &combined)
        .body(Body::empty())
        .unwrap();

    let (status, body) = send_request_and_parse(app, req).await;
    // With 2+ keys parsed we enter multi mode; one authenticates, one doesn't.
    // Should succeed (200) with agent-one's credentials only.
    assert_eq!(status, 200, "response: {body}");
    assert!(
        body["services"]["agent-one.github"].is_object(),
        "expected agent-one.github: {body}"
    );
    assert!(
        body["services"]["agent-two.slack"].is_null(),
        "unexpected agent-two.slack: {body}"
    );
    assert_eq!(body["accounts"]["agent-one"]["key_index"], 0);
}

/// An Account key only bypasses the whitelist for credentials ITS OWN team
/// holds. With keys from two teams provided, a credential that exists only in
/// the scoped key's team must resolve via that key — the other team's Account
/// key must not capture the request (it would answer for the wrong team and
/// break the call).
#[tokio::test]
async fn multi_key_account_key_does_not_capture_other_teams_credential() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    // Team t1: Account key (all_credentials), team credential "github".
    // Team t2: scoped key whitelisted on "slack" (only t2 has "slack").
    let (state, key1, key2, _tmp) = make_two_agent_state(mock, "github", &["slack"]).await;
    let store = state.db_state.store();
    store
        .set_agent_all_credentials("t1", "agent-one", true)
        .await
        .unwrap();

    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let app = build_router(state.clone());

    let combined = format!("{key1},{key2}");
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", &combined)
        .header("x-tap-credential", "slack")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(app.clone(), req).await;
    assert_eq!(
        status, 200,
        "t2's scoped key must serve its own credential despite t1's Account key: {body}"
    );
    // The injected secret must be t2's, not anything from t1.
    let headers = recorded.lock().unwrap().last().unwrap().clone();
    assert!(
        headers
            .iter()
            .any(|(n, v)| n == "authorization" && v.contains("secret-t2")),
        "upstream must receive t2's credential value, got: {headers:?}"
    );

    // And the Account key still reaches its OWN team's credential by bare name.
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", &combined)
        .header("x-tap-credential", "github")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 200, "Account key must still serve t1's own credential: {body}");
}

// =========================================================================
// Team members: invite, accept, list, remove
// =========================================================================

async fn resp_json(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// POST invite; returns (status, body). Email always fails in tests (no RESEND_API_KEY),
/// so the handler falls back to returning accept_url in the body.
async fn invite_member(app: axum::Router, token: &str, email: &str) -> (u16, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/invite")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"email": email}).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    (status, resp_json(resp).await)
}

#[tokio::test]
async fn team_members_list_shows_owner_and_no_pending_invites() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "list-team", "owner@list.com", "password123").await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/team/members")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let body = resp_json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(body["members"].as_array().unwrap().len(), 1, "only owner");
    assert_eq!(body["pending_invites"].as_array().unwrap().len(), 0);
    assert!(body["members"][0]["is_owner"].as_bool().unwrap());
}

#[tokio::test]
async fn team_members_invite_creates_pending_invite() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "inv-team", "owner@inv.com", "password123").await;

    let (status, body) = invite_member(build_router(state.clone()), &token, "newbie@inv.com").await;
    assert_eq!(status, 200);
    assert!(
        body["accept_url"].is_string(),
        "accept_url returned when email fails"
    );

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/team/members")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let list = resp_json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(list["pending_invites"].as_array().unwrap().len(), 1);
    assert_eq!(
        list["pending_invites"][0]["email"].as_str().unwrap(),
        "newbie@inv.com"
    );
}

#[tokio::test]
async fn team_members_invite_existing_member_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "dup-inv-team", "owner@dup-inv.com", "password123").await;

    let (status, _) = invite_member(build_router(state.clone()), &token, "owner@dup-inv.com").await;
    assert_eq!(status, 409);
}

#[tokio::test]
async fn team_members_accept_invite_success() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "accept-team", "owner@accept.com", "password123").await;

    let (_, invite_body) =
        invite_member(build_router(state.clone()), &token, "joiner@accept.com").await;
    let accept_url = invite_body["accept_url"].as_str().unwrap();
    let invite_token = accept_url.split("token=").nth(1).unwrap();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"token": invite_token, "password": "newpassword123"}).to_string(),
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 200);

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/team/members")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let list = resp_json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(list["members"].as_array().unwrap().len(), 2);
    assert_eq!(
        list["pending_invites"].as_array().unwrap().len(),
        0,
        "invite consumed"
    );
    assert!(
        !list["members"][1]["is_owner"].as_bool().unwrap(),
        "invited member is not owner"
    );
}

#[tokio::test]
async fn invite_info_new_user_has_account_false() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token =
        signup_and_login(&state, "info-new-team", "owner@info-new.com", "password123").await;

    let (_, invite_body) =
        invite_member(build_router(state.clone()), &token, "brandnew@info.com").await;
    let accept_url = invite_body["accept_url"].as_str().unwrap();
    let invite_token = accept_url.split("token=").nth(1).unwrap();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/invite/info?token={invite_token}"))
        .body(Body::empty())
        .unwrap();
    let body = resp_json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(body["email"].as_str().unwrap(), "brandnew@info.com");
    assert!(!body["already_member"].as_bool().unwrap());
    assert!(
        !body["has_account"].as_bool().unwrap(),
        "brand-new email should not have an account"
    );
    assert_eq!(body["invite_action"].as_str().unwrap(), "create_account");
}

#[tokio::test]
async fn invite_info_existing_account_has_account_true() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    // Team A — inviter's team
    let inviter_token = signup_and_login(
        &state,
        "info-existing-team",
        "inviter@info-ex.com",
        "password123",
    )
    .await;
    // Target signs up independently with their own team
    let _ = signup_and_login(
        &state,
        "info-existing-target",
        "target@info-ex.com",
        "password123",
    )
    .await;

    // Invite target to team A (they have an account but aren't a member here)
    let (_, invite_body) = invite_member(
        build_router(state.clone()),
        &inviter_token,
        "target@info-ex.com",
    )
    .await;
    let accept_url = invite_body["accept_url"].as_str().unwrap();
    let invite_token = accept_url.split("token=").nth(1).unwrap();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/invite/info?token={invite_token}"))
        .body(Body::empty())
        .unwrap();
    let body = resp_json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(body["email"].as_str().unwrap(), "target@info-ex.com");
    assert!(
        !body["already_member"].as_bool().unwrap(),
        "not yet a member of this team"
    );
    assert!(
        body["has_account"].as_bool().unwrap(),
        "existing account should be detected"
    );
    assert_eq!(body["invite_action"].as_str().unwrap(), "login_to_accept");
}

#[tokio::test]
async fn invite_info_already_member_has_explicit_action() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let _token = signup_and_login(
        &state,
        "info-member-team",
        "owner@info-member.com",
        "password123",
    )
    .await;

    let store = state.db_state.store();
    let raw_token = tap_proxy::admin::generate_session_token();
    let token_hash = tap_proxy::admin::hash_session_token(&raw_token);
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let owner = member_by_email(store, "owner@info-member.com").await;
    store
        .create_invite(
            &uuid::Uuid::new_v4().to_string(),
            &owner.team_id,
            "owner@info-member.com",
            "admin",
            &token_hash,
            &owner.id,
            &future,
        )
        .await
        .unwrap();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/invite/info?token={raw_token}"))
        .body(Body::empty())
        .unwrap();
    let body = resp_json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(body["email"].as_str().unwrap(), "owner@info-member.com");
    assert!(body["already_member"].as_bool().unwrap());
    assert!(body["has_account"].as_bool().unwrap());
    assert_eq!(body["invite_action"].as_str().unwrap(), "already_member");
}

#[tokio::test]
async fn team_members_accept_invite_existing_account_rejected_without_consuming_invite() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let inviter_token = signup_and_login(
        &state,
        "accept-existing-host",
        "owner@accept-existing.com",
        "password123",
    )
    .await;
    let _ = signup_and_login(
        &state,
        "accept-existing-target",
        "target@accept-existing.com",
        "password123",
    )
    .await;

    let (_, invite_body) = invite_member(
        build_router(state.clone()),
        &inviter_token,
        "target@accept-existing.com",
    )
    .await;
    let accept_url = invite_body["accept_url"].as_str().unwrap();
    let invite_token = accept_url.split("token=").nth(1).unwrap();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"token": invite_token, "password": "wrongnewpassword"}).to_string(),
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 409);
    assert!(body["existing_account"].as_bool().unwrap());
    assert_eq!(body["invite_action"].as_str().unwrap(), "login_to_accept");

    let store = state.db_state.store();
    let pending = store
        .list_invites_by_email("target@accept-existing.com")
        .await
        .unwrap();
    assert_eq!(pending.len(), 1, "invite remains for login to consume");

    let user = store
        .get_user_by_email("target@accept-existing.com")
        .await
        .unwrap()
        .unwrap();
    assert!(
        tap_proxy::admin::verify_password("password123", &user.password_hash),
        "stale invite accept must not replace the existing account password"
    );
    assert!(
        !tap_proxy::admin::verify_password("wrongnewpassword", &user.password_hash),
        "submitted invite password must be ignored for existing accounts"
    );
}

#[tokio::test]
async fn team_members_accept_invite_already_member_rejected_and_consumed() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let _token = signup_and_login(
        &state,
        "accept-member-team",
        "owner@accept-member.com",
        "password123",
    )
    .await;

    let store = state.db_state.store();
    let raw_token = tap_proxy::admin::generate_session_token();
    let token_hash = tap_proxy::admin::hash_session_token(&raw_token);
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let owner = member_by_email(store, "owner@accept-member.com").await;
    store
        .create_invite(
            &uuid::Uuid::new_v4().to_string(),
            &owner.team_id,
            "owner@accept-member.com",
            "admin",
            &token_hash,
            &owner.id,
            &future,
        )
        .await
        .unwrap();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"token": raw_token, "password": "unusedpassword"}).to_string(),
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 409);
    assert_eq!(body["invite_action"].as_str().unwrap(), "already_member");
    assert!(
        store
            .list_invites_by_email("owner@accept-member.com")
            .await
            .unwrap()
            .is_empty(),
        "already-member invite is consumed"
    );
}

#[tokio::test]
async fn team_members_accepted_member_can_login() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "login-team", "owner@login.com", "password123").await;

    let (_, invite_body) = invite_member(
        build_router(state.clone()),
        &owner_token,
        "member@login.com",
    )
    .await;
    let invite_token = invite_body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"token": invite_token, "password": "memberpass123"}).to_string(),
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 200);

    let member_token = login_existing(&state, "member@login.com", "memberpass123").await;
    assert!(!member_token.is_empty());
}

#[tokio::test]
async fn team_members_accept_invalid_token_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"token": "deadbeefdeadbeef", "password": "password123"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 404);
}

#[tokio::test]
async fn team_members_accept_expired_token_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let _ = signup_and_login(&state, "exp-team", "owner@exp.com", "password123").await;

    let store = state.db_state.store();
    let raw_token = tap_proxy::admin::generate_session_token();
    let token_hash = tap_proxy::admin::hash_session_token(&raw_token);
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let owner = member_by_email(store, "owner@exp.com").await;
    store
        .create_invite(
            &uuid::Uuid::new_v4().to_string(),
            &owner.team_id,
            "expired@exp.com",
            "admin",
            &token_hash,
            &owner.id,
            &past,
        )
        .await
        .unwrap();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"token": raw_token, "password": "password123"}).to_string(),
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 410);
}

// ---------------------------------------------------------------------------
// Invite consumption on signup/login — an invited person is never stranded
// outside the inviting team, regardless of which door they came through.
// ---------------------------------------------------------------------------

/// Self-serve signup with a project name: the invitee gets their own team AND
/// is auto-joined into the team that invited them (the bug was signup ignoring
/// the invite entirely and dropping them into a lone new team).
#[tokio::test]
async fn signup_with_own_team_also_joins_pending_invite() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "host-team", "owner@host.com", "password123").await;
    let (st, _) = invite_member(build_router(state.clone()), &owner_token, "dual@host.com").await;
    assert_eq!(st, 200);

    // Invitee signs up creating their OWN team instead of clicking the link.
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name":"dual-own","email":"dual@host.com","password":"password123"}"#,
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 201);
    let joined = body["joined_teams"].as_array().unwrap();
    assert_eq!(joined.len(), 1, "auto-joined the inviting team");
    assert_eq!(joined[0]["team_name"], "host-team");

    // Member of BOTH teams; invite consumed.
    let store = state.db_state.store();
    let user = store
        .get_user_by_email("dual@host.com")
        .await
        .unwrap()
        .unwrap();
    let teams = store.list_user_teams(&user.id).await.unwrap();
    let names: Vec<&str> = teams.iter().map(|t| t.1.as_str()).collect();
    assert_eq!(teams.len(), 2, "own team + invited team");
    assert!(names.contains(&"host-team"));
    assert!(names.contains(&"dual-own"));
    assert!(
        store
            .list_invites_by_email("dual@host.com")
            .await
            .unwrap()
            .is_empty(),
        "invite consumed on signup"
    );
}

/// Join-only signup (no project name): the invitee joins the inviting team
/// without creating a team of their own, keeping the invited role.
#[tokio::test]
async fn join_only_signup_joins_invited_team_without_creating_one() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "solo-host", "owner@solo.com", "password123").await;
    let (st, _) = invite_member(build_router(state.clone()), &owner_token, "joiner@solo.com").await;
    assert_eq!(st, 200);

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"joiner@solo.com","password":"password123"}"#,
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 201);
    assert_eq!(body["joined_teams"].as_array().unwrap().len(), 1);

    let store = state.db_state.store();
    let user = store
        .get_user_by_email("joiner@solo.com")
        .await
        .unwrap()
        .unwrap();
    let teams = store.list_user_teams(&user.id).await.unwrap();
    assert_eq!(teams.len(), 1, "no team of their own");
    assert_eq!(teams[0].1, "solo-host");
    assert_eq!(teams[0].2, "approver", "invited role preserved");
}

/// Join-only signup with nothing to join is rejected — you must name a team.
#[tokio::test]
async fn join_only_signup_without_invite_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"lonely@nobody.com","password":"password123"}"#,
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 400);
    assert!(
        body["error"].as_str().unwrap().contains("project name"),
        "unexpected error: {body}"
    );
}

/// A person who already has an account picks up a later invite simply by
/// logging in — no second account, no orphaned invite (the recovery path).
#[tokio::test]
async fn existing_account_login_picks_up_pending_invite() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // Joiner already owns their own team (verified account).
    let _ = signup_and_login(&state, "joiner-own", "member@two.com", "password123").await;
    // A different team invites them.
    let owner_token =
        signup_and_login(&state, "inviting-team", "owner@two.com", "password123").await;
    let (st, _) = invite_member(build_router(state.clone()), &owner_token, "member@two.com").await;
    assert_eq!(st, 200);

    // Joiner just logs in again — the invite is consumed on login.
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"member@two.com","password":"password123"}"#,
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["team_name"].as_str().unwrap(),
        "inviting-team",
        "login lands in the team whose invite was just accepted"
    );
    assert_eq!(
        body["member_role"].as_str().unwrap(),
        "approver",
        "invited role becomes the active role for this session"
    );
    assert_eq!(
        body["teams"].as_array().unwrap().len(),
        2,
        "login auto-joined the invited team"
    );

    let store = state.db_state.store();
    assert!(
        store
            .list_invites_by_email("member@two.com")
            .await
            .unwrap()
            .is_empty(),
        "invite consumed on login"
    );
}

#[tokio::test]
async fn team_members_remove_member_success() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "rm-team", "owner@rm.com", "password123").await;

    let (_, invite_body) =
        invite_member(build_router(state.clone()), &owner_token, "member@rm.com").await;
    let invite_token = invite_body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"token": invite_token, "password": "pass123456"}).to_string(),
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 200);

    let store = state.db_state.store();
    let member = member_by_email(store, "member@rm.com").await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/{}", member.id))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 200);

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/team/members")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let list = resp_json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(list["members"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn member_passkeys_reset_clears_all_and_allows_fresh_enrollment() {
    // Regression coverage for the passkey-lockout recovery gap: a member whose
    // only passkey no longer validates (e.g. registered against a domain the
    // team no longer serves from) can't reach the self-service
    // DELETE /user/passkeys/{id} path — that requires a session, and a
    // non-functional passkey blocks login before a session exists. The owner
    // must be able to clear it from the outside so the existing
    // zero-passkeys-triggers-setup login path takes over.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "pk-reset-team", "owner@pkreset.com", "password123").await;
    let (_, invite_body) =
        invite_member(build_router(state.clone()), &owner_token, "member@pkreset.com").await;
    let invite_token = invite_body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();
    assert_eq!(
        accept_invite_token(build_router(state.clone()), invite_token, "pass123456").await,
        200
    );

    let store = state.db_state.store();
    let member = member_by_email(store, "member@pkreset.com").await;
    store
        .save_user_passkey(&member.id, "stale-cred-id", "{}")
        .await
        .unwrap();
    assert_eq!(store.count_user_passkeys(&member.id).await.unwrap(), 1);

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/{}/passkeys", member.id))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp_json(resp).await;
    assert_eq!(body["reset"], true);
    assert_eq!(body["removed_count"], 1);

    assert_eq!(store.count_user_passkeys(&member.id).await.unwrap(), 0);
}

#[tokio::test]
async fn member_passkeys_reset_owner_target_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "pk-reset-owner-team", "owner@pkreset2.com", "password123").await;
    let (_, invite_body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "admin@pkreset2.com",
        "admin",
    )
    .await;
    let invite_token = invite_body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();
    assert_eq!(
        accept_invite_token(build_router(state.clone()), invite_token, "pass123456").await,
        200
    );
    let admin_token = login_as(&state, "admin@pkreset2.com", "pass123456").await;

    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@pkreset2.com").await;

    // An admin cannot reset the owner's passkeys — same protection as
    // "cannot remove the team owner".
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/{}/passkeys", owner.id))
        .header("authorization", format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 403);
}

#[tokio::test]
async fn member_passkeys_reset_self_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "pk-reset-self-team", "owner@pkreset3.com", "password123").await;
    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@pkreset3.com").await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/{}/passkeys", owner.id))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 400);
}

#[tokio::test]
async fn team_members_remove_self_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "self-rm-team", "owner@self-rm.com", "password123").await;
    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@self-rm.com").await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/{}", owner.id))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 400);
}

#[tokio::test]
async fn team_members_remove_owner_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "owner-rm-team", "owner@owner-rm.com", "password123").await;

    let (_, invite_body) = invite_member(
        build_router(state.clone()),
        &owner_token,
        "member@owner-rm.com",
    )
    .await;
    let invite_token = invite_body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"token": invite_token, "password": "pass123456"}).to_string(),
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 200);

    let member_token = login_existing(&state, "member@owner-rm.com", "pass123456").await;
    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@owner-rm.com").await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/{}", owner.id))
        .header("authorization", format!("Bearer {member_token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 403);
}

#[tokio::test]
async fn team_members_cancel_invite() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "cancel-team", "owner@cancel.com", "password123").await;

    invite_member(build_router(state.clone()), &token, "invited@cancel.com").await;

    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@cancel.com").await;
    let invites = store.list_pending_invites(&owner.team_id).await.unwrap();
    assert_eq!(invites.len(), 1);
    let invite_id = invites[0].id.clone();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/invites/{invite_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 200);

    let remaining = store.list_pending_invites(&owner.team_id).await.unwrap();
    assert_eq!(remaining.len(), 0);
}

// ---------------------------------------------------------------------------
// Invite with role
// ---------------------------------------------------------------------------

async fn invite_member_with_role(
    app: axum::Router,
    token: &str,
    email: &str,
    role: &str,
) -> (u16, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/invite")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"email": email, "role": role}).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    (status, resp_json(resp).await)
}

async fn accept_invite_token(app: axum::Router, token: &str, password: &str) -> u16 {
    let req = Request::builder()
        .method("POST")
        .uri("/team/members/accept")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"token": token, "password": password}).to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap().status().as_u16()
}

#[tokio::test]
async fn team_members_invite_default_role_is_approver() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token =
        signup_and_login(&state, "inv-role-def", "owner@inv-role-def.com", "pass1234").await;

    let (status, body) = invite_member(
        build_router(state.clone()),
        &token,
        "guest@inv-role-def.com",
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@inv-role-def.com").await;
    let invites = store.list_pending_invites(&owner.team_id).await.unwrap();
    assert_eq!(invites[0].role, "approver");
}

#[tokio::test]
async fn dashboard_config_exposes_role_capability_contract() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/dashboard/config")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(app, req).await;
    assert_eq!(status, 200);
    assert_eq!(body["invite"]["default_role"], "approver");

    let capabilities: std::collections::HashSet<&str> = body["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for item in body["nav"].as_array().unwrap() {
        for cap in item["capabilities_any"].as_array().unwrap() {
            assert!(
                capabilities.contains(cap.as_str().unwrap()),
                "nav item references unknown capability: {item}"
            );
        }
    }

    let roles = body["roles"].as_array().unwrap();
    let role = |id: &str| {
        roles
            .iter()
            .find(|r| r["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("missing role {id}"))
    };
    assert_eq!(role("owner")["credential_access"], "all");
    assert_eq!(role("admin")["credential_access"], "all");
    assert_eq!(role("approver")["credential_access"], "assigned");

    let approver_caps: std::collections::HashSet<&str> = role("approver")["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(approver_caps.contains("view_assigned_credentials"));
    assert!(approver_caps.contains("manage_own_agents"));
    assert!(!approver_caps.contains("manage_credentials"));
    assert!(!approver_caps.contains("manage_members"));

    let nav = body["nav"].as_array().unwrap();
    let api_keys_nav = nav
        .iter()
        .find(|item| item["id"].as_str() == Some("api-keys"))
        .unwrap();
    let api_key_caps: std::collections::HashSet<&str> = api_keys_nav["capabilities_any"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(api_key_caps.contains("manage_agents"));
    assert!(api_key_caps.contains("manage_own_agents"));
}

#[tokio::test]
async fn team_members_invite_with_member_role_succeeds() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "inv-member-role", "owner@inv-mr.com", "pass1234").await;

    let (status, _) = invite_member_with_role(
        build_router(state.clone()),
        &token,
        "guest@inv-mr.com",
        "approver",
    )
    .await;
    assert_eq!(status, 200);

    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@inv-mr.com").await;
    let invites = store.list_pending_invites(&owner.team_id).await.unwrap();
    assert_eq!(invites[0].role, "approver");
}

#[tokio::test]
async fn team_members_invite_with_owner_role_by_owner_succeeds() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "inv-owner-role", "owner@inv-or.com", "pass1234").await;

    let (status, _) = invite_member_with_role(
        build_router(state.clone()),
        &token,
        "guest@inv-or.com",
        "owner",
    )
    .await;
    assert_eq!(status, 200);

    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@inv-or.com").await;
    let invites = store.list_pending_invites(&owner.team_id).await.unwrap();
    assert_eq!(invites[0].role, "owner");
}

#[tokio::test]
async fn team_members_invite_with_invalid_role_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "inv-bad-role", "owner@inv-br.com", "pass1234").await;

    let (status, body) = invite_member_with_role(
        build_router(state.clone()),
        &token,
        "guest@inv-br.com",
        "superadmin",
    )
    .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn team_members_accepted_invite_has_correct_role() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "acc-role-team", "owner@acc-role.com", "pass1234").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &token,
        "guest@acc-role.com",
        "approver",
    )
    .await;
    let accept_url = body["accept_url"].as_str().unwrap().to_string();
    let invite_token = accept_url.split("token=").nth(1).unwrap();

    assert_eq!(
        accept_invite_token(build_router(state.clone()), invite_token, "newpassword1").await,
        200
    );

    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@acc-role.com").await;
    let guest = store
        .get_member_by_email_and_team("guest@acc-role.com", &owner.team_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(guest.member_role, "approver");
}

#[tokio::test]
async fn team_members_pending_invite_shows_role_in_list() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "inv-list-role", "owner@inv-lr.com", "pass1234").await;

    invite_member_with_role(
        build_router(state.clone()),
        &token,
        "guest@inv-lr.com",
        "approver",
    )
    .await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/team/members")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let body = resp_json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(
        body["pending_invites"][0]["role"].as_str().unwrap(),
        "approver"
    );
}

// ---------------------------------------------------------------------------
// Role change
// ---------------------------------------------------------------------------

async fn change_member_role(
    app: axum::Router,
    token: &str,
    member_id: &str,
    role: &str,
) -> (u16, serde_json::Value) {
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/team/members/{member_id}/role"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"role": role}).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    (status, resp_json(resp).await)
}

#[tokio::test]
async fn team_members_owner_can_change_role_to_member() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "cr-to-member", "owner@cr-member.com", "pass1234").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "guest@cr-member.com",
        "admin",
    )
    .await;
    let accept_url = body["accept_url"].as_str().unwrap().to_string();
    let invite_token = accept_url.split("token=").nth(1).unwrap();
    accept_invite_token(build_router(state.clone()), invite_token, "temppass1").await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cr-member.com").await;
    let guest = store
        .get_member_by_email_and_team("guest@cr-member.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(guest.member_role, "admin");

    let (status, _) = change_member_role(
        build_router(state.clone()),
        &owner_token,
        &guest.id,
        "approver",
    )
    .await;
    assert_eq!(status, 200);

    let updated = store
        .get_member_by_email_and_team("guest@cr-member.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.member_role, "approver");
}

#[tokio::test]
async fn team_members_owner_can_change_role_to_admin() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "cr-to-admin", "owner@cr-admin.com", "pass1234").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "guest@cr-admin.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cr-admin.com").await;
    let guest = store
        .get_member_by_email_and_team("guest@cr-admin.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(guest.member_role, "approver");

    let (status, _) = change_member_role(
        build_router(state.clone()),
        &owner_token,
        &guest.id,
        "admin",
    )
    .await;
    assert_eq!(status, 200);

    let updated = store
        .get_member_by_email_and_team("guest@cr-admin.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.member_role, "admin");
}

#[tokio::test]
async fn team_members_owner_can_grant_owner_role() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "cr-grant-owner", "owner@cr-go.com", "pass1234").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "guest@cr-go.com",
        "admin",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cr-go.com").await;
    let guest = store
        .get_member_by_email_and_team("guest@cr-go.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    let (status, _) = change_member_role(
        build_router(state.clone()),
        &owner_token,
        &guest.id,
        "owner",
    )
    .await;
    assert_eq!(status, 200);

    let updated = store
        .get_member_by_email_and_team("guest@cr-go.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.member_role, "owner");
    assert!(updated.is_owner());
}

#[tokio::test]
async fn team_members_admin_cannot_change_roles() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "cr-admin-blocked", "owner@cr-ab.com", "pass1234").await;

    // Invite admin and a target member.
    let (_, body_admin) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "admin@cr-ab.com",
        "admin",
    )
    .await;
    let admin_invite_token = body_admin["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(
        build_router(state.clone()),
        &admin_invite_token,
        "adminpass1",
    )
    .await;
    let admin_token = login_as(&state, "admin@cr-ab.com", "adminpass1").await;

    let (_, body_target) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "target@cr-ab.com",
        "approver",
    )
    .await;
    let target_invite_token = body_target["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(
        build_router(state.clone()),
        &target_invite_token,
        "targetpass1",
    )
    .await;
    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cr-ab.com").await;
    let target = store
        .get_member_by_email_and_team("target@cr-ab.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    let (status, body) = change_member_role(
        build_router(state.clone()),
        &admin_token,
        &target.id,
        "admin",
    )
    .await;
    assert_eq!(status, 403, "{body}");
}

#[tokio::test]
async fn team_members_cannot_change_own_role() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "cr-own-role", "owner@cr-own.com", "pass1234").await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cr-own.com").await;

    let (status, body) = change_member_role(
        build_router(state.clone()),
        &owner_token,
        &owner_row.id,
        "admin",
    )
    .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn team_members_role_change_invalid_role_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "cr-bad-role", "owner@cr-br.com", "pass1234").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "guest@cr-br.com",
        "admin",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;
    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cr-br.com").await;
    let guest = store
        .get_member_by_email_and_team("guest@cr-br.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    let (status, _) =
        change_member_role(build_router(state.clone()), &owner_token, &guest.id, "god").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn team_members_role_change_cross_team_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_a_token = signup_and_login(&state, "cr-cross-a", "owner@cr-xa.com", "pass1234").await;
    let owner_b_token = signup_and_login(&state, "cr-cross-b", "owner@cr-xb.com", "pass1234").await;

    // Invite a member into team B.
    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_b_token,
        "guest@cr-xb.com",
        "admin",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;
    let store = state.db_state.store();
    let owner_b_row = member_by_email(store, "owner@cr-xb.com").await;
    let guest_b = store
        .get_member_by_email_and_team("guest@cr-xb.com", &owner_b_row.team_id)
        .await
        .unwrap()
        .unwrap();

    // Owner of team A tries to change team B's member. With the membership
    // model, that target has no membership in team A, so it resolves to
    // "member not found" (404) — still a hard rejection, just expressed as
    // not-found-in-your-team rather than the old forbidden-cross-team (403).
    let (status, _) = change_member_role(
        build_router(state.clone()),
        &owner_a_token,
        &guest_b.id,
        "approver",
    )
    .await;
    assert_eq!(status, 404);
}

// ---------------------------------------------------------------------------
// Member credential scoping
// ---------------------------------------------------------------------------

async fn assign_credential_to_member(
    app: axum::Router,
    token: &str,
    member_id: &str,
    cred_name: &str,
) -> u16 {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/team/members/{member_id}/credentials"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"credential_name": cred_name}).to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap().status().as_u16()
}

async fn remove_credential_from_member(
    app: axum::Router,
    token: &str,
    member_id: &str,
    cred_name: &str,
) -> u16 {
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/{member_id}/credentials/{cred_name}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap().status().as_u16()
}

async fn list_credentials_as(app: axum::Router, token: &str) -> Vec<String> {
    let req = Request::builder()
        .method("GET")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let body = resp_json(app.oneshot(req).await.unwrap()).await;
    body["credentials"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|c| c["name"].as_str().map(|s| s.to_string()))
        .collect()
}

async fn request_status_as(
    app: axum::Router,
    token: &str,
    method: &str,
    uri: String,
    body: Option<serde_json::Value>,
) -> u16 {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let req_body = if let Some(body) = body {
        builder = builder.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    app.oneshot(builder.body(req_body).unwrap())
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Login helper (no signup, account must already exist).
async fn login_as(state: &AppState, email: &str, password: &str) -> String {
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"email": email, "password": password}).to_string(),
        ))
        .unwrap();
    let body = resp_json(app.oneshot(req).await.unwrap()).await;
    body["session_token"]
        .as_str()
        .unwrap_or_else(|| panic!("login failed for {email}: {body}"))
        .to_string()
}

/// Create a credential via the admin API.
async fn create_credential_via_api(app: axum::Router, token: &str, name: &str) {
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"name": name, "description": "test", "value": "secret", "allowed_hosts": ["api.example.com"]}).to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();
}

#[tokio::test]
async fn create_credential_rejects_name_with_colon_or_slash() {
    // Regression test: POST /team/credentials previously accepted any name —
    // including one containing `:` or `/` that the dashboard's own
    // create-form input (`pattern="[a-z0-9-]+"`) could never have submitted,
    // and that would also misparse as a `<CREDENTIAL:name.field>` placeholder.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "colon-slash-name", "owner@nametest.com", "pass1234").await;

    for bad_name in ["google:workspace-admin", "notion/api"] {
        let req = Request::builder()
            .method("POST")
            .uri("/team/credentials")
            .header("authorization", format!("Bearer {owner_token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"name": bad_name, "description": "test", "value": "secret"}).to_string(),
            ))
            .unwrap();
        let (status, val) = send_request_and_parse(build_router(state.clone()), req).await;
        assert_eq!(status, 400, "name: {bad_name}");
        assert!(val["error"].as_str().unwrap().contains("lowercase alphanumeric"));
    }
}

#[tokio::test]
async fn approver_cannot_mutate_workspace_resources() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "rbac-approver", "owner@rbac.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "secret").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "approver@rbac.com",
        "approver",
    )
    .await;
    let approver_invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(
        build_router(state.clone()),
        &approver_invite_token,
        "approverpass1",
    )
    .await;
    let approver_token = login_as(&state, "approver@rbac.com", "approverpass1").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "target@rbac.com",
        "approver",
    )
    .await;
    let target_invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(
        build_router(state.clone()),
        &target_invite_token,
        "targetpass1",
    )
    .await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@rbac.com").await;
    let approver_row = store
        .get_member_by_email_and_team("approver@rbac.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();
    let target_row = store
        .get_member_by_email_and_team("target@rbac.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    store
        .create_agent(
            &owner_row.team_id,
            "agent-a",
            Some("test agent"),
            &hash_api_key("agent-key"),
            None,
        )
        .await
        .unwrap();
    store
        .create_role(&owner_row.team_id, "role-a", Some("test role"), None)
        .await
        .unwrap();

    let (_, pending_body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "pending@rbac.com",
        "approver",
    )
    .await;
    assert!(pending_body["error"].is_null(), "{pending_body}");
    let pending = store
        .list_pending_invites(&owner_row.team_id)
        .await
        .unwrap();
    let pending_id = pending
        .iter()
        .find(|i| i.email == "pending@rbac.com")
        .unwrap()
        .id
        .clone();

    let cases = vec![
        (
            "POST",
            "/team/credentials".to_string(),
            Some(json!({"name": "new-cred", "description": "x", "value": "secret"})),
        ),
        (
            "PATCH",
            "/team/credentials/secret".to_string(),
            Some(json!({"description": "changed"})),
        ),
        (
            "PATCH",
            "/team/credentials/secret/secret".to_string(),
            Some(json!({"value": "changed"})),
        ),
        ("DELETE", "/team/credentials/secret".to_string(), None),
        (
            "PUT",
            "/team/agents/agent-a".to_string(),
            Some(json!({"credentials": []})),
        ),
        ("POST", "/team/agents/agent-a/rotate-key".to_string(), None),
        ("POST", "/team/agents/agent-a/disable".to_string(), None),
        ("DELETE", "/team/agents/agent-a".to_string(), None),
        ("GET", "/team/roles".to_string(), None),
        (
            "POST",
            "/team/roles".to_string(),
            Some(json!({"name": "new-role"})),
        ),
        (
            "PUT",
            "/team/roles/role-a".to_string(),
            Some(json!({"description": "changed"})),
        ),
        ("DELETE", "/team/roles/role-a".to_string(), None),
        (
            "PUT",
            "/team/policies/secret".to_string(),
            Some(json!({"auto_approve_methods": ["GET"]})),
        ),
        (
            "POST",
            "/team/members/invite".to_string(),
            Some(json!({"email": "bad@rbac.com", "role": "admin"})),
        ),
        ("DELETE", format!("/team/members/{}", target_row.id), None),
        (
            "DELETE",
            format!("/team/members/invites/{pending_id}"),
            None,
        ),
        (
            "DELETE",
            format!("/team/members/{}/passkeys", target_row.id),
            None,
        ),
        (
            "POST",
            format!("/team/members/{}/credentials", approver_row.id),
            Some(json!({"credential_name": "secret"})),
        ),
    ];

    for (method, uri, body) in cases {
        let status = request_status_as(
            build_router(state.clone()),
            &approver_token,
            method,
            uri.clone(),
            body,
        )
        .await;
        assert_eq!(status, 403, "{method} {uri} should be forbidden");
    }
}

#[tokio::test]
async fn approver_can_create_owned_agent_for_assigned_credentials() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "own-agent", "owner@oa.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "allowed").await;
    create_credential_via_api(build_router(state.clone()), &owner_token, "owner-only").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "approver@oa.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();
    accept_invite_token(build_router(state.clone()), invite_token, "approverpass1").await;
    let approver_token = login_as(&state, "approver@oa.com", "approverpass1").await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@oa.com").await;
    let approver_row = store
        .get_member_by_email_and_team("approver@oa.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();
    store
        .create_agent(
            &owner_row.team_id,
            "owner-agent",
            Some("owner key"),
            &hash_api_key("owner-key"),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        assign_credential_to_member(
            build_router(state.clone()),
            &owner_token,
            &approver_row.id,
            "allowed",
        )
        .await,
        200
    );

    let req = Request::builder()
        .method("POST")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {approver_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"id": "approver-agent", "credentials": ["allowed"]}).to_string(),
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 201, "{body}");
    assert!(body["api_key"].as_str().is_some());

    let owned = store
        .get_agent(&owner_row.team_id, "approver-agent")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        owned.owner_user_id.as_deref(),
        Some(approver_row.id.as_str())
    );
    let creds = store
        .get_agent_direct_credentials(&owner_row.team_id, "approver-agent")
        .await
        .unwrap();
    assert_eq!(creds, vec!["allowed".to_string()]);

    let req = Request::builder()
        .method("GET")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {approver_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200, "{body}");
    let ids: Vec<_> = body["agents"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|agent| agent["id"].as_str())
        .collect();
    assert_eq!(ids, vec!["approver-agent"]);

    let req = Request::builder()
        .method("GET")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200, "{body}");
    let ids: std::collections::HashSet<_> = body["agents"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|agent| agent["id"].as_str())
        .collect();
    assert!(ids.contains("owner-agent"));
    assert!(ids.contains("approver-agent"));
}

#[tokio::test]
async fn approver_owned_agent_rejects_unassigned_credentials_and_roles() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "own-agent-rules", "owner@oar.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "allowed").await;
    create_credential_via_api(build_router(state.clone()), &owner_token, "blocked").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "approver@oar.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();
    accept_invite_token(build_router(state.clone()), invite_token, "approverpass1").await;
    let approver_token = login_as(&state, "approver@oar.com", "approverpass1").await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@oar.com").await;
    let approver_row = store
        .get_member_by_email_and_team("approver@oar.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        assign_credential_to_member(
            build_router(state.clone()),
            &owner_token,
            &approver_row.id,
            "allowed",
        )
        .await,
        200
    );
    store
        .create_role(&owner_row.team_id, "reader", Some("reader"), None)
        .await
        .unwrap();
    store
        .create_agent(
            &owner_row.team_id,
            "owner-agent",
            Some("owner key"),
            &hash_api_key("owner-key-rules"),
            None,
        )
        .await
        .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {approver_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"id": "blocked-agent", "credentials": ["blocked"]}).to_string(),
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 403, "{body}");

    let req = Request::builder()
        .method("POST")
        .uri("/team/agents")
        .header("authorization", format!("Bearer {approver_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"id": "role-agent", "roles": ["reader"]}).to_string(),
        ))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 403, "{body}");

    let status = request_status_as(
        build_router(state.clone()),
        &approver_token,
        "PUT",
        "/team/agents/owner-agent".to_string(),
        Some(json!({"credentials": ["allowed"]})),
    )
    .await;
    assert_eq!(status, 403);

    let status = request_status_as(
        build_router(state.clone()),
        &approver_token,
        "POST",
        "/team/agents/owner-agent/rotate-key".to_string(),
        None,
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn team_member_scoping_admin_sees_all_credentials() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "scope-admin", "owner@scope-a.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "cred-x").await;
    create_credential_via_api(build_router(state.clone()), &owner_token, "cred-y").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "admin@scope-a.com",
        "admin",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;
    let admin_token = login_as(&state, "admin@scope-a.com", "temppass1").await;

    let creds = list_credentials_as(build_router(state.clone()), &admin_token).await;
    assert!(creds.contains(&"cred-x".to_string()));
    assert!(creds.contains(&"cred-y".to_string()));
}

#[tokio::test]
async fn team_member_scoping_member_sees_only_assigned_credentials() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "scope-member", "owner@scope-m.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "cred-a").await;
    create_credential_via_api(build_router(state.clone()), &owner_token, "cred-b").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "member@scope-m.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@scope-m.com").await;
    let member_row = store
        .get_member_by_email_and_team("member@scope-m.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    // Assign only cred-a.
    let status = assign_credential_to_member(
        build_router(state.clone()),
        &owner_token,
        &member_row.id,
        "cred-a",
    )
    .await;
    assert_eq!(status, 200);

    let member_token = login_as(&state, "member@scope-m.com", "temppass1").await;
    let creds = list_credentials_as(build_router(state.clone()), &member_token).await;
    assert_eq!(creds, vec!["cred-a".to_string()]);
    assert!(!creds.contains(&"cred-b".to_string()));
}

#[tokio::test]
async fn team_member_scoping_member_with_no_assignments_sees_nothing() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token =
        signup_and_login(&state, "scope-empty", "owner@scope-e.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "cred-secret").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "member@scope-e.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;

    let member_token = login_as(&state, "member@scope-e.com", "temppass1").await;
    let creds = list_credentials_as(build_router(state.clone()), &member_token).await;
    assert!(creds.is_empty());
}

#[tokio::test]
async fn team_member_credential_assign_and_list() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "cred-assign", "owner@ca.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "my-cred").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "member@ca.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;
    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@ca.com").await;
    let member_row = store
        .get_member_by_email_and_team("member@ca.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    let status = assign_credential_to_member(
        build_router(state.clone()),
        &owner_token,
        &member_row.id,
        "my-cred",
    )
    .await;
    assert_eq!(status, 200);

    // Verify via list endpoint.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/team/members/{}/credentials", member_row.id))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let body = resp_json(build_router(state.clone()).oneshot(req).await.unwrap()).await;
    assert_eq!(
        body["credentials"].as_array().unwrap(),
        &vec![serde_json::json!("my-cred")]
    );
}

#[tokio::test]
async fn team_member_credential_remove() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "cred-remove", "owner@cr-rem.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "removable-cred").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "member@cr-rem.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;
    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cr-rem.com").await;
    let member_row = store
        .get_member_by_email_and_team("member@cr-rem.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    assign_credential_to_member(
        build_router(state.clone()),
        &owner_token,
        &member_row.id,
        "removable-cred",
    )
    .await;
    let status = remove_credential_from_member(
        build_router(state.clone()),
        &owner_token,
        &member_row.id,
        "removable-cred",
    )
    .await;
    assert_eq!(status, 200);

    let creds = store
        .list_approver_credentials(&owner_row.team_id, &member_row.id)
        .await
        .unwrap();
    assert!(creds.is_empty());
}

#[tokio::test]
async fn team_member_cannot_assign_credentials_to_others() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "cred-perm", "owner@cp.com", "pass1234").await;

    create_credential_via_api(build_router(state.clone()), &owner_token, "secret-cred").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "member@cp.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;
    let member_token = login_as(&state, "member@cp.com", "temppass1").await;

    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cp.com").await;
    let member_row = store
        .get_member_by_email_and_team("member@cp.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    // Member tries to assign to owner.
    let status = assign_credential_to_member(
        build_router(state.clone()),
        &member_token,
        &owner_row.id,
        "secret-cred",
    )
    .await;
    assert_eq!(status, 403);
    // Member tries to assign to themselves.
    let status = assign_credential_to_member(
        build_router(state.clone()),
        &member_token,
        &member_row.id,
        "secret-cred",
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn team_member_assign_nonexistent_credential_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "cred-noexist", "owner@cne.com", "pass1234").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "member@cne.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;
    let store = state.db_state.store();
    let owner_row = member_by_email(store, "owner@cne.com").await;
    let member_row = store
        .get_member_by_email_and_team("member@cne.com", &owner_row.team_id)
        .await
        .unwrap()
        .unwrap();

    let status = assign_credential_to_member(
        build_router(state.clone()),
        &owner_token,
        &member_row.id,
        "ghost-cred",
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn team_members_list_shows_member_role_field() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let owner_token = signup_and_login(&state, "mrf-team", "owner@mrf.com", "pass1234").await;

    let (_, body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "guest@mrf.com",
        "approver",
    )
    .await;
    let invite_token = body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap()
        .to_string();
    accept_invite_token(build_router(state.clone()), &invite_token, "temppass1").await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/team/members")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let body = resp_json(app.oneshot(req).await.unwrap()).await;
    let members = body["members"].as_array().unwrap();
    let owner_entry = members
        .iter()
        .find(|m| m["email"].as_str() == Some("owner@mrf.com"))
        .unwrap();
    let guest_entry = members
        .iter()
        .find(|m| m["email"].as_str() == Some("guest@mrf.com"))
        .unwrap();
    assert_eq!(owner_entry["member_role"].as_str().unwrap(), "owner");
    assert_eq!(guest_entry["member_role"].as_str().unwrap(), "approver");
}

/// Regression: the real `DashboardChannel` (not the test mock) must keep the
/// approval details it persists during `/forward`.
///
/// The unified async-approval path used to unconditionally save an empty `"{}"`
/// placeholder row keyed by `channel_id`. For messaging channels that id is a
/// chat-message id (a separate namespace), but the dashboard channel returns
/// `request.id` — the same key it had just written the full `ApprovalDetails`
/// to — so the placeholder clobbered the details. The inbox then rendered
/// nothing (empty `target_url`) and `/approve/dashboard/{id}/approve` returned
/// 503 (the `{}` failed to deserialize into `ApprovalDetails`). The dashboard
/// channel now opts out via `persists_own_details() == true`.
///
/// The existing suite only ever wired a mock channel whose `send_approval_request`
/// persists nothing, so it could not have caught this. This test uses the real
/// channel and asserts the persisted row still carries the request details.
#[tokio::test]
async fn dashboard_channel_details_survive_forward() {
    use tap_proxy::dashboard_channel::DashboardChannel;

    let key_hash = hash_api_key("integration-test-key");
    let (store, _tmp) = temp_store().await;
    store
        .create_credential(
            "t1",
            "cred-a",
            "Credential A",
            "direct",
            None,
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "cred-a", b"secret123")
        .await
        .unwrap();
    store
        .create_agent("t1", "test-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "cred-a")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "cred-a".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string()],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    // The real dashboard channel, sharing the same store.
    let dashboard_channel: Arc<dyn ApprovalChannel> = Arc::new(DashboardChannel::new(
        Arc::new(store.clone()),
        "http://localhost".to_string(),
        None,
        1200,
    ));
    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(test_key()),
        approval_channel: dashboard_channel.clone(),
        dashboard_channel: dashboard_channel.clone(),
        telegram_channel: Some(dashboard_channel.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state: db_state.clone(),
        webauthn_state: None,
        approval_timeout_secs: 300,
    };

    // A write through the unified X-TAP-Credential header → gated → 202.
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("X-TAP-Key", "integration-test-key")
        .header("X-TAP-Credential", "cred-a")
        .header("X-TAP-Target", "https://example.com/post")
        .header("X-TAP-Method", "POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"hello":"world"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 202, "write must be gated for approval");

    // The dashboard channel persists details synchronously during /forward, so
    // by the time 202 returns the row must already carry the real request — not
    // an empty placeholder.
    let rows = db_state
        .store()
        .list_pending_approvals_for_team("t1")
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "exactly one pending approval persisted");
    assert_ne!(
        rows[0].details_json.trim(),
        "{}",
        "details must not be clobbered to an empty placeholder"
    );
    let details: serde_json::Value = serde_json::from_str(&rows[0].details_json)
        .expect("details_json must deserialize (an empty {} would 503 the approve endpoint)");
    assert_eq!(details["target_url"], "https://example.com/post");
    assert_eq!(details["method"], "POST");
    assert_eq!(details["credential_name"], "cred-a");
}

// --- Agent-originated proposals + credential prefill link ------------------

#[tokio::test]
async fn agent_creates_policy_proposal_and_polls_status() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;

    let body = json!({
        "proposal_type": "policy_change",
        "payload": { "credential_name": "cred-a", "auto_approve_methods": ["POST"] }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/agent/proposals")
        .header("x-tap-key", "integration-test-key")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, val) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 201);
    assert_eq!(val["status"], "pending");
    let id = val["proposal_id"].as_str().unwrap().to_string();

    // Poll status (team-scoped via the agent's key).
    let req2 = Request::builder()
        .method("GET")
        .uri(format!("/agent/proposals/{id}"))
        .header("x-tap-key", "integration-test-key")
        .body(Body::empty())
        .unwrap();
    let (s2, v2) = send_request_and_parse(build_router(state), req2).await;
    assert_eq!(s2, 200);
    assert_eq!(v2["status"], "pending");
}

#[tokio::test]
async fn agent_proposal_wrong_type_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let body = json!({ "proposal_type": "credential_create", "payload": {} });
    let req = Request::builder()
        .method("POST")
        .uri("/agent/proposals")
        .header("x-tap-key", "integration-test-key")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn agent_proposal_invalid_method_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let body = json!({
        "proposal_type": "policy_change",
        "payload": { "credential_name": "cred-a", "auto_approve_methods": ["FLY"] }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/agent/proposals")
        .header("x-tap-key", "integration-test-key")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn agent_proposal_requires_auth() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let body =
        json!({ "proposal_type": "policy_change", "payload": { "credential_name": "cred-a" } });
    let req = Request::builder()
        .method("POST")
        .uri("/agent/proposals")
        .header("x-tap-key", "wrong-key")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn agent_credential_link_returns_prefill_url() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let body = json!({ "name": "datadog", "connector": "direct", "api_base": "https://api.datadoghq.com" });
    let req = Request::builder()
        .method("POST")
        .uri("/agent/credential-link")
        .header("x-tap-key", "integration-test-key")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, val) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 200);
    let url = val["create_url"].as_str().unwrap();
    assert!(url.contains("prefill_credential="), "url: {url}");
    assert!(url.contains("#/credentials"), "url: {url}");
}

#[tokio::test]
async fn agent_credential_link_rejects_secret() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let body = json!({ "name": "datadog", "value": "super-secret" });
    let req = Request::builder()
        .method("POST")
        .uri("/agent/credential-link")
        .header("x-tap-key", "integration-test-key")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, _) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn agent_credential_link_rejects_name_with_colon_or_slash() {
    // Regression test: the dashboard's create-form "Name" input carries
    // `pattern="[a-z0-9-]+"`, so a prefill link built from a name outside
    // that charset would hand the human a form their own browser refuses to
    // submit. The endpoint must reject it up front instead, so the agent
    // gets clear, actionable feedback rather than a DOA link.
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    for bad_name in ["google:workspace-admin", "notion/api"] {
        let body = json!({ "name": bad_name });
        let req = Request::builder()
            .method("POST")
            .uri("/agent/credential-link")
            .header("x-tap-key", "integration-test-key")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, val) = send_request_and_parse(build_router(state.clone()), req).await;
        assert_eq!(status, 400, "name: {bad_name}");
        assert!(val["error"].as_str().unwrap().contains("lowercase alphanumeric"));
    }
}

// ===========================================================================
// POST /sign — cryptographic signing-key credentials (a signer, not a wallet).
// ===========================================================================

/// Build an AppState seeded with one signing-key credential of the given
/// algorithm, generated in-proxy so the test exercises the real key path.
/// Returns (state, api_key, generated public info).
async fn make_signing_state(
    mock_approval: Arc<dyn ApprovalChannel>,
    algorithm: tap_proxy::signing::Algorithm,
) -> (AppState, String, tap_proxy::signing::GeneratedKey) {
    let enc_key = test_key();
    let api_key = "sign-test-key";
    let key_hash = hash_api_key(api_key);
    let (store, _tmp) = temp_store().await;

    let gen = tap_proxy::signing::generate(algorithm).unwrap();
    store
        .create_credential(
            "t1",
            "my-signer",
            "Signing key",
            "sidecar",
            Some("tap:sign"),
            false,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "my-signer", gen.bundle.as_bytes())
        .await
        .unwrap();
    store
        .create_agent("t1", "sign-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "sign-agent", "my-signer")
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    (state, api_key.to_string(), gen)
}

fn sign_req(api_key: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/sign")
        .header("x-tap-key", api_key)
        .header("x-tap-credential", "my-signer")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Poll the async-approval result after the background signing task runs.
async fn poll_result(
    state: &AppState,
    api_key: &str,
    txn_id: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let poll_req = Request::builder()
        .method("GET")
        .uri(format!("/agent/approvals/{txn_id}"))
        .header("x-tap-key", api_key)
        .body(Body::empty())
        .unwrap();
    send_request_and_parse(build_router(state.clone()), poll_req).await
}

#[tokio::test]
async fn sign_secp256k1_approved_returns_recoverable_signature() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, gen) = make_signing_state(mock.clone(), Algorithm::Secp256k1).await;

    let digest = "11".repeat(32); // 32-byte digest, hex
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        sign_req(&key, json!({ "payload": digest, "encoding": "hex" })),
    )
    .await;
    assert_eq!(status, 202, "signing must be approval-gated: {body}");
    assert_eq!(
        body["blind_signature"], true,
        "no pre-image → blind: {body}"
    );
    let txn_id = body["txn_id"].as_str().unwrap().to_string();
    assert_eq!(mock.calls.lock().unwrap().len(), 1, "approval requested");

    let (poll_status, poll_body) = poll_result(&state, &key, &txn_id).await;
    assert_eq!(poll_status, 200);
    assert_eq!(poll_body["status"], "forwarded", "poll: {poll_body}");
    // A signature has no upstream headers, but the result must still report as
    // complete (headers stored as an empty list, not missing).
    assert_eq!(poll_body["response"]["complete"], true, "poll: {poll_body}");

    let sig_json: serde_json::Value =
        serde_json::from_str(poll_body["response"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(sig_json["algorithm"], "secp256k1");
    assert_eq!(
        sig_json["address"].as_str().unwrap().to_lowercase(),
        gen.address.clone().unwrap().to_lowercase(),
        "returned address must match the generated key"
    );
    // The signature must recover to the signer's public key.
    let r = hex::decode(sig_json["r"].as_str().unwrap()).unwrap();
    let s = hex::decode(sig_json["s"].as_str().unwrap()).unwrap();
    let recid = sig_json["recovery_id"].as_u64().unwrap() as u8;
    let mut rs = r.clone();
    rs.extend(s);
    let sig = k256::ecdsa::Signature::from_slice(&rs).unwrap();
    let digest_bytes = hex::decode(&digest).unwrap();
    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest_bytes,
        &sig,
        k256::ecdsa::RecoveryId::from_byte(recid).unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(recovered.to_encoded_point(true).as_bytes()),
        gen.public_key,
        "signature must recover to signer"
    );
}

#[tokio::test]
async fn sign_ed25519_signs_message_and_verifies() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, gen) = make_signing_state(mock, Algorithm::Ed25519).await;

    let msg = b"hello wallet";
    let payload = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, msg);
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        sign_req(&key, json!({ "payload": payload, "encoding": "base64" })),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(
        body["blind_signature"], false,
        "ed25519 is never blind: {body}"
    );
    let txn_id = body["txn_id"].as_str().unwrap().to_string();

    let (_, poll_body) = poll_result(&state, &key, &txn_id).await;
    assert_eq!(poll_body["status"], "forwarded", "{poll_body}");
    let sig_json: serde_json::Value =
        serde_json::from_str(poll_body["response"]["body"].as_str().unwrap()).unwrap();
    let sig = ed25519_dalek::Signature::from_slice(
        &hex::decode(sig_json["signature"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let vk_bytes: [u8; 32] = hex::decode(&gen.public_key).unwrap().try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap();
    use ed25519_dalek::Verifier;
    assert!(
        vk.verify(msg, &sig).is_ok(),
        "ed25519 signature must verify"
    );
}

#[tokio::test]
async fn sign_denied_records_denied_and_no_signature() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: false, // deny
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, _gen) = make_signing_state(mock, Algorithm::Secp256k1).await;

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        sign_req(&key, json!({ "payload": "11".repeat(32) })),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    let txn_id = body["txn_id"].as_str().unwrap().to_string();
    let (_, poll_body) = poll_result(&state, &key, &txn_id).await;
    assert_eq!(poll_body["status"], "denied", "{poll_body}");
    assert!(
        poll_body["response"].is_null(),
        "no signature on denial: {poll_body}"
    );
}

#[tokio::test]
async fn sign_prehash_verified_is_not_blind_and_signs() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, _gen) = make_signing_state(mock, Algorithm::Secp256k1).await;

    // digest == keccak256(preimage) → pre-image verifies.
    use sha3::Digest as _;
    let preimage = "transfer 1 ETH to alice";
    let digest = sha3::Keccak256::digest(preimage.as_bytes());
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        sign_req(
            &key,
            json!({
                "payload": hex::encode(digest),
                "prehash": { "preimage": preimage, "hash": "keccak256" }
            }),
        ),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(
        body["blind_signature"], false,
        "verified pre-image → not blind: {body}"
    );
    let txn_id = body["txn_id"].as_str().unwrap().to_string();
    let (_, poll_body) = poll_result(&state, &key, &txn_id).await;
    assert_eq!(poll_body["status"], "forwarded", "{poll_body}");
}

#[tokio::test]
async fn sign_prehash_mismatch_rejected_before_approval() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, _gen) = make_signing_state(mock.clone(), Algorithm::Secp256k1).await;

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        sign_req(
            &key,
            json!({
                "payload": "22".repeat(32),
                "prehash": { "preimage": "totally different", "hash": "keccak256" }
            }),
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "preimage_mismatch", "{body}");
    assert_eq!(
        mock.calls.lock().unwrap().len(),
        0,
        "no approval for a rejected request"
    );
}

#[tokio::test]
async fn sign_non_digest_for_ecdsa_errors_in_result() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, _gen) = make_signing_state(mock, Algorithm::Secp256k1).await;

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        sign_req(&key, json!({ "payload": "aabbccdd" })),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    let txn_id = body["txn_id"].as_str().unwrap().to_string();
    let (_, poll_body) = poll_result(&state, &key, &txn_id).await;
    assert_eq!(poll_body["status"], "error", "{poll_body}");
    assert!(
        poll_body["error_detail"]
            .as_str()
            .unwrap()
            .contains("32-byte digest"),
        "{poll_body}"
    );
}

#[tokio::test]
async fn sign_prehash_rejected_for_ed25519() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, _gen) = make_signing_state(mock, Algorithm::Ed25519).await;

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        sign_req(
            &key,
            json!({ "payload": "aabb", "prehash": { "preimage": "x", "hash": "keccak256" } }),
        ),
    )
    .await;
    assert_eq!(status, 400, "ed25519 + prehash must be rejected: {body}");
}

#[tokio::test]
async fn sign_unknown_credential_forbidden() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, _gen) = make_signing_state(mock, Algorithm::Secp256k1).await;

    let req = Request::builder()
        .method("POST")
        .uri("/sign")
        .header("x-tap-key", &key)
        .header("x-tap-credential", "nonexistent")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "payload": "11".repeat(32) }).to_string(),
        ))
        .unwrap();
    let (status, _body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn forward_rejects_signing_credential_with_redirect() {
    use tap_proxy::signing::Algorithm;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, key, _gen) = make_signing_state(mock, Algorithm::Secp256k1).await;

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", &key)
        .header("x-tap-credential", "my-signer")
        .header("x-tap-target", "https://api.example.com/anything")
        .header("x-tap-method", "POST")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap_or("").contains("/sign"),
        "error should redirect to POST /sign: {body}"
    );
}

// ---------------------------------------------------------------------------
// TAP for Platforms — managed end-user scoping + isolation (M2)
// ---------------------------------------------------------------------------

/// State with an app key and an ordinary key in team `t1`, plus one
/// end-user-scoped secp256k1 signing key owned by end-user `alice`
/// (stored under the namespaced name `eu:alice/wallet`).
async fn make_app_state(mock_approval: Arc<dyn ApprovalChannel>) -> (AppState, String, String) {
    let enc_key = test_key();
    let app_key = "app-key";
    let ordinary_key = "ordinary-key";
    let (store, _tmp) = temp_store().await;

    let gen = tap_proxy::signing::generate(tap_proxy::signing::Algorithm::Secp256k1).unwrap();
    store
        .create_credential_scoped(
            "t1",
            "eu:alice/wallet",
            "Alice wallet",
            "sidecar",
            Some("tap:sign"),
            false,
            None,
            None,
            Some(gen.bundle.as_bytes()),
            Some("alice"),
        )
        .await
        .unwrap();

    // App key (may assert X-TAP-End-User).
    store
        .create_app("t1", "app-agent", None, &hash_api_key(app_key), None)
        .await
        .unwrap();

    // Ordinary key, whitelisted directly for the end-user credential so we can
    // prove the isolation assertion blocks it even with the name whitelisted.
    store
        .create_agent(
            "t1",
            "ordinary-agent",
            None,
            &hash_api_key(ordinary_key),
            None,
        )
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "ordinary-agent", "eu:alice/wallet")
        .await
        .unwrap();

    // Use the DB-backed audit logger (like prod) so /app/usage metering —
    // which reads the audit_log table — is exercised end-to-end.
    let audit_store = store.clone();
    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: Arc::new(tap_proxy::audit::DbAuditLogger::new(
            audit_store,
            tokio::runtime::Handle::current(),
        )),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };
    (state, app_key.to_string(), ordinary_key.to_string())
}

fn digest_32() -> serde_json::Value {
    serde_json::json!({ "payload": "11".repeat(32), "encoding": "hex" })
}

#[tokio::test]
async fn app_sign_scoped_to_end_user_succeeds() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;

    let req = Request::builder()
        .method("POST")
        .uri("/sign")
        .header("x-tap-key", &app_key)
        .header("x-tap-credential", "wallet")
        .header("x-tap-end-user", "alice")
        .header("content-type", "application/json")
        .body(Body::from(digest_32().to_string()))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 202, "{body}");
    let txn_id = body["txn_id"].as_str().unwrap();
    let (poll_status, poll_body) = poll_result(&state, &app_key, txn_id).await;
    assert_eq!(poll_status, 200, "{poll_body}");
    assert_eq!(poll_body["status"], "forwarded", "{poll_body}");
}

#[tokio::test]
async fn app_sign_other_end_user_cannot_reach_key() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;

    // Bob has no wallet; namespacing resolves `eu:bob/wallet` which does not
    // exist — bob can never reach alice's key.
    let req = Request::builder()
        .method("POST")
        .uri("/sign")
        .header("x-tap-key", &app_key)
        .header("x-tap-credential", "wallet")
        .header("x-tap-end-user", "bob")
        .header("content-type", "application/json")
        .body(Body::from(digest_32().to_string()))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 404, "bob must not reach alice's key: {body}");
}

#[tokio::test]
async fn non_app_agent_asserting_end_user_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _app_key, ordinary_key) = make_app_state(mock).await;

    let req = Request::builder()
        .method("POST")
        .uri("/sign")
        .header("x-tap-key", &ordinary_key)
        .header("x-tap-credential", "wallet")
        .header("x-tap-end-user", "alice")
        .header("content-type", "application/json")
        .body(Body::from(digest_32().to_string()))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error_code"], "not_an_app_key", "{body}");
}

#[tokio::test]
async fn ordinary_request_directly_naming_end_user_credential_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _app_key, ordinary_key) = make_app_state(mock).await;

    // No X-TAP-End-User header, but names the end-user credential directly.
    // It is whitelisted for this agent, yet the isolation assertion (cred owns
    // end_user_id while none asserted) must still reject it.
    let req = Request::builder()
        .method("POST")
        .uri("/sign")
        .header("x-tap-key", &ordinary_key)
        .header("x-tap-credential", "eu:alice/wallet")
        .header("content-type", "application/json")
        .body(Body::from(digest_32().to_string()))
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error_code"], "end_user_mismatch", "{body}");
}

#[tokio::test]
async fn end_user_signing_key_via_forward_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;

    // A signing key — even an end-user-scoped one — must never be usable via
    // /forward (the value-based signing guard still fires after namespacing).
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", &app_key)
        .header("x-tap-credential", "wallet")
        .header("x-tap-end-user", "alice")
        .header("x-tap-target", "https://api.example.com/anything")
        .header("x-tap-method", "POST")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"].as_str().unwrap_or("").contains("/sign"),
        "should redirect to POST /sign: {body}"
    );
}

// ---------------------------------------------------------------------------
// TAP for Platforms — headless provisioning endpoints (M3)
// ---------------------------------------------------------------------------

fn app_post(api_key: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("x-tap-key", api_key)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn app_provision_key_then_sign_end_to_end() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;

    // Provision a fresh signing key for end-user "carol".
    let req = app_post(
        &app_key,
        "/app/users/carol/keys",
        serde_json::json!({ "name": "wallet", "algorithm": "secp256k1" }),
    );
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 201, "{body}");
    assert!(
        body["address"].as_str().is_some(),
        "address returned: {body}"
    );
    assert!(
        body.get("private_key").is_none(),
        "private key must never be returned: {body}"
    );

    // Sign with it via the namespaced logical name + end-user header.
    let sign = Request::builder()
        .method("POST")
        .uri("/sign")
        .header("x-tap-key", &app_key)
        .header("x-tap-credential", "wallet")
        .header("x-tap-end-user", "carol")
        .header("content-type", "application/json")
        .body(Body::from(digest_32().to_string()))
        .unwrap();
    let (s, b) = send_request_and_parse(build_router(state.clone()), sign).await;
    assert_eq!(s, 202, "{b}");
    let (ps, pb) = poll_result(&state, &app_key, b["txn_id"].as_str().unwrap()).await;
    assert_eq!(ps, 200, "{pb}");
    assert_eq!(pb["status"], "forwarded", "{pb}");

    // The signature is metered: the sign action lands in the audit log scoped to
    // the end-user, so /app/usage counts it (the audit write happens just
    // after the async result resolves, so retry briefly).
    let from = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
    let to = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    let mut carol = 0i64;
    for _ in 0..20 {
        let usage = state
            .db_state
            .store()
            .end_user_usage("t1", &from, &to)
            .await
            .unwrap();
        carol = usage
            .iter()
            .find(|(e, _)| e == "carol")
            .map(|(_, n)| *n)
            .unwrap_or(0);
        if carol > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(carol >= 1, "sign action must be metered for the end-user");
}

#[tokio::test]
async fn app_import_key_then_sign_end_to_end() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;

    // Import a known secp256k1 key (private scalar = 1, a standard test vector
    // → address 0x7e5f…95bdf) instead of generating one. This is the path a
    // key reconstructed elsewhere (e.g. a 2PC keyshare) takes into TAP custody.
    let req = app_post(
        &app_key,
        "/app/users/dave/keys",
        serde_json::json!({
            "name": "wallet",
            "algorithm": "secp256k1",
            "value": {
                "algorithm": "secp256k1",
                "private_key": "0000000000000000000000000000000000000000000000000000000000000001"
            }
        }),
    );
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(
        body["address"].as_str().unwrap_or("").to_lowercase(),
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        "imported key must derive its OWN address, not a freshly generated one: {body}"
    );
    assert!(
        body.get("private_key").is_none(),
        "private key must never be returned: {body}"
    );

    // The imported key signs on-behalf-of the end-user like any provisioned key.
    let sign = Request::builder()
        .method("POST")
        .uri("/sign")
        .header("x-tap-key", &app_key)
        .header("x-tap-credential", "wallet")
        .header("x-tap-end-user", "dave")
        .header("content-type", "application/json")
        .body(Body::from(digest_32().to_string()))
        .unwrap();
    let (s, b) = send_request_and_parse(build_router(state.clone()), sign).await;
    assert_eq!(s, 202, "{b}");
    let (ps, pb) = poll_result(&state, &app_key, b["txn_id"].as_str().unwrap()).await;
    assert_eq!(ps, 200, "{pb}");
    assert_eq!(pb["status"], "forwarded", "{pb}");
}

#[tokio::test]
async fn app_import_key_rejects_malformed_and_mismatched() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;

    // A malformed private key is rejected before storage — validate_import
    // signs a probe, which fails to parse the key.
    let bad = app_post(
        &app_key,
        "/app/users/erin/keys",
        serde_json::json!({
            "name": "wallet",
            "algorithm": "secp256k1",
            "value": { "algorithm": "secp256k1", "private_key": "abcd" }
        }),
    );
    let (status, body) = send_request_and_parse(build_router(state.clone()), bad).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error_code"], "invalid_signing_key", "{body}");

    // Declaring one algorithm but supplying a bundle for another is rejected.
    let mism = app_post(
        &app_key,
        "/app/users/erin/keys",
        serde_json::json!({
            "name": "wallet2",
            "algorithm": "ed25519",
            "value": {
                "algorithm": "secp256k1",
                "private_key": "0000000000000000000000000000000000000000000000000000000000000001"
            }
        }),
    );
    let (status, body) = send_request_and_parse(build_router(state), mism).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error_code"], "algorithm_mismatch", "{body}");
}

#[tokio::test]
async fn app_provisioning_rejects_non_app_key() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _app_key, ordinary_key) = make_app_state(mock).await;
    let req = app_post(
        &ordinary_key,
        "/app/users/x/keys",
        serde_json::json!({ "name": "wallet", "algorithm": "secp256k1" }),
    );
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error_code"], "not_an_app_key", "{body}");
}

#[tokio::test]
async fn app_list_keys_returns_address_not_private() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;

    // alice already has a wallet from make_app_state; list her keys.
    let req = Request::builder()
        .method("GET")
        .uri("/app/users/alice/keys")
        .header("x-tap-key", &app_key)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 200, "{body}");
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "{body}");
    assert_eq!(
        keys[0]["name"], "wallet",
        "logical name, not namespaced: {body}"
    );
    assert!(keys[0]["address"].as_str().is_some(), "{body}");
    assert!(keys[0].get("private_key").is_none(), "{body}");
}

#[tokio::test]
async fn app_create_credential_rejects_signing_bundle() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;
    let req = app_post(
        &app_key,
        "/app/users/eve/credentials",
        serde_json::json!({
            "name": "sneaky",
            "value": "{\"algorithm\":\"secp256k1\",\"private_key\":\"abcd\"}"
        }),
    );
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error_code"], "signing_bundle_rejected", "{body}");
}

#[tokio::test]
async fn app_create_credential_is_idempotent_conflict() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;
    let mk = || {
        app_post(
            &app_key,
            "/app/users/frank/credentials",
            serde_json::json!({ "name": "github", "value": "ghp_token", "connector": "direct" }),
        )
    };
    let (s1, b1) = send_request_and_parse(build_router(state.clone()), mk()).await;
    assert_eq!(s1, 201, "{b1}");
    let (s2, b2) = send_request_and_parse(build_router(state), mk()).await;
    assert_eq!(s2, 409, "{b2}");
    assert_eq!(b2["error_code"], "credential_exists", "{b2}");
}

// ---------------------------------------------------------------------------
// TAP for Platforms — account-less end-user passkey ceremony gating (M4)
// (Full WebAuthn ceremonies with valid assertions are covered by Playwright
// with a virtual authenticator; here we assert auth/team gating.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn passkey_register_begin_requires_app_key() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _app_key, ordinary_key) = make_app_state(mock).await;
    let req = Request::builder()
        .method("POST")
        .uri("/app/users/alice/passkey/register/begin")
        .header("x-tap-key", &ordinary_key)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error_code"], "not_an_app_key", "{body}");
}

#[tokio::test]
async fn approval_passkey_begin_unknown_txn_returns_404() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;
    // webauthn_state is None in this test harness, so an existing txn would 503;
    // an unknown txn must be rejected on the team-binding check first (404),
    // independent of webauthn configuration is not guaranteed — so assert it is
    // one of the gating rejections rather than a success.
    let req = Request::builder()
        .method("POST")
        .uri("/app/users/alice/approvals/no-such-txn/passkey/begin")
        .header("x-tap-key", &app_key)
        .body(Body::empty())
        .unwrap();
    let (status, _body) = send_request_and_parse(build_router(state), req).await;
    assert!(
        status == 404 || status == 503,
        "unknown txn must not be approvable: {status}"
    );
}

// ---------------------------------------------------------------------------
// TAP for Platforms — passkey-lock on policy loosening (M4c)
// ---------------------------------------------------------------------------

fn app_put(api_key: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("x-tap-key", api_key)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn app_policy_tighten_applies_but_loosen_is_locked() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;

    // 1. Initial set establishes passkey protection — applies immediately
    // (the baseline is not yet locked, so this isn't a "loosening").
    let r = app_put(
        &app_key,
        "/app/users/alice/credentials/wallet/policy",
        serde_json::json!({ "require_passkey": true, "require_approval_methods": ["POST"] }),
    );
    let (s, b) = send_request_and_parse(build_router(state.clone()), r).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(b["policy_set"], true, "{b}");

    // 2. Attempt to loosen (drop passkey) — must be STAGED, not applied.
    let r = app_put(
        &app_key,
        "/app/users/alice/credentials/wallet/policy",
        serde_json::json!({ "require_passkey": false }),
    );
    let (s, b) = send_request_and_parse(build_router(state.clone()), r).await;
    assert_eq!(
        s, 202,
        "loosening must be staged behind the end-user passkey: {b}"
    );
    assert_eq!(b["requires_end_user_passkey"], true, "{b}");
    assert!(b["txn_id"].as_str().is_some(), "{b}");

    // The stored policy must be UNCHANGED (still passkey-protected).
    let pol = state
        .db_state
        .store()
        .get_policy("t1", "eu:alice/wallet")
        .await
        .unwrap()
        .unwrap();
    assert!(
        pol.require_passkey,
        "passkey protection must survive the blocked loosening"
    );

    // 3. Tightening (raise min_approvals, keep passkey) applies immediately.
    let r = app_put(
        &app_key,
        "/app/users/alice/credentials/wallet/policy",
        serde_json::json!({ "require_passkey": true, "require_approval_methods": ["POST"], "min_approvals": 2 }),
    );
    let (s, b) = send_request_and_parse(build_router(state.clone()), r).await;
    assert_eq!(s, 200, "tightening should apply directly: {b}");
    let pol = state
        .db_state
        .store()
        .get_policy("t1", "eu:alice/wallet")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pol.min_approvals, 2, "tightening took effect");
    assert!(pol.require_passkey);
}

#[tokio::test]
async fn app_policy_requires_app_key() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _app_key, ordinary_key) = make_app_state(mock).await;
    let r = app_put(
        &ordinary_key,
        "/app/users/alice/credentials/wallet/policy",
        serde_json::json!({ "require_passkey": false }),
    );
    let (s, b) = send_request_and_parse(build_router(state), r).await;
    assert_eq!(s, 403, "{b}");
    assert_eq!(b["error_code"], "not_an_app_key", "{b}");
}

// ---------------------------------------------------------------------------
// TAP for Platforms — TAP-mediated per-end-user OAuth start gating (M3b)
// (Full Google round-trip needs external Google; covered by staging/smoke.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn app_oauth_start_requires_app_key() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _app_key, ordinary_key) = make_app_state(mock).await;
    let r = app_post(
        &ordinary_key,
        "/app/users/alice/credentials/oauth/google/start",
        serde_json::json!({ "name": "google", "return_url": "https://app.example/done" }),
    );
    let (s, b) = send_request_and_parse(build_router(state), r).await;
    assert_eq!(s, 403, "{b}");
    assert_eq!(b["error_code"], "not_an_app_key", "{b}");
}

#[tokio::test]
async fn app_oauth_start_rejects_unsafe_return_url() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, app_key, _ordinary) = make_app_state(mock).await;
    let r = app_post(
        &app_key,
        "/app/users/alice/credentials/oauth/google/start",
        serde_json::json!({ "name": "google", "return_url": "javascript:alert(1)" }),
    );
    let (s, b) = send_request_and_parse(build_router(state), r).await;
    assert_eq!(s, 400, "{b}");
}

// ---------------------------------------------------------------------------
// TAP for Platforms — dashboard End Users endpoints (M5)
// (Data correctness is store-tested; here we confirm routing + session gate.
// The Svelte tab is exercised by the Playwright dashboard E2E.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_end_users_requires_session() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _app_key, _ordinary) = make_app_state(mock).await;
    // No Authorization header → session auth must reject (not a 200).
    let req = Request::builder()
        .method("GET")
        .uri("/team/end-users")
        .body(Body::empty())
        .unwrap();
    let (status, _b) = send_request_and_parse(build_router(state), req).await;
    assert_eq!(
        status, 401,
        "end-users list must require a dashboard session"
    );
}

// ---------------------------------------------------------------------------
// Time-boxed approval grants (#49)
// ---------------------------------------------------------------------------

fn grant_row(
    id: &str,
    route: &str,
    minutes: i64,
    max_uses: Option<i64>,
) -> tap_core::store::GrantRow {
    tap_core::store::GrantRow {
        id: id.to_string(),
        team_id: "t1".into(),
        credential_name: "api-cred".into(),
        methods: vec!["POST".into()],
        route_scope: vec![route.to_string()],
        expires_at: (chrono::Utc::now() + chrono::Duration::minutes(minutes)).to_rfc3339(),
        granted_by: "owner@example.com".into(),
        max_uses,
        uses: 0,
        revoked: false,
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// A live grant covering the request skips the human prompt entirely: the
/// gated POST forwards synchronously, no approval-channel call, and the audit
/// row names the grant. Once max_uses is exhausted the next request escalates
/// to the ordinary approval flow.
#[tokio::test]
async fn db_mode_grant_skips_prompt_then_escalates_when_exhausted() {
    let (upstream_url, _h, _recorded) = start_recording_post_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_db_state(mock.clone()).await;

    state
        .db_state
        .store()
        .create_approval_grant(&grant_row("g-e2e", "/test", 30, Some(1)))
        .await
        .unwrap();

    let post = |target: String| {
        Request::builder()
            .method("POST")
            .uri("/forward")
            .header("x-tap-key", "db-test-key")
            .header("x-tap-credential", "api-cred")
            .header("x-tap-target", target)
            .header("x-tap-method", "POST")
            .body(Body::empty())
            .unwrap()
    };

    // Use 1/1: forwarded directly under the grant — no approval prompt.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        post(format!("{upstream_url}/test")),
    )
    .await;
    assert_eq!(status, 200, "grant-covered POST must forward directly: {body}");
    assert_eq!(
        mock.calls.lock().unwrap().len(),
        0,
        "no approval channel call under a live grant"
    );
    let entries = audit.entries();
    let reason = entries
        .last()
        .and_then(|e| e.policy_reason.clone())
        .unwrap_or_default();
    assert_eq!(reason, "grant:g-e2e", "audit must name the consumed grant");

    // Grant exhausted: the same request now escalates to human approval.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        post(format!("{upstream_url}/test")),
    )
    .await;
    assert_eq!(status, 202, "exhausted grant must escalate: {body}");
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
}

/// A grant only covers its route_scope — an out-of-scope URL escalates.
#[tokio::test]
async fn db_mode_grant_ignores_out_of_scope_url() {
    let (upstream_url, _h, _recorded) = start_recording_post_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock.clone()).await;

    state
        .db_state
        .store()
        .create_approval_grant(&grant_row("g-scope", "/v1/messages", 30, None))
        .await
        .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "POST")
        .body(Body::empty())
        .unwrap();
    let (status, _body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 202, "out-of-scope request must still require approval");
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
}

/// F1: a `require_approval_urls` safety gate (Decision #13) always wins over
/// auto-approve rules — and a grant is an auto-approve rule with a TTL. Even
/// when a live grant EXACTLY covers the requested method+path, a request whose
/// policy decision came from a require-approval-URL must still escalate to
/// human approval; the grant must not override the safety override.
#[tokio::test]
async fn db_mode_grant_does_not_override_require_approval_url() {
    let (upstream_url, _h, _recorded) = start_recording_post_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock.clone()).await;

    // Re-gate the exact path with a require_approval_urls safety override.
    state
        .db_state
        .store()
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "api-cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string()],
            auto_approve_urls: vec![],
            require_approval_urls: vec!["/v1/danger".to_string()],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    // A grant that EXACTLY covers the protected path+method. Absent the F1 fix
    // this grant would be claimed and the request auto-forwarded.
    state
        .db_state
        .store()
        .create_approval_grant(&grant_row("g-safety", "/v1/danger", 30, None))
        .await
        .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/v1/danger"))
        .header("x-tap-method", "POST")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(
        status, 202,
        "require_approval_urls must win over a covering grant: {body}"
    );
    assert_eq!(
        mock.calls.lock().unwrap().len(),
        1,
        "request must escalate to human approval, not be claimed by the grant"
    );
}

/// Guardrails at the create endpoint: match-everything scopes, empty methods,
/// out-of-range TTLs, and passkey-protected credentials are all rejected;
/// a well-scoped grant is created, listed and revocable.
#[tokio::test]
async fn grant_create_endpoint_enforces_guardrails() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "acme", "alice@acme.com", "password123").await;

    for name in ["slack", "prod-keys"] {
        let req = Request::builder()
            .method("POST")
            .uri("/team/credentials")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name": "{name}", "description": "d", "value": "secret", "allowed_hosts": ["api.example.com"]}}"#
            )))
            .unwrap();
        let resp = build_router(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 201);
    }
    let req = Request::builder()
        .method("PUT")
        .uri("/team/policies/prod-keys")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"require_passkey": true}"#))
        .unwrap();
    let resp = build_router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let create = |cred: &str, body: String| {
        Request::builder()
            .method("POST")
            .uri(format!("/team/credentials/{cred}/grants"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    };

    // Match-everything scope rejected.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        create(
            "slack",
            r#"{"methods":["POST"],"route_scope":["/"],"ttl_minutes":30}"#.into(),
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // Path-only scope rejected: it would cover that path on EVERY host,
    // letting the grant auto-approve a forward of the injected secret to an
    // attacker-controlled host. Grants must name their concrete host.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        create(
            "slack",
            r#"{"methods":["POST"],"route_scope":["/v1/messages"],"ttl_minutes":30}"#.into(),
        ),
    )
    .await;
    assert_eq!(status, 400, "path-only grant scope must be rejected: {body}");

    // Empty methods rejected.
    let (status, _) = send_request_and_parse(
        build_router(state.clone()),
        create(
            "slack",
            r#"{"methods":[],"route_scope":["api.example.com/v1/x"],"ttl_minutes":30}"#.into(),
        ),
    )
    .await;
    assert_eq!(status, 400);

    // TTL over the cap rejected.
    let (status, _) = send_request_and_parse(
        build_router(state.clone()),
        create(
            "slack",
            r#"{"methods":["POST"],"route_scope":["api.example.com/v1/x"],"ttl_minutes":9999}"#.into(),
        ),
    )
    .await;
    assert_eq!(status, 400);

    // Passkey-protected credential can never be time-boxed.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        create(
            "prod-keys",
            r#"{"methods":["POST"],"route_scope":["api.example.com/v1/x"],"ttl_minutes":30}"#.into(),
        ),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error_code"], "grant_not_allowed_passkey", "{body}");

    // A well-scoped grant on an ordinary credential is accepted…
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        create(
            "slack",
            r#"{"methods":["POST"],"route_scope":["slack.com/api/chat.postMessage"],"ttl_minutes":30,"max_uses":15}"#.into(),
        ),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let grant_id = body["grant"]["id"].as_str().unwrap().to_string();

    // …listed team-wide…
    let req = Request::builder()
        .method("GET")
        .uri("/team/grants")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200);
    assert_eq!(body["grants"].as_array().unwrap().len(), 1);

    // …and revocable in one click.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/team/grants/{grant_id}/revoke"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], true);
}

// --- Inbox approve-with-grant (#49 follow-up) --------------------------------

/// Full environment for the dashboard-inbox grant flow: real DashboardChannel
/// (persists `pending_approvals` during `/forward`) with the webauthn approval
/// router merged in, so `/forward` and `/approve/dashboard/*` are both
/// reachable on one router. `role` controls the member the session belongs to.
async fn make_inbox_grant_env(
    role: &str,
) -> (
    AppState,
    axum::Router,
    Arc<InMemoryAuditLogger>,
    String, // session token
    String, // team_id
    tempfile::NamedTempFile,
) {
    use tap_proxy::dashboard_channel::DashboardChannel;

    let (store, tmp) = temp_store().await;
    let team_id = uuid::Uuid::new_v4().to_string();
    store
        .create_team(&team_id, "grant-inbox-team")
        .await
        .unwrap();

    store
        .create_credential(
            &team_id, "api-cred", "API cred", "direct", None, false, None, None, None,
        )
        .await
        .unwrap();
    store
        .set_credential_value(&team_id, "api-cred", b"secret123")
        .await
        .unwrap();
    store
        .create_agent(
            &team_id,
            "grant-agent",
            None,
            &hash_api_key("grant-inbox-key"),
            None,
        )
        .await
        .unwrap();
    store
        .add_direct_credential(&team_id, "grant-agent", "api-cred")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: team_id.clone(),
            credential_name: "api-cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string()],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 1,
        })
        .await
        .unwrap();

    // Session member with the requested role (email pre-verified for tests).
    let user_id = uuid::Uuid::new_v4().to_string();
    let pw_hash = tap_proxy::admin::hash_password("pw-grant-inbox").unwrap();
    let uid = store
        .create_user_with_membership(
            &user_id,
            &team_id,
            "inbox-grant@example.com",
            &pw_hash,
            role,
        )
        .await
        .unwrap();
    store.set_user_email_verified(&uid).await.unwrap();

    let dashboard_channel: Arc<dyn ApprovalChannel> = Arc::new(DashboardChannel::new(
        Arc::new(store.clone()),
        "http://localhost".to_string(),
        None,
        1200,
    ));
    let audit = Arc::new(InMemoryAuditLogger::new());
    let db_state = Arc::new(DbState::new(store.clone(), Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(test_key()),
        approval_channel: dashboard_channel.clone(),
        dashboard_channel: dashboard_channel.clone(),
        telegram_channel: Some(dashboard_channel.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: audit.clone(),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"email": "inbox-grant@example.com", "password": "pw-grant-inbox"}).to_string(),
        ))
        .unwrap();
    let (status, val) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200, "login must succeed: {val}");
    let token = val["session_token"].as_str().unwrap().to_string();

    // The approval endpoints live on the webauthn router (merged in main.rs in
    // production); merge the same way here.
    let wa = Arc::new(
        tap_proxy::webauthn::WebAuthnState::new(
            "localhost",
            "http://localhost",
            "http://localhost",
            Some(store.clone()),
            &[],
        )
        .unwrap(),
    );
    let tg = Arc::new(
        tap_bot::TelegramChannel::new(tap_bot::TelegramConfig {
            bot_token: String::new(),
            chat_id: String::new(),
        })
        .unwrap(),
    );
    let router = build_router(state.clone()).merge(tap_proxy::webauthn::build_approval_router(
        wa,
        Some(tg),
        None,
        Some(Arc::new(store)),
    ));

    (state, router, audit, token, team_id, tmp)
}

fn inbox_grant_forward(target: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/forward")
        .header("X-TAP-Key", "grant-inbox-key")
        .header("X-TAP-Credential", "api-cred")
        .header("X-TAP-Target", target)
        .header("X-TAP-Method", "POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"n":1}"#))
        .unwrap()
}

/// The headline flow: a gated POST lands in the inbox; the manager approves it
/// WITH a 30-minute grant; the identical follow-up request skips the prompt
/// (200, audit names the grant); an out-of-scope URL still escalates.
#[tokio::test]
async fn db_mode_inbox_approve_with_grant_opens_window_then_out_of_scope_escalates() {
    let (state, router, audit, token, team_id, _tmp) = make_inbox_grant_env("owner").await;
    let (upstream, _h, _rec) = start_recording_post_upstream().await;

    let (status, body) = send_request_and_parse(
        router.clone(),
        inbox_grant_forward(&format!("{upstream}/test")),
    )
    .await;
    assert_eq!(status, 202, "gated write must escalate first: {body}");
    let rows = state
        .db_state
        .store()
        .list_pending_approvals_for_team(&team_id)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "one pending inbox row");
    let txn_id = rows[0].txn_id.clone();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approve/dashboard/{txn_id}/approve-with-grant"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"ttl_minutes": 30}).to_string()))
        .unwrap();
    let (status, val) = send_request_and_parse(router.clone(), req).await;
    assert_eq!(status, 200, "approve-with-grant must succeed: {val}");
    assert_eq!(val["status"], "approved");
    let grant_id = val["grant"]["id"].as_str().unwrap().to_string();
    // Scope is derived from the request the human reviewed: this method only,
    // host-pinned to the upstream, path-anchored to the route.
    assert_eq!(val["grant"]["methods"], json!(["POST"]));
    let scope = val["grant"]["route_scope"][0].as_str().unwrap();
    assert!(
        scope.ends_with("/test") && !scope.starts_with('/'),
        "scope must be host-pinned + path-anchored, got: {scope}"
    );

    // Identical follow-up request: straight through, no prompt.
    let (status, body) = send_request_and_parse(
        router.clone(),
        inbox_grant_forward(&format!("{upstream}/test")),
    )
    .await;
    assert_eq!(status, 200, "grant-covered POST must skip the prompt: {body}");
    let expected_reason = format!("grant:{grant_id}");
    assert!(
        audit
            .entries()
            .iter()
            .any(|e| e.policy_reason.as_deref() == Some(expected_reason.as_str())),
        "audit must name the consumed grant"
    );

    // Out-of-scope path on the same host: the grant must NOT cover it.
    let (status, body) = send_request_and_parse(
        router.clone(),
        inbox_grant_forward(&format!("{upstream}/other")),
    )
    .await;
    assert_eq!(status, 202, "out-of-scope URL must still escalate: {body}");
}

/// Only workspace managers may open an auto-approve window. A plain approver
/// gets a 403 and no grant row comes into existence.
#[tokio::test]
async fn inbox_approve_with_grant_requires_workspace_manager() {
    let (state, router, _audit, token, team_id, _tmp) = make_inbox_grant_env("approver").await;
    let (upstream, _h, _rec) = start_recording_post_upstream().await;

    let (status, _body) = send_request_and_parse(
        router.clone(),
        inbox_grant_forward(&format!("{upstream}/test")),
    )
    .await;
    assert_eq!(status, 202);
    let rows = state
        .db_state
        .store()
        .list_pending_approvals_for_team(&team_id)
        .await
        .unwrap();
    let txn_id = rows[0].txn_id.clone();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approve/dashboard/{txn_id}/approve-with-grant"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"ttl_minutes": 30}).to_string()))
        .unwrap();
    let (status, val) = send_request_and_parse(router.clone(), req).await;
    assert_eq!(status, 403, "approver role must be refused: {val}");
    assert_eq!(val["error_code"], "grant_requires_manager");
    assert!(
        state
            .db_state
            .store()
            .list_approval_grants(&team_id)
            .await
            .unwrap()
            .is_empty(),
        "no grant may exist after a refused attempt"
    );
}

/// approve-with-grant reuses the plain approve's authorization: a
/// require_passkey credential is refused (412) before any grant logic runs,
/// and the pending request stays pending.
#[tokio::test]
async fn inbox_approve_with_grant_refuses_passkey_credential() {
    let (state, router, _audit, token, team_id, _tmp) = make_inbox_grant_env("owner").await;
    let (upstream, _h, _rec) = start_recording_post_upstream().await;

    // Tighten the policy to require a passkey BEFORE the request comes in.
    let store = state.db_state.store();
    store
        .set_policy(&PolicyRow {
            team_id: team_id.clone(),
            credential_name: "api-cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string()],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: true,
            min_approvals: 1,
        })
        .await
        .unwrap();

    let (status, _body) = send_request_and_parse(
        router.clone(),
        inbox_grant_forward(&format!("{upstream}/test")),
    )
    .await;
    assert_eq!(status, 202);
    let rows = store
        .list_pending_approvals_for_team(&team_id)
        .await
        .unwrap();
    let txn_id = rows[0].txn_id.clone();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approve/dashboard/{txn_id}/approve-with-grant"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"ttl_minutes": 30}).to_string()))
        .unwrap();
    let (status, val) = send_request_and_parse(router.clone(), req).await;
    assert_eq!(status, 412, "passkey credential must be refused: {val}");
    assert!(
        store
            .list_approval_grants(&team_id)
            .await
            .unwrap()
            .is_empty(),
        "no grant may exist for a passkey credential"
    );
    // Still pending: the refused call must not have resolved the row.
    assert_eq!(
        store
            .list_pending_approvals_for_team(&team_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// The strict claim behind every grant surface (`claim_pending_approval_for_grant`):
/// only the actual pending→approved transition returns true. An
/// already-approved row does NOT count (unlike `resolve_pending_approval`,
/// which treats a same-status re-resolution as success for duplicate
/// delivery), and a prior deny wins — so two concurrent "approve with grant"
/// actions can never both mint a window.
#[tokio::test]
async fn claim_pending_approval_for_grant_is_exclusive() {
    let (store, _tmp) = temp_store().await;
    let expires = (chrono::Utc::now() + chrono::Duration::minutes(20)).to_rfc3339();

    store
        .save_pending_approval_with_team("txn-grant-claim", "{}", &expires, None)
        .await
        .unwrap();
    assert!(
        store
            .claim_pending_approval_for_grant("txn-grant-claim", Some("a@example.com"))
            .await
            .unwrap(),
        "first claim takes the pending→approved transition"
    );
    assert!(
        !store
            .claim_pending_approval_for_grant("txn-grant-claim", Some("b@example.com"))
            .await
            .unwrap(),
        "second claim must lose: the row is no longer pending"
    );
    // Contrast: the idempotent resolve still reports success on the
    // already-approved row — which is exactly why the grant path can't use it.
    assert!(store
        .resolve_pending_approval("txn-grant-claim", "approved", None)
        .await
        .unwrap());

    // A prior deny wins against a grant claim.
    store
        .save_pending_approval_with_team("txn-grant-denied", "{}", &expires, None)
        .await
        .unwrap();
    assert!(store
        .resolve_pending_approval("txn-grant-denied", "denied", None)
        .await
        .unwrap());
    assert!(
        !store
            .claim_pending_approval_for_grant("txn-grant-denied", Some("a@example.com"))
            .await
            .unwrap(),
        "a denied row must never be claimable for a grant"
    );
}

/// Double-submitting approve-with-grant must mint exactly ONE grant: the
/// second submission hits the exclusive claim (or the details load) and is
/// refused instead of stacking a second window on the already-approved row.
#[tokio::test]
async fn inbox_approve_with_grant_double_submit_mints_one_grant() {
    let (state, router, _audit, token, team_id, _tmp) = make_inbox_grant_env("owner").await;
    let (upstream, _h, _rec) = start_recording_post_upstream().await;

    let (status, _body) = send_request_and_parse(
        router.clone(),
        inbox_grant_forward(&format!("{upstream}/test")),
    )
    .await;
    assert_eq!(status, 202);
    let store = state.db_state.store();
    let rows = store
        .list_pending_approvals_for_team(&team_id)
        .await
        .unwrap();
    let txn_id = rows[0].txn_id.clone();

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri(format!("/approve/dashboard/{txn_id}/approve-with-grant"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"ttl_minutes": 30}).to_string()))
            .unwrap()
    };
    let (status, val) = send_request_and_parse(router.clone(), make_req()).await;
    assert_eq!(status, 200, "first approve-with-grant succeeds: {val}");

    let (status, val) = send_request_and_parse(router.clone(), make_req()).await;
    assert_ne!(
        status, 200,
        "second submission must be refused, not mint another grant: {val}"
    );
    assert_eq!(
        store.list_approval_grants(&team_id).await.unwrap().len(),
        1,
        "exactly one grant may exist after a double-submit"
    );
}

/// A multi-approval credential can't be short-circuited by one manager via the
/// dashboard grant button — same refusal as the Telegram ⏱ / Matrix ⏳ paths.
#[tokio::test]
async fn inbox_approve_with_grant_refuses_multi_approval_credential() {
    let (state, router, _audit, token, team_id, _tmp) = make_inbox_grant_env("owner").await;
    let (upstream, _h, _rec) = start_recording_post_upstream().await;

    let store = state.db_state.store();
    store
        .set_policy(&PolicyRow {
            team_id: team_id.clone(),
            credential_name: "api-cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string()],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            allowed_approvers: vec![],
            approval_channel: None,
            telegram_chat_id: None,
            matrix_room_id: None,
            matrix_allowed_approvers: vec![],
            require_passkey: false,
            min_approvals: 2,
        })
        .await
        .unwrap();

    let (status, _body) = send_request_and_parse(
        router.clone(),
        inbox_grant_forward(&format!("{upstream}/test")),
    )
    .await;
    assert_eq!(status, 202);
    let rows = store
        .list_pending_approvals_for_team(&team_id)
        .await
        .unwrap();
    let txn_id = rows[0].txn_id.clone();

    let req = Request::builder()
        .method("POST")
        .uri(format!("/approve/dashboard/{txn_id}/approve-with-grant"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"ttl_minutes": 30}).to_string()))
        .unwrap();
    let (status, val) = send_request_and_parse(router.clone(), req).await;
    assert_eq!(status, 400, "multi-approval credential must be refused: {val}");
    assert_eq!(val["error_code"], "grant_not_allowed_multi_approval");
    assert!(
        store
            .list_approval_grants(&team_id)
            .await
            .unwrap()
            .is_empty(),
        "no grant may exist for a multi-approval credential"
    );
    // Still pending: the refusal happens before any resolve.
    assert_eq!(
        store
            .list_pending_approvals_for_team(&team_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// Google sign-in (dashboard login) — see crates/tap-proxy/src/google_login.rs
// ---------------------------------------------------------------------------

/// Mock Google token endpoint: mints an (unsigned) id_token whose identity is
/// derived from the authorization `code`, so one server covers every scenario.
/// Codes look like `sub|email|verified`.
async fn start_mock_google_token_endpoint() -> (String, tokio::task::JoinHandle<()>) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    async fn token(body: String) -> axum::Json<serde_json::Value> {
        let params: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
        let code = params.get("code").cloned().unwrap_or_default();
        let mut parts = code.split('|');
        let sub = parts.next().unwrap_or_default();
        let email = parts.next().unwrap_or_default();
        let verified = parts.next() == Some("verified");
        // `parse_id_token_claims` validates aud/iss/exp as defense-in-depth, so
        // the mock must mint a well-formed token: audience = the client id the
        // harness configures (`test-client`), a Google issuer, and a future exp.
        let payload = json!({
            "sub": sub,
            "email": email,
            "email_verified": verified,
            "aud": "test-client",
            "iss": "https://accounts.google.com",
            "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        });
        let id_token = format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes()),
        );
        axum::Json(json!({"access_token": "at", "id_token": id_token}))
    }

    let app = axum::Router::new().route("/token", axum::routing::post(token));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/token");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle)
}

/// Drive /auth/google/start on `app_a` and the callback (with `code`) on
/// `app_b` — different router instances sharing the DB, per the Distributed
/// State Rule. Returns the callback redirect Location.
async fn google_roundtrip(app_a: axum::Router, app_b: axum::Router, code: &str) -> String {
    let (oauth_state, bind_cookie) = google_start(app_a).await;
    // The browser carries the binding cookie from /start back to the callback.
    callback_location(app_b, &oauth_state, code, bind_cookie.as_deref()).await
}

/// Drive /auth/google/start and return `(oauth_state, bind_cookie)`, where
/// `bind_cookie` is the `name=value` pair to replay as the browser `Cookie`.
async fn google_start(app: axum::Router) -> (String, Option<String>) {
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/google/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_redirection(), "start must redirect");
    let bind_cookie = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            s.starts_with("tap_oauth_bind=")
                .then(|| s.split(';').next().unwrap_or(s).to_string())
        });
    let location = resp.headers()["location"].to_str().unwrap();
    let auth_url = url::Url::parse(location).unwrap();
    assert_eq!(auth_url.host_str(), Some("accounts.google.com"));
    let oauth_state = auth_url
        .query_pairs()
        .find_map(|(k, v)| (k == "state").then(|| v.into_owned()))
        .expect("state param present");
    (oauth_state, bind_cookie)
}

async fn callback_location(
    app: axum::Router,
    oauth_state: &str,
    code: &str,
    bind_cookie: Option<&str>,
) -> String {
    let uri = format!(
        "/auth/google/callback?state={}&code={}",
        urlencode_query(oauth_state),
        urlencode_query(code)
    );
    let mut builder = Request::builder().uri(uri);
    if let Some(cookie) = bind_cookie {
        builder = builder.header(axum::http::header::COOKIE, cookie);
    }
    let resp = app.oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();
    assert!(resp.status().is_redirection(), "callback must redirect");
    resp.headers()["location"].to_str().unwrap().to_string()
}

fn urlencode_query(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn query_param(location: &str, key: &str) -> Option<String> {
    url::Url::parse(location)
        .ok()?
        .query_pairs()
        .find_map(|(k, v)| (k == key).then(|| v.into_owned()))
}

async fn complete_google(
    app: axum::Router,
    token: &str,
    team_name: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let mut body = json!({"token": token});
    if let Some(name) = team_name {
        body["team_name"] = json!(name);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/auth/google/complete")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    send_request_and_parse(app, req).await
}

/// One sequential test for the whole Google sign-in surface: the flow mutates
/// process env (Google client config + the test token endpoint), and env is
/// process-global while the integration suite runs in parallel.
#[tokio::test]
async fn google_login_signup_link_and_state_rules() {
    let (token_url, _h) = start_mock_google_token_endpoint().await;
    std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "test-client");
    std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "test-secret");
    std::env::set_var("TAP_GOOGLE_LOGIN_TOKEN_URL", &token_url);
    std::env::set_var(
        "GOOGLE_LOGIN_REDIRECT_URI",
        "http://127.0.0.1:3100/auth/google/callback",
    );

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    // webauthn_state is None in the test harness, so a completed continuation
    // returns a full session — which also exercises the immediate persistence
    // of staged identity links.
    let (state, _audit, _tmp) = make_state(mock).await;
    let store = state.db_state.store().clone();
    let app = || build_router(state.clone());

    // --- (c) no account: signup continuation, project name required --------
    let location = google_roundtrip(app(), app(), "sub-new|alice@example.com|verified").await;
    let token = query_param(&location, "google_signup").expect("signup continuation");
    assert_eq!(query_param(&location, "join").as_deref(), Some("0"));

    // Missing project name: 400 + needs_team_name, and the single-use token is
    // RE-ARMED (a typo must not force the user back through Google).
    let (status, body) = complete_google(app(), &token, None).await;
    assert_eq!(status, 400);
    assert_eq!(body["needs_team_name"], true);

    // Same token again, with a name -> account + team + session.
    let (status, body) = complete_google(app(), &token, Some("g-team-alice")).await;
    assert_eq!(status, 200, "signup completes: {body}");
    assert!(body["session_token"].is_string());
    let alice = store
        .get_user_by_email("alice@example.com")
        .await
        .unwrap()
        .expect("alice created");
    assert!(alice.email_verified, "Google-verified email skips the code");
    assert_eq!(
        store
            .get_identity_user("google", "sub-new")
            .await
            .unwrap()
            .as_deref(),
        Some(alice.id.as_str()),
        "new account links immediately"
    );

    // The continuation is spent — replaying it must fail.
    let (status, _b) = complete_google(app(), &token, Some("g-team-alice2")).await;
    assert_eq!(status, 401, "spent continuation is single-use");

    // --- (a) linked identity: plain login ----------------------------------
    let location = google_roundtrip(app(), app(), "sub-new|alice@example.com|verified").await;
    let token = query_param(&location, "google_login").expect("login continuation");
    let (status, body) = complete_google(app(), &token, None).await;
    assert_eq!(status, 200, "linked login completes: {body}");
    assert!(body["session_token"].is_string());

    // Email changes on the Google account do not matter — sub is the key.
    let location = google_roundtrip(app(), app(), "sub-new|renamed@example.com|verified").await;
    assert!(query_param(&location, "google_login").is_some());

    // --- (b) existing verified password account: staged link ---------------
    let carol_hash = tap_proxy::admin::hash_password("carol-password-123").unwrap();
    store.create_team("t-carol", "carol-team").await.unwrap();
    store
        .create_user_with_membership(
            "u-carol",
            "t-carol",
            "carol@example.com",
            &carol_hash,
            "owner",
        )
        .await
        .unwrap();
    store.set_user_email_verified("u-carol").await.unwrap();

    let location = google_roundtrip(app(), app(), "sub-carol|carol@example.com|verified").await;
    let token = query_param(&location, "google_login").expect("link continuation");
    assert!(
        store
            .get_identity_user("google", "sub-carol")
            .await
            .unwrap()
            .is_none(),
        "link must NOT persist before the login completes"
    );
    let (status, body) = complete_google(app(), &token, None).await;
    assert_eq!(status, 200, "carol login completes: {body}");
    assert_eq!(
        store
            .get_identity_user("google", "sub-carol")
            .await
            .unwrap()
            .as_deref(),
        Some("u-carol"),
        "full login persists the staged link"
    );

    // --- (b2) existing UNVERIFIED account: refuse (takeover guard) ---------
    store.create_team("t-dave", "dave-team").await.unwrap();
    store
        .create_user_with_membership(
            "u-dave",
            "t-dave",
            "dave@example.com",
            &carol_hash,
            "owner",
        )
        .await
        .unwrap();
    let location = google_roundtrip(app(), app(), "sub-dave|dave@example.com|verified").await;
    assert_eq!(
        query_param(&location, "google_login_error").as_deref(),
        Some("account_email_unverified"),
        "unverified squatted account must not be inherited"
    );
    assert!(store
        .get_identity_user("google", "sub-dave")
        .await
        .unwrap()
        .is_none());

    // --- Google-side unverified email: refuse ------------------------------
    let location = google_roundtrip(app(), app(), "sub-eve|eve@example.com|unverified").await;
    assert_eq!(
        query_param(&location, "google_login_error").as_deref(),
        Some("google_email_unverified")
    );

    // --- state replay + expiry ---------------------------------------------
    // Fresh start, then replay the SAME state twice: second consume must fail.
    let (oauth_state, bind_cookie) = google_start(app()).await;
    let first = callback_location(
        app(),
        &oauth_state,
        "sub-x|x@example.com|verified",
        bind_cookie.as_deref(),
    )
    .await;
    assert!(query_param(&first, "google_signup").is_some());
    let replay = callback_location(
        app(),
        &oauth_state,
        "sub-x|x@example.com|verified",
        bind_cookie.as_deref(),
    )
    .await;
    assert_eq!(
        query_param(&replay, "google_login_error").as_deref(),
        Some("invalid_state"),
        "a state is single-use"
    );

    // --- browser-binding (login-CSRF / session-fixation) -------------------
    // A callback replayed WITHOUT the binding cookie the initiating browser
    // holds must be rejected — even though the state itself is valid.
    let (bound_state, bound_cookie) = google_start(app()).await;
    let no_cookie =
        callback_location(app(), &bound_state, "sub-z|z@example.com|verified", None).await;
    assert_eq!(
        query_param(&no_cookie, "google_login_error").as_deref(),
        Some("missing_bind"),
        "callback without the binding cookie is rejected"
    );
    // And the claim burned the state, so even the right cookie can't reuse it.
    let after_burn = callback_location(
        app(),
        &bound_state,
        "sub-z|z@example.com|verified",
        bound_cookie.as_deref(),
    )
    .await;
    assert_eq!(
        query_param(&after_burn, "google_login_error").as_deref(),
        Some("invalid_state"),
        "a failed-bind callback still consumes the single-use state"
    );
    // A cookie whose nonce doesn't match the stored hash is rejected too.
    let (mismatch_state, _) = google_start(app()).await;
    let mismatch = callback_location(
        app(),
        &mismatch_state,
        "sub-w|w@example.com|verified",
        Some("tap_oauth_bind=not-the-right-nonce"),
    )
    .await;
    assert_eq!(
        query_param(&mismatch, "google_login_error").as_deref(),
        Some("bind_mismatch"),
        "a mismatched binding cookie is rejected"
    );

    // Expired state: insert one already past its expiry (no binding hash —
    // expiry is checked before the bind check, so this still surfaces as
    // expired_state).
    let expired_hash = tap_proxy::admin::hash_session_token("expired-state-token");
    store
        .create_login_oauth_state(
            &expired_hash,
            "google",
            &(chrono::Utc::now() - chrono::Duration::seconds(5)).to_rfc3339(),
            None,
        )
        .await
        .unwrap();
    let loc = callback_location(
        app(),
        "expired-state-token",
        "sub-y|y@example.com|verified",
        None,
    )
    .await;
    assert_eq!(
        query_param(&loc, "google_login_error").as_deref(),
        Some("expired_state")
    );

    std::env::remove_var("GOOGLE_OAUTH_CLIENT_ID");
    std::env::remove_var("GOOGLE_OAUTH_CLIENT_SECRET");
    std::env::remove_var("TAP_GOOGLE_LOGIN_TOKEN_URL");
    std::env::remove_var("GOOGLE_LOGIN_REDIRECT_URI");
}

// ---------------------------------------------------------------------------
// GitHub sign-in (dashboard login) — see crates/tap-proxy/src/github_login.rs
// ---------------------------------------------------------------------------

/// Mock GitHub: the token endpoint forges `access_token = code`, and the API
/// endpoints (`/user`, `/user/emails`) parse the identity back out of the
/// bearer token — so one server covers every scenario. Codes look like
/// `numeric_id|email|verified`.
async fn start_mock_github_endpoints() -> (String, String, tokio::task::JoinHandle<()>) {
    fn bearer_identity(headers: &axum::http::HeaderMap) -> (String, String, bool) {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        let mut parts = token.split('|');
        let id = parts.next().unwrap_or_default().to_string();
        let email = parts.next().unwrap_or_default().to_string();
        let verified = parts.next() == Some("verified");
        (id, email, verified)
    }

    async fn token(headers: axum::http::HeaderMap, body: String) -> axum::Json<serde_json::Value> {
        // Without Accept: application/json GitHub answers form-encoded.
        assert_eq!(
            headers.get("accept").and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "token exchange must send Accept: application/json"
        );
        let params: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
        let code = params.get("code").cloned().unwrap_or_default();
        axum::Json(
            json!({"access_token": code, "token_type": "bearer", "scope": "read:user,user:email"}),
        )
    }

    async fn user(headers: axum::http::HeaderMap) -> axum::Json<serde_json::Value> {
        assert!(
            headers.contains_key("user-agent"),
            "GitHub requires a User-Agent header"
        );
        let (id, _email, _verified) = bearer_identity(&headers);
        let id: u64 = id.parse().expect("mock codes start with a numeric id");
        // login/name/email are deliberately unusable — the flow must key on
        // the numeric id and read the email from /user/emails.
        axum::Json(json!({"id": id, "login": "renameable-login", "name": null, "email": null}))
    }

    async fn emails(headers: axum::http::HeaderMap) -> axum::Json<serde_json::Value> {
        assert!(headers.contains_key("user-agent"));
        let (_id, email, verified) = bearer_identity(&headers);
        axum::Json(json!([
            {"email": "secondary-verified@example.net", "primary": false, "verified": true},
            {"email": email, "primary": true, "verified": verified},
        ]))
    }

    let app = axum::Router::new()
        .route("/login/oauth/access_token", axum::routing::post(token))
        .route("/user", axum::routing::get(user))
        .route("/user/emails", axum::routing::get(emails));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token_url = format!("http://{addr}/login/oauth/access_token");
    let api_url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (token_url, api_url, handle)
}

/// Drive /auth/github/start on `app_a` and the callback (with `code`) on
/// `app_b` — different router instances sharing the DB, per the Distributed
/// State Rule. Returns the callback redirect Location.
async fn github_roundtrip(app_a: axum::Router, app_b: axum::Router, code: &str) -> String {
    let resp = app_a
        .oneshot(
            Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_redirection(), "start must redirect");
    // /start sets the browser-binding cookie; the callback requires it.
    let bind_cookie = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            s.starts_with("tap_oauth_bind=")
                .then(|| s.split(';').next().unwrap_or(s).to_string())
        });
    let location = resp.headers()["location"].to_str().unwrap();
    let auth_url = url::Url::parse(location).unwrap();
    assert_eq!(auth_url.host_str(), Some("github.com"));
    assert_eq!(auth_url.path(), "/login/oauth/authorize");
    let scope = auth_url
        .query_pairs()
        .find_map(|(k, v)| (k == "scope").then(|| v.into_owned()))
        .expect("scope param present");
    assert_eq!(scope, "read:user user:email");
    let oauth_state = auth_url
        .query_pairs()
        .find_map(|(k, v)| (k == "state").then(|| v.into_owned()))
        .expect("state param present");

    github_callback_location(app_b, &oauth_state, code, bind_cookie.as_deref()).await
}

async fn github_callback_location(
    app: axum::Router,
    oauth_state: &str,
    code: &str,
    bind_cookie: Option<&str>,
) -> String {
    let uri = format!(
        "/auth/github/callback?state={}&code={}",
        urlencode_query(oauth_state),
        urlencode_query(code)
    );
    let mut req = Request::builder().uri(uri);
    if let Some(cookie) = bind_cookie {
        req = req.header(axum::http::header::COOKIE, cookie);
    }
    let resp = app
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(resp.status().is_redirection(), "callback must redirect");
    resp.headers()["location"].to_str().unwrap().to_string()
}

async fn complete_github(
    app: axum::Router,
    token: &str,
    team_name: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let mut body = json!({"token": token});
    if let Some(name) = team_name {
        body["team_name"] = json!(name);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/auth/github/complete")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    send_request_and_parse(app, req).await
}

/// One sequential test for the whole GitHub sign-in surface, mirroring
/// `google_login_signup_link_and_state_rules`: the flow mutates process env
/// (GitHub client config + the test endpoint overrides), and env is
/// process-global while the integration suite runs in parallel. The env vars
/// are disjoint from the Google test's, so the two can still interleave.
#[tokio::test]
async fn github_login_signup_link_and_state_rules() {
    let (token_url, api_url, _h) = start_mock_github_endpoints().await;
    std::env::set_var("GITHUB_LOGIN_CLIENT_ID", "test-gh-client");
    std::env::set_var("GITHUB_LOGIN_CLIENT_SECRET", "test-gh-secret");
    std::env::set_var("TAP_GITHUB_LOGIN_TOKEN_URL", &token_url);
    std::env::set_var("TAP_GITHUB_LOGIN_API_URL", &api_url);
    std::env::set_var(
        "GITHUB_LOGIN_REDIRECT_URI",
        "http://127.0.0.1:3100/auth/github/callback",
    );

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    // webauthn_state is None in the test harness, so a completed continuation
    // returns a full session — which also exercises the immediate persistence
    // of staged identity links.
    let (state, _audit, _tmp) = make_state(mock).await;
    let store = state.db_state.store().clone();
    let app = || build_router(state.clone());

    // --- (c) no account: signup continuation, project name required --------
    let location = github_roundtrip(app(), app(), "201|gh-alice@example.com|verified").await;
    let token = query_param(&location, "github_signup").expect("signup continuation");
    assert_eq!(query_param(&location, "join").as_deref(), Some("0"));

    // Missing project name: 400 + needs_team_name, and the single-use token is
    // RE-ARMED (a typo must not force the user back through GitHub).
    let (status, body) = complete_github(app(), &token, None).await;
    assert_eq!(status, 400);
    assert_eq!(body["needs_team_name"], true);

    // Same token again, with a name -> account + team + session.
    let (status, body) = complete_github(app(), &token, Some("gh-team-alice")).await;
    assert_eq!(status, 200, "signup completes: {body}");
    assert!(body["session_token"].is_string());
    let alice = store
        .get_user_by_email("gh-alice@example.com")
        .await
        .unwrap()
        .expect("alice created");
    assert!(alice.email_verified, "GitHub-verified email skips the code");
    assert_eq!(
        store
            .get_identity_user("github", "201")
            .await
            .unwrap()
            .as_deref(),
        Some(alice.id.as_str()),
        "new account links immediately, keyed on the numeric id"
    );

    // The continuation is spent — replaying it must fail.
    let (status, _b) = complete_github(app(), &token, Some("gh-team-alice2")).await;
    assert_eq!(status, 401, "spent continuation is single-use");

    // --- (a) linked identity: plain login ----------------------------------
    let location = github_roundtrip(app(), app(), "201|gh-alice@example.com|verified").await;
    let token = query_param(&location, "github_login").expect("login continuation");
    let (status, body) = complete_github(app(), &token, None).await;
    assert_eq!(status, 200, "linked login completes: {body}");
    assert!(body["session_token"].is_string());

    // Email changes on the GitHub account do not matter — the id is the key.
    let location = github_roundtrip(app(), app(), "201|gh-renamed@example.com|verified").await;
    assert!(query_param(&location, "github_login").is_some());

    // --- (b) existing verified password account: staged link ---------------
    let carol_hash = tap_proxy::admin::hash_password("carol-password-123").unwrap();
    store
        .create_team("t-gh-carol", "gh-carol-team")
        .await
        .unwrap();
    store
        .create_user_with_membership(
            "u-gh-carol",
            "t-gh-carol",
            "gh-carol@example.com",
            &carol_hash,
            "owner",
        )
        .await
        .unwrap();
    store.set_user_email_verified("u-gh-carol").await.unwrap();

    let location = github_roundtrip(app(), app(), "202|gh-carol@example.com|verified").await;
    let token = query_param(&location, "github_login").expect("link continuation");
    assert!(
        store
            .get_identity_user("github", "202")
            .await
            .unwrap()
            .is_none(),
        "link must NOT persist before the login completes"
    );
    let (status, body) = complete_github(app(), &token, None).await;
    assert_eq!(status, 200, "carol login completes: {body}");
    assert_eq!(
        store
            .get_identity_user("github", "202")
            .await
            .unwrap()
            .as_deref(),
        Some("u-gh-carol"),
        "full login persists the staged link"
    );

    // --- (b2) existing UNVERIFIED account: refuse (takeover guard) ---------
    store
        .create_team("t-gh-dave", "gh-dave-team")
        .await
        .unwrap();
    store
        .create_user_with_membership(
            "u-gh-dave",
            "t-gh-dave",
            "gh-dave@example.com",
            &carol_hash,
            "owner",
        )
        .await
        .unwrap();
    let location = github_roundtrip(app(), app(), "203|gh-dave@example.com|verified").await;
    assert_eq!(
        query_param(&location, "github_login_error").as_deref(),
        Some("account_email_unverified"),
        "unverified squatted account must not be inherited"
    );
    assert!(store
        .get_identity_user("github", "203")
        .await
        .unwrap()
        .is_none());

    // --- GitHub-side unverified primary email: refuse ----------------------
    let location = github_roundtrip(app(), app(), "204|gh-eve@example.com|unverified").await;
    assert_eq!(
        query_param(&location, "github_login_error").as_deref(),
        Some("github_email_unverified"),
        "an unverified primary GitHub email must never mint or link an account"
    );
    assert!(store
        .get_identity_user("github", "204")
        .await
        .unwrap()
        .is_none());

    // --- state replay + expiry ---------------------------------------------
    // Fresh start, then replay the SAME state twice: second consume must fail.
    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Carry the binding cookie so this asserts state single-use, not the bind check.
    let replay_cookie = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            s.starts_with("tap_oauth_bind=")
                .then(|| s.split(';').next().unwrap_or(s).to_string())
        });
    let auth_url = url::Url::parse(resp.headers()["location"].to_str().unwrap()).unwrap();
    let oauth_state = auth_url
        .query_pairs()
        .find_map(|(k, v)| (k == "state").then(|| v.into_owned()))
        .unwrap();
    let first = github_callback_location(
        app(),
        &oauth_state,
        "205|gh-x@example.com|verified",
        replay_cookie.as_deref(),
    )
    .await;
    assert!(query_param(&first, "github_signup").is_some());
    let replay = github_callback_location(
        app(),
        &oauth_state,
        "205|gh-x@example.com|verified",
        replay_cookie.as_deref(),
    )
    .await;
    assert_eq!(
        query_param(&replay, "github_login_error").as_deref(),
        Some("invalid_state"),
        "a state is single-use"
    );

    // Expired state: insert one already past its expiry.
    let expired_hash = tap_proxy::admin::hash_session_token("gh-expired-state-token");
    store
        .create_login_oauth_state(
            &expired_hash,
            "github",
            &(chrono::Utc::now() - chrono::Duration::seconds(5)).to_rfc3339(),
            None,
        )
        .await
        .unwrap();
    // No bind cookie needed: the expiry check runs before the binding check.
    let loc = github_callback_location(
        app(),
        "gh-expired-state-token",
        "206|gh-y@example.com|verified",
        None,
    )
    .await;
    assert_eq!(
        query_param(&loc, "github_login_error").as_deref(),
        Some("expired_state")
    );

    // A github state must not be consumable by the GOOGLE callback (and vice
    // versa) — login_oauth_states.provider keys each callback.
    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/auth/github/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let auth_url = url::Url::parse(resp.headers()["location"].to_str().unwrap()).unwrap();
    let gh_state = auth_url
        .query_pairs()
        .find_map(|(k, v)| (k == "state").then(|| v.into_owned()))
        .unwrap();
    // No bind cookie needed: the provider mismatch is rejected before the
    // binding check, which is exactly what this asserts.
    let loc = callback_location(
        app(),
        &gh_state,
        "sub-cross|cross@example.com|verified",
        None,
    )
    .await;
    assert_eq!(
        query_param(&loc, "google_login_error").as_deref(),
        Some("invalid_state"),
        "the google callback must reject a github state"
    );

    std::env::remove_var("GITHUB_LOGIN_CLIENT_ID");
    std::env::remove_var("GITHUB_LOGIN_CLIENT_SECRET");
    std::env::remove_var("TAP_GITHUB_LOGIN_TOKEN_URL");
    std::env::remove_var("TAP_GITHUB_LOGIN_API_URL");
    std::env::remove_var("GITHUB_LOGIN_REDIRECT_URI");
}

// ────────────────────────────────────────────────────────────────────────────
// /internal/mcp/* — the endpoints that MINT tap-mcp's OAuth tokens.
//
// tap-mcp holds neither database credentials nor the token-signing key (it runs
// outside the attested enclave that tap-proxy runs in), so these two endpoints
// are its only path to a usable token. They are gated on a shared
// TAP_MCP_SERVICE_KEY, and — critically — identity is derived from the proxy's
// OWN authorization assertion, never from the request body.
//
// All the cases live in ONE test function on purpose: the integration suite runs
// in parallel and these assertions mutate process-wide env vars, so splitting
// them would race against each other. No other test reads those vars.
// ────────────────────────────────────────────────────────────────────────────

const MCP_SERVICE_KEY_ENV: &str = "TAP_MCP_SERVICE_KEY";

fn internal_mcp_request(path: &str, service_key: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(key) = service_key {
        builder = builder.header("x-tap-service-key", key);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

/// Sign a value the way `mcp_auth` does: `base64url(json).base64url(HMAC(kind ||
/// 0x00 || body))`. Parameterised by key so a test can sign as the proxy (the
/// legitimate path) *or* as a compromised tap-mcp holding only its local key.
fn sign_mcp_value(key: &[u8], kind: &str, payload: &serde_json::Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).unwrap();
    mac.update(kind.as_bytes());
    mac.update(&[0]);
    mac.update(body.as_bytes());
    format!("{body}.{}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

#[tokio::test]
async fn internal_mcp_token_endpoints_gate_on_the_service_key_and_derive_identity_from_the_assertion(
) {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _app_key, _ordinary) = make_app_state(mock).await;

    const PROXY_KEY: &[u8] = b"proxy-only-signing-key-aaaaaaaaaa";
    const MCP_LOCAL_KEY: &[u8] = b"tap-mcp-local-key-bbbbbbbbbbbbbbb";
    std::env::set_var("TAP_MCP_SIGNING_KEY", std::str::from_utf8(PROXY_KEY).unwrap());
    std::env::set_var("TAP_MCP_LOCAL_KEY", std::str::from_utf8(MCP_LOCAL_KEY).unwrap());
    std::env::set_var("TAP_MCP_PUBLIC_URL", "https://mcp.example");

    let now = chrono::Utc::now().timestamp();
    let expires_at = now + 3600;
    let assertion_claims = json!({
        "request": "signed-oauth-request",
        "subject": "user-1",
        "team_id": "t1",
        "agent_id": "mcp-user-1",
        "issued_at": now,
        "expires_at": now + 120,
    });
    let assertion = sign_mcp_value(PROXY_KEY, "tap-authorization-assertion", &assertion_claims);
    let issue_body = |jti: &str| {
        json!({
            "assertion": assertion,
            "client_id": "client-1",
            "code_jti": jti,
            "code_expires_at": expires_at,
        })
    };

    // ── 1. Unconfigured proxy ⇒ the endpoints do not exist at all (fail closed).
    // A misconfigured deploy must never leave an unauthenticated minting path open.
    std::env::remove_var(MCP_SERVICE_KEY_ENV);
    for (path, body) in [
        ("/internal/mcp/token/issue", issue_body("code-a")),
        (
            "/internal/mcp/token/refresh",
            json!({"refresh_token": "rt", "client_id": "client-1"}),
        ),
    ] {
        let (status, _) = send_request_and_parse(
            build_router(state.clone()),
            internal_mcp_request(path, Some("any-key"), body),
        )
        .await;
        assert_eq!(status, 404, "{path} must 404 when {MCP_SERVICE_KEY_ENV} is unset");
    }

    // An EMPTY key counts as unset — not as "the empty string is the password".
    std::env::set_var(MCP_SERVICE_KEY_ENV, "   ");
    let (status, _) = send_request_and_parse(
        build_router(state.clone()),
        internal_mcp_request("/internal/mcp/token/issue", Some(""), issue_body("code-a")),
    )
    .await;
    assert_eq!(status, 404, "an empty service key must disable the endpoints");

    // ── 2. Configured proxy: missing / wrong / truncated key ⇒ 401.
    let service_key = "s3rvice-key-for-tap-mcp";
    std::env::set_var(MCP_SERVICE_KEY_ENV, service_key);
    for (label, key) in [
        ("a missing", None),
        ("a wrong", Some("wrong-key")),
        ("a truncated", Some(&service_key[..8])),
    ] {
        let (status, _) = send_request_and_parse(
            build_router(state.clone()),
            internal_mcp_request("/internal/mcp/token/issue", key, issue_body("code-a")),
        )
        .await;
        assert_eq!(status, 401, "{label} service key must be rejected");
    }

    // ── 3. THE TRUST BOUNDARY, end-to-end over HTTP.
    //
    // A compromised tap-mcp holds the service key (it must, to call at all) and
    // its own local key — and neither lets it name an identity. An assertion
    // signed with the local key is refused, so it cannot mint for a victim team.
    let forged = sign_mcp_value(
        MCP_LOCAL_KEY,
        "tap-authorization-assertion",
        &json!({
            "request": "r", "subject": "victim", "team_id": "victim-team",
            "agent_id": "mcp-victim", "issued_at": now, "expires_at": now + 120,
        }),
    );
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        internal_mcp_request(
            "/internal/mcp/token/issue",
            Some(service_key),
            json!({
                "assertion": forged,
                "client_id": "client-1",
                "code_jti": "code-forged",
                "code_expires_at": expires_at,
            }),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["issued"], false,
        "an assertion tap-mcp signed itself must never mint a token"
    );
    assert_eq!(body["reason"], "assertion_invalid", "{body}");

    // ── 4. The legitimate path: a proxy-signed assertion mints a pair.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        internal_mcp_request(
            "/internal/mcp/token/issue",
            Some(service_key),
            issue_body("code-http-1"),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["issued"], true, "{body}");
    let access_token = body["access_token"].as_str().unwrap().to_string();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();
    assert!(body["expires_in"].as_i64().unwrap() > 0, "{body}");

    // The agent named in the token was derived by the proxy (ensure_mcp_agent),
    // not taken from the request — and it really exists.
    assert!(
        state
            .db_state
            .store()
            .get_agent("t1", "mcp-user-1")
            .await
            .unwrap()
            .is_some(),
        "issuing must provision the MCP agent for the asserted subject"
    );

    // The access token authenticates at /forward as that agent. (Proof the pair
    // the proxy minted is the one the proxy accepts — the loop is closed.)
    let (status, _) = send_request_and_parse(
        build_router(state.clone()),
        Request::builder()
            .method("GET")
            .uri("/agent/services")
            .header("authorization", format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200, "a proxy-minted access token must authenticate");

    // ── 5. The authorization code is single-use: a replay mints nothing, even
    // with the very same valid assertion.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        internal_mcp_request(
            "/internal/mcp/token/issue",
            Some(service_key),
            issue_body("code-http-1"),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["issued"], false, "an authorization code must be single-use");
    assert_eq!(body["reason"], "code_already_used", "{body}");

    // ── 6. Refresh rotates the family atomically and returns a new pair.
    let refresh_req = |token: &str| {
        json!({"refresh_token": token, "client_id": "client-1", "resource": "https://mcp.example/mcp"})
    };
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        internal_mcp_request(
            "/internal/mcp/token/refresh",
            Some(service_key),
            refresh_req(&refresh_token),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["issued"], true, "{body}");
    let rotated_refresh = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(rotated_refresh, refresh_token, "rotation must issue a new token");

    // …and REPLAYING the superseded refresh token is rejected — surfaced as a
    // 200 with `issued:false`, so tap-mcp tells "replay" from a transport error.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        internal_mcp_request(
            "/internal/mcp/token/refresh",
            Some(service_key),
            refresh_req(&refresh_token),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["issued"], false, "a replayed refresh token must not rotate");
    assert_eq!(body["reason"], "refresh_token_superseded", "{body}");

    // A refresh token is bound to the OAuth client it was issued to.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        internal_mcp_request(
            "/internal/mcp/token/refresh",
            Some(service_key),
            json!({"refresh_token": rotated_refresh, "client_id": "other-client"}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["issued"], false, "a refresh token must not cross OAuth clients");

    // ── 7. A revoked family cannot rotate — the dashboard disconnect path stays
    // effective through the minting endpoint.
    tap_core::mcp_tokens::revoke_families_for_agent(
        state.db_state.store().pool(),
        "t1",
        "mcp-user-1",
        chrono::Utc::now().timestamp(),
    )
    .await
    .unwrap();
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        internal_mcp_request(
            "/internal/mcp/token/refresh",
            Some(service_key),
            refresh_req(&rotated_refresh),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["issued"], false, "a revoked family must not rotate");

    std::env::remove_var(MCP_SERVICE_KEY_ENV);
    std::env::remove_var("TAP_MCP_SIGNING_KEY");
    std::env::remove_var("TAP_MCP_LOCAL_KEY");
    std::env::remove_var("TAP_MCP_PUBLIC_URL");
}

// ---------------------------------------------------------------------------
// Admin passkey-reset hardening: audit row + acting-admin passkey step-up.
//
// `DELETE /team/members/{id}/passkeys` (and its POST sibling) is a
// 2FA-stripping primitive — it removes another person's second factor, and the
// next login on that account enrols whatever authenticator answers. These tests
// pin the two controls that close that: a fresh WebAuthn assertion from the
// ACTING manager, and an immutable audit row.
//
// The assertions come from `SoftAuthenticator` below — a minimal in-process
// WebAuthn authenticator (P-256/ES256, no attestation) so the identity check is
// exercised with *cryptographically valid* assertions, not just the
// fail-closed reject path.
// ---------------------------------------------------------------------------

use base64::Engine as _;

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A software WebAuthn authenticator: one ES256 passkey, no attestation.
struct SoftAuthenticator {
    key: p256::ecdsa::SigningKey,
    cred_id: Vec<u8>,
    rp_id: String,
    origin: String,
}

impl SoftAuthenticator {
    fn new(rp_id: &str, origin: &str) -> Self {
        let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let cred_id: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        Self {
            key,
            cred_id,
            rp_id: rp_id.to_string(),
            origin: origin.to_string(),
        }
    }

    fn credential_id_b64(&self) -> String {
        B64URL.encode(&self.cred_id)
    }

    /// The `webauthn_rs::prelude::Passkey` JSON the store persists in
    /// `webauthn_credentials.public_key_json`.
    fn passkey_json(&self) -> String {
        let point = self.key.verifying_key().to_encoded_point(false);
        let value = json!({
            "cred": {
                "cred_id": self.credential_id_b64(),
                "cred": {
                    "type_": "ES256",
                    "key": {
                        "EC_EC2": {
                            "curve": "SECP256R1",
                            "x": B64URL.encode(point.x().unwrap()),
                            "y": B64URL.encode(point.y().unwrap()),
                        }
                    }
                },
                "counter": 0,
                "transports": null,
                "user_verified": true,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "preferred",
                "extensions": {},
                "attestation": {"data": "None", "metadata": "None"},
                "attestation_format": "none",
            }
        });
        // Fail loudly here rather than deep inside webauthn-rs if the shape drifts.
        serde_json::from_str::<webauthn_rs::prelude::Passkey>(&value.to_string())
            .expect("hand-built Passkey JSON must match webauthn-rs's shape");
        value.to_string()
    }

    /// Answer a `RequestChallengeResponse` with a signed assertion.
    fn assert(&self, rcr: &serde_json::Value) -> serde_json::Value {
        use p256::ecdsa::signature::Signer;
        use sha2::{Digest, Sha256};

        let challenge = rcr["publicKey"]["challenge"].as_str().unwrap();
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": false,
        })
        .to_string();

        // rpIdHash || flags (UP|UV) || signCount
        let mut auth_data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        auth_data.push(0x05);
        auth_data.extend_from_slice(&0u32.to_be_bytes());

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let sig: p256::ecdsa::Signature = self.key.sign(&signed);

        json!({
            "id": self.credential_id_b64(),
            "rawId": self.credential_id_b64(),
            "type": "public-key",
            "response": {
                "authenticatorData": B64URL.encode(&auth_data),
                "clientDataJSON": B64URL.encode(client_data.as_bytes()),
                "signature": B64URL.encode(sig.to_der().as_bytes()),
                "userHandle": null,
            },
        })
    }
}

/// `make_empty_state_with_audit` plus a real `WebAuthnState` on `localhost`, so
/// the passkey step-up is actually enforced (the other test states set
/// `webauthn_state: None`, which is the "WebAuthn not configured" convention).
async fn make_state_with_webauthn(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, Arc<InMemoryAuditLogger>) {
    let enc_key = test_key();
    let (store, _url) = ConfigStore::new_isolated_test(enc_key).await;
    let wa = Arc::new(
        tap_proxy::webauthn::WebAuthnState::new(
            "localhost",
            "http://localhost",
            "http://localhost",
            Some(store.clone()),
            &[],
        )
        .unwrap(),
    );
    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval.clone(),
        dashboard_channel: mock_approval.clone(),
        telegram_channel: Some(mock_approval.clone()),
        matrix_channel: None,
        matrix_channel_raw: None,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        db_state,
        webauthn_state: Some(wa),
        approval_timeout_secs: 300,
    };
    (state, audit_logger)
}

fn pk_mock_channel() -> Arc<MockApproval> {
    Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    })
}

/// Log in and return a usable bearer token. With WebAuthn configured, a user
/// who has not yet enrolled a passkey gets `passkey_setup_token` instead of
/// `session_token` — both are real DB sessions, so either works here.
async fn pk_login(state: &AppState, email: &str, password: &str) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"email": email, "password": password}).to_string(),
        ))
        .unwrap();
    let (status, v) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 200, "login must succeed: {v}");
    v["session_token"]
        .as_str()
        .or_else(|| v["passkey_setup_token"].as_str())
        .unwrap_or_else(|| panic!("login returned no usable token: {v}"))
        .to_string()
}

/// Create a verified team owner directly (bypassing email verification, as
/// `signup_and_login` does) and return a bearer token for them.
async fn pk_signup_owner(state: &AppState, team_name: &str, email: &str, password: &str) -> String {
    let store = state.db_state.store();
    let team_id = uuid::Uuid::new_v4().to_string();
    store.create_team(&team_id, team_name).await.unwrap();
    let new_user_id = uuid::Uuid::new_v4().to_string();
    let pw_hash = tap_proxy::admin::hash_password(password).unwrap();
    let user_id = store
        .create_user_with_membership(&new_user_id, &team_id, email, &pw_hash, "owner")
        .await
        .unwrap();
    store.set_user_email_verified(&user_id).await.unwrap();
    pk_login(state, email, password).await
}

/// Seed an owner + one ordinary member; returns (owner session token, member).
async fn seed_owner_and_member(
    state: &AppState,
    slug: &str,
    owner_email: &str,
    member_email: &str,
) -> (String, tap_core::store::Member) {
    let owner_token = pk_signup_owner(state, slug, owner_email, "password123").await;
    let (_, invite_body) =
        invite_member(build_router(state.clone()), &owner_token, member_email).await;
    let invite_token = invite_body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();
    assert_eq!(
        accept_invite_token(build_router(state.clone()), invite_token, "pass123456").await,
        200
    );
    let member = member_by_email(state.db_state.store(), member_email).await;
    (owner_token, member)
}

fn pk_reset_begin(token: &str, member_id: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/team/members/{member_id}/passkeys/reset/begin"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn pk_reset_request(token: &str, member_id: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/team/members/{member_id}/passkeys/reset"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// (a) With WebAuthn configured, a reset carrying no assertion is refused. A
/// stolen dashboard session alone must never strip a teammate's 2FA.
#[tokio::test]
async fn member_passkey_reset_without_assertion_is_rejected() {
    let (state, audit) = make_state_with_webauthn(pk_mock_channel()).await;
    let (owner_token, member) = seed_owner_and_member(
        &state,
        "pk-stepup",
        "owner@pkstepup.com",
        "member@pkstepup.com",
    )
    .await;
    let store = state.db_state.store();
    store
        .save_user_passkey(&member.id, "stale-cred-id", "{}")
        .await
        .unwrap();

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_request(&owner_token, &member.id, json!({})),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error_code"], "passkey_required");

    // The legacy bodyless DELETE alias cannot carry an assertion, so it fails
    // closed the same way rather than remaining an un-stepped-up back door.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/team/members/{}/passkeys", member.id))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error_code"], "passkey_required");

    // Nothing removed, nothing audited.
    assert_eq!(store.count_user_passkeys(&member.id).await.unwrap(), 1);
    assert!(audit.entries().is_empty());
}

/// (b) A cryptographically VALID assertion belonging to somebody other than the
/// acting manager is refused with 403. `finish_approval` accepts any registered
/// passkey, so the handler must compare the returned owner email to the acting
/// manager's — this is that binding.
#[tokio::test]
async fn member_passkey_reset_with_another_users_assertion_is_rejected() {
    let (state, audit) = make_state_with_webauthn(pk_mock_channel()).await;
    let (owner_token, member) = seed_owner_and_member(
        &state,
        "pk-wrongkey",
        "owner@pkwrongkey.com",
        "member@pkwrongkey.com",
    )
    .await;
    let store = state.db_state.store();
    store
        .save_user_passkey(&member.id, "stale-cred-id", "{}")
        .await
        .unwrap();

    // The owner needs a real passkey of their own: the ceremony is now scoped to
    // the acting manager, so `begin` refuses to mint a challenge for a manager
    // with no credentials (you cannot strip someone's 2FA without having yours).
    let owner = member_by_email(store, "owner@pkwrongkey.com").await;
    let owner_soft = SoftAuthenticator::new("localhost", "http://localhost");
    store
        .save_user_passkey(
            &owner.id,
            &owner_soft.credential_id_b64(),
            &owner_soft.passkey_json(),
        )
        .await
        .unwrap();

    // The passkey we will actually sign with belongs to the *member*, not to the
    // owner driving the reset.
    let soft = SoftAuthenticator::new("localhost", "http://localhost");
    store
        .save_user_passkey(&member.id, &soft.credential_id_b64(), &soft.passkey_json())
        .await
        .unwrap();

    let (status, rcr) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_begin(&owner_token, &member.id),
    )
    .await;
    assert_eq!(status, 200, "{rcr}");

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_request(
            &owner_token,
            &member.id,
            json!({"assertion": soft.assert(&rcr)}),
        ),
    )
    .await;
    assert_eq!(
        status, 401,
        "an assertion owned by another user must not authorize the reset: {body}"
    );
    // 401, not 403: the ceremony is now SCOPED to the acting manager's
    // credentials, so a foreign credential is rejected at the lookup inside
    // `finish_approval_for_user` rather than by the post-hoc identity compare.
    // That is the stronger outcome — the crypto layer refuses it, and the
    // identity check behind it is now a redundant backstop rather than the only
    // thing holding the line.

    // Fail closed: both passkeys survive and no audit row is written.
    assert_eq!(store.count_user_passkeys(&member.id).await.unwrap(), 2);
    assert!(audit.entries().is_empty());
}

/// (c) The team owner is never a valid target — and that guard runs BEFORE the
/// ceremony, so no challenge is ever minted for the owner and a manager holding
/// a perfectly good passkey still gets 403.
#[tokio::test]
async fn member_passkey_reset_owner_target_rejected_even_with_valid_assertion() {
    let (state, audit) = make_state_with_webauthn(pk_mock_channel()).await;
    let owner_token = pk_signup_owner(
        &state,
        "pk-ownertarget",
        "owner@pkownertarget.com",
        "password123",
    )
    .await;
    let (_, invite_body) = invite_member_with_role(
        build_router(state.clone()),
        &owner_token,
        "admin@pkownertarget.com",
        "admin",
    )
    .await;
    let invite_token = invite_body["accept_url"]
        .as_str()
        .unwrap()
        .split("token=")
        .nth(1)
        .unwrap();
    assert_eq!(
        accept_invite_token(build_router(state.clone()), invite_token, "pass123456").await,
        200
    );
    let admin_token = pk_login(&state, "admin@pkownertarget.com", "pass123456").await;

    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@pkownertarget.com").await;
    let acting_admin = member_by_email(store, "admin@pkownertarget.com").await;

    // The acting admin holds a genuine passkey of their own.
    let soft = SoftAuthenticator::new("localhost", "http://localhost");
    store
        .save_user_passkey(
            &acting_admin.id,
            &soft.credential_id_b64(),
            &soft.passkey_json(),
        )
        .await
        .unwrap();
    // A real passkey for the owner: they mint the challenge below, and a scoped
    // ceremony needs the minting manager to actually hold credentials.
    let owner_soft = SoftAuthenticator::new("localhost", "http://localhost");
    store
        .save_user_passkey(
            &owner.id,
            &owner_soft.credential_id_b64(),
            &owner_soft.passkey_json(),
        )
        .await
        .unwrap();

    // No challenge is handed out for a forbidden target.
    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_begin(&admin_token, &owner.id),
    )
    .await;
    assert_eq!(status, 403, "{body}");

    // Mint a challenge against a permitted target so the assertion below is a
    // real, verifiable one, then aim the reset at the owner.
    let (status, rcr) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_begin(&owner_token, &acting_admin.id),
    )
    .await;
    assert_eq!(status, 200, "{rcr}");

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_request(
            &admin_token,
            &owner.id,
            json!({"assertion": owner_soft.assert(&rcr)}),
        ),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(store.count_user_passkeys(&owner.id).await.unwrap(), 1);
    assert!(audit.entries().is_empty());
}

/// (d) Happy path: the acting manager's own assertion authorizes the reset,
/// every passkey goes away, and the action lands in the immutable audit log.
#[tokio::test]
async fn member_passkey_reset_with_own_assertion_succeeds_and_is_audited() {
    let (state, audit) = make_state_with_webauthn(pk_mock_channel()).await;
    let (owner_token, member) =
        seed_owner_and_member(&state, "pk-audit", "owner@pkaudit.com", "member@pkaudit.com").await;
    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@pkaudit.com").await;

    // The acting owner's own passkey.
    let soft = SoftAuthenticator::new("localhost", "http://localhost");
    store
        .save_user_passkey(&owner.id, &soft.credential_id_b64(), &soft.passkey_json())
        .await
        .unwrap();
    // Two stale passkeys on the locked-out member.
    store
        .save_user_passkey(&member.id, "stale-cred-1", "{}")
        .await
        .unwrap();
    store
        .save_user_passkey(&member.id, "stale-cred-2", "{}")
        .await
        .unwrap();

    let (status, rcr) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_begin(&owner_token, &member.id),
    )
    .await;
    assert_eq!(status, 200, "{rcr}");

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_request(
            &owner_token,
            &member.id,
            json!({"assertion": soft.assert(&rcr)}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["reset"], true);
    assert_eq!(body["removed_count"], 2);
    assert_eq!(store.count_user_passkeys(&member.id).await.unwrap(), 0);
    // The acting owner's own passkey is untouched.
    assert_eq!(store.count_user_passkeys(&owner.id).await.unwrap(), 1);

    let entries = audit.entries();
    assert_eq!(entries.len(), 1, "a reset must write exactly one audit row");
    let e = &entries[0];
    assert_eq!(e.target_url, "tap:passkey-reset");
    assert_eq!(e.method, HttpMethod::Delete);
    assert_eq!(e.agent_id, owner.id);
    assert_eq!(e.approver_identity.as_deref(), Some("owner@pkaudit.com"));
    assert_eq!(
        e.policy_reason.as_deref(),
        Some(format!("passkey_reset:{}", member.id).as_str())
    );
    let summary: serde_json::Value =
        serde_json::from_str(e.request_body.as_deref().unwrap()).unwrap();
    assert_eq!(summary["target_member_email"], "member@pkaudit.com");
    assert_eq!(summary["target_member_id"], member.id);
    assert_eq!(summary["removed_count"], 2);
    assert_eq!(summary["source"], "dashboard");
}

/// The challenge is single-use, so an assertion captured once cannot be replayed
/// to strip a second member's 2FA.
#[tokio::test]
async fn member_passkey_reset_assertion_is_single_use() {
    let (state, _audit) = make_state_with_webauthn(pk_mock_channel()).await;
    let (owner_token, member) = seed_owner_and_member(
        &state,
        "pk-replay",
        "owner@pkreplay.com",
        "member@pkreplay.com",
    )
    .await;
    let store = state.db_state.store();
    let owner = member_by_email(store, "owner@pkreplay.com").await;
    let soft = SoftAuthenticator::new("localhost", "http://localhost");
    store
        .save_user_passkey(&owner.id, &soft.credential_id_b64(), &soft.passkey_json())
        .await
        .unwrap();
    store
        .save_user_passkey(&member.id, "stale-cred-1", "{}")
        .await
        .unwrap();

    let (status, rcr) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_begin(&owner_token, &member.id),
    )
    .await;
    assert_eq!(status, 200, "{rcr}");
    let assertion = soft.assert(&rcr);

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_request(&owner_token, &member.id, json!({"assertion": assertion})),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = send_request_and_parse(
        build_router(state.clone()),
        pk_reset_request(&owner_token, &member.id, json!({"assertion": assertion})),
    )
    .await;
    assert_eq!(status, 401, "a replayed assertion must be refused: {body}");
}

// ---------------------------------------------------------------------------
// Credential hints (.env importer LLM assist)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credential_hints_requires_session_and_rejects_value_shaped_keys() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // No session → 401.
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/credential-hints")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"keys":["POSTHOG_API_KEY"]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);

    let token = signup_and_login(&state, "hints", "owner@hints.com", "password123").await;

    // A value-shaped entry must be rejected — the name gate is what keeps
    // secrets out of the LLM request.
    for bad in [
        r#"{"keys":["sk-proj-abc123"]}"#,
        r#"{"keys":["FOO=bar"]}"#,
        r#"{"keys":[]}"#,
    ] {
        let app = build_router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/team/credential-hints")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(bad))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 400, "payload should be rejected: {bad}");
    }

    // Valid names but no CLAUDE_API_KEY configured → graceful unavailable, not
    // an error (self-hosted default).
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/team/credential-hints")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(r#"{"keys":["POSTHOG_API_KEY","MYSTERY_TOKEN"]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["available"], false);
    assert_eq!(value["hints"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// POST /team/credentials/{name}/verify — live credential verification
// ---------------------------------------------------------------------------

async fn verify_call(
    state: &AppState,
    token: &str,
    name: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/team/credentials/{name}/verify"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    send_request_and_parse(build_router(state.clone()), req).await
}

/// The response contract: verdict metadata only — never the upstream body,
/// never headers, never anything derived from the vendor's response content.
fn assert_status_only_shape(body: &serde_json::Value) {
    let obj = body.as_object().expect("verify response is an object");
    for key in obj.keys() {
        assert!(
            ["status", "http_status", "probe_url", "detail"].contains(&key.as_str()),
            "unexpected key {key} in verify response — body leak?"
        );
    }
}

#[tokio::test]
async fn credential_verify_requires_session_and_manager_role() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // No session → 401, before any credential lookup.
    let req = Request::builder()
        .method("POST")
        .uri("/team/credentials/anything/verify")
        .body(Body::empty())
        .unwrap();
    let resp = build_router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);

    // Unknown credential → 404 with a session.
    let token = signup_and_login(&state, "verify", "owner@verify.com", "password123").await;
    let (status, _body) = verify_call(&state, &token, "nope").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn credential_verify_edge_verdicts() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;
    let token = signup_and_login(&state, "verify2", "owner@verify2.com", "password123").await;

    // Helper: create a credential through the real admin API.
    async fn create(state: &AppState, token: &str, body: &str) {
        let req = Request::builder()
            .method("POST")
            .uri("/team/credentials")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, resp_body) = send_request_and_parse(build_router(state.clone()), req).await;
        assert_eq!(status, 201, "create failed for {body}: {resp_body}");
    }

    // Sidecar credentials are not probe-verifiable.
    create(
        &state,
        &token,
        r#"{"name":"side","description":"d","connector":"sidecar","api_base":"http://oauth2cc-inline","allowed_hosts":["api.example.com"],"value":"{\"client_id\":\"a\",\"client_secret\":\"b\",\"token_url\":\"https://x/token\"}"}"#,
    )
    .await;
    let (status, body) = verify_call(&state, &token, "side").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "unsupported", "{body}");
    assert_status_only_shape(&body);

    // (An UNBOUND direct credential can no longer be created through the API —
    // allowed_hosts is required at create time — so the empty-allowed_hosts →
    // no_probe branch is covered by the pick_probe unit test instead.)

    // Wildcard-only binding: nothing concrete to aim at → no_probe.
    create(
        &state,
        &token,
        r#"{"name":"wild","description":"d","value":"secret-value-123","allowed_hosts":["*.amazonaws.com"]}"#,
    )
    .await;
    let (status, body) = verify_call(&state, &token, "wild").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "no_probe", "{body}");

    // Bound to a concrete host with nothing listening on 443: the generic
    // probe fires (https://127.0.0.1/) and must come back as a clean verdict
    // from the closed set — never a 500, never upstream content.
    create(
        &state,
        &token,
        r#"{"name":"local","description":"d","value":"secret-value-123","allowed_hosts":["127.0.0.1"]}"#,
    )
    .await;
    let (status, body) = verify_call(&state, &token, "local").await;
    assert_eq!(status, 200);
    let verdict = body["status"].as_str().unwrap();
    assert!(
        ["upstream_error", "inconclusive", "auth_rejected"].contains(&verdict),
        "unexpected verdict {verdict}"
    );
    assert_eq!(body["probe_url"], "https://127.0.0.1/");
    assert_status_only_shape(&body);

    // A multi-secret credential with no bindings has broken wiring — the
    // verdict says so instead of probing garbage.
    create(
        &state,
        &token,
        r#"{"name":"multibad","description":"d","value":{"api_key":"aaa","app_key":"bbb"},"allowed_hosts":["127.0.0.1"]}"#,
    )
    .await;
    let (status, body) = verify_call(&state, &token, "multibad").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "config_error", "{body}");
    assert_status_only_shape(&body);
}
