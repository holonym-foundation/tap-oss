//! End-to-end approval flow test.
//! Boots the REAL proxy + a mock approval channel + mock upstream.

// Test scaffolding: some recorded-request fields are captured for completeness but
// not asserted on, and a few asserts hold a std Mutex guard across an await. Both are
// fine in single-threaded test context.
#![allow(dead_code)]
#![allow(clippy::await_holding_lock)]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request};
use serde_json::json;
use tap_core::approval::{ApprovalChannel, ApprovalContext};
use tap_core::error::AgentSecError;
use tap_core::store::{ConfigStore, PolicyRow};
use tap_core::types::*;
use tap_proxy::audit::InMemoryAuditLogger;
use tap_proxy::auth::hash_api_key;
use tap_proxy::proxy::{build_router, AppState};
use tower::util::ServiceExt;

fn test_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    key
}

/// Mock approval channel that records calls and returns configurable decisions.
struct MockApprovalChannel {
    decision: ApprovalStatus,
    requests: std::sync::Mutex<Vec<MockApprovalRequest>>,
}

#[derive(Debug, Clone)]
struct MockApprovalRequest {
    agent_id: String,
    method: HttpMethod,
    target_url: String,
}

#[async_trait::async_trait]
impl ApprovalChannel for MockApprovalChannel {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        _desc: &str,
        _context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        self.requests.lock().unwrap().push(MockApprovalRequest {
            agent_id: request.agent_id.clone(),
            method: request.method.clone(),
            target_url: request.target_url.clone(),
        });
        Ok(request.id.to_string())
    }

    async fn wait_for_decision(
        &self,
        _id: &str,
        _timeout: u64,
    ) -> Result<ApprovalStatus, AgentSecError> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(self.decision.clone())
    }

    fn format_message(&self, _request: &ProxyRequest, _desc: &str) -> String {
        "e2e mock".to_string()
    }

    fn channel_name(&self) -> &str {
        "mock"
    }

    async fn notify_unauthorized(&self, _: &str, _: &str) -> Result<(), AgentSecError> {
        Ok(())
    }
}

/// Mock upstream that records received requests and returns configurable responses.
#[derive(Clone, Default)]
struct RecordedUpstream {
    requests: Arc<std::sync::Mutex<Vec<UpstreamRequest>>>,
}

#[derive(Debug, Clone)]
struct UpstreamRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn start_mock_upstream(recorded: RecordedUpstream) -> (String, tokio::task::JoinHandle<()>) {
    use axum::routing::{get, post};

    let rec = recorded.clone();
    let app = axum::Router::new()
        .route(
            "/api/tweet",
            post({
                let rec = rec.clone();
                move |headers: HeaderMap, body: axum::body::Bytes| {
                    let rec = rec.clone();
                    async move {
                        let hdrs: Vec<(String, String)> = headers
                            .iter()
                            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        rec.requests.lock().unwrap().push(UpstreamRequest {
                            method: "POST".to_string(),
                            path: "/api/tweet".to_string(),
                            headers: hdrs,
                            body: body.to_vec(),
                        });
                        axum::Json(json!({"posted": true}))
                    }
                }
            }),
        )
        .route(
            "/api/tweet",
            get({
                let rec = rec.clone();
                move |headers: HeaderMap| {
                    let rec = rec.clone();
                    async move {
                        let hdrs: Vec<(String, String)> = headers
                            .iter()
                            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        rec.requests.lock().unwrap().push(UpstreamRequest {
                            method: "GET".to_string(),
                            path: "/api/tweet".to_string(),
                            headers: hdrs,
                            body: vec![],
                        });
                        axum::Json(json!({"tweets": []}))
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
    (url, handle)
}

async fn make_e2e_state(
    approval_channel: Arc<dyn ApprovalChannel>,
    _upstream_url: &str,
) -> (AppState, Arc<InMemoryAuditLogger>, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let api_key = "e2e-key-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890";
    let key_hash = hash_api_key(api_key);

    let tmp = tempfile::NamedTempFile::new().unwrap(); // kept for return type compat
                                                       // Each test gets its own freshly-created database (isolated, parallel-safe).
    let (store, _url) = ConfigStore::new_isolated_test(enc_key).await;
    store.create_team("t1", "test-team").await.unwrap();
    store
        .create_credential(
            "t1",
            "e2e-cred",
            "E2E test credential",
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
        .set_credential_value("t1", "e2e-cred", b"real-secret-xyz")
        .await
        .unwrap();
    store
        .create_agent("t1", "e2e-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "e2e-agent", "e2e-cred")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "e2e-cred".to_string(),
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

    let db_state = Arc::new(tap_proxy::db_state::DbState::new(
        store,
        Duration::from_secs(30),
    ));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: approval_channel.clone(),
        dashboard_channel: approval_channel.clone(),
        telegram_channel: Some(approval_channel),
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

const E2E_API_KEY: &str = "e2e-key-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890";

#[tokio::test]
async fn e2e_write_request_approval_flow() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Approved,
        requests: std::sync::Mutex::new(vec![]),
    });

    let (state, audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;

    // 1. POST /forward → 202 Accepted (async approval is the default)
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "POST")
        .header("authorization", "Bearer <CREDENTIAL:e2e-cred>")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "Hello from E2E test"}"#))
        .unwrap();

    let (status, body) = send_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 202, "expected 202 Accepted, got {status}: {body}");
    let txn_id = body["txn_id"].as_str().expect("txn_id missing").to_string();

    // 2. approval channel was called
    let approval_requests = mock_approval.requests.lock().unwrap();
    assert_eq!(approval_requests.len(), 1);
    assert_eq!(approval_requests[0].agent_id, "e2e-agent");
    assert_eq!(approval_requests[0].method, HttpMethod::Post);
    assert!(approval_requests[0].target_url.contains("/api/tweet"));
    drop(approval_requests);

    // 3. Wait for background approval task (mock sleeps 100ms)
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 4. Poll → forwarded
    let poll_req = Request::builder()
        .method("GET")
        .uri(format!("/agent/approvals/{txn_id}"))
        .header("x-tap-key", E2E_API_KEY)
        .body(Body::empty())
        .unwrap();
    let (poll_status, poll_body) = send_and_parse(build_router(state.clone()), poll_req).await;

    assert_eq!(poll_status, 200);
    assert_eq!(poll_body["status"], "forwarded", "poll body: {poll_body}");
    assert_eq!(poll_body["response"]["status"], 200);

    // 5. Upstream received request with substituted credential
    let upstream_reqs = recorded.requests.lock().unwrap();
    assert_eq!(upstream_reqs.len(), 1);
    let auth_header = upstream_reqs[0]
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert_eq!(auth_header, "Bearer real-secret-xyz");
    let body_str = String::from_utf8(upstream_reqs[0].body.clone()).unwrap();
    assert!(body_str.contains("Hello from E2E test"));

    // 6. The approval-gated write now shows up in the audit log (previously a
    // gap: only auto-approved requests were audited). The stored request body
    // is the pre-substitution placeholder, never the real injected secret.
    let entries = audit.entries();
    assert_eq!(entries.len(), 1, "expected exactly one audit entry");
    let entry = &entries[0];
    assert_eq!(entry.approval_status, Some(ApprovalStatus::Approved));
    assert_eq!(entry.upstream_status, Some(200));
    let auth_in_audit = entry
        .request_headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str());
    assert_eq!(
        auth_in_audit,
        Some("Bearer <CREDENTIAL:e2e-cred>"),
        "audit log must store the pre-substitution placeholder, never the real secret"
    );
    let audit_body = entry.request_body.as_deref().unwrap_or_default();
    assert!(!audit_body.contains("real-secret-xyz"));
    assert!(audit_body.contains("Hello from E2E test"));
    assert!(entry.policy_reason.is_some());
}

#[tokio::test]
async fn e2e_write_request_denied() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Denied,
        requests: std::sync::Mutex::new(vec![]),
    });

    let (state, audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;

    // 1. POST /forward → 202 Accepted
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "POST")
        .header("authorization", "Bearer <CREDENTIAL:e2e-cred>")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "Should be denied"}"#))
        .unwrap();

    let (status, body) = send_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 202, "expected 202 Accepted, got {status}: {body}");
    let txn_id = body["txn_id"].as_str().expect("txn_id missing").to_string();

    // 2. Wait for background approval task
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 3. Poll → denied
    let poll_req = Request::builder()
        .method("GET")
        .uri(format!("/agent/approvals/{txn_id}"))
        .header("x-tap-key", E2E_API_KEY)
        .body(Body::empty())
        .unwrap();
    let (poll_status, poll_body) = send_and_parse(build_router(state.clone()), poll_req).await;

    assert_eq!(poll_status, 200);
    assert_eq!(poll_body["status"], "denied", "poll body: {poll_body}");

    // 4. Upstream received zero requests
    let upstream_reqs = recorded.requests.lock().unwrap();
    assert_eq!(
        upstream_reqs.len(),
        0,
        "denied request should not reach upstream"
    );

    // 5. A denial is still an audit-worthy policy decision and must be visible.
    let entries = audit.entries();
    assert_eq!(entries.len(), 1, "denied requests must still be audited");
    assert_eq!(entries[0].approval_status, Some(ApprovalStatus::Denied));
    assert_eq!(entries[0].upstream_status, None);
}

#[tokio::test]
async fn e2e_read_request_skips_approval() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Approved,
        requests: std::sync::Mutex::new(vec![]),
    });

    let (state, audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;
    let app = build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:e2e-cred>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // 1. MockApprovalChannel.send_approval_request was NOT called
    let approval_requests = mock_approval.requests.lock().unwrap();
    assert_eq!(
        approval_requests.len(),
        0,
        "GET should not trigger approval"
    );
    drop(approval_requests);

    // 2. Proxy returned 200
    assert_eq!(resp.status(), 200);

    // 3. Mock upstream received the GET with real credential
    let upstream_reqs = recorded.requests.lock().unwrap();
    assert_eq!(upstream_reqs.len(), 1);
    let auth_header = upstream_reqs[0]
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert_eq!(auth_header, "Bearer real-secret-xyz");
    drop(upstream_reqs);

    // 4. Audit log entry
    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].approval_status.is_none());
}

// ---------------------------------------------------------------------------
// Async polling tests
// ---------------------------------------------------------------------------

/// Helper: send a request and parse the JSON response body.
async fn send_and_parse(
    app: axum::Router,
    req: Request<Body>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn async_approved_write_returns_202_and_poll_returns_forwarded() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Approved,
        requests: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;

    // 1. POST /forward with Prefer: respond-async → 202
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-credential", "e2e-cred")
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "POST")
        .header("prefer", "respond-async")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "async tweet"}"#))
        .unwrap();
    let (status, body) = send_and_parse(build_router(state.clone()), req).await;

    assert_eq!(status, 202, "expected 202 Accepted, got {status}: {body}");
    let txn_id = body["txn_id"].as_str().expect("txn_id missing").to_string();
    assert_eq!(body["status"], "pending");
    assert!(body["poll_url"].as_str().unwrap().contains(&txn_id));

    // 2. Background task runs (MockApprovalChannel sleeps 100ms → approve → forward)
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 3. Poll → forwarded with upstream response
    let poll_req = Request::builder()
        .method("GET")
        .uri(format!("/agent/approvals/{txn_id}"))
        .header("x-tap-key", E2E_API_KEY)
        .body(Body::empty())
        .unwrap();
    let (poll_status, poll_body) = send_and_parse(build_router(state.clone()), poll_req).await;

    assert_eq!(poll_status, 200);
    assert_eq!(
        poll_body["status"], "forwarded",
        "unexpected status: {poll_body}"
    );
    assert_eq!(poll_body["response"]["status"], 200);
    let resp_body = poll_body["response"]["body"].as_str().unwrap();
    assert!(resp_body.contains("posted"), "unexpected body: {resp_body}");

    // 4. Upstream received exactly one request with the credential injected
    let upstream_reqs = recorded.requests.lock().unwrap();
    assert_eq!(upstream_reqs.len(), 1);
    let auth = upstream_reqs[0]
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(auth, "Bearer real-secret-xyz");
}

#[tokio::test]
async fn async_denied_write_poll_returns_denied() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Denied,
        requests: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-credential", "e2e-cred")
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "POST")
        .header("prefer", "respond-async")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "will be denied"}"#))
        .unwrap();
    let (status, body) = send_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 202);
    let txn_id = body["txn_id"].as_str().unwrap().to_string();

    tokio::time::sleep(Duration::from_millis(500)).await;

    let poll_req = Request::builder()
        .method("GET")
        .uri(format!("/agent/approvals/{txn_id}"))
        .header("x-tap-key", E2E_API_KEY)
        .body(Body::empty())
        .unwrap();
    let (poll_status, poll_body) = send_and_parse(build_router(state.clone()), poll_req).await;

    assert_eq!(poll_status, 200);
    assert_eq!(poll_body["status"], "denied", "{poll_body}");
    // Upstream must not have been called
    assert_eq!(recorded.requests.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn async_poll_unknown_txn_returns_404() {
    let (upstream_url, _h) = start_mock_upstream(RecordedUpstream::default()).await;
    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Approved,
        requests: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_e2e_state(mock_approval, &upstream_url).await;

    let req = Request::builder()
        .method("GET")
        .uri("/agent/approvals/does-not-exist")
        .header("x-tap-key", E2E_API_KEY)
        .body(Body::empty())
        .unwrap();
    let (status, _) = send_and_parse(build_router(state), req).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn async_placeholder_path_approved_poll_returns_forwarded() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Approved,
        requests: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;

    // Use legacy placeholder syntax (no X-TAP-Credential header)
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "POST")
        .header("prefer", "respond-async")
        .header("authorization", "Bearer <CREDENTIAL:e2e-cred>")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "placeholder async"}"#))
        .unwrap();
    let (status, body) = send_and_parse(build_router(state.clone()), req).await;
    assert_eq!(status, 202, "{body}");
    let txn_id = body["txn_id"].as_str().unwrap().to_string();

    tokio::time::sleep(Duration::from_millis(500)).await;

    let poll_req = Request::builder()
        .method("GET")
        .uri(format!("/agent/approvals/{txn_id}"))
        .header("x-tap-key", E2E_API_KEY)
        .body(Body::empty())
        .unwrap();
    let (poll_status, poll_body) = send_and_parse(build_router(state.clone()), poll_req).await;

    assert_eq!(poll_status, 200);
    assert_eq!(poll_body["status"], "forwarded", "{poll_body}");

    // Credential was substituted before forwarding
    let upstream_reqs = recorded.requests.lock().unwrap();
    assert_eq!(upstream_reqs.len(), 1);
    let auth = upstream_reqs[0]
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(auth, "Bearer real-secret-xyz");
}
