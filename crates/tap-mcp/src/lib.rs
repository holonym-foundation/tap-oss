//! Remote Model Context Protocol server for TAP.
//!
//! This crate is an interoperability spike. It implements the complete
//! URL-only discovery path used by hosted MCP clients:
//!
//! 1. protected-resource discovery;
//! 2. OAuth authorization-server discovery;
//! 3. dynamic client registration;
//! 4. authorization-code + PKCE token issuance; and
//! 5. an authenticated Streamable HTTP MCP endpoint.
//!
//! The consent screen is intentionally demo-only. Production consent must be
//! delegated to TAP's existing browser session and passkey ceremony.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rmcp::{
    handler::server::common::Extension,
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ServerHandler,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

const FULL_SCOPE: &str = "tap:full";
const ACCESS_TOKEN_LIFETIME_SECONDS: i64 = 60 * 60;
/// Absolute lifetime of a refresh-token *family*: rotated refresh tokens carry
/// the original expiry forward, so a connection silently renews for this long
/// and then requires a fresh login + passkey.
const REFRESH_TOKEN_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;
const AUTHORIZATION_CODE_LIFETIME_SECONDS: i64 = 2 * 60;
const AUTHORIZATION_REQUEST_LIFETIME_SECONDS: i64 = 5 * 60;
const DYNAMIC_CLIENT_LIFETIME_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing environment variable {0}")]
    Missing(&'static str),
    #[error("invalid TAP_MCP_PUBLIC_URL: {0}")]
    InvalidPublicUrl(String),
    #[error("TAP_MCP_LOCAL_KEY must contain at least 32 bytes")]
    LocalKeyTooShort,
    #[error("invalid TAP_MCP_LISTEN_ADDR: {0}")]
    InvalidListenAddr(String),
    #[error("missing environment variable TAP_DASHBOARD_URL outside demo mode")]
    MissingDashboardUrl,
    #[error("invalid TAP_DASHBOARD_URL: {0}")]
    InvalidDashboardUrl(String),
    #[error("invalid TAP_PROXY_URL: {0}")]
    InvalidProxyUrl(String),
    #[error(
        "DANGEROUS_TAP_MCP_DEMO_AUTH is only allowed with a loopback TAP_MCP_PUBLIC_URL \
         (127.0.0.1/localhost/::1) — refusing to run the demo consent screen on a public host"
    )]
    DemoModeRequiresLoopback,
    #[error("missing environment variable TAP_PROXY_URL outside demo mode")]
    MissingProxyUrl,
    #[error(
        "missing environment variable TAP_MCP_SERVICE_KEY outside demo mode — it authenticates \
         this service to the proxy's /internal/mcp endpoints and must match the value set on \
         tap-proxy"
    )]
    MissingServiceKey,
}

#[derive(Debug, Clone)]
pub struct McpConfig {
    public_base_url: Url,
    listen_addr: SocketAddr,
    /// `TAP_MCP_LOCAL_KEY` — this service's **own** HMAC key, for artifacts it
    /// both issues and verifies and that `tap-proxy` never acts on: the signed
    /// `authorization-request`, the DCR `dynamic-client` id, and the
    /// `authorization-code`.
    ///
    /// It is emphatically **not** tap-proxy's token-signing key, which this
    /// service no longer reads at all. HMAC is symmetric, so holding the key
    /// that signs access tokens *is* the authority to mint one for any
    /// `team_id`/`agent_id` —
    /// letting this internet-facing, non-enclave process forge a bearer for any
    /// team and act as it on `/forward`, bypassing the passkey consent flow
    /// entirely. Domain separation cannot help: it constrains a value, not a key
    /// holder. So access tokens, refresh tokens and authorization assertions are
    /// minted and verified **only** by tap-proxy, which this service reaches via
    /// `/internal/mcp/token/{issue,refresh}`.
    ///
    /// Must be a different value from tap-proxy's token-signing key. See
    /// `README.md` ("Two keys, two trust domains") for the full contract.
    local_key: Arc<[u8]>,
    demo_auth: bool,
    dashboard_url: Option<Url>,
    /// Base URL of the TAP proxy the MCP tools call on the user's behalf
    /// (`/agent/services`, `/forward`, `/agent/approvals/{id}`). None disables
    /// the credential tools (discovery-only spike).
    proxy_url: Option<Url>,
    /// Shared secret authenticating this service to the proxy's
    /// `/internal/mcp/*` endpoints, which back the durable OAuth token state
    /// (revocable refresh-token families + single-use authorization codes).
    ///
    /// **tap-mcp holds no database credentials.** It is an internet-facing OAuth
    /// server running outside the attested enclave that `tap-proxy` runs in, so
    /// handing it a connection string to the database holding encrypted
    /// credential blobs would put that capability on the wrong side of the
    /// boundary. The three token-state writes go to the proxy instead.
    ///
    /// Required (together with `proxy_url`) outside demo mode; `None` in the
    /// demo keeps the stateless legacy path.
    service_key: Option<String>,
}

impl McpConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let public_url = std::env::var("TAP_MCP_PUBLIC_URL")
            .map_err(|_| ConfigError::Missing("TAP_MCP_PUBLIC_URL"))?;
        // NOTE: this service deliberately reads NO token-signing key. Minting
        // is tap-proxy's alone — see the `local_key` field docs.
        let local_key = std::env::var("TAP_MCP_LOCAL_KEY")
            .map_err(|_| ConfigError::Missing("TAP_MCP_LOCAL_KEY"))?;
        let listen_addr =
            std::env::var("TAP_MCP_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3200".to_string());
        // Dangerous flag per repo convention (mirrors DANGEROUS_TAP_*): the demo
        // consent screen bypasses TAP login + passkey, so it must never be on in
        // production. The old name (TAP_MCP_DEMO_AUTH) is intentionally ignored.
        let demo_auth = std::env::var("DANGEROUS_TAP_MCP_DEMO_AUTH")
            .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let dashboard_url = std::env::var("TAP_DASHBOARD_URL").ok();
        let proxy_url = std::env::var("TAP_PROXY_URL").ok();
        let service_key = std::env::var("TAP_MCP_SERVICE_KEY")
            .ok()
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty());

        // Outside the demo, refresh-token revocation + single-use codes are
        // mandatory (TAP Distributed State Rule). They are backed by the proxy's
        // `/internal/mcp/*` endpoints, so both the proxy URL and the service key
        // are required — this service never talks to Postgres itself.
        if !demo_auth {
            if proxy_url.is_none() {
                return Err(ConfigError::MissingProxyUrl);
            }
            if service_key.is_none() {
                return Err(ConfigError::MissingServiceKey);
            }
        }

        let mut config = Self::new_full(
            &public_url,
            dashboard_url.as_deref(),
            proxy_url.as_deref(),
            &local_key,
            &listen_addr,
            demo_auth,
        )?;
        config.service_key = service_key;
        Ok(config)
    }

    pub fn new(
        public_url: &str,
        local_key: &str,
        listen_addr: &str,
        demo_auth: bool,
    ) -> Result<Self, ConfigError> {
        Self::new_full(public_url, None, None, local_key, listen_addr, demo_auth)
    }

    pub fn new_with_dashboard(
        public_url: &str,
        dashboard_url: Option<&str>,
        local_key: &str,
        listen_addr: &str,
        demo_auth: bool,
    ) -> Result<Self, ConfigError> {
        Self::new_full(
            public_url,
            dashboard_url,
            None,
            local_key,
            listen_addr,
            demo_auth,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_full(
        public_url: &str,
        dashboard_url: Option<&str>,
        proxy_url: Option<&str>,
        local_key: &str,
        listen_addr: &str,
        demo_auth: bool,
    ) -> Result<Self, ConfigError> {
        if local_key.len() < 32 {
            return Err(ConfigError::LocalKeyTooShort);
        }

        let mut public_base_url = Url::parse(public_url)
            .map_err(|error| ConfigError::InvalidPublicUrl(error.to_string()))?;
        if public_base_url.query().is_some()
            || public_base_url.fragment().is_some()
            || public_base_url.cannot_be_a_base()
        {
            return Err(ConfigError::InvalidPublicUrl(
                "the URL must be an absolute HTTP(S) origin".to_string(),
            ));
        }
        if public_base_url.scheme() != "https"
            && !(demo_auth
                && public_base_url.scheme() == "http"
                && matches!(public_base_url.host_str(), Some("127.0.0.1" | "localhost")))
        {
            return Err(ConfigError::InvalidPublicUrl(
                "HTTPS is required outside local demo mode".to_string(),
            ));
        }
        // Demo mode disables the allowed-hosts guard and serves a passwordless
        // consent screen — refuse it on any non-loopback public URL, even HTTPS.
        if demo_auth
            && !matches!(
                public_base_url.host_str(),
                Some("127.0.0.1" | "localhost" | "::1")
            )
        {
            return Err(ConfigError::DemoModeRequiresLoopback);
        }
        public_base_url.set_path("/");
        let listen_addr = listen_addr
            .parse::<SocketAddr>()
            .map_err(|error| ConfigError::InvalidListenAddr(error.to_string()))?;

        let dashboard_url = match dashboard_url {
            Some(raw) => {
                let url = Url::parse(raw)
                    .map_err(|error| ConfigError::InvalidDashboardUrl(error.to_string()))?;
                if url.cannot_be_a_base()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || (url.scheme() != "https"
                        && !(url.scheme() == "http"
                            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))))
                {
                    return Err(ConfigError::InvalidDashboardUrl(
                        "expected an HTTPS URL without a query or fragment".to_string(),
                    ));
                }
                Some(url)
            }
            None if demo_auth => None,
            None => return Err(ConfigError::MissingDashboardUrl),
        };

        let proxy_url = match proxy_url {
            Some(raw) => {
                let url = Url::parse(raw)
                    .map_err(|error| ConfigError::InvalidProxyUrl(error.to_string()))?;
                if url.cannot_be_a_base()
                    || url.fragment().is_some()
                    || (url.scheme() != "https"
                        && !(url.scheme() == "http"
                            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))))
                {
                    return Err(ConfigError::InvalidProxyUrl(
                        "expected an HTTPS URL (HTTP allowed only on loopback)".to_string(),
                    ));
                }
                Some(url)
            }
            None => None,
        };

        Ok(Self {
            public_base_url,
            listen_addr,
            local_key: Arc::from(local_key.as_bytes()),
            demo_auth,
            dashboard_url,
            proxy_url,
            service_key: None,
        })
    }

    /// Build the durable token-state client — an authenticated HTTP client for
    /// the proxy's `/internal/mcp/*` endpoints. `None` (demo mode: no proxy URL
    /// or no service key) keeps the stateless legacy path.
    pub fn token_client(&self) -> Option<TokenClient> {
        let base = self.proxy_url.clone()?;
        let service_key = self.service_key.clone()?;
        Some(TokenClient::new(base, service_key))
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn public_base_url(&self) -> &Url {
        &self.public_base_url
    }

    fn endpoint(&self, path: &str) -> Url {
        self.public_base_url
            .join(path.trim_start_matches('/'))
            .expect("validated base URL accepts relative paths")
    }

    fn resource_url(&self) -> Url {
        self.endpoint("mcp")
    }

    fn dashboard_authorization_url(&self, signed_request: &str) -> Option<Url> {
        self.dashboard_url.as_ref().map(|base| {
            let mut url = base.clone();
            url.query_pairs_mut()
                .append_pair("mcp_request", signed_request);
            url
        })
    }
}

/// How long a token-state call to the proxy may take. These sit on the OAuth
/// connect/refresh path (never per-request), so a generous timeout is fine; the
/// caller fails closed if it elapses.
const TOKEN_STATE_TIMEOUT_SECS: u64 = 10;

/// Something went wrong *talking to* the proxy. Distinct from a proxy answer of
/// "rejected" (`Ok(false)`), which is a normal, expected outcome. Every caller
/// treats this as **fail closed** — the token or code is refused.
#[derive(Debug, Error)]
pub enum TokenStateError {
    #[error("could not reach the TAP proxy token-state endpoint: {0}")]
    Transport(String),
    #[error("TAP proxy token-state endpoint returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("TAP proxy token-state endpoint returned an unexpected body: {0}")]
    Malformed(String),
}

/// Authenticated client for the proxy's `/internal/mcp/*` endpoints — the
/// durable, cross-instance OAuth token state (`tap_core::mcp_tokens`, executed
/// *inside* the enclave by tap-proxy).
///
/// `tap-mcp` deliberately owns no database connection: it is an internet-facing
/// OAuth server outside the attested container group, and a `POSTGRES_DATABASE_URL`
/// there would be a credential for the database holding encrypted credential
/// blobs. Only three low-frequency operations are needed (record on issue,
/// rotate on refresh, consume on code redemption), all on the OAuth ceremony
/// path, so routing them through the proxy costs nothing on the hot path.
#[derive(Clone)]
pub struct TokenClient {
    http: reqwest::Client,
    base: Url,
    service_key: String,
}

impl std::fmt::Debug for TokenClient {
    /// Never render the service key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenClient")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl TokenClient {
    pub fn new(base: Url, service_key: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(TOKEN_STATE_TIMEOUT_SECS))
            .build()
            .unwrap_or_default();
        Self {
            http,
            base,
            service_key,
        }
    }

    async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, TokenStateError> {
        let url = self
            .base
            .join(path)
            .map_err(|error| TokenStateError::Transport(error.to_string()))?;
        let response = self
            .http
            .post(url)
            .header("X-TAP-Service-Key", &self.service_key)
            .json(&body)
            .send()
            .await
            .map_err(|error| TokenStateError::Transport(error.to_string()))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // 404 here means the proxy has no TAP_MCP_SERVICE_KEY configured, so
            // the endpoints are disabled; 401 means ours does not match. Both are
            // deployment faults and both fail closed.
            return Err(TokenStateError::Status {
                status: status.as_u16(),
                body: text.chars().take(200).collect(),
            });
        }
        serde_json::from_str(&text).map_err(|error| TokenStateError::Malformed(error.to_string()))
    }

    /// Ask the proxy to mint a token pair for the `authorization_code` grant.
    ///
    /// We send the **proxy's own** authorization assertion, not an identity of
    /// our choosing: the proxy re-verifies it with a key this service does not
    /// hold and derives `subject`/`team_id`/`agent_id` itself. `code_jti` is the
    /// authorization code's nonce, consumed exactly once inside the same call,
    /// so a replayed code cannot open a second token family.
    async fn issue_tokens(
        &self,
        assertion: &str,
        client_id: &str,
        code_jti: &str,
        code_expires_at: i64,
    ) -> Result<Option<MintedTokens>, TokenStateError> {
        self.mint(
            "internal/mcp/token/issue",
            serde_json::json!({
                "assertion": assertion,
                "client_id": client_id,
                "code_jti": code_jti,
                "code_expires_at": code_expires_at,
            }),
        )
        .await
    }

    /// Ask the proxy to verify and rotate a refresh token. `Ok(None)` means the
    /// proxy *rejected* it — replayed, superseded, revoked or expired — which is
    /// exactly the replay-detection signal, distinct from a transport failure.
    async fn refresh_tokens(
        &self,
        refresh_token: &str,
        client_id: &str,
        resource: Option<&str>,
    ) -> Result<Option<MintedTokens>, TokenStateError> {
        self.mint(
            "internal/mcp/token/refresh",
            serde_json::json!({
                "refresh_token": refresh_token,
                "client_id": client_id,
                "resource": resource,
            }),
        )
        .await
    }

    /// Shared shape of both minting calls: `{"issued": true, …tokens}` or
    /// `{"issued": false, "reason": …}`. A missing/!bool `issued` is malformed
    /// and fails closed rather than being read as success.
    async fn mint(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<Option<MintedTokens>, TokenStateError> {
        let value = self.post(path, body).await?;
        let issued = value
            .get("issued")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| TokenStateError::Malformed("missing boolean `issued`".to_string()))?;
        if !issued {
            return Ok(None);
        }
        serde_json::from_value(value)
            .map(Some)
            .map_err(|error| TokenStateError::Malformed(error.to_string()))
    }
}

/// The token pair the proxy minted. `tap-mcp` relays these to the OAuth client
/// verbatim and cannot read or forge them — it holds no key that verifies them.
#[derive(Debug, Deserialize)]
struct MintedTokens {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Clone)]
struct AppState {
    config: McpConfig,
    signer: TokenSigner,
    /// Durable OAuth token state (revocable refresh-token families + single-use
    /// authorization codes), reached over the proxy's authenticated
    /// `/internal/mcp/*` endpoints. `None` (demo mode) ⇒ stateless legacy
    /// tokens; the production path is a cross-instance DB claim executed inside
    /// the enclave by tap-proxy (`tap_core::mcp_tokens`).
    token_client: Option<TokenClient>,
    /// Same-instance single-use fallback for the demo/no-client path only (the
    /// production single-use guarantee is the DB claim above). Maps a consumed
    /// code's nonce → its expiry; pruned on each exchange.
    consumed_codes: Arc<Mutex<HashMap<String, i64>>>,
    /// Basic per-IP throttle for the unauthenticated OAuth endpoints.
    rate_limiter: Arc<OAuthRateLimiter>,
}

impl AppState {
    fn new(config: McpConfig, token_client: Option<TokenClient>) -> Self {
        let signer = TokenSigner::new(config.local_key.clone());
        Self {
            config,
            signer,
            token_client,
            consumed_codes: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: Arc::new(OAuthRateLimiter::default()),
        }
    }
}

/// Requests per IP per fixed window allowed on the OAuth ceremony endpoints
/// (`/register`, `/authorize`, `/token`). A basic anti-abuse throttle, not a
/// security boundary — PKCE + the signed-value checks are. Process-local (these
/// endpoints are pre-auth so there is no agent to key a DB counter on); behind a
/// shared load balancer the peer IP may be the LB, so treat this as best-effort.
const OAUTH_RATE_LIMIT_MAX: u32 = 30;
const OAUTH_RATE_LIMIT_WINDOW_SECS: i64 = 60;

#[derive(Default)]
struct OAuthRateLimiter {
    hits: Mutex<HashMap<IpAddr, (i64, u32)>>,
}

impl OAuthRateLimiter {
    /// Fixed-window count. Returns `false` when the IP is over the limit for the
    /// current window. Fail-open on a poisoned lock (throttle is not the boundary).
    fn allow(&self, ip: IpAddr, now: i64) -> bool {
        let window = now - now.rem_euclid(OAUTH_RATE_LIMIT_WINDOW_SECS);
        let mut map = match self.hits.lock() {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Bound memory: drop entries from prior windows if the map grows large.
        if map.len() > 10_000 {
            map.retain(|_, (w, _)| *w == window);
        }
        let entry = map.entry(ip).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= OAUTH_RATE_LIMIT_MAX {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// Per-IP throttle middleware for the OAuth endpoints. The peer address is read
/// from the request's `ConnectInfo` extension, which is absent under
/// `tower::oneshot` tests (they set no peer) so those simply pass through.
async fn oauth_rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Some(ConnectInfo(addr)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        if !state.rate_limiter.allow(addr.ip(), now_timestamp()) {
            return oauth_error(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "Too many requests — slow down and retry shortly",
            );
        }
    }
    next.run(request).await
}

#[derive(Debug, Clone)]
struct TokenSigner {
    key: Arc<[u8]>,
}

#[derive(Debug, Error)]
enum TokenError {
    #[error("malformed signed value")]
    Malformed,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid payload")]
    InvalidPayload,
}

impl TokenSigner {
    fn new(key: Arc<[u8]>) -> Self {
        Self { key }
    }

    fn sign<T: Serialize>(&self, kind: &str, payload: &T) -> Result<String, TokenError> {
        let json = serde_json::to_vec(payload).map_err(|_| TokenError::InvalidPayload)?;
        let body = URL_SAFE_NO_PAD.encode(json);
        let signature = self.signature(kind, &body)?;
        Ok(format!("{body}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    fn verify<T: DeserializeOwned>(&self, kind: &str, token: &str) -> Result<T, TokenError> {
        let (body, signature) = token.split_once('.').ok_or(TokenError::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| TokenError::Malformed)?;
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| TokenError::Malformed)?;
        mac.update(kind.as_bytes());
        mac.update(&[0]);
        mac.update(body.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| TokenError::InvalidSignature)?;
        let payload = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| TokenError::Malformed)?;
        serde_json::from_slice(&payload).map_err(|_| TokenError::InvalidPayload)
    }

    /// Decode a signed value's payload **without checking its signature**.
    ///
    /// Used only for values signed with tap-proxy's token-signing key, which
    /// this service does not hold and therefore cannot verify: the authorization
    /// assertion (decoded to route the OAuth flow) and the access token (decoded
    /// to answer the `WWW-Authenticate` challenge cheaply). **The result is
    /// untrusted.** Authority is established downstream by tap-proxy, which
    /// verifies the assertion at `/internal/mcp/token/issue` and the access
    /// token on every `/forward` and `/agent/services` call. A forged value gets
    /// no further than a proxy rejection relayed back to the client.
    fn decode_unverified<T: DeserializeOwned>(token: &str) -> Result<T, TokenError> {
        let (body, _) = token.split_once('.').ok_or(TokenError::Malformed)?;
        let payload = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| TokenError::Malformed)?;
        serde_json::from_slice(&payload).map_err(|_| TokenError::InvalidPayload)
    }

    fn signature(&self, kind: &str, body: &str) -> Result<Vec<u8>, TokenError> {
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| TokenError::Malformed)?;
        mac.update(kind.as_bytes());
        mac.update(&[0]);
        mac.update(body.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

/// How long a `tap_call` blocks waiting for a human to approve a gated write
/// before returning "still pending" (the user can call again to resume).
const APPROVAL_POLL_ATTEMPTS: u32 = 40;
const APPROVAL_POLL_INTERVAL_MS: u64 = 1500;

#[derive(Debug, Clone)]
struct TapMcpServer {
    tool_router: ToolRouter<Self>,
    /// TAP proxy the tools call on the user's behalf. None ⇒ credential tools
    /// report that they are unavailable (e.g. the demo, which has no proxy).
    proxy_url: Option<Url>,
    http: reqwest::Client,
}

impl TapMcpServer {
    fn new(proxy_url: Option<Url>, http: reqwest::Client) -> Self {
        Self {
            tool_router: Self::tool_router(),
            proxy_url,
            http,
        }
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct TapCallArgs {
    /// Credential name to use, exactly as returned by `tap_discover` (the
    /// `X-TAP-Credential` value, e.g. "stripe" or "gmail-personal").
    credential: String,
    /// The upstream request target. A full URL for normal credentials
    /// (e.g. "https://api.stripe.com/v1/refunds"); a path for relative-target
    /// credentials (as noted in `tap_discover`).
    target: String,
    /// Upstream HTTP method: GET, POST, PUT, PATCH or DELETE. Defaults to GET.
    /// Reads (GET/HEAD) return immediately; writes pause for human approval.
    #[serde(default)]
    method: Option<String>,
    /// Optional JSON request body for writes.
    #[serde(default)]
    body: Option<Value>,
    /// Optional extra HTTP headers to send upstream, e.g.
    /// {"User-Agent": "my-app", "Notion-Version": "2022-06-28"}. Forwarded
    /// verbatim. Do NOT put secrets here — TAP injects the credential itself;
    /// Authorization and X-TAP-* headers are ignored.
    #[serde(default)]
    headers: Option<std::collections::HashMap<String, String>>,
}

fn tool_error(message: impl Into<String>) -> String {
    json!({ "error": message.into() }).to_string()
}

/// Hard cap on how much of a proxy/upstream response body the MCP tools buffer
/// into memory. The proxy already sanitizes and bounds upstream bodies, but the
/// tools must not be a second unbounded sink — a hostile or misconfigured
/// upstream could otherwise stream gigabytes into a `String`.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Read a response body as UTF-8 (lossy), truncated at `MAX_RESPONSE_BYTES`.
/// Streams chunk-by-chunk so an oversized body is never fully materialized.
async fn read_body_capped(mut response: reqwest::Response) -> String {
    let mut buf: Vec<u8> = Vec::new();
    // `chunk()` yields `Ok(None)` at end of body and `Err` on a transport blip;
    // both end the read (we return what we have).
    while let Ok(Some(chunk)) = response.chunk().await {
        let remaining = MAX_RESPONSE_BYTES.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// The OAuth access token the MCP client sent, lifted back off the HTTP request
/// parts (rmcp injects these into the tool context). The proxy re-verifies it.
fn bearer_from_parts(parts: &http::request::Parts) -> Option<String> {
    parts
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

/// Condense the proxy's `/agent/services` payload into a compact, MCP-oriented
/// list. The raw payload is written for an HTTP/curl agent using `X-TAP-Key` —
/// it's full of `$TAP_PROXY_URL`, `X-TAP-*` headers, curl request templates and
/// protocol caveats. Handing that to an MCP client (which has the `tap_call`
/// tool, no curl, no headers) makes the model hallucinate HTTP plumbing. So we
/// keep only what `tap_call` needs: name, purpose, target shape, and what does
/// or doesn't pause for approval.
fn summarize_discovery(raw: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return raw.to_string();
    };
    let services = value.get("services").and_then(Value::as_object);
    if services.map(|s| s.is_empty()).unwrap_or(true) {
        // The proxy's empty-state guidance (ask the admin / setup link) is
        // already agent-directed — pass it through instead of a bare list.
        let mut empty = json!({ "credentials": [] });
        for key in ["agent_action", "dashboard_url"] {
            if let Some(v) = value.get(key) {
                empty[key] = v.clone();
            }
        }
        return empty.to_string();
    }
    let mut credentials = Vec::new();
    for (name, svc) in services.expect("checked non-empty above") {
        let description = svc.get("description").and_then(Value::as_str).unwrap_or("");

        // Signing keys are used via the proxy's /sign endpoint, which tap_call
        // does not speak — list them so the model can tell the user, no more.
        if svc.get("signing").is_some() {
            credentials.push(json!({
                "name": name,
                "description": description,
                "not_callable": "This is a signing key, used via TAP's /sign endpoint — tap_call cannot use it. Tell the user if they ask.",
            }));
            continue;
        }

        let relative = svc.get("target_shape").and_then(Value::as_str) == Some("relative_path");
        let placeholder = svc.get("target_placeholder").and_then(Value::as_str);
        let target = match (relative, placeholder) {
            (true, Some(p)) => format!("a URL path starting with '/', e.g. {p}"),
            (true, None) => "a URL path starting with '/', not a full URL".to_string(),
            (false, Some(p)) => format!("a full upstream URL, e.g. {p}"),
            (false, None) => "a full upstream URL".to_string(),
        };

        // Writes pause for approval unless every write rule proceeds
        // immediately; URL-override rules skip approval for any method.
        let rules = svc
            .pointer("/approval/rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let writes_need_approval = rules.iter().any(|rule| {
            rule.get("decision").and_then(Value::as_str) == Some("pauses_for_human")
        }) || rules.is_empty();
        let auto_approved_url_patterns: Vec<&str> = rules
            .iter()
            .filter(|rule| {
                rule.get("priority").and_then(Value::as_str) == Some("url_override")
                    && rule.get("decision").and_then(Value::as_str)
                        == Some("proceeds_immediately")
            })
            .filter_map(|rule| rule.get("target").and_then(Value::as_str))
            .collect();

        let mut entry = json!({
            "name": name,
            "description": description,
            "target": target,
            "writes_need_approval": writes_need_approval,
        });
        if !auto_approved_url_patterns.is_empty() {
            entry["auto_approved_url_patterns"] = json!(auto_approved_url_patterns);
            entry["auto_approved_note"] =
                json!("Targets containing one of these patterns skip approval for ANY method.");
        }
        credentials.push(entry);
    }
    json!({
        "credentials": credentials,
        "how_to_use": "Call the tap_call tool with: credential (a name from this list), target (as noted in its 'target' field), method (GET/HEAD return immediately; POST/PUT/PATCH/DELETE pause for the user's one-tap approval), and an optional JSON body for writes. Do NOT build curl commands, X-TAP-* headers, or any proxy URL — those do not exist here; just call tap_call.",
    })
    .to_string()
}

#[tool_router]
impl TapMcpServer {
    #[tool(
        description = "List the TAP credentials this connection can use and how to call each one — service name, whether writes need approval, and example targets. Call this FIRST to discover what is available before using tap_call."
    )]
    async fn tap_discover(&self, Extension(parts): Extension<http::request::Parts>) -> String {
        let Some(base) = self.proxy_url.as_ref() else {
            return tool_error("This TAP MCP server is not linked to a TAP proxy, so credential discovery is unavailable.");
        };
        let Some(token) = bearer_from_parts(&parts) else {
            return tool_error("Missing OAuth bearer token on the MCP request.");
        };
        let url = match base.join("agent/services") {
            Ok(url) => url,
            Err(error) => return tool_error(format!("invalid proxy URL: {error}")),
        };
        match self.http.get(url).bearer_auth(&token).send().await {
            Ok(response) => {
                let status = response.status();
                let text = read_body_capped(response).await;
                if !status.is_success() {
                    return json!({
                        "error": format!("TAP proxy returned HTTP {}", status.as_u16()),
                        "detail": serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text)),
                    })
                    .to_string();
                }
                summarize_discovery(&text)
            }
            Err(error) => tool_error(format!("Could not reach the TAP proxy: {error}")),
        }
    }

    #[tool(
        description = "Call a third-party API through TAP using one of your credentials by NAME. TAP holds the real secret, injects it, enforces policy, and pauses writes (POST/PUT/PATCH/DELETE) for your one-tap human approval before forwarding. You never see the secret. Use a credential name and target from tap_discover."
    )]
    async fn tap_call(
        &self,
        Parameters(args): Parameters<TapCallArgs>,
        Extension(parts): Extension<http::request::Parts>,
    ) -> String {
        let Some(base) = self.proxy_url.as_ref() else {
            return tool_error("This TAP MCP server is not linked to a TAP proxy, so credential calls are unavailable.");
        };
        let Some(token) = bearer_from_parts(&parts) else {
            return tool_error("Missing OAuth bearer token on the MCP request.");
        };
        let method = args
            .method
            .as_deref()
            .map(|value| value.trim().to_ascii_uppercase())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "GET".to_string());

        let forward_url = match base.join("forward") {
            Ok(url) => url,
            Err(error) => return tool_error(format!("invalid proxy URL: {error}")),
        };
        let mut request = self
            .http
            .post(forward_url)
            .bearer_auth(&token)
            .header("X-TAP-Credential", &args.credential)
            .header("X-TAP-Target", &args.target)
            .header("X-TAP-Method", &method);
        // Custom upstream headers pass through verbatim; never let the agent
        // clobber the MCP auth (Authorization) or forge X-TAP-* control headers.
        if let Some(extra) = &args.headers {
            for (name, value) in extra {
                let lower = name.to_ascii_lowercase();
                if lower == "authorization" || lower.starts_with("x-tap-") {
                    continue;
                }
                request = request.header(name, value);
            }
        }
        if let Some(body) = &args.body {
            request = request.json(body);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => return tool_error(format!("Could not reach the TAP proxy: {error}")),
        };

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let text = read_body_capped(response).await;

        // A gated write returns 202 + txn_id; block on the approval, then resume.
        if status == 202 {
            if let Some(txn_id) = serde_json::from_str::<Value>(&text)
                .ok()
                .as_ref()
                .and_then(|value| value.get("txn_id"))
                .and_then(Value::as_str)
            {
                return self.poll_approval(base, &token, txn_id).await;
            }
        }
        shape_forward_response(status, content_type.as_deref(), &text)
    }
}

impl TapMcpServer {
    async fn poll_approval(&self, base: &Url, token: &str, txn_id: &str) -> String {
        let poll_url = match base.join(&format!("agent/approvals/{txn_id}")) {
            Ok(url) => url,
            Err(error) => return tool_error(format!("invalid proxy URL: {error}")),
        };
        for _ in 0..APPROVAL_POLL_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_millis(APPROVAL_POLL_INTERVAL_MS)).await;
            let response = match self.http.get(poll_url.clone()).bearer_auth(token).send().await {
                Ok(response) => response,
                // Transient network blip — the approval may still land; the
                // loop is bounded, so keep waiting instead of aborting.
                Err(_) => continue,
            };
            let text = read_body_capped(response).await;
            let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            // An error body (expired session, unknown transaction…) never
            // gains a status field — stop polling instead of reporting a
            // misleading "pending" a minute later.
            if value.get("status").is_none() && value.get("error").is_some() {
                return json!({
                    "approval": "unknown",
                    "tap_error": value,
                    "message": "TAP could not report this approval's status. The write may or may not still be waiting — check with the user before retrying.",
                })
                .to_string();
            }
            match value.get("status").and_then(Value::as_str) {
                Some("forwarded") => return shape_approved_result(&value),
                Some("denied") => {
                    return json!({
                        "approval": "denied",
                        "message": "The user denied this request. Nothing was sent upstream and no secret was used. Do not retry — tell the user and ask how they want to proceed.",
                    })
                    .to_string();
                }
                Some("timed_out") => {
                    return json!({
                        "approval": "timed_out",
                        "message": "Nobody decided within TAP's approval window, so nothing was sent. Ask the user, then call tap_call again to re-request.",
                    })
                    .to_string();
                }
                Some("error") => {
                    return json!({
                        "approval": "error",
                        "detail": value.get("error_detail").cloned().unwrap_or(value.clone()),
                        "message": "The request was approved but the upstream call failed — see detail.",
                    })
                    .to_string();
                }
                _ => continue,
            }
        }
        json!({
            "status": "pending",
            "txn_id": txn_id,
            "message": "Still awaiting human approval. Ask the user to approve it (Telegram or the TAP dashboard), then call tap_call again to resume."
        })
        .to_string()
    }
}

/// Shape a mirrored `/forward` response for the model: keep the upstream
/// status and content type, parse a JSON body into real JSON (a JSON-escaped
/// string both wastes tokens and reads as noise), and separate TAP's own
/// policy rejections — which carry agent-directed fields — from upstream
/// errors, with a corrective hint instead of the raw envelope.
fn shape_forward_response(status: u16, content_type: Option<&str>, body: &str) -> String {
    let parsed: Option<Value> = serde_json::from_str(body).ok();

    // TAP's own rejections (bad credential name, blocked host, expired
    // session…) are JSON with agent-directed markers; upstream responses are
    // mirrored verbatim and never carry them.
    if status >= 400 {
        if let Some(value) = parsed.as_ref().filter(|value| is_tap_error(value)) {
            let mut out = json!({ "tap_error": value, "hint": tap_error_hint(status, value) });
            if let Some(link) = value.get("credential_link_url") {
                out["credential_link_url"] = link.clone();
            }
            return out.to_string();
        }
    }

    // A bare {"error": "<msg>"} is also the shape of TAP's generic rejections
    // (routing, rate limit, SSRF guard), which carry no other marker — don't
    // assert an origin we can't know.
    let ambiguous_error = parsed
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|map| map.len() == 1 && map.get("error").is_some_and(Value::is_string));
    let mut out = json!({
        "upstream_status": status,
        "content_type": content_type,
        "body": shape_body(content_type, parsed, body),
    });
    if status >= 400 {
        out["note"] = if ambiguous_error {
            json!("This error may come from TAP rejecting the request before forwarding, or from the upstream API itself — read the error text.")
        } else {
            json!("This status came from the upstream API itself — TAP forwarded the request.")
        };
    }
    out.to_string()
}

/// The upstream body as real JSON when it is JSON, otherwise the raw string.
fn shape_body(content_type: Option<&str>, parsed: Option<Value>, body: &str) -> Value {
    let looks_json = content_type.is_some_and(|ct| ct.contains("json"));
    match parsed {
        Some(value) if looks_json || matches!(value, Value::Object(_) | Value::Array(_)) => value,
        _ => Value::String(body.to_string()),
    }
}

fn is_tap_error(value: &Value) -> bool {
    // Every field TAP's own /forward rejections carry that a mirrored upstream
    // body never does: the Socratic fields (error_code/agent_action/
    // safe_to_retry/setup_url), the missing-credential enrichment
    // (credential_link_url), the allowed_hosts 403 ("fix"), and the inline
    // OAuth reauth errors (reauth_url/retry_after_reauth).
    [
        "error_code",
        "agent_action",
        "safe_to_retry",
        "setup_url",
        "credential_link_url",
        "fix",
        "reauth_url",
        "retry_after_reauth",
    ]
    .iter()
    .any(|marker| value.get(marker).is_some())
}

fn tap_error_hint(status: u16, value: &Value) -> &'static str {
    if value.get("credential_link_url").is_some() {
        return "That credential does not exist yet. Give the user the credential_link_url so they can create it in the TAP dashboard, then retry.";
    }
    if value.get("reauth_url").is_some() {
        return "The stored OAuth token needs the user to re-authorize. Give the user the reauth_url, wait for them to finish, then retry.";
    }
    match status {
        401 => "The TAP connection is no longer valid. Ask the user to reconnect this MCP server (disconnect and reconnect it in their client).",
        403 => "TAP refused this request — not the upstream API. Usual causes: the credential name is wrong, or this credential is not allowed to reach that host. Re-run tap_discover and check both.",
        400 => "TAP rejected the request as malformed. Check the target (full URL vs path — see tap_discover) and the method.",
        429 => "TAP rate-limited this agent. Wait a bit before retrying.",
        _ if value.get("safe_to_retry").and_then(Value::as_bool) == Some(true) => {
            "Transient TAP-side failure — safe to retry."
        }
        _ => "TAP could not complete the request — see tap_error for details.",
    }
}

/// Shape the stored upstream response of an approved-and-forwarded write the
/// same way as an immediate `/forward` mirror (status + content type + parsed
/// body), instead of dumping the whole approval envelope with its full
/// upstream header list.
fn shape_approved_result(value: &Value) -> String {
    let response = value.get("response");
    let status = response
        .and_then(|r| r.get("status"))
        .and_then(Value::as_u64);
    let content_type = response
        .and_then(|r| r.get("headers"))
        .and_then(Value::as_array)
        .and_then(|headers| {
            headers.iter().find_map(|pair| {
                let name = pair.get(0).and_then(Value::as_str)?;
                name.eq_ignore_ascii_case("content-type")
                    .then(|| pair.get(1).and_then(Value::as_str))
                    .flatten()
            })
        });
    let body = response
        .and_then(|r| r.get("body"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let body_encoding = response
        .and_then(|r| r.get("body_encoding"))
        .and_then(Value::as_str);

    let mut out = json!({
        "approval": "approved_and_forwarded",
        "upstream_status": status,
        "content_type": content_type,
    });
    if body_encoding == Some("base64") {
        out["body"] = json!(body);
        out["body_encoding"] = json!("base64");
    } else {
        out["body"] = shape_body(content_type, serde_json::from_str(body).ok(), body);
    }
    // The proxy annotates a forwarded row whose stored upstream response is
    // incomplete — keep that explanation rather than showing bare nulls.
    if let Some(note) = response.and_then(|r| r.get("note")) {
        out["note"] = note.clone();
    }
    out.to_string()
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for TapMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("tap-mcp", env!("CARGO_PKG_VERSION")).with_title("TAP MCP"),
            )
            .with_instructions(
                "TAP lets you call the user's third-party APIs without ever seeing their secrets. \
                 Call tap_discover to list the credentials available on this connection, then \
                 tap_call to make a request by credential name — TAP injects the secret, enforces \
                 policy, and pauses any write for the user's approval.",
            )
    }
}

/// Build the router, deriving the durable token-state client from the config.
///
/// Production (`McpConfig::from_env`) always yields a client, because
/// `TAP_PROXY_URL` + `TAP_MCP_SERVICE_KEY` are mandatory outside demo mode.
/// Programmatically-built configs (demo/tests) yield `None` and keep the
/// stateless legacy path.
pub fn build_router(config: McpConfig) -> Router {
    let token_client = config.token_client();
    build_router_with_client(config, token_client)
}

/// Build the router with an explicitly supplied token-state client. Used by
/// tests that point the client at a mock proxy.
pub fn build_router_with_client(config: McpConfig, token_client: Option<TokenClient>) -> Router {
    let state = AppState::new(config, token_client);
    let mut transport_config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None);
    if state.config.demo_auth {
        // A temporary public tunnel has an unpredictable Host header. This is
        // enabled only alongside the explicit demo-auth flag and must not be
        // used for production deployment.
        transport_config = transport_config.disable_allowed_hosts();
    } else if let Some(host) = state.config.public_base_url.host_str() {
        transport_config = transport_config.with_allowed_hosts([host]);
    }

    let proxy_url = state.config.proxy_url.clone();
    let http = reqwest::Client::new();
    let mcp_service: StreamableHttpService<TapMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(TapMcpServer::new(proxy_url.clone(), http.clone())),
            Default::default(),
            transport_config,
        );

    let protected_mcp = Router::new().nest_service("/mcp", mcp_service).route_layer(
        middleware::from_fn_with_state(state.clone(), require_mcp_access_token),
    );

    let public = Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        // RFC 8414 path-suffixed variant (resource is /mcp) plus the OIDC
        // discovery aliases — clients differ in which they probe first
        // (ChatGPT tries these before falling back), so serve them all.
        .route(
            "/.well-known/oauth-authorization-server/mcp",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration/mcp",
            get(authorization_server_metadata),
        )
        .route("/authorize/callback", get(authorize_callback));

    // Per-IP throttle on the unauthenticated OAuth ceremony endpoints.
    let oauth = Router::new()
        .route("/register", post(register_client))
        .route("/authorize", get(authorize_page).post(authorize_decision))
        .route("/token", post(exchange_token))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            oauth_rate_limit,
        ));

    public.merge(oauth).with_state(state).merge(protected_mcp)
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "service": "tap-mcp"}))
}

async fn protected_resource_metadata(State(state): State<AppState>) -> Json<Value> {
    let resource = state.config.resource_url().to_string();
    let issuer = state.config.public_base_url().to_string();
    let documentation = state.config.endpoint("docs").to_string();
    Json(json!({
        "resource": resource,
        "authorization_servers": [issuer],
        "scopes_supported": [FULL_SCOPE],
        "resource_documentation": documentation
    }))
}

async fn authorization_server_metadata(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.config.public_base_url().to_string();
    let authorization_endpoint = state.config.endpoint("authorize").to_string();
    let token_endpoint = state.config.endpoint("token").to_string();
    let registration_endpoint = state.config.endpoint("register").to_string();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "registration_endpoint": registration_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [FULL_SCOPE]
    }))
}

#[derive(Debug, Deserialize)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    #[serde(default)]
    response_types: Vec<String>,
    #[serde(default = "default_token_endpoint_auth_method")]
    token_endpoint_auth_method: String,
}

fn default_token_endpoint_auth_method() -> String {
    "none".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisteredClient {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    issued_at: i64,
    expires_at: i64,
}

async fn register_client(
    State(state): State<AppState>,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    if request.redirect_uris.is_empty() || request.redirect_uris.len() > 8 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "One to eight redirect URIs are required",
        );
    }
    if request
        .redirect_uris
        .iter()
        .any(|redirect| !valid_redirect_uri(redirect))
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Redirect URIs must be HTTPS or an HTTP loopback address",
        );
    }
    // PKCE is the real security boundary here; the auth method only decides
    // whether we also hand back a (stateless, HMAC-derived) client_secret.
    // ChatGPT registers as client_secret_post — rejecting it broke its
    // connector setup outright ("Couldn't register with tap's sign-in service").
    if !matches!(
        request.token_endpoint_auth_method.as_str(),
        "none" | "client_secret_post" | "client_secret_basic"
    ) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "Supported token endpoint auth methods: none, client_secret_post, client_secret_basic",
        );
    }
    if !request.grant_types.is_empty()
        && !request
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "authorization_code grant is required",
        );
    }
    if !request.response_types.is_empty()
        && !request
            .response_types
            .iter()
            .any(|response| response == "code")
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "code response type is required",
        );
    }

    let now = now_timestamp();
    let client = RegisteredClient {
        redirect_uris: request.redirect_uris.clone(),
        client_name: request.client_name.clone(),
        issued_at: now,
        expires_at: now + DYNAMIC_CLIENT_LIFETIME_SECONDS,
    };
    let client_id = match state.signer.sign("dynamic-client", &client) {
        Ok(client_id) => client_id,
        Err(error) => {
            tracing::error!(%error, "failed to sign dynamic client registration");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Could not register OAuth client",
            );
        }
    };

    let mut response = json!({
        "client_id": client_id,
        "client_id_issued_at": now,
        "redirect_uris": request.redirect_uris,
        "client_name": request.client_name,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": request.token_endpoint_auth_method,
    });
    if request.token_endpoint_auth_method != "none" {
        // Stateless client secret: an HMAC over the client_id under its own
        // domain. Deterministic, so /token can verify it without storage; the
        // domain separator keeps it unusable as any other signed value.
        let client_secret = match state.signer.sign("client-secret", &client_id) {
            Ok(secret) => secret,
            Err(error) => {
                tracing::error!(%error, "failed to derive client secret");
                return oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Could not register OAuth client",
                );
            }
        };
        response["client_secret"] = json!(client_secret);
        response["client_secret_expires_at"] = json!(client.expires_at);
    }

    (StatusCode::CREATED, Json(response)).into_response()
}

fn valid_redirect_uri(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if url.scheme() == "https" {
        return url.host_str().is_some();
    }
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    resource: String,
    scope: Option<String>,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct AuthorizationQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    resource: String,
    #[serde(default)]
    scope: Option<String>,
}

async fn authorize_page(
    State(state): State<AppState>,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    if let Err(error) = validate_authorization_query(&state, &query) {
        return error.into_response();
    }

    let request = AuthorizationRequest {
        response_type: query.response_type,
        client_id: query.client_id,
        redirect_uri: query.redirect_uri,
        state: query.state,
        code_challenge: query.code_challenge,
        code_challenge_method: query.code_challenge_method,
        resource: query.resource,
        scope: query.scope,
        expires_at: now_timestamp() + AUTHORIZATION_REQUEST_LIFETIME_SECONDS,
    };
    let signed_request = match state.signer.sign("authorization-request", &request) {
        Ok(request) => request,
        Err(error) => {
            tracing::error!(%error, "failed to sign authorization request");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Could not create authorization request",
            );
        }
    };

    if !state.config.demo_auth {
        let Some(dashboard_url) = state.config.dashboard_authorization_url(&signed_request) else {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "TAP dashboard authorization is not configured",
            );
        };
        return Redirect::to(dashboard_url.as_str()).into_response();
    }

    // human.tech design language: white surface, brand-navy (#17235E) headline,
    // interactive blue (#4E77F4), tinted scope card. Inline styles keep this
    // standalone page dependency-free (no dashboard fonts/CSS are available here).
    // The production consent lives in the dashboard's McpConnect.svelte; this demo
    // page is only shown under TAP_MCP_DEMO_AUTH.
    // `r##"…"##` (not `r#"…"#`) because the SVG contains `"#` sequences
    // (e.g. stroke="#4E77F4") that would otherwise close the raw string.
    Html(format!(
        r##"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect TAP</title></head>
<body style="margin:0;background:#FAFAFA;color:#525252;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">
  <main style="max-width:440px;margin:64px auto;padding:0 20px">
    <div style="background:#FFFFFF;border:1px solid #E5E5E5;border-radius:16px;padding:32px">
      <svg width="34" height="39" viewBox="0 0 20 23" fill="none" style="display:block;margin:0 auto 20px" aria-hidden="true">
        <path d="M4.5 10V7a5.5 5.5 0 0 1 11 0v3" stroke="#4E77F4" stroke-width="2.2" stroke-linecap="round"/>
        <rect x="1" y="10" width="18" height="12" rx="4" fill="#17235E"/>
        <circle cx="10" cy="16" r="2" fill="white" opacity="0.9"/>
        <path d="M10 18v1.5" stroke="white" stroke-width="1.8" stroke-linecap="round" opacity="0.9"/>
      </svg>
      <div style="text-align:center;color:#4E77F4;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em">Remote MCP connection</div>
      <h1 style="font-family:Georgia,'Times New Roman',serif;color:#17235E;font-size:25px;font-weight:600;letter-spacing:-0.02em;text-align:center;margin:8px 0 10px">Connect this app to TAP?</h1>
      <p style="font-size:14px;line-height:1.55;text-align:center;margin:0 0 20px">The app is requesting access to your TAP tools and credentials. TAP policies and approval rules still apply to every action.</p>
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px;border:1px solid #D0E0FF;border-radius:10px;background:#F5F9FF;margin-bottom:20px">
        <div style="display:flex;flex-direction:column;gap:3px">
          <span style="color:#737373;font-size:11px;text-transform:uppercase;letter-spacing:0.05em">Requested access</span>
          <strong style="color:#17235E;font-size:14px">Full TAP account</strong>
        </div>
        <span style="background:#E5EFFF;color:#17235E;font-size:12px;font-weight:600;padding:5px 12px;border-radius:9999px">tap:full</span>
      </div>
      <form method="post" action="/authorize" style="margin:0">
        <input type="hidden" name="request" value="{signed_request}">
        <button name="decision" value="approve" style="width:100%;background:#4E77F4;color:#FFFFFF;border:0;border-radius:10px;padding:13px 18px;font-size:15px;font-weight:600;cursor:pointer">Authorize connection</button>
        <button name="decision" value="deny" style="width:100%;background:transparent;color:#737373;border:1px solid #E5E5E5;border-radius:10px;padding:12px 18px;font-size:15px;font-weight:500;cursor:pointer;margin-top:10px">Deny</button>
      </form>
      <p style="color:#A3A3A3;font-size:12px;line-height:1.5;text-align:center;margin:18px 0 0">Demo authorization. In production this step is TAP login and passkey approval.</p>
    </div>
  </main>
</body>
</html>"##
    ))
    .into_response()
}

fn validate_authorization_query(
    state: &AppState,
    query: &AuthorizationQuery,
) -> Result<(), OAuthValidationError> {
    if query.response_type != "code" {
        return Err(OAuthValidationError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "Only authorization code is supported",
        ));
    }
    if query.code_challenge_method != "S256" || query.code_challenge.is_empty() {
        return Err(OAuthValidationError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PKCE S256 is required",
        ));
    }
    if query.resource != state.config.resource_url().as_str() {
        return Err(OAuthValidationError::new(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "The resource parameter does not identify this MCP server",
        ));
    }
    if !scope_is_allowed(query.scope.as_deref()) {
        return Err(OAuthValidationError::new(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Only tap:full is supported by this spike",
        ));
    }

    let client: RegisteredClient = state
        .signer
        .verify("dynamic-client", &query.client_id)
        .map_err(|_| {
            OAuthValidationError::new(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "Unknown or invalid dynamic client",
            )
        })?;
    if client.expires_at < now_timestamp() {
        return Err(OAuthValidationError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "Dynamic client registration expired",
        ));
    }
    if !client
        .redirect_uris
        .iter()
        .any(|redirect| redirect == &query.redirect_uri)
    {
        return Err(OAuthValidationError::new(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uri was not registered",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct OAuthValidationError {
    status: StatusCode,
    error: &'static str,
    description: &'static str,
}

impl OAuthValidationError {
    fn new(status: StatusCode, error: &'static str, description: &'static str) -> Self {
        Self {
            status,
            error,
            description,
        }
    }

    fn into_response(self) -> Response {
        oauth_error(self.status, self.error, self.description)
    }
}

fn scope_is_allowed(scope: Option<&str>) -> bool {
    match scope {
        None | Some("") => true,
        Some(scope) => scope
            .split_ascii_whitespace()
            .all(|requested| requested == FULL_SCOPE),
    }
}

#[derive(Debug, Deserialize)]
struct ConsentForm {
    request: String,
    decision: String,
}

/// Signed with `TAP_MCP_LOCAL_KEY` — this service's own artifact.
///
/// It deliberately carries **no trusted identity**. In production it carries the
/// opaque proxy-signed `assertion`, which is handed straight back to the proxy
/// at token issue and verified there; this service cannot read or forge it. The
/// `demo_*` fields exist only for the loopback demo, which has no proxy at all.
#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationCode {
    /// Production: tap-proxy's authorization assertion, relayed verbatim.
    #[serde(default)]
    assertion: String,
    /// Demo only (`DANGEROUS_TAP_MCP_DEMO_AUTH`): locally minted identity.
    #[serde(default)]
    demo_subject: String,
    #[serde(default)]
    demo_team_id: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    resource: String,
    scope: String,
    expires_at: i64,
    nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TapAuthorizationAssertion {
    request: String,
    subject: String,
    team_id: String,
    /// TAP agent id provisioned by tap-proxy for this connection (see
    /// `mcp_auth.rs`); empty when the proxy did not provision one.
    #[serde(default)]
    agent_id: String,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct AuthorizationCallbackQuery {
    assertion: String,
}

async fn authorize_decision(
    State(state): State<AppState>,
    Form(form): Form<ConsentForm>,
) -> Response {
    if !state.config.demo_auth {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "The demo authorization server is disabled",
        );
    }
    let request: AuthorizationRequest =
        match state.signer.verify("authorization-request", &form.request) {
            Ok(request) => request,
            Err(_) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Authorization request is invalid",
                );
            }
        };
    if request.expires_at < now_timestamp() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request expired",
        );
    }

    let mut redirect = match Url::parse(&request.redirect_uri) {
        Ok(redirect) => redirect,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect_uri is invalid",
            );
        }
    };
    if form.decision != "approve" {
        redirect
            .query_pairs_mut()
            .append_pair("error", "access_denied");
        if let Some(state) = request.state {
            redirect.query_pairs_mut().append_pair("state", &state);
        }
        return Redirect::to(redirect.as_str()).into_response();
    }

    issue_authorization_code(
        &state,
        request,
        CodeIdentity::Demo {
            subject: "tap-demo-user".to_string(),
            team_id: "tap-demo-team".to_string(),
        },
    )
}

/// Where the identity behind an authorization code comes from.
enum CodeIdentity {
    /// Production: tap-proxy's signed assertion, opaque to this service and
    /// re-verified by the proxy at token issue.
    Assertion(String),
    /// Demo only: no proxy exists, so this service mints locally.
    Demo { subject: String, team_id: String },
}

async fn authorize_callback(
    State(state): State<AppState>,
    Query(query): Query<AuthorizationCallbackQuery>,
) -> Response {
    // The assertion is signed with tap-proxy's key, which this service does not
    // hold, so it is decoded WITHOUT verification — purely to read the OAuth
    // `request` it wraps and to reject an obviously stale ceremony early. The
    // assertion is relayed verbatim into the authorization code and verified for
    // real by the proxy at `/internal/mcp/token/issue`; a forged one therefore
    // yields a code that can never be exchanged for a token.
    let assertion: TapAuthorizationAssertion =
        match TokenSigner::decode_unverified(&query.assertion) {
            Ok(assertion) => assertion,
            Err(_) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "TAP authorization assertion is malformed",
                );
            }
        };
    let now = now_timestamp();
    if assertion.expires_at < now || assertion.issued_at > now + 30 {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "TAP authorization assertion expired",
        );
    }
    // The OAuth request inside IS ours, so this signature check is real and is
    // what stops a crafted callback from driving the flow to another client.
    let request: AuthorizationRequest = match state
        .signer
        .verify("authorization-request", &assertion.request)
    {
        Ok(request) => request,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "OAuth authorization request is invalid",
            );
        }
    };
    if request.expires_at < now {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "OAuth authorization request expired",
        );
    }

    issue_authorization_code(&state, request, CodeIdentity::Assertion(query.assertion))
}

fn issue_authorization_code(
    state: &AppState,
    request: AuthorizationRequest,
    identity: CodeIdentity,
) -> Response {
    let mut redirect = match Url::parse(&request.redirect_uri) {
        Ok(redirect) => redirect,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect_uri is invalid",
            );
        }
    };

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let (assertion, demo_subject, demo_team_id) = match identity {
        CodeIdentity::Assertion(assertion) => (assertion, String::new(), String::new()),
        CodeIdentity::Demo { subject, team_id } => (String::new(), subject, team_id),
    };
    let code = AuthorizationCode {
        assertion,
        demo_subject,
        demo_team_id,
        client_id: request.client_id,
        redirect_uri: request.redirect_uri,
        code_challenge: request.code_challenge,
        resource: request.resource,
        scope: request.scope.unwrap_or_else(|| FULL_SCOPE.to_string()),
        expires_at: now_timestamp() + AUTHORIZATION_CODE_LIFETIME_SECONDS,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
    };
    let code = match state.signer.sign("authorization-code", &code) {
        Ok(code) => code,
        Err(error) => {
            tracing::error!(%error, "failed to issue authorization code");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Could not issue authorization code",
            );
        }
    };
    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = request.state {
        redirect.query_pairs_mut().append_pair("state", &state);
    }
    Redirect::to(redirect.as_str()).into_response()
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    // authorization_code grant
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    // refresh_token grant
    #[serde(default)]
    refresh_token: Option<String>,
    /// Sent by clients registered as client_secret_post (e.g. ChatGPT).
    /// Optional: PKCE is the security boundary, the secret is verified only
    /// when presented.
    #[serde(default)]
    client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenClaims {
    subject: String,
    team_id: String,
    /// The provisioned TAP agent id. tap-proxy re-verifies this token and acts
    /// as this agent for `/forward` + `/agent/services` (see `mcp_auth.rs`).
    #[serde(default)]
    agent_id: String,
    client_id: String,
    audience: String,
    scope: String,
    /// Random id of the refresh-token family this access token belongs to. The
    /// proxy checks it is not revoked at `/forward` time (`mcp_auth.rs`). Empty
    /// only for the stateless demo path (no token store).
    #[serde(default)]
    family_id: String,
    issued_at: i64,
    expires_at: i64,
}

/// Long-lived, HMAC-signed refresh token. Backed by a durable *token family* row
/// (`tap_core::mcp_tokens`): `family_id` names the family and `jti` is this
/// token's position in the rotation chain. Rotation is a single atomic DB
/// check-and-swap, so a replayed or superseded refresh token is rejected and a
/// family can be revoked cross-instance without deleting the `mcp-*` agent.
/// `expires_at` is the fixed family expiry, carried unchanged through rotations.
#[derive(Debug, Serialize, Deserialize)]
struct RefreshTokenClaims {
    subject: String,
    team_id: String,
    #[serde(default)]
    agent_id: String,
    client_id: String,
    audience: String,
    scope: String,
    /// Durable family id (empty only on the stateless demo path).
    #[serde(default)]
    family_id: String,
    /// This refresh token's unique id within the family; must equal the family's
    /// `current_jti` to rotate (single-use). Empty on the stateless demo path.
    #[serde(default)]
    jti: String,
    issued_at: i64,
    expires_at: i64,
}

async fn exchange_token(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Response {
    // A presented client_secret must be OUR secret for THIS client (the
    // HMAC-derived value issued at registration) — a wrong one is rejected
    // rather than ignored.
    if let Some(secret) = request.client_secret.as_deref() {
        let valid = state
            .signer
            .verify::<String>("client-secret", secret)
            .map(|bound| bound == request.client_id)
            .unwrap_or(false);
        if !valid {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client_secret does not match this client",
            );
        }
    }
    match request.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(&state, request).await,
        "refresh_token" => exchange_refresh_token(&state, request).await,
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Only authorization_code and refresh_token are supported",
        ),
    }
}

async fn exchange_authorization_code(state: &AppState, request: TokenRequest) -> Response {
    let (Some(request_code), Some(redirect_uri), Some(code_verifier), Some(resource)) = (
        request.code.as_deref(),
        request.redirect_uri.as_deref(),
        request.code_verifier.as_deref(),
        request.resource.as_deref(),
    ) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code, redirect_uri, code_verifier and resource are required",
        );
    };
    let code: AuthorizationCode = match state.signer.verify("authorization-code", request_code) {
        Ok(code) => code,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Authorization code is invalid",
            );
        }
    };
    if code.expires_at < now_timestamp()
        || code.client_id != request.client_id
        || code.redirect_uri != redirect_uri
        || code.resource != resource
        || resource != state.config.resource_url().as_str()
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code binding is invalid or expired",
        );
    }
    if !valid_pkce_verifier(code_verifier) || pkce_s256(code_verifier) != code.code_challenge {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        );
    }

    let now = now_timestamp();

    // Production: tap-proxy mints. We relay its own assertion (which we cannot
    // forge) plus the code's nonce as the single-use jti; the proxy verifies the
    // assertion, derives the identity itself, consumes the code and records the
    // refresh-token family, all in one call. We never mint an access token.
    //
    // Every failure below fails CLOSED — a transport blip refuses the exchange
    // rather than falling back to local minting, which is not possible anyway:
    // this service holds no key the proxy would accept.
    if let Some(tokens) = state.token_client.as_ref() {
        if code.assertion.is_empty() {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Authorization code carries no TAP authorization assertion",
            );
        }
        return match tokens
            .issue_tokens(
                &code.assertion,
                &code.client_id,
                &code.nonce,
                code.expires_at,
            )
            .await
        {
            Ok(Some(minted)) => token_response(minted, &code.scope),
            Ok(None) => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Authorization code is invalid, expired or already used",
            ),
            Err(error) => {
                tracing::error!(%error, "tap-proxy could not issue MCP tokens");
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Could not complete the token exchange",
                )
            }
        };
    }

    // Demo/no-store only (loopback, no proxy): same-instance single-use stopgap,
    // then mint locally with TAP_MCP_LOCAL_KEY. These tokens are accepted by
    // nothing but this process — notably NOT by any tap-proxy.
    {
        let mut consumed = state
            .consumed_codes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        consumed.retain(|_, expires_at| *expires_at >= now);
        if consumed.insert(code.nonce.clone(), code.expires_at).is_some() {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Authorization code has already been used",
            );
        }
    }

    issue_demo_token_pair(
        state,
        AccessTokenClaims {
            subject: code.demo_subject,
            team_id: code.demo_team_id,
            agent_id: String::new(),
            client_id: code.client_id,
            audience: code.resource,
            scope: code.scope,
            family_id: String::new(),
            issued_at: now,
            expires_at: now + ACCESS_TOKEN_LIFETIME_SECONDS,
        },
        now + REFRESH_TOKEN_LIFETIME_SECONDS,
        String::new(),
    )
}

/// Relay a proxy-minted pair to the OAuth client verbatim.
fn token_response(minted: MintedTokens, scope: &str) -> Response {
    Json(json!({
        "access_token": minted.access_token,
        "token_type": "Bearer",
        "expires_in": minted.expires_in,
        "refresh_token": minted.refresh_token,
        "scope": scope
    }))
    .into_response()
}

async fn exchange_refresh_token(state: &AppState, request: TokenRequest) -> Response {
    let Some(refresh_token) = request.refresh_token.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };
    // Production: the refresh token was signed by tap-proxy with a key we do not
    // hold, so we neither verify nor rotate it — we ask the proxy to. It checks
    // expiry, client binding and audience, atomically rotates the family (a
    // replayed or superseded token matches no row) and mints the new pair. A
    // transport failure fails CLOSED.
    if let Some(tokens) = state.token_client.as_ref() {
        return match tokens
            .refresh_tokens(
                refresh_token,
                &request.client_id,
                request.resource.as_deref(),
            )
            .await
        {
            Ok(Some(minted)) => token_response(minted, FULL_SCOPE),
            Ok(None) => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Refresh token is invalid, expired, revoked or already used",
            ),
            Err(error) => {
                tracing::error!(%error, "tap-proxy could not rotate the MCP refresh token");
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Could not complete the token exchange",
                )
            }
        };
    }

    // Demo/no-store only: locally signed tokens, stateless rotation.
    let claims: RefreshTokenClaims = match state.signer.verify("refresh-token", refresh_token) {
        Ok(claims) => claims,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Refresh token is invalid",
            );
        }
    };
    let now = now_timestamp();
    // `resource` is optional on refresh (RFC 8707); when present it must match
    // the audience the family was issued for.
    if claims.expires_at < now
        || claims.client_id != request.client_id
        || claims.audience != state.config.resource_url().as_str()
        || request
            .resource
            .as_deref()
            .is_some_and(|resource| resource != claims.audience)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token binding is invalid or expired",
        );
    }

    issue_demo_token_pair(
        state,
        AccessTokenClaims {
            subject: claims.subject,
            team_id: claims.team_id,
            agent_id: claims.agent_id,
            client_id: claims.client_id,
            audience: claims.audience,
            scope: claims.scope,
            family_id: claims.family_id,
            issued_at: now,
            expires_at: now + ACCESS_TOKEN_LIFETIME_SECONDS,
        },
        // Rotate the token but keep the family expiry — see RefreshTokenClaims.
        claims.expires_at,
        String::new(),
    )
}

/// Mint a token pair locally with `TAP_MCP_LOCAL_KEY`.
///
/// **Demo mode only.** In production tap-proxy is the sole issuer; these tokens
/// are signed with a key no proxy verifies with, so they authenticate nothing
/// beyond this process — which is exactly the property the trust split exists to
/// guarantee (see `token_minted_locally_is_not_accepted_by_the_proxy`).
fn issue_demo_token_pair(
    state: &AppState,
    access_claims: AccessTokenClaims,
    refresh_expires_at: i64,
    refresh_jti: String,
) -> Response {
    let refresh_claims = RefreshTokenClaims {
        subject: access_claims.subject.clone(),
        team_id: access_claims.team_id.clone(),
        agent_id: access_claims.agent_id.clone(),
        client_id: access_claims.client_id.clone(),
        audience: access_claims.audience.clone(),
        scope: access_claims.scope.clone(),
        family_id: access_claims.family_id.clone(),
        jti: refresh_jti,
        issued_at: access_claims.issued_at,
        expires_at: refresh_expires_at,
    };
    let signed = state
        .signer
        .sign("access-token", &access_claims)
        .and_then(|access| {
            state
                .signer
                .sign("refresh-token", &refresh_claims)
                .map(|refresh| (access, refresh))
        });
    let (access_token, refresh_token) = match signed {
        Ok(pair) => pair,
        Err(error) => {
            tracing::error!(%error, "failed to issue tokens");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Could not issue tokens",
            );
        }
    };

    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_LIFETIME_SECONDS,
        "refresh_token": refresh_token,
        "scope": access_claims.scope
    }))
    .into_response()
}

fn valid_pkce_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn require_mcp_access_token(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return oauth_challenge(&state, None);
    };
    // In production the access token is signed by tap-proxy with a key this
    // service does not hold, so this gate CANNOT be the security boundary — and
    // it never was. It is a cheap, unverified shape/expiry/audience screen that
    // turns obvious junk into a proper `WWW-Authenticate` challenge. Real
    // authorization happens on every tool call: `tap_discover`/`tap_call` present
    // this bearer to tap-proxy, which verifies the signature, checks the
    // refresh-token family for revocation and resolves the agent
    // (`mcp_auth::resolve_mcp_agent`). A forged bearer reaches the tools and is
    // then rejected by the proxy with nothing granted.
    //
    // In demo mode we signed the token ourselves, so verify it for real.
    let claims: AccessTokenClaims = if state.token_client.is_some() {
        match TokenSigner::decode_unverified(token) {
            Ok(claims) => claims,
            Err(_) => return oauth_challenge(&state, Some("invalid_token")),
        }
    } else {
        match state.signer.verify("access-token", token) {
            Ok(claims) => claims,
            Err(_) => return oauth_challenge(&state, Some("invalid_token")),
        }
    };
    if claims.expires_at < now_timestamp()
        || claims.audience != state.config.resource_url().as_str()
        || !claims
            .scope
            .split_ascii_whitespace()
            .any(|scope| scope == FULL_SCOPE)
    {
        return oauth_challenge(&state, Some("invalid_token"));
    }
    next.run(request).await
}

fn oauth_challenge(state: &AppState, error: Option<&str>) -> Response {
    let metadata = state
        .config
        .endpoint(".well-known/oauth-protected-resource");
    let mut challenge = format!(
        "Bearer resource_metadata=\"{metadata}\", scope=\"{FULL_SCOPE}\""
    );
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "authentication_required"})),
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).expect("challenge contains validated URLs"),
    );
    response
}

fn oauth_error(status: StatusCode, error: &'static str, description: &'static str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response()
}

fn now_timestamp() -> i64 {
    Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use http_body_util::BodyExt;
    use tower::ServiceExt;


    // ── TokenClient: the HTTP replacement for tap-mcp's removed DB access ──
    //
    // tap-mcp holds no POSTGRES_DATABASE_URL. These cover the contract with the
    // proxy's /internal/mcp endpoints: the service key is presented, a proxy
    // answer of "rejected" is distinguishable from a transport failure, and
    // every transport failure fails CLOSED.

    /// Boot a throwaway "proxy" that replies with `status` + `body` and records
    /// the `X-TAP-Service-Key` it saw. Returns its base URL and that recorder.
    async fn mock_proxy(
        status: axum::http::StatusCode,
        body: &'static str,
    ) -> (Url, Arc<Mutex<Vec<String>>>) {
        use axum::routing::post;
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let handler = move |headers: axum::http::HeaderMap| {
            let recorder = recorder.clone();
            async move {
                let key = headers
                    .get("x-tap-service-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                recorder.lock().unwrap().push(key);
                (status, body)
            }
        };
        let app = Router::new()
            .route("/internal/mcp/token/issue", post(handler.clone()))
            .route("/internal/mcp/token/refresh", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (Url::parse(&format!("http://{addr}/")).unwrap(), seen)
    }

    #[tokio::test]
    async fn token_client_presents_the_service_key_and_reads_the_minted_pair() {
        let (base, seen) = mock_proxy(
            axum::http::StatusCode::OK,
            r#"{"issued":true,"access_token":"at","refresh_token":"rt","expires_in":3600}"#,
        )
        .await;
        let client = TokenClient::new(base, "the-service-key".to_string());

        let minted = client
            .issue_tokens("assertion", "client", "jti", 99)
            .await
            .unwrap()
            .expect("proxy issued a pair");
        assert_eq!(minted.access_token, "at");
        assert_eq!(minted.refresh_token, "rt");
        assert_eq!(minted.expires_in, 3600);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["the-service-key"],
            "the service key must be sent as X-TAP-Service-Key"
        );
    }

    #[tokio::test]
    async fn token_client_reports_a_rejection_as_ok_none_not_an_error() {
        // "rejected" (replayed code / superseded refresh token) is a normal
        // outcome and must stay distinguishable from a transport failure — that
        // distinction is what keeps replay detection meaningful.
        let (base, _) = mock_proxy(
            axum::http::StatusCode::OK,
            r#"{"issued":false,"reason":"code_already_used"}"#,
        )
        .await;
        let client = TokenClient::new(base, "k".to_string());
        assert!(client
            .issue_tokens("a", "c", "j", 1)
            .await
            .unwrap()
            .is_none());

        let (base, _) = mock_proxy(
            axum::http::StatusCode::OK,
            r#"{"issued":false,"reason":"refresh_token_superseded"}"#,
        )
        .await;
        let client = TokenClient::new(base, "k".to_string());
        assert!(client
            .refresh_tokens("rt", "c", None)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn token_client_fails_closed_on_transport_and_protocol_faults() {
        // 401: our key does not match the proxy's.
        let (base, _) = mock_proxy(axum::http::StatusCode::UNAUTHORIZED, "nope").await;
        let client = TokenClient::new(base, "wrong".to_string());
        assert!(matches!(
            client.refresh_tokens("rt", "c", None).await,
            Err(TokenStateError::Status { status: 401, .. })
        ));

        // 404: the proxy has no TAP_MCP_SERVICE_KEY, so the endpoints are off.
        let (base, _) = mock_proxy(axum::http::StatusCode::NOT_FOUND, "nope").await;
        let client = TokenClient::new(base, "k".to_string());
        assert!(matches!(
            client.issue_tokens("a", "c", "j", 1).await,
            Err(TokenStateError::Status { status: 404, .. })
        ));

        // 500: the proxy could not reach its database or could not sign.
        let (base, _) = mock_proxy(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"boom"}"#,
        )
        .await;
        let client = TokenClient::new(base, "k".to_string());
        assert!(client.issue_tokens("a", "c", "j", 1).await.is_err());

        // A 200 whose body lacks `issued` is NOT silently read as success.
        let (base, _) = mock_proxy(axum::http::StatusCode::OK, r#"{"something":"else"}"#).await;
        let client = TokenClient::new(base, "k".to_string());
        assert!(matches!(
            client.issue_tokens("a", "c", "j", 1).await,
            Err(TokenStateError::Malformed(_))
        ));

        // `issued:true` without the tokens is malformed, never a silent success.
        let (base, _) = mock_proxy(axum::http::StatusCode::OK, r#"{"issued":true}"#).await;
        let client = TokenClient::new(base, "k".to_string());
        assert!(matches!(
            client.issue_tokens("a", "c", "j", 1).await,
            Err(TokenStateError::Malformed(_))
        ));

        // Nothing listening at all ⇒ still an error, never a silent success.
        let client = TokenClient::new(Url::parse("http://127.0.0.1:1/").unwrap(), "k".to_string());
        assert!(matches!(
            client.refresh_tokens("rt", "c", None).await,
            Err(TokenStateError::Transport(_))
        ));
    }

    #[test]
    fn token_client_never_renders_the_service_key() {
        let client = TokenClient::new(
            Url::parse("http://127.0.0.1:3100/").unwrap(),
            "super-secret-service-key".to_string(),
        );
        let rendered = format!("{client:?}");
        assert!(
            !rendered.contains("super-secret-service-key"),
            "Debug leaked the service key: {rendered}"
        );
    }

    const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

    fn test_config() -> McpConfig {
        McpConfig::new(
            "http://127.0.0.1:3200",
            TEST_SIGNING_KEY,
            "127.0.0.1:3200",
            true,
        )
        .expect("test config is valid")
    }

    fn production_config() -> McpConfig {
        McpConfig::new_with_dashboard(
            "https://mcp.tap.example",
            Some("https://tap.example/dashboard"),
            TEST_SIGNING_KEY,
            "127.0.0.1:3200",
            false,
        )
        .expect("production test config is valid")
    }

    async fn response_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body is readable");
        serde_json::from_slice(&bytes).expect("response is JSON")
    }

    #[tokio::test]
    async fn unauthenticated_mcp_returns_discoverable_oauth_challenge() {
        let response = build_router(test_config())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("challenge is present")
            .to_str()
            .expect("challenge is text");
        assert!(challenge.contains("/.well-known/oauth-protected-resource"));
        assert!(challenge.contains("tap:full"));
    }

    #[tokio::test]
    async fn metadata_advertises_url_only_dcr_flow() {
        let protected = build_router(test_config())
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert_eq!(protected.status(), StatusCode::OK);
        let protected = response_json(protected).await;
        assert_eq!(protected["resource"], "http://127.0.0.1:3200/mcp");

        let authorization = build_router(test_config())
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        let authorization = response_json(authorization).await;
        assert_eq!(
            authorization["registration_endpoint"],
            "http://127.0.0.1:3200/register"
        );
        assert_eq!(authorization["code_challenge_methods_supported"][0], "S256");
    }

    #[tokio::test]
    async fn dcr_pkce_and_mcp_handshake_work_end_to_end() {
        let router = build_router(test_config());
        let registration = json!({
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        });
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(registration.to_string()))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::CREATED);
        let client_id = response_json(response).await["client_id"]
            .as_str()
            .expect("client id is returned")
            .to_string();

        let challenge = pkce_s256(VERIFIER);
        let authorize_query = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://claude.ai/api/mcp/auth_callback"),
            ("state", "state-123"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", "http://127.0.0.1:3200/mcp"),
            ("scope", FULL_SCOPE),
        ])
        .expect("query serializes");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/authorize?{authorize_query}"))
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("HTML body is readable")
            .to_bytes();
        let html = String::from_utf8(body.to_vec()).expect("HTML is UTF-8");
        let marker = "name=\"request\" value=\"";
        let request_start = html.find(marker).expect("signed request is in form") + marker.len();
        let request_end = html[request_start..]
            .find('"')
            .expect("signed request value terminates")
            + request_start;
        let signed_request = &html[request_start..request_end];

        let consent =
            serde_urlencoded::to_string([("request", signed_request), ("decision", "approve")])
                .expect("form serializes");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/authorize")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(consent))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert!(response.status().is_redirection());
        let redirect = Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .expect("redirect location exists")
                .to_str()
                .expect("redirect location is text"),
        )
        .expect("redirect is a URL");
        let redirect_params: std::collections::HashMap<_, _> =
            redirect.query_pairs().into_owned().collect();
        assert_eq!(redirect_params.get("state"), Some(&"state-123".to_string()));
        let code = redirect_params
            .get("code")
            .expect("authorization code exists");

        let token_form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://claude.ai/api/mcp/auth_callback"),
            ("code_verifier", VERIFIER),
            ("resource", "http://127.0.0.1:3200/mcp"),
        ])
        .expect("token form serializes");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(token_form))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        let access_token = response_json(response).await["access_token"]
            .as_str()
            .expect("access token is returned")
            .to_string();

        // The code is single-use: replaying the identical exchange (same
        // code, same PKCE verifier) must not mint a second token pair.
        let replay_form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://claude.ai/api/mcp/auth_callback"),
            ("code_verifier", VERIFIER),
            ("resource", "http://127.0.0.1:3200/mcp"),
        ])
        .expect("token form serializes");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(replay_form))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "replayed authorization code must be rejected"
        );

        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "tap-mcp-test", "version": "0.1.0"}
            }
        });
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "127.0.0.1:3200")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .body(Body::from(initialize.to_string()))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("MCP response body is readable");
        let body_text = String::from_utf8_lossy(&body);
        assert_eq!(status, StatusCode::OK, "MCP response: {body_text}");
        let initialized: Value =
            serde_json::from_slice(&body).expect("successful MCP response is JSON");
        assert_eq!(initialized["result"]["serverInfo"]["name"], "tap-mcp");
    }

    #[tokio::test]
    async fn tap_dashboard_passkey_assertion_completes_oauth() {
        let config = production_config();
        // The proxy is the sole token issuer, so drive the flow against a mock
        // one that records exactly what tap-mcp asks it to mint.
        let (proxy_base, issue_bodies) = recording_mint_proxy().await;
        let state = AppState::new(config.clone(), None);
        let router = build_router_with_client(
            config,
            Some(TokenClient::new(proxy_base, "service-key".to_string())),
        );
        let registration = json!({
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        });
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(registration.to_string()))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::CREATED);
        let client_id = response_json(response).await["client_id"]
            .as_str()
            .expect("client id is returned")
            .to_string();

        let challenge = pkce_s256(VERIFIER);
        let authorize_query = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://claude.ai/api/mcp/auth_callback"),
            ("state", "tap-state"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("resource", "https://mcp.tap.example/mcp"),
            ("scope", FULL_SCOPE),
        ])
        .expect("query serializes");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/authorize?{authorize_query}"))
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert!(response.status().is_redirection());
        let dashboard_redirect = Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .expect("dashboard redirect exists")
                .to_str()
                .expect("dashboard redirect is text"),
        )
        .expect("dashboard redirect is a URL");
        assert_eq!(dashboard_redirect.host_str(), Some("tap.example"));
        let signed_request = dashboard_redirect
            .query_pairs()
            .find_map(|(key, value)| (key == "mcp_request").then(|| value.into_owned()))
            .expect("dashboard receives the signed request");

        let now = now_timestamp();
        let assertion = state
            .signer
            .sign(
                "tap-authorization-assertion",
                &TapAuthorizationAssertion {
                    request: signed_request,
                    subject: "user-123".to_string(),
                    team_id: "team-456".to_string(),
                    agent_id: "agent-789".to_string(),
                    issued_at: now,
                    expires_at: now + 120,
                },
            )
            .expect("TAP proxy assertion signs");
        let callback_query = serde_urlencoded::to_string([("assertion", assertion.as_str())])
            .expect("callback query serializes");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/authorize/callback?{callback_query}"))
                    .body(Body::empty())
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert!(response.status().is_redirection());
        let claude_redirect = Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .expect("Claude callback exists")
                .to_str()
                .expect("Claude callback is text"),
        )
        .expect("Claude callback is a URL");
        let params: std::collections::HashMap<_, _> =
            claude_redirect.query_pairs().into_owned().collect();
        assert_eq!(params.get("state"), Some(&"tap-state".to_string()));
        let code = params.get("code").expect("authorization code is returned");

        let token_form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://claude.ai/api/mcp/auth_callback"),
            ("code_verifier", VERIFIER),
            ("resource", "https://mcp.tap.example/mcp"),
        ])
        .expect("token form serializes");
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(token_form))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        // The tokens handed to the client are the PROXY's, relayed verbatim.
        assert_eq!(body["access_token"], "proxy-minted-access");
        assert_eq!(body["refresh_token"], "proxy-minted-refresh");

        // And what tap-mcp asked for carries no identity of its own: the
        // proxy-signed assertion is relayed opaquely, and subject/team_id/
        // agent_id/scope are absent — the proxy derives all of them itself.
        let issued = issue_bodies.lock().unwrap().clone();
        assert_eq!(issued.len(), 1, "exactly one mint request");
        let issued = &issued[0];
        assert_eq!(
            issued["assertion"], assertion,
            "the proxy's own assertion must be relayed verbatim"
        );
        assert_eq!(issued["client_id"], client_id);
        assert!(
            issued["code_jti"].as_str().is_some_and(|jti| !jti.is_empty()),
            "the authorization code jti must be sent for single-use consumption"
        );
        for forbidden in ["subject", "team_id", "agent_id", "scope"] {
            assert!(
                issued.get(forbidden).is_none(),
                "tap-mcp must not be able to assert `{forbidden}` — the proxy derives it"
            );
        }
    }

    /// A mock tap-proxy that always mints, recording each `/token/issue` body.
    async fn recording_mint_proxy() -> (Url, Arc<Mutex<Vec<Value>>>) {
        use axum::routing::post;
        let bodies: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = bodies.clone();
        let issue = move |Json(body): Json<Value>| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().unwrap().push(body);
                Json(json!({
                    "issued": true,
                    "access_token": "proxy-minted-access",
                    "refresh_token": "proxy-minted-refresh",
                    "expires_in": 3600,
                }))
            }
        };
        let app = Router::new().route("/internal/mcp/token/issue", post(issue));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (Url::parse(&format!("http://{addr}/")).unwrap(), bodies)
    }

    async fn post_token(router: &Router, form: &[(&str, &str)]) -> Response {
        let form = serde_urlencoded::to_string(form).expect("token form serializes");
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds")
    }

    #[tokio::test]
    async fn refresh_grant_rotates_tokens_and_keeps_bindings() {
        let config = test_config();
        let state = AppState::new(config.clone(), None);
        let router = build_router(config);

        let now = now_timestamp();
        let refresh = state
            .signer
            .sign(
                "refresh-token",
                &RefreshTokenClaims {
                    subject: "user-123".to_string(),
                    team_id: "team-456".to_string(),
                    agent_id: "agent-789".to_string(),
                    client_id: "client-abc".to_string(),
                    audience: "http://127.0.0.1:3200/mcp".to_string(),
                    scope: FULL_SCOPE.to_string(),
                    family_id: String::new(),
                    jti: String::new(),
                    issued_at: now,
                    expires_at: now + REFRESH_TOKEN_LIFETIME_SECONDS,
                },
            )
            .expect("refresh token signs");

        // Wrong client_id must be rejected.
        let response = post_token(
            &router,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", "someone-else"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Correct binding issues a fresh pair; the rotated refresh token keeps
        // the original family expiry and claims.
        let response = post_token(
            &router,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", "client-abc"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let access: AccessTokenClaims = state
            .signer
            .verify("access-token", body["access_token"].as_str().unwrap())
            .expect("access token verifies");
        assert_eq!(access.subject, "user-123");
        assert_eq!(access.agent_id, "agent-789");
        let rotated: RefreshTokenClaims = state
            .signer
            .verify("refresh-token", body["refresh_token"].as_str().unwrap())
            .expect("rotated refresh token verifies");
        assert_eq!(rotated.expires_at, now + REFRESH_TOKEN_LIFETIME_SECONDS);
        assert_eq!(rotated.agent_id, "agent-789");
    }

    /// ChatGPT's connector registers as client_secret_post and probes the
    /// path-suffixed/OIDC metadata aliases — both must work end-to-end.
    #[tokio::test]
    async fn confidential_client_registration_works_like_chatgpt() {
        let config = test_config();
        let state = AppState::new(config.clone(), None);
        let router = build_router(config);

        for path in [
            "/.well-known/oauth-authorization-server/mcp",
            "/.well-known/openid-configuration",
            "/.well-known/openid-configuration/mcp",
        ] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .expect("router responds");
            assert_eq!(response.status(), StatusCode::OK, "metadata alias {path}");
        }

        let registration = json!({
            "client_name": "ChatGPT",
            "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post"
        });
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(registration.to_string()))
                    .expect("request is valid"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response_json(response).await;
        assert_eq!(body["token_endpoint_auth_method"], "client_secret_post");
        let client_id = body["client_id"].as_str().unwrap().to_string();
        let client_secret = body["client_secret"]
            .as_str()
            .expect("confidential client gets a secret")
            .to_string();

        // The secret round-trips on /token; a wrong one is rejected as
        // invalid_client (not silently ignored).
        let now = now_timestamp();
        let refresh = state
            .signer
            .sign(
                "refresh-token",
                &RefreshTokenClaims {
                    subject: "user-1".to_string(),
                    team_id: "team-1".to_string(),
                    agent_id: "mcp-user-1".to_string(),
                    client_id: client_id.clone(),
                    audience: "http://127.0.0.1:3200/mcp".to_string(),
                    scope: FULL_SCOPE.to_string(),
                    family_id: String::new(),
                    jti: String::new(),
                    issued_at: now,
                    expires_at: now + REFRESH_TOKEN_LIFETIME_SECONDS,
                },
            )
            .expect("refresh token signs");
        let response = post_token(
            &router,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "secret accepted");

        let response = post_token(
            &router,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", client_id.as_str()),
                ("client_secret", "forged-secret"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "forged secret rejected");
    }

    #[tokio::test]
    async fn expired_refresh_token_is_rejected() {
        let config = test_config();
        let state = AppState::new(config.clone(), None);
        let router = build_router(config);

        let now = now_timestamp();
        let refresh = state
            .signer
            .sign(
                "refresh-token",
                &RefreshTokenClaims {
                    subject: "user-123".to_string(),
                    team_id: "team-456".to_string(),
                    agent_id: "agent-789".to_string(),
                    client_id: "client-abc".to_string(),
                    audience: "http://127.0.0.1:3200/mcp".to_string(),
                    scope: FULL_SCOPE.to_string(),
                    family_id: String::new(),
                    jti: String::new(),
                    issued_at: now - REFRESH_TOKEN_LIFETIME_SECONDS - 10,
                    expires_at: now - 10,
                },
            )
            .expect("refresh token signs");
        let response = post_token(
            &router,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", "client-abc"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await["error"], "invalid_grant");
    }

    #[test]
    fn discovery_summary_describes_relative_and_auto_approved_targets() {
        let raw = json!({
            "services": {
                "telegram-personal": {
                    "description": "Personal Telegram",
                    "target_shape": "relative_path",
                    "target_placeholder": "<relative path like /resource?limit=10>",
                    "approval": { "rules": [
                        {"target": "*", "methods": ["GET", "HEAD"], "decision": "proceeds_immediately"},
                        {"target": "*", "methods": ["POST"], "decision": "pauses_for_human"}
                    ]}
                },
                "github": {
                    "description": "GitHub API",
                    "target_shape": "full_url",
                    "target_placeholder": "https://api.github.com/<path>",
                    "approval": { "rules": [
                        {"target": "/search/", "methods": "ANY", "decision": "proceeds_immediately", "priority": "url_override"},
                        {"target": "*", "methods": ["POST"], "decision": "pauses_for_human"}
                    ]}
                },
                "eth-signer": {
                    "description": "Ethereum signing key",
                    "signing": {"endpoint": "POST /sign"}
                }
            }
        })
        .to_string();
        let summary: Value =
            serde_json::from_str(&summarize_discovery(&raw)).expect("summary is JSON");
        let credentials = summary["credentials"].as_array().expect("credential list");

        let telegram = credentials
            .iter()
            .find(|c| c["name"] == "telegram-personal")
            .expect("telegram listed");
        let target = telegram["target"].as_str().unwrap();
        assert!(target.contains("path starting with '/'"), "got: {target}");
        assert!(!target.contains("full upstream URL"), "got: {target}");

        let github = credentials
            .iter()
            .find(|c| c["name"] == "github")
            .expect("github listed");
        assert!(github["target"].as_str().unwrap().contains("api.github.com"));
        assert_eq!(github["auto_approved_url_patterns"][0], "/search/");

        let signer = credentials
            .iter()
            .find(|c| c["name"] == "eth-signer")
            .expect("signer listed");
        assert!(signer["not_callable"].as_str().is_some());
    }

    #[test]
    fn discovery_summary_passes_through_empty_state_guidance() {
        let raw = json!({
            "services": {},
            "agent_action": "No credentials are assigned yet.",
            "dashboard_url": "https://tap.example/dashboard"
        })
        .to_string();
        let summary: Value =
            serde_json::from_str(&summarize_discovery(&raw)).expect("summary is JSON");
        assert!(summary["credentials"].as_array().unwrap().is_empty());
        assert_eq!(summary["agent_action"], "No credentials are assigned yet.");
        assert_eq!(summary["dashboard_url"], "https://tap.example/dashboard");
    }

    #[test]
    fn forward_response_shaping_separates_tap_errors_from_upstream() {
        // Upstream JSON success: body is real JSON, not an escaped string.
        let shaped: Value = serde_json::from_str(&shape_forward_response(
            200,
            Some("application/json; charset=utf-8"),
            r#"{"login":"octocat"}"#,
        ))
        .expect("shaped output is JSON");
        assert_eq!(shaped["upstream_status"], 200);
        assert_eq!(shaped["body"]["login"], "octocat");

        // Upstream 404 is labeled as upstream, not as a TAP failure.
        let shaped: Value = serde_json::from_str(&shape_forward_response(
            404,
            Some("application/json"),
            r#"{"message":"Not Found"}"#,
        ))
        .expect("shaped output is JSON");
        assert_eq!(shaped["upstream_status"], 404);
        assert!(shaped["note"].as_str().unwrap().contains("upstream API"));
        assert!(shaped.get("tap_error").is_none());

        // TAP's own rejection carries agent-directed markers → hint, no mirror.
        let shaped: Value = serde_json::from_str(&shape_forward_response(
            403,
            Some("application/json"),
            r#"{"error":"host not allowed","error_code":"host_not_allowed"}"#,
        ))
        .expect("shaped output is JSON");
        assert!(shaped.get("upstream_status").is_none());
        assert_eq!(shaped["tap_error"]["error_code"], "host_not_allowed");
        assert!(shaped["hint"].as_str().unwrap().contains("tap_discover"));

        // Missing credential enrichment surfaces the setup link.
        let shaped: Value = serde_json::from_str(&shape_forward_response(
            403,
            Some("application/json"),
            r#"{"error":"unknown credential","error_code":"unknown_credential","credential_link_url":"https://tap.example/dashboard?prefill"}"#,
        ))
        .expect("shaped output is JSON");
        assert_eq!(
            shaped["credential_link_url"],
            "https://tap.example/dashboard?prefill"
        );
        assert!(shaped["hint"].as_str().unwrap().contains("credential_link_url"));

        // Non-JSON body stays a raw string with its content type.
        let shaped: Value = serde_json::from_str(&shape_forward_response(
            200,
            Some("text/html"),
            "<html>hi</html>",
        ))
        .expect("shaped output is JSON");
        assert_eq!(shaped["content_type"], "text/html");
        assert_eq!(shaped["body"], "<html>hi</html>");

        // The allowed_hosts 403 has no error_code — its "fix" field must still
        // mark it as TAP's rejection, not an upstream error.
        let shaped: Value = serde_json::from_str(&shape_forward_response(
            403,
            Some("application/json"),
            r#"{"error":"host_not_allowed","message":"Credential 'github' may not be sent to host 'evil.example'.","credential":"github","host":"evil.example","fix":"add the host to allowed_hosts"}"#,
        ))
        .expect("shaped output is JSON");
        assert_eq!(shaped["tap_error"]["error"], "host_not_allowed");
        assert!(shaped["hint"].as_str().unwrap().contains("TAP refused"));

        // Inline OAuth reauth errors point the user at reauth_url.
        let shaped: Value = serde_json::from_str(&shape_forward_response(
            502,
            Some("application/json"),
            r#"{"error":"Google token refresh failed","reauth_url":"https://tap.example/dashboard#/credentials","retry_after_reauth":true}"#,
        ))
        .expect("shaped output is JSON");
        assert!(shaped["hint"].as_str().unwrap().contains("reauth_url"));

        // A bare {"error": "…"} could be TAP's generic rejection (rate limit,
        // SSRF guard, routing) or the upstream's — the note must not claim it
        // came from the upstream.
        let shaped: Value = serde_json::from_str(&shape_forward_response(
            429,
            Some("application/json"),
            r#"{"error":"rate limit exceeded"}"#,
        ))
        .expect("shaped output is JSON");
        assert_eq!(shaped["upstream_status"], 429);
        assert!(shaped["note"].as_str().unwrap().contains("may come from TAP"));
    }

    #[test]
    fn approved_result_shaping_extracts_upstream_response() {
        let value = json!({
            "txn_id": "txn-1",
            "status": "forwarded",
            "response": {
                "status": 201,
                "headers": [["Content-Type", "application/json"], ["X-Noise", "yes"]],
                "body": r#"{"id": 42}"#,
                "body_encoding": "utf-8",
                "complete": true
            }
        });
        let shaped: Value =
            serde_json::from_str(&shape_approved_result(&value)).expect("shaped output is JSON");
        assert_eq!(shaped["approval"], "approved_and_forwarded");
        assert_eq!(shaped["upstream_status"], 201);
        assert_eq!(shaped["content_type"], "application/json");
        assert_eq!(shaped["body"]["id"], 42);
        assert!(shaped.get("headers").is_none());
    }
}
