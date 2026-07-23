//! HTTP client that forwards requests to target URLs.

use std::net::IpAddr;
use std::time::Duration;
use tap_core::error::AgentSecError;
use tap_core::http_client::{configure_client, ClientRoute};
use url::Url;

/// Sent when the agent supplies no `User-Agent`. Some upstreams (GitHub,
/// Cloudflare-protected APIs) reject requests without one, which otherwise
/// surfaces as a confusing 403 the agent tends to loop on. An agent that needs
/// a specific UA can still set its own — this only fills the gap.
const DEFAULT_USER_AGENT: &str = "TAP-Proxy/1.0 (+https://tap.human.tech)";

/// Secure-by-default SSRF guard toggle. The guard (see `validate_public_target`)
/// is ON unless `DANGEROUS_TAP_ALLOW_PRIVATE_TARGETS` is a truthy value. Production never
/// sets it; the test harness does (it forwards to 127.0.0.1 mock upstreams).
fn private_targets_allowed() -> bool {
    std::env::var("DANGEROUS_TAP_ALLOW_PRIVATE_TARGETS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// True when `ip` is in a range an agent-supplied target must never reach:
/// loopback, IPv4 link-local (`169.254.0.0/16`, which includes the cloud
/// metadata endpoint `169.254.169.254`), RFC1918 private, CGNAT/shared
/// (`100.64.0.0/10`), unspecified, broadcast, multicast, documentation, and the
/// IPv6 equivalents (loopback, unspecified, multicast, ULA `fc00::/7`,
/// link-local `fe80::/10`, plus IPv4-mapped forms).
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // CGNAT / shared address space 100.64.0.0/10
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal_ip(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (first & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Global SSRF guard for an **agent-supplied** target URL. Rejects any target
/// whose host is — or resolves to — an internal/loopback/cloud-metadata address.
///
/// This is independent of (and complements) per-credential `allowed_hosts`: it
/// applies even to a credential-less forward, and it is a *denylist* of internal
/// ranges, not an allowlist. Callers run it only on the agent-controlled target
/// (`X-TAP-Target`), never on operator-configured sidecar `api_base` values, and
/// skip it for `relative_target` credentials (whose target is a path, not a
/// host). For a domain target it resolves the name and refuses if **any**
/// resolved address is internal (best-effort anti-rebinding; the connect may
/// re-resolve, but this blocks the literal-internal and split-horizon cases).
pub async fn validate_public_target(target_url: &str) -> Result<(), AgentSecError> {
    if private_targets_allowed() {
        return Ok(());
    }
    let url = Url::parse(target_url).map_err(|_| {
        AgentSecError::Upstream(format!(
            "X-TAP-Target '{target_url}' is not a valid absolute URL"
        ))
    })?;
    let host = url
        .host()
        .ok_or_else(|| AgentSecError::Upstream(format!("X-TAP-Target '{target_url}' has no host")))?;
    match host {
        url::Host::Ipv4(ip) if is_internal_ip(IpAddr::V4(ip)) => Err(blocked_target(target_url, ip)),
        url::Host::Ipv6(ip) if is_internal_ip(IpAddr::V6(ip)) => Err(blocked_target(target_url, ip)),
        url::Host::Domain(domain) => {
            let port = url.port_or_known_default().unwrap_or(443);
            let addrs = tokio::net::lookup_host((domain, port)).await.map_err(|e| {
                AgentSecError::Upstream(format!(
                    "X-TAP-Target host '{domain}' could not be resolved: {e}"
                ))
            })?;
            let mut resolved_any = false;
            for addr in addrs {
                resolved_any = true;
                if is_internal_ip(addr.ip()) {
                    return Err(blocked_target(target_url, addr.ip()));
                }
            }
            if !resolved_any {
                return Err(AgentSecError::Upstream(format!(
                    "X-TAP-Target host '{domain}' resolved to no addresses"
                )));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn blocked_target(target_url: &str, ip: impl std::fmt::Display) -> AgentSecError {
    AgentSecError::Upstream(format!(
        "X-TAP-Target '{target_url}' resolves to internal address {ip}; \
         forwarding to loopback, link-local, private, or cloud-metadata ranges is not allowed"
    ))
}

/// Result of forwarding a request to the target.
#[derive(Debug)]
pub struct ForwardResult {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Maximum response body size (10MB).
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

fn client_route_for_target(target_url: &str) -> ClientRoute {
    let Ok(url) = Url::parse(target_url) else {
        return ClientRoute::EgressProxy;
    };

    let Some(host) = url.host_str() else {
        return ClientRoute::EgressProxy;
    };

    if host.eq_ignore_ascii_case("localhost") || !host.contains('.') {
        return ClientRoute::Direct;
    }

    match url.host() {
        Some(url::Host::Ipv4(ip)) => {
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() {
                return ClientRoute::Direct;
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if ip.is_loopback() || ip.is_unspecified() {
                return ClientRoute::Direct;
            }
        }
        Some(url::Host::Domain(_)) | None => {}
    }

    ClientRoute::EgressProxy
}

/// Forward a request to the target URL.
pub async fn forward_request(
    target_url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<ForwardResult, AgentSecError> {
    // Disable automatic redirects — reqwest's default policy strips the
    // Authorization header on cross-origin redirects, which breaks Google APIs
    // that redirect between subdomains (e.g. www.googleapis.com → calendar.googleapis.com).
    // The proxy returns the redirect response as-is; the agent can retry if needed.
    let route = client_route_for_target(target_url);
    let client = configure_client(
        reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none()),
        route,
    )
    .and_then(|builder| builder.build())
    .map_err(|e| AgentSecError::Internal(format!("Failed to create HTTP client: {e}")))?;

    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return Err(AgentSecError::Upstream(format!(
            "X-TAP-Target '{target_url}' is not a valid URL — must start with https:// or http://. \
             Relative paths like '/path' are only valid for sidecar credentials with relative_target enabled. \
             See GET /agent/services for the correct request template for this credential."
        )));
    }

    let reqwest_method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|e| AgentSecError::Internal(format!("Invalid HTTP method: {e}")))?;

    let mut req = client.request(reqwest_method, target_url);

    // Add headers (skip host and content-length, let reqwest handle those)
    for (name, value) in headers {
        let lower = name.to_lowercase();
        if lower == "host" || lower == "content-length" || lower == "transfer-encoding" {
            continue;
        }
        req = req.header(name.as_str(), value.as_str());
    }

    // Fill in a default User-Agent only when the agent didn't send one.
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
    {
        req = req.header("User-Agent", DEFAULT_USER_AGENT);
    }

    if let Some(body_bytes) = body {
        req = req.body(body_bytes.to_vec());
    }

    let response = req.send().await.map_err(|e| {
        if e.is_timeout() {
            AgentSecError::Upstream(format!("Request timed out: {e}"))
        } else if e.is_connect() {
            AgentSecError::Upstream(format!("Connection failed: {e}"))
        } else {
            AgentSecError::Upstream(format!("Request failed: {e}"))
        }
    })?;

    let status = response.status().as_u16();

    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();

    // Read body with size check
    let body = response
        .bytes()
        .await
        .map_err(|e| AgentSecError::Upstream(format!("Failed to read response body: {e}")))?;

    if body.len() > MAX_RESPONSE_SIZE {
        tracing::warn!(
            size = body.len(),
            "Response body exceeds {MAX_RESPONSE_SIZE} bytes, sanitization will be skipped"
        );
    }

    Ok(ForwardResult {
        status,
        headers: resp_headers,
        body: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::net::TcpListener;

    #[test]
    fn is_internal_ip_flags_private_loopback_metadata() {
        // Internal / disallowed.
        for ip in [
            "127.0.0.1",
            "169.254.169.254", // cloud metadata
            "10.1.2.3",
            "192.168.0.1",
            "172.16.5.5",
            "100.64.0.1", // CGNAT
            "0.0.0.0",
        ] {
            assert!(
                is_internal_ip(ip.parse::<Ipv4Addr>().unwrap().into()),
                "{ip} should be internal"
            );
        }
        for ip in ["::1", "fe80::1", "fc00::1", "fd12::3"] {
            assert!(
                is_internal_ip(ip.parse::<Ipv6Addr>().unwrap().into()),
                "{ip} should be internal"
            );
        }
        // IPv4-mapped loopback must also be caught.
        assert!(is_internal_ip("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap().into()));

        // Public — allowed.
        for ip in ["8.8.8.8", "1.1.1.1", "93.184.216.34"] {
            assert!(
                !is_internal_ip(ip.parse::<Ipv4Addr>().unwrap().into()),
                "{ip} should be public"
            );
        }
        assert!(!is_internal_ip("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().into()));
    }

    #[tokio::test]
    async fn validate_public_target_blocks_internal_and_allows_public() {
        // Ensure the guard is active for this test (serial lib tests).
        std::env::remove_var("DANGEROUS_TAP_ALLOW_PRIVATE_TARGETS");

        // Internal IP literals and loopback names are rejected.
        for t in [
            "http://169.254.169.254/metadata/instance",
            "http://127.0.0.1:8080/x",
            "http://localhost:3100/admin",
            "http://[::1]:9000/",
            "http://10.0.0.5/",
        ] {
            assert!(
                validate_public_target(t).await.is_err(),
                "{t} should be blocked"
            );
        }

        // A public IP literal passes.
        assert!(validate_public_target("https://1.1.1.1/").await.is_ok());

        // Non-absolute / schemeless targets fail closed.
        assert!(validate_public_target("/relative/path").await.is_err());

        // The opt-out re-enables internal targets (used by the test harness).
        std::env::set_var("DANGEROUS_TAP_ALLOW_PRIVATE_TARGETS", "1");
        assert!(validate_public_target("http://127.0.0.1:8080/x").await.is_ok());
        std::env::remove_var("DANGEROUS_TAP_ALLOW_PRIVATE_TARGETS");
    }

    async fn start_mock_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");

        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        (url, handle)
    }

    #[tokio::test]
    async fn successful_forward() {
        let app = Router::new().route("/test", get(|| async { "hello" }));
        let (url, _handle) = start_mock_server(app).await;

        let result = forward_request(
            &format!("{url}/test"),
            "GET",
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, b"hello");
    }

    #[tokio::test]
    async fn forward_timeout() {
        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                "done"
            }),
        );
        let (url, _handle) = start_mock_server(app).await;

        let result = forward_request(
            &format!("{url}/slow"),
            "GET",
            &[],
            None,
            Duration::from_secs(1),
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timed out") || err.contains("timeout"));
    }

    #[tokio::test]
    async fn forward_response_too_large() {
        let app = Router::new().route(
            "/large",
            get(|| async {
                // Return 11MB body
                vec![b'A'; 11 * 1024 * 1024]
            }),
        );
        let (url, _handle) = start_mock_server(app).await;

        let result = forward_request(
            &format!("{url}/large"),
            "GET",
            &[],
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        // Response is returned (not rejected) but it's larger than the cap
        assert_eq!(result.status, 200);
        assert!(result.body.len() > MAX_RESPONSE_SIZE);
    }

    #[tokio::test]
    async fn forward_preserves_response_headers() {
        let app = Router::new().route(
            "/headers",
            get(|| async {
                (
                    [("Content-Type", "application/json"), ("X-Custom", "value")],
                    "{}",
                )
            }),
        );
        let (url, _handle) = start_mock_server(app).await;

        let result = forward_request(
            &format!("{url}/headers"),
            "GET",
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert!(result
            .headers
            .iter()
            .any(|(n, v)| n == "content-type" && v.contains("application/json")));
        assert!(result
            .headers
            .iter()
            .any(|(n, v)| n == "x-custom" && v == "value"));
    }

    #[test]
    fn internal_targets_bypass_egress_proxy() {
        assert_eq!(
            client_route_for_target("http://127.0.0.1:8082/health"),
            ClientRoute::Direct
        );
        assert_eq!(
            client_route_for_target("http://localhost:8082/health"),
            ClientRoute::Direct
        );
        assert_eq!(
            client_route_for_target("http://telegram-client:8082/dialogs?limit=10"),
            ClientRoute::Direct
        );
        assert_eq!(
            client_route_for_target("http://172.31.0.10:8082/health"),
            ClientRoute::Direct
        );
    }

    #[test]
    fn public_targets_use_egress_proxy() {
        assert_eq!(
            client_route_for_target("https://api.telegram.org/botabc/sendMessage"),
            ClientRoute::EgressProxy
        );
        assert_eq!(
            client_route_for_target("https://api.mercury.com/accounts"),
            ClientRoute::EgressProxy
        );
    }
}
