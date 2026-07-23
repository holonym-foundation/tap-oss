//! Policy evaluation: auto-approve, require approval, rate limiting.

use tap_core::config::{ApprovalMode, PolicyConfig};
use tap_core::error::AgentSecError;
use tap_core::types::HttpMethod;

/// Machine-readable reason for a `PolicyDecision`, for audit-log visibility.
/// Distinct from the boolean `requires_approval`/`auto_approved` fields: this
/// says *which rule* produced the decision, not just what it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyReason {
    /// Team posture is Autonomous and the credential has no explicit policy.
    TeamAutonomousDefault,
    /// Team posture is Gated, no explicit policy, method is GET/HEAD.
    TeamGatedDefaultSafeMethod,
    /// Team posture is Gated, no explicit policy, method is not GET/HEAD.
    TeamGatedDefaultUnsafeMethod,
    /// Matched an `auto_approve_urls` pattern.
    AutoApproveUrl,
    /// Matched a `require_approval_urls` pattern.
    RequireApprovalUrl,
    /// Matched the credential's `auto_approve` method list.
    AutoApproveMethod,
    /// Matched the credential's `require_approval` method list.
    RequireApprovalMethod,
    /// Method absent from both lists — fails closed to requiring approval.
    RequireApprovalDefault,
}

impl PolicyReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TeamAutonomousDefault => "team_autonomous_default",
            Self::TeamGatedDefaultSafeMethod => "team_gated_default_safe_method",
            Self::TeamGatedDefaultUnsafeMethod => "team_gated_default_unsafe_method",
            Self::AutoApproveUrl => "auto_approve_url",
            Self::RequireApprovalUrl => "require_approval_url",
            Self::AutoApproveMethod => "auto_approve_method",
            Self::RequireApprovalMethod => "require_approval_method",
            Self::RequireApprovalDefault => "require_approval_default",
        }
    }
}

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub requires_approval: bool,
    pub auto_approved: bool,
    pub reason: PolicyReason,
}

/// Evaluate whether a request requires human approval based on policy.
///
/// Convenience wrapper assuming the **safe** default posture (`Gated`):
/// credentials with no explicit policy gate writes. Production forward paths
/// should call [`evaluate_policy_with_default`] with the team's posture. Any
/// caller without team context that lands here fails *safe* (over-gates, never
/// under-gates), so this is the correct default.
pub fn evaluate_policy(
    method: &HttpMethod,
    policy: Option<&PolicyConfig>,
    target_url: Option<&str>,
) -> PolicyDecision {
    evaluate_policy_with_default(method, policy, target_url, ApprovalMode::Gated)
}

/// Evaluate policy. `team_default` governs the **no-explicit-policy** case only;
/// an explicit per-credential policy always takes precedence over it.
/// `target_url` is checked against `auto_approve_urls` for URL-pattern overrides.
pub fn evaluate_policy_with_default(
    method: &HttpMethod,
    policy: Option<&PolicyConfig>,
    target_url: Option<&str>,
    team_default: ApprovalMode,
) -> PolicyDecision {
    let policy = match policy {
        Some(p) => p,
        None => {
            // No explicit policy: fall back to the team's default posture.
            //   Autonomous -> auto-approve everything. The team opted into
            //     unattended agents; credential isolation + allowed_hosts +
            //     SSRF guard still apply, and any credential can override with
            //     its own policy.
            //   Gated -> auto-approve safe reads (GET/HEAD), require approval
            //     for writes. The safe default; every existing/unset team gets
            //     this, so it matches TAP's historical behavior exactly.
            match team_default {
                ApprovalMode::Autonomous => {
                    return PolicyDecision {
                        requires_approval: false,
                        auto_approved: true,
                        reason: PolicyReason::TeamAutonomousDefault,
                    };
                }
                ApprovalMode::Gated => {
                    let method_str = method_to_string(method);
                    let safe = method_str == "GET" || method_str == "HEAD";
                    return PolicyDecision {
                        requires_approval: !safe,
                        auto_approved: safe,
                        reason: if safe {
                            PolicyReason::TeamGatedDefaultSafeMethod
                        } else {
                            PolicyReason::TeamGatedDefaultUnsafeMethod
                        },
                    };
                }
            }
        }
    };

    // Check URL-pattern require rules first. They are the safety override for
    // broader auto URL patterns, e.g. auto-approve branch creation at
    // /git/refs while still gating /git/refs/heads/... deletes/force-updates.
    if let Some(url) = target_url {
        if policy
            .require_approval_urls
            .iter()
            .any(|pattern| url_matches_policy_pattern(url, pattern))
        {
            return PolicyDecision {
                requires_approval: true,
                auto_approved: false,
                reason: PolicyReason::RequireApprovalUrl,
            };
        }
    }

    // Check URL-pattern auto overrides next (takes priority over method rules).
    if let Some(url) = target_url {
        if policy
            .auto_approve_urls
            .iter()
            .any(|pattern| url_matches_policy_pattern(url, pattern))
        {
            return PolicyDecision {
                requires_approval: false,
                auto_approved: true,
                reason: PolicyReason::AutoApproveUrl,
            };
        }
    }

    let method_str = method_to_string(method);

    // HEAD follows GET policy (both are read-only)
    let check_method = if method_str == "HEAD" {
        "GET".to_string()
    } else {
        method_str.clone()
    };

    // Check auto-approve list
    if policy
        .auto_approve
        .iter()
        .any(|m| m.to_uppercase() == check_method)
    {
        return PolicyDecision {
            requires_approval: false,
            auto_approved: true,
            reason: PolicyReason::AutoApproveMethod,
        };
    }

    // Check require-approval list
    if policy
        .require_approval
        .iter()
        .any(|m| m.to_uppercase() == check_method)
    {
        return PolicyDecision {
            requires_approval: true,
            auto_approved: false,
            reason: PolicyReason::RequireApprovalMethod,
        };
    }

    // Method not in either list — default to require approval (fail closed)
    PolicyDecision {
        requires_approval: true,
        auto_approved: false,
        reason: PolicyReason::RequireApprovalDefault,
    }
}

/// Structurally match an `auto_approve_urls` pattern against a target URL.
///
/// Historically this was a raw substring test (`url.contains(pattern)`), which
/// let an attacker smuggle the pattern into the query string or a different host
/// (e.g. pattern `/v1/search` matched `https://evil.com/?x=/v1/search`, or
/// `api.github.com` matched anywhere in the URL) and thereby auto-approve a
/// write or exfiltration. We now parse the URL and anchor the match:
///
/// - A pattern starting with `/` is **path-anchored**: it matches the URL path
///   prefix only (query and fragment are ignored entirely).
/// - Any other pattern is **host-anchored**: the part before the first `/` must
///   exactly match the host, and the remaining path must match the path prefix.
/// - A `*` segment in the path pattern matches exactly one non-empty path
///   segment. Host wildcards are intentionally unsupported.
///
/// In both cases the match must end on a path boundary (`/`) or consume the
/// whole haystack, so `api.github.com` does not match `api.github.com.evil.com`
/// and `/v1/search` does not match `/v1/searchx`. Unparseable targets never
/// auto-approve (fail closed). Host comparison is case-insensitive; path
/// matching stays case-sensitive.
/// Does a time-boxed grant (#49) cover this request? The method must be in
/// the grant's method list (case-insensitive) AND the URL must match one of
/// its `route_scope` patterns — the same structural matcher as
/// `auto_approve_urls`, so a grant can never be broader than what a permanent
/// rule could express. Pure; liveness (expiry/uses/revocation) is checked by
/// the store's atomic claim, not here.
///
/// Unlike `auto_approve_urls`, a grant is matched **exact-path anchored**, not
/// prefix-anchored (F2): a grant scoped to `api.example.com/v1/messages` covers
/// only that exact path (`*` still matches one segment), NOT
/// `api.example.com/v1/messages/{id}/send`. A grant is a narrow, temporary
/// exception minted from a reviewed request — it must never auto-approve a
/// deeper subpath the approver never saw. Host-only patterns (no path) are
/// rejected outright, since they would cover every path on the host. Standing
/// `auto_approve_urls` rules keep the broader prefix semantics.
pub fn grant_covers(methods: &[String], route_scope: &[String], method: &str, url: &str) -> bool {
    methods.iter().any(|m| m.eq_ignore_ascii_case(method))
        && route_scope
            .iter()
            .any(|pattern| grant_scope_covers_url(url, pattern))
}

/// Exact-path grant matcher (F2). Mirrors the host/path anchoring of
/// `url_matches_policy_pattern`, but the path must match on **every** segment
/// (equal segment count) rather than as a prefix, and a host-only pattern never
/// matches (it would cover every path). Path-only (`/`-prefixed) patterns are
/// still matched for backward compatibility with directly-seeded grant rows;
/// the create endpoint rejects authoring them (`admin::validate_grant_request`).
fn grant_scope_covers_url(url: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let host = parsed.host_str().unwrap_or("");
    let path = parsed.path();

    if pattern.starts_with('/') {
        return path_segments_match(path, pattern, true);
    }

    let Some((host_pattern, path_pattern)) = pattern.split_once('/') else {
        // Host-only pattern would auto-approve EVERY path on the host — an
        // approver who reviewed one request never authorized that. Fail closed.
        return false;
    };

    if host_pattern.is_empty() || host_pattern.contains('*') {
        return false;
    }

    host.eq_ignore_ascii_case(host_pattern)
        && path_segments_match(path, &format!("/{path_pattern}"), true)
}

/// Derive the narrowest useful grant scope from a concrete target URL:
/// `host/path` (host-pinned path prefix), or just `host` when the path is `/`.
/// This is what approve-with-grant uses — the pattern is computed from the
/// request the human just reviewed, never typed. Shared with the Telegram and
/// Matrix grant surfaces via `tap_core::grants` (tap-bot cannot depend on
/// tap-proxy); re-exported here so proxy callers and tests keep one name.
///
/// Note (F2): a root-path target still derives a host-only pattern here, but
/// `grant_scope_covers_url` never matches a host-only pattern and
/// `admin::validate_grant_request` rejects authoring one — so such a scope
/// cannot silently auto-approve every path on the host.
pub use tap_core::grants::scope_from_target as grant_scope_from_target;

fn url_matches_policy_pattern(url: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let host = parsed.host_str().unwrap_or("");
    let path = parsed.path();

    if pattern.starts_with('/') {
        return path_prefix_matches(path, pattern);
    }

    let Some((host_pattern, path_pattern)) = pattern.split_once('/') else {
        return !pattern.contains('*') && host.eq_ignore_ascii_case(pattern);
    };

    if host_pattern.is_empty() || host_pattern.contains('*') {
        return false;
    }

    host.eq_ignore_ascii_case(host_pattern)
        && path_prefix_matches(path, &format!("/{path_pattern}"))
}

fn path_prefix_matches(path: &str, pattern: &str) -> bool {
    path_segments_match(path, pattern, false)
}

/// Segment-wise path matcher. With `exact = false` the pattern is a **prefix**
/// (used by `auto_approve_urls`); with `exact = true` the pattern must match the
/// whole path (equal segment count — used by time-boxed grants, F2). In both
/// modes a `*` segment matches exactly one non-empty segment.
fn path_segments_match(path: &str, pattern: &str, exact: bool) -> bool {
    if !pattern.starts_with('/') {
        return false;
    }

    let path = trim_trailing_slash(path);
    let pattern = trim_trailing_slash(pattern);
    let path_segments: Vec<&str> = path.split('/').collect();
    let pattern_segments: Vec<&str> = pattern.split('/').collect();

    if exact {
        if pattern_segments.len() != path_segments.len() {
            return false;
        }
    } else if pattern_segments.len() > path_segments.len() {
        return false;
    }

    pattern_segments
        .iter()
        .zip(path_segments.iter())
        .all(|(pattern_segment, path_segment)| {
            if *pattern_segment == "*" {
                !path_segment.is_empty()
            } else {
                pattern_segment == path_segment
            }
        })
}

fn trim_trailing_slash(value: &str) -> &str {
    if value.len() > 1 {
        value.trim_end_matches('/')
    } else {
        value
    }
}

fn method_to_string(method: &HttpMethod) -> String {
    match method {
        HttpMethod::Get => "GET".to_string(),
        HttpMethod::Post => "POST".to_string(),
        HttpMethod::Put => "PUT".to_string(),
        HttpMethod::Delete => "DELETE".to_string(),
        HttpMethod::Patch => "PATCH".to_string(),
        HttpMethod::Head => "HEAD".to_string(),
        HttpMethod::Options => "OPTIONS".to_string(),
    }
}

/// Check rate limit for an agent.
pub fn check_rate_limit(request_count: u64, limit_per_hour: u64) -> Result<(), AgentSecError> {
    if request_count >= limit_per_hour {
        return Err(AgentSecError::RateLimited(format!(
            "Rate limit exceeded: {request_count}/{limit_per_hour} requests in the last hour"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_scope_from_target_pins_host_and_path() {
        assert_eq!(
            grant_scope_from_target("https://api.example.com/v1/messages?x=1#frag"),
            Some("api.example.com/v1/messages".to_string()),
            "query and fragment must be dropped"
        );
        // Root path → host-only pattern. Note (F2): such a pattern is never
        // *covering* (grant_scope_covers_url rejects host-only) and cannot be
        // authored via the create endpoint — this asserts derivation only.
        assert_eq!(
            grant_scope_from_target("https://api.example.com/"),
            Some("api.example.com".to_string())
        );
        // The derived scope must actually cover the original request…
        let scope = grant_scope_from_target("http://127.0.0.1:8080/test").unwrap();
        assert!(grant_covers(
            &["POST".to_string()],
            std::slice::from_ref(&scope),
            "POST",
            "http://127.0.0.1:8080/test"
        ));
        // …and not a different host with the same path.
        assert!(!grant_covers(
            &["POST".to_string()],
            &[scope],
            "POST",
            "http://evil.example.com/test"
        ));
    }

    #[test]
    fn grant_scope_from_target_fails_closed() {
        assert_eq!(grant_scope_from_target("not a url"), None);
        assert_eq!(grant_scope_from_target("file:///etc/passwd"), None);
        // Dotless hosts can't be expressed as a concrete grant pattern.
        assert_eq!(grant_scope_from_target("http://localhost/api"), None);
    }

    fn test_policy() -> PolicyConfig {
        PolicyConfig {
            auto_approve: vec!["GET".to_string()],
            require_approval: vec!["POST".to_string(), "PUT".to_string(), "DELETE".to_string()],
            auto_approve_urls: vec![],
            require_approval_urls: vec![],
            approval: None,
        }
    }

    #[test]
    fn get_request_auto_approved() {
        let policy = test_policy();
        let decision = evaluate_policy(&HttpMethod::Get, Some(&policy), None);
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);
        assert_eq!(decision.reason, PolicyReason::AutoApproveMethod);
    }

    #[test]
    fn post_request_requires_approval() {
        let policy = test_policy();
        let decision = evaluate_policy(&HttpMethod::Post, Some(&policy), None);
        assert!(decision.requires_approval);
        assert!(!decision.auto_approved);
        assert_eq!(decision.reason, PolicyReason::RequireApprovalMethod);
    }

    #[test]
    fn reason_reflects_url_pattern_match() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/v1/search".to_string()];
        let decision = evaluate_policy(
            &HttpMethod::Post,
            Some(&policy),
            Some("https://api.notion.com/v1/search"),
        );
        assert_eq!(decision.reason, PolicyReason::AutoApproveUrl);
    }

    #[test]
    fn reason_reflects_team_default_posture() {
        let autonomous =
            evaluate_policy_with_default(&HttpMethod::Post, None, None, ApprovalMode::Autonomous);
        assert_eq!(autonomous.reason, PolicyReason::TeamAutonomousDefault);

        let gated_get =
            evaluate_policy_with_default(&HttpMethod::Get, None, None, ApprovalMode::Gated);
        assert_eq!(gated_get.reason, PolicyReason::TeamGatedDefaultSafeMethod);

        let gated_post =
            evaluate_policy_with_default(&HttpMethod::Post, None, None, ApprovalMode::Gated);
        assert_eq!(
            gated_post.reason,
            PolicyReason::TeamGatedDefaultUnsafeMethod
        );
    }

    #[test]
    fn delete_request_requires_approval() {
        let policy = test_policy();
        let decision = evaluate_policy(&HttpMethod::Delete, Some(&policy), None);
        assert!(decision.requires_approval);
        assert!(!decision.auto_approved);
    }

    #[test]
    fn head_request_auto_approved() {
        let policy = test_policy();
        let decision = evaluate_policy(&HttpMethod::Head, Some(&policy), None);
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);
    }

    #[test]
    fn url_pattern_overrides_method_policy() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/v1/search".to_string()];

        // POST normally requires approval
        let decision = evaluate_policy(
            &HttpMethod::Post,
            Some(&policy),
            Some("https://api.notion.com/v1/search"),
        );
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);

        // POST to a different URL still requires approval
        let decision = evaluate_policy(
            &HttpMethod::Post,
            Some(&policy),
            Some("https://api.notion.com/v1/pages"),
        );
        assert!(decision.requires_approval);
    }

    #[test]
    fn auto_approve_url_pattern_not_smuggled_via_query_string() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/v1/search".to_string()];
        // Pattern appears only in the query string of a write to a different path.
        let decision = evaluate_policy(
            &HttpMethod::Post,
            Some(&policy),
            Some("https://api.notion.com/v1/pages?ref=/v1/search"),
        );
        assert!(
            decision.requires_approval,
            "query-string smuggling must not auto-approve"
        );
    }

    #[test]
    fn auto_approve_url_pattern_not_smuggled_via_foreign_host() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["api.notion.com/v1/search".to_string()];
        // Host-anchored pattern must not match when it appears in the path of
        // an attacker host.
        let decision = evaluate_policy(
            &HttpMethod::Post,
            Some(&policy),
            Some("https://evil.com/api.notion.com/v1/search"),
        );
        assert!(decision.requires_approval);
    }

    #[test]
    fn auto_approve_host_pattern_respects_dot_boundary() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["api.notion.com".to_string()];
        // Exact host (and subpaths) auto-approve…
        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.notion.com/v1/search")
            )
            .auto_approved
        );
        // …but a look-alike suffix host does not.
        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.notion.com.evil.com/v1/search")
            )
            .requires_approval
        );
    }

    #[test]
    fn auto_approve_path_pattern_respects_segment_boundary() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/v1/search".to_string()];
        // Sub-path matches.
        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.notion.com/v1/search/results")
            )
            .auto_approved
        );
        // A longer first segment does not.
        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.notion.com/v1/searchx")
            )
            .requires_approval
        );
    }

    #[test]
    fn auto_approve_path_pattern_is_prefix_not_substring() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/git/refs".to_string()];

        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.github.com/git/refs")
            )
            .auto_approved
        );
        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.github.com/repos/owner/repo/git/refs")
            )
            .requires_approval,
            "path patterns are anchored prefixes, not arbitrary path substrings"
        );
    }

    #[test]
    fn auto_approve_path_pattern_supports_star_segments() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/repos/*/*/git/refs".to_string()];

        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.github.com/repos/owner/repo/git/refs")
            )
            .auto_approved
        );
        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.github.com/repos/owner/repo/git/refs/heads/main")
            )
            .auto_approved
        );
        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.github.com/repos/owner/git/refs")
            )
            .requires_approval,
            "each star consumes exactly one path segment"
        );
    }

    #[test]
    fn auto_approve_host_path_pattern_supports_star_path_segments() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["api.github.com/repos/*/*/git/refs".to_string()];

        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.github.com/repos/owner/repo/git/refs")
            )
            .auto_approved
        );
        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://uploads.github.com/repos/owner/repo/git/refs")
            )
            .requires_approval,
            "host must match exactly when present in the pattern"
        );
    }

    #[test]
    fn auto_approve_host_wildcards_are_not_supported() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["*.github.com/repos/*/*/git/refs".to_string()];

        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.github.com/repos/owner/repo/git/refs")
            )
            .requires_approval
        );
    }

    #[test]
    fn auto_approve_partial_segment_star_is_literal() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/repos/*/*/git/ref*".to_string()];

        assert!(
            evaluate_policy(
                &HttpMethod::Post,
                Some(&policy),
                Some("https://api.github.com/repos/owner/repo/git/refs")
            )
            .requires_approval,
            "only a full '*' segment is a wildcard"
        );
    }

    #[test]
    fn require_url_overrides_broader_auto_url() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["api.github.com/repos/*/*/git/refs".to_string()];
        policy.require_approval_urls = vec!["api.github.com/repos/*/*/git/refs/heads".to_string()];

        let create = evaluate_policy(
            &HttpMethod::Post,
            Some(&policy),
            Some("https://api.github.com/repos/owner/repo/git/refs"),
        );
        assert!(create.auto_approved);
        assert_eq!(create.reason, PolicyReason::AutoApproveUrl);

        let delete = evaluate_policy(
            &HttpMethod::Delete,
            Some(&policy),
            Some("https://api.github.com/repos/owner/repo/git/refs/heads/main"),
        );
        assert!(delete.requires_approval);
        assert_eq!(delete.reason, PolicyReason::RequireApprovalUrl);
    }

    #[test]
    fn auto_approve_unparseable_target_fails_closed() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/v1/search".to_string()];
        let decision = evaluate_policy(&HttpMethod::Post, Some(&policy), Some("not a url"));
        assert!(decision.requires_approval);
    }

    #[test]
    fn rate_limit_under_threshold() {
        let result = check_rate_limit(5, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn rate_limit_exceeded() {
        let result = check_rate_limit(101, 100);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Rate limit exceeded"));
    }

    #[test]
    fn no_policy_auto_approves_get() {
        let decision = evaluate_policy(&HttpMethod::Get, None, None);
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);
    }

    #[test]
    fn no_policy_auto_approves_head() {
        let decision = evaluate_policy(&HttpMethod::Head, None, None);
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);
    }

    #[test]
    fn no_policy_requires_approval_for_post() {
        let decision = evaluate_policy(&HttpMethod::Post, None, None);
        assert!(decision.requires_approval);
        assert!(!decision.auto_approved);
    }

    #[test]
    fn no_policy_requires_approval_for_delete() {
        let decision = evaluate_policy(&HttpMethod::Delete, None, None);
        assert!(decision.requires_approval);
        assert!(!decision.auto_approved);
    }

    // --- team default approval posture (no explicit policy) ---

    #[test]
    fn autonomous_no_policy_auto_approves_post() {
        let d =
            evaluate_policy_with_default(&HttpMethod::Post, None, None, ApprovalMode::Autonomous);
        assert!(d.auto_approved);
        assert!(!d.requires_approval);
    }

    #[test]
    fn autonomous_no_policy_auto_approves_delete() {
        let d =
            evaluate_policy_with_default(&HttpMethod::Delete, None, None, ApprovalMode::Autonomous);
        assert!(d.auto_approved);
        assert!(!d.requires_approval);
    }

    #[test]
    fn gated_no_policy_still_gates_post() {
        // Regression guard: explicit Gated == TAP's historical default.
        let d = evaluate_policy_with_default(&HttpMethod::Post, None, None, ApprovalMode::Gated);
        assert!(d.requires_approval);
        assert!(!d.auto_approved);
    }

    #[test]
    fn gated_no_policy_auto_approves_get() {
        let d = evaluate_policy_with_default(&HttpMethod::Get, None, None, ApprovalMode::Gated);
        assert!(d.auto_approved);
        assert!(!d.requires_approval);
    }

    #[test]
    fn explicit_policy_overrides_autonomous_posture() {
        // A credential whose explicit policy requires approval for POST must NOT
        // be auto-approved just because the team is autonomous.
        let policy = test_policy(); // POST is in require_approval
        let d = evaluate_policy_with_default(
            &HttpMethod::Post,
            Some(&policy),
            None,
            ApprovalMode::Autonomous,
        );
        assert!(
            d.requires_approval,
            "explicit per-credential policy must win over team posture"
        );
        assert!(!d.auto_approved);
    }

    // --- Time-boxed grant scope matching (#49, F2: exact-path anchoring) ---

    #[test]
    fn grant_covers_exact_path_only() {
        let methods = vec!["POST".to_string()];
        let scope = vec!["api.example.com/v1/messages".to_string()];

        // The exact reviewed path is covered.
        assert!(grant_covers(
            &methods,
            &scope,
            "POST",
            "https://api.example.com/v1/messages"
        ));
        // Trailing slash is normalized, still covered.
        assert!(grant_covers(
            &methods,
            &scope,
            "POST",
            "https://api.example.com/v1/messages/"
        ));
    }

    #[test]
    fn grant_does_not_cover_deeper_subpath() {
        // F2: a derived/authored grant for `.../messages` must NOT auto-approve
        // `.../messages/{id}/send` — a deeper path the approver never reviewed.
        let methods = vec!["POST".to_string()];
        let scope = vec!["api.example.com/v1/messages".to_string()];
        assert!(
            !grant_covers(
                &methods,
                &scope,
                "POST",
                "https://api.example.com/v1/messages/abc123/send"
            ),
            "grant on /v1/messages must not cover /v1/messages/{{id}}/send"
        );

        // Same guarantee for the path-only pattern form.
        let path_scope = vec!["/v1/messages".to_string()];
        assert!(!grant_covers(
            &methods,
            &path_scope,
            "POST",
            "https://api.example.com/v1/messages/abc123/send"
        ));
    }

    #[test]
    fn grant_host_only_pattern_covers_nothing() {
        // A host-only scope would otherwise cover EVERY path on the host (F2).
        let methods = vec!["POST".to_string()];
        let scope = vec!["api.example.com".to_string()];
        assert!(!grant_covers(
            &methods,
            &scope,
            "POST",
            "https://api.example.com/anything"
        ));
        assert!(!grant_covers(&methods, &scope, "POST", "https://api.example.com/"));
    }

    #[test]
    fn grant_wildcard_segment_still_matches_one_segment() {
        // `*` matching (one segment) is preserved under exact-path anchoring.
        let methods = vec!["POST".to_string()];
        let scope = vec!["api.example.com/v1/*/send".to_string()];
        assert!(grant_covers(
            &methods,
            &scope,
            "POST",
            "https://api.example.com/v1/abc123/send"
        ));
        // But not a deeper path beyond the wildcard segment.
        assert!(!grant_covers(
            &methods,
            &scope,
            "POST",
            "https://api.example.com/v1/abc123/send/now"
        ));
    }
}
