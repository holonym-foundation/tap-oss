//! `tap logs`: tail and display audit log entries.

use tap_core::types::AuditEntry;

/// Parse a JSON line into an AuditEntry.
pub fn parse_log_line(line: &str) -> Result<AuditEntry, serde_json::Error> {
    serde_json::from_str(line)
}

/// Format an audit entry for terminal display.
pub fn format_entry(entry: &AuditEntry) -> String {
    let status_indicator = match &entry.approval_status {
        Some(tap_core::types::ApprovalStatus::Approved) => "APPROVED",
        Some(tap_core::types::ApprovalStatus::Denied) => "DENIED",
        Some(tap_core::types::ApprovalStatus::Timeout) => "TIMEOUT",
        Some(tap_core::types::ApprovalStatus::Pending) => "PENDING",
        None => "AUTO",
    };

    let sanitized_indicator = if entry.response_sanitized {
        " [SANITIZED]"
    } else {
        ""
    };

    let mut suffix = String::new();
    if let Some(ref reason) = entry.policy_reason {
        suffix.push_str(&format!(" [policy: {reason}]"));
    }
    if entry.require_passkey {
        suffix.push_str(" [passkey]");
    }
    if let Some(ref approver) = entry.approver_identity {
        suffix.push_str(&format!(" [approved by: {approver}]"));
    }

    format!(
        "[{}] {} {:?} {} → {} ({}ms){}{}",
        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
        entry.agent_id,
        entry.method,
        entry.target_url,
        status_indicator,
        entry.total_latency_ms,
        sanitized_indicator,
        suffix,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tap_core::types::*;
    use uuid::Uuid;

    fn test_entry() -> AuditEntry {
        AuditEntry {
            request_id: Uuid::new_v4(),
            agent_id: "openclaw".to_string(),
            credential_names: vec!["twitter".to_string()],
            target_url: "https://api.twitter.com/2/tweets".to_string(),
            method: HttpMethod::Post,
            approval_status: Some(ApprovalStatus::Approved),
            upstream_status: Some(200),
            total_latency_ms: 142,
            approval_latency_ms: Some(50),
            upstream_latency_ms: Some(80),
            response_sanitized: false,
            end_user_id: None,
            request_headers: vec![("X-TAP-Credential".to_string(), "twitter".to_string())],
            request_body: Some("{\"text\":\"hello\"}".to_string()),
            request_body_truncated: false,
            policy_reason: Some("require_approval_method".to_string()),
            require_passkey: false,
            approver_identity: Some("a@b.com".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn parse_audit_log_entry() {
        let entry = test_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed = parse_log_line(&json).unwrap();
        assert_eq!(parsed.agent_id, "openclaw");
        assert_eq!(parsed.method, HttpMethod::Post);
    }

    #[test]
    fn parse_malformed_log_line() {
        let result = parse_log_line("this is not json");
        assert!(result.is_err());
    }

    #[test]
    fn format_log_entry_for_display() {
        let entry = test_entry();
        let formatted = format_entry(&entry);
        assert!(formatted.contains("openclaw"));
        assert!(formatted.contains("Post"));
        assert!(formatted.contains("api.twitter.com"));
        assert!(formatted.contains("142ms"));
    }

    #[test]
    fn format_log_entry_with_denial() {
        let mut entry = test_entry();
        entry.approval_status = Some(ApprovalStatus::Denied);
        let formatted = format_entry(&entry);
        assert!(formatted.contains("DENIED"));
    }

    #[test]
    fn format_log_entry_with_sanitization() {
        let mut entry = test_entry();
        entry.response_sanitized = true;
        let formatted = format_entry(&entry);
        assert!(formatted.contains("SANITIZED"));
    }
}
