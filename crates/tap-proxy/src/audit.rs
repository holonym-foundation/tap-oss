//! JSON lines audit log writer.

use std::io::Write;
use std::path::PathBuf;
use tap_core::types::AuditEntry;

/// Trait for audit logging backends.
pub trait AuditLog: Send + Sync {
    fn write_entry(&self, entry: &AuditEntry);
    /// Read recent entries for a specific agent. Returns up to `limit` entries, newest first.
    fn read_entries(&self, agent_id: &str, limit: usize) -> Vec<AuditEntry>;
}

/// File-based audit logger — appends JSON lines.
pub struct AuditLogger {
    path: PathBuf,
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Write an audit entry as a JSON line. Returns any IO error.
    pub fn write_entry_result(&self, entry: &AuditEntry) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(entry).map_err(std::io::Error::other)?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        writeln!(file, "{json}")?;
        Ok(())
    }
}

impl AuditLog for AuditLogger {
    fn write_entry(&self, entry: &AuditEntry) {
        if let Err(e) = self.write_entry_result(entry) {
            tracing::error!(error = %e, "Failed to write audit log entry");
        }
    }

    fn read_entries(&self, agent_id: &str, limit: usize) -> Vec<AuditEntry> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut entries: Vec<AuditEntry> = content
            .lines()
            .rev()
            .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
            .filter(|e| e.agent_id == agent_id)
            .take(limit)
            .collect();
        entries.reverse(); // chronological order
        entries
    }
}

/// Database-backed audit logger — persists entries to SQLite/Turso via ConfigStore.
/// Survives enclave redeployments when backed by Turso.
pub struct DbAuditLogger {
    store: tap_core::store::ConfigStore,
    handle: tokio::runtime::Handle,
}

impl DbAuditLogger {
    pub fn new(store: tap_core::store::ConfigStore, handle: tokio::runtime::Handle) -> Self {
        Self { store, handle }
    }
}

impl AuditLog for DbAuditLogger {
    fn write_entry(&self, entry: &AuditEntry) {
        let store = self.store.clone();
        let entry = entry.clone();
        self.handle.spawn(async move {
            if let Err(e) = store.write_audit_entry(&entry).await {
                tracing::error!(error = %e, "Failed to write audit entry to DB");
            }
        });
    }

    fn read_entries(&self, agent_id: &str, limit: usize) -> Vec<AuditEntry> {
        let store = self.store.clone();
        let agent_id = agent_id.to_string();
        // Block on the async call — this is called from async context via axum handlers,
        // but the trait is sync. Use spawn + block to avoid nested runtime panic.
        let handle = self.handle.clone();
        std::thread::scope(|s| {
            s.spawn(move || {
                handle.block_on(async {
                    store
                        .read_audit_entries(&agent_id, limit)
                        .await
                        .unwrap_or_else(|e| {
                            tracing::error!(error = %e, "Failed to read audit entries from DB");
                            vec![]
                        })
                })
            })
            .join()
            .unwrap_or_default()
        })
    }
}

/// In-memory audit logger for testing.
#[derive(Default)]
pub struct InMemoryAuditLogger {
    pub entries: std::sync::Mutex<Vec<AuditEntry>>,
}

impl InMemoryAuditLogger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().unwrap().clone()
    }
}

impl AuditLog for InMemoryAuditLogger {
    fn write_entry(&self, entry: &AuditEntry) {
        self.entries.lock().unwrap().push(entry.clone());
    }

    fn read_entries(&self, agent_id: &str, limit: usize) -> Vec<AuditEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .rev()
            .filter(|e| e.agent_id == agent_id)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tap_core::types::{ApprovalStatus, HttpMethod};
    use uuid::Uuid;

    fn test_entry() -> AuditEntry {
        AuditEntry {
            request_id: Uuid::new_v4(),
            agent_id: "openclaw".to_string(),
            credential_names: vec!["twitter-holonym".to_string()],
            target_url: "https://api.twitter.com/2/tweets".to_string(),
            method: HttpMethod::Post,
            approval_status: Some(ApprovalStatus::Approved),
            upstream_status: Some(200),
            total_latency_ms: 142,
            approval_latency_ms: Some(50),
            upstream_latency_ms: Some(80),
            response_sanitized: false,
            end_user_id: None,
            request_headers: vec![("X-TAP-Credential".to_string(), "twitter-holonym".to_string())],
            request_body: None,
            request_body_truncated: false,
            policy_reason: Some("require_approval_method".to_string()),
            require_passkey: false,
            approver_identity: Some("a@b.com".to_string()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn write_audit_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(path.clone());

        let entry = test_entry();
        logger.write_entry_result(&entry).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: AuditEntry = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.agent_id, "openclaw");
        assert_eq!(parsed.request_id, entry.request_id);
    }

    #[test]
    fn audit_entry_has_required_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(path.clone());

        let entry = test_entry();
        logger.write_entry_result(&entry).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert!(value.get("request_id").is_some());
        assert!(value.get("agent_id").is_some());
        assert!(value.get("credential_names").is_some());
        assert!(value.get("target_url").is_some());
        assert!(value.get("method").is_some());
        assert!(value.get("timestamp").is_some());
        assert!(value.get("total_latency_ms").is_some());
    }

    #[test]
    fn multiple_entries_are_separate_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(path.clone());

        for _ in 0..3 {
            logger.write_entry_result(&test_entry()).unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 3);

        for line in &lines {
            let _: AuditEntry = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn trait_object_works() {
        let logger: Box<dyn AuditLog> = Box::new(InMemoryAuditLogger::new());
        logger.write_entry(&test_entry());
    }
}
