//! Fire-and-forget PostHog event capture for TAP product analytics.
//!
//! Enabled by setting POSTHOG_PROJECT_KEY in the environment. No-op if unset.
//! All captures are spawned as background tasks — analytics never block the
//! request path.

use sha2::{Digest, Sha256};

/// Compute a stable, non-reversible agent identifier: sha256(key)[..16].
pub fn agent_distinct_id(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// Spawn a fire-and-forget PostHog capture. Returns immediately; the HTTP
/// POST runs in a background task. Silently skips if POSTHOG_PROJECT_KEY is
/// not set.
pub fn capture(event: &str, distinct_id: &str, mut properties: serde_json::Value) {
    let Ok(project_key) = std::env::var("POSTHOG_PROJECT_KEY") else {
        return;
    };
    let event = event.to_string();
    let distinct_id = distinct_id.to_string();
    if let Some(obj) = properties.as_object_mut() {
        obj.insert(
            "product".to_string(),
            serde_json::Value::String("tap".to_string()),
        );
    }
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let _ = client
            .post("https://eu.i.posthog.com/capture/")
            .json(&serde_json::json!({
                "api_key": project_key,
                "event": event,
                "distinct_id": distinct_id,
                "properties": properties,
            }))
            .send()
            .await;
    });
}
