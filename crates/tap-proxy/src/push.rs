//! Web Push notification delivery for the dashboard approval channel.
//!
//! The `PushSender` trait is the seam the `DashboardChannel` depends on; the
//! concrete VAPID/web-push implementation and the `/push/*` subscription
//! endpoints are layered on top. Delivery is always best-effort: the durable
//! `pending_approvals` row is the source of truth, so a failed push never fails
//! an approval — it only means the approver isn't proactively nudged.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, warn};
use web_push::{ContentEncoding, SubscriptionInfo, VapidSignatureBuilder, WebPushMessageBuilder};

use tap_core::error::AgentSecError;
use tap_core::store::{ConfigStore, PushSubscriptionRow};

/// Outcome of a single push send, distinguishing a permanently-gone subscription
/// (prune it) from a transient failure (keep it, just log).
enum DeliveryError {
    /// The push service reported the subscription is gone (404/410) — prune.
    Gone,
    /// Anything else (build error, transport error, 5xx) — transient, keep.
    Failed(String),
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliveryError::Gone => f.write_str("subscription gone"),
            DeliveryError::Failed(s) => write!(f, "{s}"),
        }
    }
}

/// Sends a "you have a pending approval" push to a team's subscribed browsers.
#[async_trait]
pub trait PushSender: Send + Sync {
    /// Notify every push subscription registered for `team_id`. `txn_id` lets the
    /// service worker deep-link to the specific request; `summary` is the human
    /// one-liner shown in the notification (method + target + credential).
    async fn notify_team(
        &self,
        team_id: &str,
        txn_id: &str,
        summary: &str,
    ) -> Result<(), AgentSecError>;
}

/// Env var holding the VAPID private key (base64url, no padding — the raw EC
/// P-256 private scalar, as produced by `web-push generate-vapid-keys` or
/// `openssl`). Absent ⇒ web push disabled (the channel falls back to the
/// pull-based inbox).
const ENV_VAPID_PRIVATE: &str = "TAP_VAPID_PRIVATE_KEY";
/// Env var holding the matching VAPID public key (base64url), served to the
/// browser so it can create a subscription bound to our key pair.
const ENV_VAPID_PUBLIC: &str = "TAP_VAPID_PUBLIC_KEY";
/// VAPID `sub` claim — a contact URI (`mailto:` or `https:`) per RFC 8292.
const ENV_VAPID_SUBJECT: &str = "TAP_VAPID_SUBJECT";

const DEFAULT_VAPID_SUBJECT: &str = "mailto:approvals@tap.human.tech";

/// Concrete Web Push delivery. Builds the encrypted, VAPID-signed message with
/// the `web-push` crate and ships it over the shared `reqwest` client — so we
/// avoid the crate's bundled isahc/libcurl client and its hyper-version pin.
pub struct WebPushSender {
    store: Arc<ConfigStore>,
    http: reqwest::Client,
    vapid_private_key: String,
    vapid_subject: String,
}

impl WebPushSender {
    /// Construct from env. Returns `None` when no VAPID private key is set, which
    /// is the signal to run the dashboard channel inbox-only (no proactive push).
    pub fn from_env(store: Arc<ConfigStore>) -> Option<Self> {
        let vapid_private_key = std::env::var(ENV_VAPID_PRIVATE)
            .ok()
            .filter(|s| !s.is_empty())?;
        let vapid_subject = std::env::var(ENV_VAPID_SUBJECT)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_VAPID_SUBJECT.to_string());
        Some(Self {
            store,
            http: reqwest::Client::new(),
            vapid_private_key,
            vapid_subject,
        })
    }

    /// The public key the browser needs to subscribe. `None` ⇒ push disabled.
    pub fn public_key_from_env() -> Option<String> {
        std::env::var(ENV_VAPID_PUBLIC)
            .ok()
            .filter(|s| !s.is_empty())
    }

    /// Encrypt, sign, and POST a single notification. Returns the `WebPushError`
    /// so the caller can prune subscriptions the push service has retired.
    async fn send_one(
        &self,
        sub: &PushSubscriptionRow,
        payload: &[u8],
    ) -> Result<(), DeliveryError> {
        let info = SubscriptionInfo::new(&sub.endpoint, &sub.p256dh, &sub.auth);

        let mut sig_builder = VapidSignatureBuilder::from_base64(&self.vapid_private_key, &info)
            .map_err(|e| DeliveryError::Failed(format!("vapid key: {e}")))?;
        sig_builder.add_claim("sub", self.vapid_subject.as_str());
        let signature = sig_builder
            .build()
            .map_err(|e| DeliveryError::Failed(format!("vapid sign: {e}")))?;

        let mut msg_builder = WebPushMessageBuilder::new(&info);
        msg_builder.set_payload(ContentEncoding::Aes128Gcm, payload);
        msg_builder.set_vapid_signature(signature);
        let message = msg_builder
            .build()
            .map_err(|e| DeliveryError::Failed(format!("encrypt: {e}")))?;

        // Replicate web_push::request_builder::build_request over reqwest so we
        // don't depend on the crate's HTTP client. The crypto_headers carry the
        // VAPID Authorization and the encryption key material.
        let endpoint = message.endpoint.to_string();
        let mut req = self
            .http
            .post(&endpoint)
            .header("TTL", message.ttl.to_string());
        if let Some(urgency) = message.urgency {
            req = req.header("Urgency", urgency.to_string());
        }
        if let Some(topic) = message.topic {
            req = req.header("Topic", topic);
        }
        let req = if let Some(payload) = message.payload {
            let mut r = req
                .header("Content-Encoding", payload.content_encoding.to_str())
                .header("Content-Type", "application/octet-stream");
            for (k, v) in payload.crypto_headers {
                r = r.header(k, v);
            }
            r.body(payload.content)
        } else {
            req
        };

        let resp = req
            .send()
            .await
            .map_err(|e| DeliveryError::Failed(format!("transport: {e}")))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        // 404/410 mean the subscription is permanently gone — signal a prune.
        if status.as_u16() == 404 || status.as_u16() == 410 {
            return Err(DeliveryError::Gone);
        }
        Err(DeliveryError::Failed(format!(
            "push service status {status}"
        )))
    }
}

#[async_trait]
impl PushSender for WebPushSender {
    async fn notify_team(
        &self,
        team_id: &str,
        txn_id: &str,
        summary: &str,
    ) -> Result<(), AgentSecError> {
        let subs = self.store.list_push_subscriptions_for_team(team_id).await?;
        if subs.is_empty() {
            return Ok(());
        }
        // The service worker reads this JSON to render the notification and to
        // deep-link the click straight to the pending request in the inbox.
        let payload = serde_json::json!({
            "title": "Approval needed",
            "body": summary,
            "txn_id": txn_id,
            "url": "/#/approvals",
        })
        .to_string();
        let payload_bytes = payload.into_bytes();

        for sub in &subs {
            match self.send_one(sub, &payload_bytes).await {
                Ok(()) => debug!(team_id, endpoint = %sub.endpoint, "Push delivered"),
                Err(DeliveryError::Gone) => {
                    // Subscription retired by the push service — prune it so we
                    // stop trying. Best-effort; ignore delete errors.
                    if let Err(e) = self.store.delete_push_subscription(&sub.endpoint).await {
                        warn!(endpoint = %sub.endpoint, error = %e, "Failed to prune dead push subscription");
                    } else {
                        debug!(endpoint = %sub.endpoint, "Pruned retired push subscription");
                    }
                }
                Err(e) => warn!(endpoint = %sub.endpoint, error = %e, "Push delivery failed"),
            }
        }
        Ok(())
    }
}
