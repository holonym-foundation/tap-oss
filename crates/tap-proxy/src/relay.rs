//! Telegram egress-relay feature flags, per-user identity derivation, and the
//! chisel authfile projection.
//!
//! The relay lets a personal Telegram (MTProto) session egress through the user's
//! own reverse-SOCKS relay so Telegram sees the user's IP, not the enclave's,
//! while the auth key never leaves the enclave. Feature-flagged via env so it is
//! fully inert unless an operator opts a credential in (merge-safe: absent env =>
//! off). See `docs/telegram-local-relay-design.md` and issue #91.
//!
//! ## Multi-user isolation
//! Every session gets its **own** chisel credential and its **own** reverse-SOCKS
//! port, both derived deterministically from the session key:
//! - `relay_user`  = a `:`-free id (hash of the session key).
//! - `relay_pass`  = HMAC(TAP_RELAY_SIGNING_SECRET, session_key) — reproducible
//!   only by the enclave, and disclosed only to the credential's owner via an
//!   authenticated `/relay/heartbeat`.
//! - `socks_port`  = a deterministic port in `[PORT_BASE, PORT_BASE+PORT_SPAN)`.
//!
//! The chisel server runs with `--authfile`, projected from the live sessions, so
//! each credential is **pinned to its own port** (`^R:127.0.0.1:<port>$`). A user
//! who tries to bind another user's port is denied by chisel, and cannot forge
//! another user's password without the signing secret. Combined with the
//! forward-path injecting `X-Relay-Socks: 127.0.0.1:<socks_port(session_key)>`,
//! a Telegram session can only ever egress through *its own* relay.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tap_core::config::{ConnectorType, CredentialConfig};

type HmacSha256 = Hmac<Sha256>;

/// Reverse-SOCKS port range. 40k ports comfortably covers per-session assignment.
const PORT_BASE: u16 = 20001;
const PORT_SPAN: u32 = 40000;

/// Master switch: the egress relay is active when `TAP_ENABLE_RELAY_SERVER=1`
/// (the same flag that spawns the chisel server). Off by default (inert).
pub fn server_enabled() -> bool {
    std::env::var("TAP_ENABLE_RELAY_SERVER").unwrap_or_default() == "1"
}

/// Whether a credential is a **Telegram** credential, detected by *type*, not name:
/// a sidecar whose `api_base` targets the Telegram protocol-translating sidecar
/// (`telegram-client`). Works for any name the user chose (`telegram`, `tg`,
/// `my-tg`, `eu:{ext}/whatever`) and for end-user credentials alike. The stored
/// `api_base` is the canonical `telegram-client:8082` regardless of the enclave's
/// embedded-base rewrite, so this is stable.
pub fn is_telegram_credential(cfg: &CredentialConfig) -> bool {
    matches!(cfg.connector, ConnectorType::Sidecar)
        && cfg
            .api_base
            .as_deref()
            .is_some_and(|b| b.contains("telegram-client"))
}

/// Whether this credential must egress through a per-user reverse-SOCKS relay:
/// the relay is enabled AND the credential is a Telegram credential (by type).
/// This replaces the old name-list gate — a Telegram session egresses through the
/// user's own IP whatever the credential is named.
pub fn credential_uses_relay(cfg: &CredentialConfig) -> bool {
    server_enabled() && is_telegram_credential(cfg)
}

/// Lease TTL: how long a relay is considered live after its last heartbeat
/// (`TAP_RELAY_TTL_SECS`, default 45).
pub fn ttl_secs() -> i64 {
    std::env::var("TAP_RELAY_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(45)
}

/// Interval the relay client should heartbeat at (ttl / 3, floored at 5s) so a
/// missed beat or two doesn't drop a healthy relay.
pub fn heartbeat_secs() -> u64 {
    (ttl_secs().max(15) / 3).max(5) as u64
}

/// Path to the chisel authfile the proxy projects from live sessions
/// (`TAP_RELAY_AUTHFILE`, default `/data/relay-authfile.json`).
pub fn authfile_path() -> String {
    std::env::var("TAP_RELAY_AUTHFILE").unwrap_or_else(|_| "/data/relay-authfile.json".to_string())
}

/// The HMAC signing secret used to derive per-session relay passwords. Required
/// when the relay is active; absence fails closed (no password can be minted).
fn signing_secret() -> Result<Vec<u8>, String> {
    let s = std::env::var("TAP_RELAY_SIGNING_SECRET").map_err(|_| {
        "TAP_RELAY_SIGNING_SECRET is required to derive per-user relay credentials".to_string()
    })?;
    if s.len() < 16 {
        return Err("TAP_RELAY_SIGNING_SECRET must be at least 16 chars".to_string());
    }
    Ok(s.into_bytes())
}

/// `:`-free relay username derived from the session key (chisel authfile keys are
/// `user:pass`, so the username must not contain a colon).
pub fn relay_user(session_key: &str) -> String {
    let h = Sha256::digest(format!("relay-user:{session_key}").as_bytes());
    format!("u{}", hex::encode(&h[..8]))
}

/// Per-session reverse-SOCKS port, deterministic in `[PORT_BASE, PORT_BASE+PORT_SPAN)`.
/// NOTE: deterministic ⇒ two session keys can (rarely) collide on a port; that is
/// an availability wrinkle, not a security one, and a follow-up can move to
/// DB-assigned ports. Isolation does not depend on port unguessability — chisel
/// pins each credential to its port.
pub fn socks_port(session_key: &str) -> u16 {
    let h = Sha256::digest(format!("relay-port:{session_key}").as_bytes());
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    PORT_BASE + (n % PORT_SPAN) as u16
}

/// Per-session relay password = HMAC(secret, session_key), hex. Only the enclave
/// (holding the secret) can reproduce it, and it is disclosed only to the
/// credential owner through an authenticated `/relay/heartbeat`.
pub fn relay_pass(session_key: &str) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(&signing_secret()?)
        .map_err(|e| format!("relay hmac init: {e}"))?;
    mac.update(session_key.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// The full relay identity for a session: `(user, pass, socks_port)`.
pub fn relay_identity(session_key: &str) -> Result<(String, String, u16), String> {
    Ok((
        relay_user(session_key),
        relay_pass(session_key)?,
        socks_port(session_key),
    ))
}

/// Render the chisel authfile as a projection of the given live session keys:
/// `{ "<user>:<pass>": ["^R:127.0.0.1:<port>$"] }`. Each credential is pinned to
/// its own port, so no relay can bind another user's port.
pub fn render_authfile(session_keys: &[String]) -> Result<String, String> {
    let mut map = serde_json::Map::new();
    for sk in session_keys {
        let (user, pass, port) = relay_identity(sk)?;
        map.insert(
            format!("{user}:{pass}"),
            serde_json::json!([format!("^R:127.0.0.1:{port}$")]),
        );
    }
    serde_json::to_string(&serde_json::Value::Object(map)).map_err(|e| e.to_string())
}

/// Atomically write the authfile projection to `authfile_path()` (temp + rename),
/// so chisel (which watches the file) never reads a partial write.
pub fn write_authfile(session_keys: &[String]) -> Result<(), String> {
    let path = authfile_path();
    let content = render_authfile(session_keys)?;
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, content).map_err(|e| format!("write authfile {tmp}: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename authfile -> {path}: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(api_base: Option<&str>, connector: ConnectorType) -> CredentialConfig {
        CredentialConfig {
            description: String::new(),
            api_base: api_base.map(str::to_string),
            substitution: Default::default(),
            connector,
            relative_target: true,
            auth_header_format: None,
            auth_bindings: vec![],
            end_user_id: None,
            allowed_hosts: vec![],
        }
    }

    // Mutates process env; the tap-proxy lib unit tests run serial
    // (--test-threads=1) per the test docs, so this is safe.
    #[test]
    fn relay_triggers_on_telegram_type_not_name() {
        let telegram = cfg(Some("http://telegram-client:8082"), ConnectorType::Sidecar);
        let notion = cfg(Some("https://api.notion.com"), ConnectorType::Sidecar);
        let direct_tg = cfg(Some("http://telegram-client:8082"), ConnectorType::Direct);
        // Detected by TYPE (sidecar → telegram-client), independent of the name.
        assert!(is_telegram_credential(&telegram));
        assert!(!is_telegram_credential(&notion));
        assert!(!is_telegram_credential(&direct_tg)); // must be a sidecar

        std::env::set_var("TAP_ENABLE_RELAY_SERVER", "1");
        assert!(credential_uses_relay(&telegram));
        assert!(!credential_uses_relay(&notion));
        std::env::set_var("TAP_ENABLE_RELAY_SERVER", "0");
        assert!(!credential_uses_relay(&telegram)); // master switch off => inert
        std::env::remove_var("TAP_ENABLE_RELAY_SERVER");
    }

    #[test]
    fn per_user_identity_is_isolated_and_deterministic() {
        std::env::set_var("TAP_RELAY_SIGNING_SECRET", "test-secret-at-least-16-chars");
        let a = "team1:telegram";
        let b = "team1:eu:bob/telegram";
        let ia = relay_identity(a).unwrap();
        let ib = relay_identity(b).unwrap();
        // Deterministic.
        assert_eq!(ia, relay_identity(a).unwrap());
        // Distinct sessions get distinct user + pass (port may rarely collide).
        assert_ne!(ia.0, ib.0, "usernames must differ");
        assert_ne!(ia.1, ib.1, "passwords must differ");
        // No colon in the username (would corrupt the authfile key).
        assert!(!ia.0.contains(':'));
        // Port in range.
        assert!((PORT_BASE..PORT_BASE + PORT_SPAN as u16).contains(&ia.2));
        std::env::remove_var("TAP_RELAY_SIGNING_SECRET");
    }

    #[test]
    fn password_requires_signing_secret() {
        std::env::remove_var("TAP_RELAY_SIGNING_SECRET");
        assert!(relay_pass("team1:telegram").is_err(), "must fail closed");
    }

    #[test]
    fn authfile_pins_each_user_to_own_port() {
        std::env::set_var("TAP_RELAY_SIGNING_SECRET", "test-secret-at-least-16-chars");
        let sessions = vec!["team1:telegram".to_string(), "team2:telegram".to_string()];
        let json = render_authfile(&sessions).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 2, "one authfile entry per session");
        for sk in &sessions {
            let (user, pass, port) = relay_identity(sk).unwrap();
            let allowed = obj.get(&format!("{user}:{pass}")).unwrap();
            assert_eq!(allowed[0], format!("^R:127.0.0.1:{port}$"));
        }
        std::env::remove_var("TAP_RELAY_SIGNING_SECRET");
    }
}
