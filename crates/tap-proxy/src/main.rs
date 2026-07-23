use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tap_bot::{MatrixChannel, TelegramChannel};
use tap_proxy::proxy::{build_router, AppState};
use tokio::process::Command;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("tap_proxy=info".parse().unwrap()),
        )
        .json()
        .init();

    tracing::info!("TAP proxy starting");
    startup_marker("process_start").await;

    // 0. Startup DEK re-wrap migration hook (option b, internal-docs#1187). No-op unless
    //    TAP_MIGRATE_REWRAP_KEK_PUBLIC_JWK is set. Runs inside the source (Evervault) enclave:
    //    wraps the in-memory DEK under the Azure KEK's public key and writes only the wrapped
    //    ciphertext to a config row — the plaintext DEK never leaves the enclave. When the
    //    migration ran and TAP_MIGRATE_EXIT_AFTER is truthy, exit cleanly (one-shot mode);
    //    otherwise fall through to normal startup. Enclave-only.
    #[cfg(feature = "enclave")]
    {
        match tap_proxy::key_provider::run_startup_rewrap().await {
            Ok(Some(_)) => {
                let exit_after = std::env::var("TAP_MIGRATE_EXIT_AFTER")
                    .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(false);
                if exit_after {
                    tracing::info!(
                        "Startup DEK re-wrap done; TAP_MIGRATE_EXIT_AFTER set — exiting"
                    );
                    std::process::exit(0);
                }
                tracing::info!("Startup DEK re-wrap done; continuing normal startup");
            }
            Ok(None) => {} // migration disabled — normal startup
            Err(e) => startup_panic("Startup DEK re-wrap migration failed", e).await,
        }
    }

    // 1. Load encryption key (env var in standard mode, in-enclave KMS in enclave mode)
    startup_marker("before_load_encryption_key").await;
    let encryption_key = match tap_proxy::key_provider::load_encryption_key().await {
        Ok(key) => key,
        Err(e) => startup_panic("Failed to load encryption key", e).await,
    };
    startup_marker("after_load_encryption_key").await;

    #[cfg(feature = "enclave")]
    tracing::info!("Encryption key loaded from in-enclave KMS");
    #[cfg(not(feature = "enclave"))]
    tracing::info!("Encryption key loaded from environment");

    if let Err(e) = maybe_start_embedded_telegram_sidecar().await {
        startup_panic("Failed to start embedded Telegram sidecar", e).await;
    }

    // The egress relay is an OPTIONAL feature. If it can't start (missing chisel
    // binary, bad signing secret, etc.) that must NOT take down the whole enclave —
    // every other credential, approvals, and TLS must keep serving. Log loudly and
    // continue; relay-enabled credentials then fail closed with relay_offline.
    if let Err(e) = maybe_start_relay_server().await {
        tracing::error!(
            error = %e,
            "Telegram egress relay server failed to start — continuing WITHOUT it; \
             relay-enabled credentials will fail closed (relay_offline)"
        );
    }

    // 2. Initialize ConfigStore (Postgres)
    let database_url = match std::env::var("POSTGRES_DATABASE_URL") {
        Ok(url) => url,
        Err(e) => startup_panic("POSTGRES_DATABASE_URL environment variable is required", e).await,
    };
    startup_marker("before_config_store").await;
    let cache_ttl = std::env::var("TAP_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30u64);
    let store = match tap_core::store::ConfigStore::new(&database_url, encryption_key).await {
        Ok(store) => store,
        Err(e) => startup_panic("Failed to connect to database", e).await,
    };
    startup_marker("after_config_store").await;
    tracing::info!(cache_ttl_secs = cache_ttl, "ConfigStore initialized");

    // One-time data migration from Turso → Postgres (no-op once the flag is set).
    tap_proxy::turso_migration::maybe_migrate(store.pool()).await;
    let webauthn_store = store.clone(); // Clone before DbState consumes it
    let matrix_store = Arc::new(store.clone()); // For Matrix DB persistence
    let polling_store = Arc::new(store.clone()); // For Telegram command handling
                                                 // Clone the Postgres pool before `store` is moved into DbState — the in-enclave TLS
                                                 // terminator (internal-docs#1188) uses it for the DEK-encrypted ACME cert cache.
    let tls_pool = store.pool().clone();
    let dashboard_store = Arc::new(store.clone()); // For the dashboard approval channel
    let db_state = Arc::new(tap_proxy::db_state::DbState::new(
        store,
        Duration::from_secs(cache_ttl),
    ));

    // 3. Initialize Telegram approval channel (optional).
    //    Without TELEGRAM_BOT_TOKEN — common for self-hosted deployments —
    //    Telegram approvals are simply disabled: telegram channel rows and
    //    per-credential overrides fall through to dashboard/agent-reflected.
    //    In enclave mode: encrypted in DB via in-enclave KMS (bootstraps from
    //    env on first run); a KMS/unseal *error* still fails boot — only a
    //    genuinely absent token disables the channel.
    //    TELEGRAM_CHAT_ID is optional — teams configure their own via admin API.
    let bot_token = match tap_proxy::key_provider::load_optional_secret(
        "TELEGRAM_BOT_TOKEN",
        "telegram_bot_token_ciphertext",
    )
    .await
    {
        Ok(token) => token.filter(|t| !t.is_empty()),
        Err(e) => startup_panic("Failed to load Telegram bot token", e).await,
    };
    startup_marker("after_telegram_secret").await;
    let telegram_setup: Option<(Arc<TelegramChannel>, tap_bot::TelegramConfig)> = match bot_token {
        Some(bot_token) => {
            let default_chat_id = tap_proxy::key_provider::load_secret(
                "TELEGRAM_CHAT_ID",
                "telegram_chat_id_ciphertext",
            )
            .await
            .unwrap_or_default();
            if default_chat_id.is_empty() {
                tracing::warn!(
                    "TELEGRAM_CHAT_ID not set — teams must configure notification channels via the admin API"
                );
            }
            let telegram_config = tap_bot::TelegramConfig {
                bot_token,
                chat_id: default_chat_id,
            };
            match TelegramChannel::with_store(telegram_config.clone(), Some(polling_store.clone()))
            {
                Ok(channel) => Some((Arc::new(channel), telegram_config)),
                Err(e) => startup_panic("Failed to initialize Telegram channel", e).await,
            }
        }
        None => {
            tracing::warn!(
                "TELEGRAM_BOT_TOKEN not set — Telegram approvals disabled; approvals use the dashboard/agent-reflected channels"
            );
            None
        }
    };

    // 4. Initialize audit logger — always DB-backed (Postgres).
    let audit_logger: Arc<dyn tap_proxy::audit::AuditLog> = {
        let handle = tokio::runtime::Handle::current();
        tracing::info!("Audit log: database-backed (Postgres)");
        Arc::new(tap_proxy::audit::DbAuditLogger::new(
            db_state.store().clone(),
            handle,
        ))
    };

    // 4b. Telegram update delivery: webhook if a public URL is reachable, else long-polling.
    //     TELEGRAM_WEBHOOK_URL overrides; otherwise derived from TAP_PUBLIC_URL/TAP_BASE_URL.
    let webhook_secret = std::env::var("TELEGRAM_WEBHOOK_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    if let Some((tg_channel, _)) = telegram_setup.as_ref() {
        if webhook_secret.is_some() {
            tracing::info!("Telegram webhook secret verification enabled");
        }
        let webhook_url = std::env::var("TELEGRAM_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "{}/telegram/webhook",
                    tap_proxy::proxy::configured_proxy_url()
                )
            });
        let use_polling = match tg_channel
            .register_webhook(&webhook_url, webhook_secret.as_deref())
            .await
        {
            Ok(()) => {
                tracing::info!(url = %webhook_url, "Telegram webhook registered — long-polling disabled");
                false
            }
            Err(e) => {
                tracing::warn!(error = %e, "Telegram webhook registration failed — falling back to long-polling");
                true
            }
        };
        if use_polling {
            tg_channel.start_polling(Some(polling_store));
        }
    }

    // 4c. Initialize Matrix approval channel (optional). In enclave mode, the
    //     homeserver URL can come from either an already sealed DB row or a
    //     first-run bootstrap env var. Per-team rooms go through the admin API
    //     (channel_type = "matrix", config = {homeserver_url, room_id}).
    let (matrix_channel, matrix_channel_raw): (
        Option<Arc<dyn tap_core::approval::ApprovalChannel>>,
        Option<Arc<MatrixChannel>>,
    ) = if let Some(homeserver_url) = match tap_proxy::key_provider::load_optional_secret(
        "MATRIX_HOMESERVER_URL",
        "matrix_homeserver_url_ciphertext",
    )
    .await
    {
        Ok(value) => value,
        Err(e) => startup_panic("Failed to load Matrix homeserver URL", e).await,
    } {
        if homeserver_url.trim().is_empty() {
            startup_panic(
                "Failed to load Matrix homeserver URL",
                "MATRIX_HOMESERVER_URL must not be empty",
            )
            .await;
        }
        let access_token = match tap_proxy::key_provider::load_secret(
            "MATRIX_ACCESS_TOKEN",
            "matrix_access_token_ciphertext",
        )
        .await
        {
            Ok(token) => token,
            Err(e) => startup_panic("Failed to load Matrix access token", e).await,
        };
        if access_token.is_empty() {
            startup_panic(
                "Failed to load Matrix access token",
                "MATRIX_ACCESS_TOKEN must not be empty",
            )
            .await;
        }
        let default_room_id = match tap_proxy::key_provider::load_optional_secret(
            "MATRIX_ROOM_ID",
            "matrix_room_id_ciphertext",
        )
        .await
        {
            Ok(value) => value.unwrap_or_default(),
            Err(e) => startup_panic("Failed to load Matrix room ID", e).await,
        };
        if default_room_id.is_empty() {
            tracing::warn!(
                "MATRIX_ROOM_ID not set — teams must configure notification channels via the admin API"
            );
        }
        let matrix_config = tap_bot::MatrixConfig {
            homeserver_url: homeserver_url.trim_end_matches('/').to_string(),
            access_token,
            room_id: default_room_id,
        };
        let channel = Arc::new(
            match MatrixChannel::new(matrix_config, Some(matrix_store)) {
                Ok(channel) => channel,
                Err(e) => startup_panic("Failed to initialize Matrix channel", e).await,
            },
        );
        channel.start_syncing();
        tracing::info!("Matrix approval channel initialized");
        let raw = channel.clone();
        (
            Some(channel as Arc<dyn tap_core::approval::ApprovalChannel>),
            Some(raw),
        )
    } else {
        tracing::info!("Matrix homeserver not configured — Matrix channel disabled");
        (None, None)
    };

    // 5. Build proxy state
    let forward_timeout = std::env::var("TAP_FORWARD_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30u64);
    let approval_timeout_secs = std::env::var("TAP_APPROVAL_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600u64);
    // Pending inbox/passkey rows stay actionable slightly past the approval
    // window so an approver who clicks right at the deadline gets a clean
    // "already expired" resolution instead of a missing row.
    let pending_ttl_secs = approval_timeout_secs + 600;

    // 5b. Initialize WebAuthn if configured
    let webauthn_state = match (
        std::env::var("WEBAUTHN_RP_ID").ok(),
        std::env::var("WEBAUTHN_RP_ORIGIN").ok(),
        std::env::var("TAP_APPROVAL_BASE_URL")
            .or_else(|_| std::env::var("TAP_APP_URL"))
            .ok(),
    ) {
        (Some(rp_id), Some(rp_origin), Some(base_url)) => {
            let additional_origins: Vec<String> = std::env::var("WEBAUTHN_ADDITIONAL_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            match tap_proxy::webauthn::WebAuthnState::new(
                &rp_id,
                &rp_origin,
                &base_url,
                Some(webauthn_store),
                &additional_origins,
            ) {
                Ok(wa) => {
                    let wa = Arc::new(wa);
                    // Load persisted passkeys from DB
                    match wa.load_credentials_from_db().await {
                        Ok(count) => tracing::info!(count, "Loaded approver passkeys from DB"),
                        Err(e) => tracing::warn!("Failed to load passkeys from DB: {e}"),
                    }
                    // Load admin passkeys for 2FA
                    match wa.load_admin_credentials_from_db().await {
                        Ok(count) => tracing::info!(count, "Loaded admin passkeys from DB"),
                        Err(e) => tracing::warn!("Failed to load admin passkeys from DB: {e}"),
                    }
                    tracing::info!(rp_id = %rp_id, "WebAuthn approval enabled");
                    Some(wa)
                }
                Err(e) => {
                    tracing::warn!("WebAuthn initialization failed: {e}");
                    None
                }
            }
        }
        _ => {
            tracing::info!(
                "WebAuthn not configured (set WEBAUTHN_RP_ID, WEBAUTHN_RP_ORIGIN, TAP_APP_URL)"
            );
            None
        }
    };

    // First-party dashboard channel — inbox + web-push, selected when a team
    // explicitly adds a `dashboard` notification-channels row.
    let dashboard_base_url = std::env::var("TAP_APPROVAL_BASE_URL")
        .or_else(|_| std::env::var("TAP_APP_URL"))
        .unwrap_or_else(|_| tap_proxy::proxy::configured_proxy_url());
    let push_sender: Option<Arc<dyn tap_proxy::push::PushSender>> =
        tap_proxy::push::WebPushSender::from_env(dashboard_store.clone())
            .map(|s| Arc::new(s) as Arc<dyn tap_proxy::push::PushSender>);
    if push_sender.is_some() {
        tracing::info!("Web Push enabled for dashboard approvals");
    } else {
        tracing::info!(
            "Web Push disabled (set TAP_VAPID_PRIVATE_KEY + TAP_VAPID_PUBLIC_KEY to enable) — dashboard approvals are inbox-only"
        );
    }
    let dashboard_channel: Arc<dyn tap_core::approval::ApprovalChannel> =
        Arc::new(tap_proxy::dashboard_channel::DashboardChannel::new(
            dashboard_store.clone(),
            dashboard_base_url,
            push_sender,
            pending_ttl_secs,
        ));

    // Agent-reflected channel — the default fallback for teams with no Telegram
    // or Matrix row. Returns the approval URL directly in the 202 response body
    // so the agent can show it inline; no external messaging setup required.
    let agent_reflected_channel: Arc<dyn tap_core::approval::ApprovalChannel> = Arc::new(
        tap_proxy::agent_reflected_channel::AgentReflectedChannel::new(
            dashboard_store,
            pending_ttl_secs,
        ),
    );

    let state = AppState {
        encryption_key: Arc::new(encryption_key),
        approval_channel: agent_reflected_channel,
        dashboard_channel,
        telegram_channel: telegram_setup
            .as_ref()
            .map(|(c, _)| c.clone() as Arc<dyn tap_core::approval::ApprovalChannel>),
        matrix_channel: matrix_channel.clone(),
        matrix_channel_raw: matrix_channel_raw.clone(),
        audit_logger,
        forward_timeout: Duration::from_secs(forward_timeout),
        db_state,
        webauthn_state: webauthn_state.clone(),
        approval_timeout_secs,
    };

    // 6a. Background cleanup — purge expired pending_approvals and async_approvals
    // rows every 5 minutes. This is the safety net for rows whose callers don't
    // delete on decision (e.g. Telegram/Matrix bots that crash mid-flow, async
    // approvals whose response bodies were never polled, etc.).
    {
        let cleanup_store = state.db_state.store().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                match cleanup_store.cleanup_expired_rows().await {
                    Ok((p, a)) if p > 0 || a > 0 => {
                        tracing::info!(
                            pending_deleted = p,
                            async_deleted = a,
                            "Expired approval rows cleaned up"
                        );
                    }
                    Err(e) => tracing::warn!(error = %e, "Approval row cleanup failed"),
                    _ => {}
                }
            }
        });
    }

    // 6. Build router with telegram webhook + optional WebAuthn
    let app = build_router_with_webhook(
        state,
        telegram_setup,
        webhook_secret,
        webauthn_state,
        matrix_channel_raw,
    );

    // 7. Serve. If TLS_DOMAIN is set, terminate TLS *inside* the enclave (internal-docs#1188)
    //    so plaintext never leaves the TEE — auto-renewing Let's Encrypt certs over
    //    TLS-ALPN-01, with a DEK-encrypted Postgres cert cache that survives restarts /
    //    scale-to-zero. Otherwise keep the plain-HTTP path unchanged (e.g. when TLS is
    //    terminated upstream in non-enclave deployments).
    let tls_domain = std::env::var("TLS_DOMAIN")
        .ok()
        .filter(|s| !s.trim().is_empty());
    if tls_domain.is_some() {
        if let Err(e) = tap_proxy::tls::serve_tls(app, encryption_key, tls_pool).await {
            startup_panic("In-enclave TLS server failed", e).await;
        }
    } else {
        let addr = std::env::var("TAP_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3100".to_string());
        tracing::info!("Listening on {addr} (plain HTTP)");
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => listener,
            Err(e) => startup_panic("Plain HTTP listener bind failed", e).await,
        };
        if let Err(e) = axum::serve(listener, app).await {
            startup_panic("Plain HTTP server failed", e).await;
        }
    }
}

async fn maybe_start_embedded_telegram_sidecar() -> Result<(), String> {
    let default_enabled = if cfg!(feature = "enclave") { "1" } else { "0" };
    let enabled = std::env::var("TAP_ENABLE_EMBEDDED_TELEGRAM")
        .unwrap_or_else(|_| default_enabled.to_string());
    if enabled != "1" {
        tracing::info!("Embedded Telegram sidecar disabled");
        return Ok(());
    }

    let python =
        std::env::var("TAP_EMBEDDED_TELEGRAM_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let script = std::env::var("TAP_EMBEDDED_TELEGRAM_SCRIPT")
        .unwrap_or_else(|_| "/opt/tap/telegram_sidecar.py".to_string());
    let port = std::env::var("TAP_EMBEDDED_TELEGRAM_PORT").unwrap_or_else(|_| "8082".to_string());
    let health_url = format!("http://127.0.0.1:{port}/health");

    let mut child = Command::new(&python)
        .arg(&script)
        .env("PYTHONUNBUFFERED", "1")
        .env("TELEGRAM_SIDECAR_HOST", "127.0.0.1")
        .env("TELEGRAM_SIDECAR_PORT", &port)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn {python} {script}: {e}"))?;

    for _ in 0..40 {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("check embedded Telegram sidecar status: {e}"))?
        {
            return Err(format!(
                "embedded Telegram sidecar exited early with status {status}"
            ));
        }

        match reqwest::get(&health_url).await {
            Ok(resp) if resp.status().is_success() => {
                let pid = child.id().unwrap_or_default();
                tracing::info!(pid, health_url = %health_url, "Embedded Telegram sidecar ready");
                tokio::spawn(async move {
                    match child.wait().await {
                        Ok(status) => tracing::warn!(?status, "Embedded Telegram sidecar exited"),
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed waiting on embedded Telegram sidecar")
                        }
                    }
                });
                return Ok(());
            }
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }

    let _ = child.kill().await;
    Err(format!(
        "embedded Telegram sidecar did not become healthy at {health_url}"
    ))
}

/// Start the chisel reverse-tunnel server that backs the Telegram egress relay.
/// Disabled unless `TAP_ENABLE_RELAY_SERVER=1` (so it is inert by default). The
/// proxy reverse-proxies `/relay` (WebSocket) to this local server; a relay
/// client dials in and exposes a reverse SOCKS port the Telethon sidecar egresses
/// through. See `docs/telegram-local-relay-design.md`.
async fn maybe_start_relay_server() -> Result<(), String> {
    if std::env::var("TAP_ENABLE_RELAY_SERVER").unwrap_or_else(|_| "0".to_string()) != "1" {
        tracing::info!("Telegram egress relay server disabled");
        return Ok(());
    }

    let bin =
        std::env::var("TAP_RELAY_CHISEL_BIN").unwrap_or_else(|_| "/usr/local/bin/chisel".to_string());
    let port = std::env::var("TAP_RELAY_CHISEL_PORT").unwrap_or_else(|_| "8083".to_string());
    // Multi-user isolation: chisel runs with an authfile projected from the live
    // relay sessions (tap_proxy::relay). Each session has its own credential pinned
    // to its own reverse-SOCKS port, so no relay can bind another user's port. We
    // require the signing secret up front (fail closed) and seed an empty authfile
    // before chisel starts; the /relay/heartbeat path regenerates it as users
    // enroll, and chisel watches the file for changes.
    let _ = tap_proxy::relay::relay_pass("startup-probe")
        .map_err(|e| format!("TAP_ENABLE_RELAY_SERVER=1 requires a signing secret: {e}"))?;
    let authfile = tap_proxy::relay::authfile_path();
    tap_proxy::relay::write_authfile(&[])
        .map_err(|e| format!("failed to seed relay authfile at {authfile}: {e}"))?;

    let mut cmd = Command::new(&bin);
    cmd.arg("server")
        .arg("--reverse")
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(&port)
        .arg("--authfile")
        .arg(&authfile)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn {bin} server: {e}"))?;

    let addr = format!("127.0.0.1:{port}");
    for _ in 0..40 {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("check relay server status: {e}"))?
        {
            return Err(format!("relay server exited early with status {status}"));
        }
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            let pid = child.id().unwrap_or_default();
            tracing::info!(pid, addr = %addr, "Telegram egress relay server ready");
            tokio::spawn(async move {
                match child.wait().await {
                    Ok(status) => tracing::warn!(?status, "relay server exited"),
                    Err(e) => tracing::warn!(error = %e, "Failed waiting on relay server"),
                }
            });
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let _ = child.kill().await;
    Err(format!("relay server did not start listening on {addr}"))
}

async fn startup_panic(stage: &str, error: impl std::fmt::Display) -> ! {
    let detail = sanitize_startup_error(&error.to_string());
    tracing::error!(stage, error = %detail, "startup failed");

    #[cfg(feature = "enclave")]
    if let Err(e) = persist_startup_error(stage, &detail).await {
        tracing::warn!(error = %e, "failed to persist startup diagnostic");
    }

    panic!("{stage}: {detail}");
}

async fn startup_marker(_stage: &str) {
    #[cfg(feature = "enclave")]
    if let Err(e) = persist_startup_marker(_stage).await {
        tracing::warn!(stage = _stage, error = %e, "failed to persist startup marker");
    }
}

fn sanitize_startup_error(input: &str) -> String {
    let mut out = input.to_string();
    for scheme in ["postgres://", "postgresql://"] {
        let mut start = 0;
        while let Some(pos) = out[start..].find(scheme) {
            let url_start = start + pos;
            let userinfo_start = url_start + scheme.len();
            let at = match out[userinfo_start..].find('@') {
                Some(at) => userinfo_start + at,
                None => break,
            };
            let end = out[userinfo_start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map(|end| userinfo_start + end)
                .unwrap_or(out.len());
            if at < end {
                out.replace_range(userinfo_start..=at, "<redacted>@");
                start = url_start + scheme.len() + "<redacted>@".len();
            } else {
                start = userinfo_start;
            }
        }
    }
    out.chars().take(2048).collect()
}

#[cfg(feature = "enclave")]
async fn persist_startup_error(stage: &str, detail: &str) -> anyhow::Result<()> {
    persist_startup_diagnostic("tap_proxy_startup_last_error", stage, Some(detail)).await
}

#[cfg(feature = "enclave")]
async fn persist_startup_marker(stage: &str) -> anyhow::Result<()> {
    persist_startup_diagnostic("tap_proxy_startup_last_marker", stage, None).await
}

#[cfg(feature = "enclave")]
async fn persist_startup_diagnostic(
    key: &str,
    stage: &str,
    detail: Option<&str>,
) -> anyhow::Result<()> {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
    use sqlx::Executor as _;
    use std::str::FromStr as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let url = std::env::var("POSTGRES_DATABASE_URL")?;
    let ca_cert_path = std::env::var("TAP_POSTGRES_CA_CERT_PATH")
        .unwrap_or_else(|_| "/etc/ssl/certs/tap-supabase-ca.crt".to_string());
    let opts = PgConnectOptions::from_str(&url)?
        .statement_cache_capacity(0)
        .ssl_mode(PgSslMode::VerifyFull);
    let pool_opts = PgPoolOptions::new()
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("DEALLOCATE ALL").await?;
                Ok(())
            })
        })
        .before_acquire(|conn, _meta| {
            Box::pin(async move {
                conn.execute("DEALLOCATE ALL").await?;
                Ok(true)
            })
        });
    let pool = if std::path::Path::new(&ca_cert_path).exists() {
        match pool_opts
            .clone()
            .connect_with(opts.clone().ssl_root_cert(&ca_cert_path))
            .await
        {
            Ok(pool) => pool,
            Err(_) => pool_opts.connect_with(opts).await?,
        }
    } else {
        pool_opts.connect_with(opts).await?
    };
    sqlx::query("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .execute(&pool)
        .await?;
    let ts_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut payload = serde_json::json!({
        "stage": stage,
        "ts_unix": ts_unix,
    });
    if let Some(detail) = detail {
        payload["error"] = serde_json::Value::String(detail.to_string());
    }
    sqlx::query(
        "INSERT INTO config (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(key)
    .bind(payload.to_string())
    .execute(&pool)
    .await?;
    Ok(())
}

/// Build the main router plus the Telegram webhook + optional WebAuthn routes.
fn build_router_with_webhook(
    state: AppState,
    telegram_setup: Option<(Arc<TelegramChannel>, tap_bot::TelegramConfig)>,
    webhook_secret: Option<String>,
    webauthn_state: Option<Arc<tap_proxy::webauthn::WebAuthnState>>,
    matrix_channel: Option<Arc<tap_bot::MatrixChannel>>,
) -> axum::Router {
    use axum::extract::State as AxumState;
    use axum::http::StatusCode;
    use axum::Json;

    #[derive(Clone)]
    struct WebhookState {
        channel: Arc<TelegramChannel>,
        /// If set, reject webhook requests that don't carry this secret
        /// in the X-Telegram-Bot-Api-Secret-Token header.
        webhook_secret: Option<String>,
        db_state: Arc<tap_proxy::db_state::DbState>,
        telegram_config: tap_bot::TelegramConfig,
    }

    async fn send_telegram_reply(config: &tap_bot::TelegramConfig, chat_id: i64, text: &str) {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            config.bot_token
        );
        let client = match tap_core::http_client::build_client(
            tap_core::http_client::ClientRoute::EgressProxy,
        ) {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!("Failed to create Telegram reply HTTP client: {e}");
                return;
            }
        };
        let _ = client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
            }))
            .send()
            .await;
    }

    async fn handle_telegram_webhook(
        AxumState(wh): AxumState<WebhookState>,
        headers: axum::http::HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        // Verify webhook secret if configured
        if let Some(ref expected) = wh.webhook_secret {
            let provided = headers
                .get("x-telegram-bot-api-secret-token")
                .and_then(|v| v.to_str().ok());
            match provided {
                Some(token) if token == expected => {}
                _ => {
                    tracing::warn!("Telegram webhook rejected: invalid or missing secret token");
                    return StatusCode::UNAUTHORIZED;
                }
            }
        }

        if let Some(callback_query) = body.get("callback_query") {
            let data = callback_query
                .get("data")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            let cq_id = callback_query
                .get("id")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            let user_id = callback_query
                .get("from")
                .and_then(|f| f.get("id"))
                .and_then(|id| id.as_i64())
                .map(|id| id.to_string());

            if let Err(e) = wh
                .channel
                .handle_callback(data, cq_id, user_id.as_deref())
                .await
            {
                tracing::warn!(error = %e, "Telegram callback handling failed");
                return StatusCode::BAD_REQUEST;
            }
        }

        // Handle text commands (admin whitelist management)
        if let Some(message) = body.get("message") {
            let text = message.get("text").and_then(|t| t.as_str()).unwrap_or("");
            let chat_id = message
                .get("chat")
                .and_then(|c| c.get("id"))
                .and_then(|id| id.as_i64());

            // Only process commands from the configured approval chat
            let admin_chat_id = wh.telegram_config.chat_id.parse::<i64>().unwrap_or(0);
            if chat_id != Some(admin_chat_id) {
                return StatusCode::OK; // ignore messages from other chats
            }

            if let Some(email) = text
                .strip_prefix("/whitelist ")
                .map(|s| s.trim().to_lowercase())
            {
                if email.contains('@') && email.contains('.') {
                    match wh.db_state.store().add_to_whitelist(&email, "pro").await {
                        Ok(()) => {
                            send_telegram_reply(
                                &wh.telegram_config,
                                admin_chat_id,
                                &format!("\u{2713} {email} whitelisted (Pro tier)"),
                            )
                            .await;
                        }
                        Err(e) => {
                            send_telegram_reply(
                                &wh.telegram_config,
                                admin_chat_id,
                                &format!("\u{2717} Failed: {e}"),
                            )
                            .await;
                        }
                    }
                } else {
                    send_telegram_reply(
                        &wh.telegram_config,
                        admin_chat_id,
                        "\u{2717} Invalid email format",
                    )
                    .await;
                }
            } else if let Some(email) = text
                .strip_prefix("/unwhitelist ")
                .map(|s| s.trim().to_lowercase())
            {
                match wh.db_state.store().remove_from_whitelist(&email).await {
                    Ok(()) => {
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            &format!("\u{2713} {email} removed from whitelist"),
                        )
                        .await;
                    }
                    Err(e) => {
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            &format!("\u{2717} Failed: {e}"),
                        )
                        .await;
                    }
                }
            } else if text.trim() == "/whitelist" {
                // List all whitelisted emails
                match wh.db_state.store().list_whitelist().await {
                    Ok(entries) if entries.is_empty() => {
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            "No whitelisted emails.",
                        )
                        .await;
                    }
                    Ok(entries) => {
                        let list = entries
                            .iter()
                            .map(|(e, t)| format!("\u{2022} {e} ({t})"))
                            .collect::<Vec<_>>()
                            .join("\n");
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            &format!("Whitelisted emails:\n{list}"),
                        )
                        .await;
                    }
                    Err(e) => {
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            &format!("\u{2717} Failed: {e}"),
                        )
                        .await;
                    }
                }
            }
        }

        StatusCode::OK
    }

    let config_store = std::sync::Arc::new(state.db_state.store().clone());
    let db_state = state.db_state.clone();

    let mut router = build_router(state);

    if let Some((tg_channel, telegram_config)) = telegram_setup.as_ref() {
        let wh_state = WebhookState {
            channel: tg_channel.clone(),
            webhook_secret,
            db_state,
            telegram_config: telegram_config.clone(),
        };
        router = router.merge(
            axum::Router::new()
                .route(
                    "/telegram/webhook",
                    axum::routing::post(handle_telegram_webhook),
                )
                .with_state(wh_state),
        );
    }

    if let Some(wa_state) = webauthn_state {
        router = router.merge(tap_proxy::webauthn::build_approval_router(
            wa_state,
            telegram_setup.map(|(c, _)| c),
            matrix_channel,
            Some(config_store),
        ));
    }

    router
}
