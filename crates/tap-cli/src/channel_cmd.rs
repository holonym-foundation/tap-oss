//! `tap channel` subcommands — route approval notifications for self-hosted
//! deployments.
//!
//! Without a notification-channels row a team gets agent-reflected approval
//! links, which point at the dashboard — not useful on an OSS deployment where
//! the dashboard is a placeholder. `tap channel set telegram|matrix` is the
//! CLI way to route write-approvals to a messaging channel instead.

use colored::Colorize;
use tap_core::store::ConfigStore;

pub async fn set(store: &ConfigStore, team_id: &str, channel_type: &str, room_id: Option<&str>) {
    let config_json = match channel_type {
        "telegram" => "{}".to_string(),
        "matrix" => {
            let Some(room) = room_id else {
                eprintln!("Error: matrix channels need --room-id (e.g. !abc123:matrix.org)");
                std::process::exit(1);
            };
            match serde_json::to_string(&serde_json::json!({ "room_id": room })) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("Error: unknown channel type '{other}'. Use: telegram, matrix");
            std::process::exit(1);
        }
    };

    // "set" is idempotent: replace any existing row of the same name.
    let _ = store.delete_notification_channel(team_id, channel_type).await;
    match store
        .create_notification_channel(team_id, channel_type, channel_type, &config_json)
        .await
    {
        Ok(_) => {
            println!("Approval channel set to '{channel_type}'.");
            match channel_type {
                "telegram" => println!(
                    "Make sure TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set in the proxy environment."
                ),
                "matrix" => println!(
                    "Make sure MATRIX_HOMESERVER_URL and MATRIX_ACCESS_TOKEN are set in the proxy environment, and the bot has joined the room."
                ),
                _ => {}
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn list(store: &ConfigStore, team_id: &str) {
    match store.list_notification_channels(team_id).await {
        Ok(rows) => {
            if rows.is_empty() {
                println!("No approval channels configured.");
                println!("Writes will return agent-reflected approval links (dashboard-only).");
                println!("Configure one with: tap channel set telegram");
                return;
            }
            println!(
                "{:<12} {:<12} {:<8} {}",
                "NAME".bold(),
                "TYPE".bold(),
                "ENABLED".bold(),
                "CONFIG".bold()
            );
            for r in rows {
                println!(
                    "{:<12} {:<12} {:<8} {}",
                    r.name,
                    r.channel_type,
                    if r.enabled { "yes" } else { "no" },
                    r.config_json
                );
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn remove(store: &ConfigStore, team_id: &str, name: &str) {
    match store.delete_notification_channel(team_id, name).await {
        Ok(()) => println!("Channel '{name}' removed."),
        Err(e) => eprintln!("Error: {e}"),
    }
}
