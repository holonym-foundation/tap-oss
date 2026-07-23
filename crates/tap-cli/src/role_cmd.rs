//! `tap role` subcommands — manage RBAC roles in the shared Postgres config store.

use colored::Colorize;
use tap_core::store::ConfigStore;

pub async fn list(store: &ConfigStore, team_id: &str) {
    match store.list_roles(team_id).await {
        Ok(roles) => {
            if roles.is_empty() {
                println!("No roles configured.");
                return;
            }
            println!(
                "{:<20} {:<12} {}",
                "NAME".bold(),
                "RATE LIMIT".bold(),
                "DESCRIPTION".bold()
            );
            for r in roles {
                let rate = r
                    .rate_limit_per_hour
                    .map(|r| format!("{r}/hr"))
                    .unwrap_or_else(|| "unlimited".to_string());
                println!(
                    "{:<20} {:<12} {}",
                    r.name,
                    rate,
                    r.description.unwrap_or_default()
                );
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn create(
    store: &ConfigStore,
    team_id: &str,
    name: &str,
    description: Option<&str>,
    credentials: &[String],
    rate_limit: Option<i64>,
) {
    if let Err(e) = store
        .create_role(team_id, name, description, rate_limit)
        .await
    {
        eprintln!("Error creating role: {e}");
        return;
    }

    for cred in credentials {
        if let Err(e) = store.add_credential_to_role(team_id, name, cred).await {
            eprintln!("Warning: failed to add credential '{cred}' to role: {e}");
        }
    }

    println!(
        "Role '{}' created with {} credential(s).",
        name,
        credentials.len()
    );
}

pub async fn add_credential(
    store: &ConfigStore,
    team_id: &str,
    role_name: &str,
    credential_name: &str,
) {
    match store
        .add_credential_to_role(team_id, role_name, credential_name)
        .await
    {
        Ok(()) => println!("Added '{credential_name}' to role '{role_name}'."),
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn remove_credential(
    store: &ConfigStore,
    team_id: &str,
    role_name: &str,
    credential_name: &str,
) {
    match store
        .remove_credential_from_role(team_id, role_name, credential_name)
        .await
    {
        Ok(()) => println!("Removed '{credential_name}' from role '{role_name}'."),
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn delete(store: &ConfigStore, team_id: &str, name: &str) {
    match store.delete_role(team_id, name).await {
        Ok(()) => println!("Role '{name}' deleted."),
        Err(e) => eprintln!("Error: {e}"),
    }
}
