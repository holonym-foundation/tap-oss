#![allow(dead_code)]

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

mod add;
mod agent_cmd;
mod auth;
mod channel_cmd;
mod cred;
mod init;
mod logs;
mod recipe;
mod role_cmd;

#[derive(Parser)]
#[command(
    name = "tap",
    version = "0.1.0",
    about = "Tool Authorization Protocol — credential isolation for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Commands {
    /// Show which account you're logged in to
    Status {
        #[arg(long)]
        account: Option<String>,
    },
    /// Tail and display audit log entries
    Logs {
        /// Path to audit log file
        #[arg(short, long, default_value = "./audit.jsonl")]
        log_file: PathBuf,
        /// Number of recent entries to show (0 = all)
        #[arg(short, long, default_value = "20")]
        tail: usize,
    },
    /// Add a new service/credential to the database
    Add {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Service name (interactive if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Service description
        #[arg(long)]
        description: Option<String>,
        /// Auth type: api-key, oauth2, oauth1, custom
        #[arg(long)]
        auth: Option<String>,
        /// API base URL or sidecar URL
        #[arg(long)]
        api_base: Option<String>,
        /// Target is a relative path (for protocol translators like Telegram)
        #[arg(long)]
        relative_target: bool,
        /// Secret value, stored encrypted in the database. For OAuth/signing
        /// credentials pass the JSON bundle. Prompted for interactively if
        /// omitted for api-key credentials.
        #[arg(long)]
        value: Option<String>,
    },

    // -- DB-backed management commands --
    /// Manage agents (list, create, show, enable, disable, delete)
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Manage RBAC roles (list, create, add-credential, remove-credential, delete)
    Role {
        #[command(subcommand)]
        action: RoleAction,
    },

    // -- Web-auth CLI (talks HTTP to the proxy) --
    /// Log in to a TAP proxy in your browser and store the session securely
    Login {
        /// Proxy base URL (defaults to the managed TAP proxy)
        #[arg(long, default_value = "https://proxy.tap.human.tech")]
        proxy: String,
        /// Store under a named profile (default: your email)
        #[arg(long = "as")]
        as_profile: Option<String>,
    },
    /// Show the current logged-in account
    Whoami {
        #[arg(long)]
        account: Option<String>,
    },
    /// Log out and remove the stored session
    Logout {
        #[arg(long)]
        account: Option<String>,
    },
    /// Manage multiple accounts (list, use)
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Route approval notifications (telegram, matrix) for self-hosted deployments
    Channel {
        #[command(subcommand)]
        action: ChannelAction,
    },
    /// Add a credential without pasting the secret into the dashboard
    Cred {
        #[command(subcommand)]
        action: CredAction,
    },
    /// One-command use-case setup ("starter packs")
    Recipe {
        #[command(subcommand)]
        action: RecipeAction,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum AccountAction {
    /// List logged-in accounts
    List,
    /// Switch the active account
    Use { name: String },
}

#[derive(Subcommand, Debug, PartialEq)]
enum ChannelAction {
    /// Set the team approval channel (replaces any existing one of that type)
    Set {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Channel type: telegram or matrix
        channel_type: String,
        /// Matrix room ID (required for matrix, e.g. !abc123:matrix.org)
        #[arg(long)]
        room_id: Option<String>,
    },
    /// List configured approval channels
    List {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
    },
    /// Remove an approval channel by name
    Remove {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum CredAction {
    /// Add a credential: type the secret at a hidden prompt, approve with a passkey
    Set {
        /// Credential name (e.g. stripe)
        name: String,
        /// Destination host binding (repeatable, recommended): --host api.stripe.com
        #[arg(long = "host")]
        host: Vec<String>,
        /// Human-readable description
        #[arg(long)]
        desc: Option<String>,
        /// Auth header format, e.g. "Bearer {}"
        #[arg(long = "header-format")]
        header_format: Option<String>,
        /// Sidecar api_base (marks the credential as a sidecar connector)
        #[arg(long = "api-base")]
        api_base: Option<String>,
        /// Which logged-in account to use (defaults to the active one)
        #[arg(long)]
        account: Option<String>,
        /// Read the secret from stdin instead of a hidden prompt
        #[arg(long)]
        stdin: bool,
        /// Gate every agent action on this credential behind a passkey approval
        /// (opt-in; for money-moving / high-stakes creds)
        #[arg(long = "require-passkey")]
        require_passkey: bool,
    },
    /// Connect an OAuth credential (Google today): opens the dashboard connect
    /// page — pick agent key(s), approve with a passkey, then consent. No secret
    /// is typed. Extensible to other providers via --provider.
    Oauth {
        /// Credential name (e.g. gmail)
        name: String,
        /// OAuth provider (currently only "google")
        #[arg(long, default_value = "google")]
        provider: String,
        /// Least-privilege scope bundle ids, comma-separated (e.g. gmail-readonly)
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
        /// Which logged-in account to use (defaults to the active one)
        #[arg(long)]
        account: Option<String>,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum RecipeAction {
    /// List available recipes
    List,
    /// Show what a recipe sets up
    Show { name: String },
    /// Run a recipe: connect if needed, set up its credentials, print the prompt
    Run {
        /// Recipe name (e.g. invoice-payer)
        name: String,
        /// Which logged-in account to use (defaults to the active one)
        #[arg(long)]
        account: Option<String>,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum AgentAction {
    /// List all agents
    List {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
    },
    /// Create a new agent
    Create {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Agent name/ID
        #[arg(long)]
        name: String,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Comma-separated role names
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        /// Comma-separated direct credential names
        #[arg(long, value_delimiter = ',')]
        credentials: Vec<String>,
        /// Rate limit per hour
        #[arg(long)]
        rate_limit: Option<i64>,
    },
    /// Show agent details and effective permissions
    Show {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Agent name/ID
        name: String,
    },
    /// Disable an agent (blocks all requests)
    Disable {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
    /// Re-enable a disabled agent
    Enable {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
    /// Delete an agent
    Delete {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum RoleAction {
    /// List all roles
    List {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
    },
    /// Create a new role
    Create {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Role name
        #[arg(long)]
        name: String,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Comma-separated credential names
        #[arg(long, value_delimiter = ',')]
        credentials: Vec<String>,
        /// Rate limit per hour
        #[arg(long)]
        rate_limit: Option<i64>,
    },
    /// Add a credential to a role
    AddCredential {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Role name
        role: String,
        /// Credential name
        credential: String,
    },
    /// Remove a credential from a role
    RemoveCredential {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        role: String,
        credential: String,
    },
    /// Delete a role
    Delete {
        #[arg(long, env = "TAP_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { account } => auth::cmd_status(account).await,
        Commands::Logs { log_file, tail } => cmd_logs(&log_file, tail),
        Commands::Add {
            encryption_key,
            name,
            description,
            auth,
            api_base,
            relative_target,
            value,
        } => {
            cmd_add(
                &encryption_key,
                name,
                description,
                auth,
                api_base,
                relative_target,
                value,
            )
            .await
        }
        Commands::Agent { action } => cmd_agent(action).await,
        Commands::Role { action } => cmd_role(action).await,
        Commands::Login { proxy, as_profile } => auth::cmd_login(&proxy, as_profile).await,
        Commands::Whoami { account } => auth::cmd_whoami(account).await,
        Commands::Logout { account } => auth::cmd_logout(account).await,
        Commands::Account { action } => match action {
            AccountAction::List => auth::cmd_account_list(),
            AccountAction::Use { name } => auth::cmd_account_use(&name),
        },
        Commands::Channel { action } => cmd_channel(action).await,
        Commands::Cred { action } => match action {
            CredAction::Set {
                name,
                host,
                desc,
                header_format,
                api_base,
                account,
                stdin,
                require_passkey,
            } => {
                cred::cmd_cred_set(cred::CredSetOpts {
                    name,
                    hosts: host,
                    description: desc,
                    header_format,
                    api_base,
                    account,
                    stdin,
                    require_passkey,
                })
                .await;
            }
            CredAction::Oauth {
                name,
                provider,
                scopes,
                account,
            } => {
                cred::cmd_cred_oauth(cred::CredOauthOpts {
                    name,
                    provider,
                    scopes,
                    account,
                })
                .await;
            }
        },
        Commands::Recipe { action } => match action {
            RecipeAction::List => recipe::cmd_list(),
            RecipeAction::Show { name } => recipe::cmd_show(&name),
            RecipeAction::Run { name, account } => recipe::cmd_run(&name, account).await,
        },
    }
}

async fn cmd_channel(action: ChannelAction) {
    match action {
        ChannelAction::Set {
            encryption_key,
            channel_type,
            room_id,
        } => {
            let store = open_store(&encryption_key).await;
            channel_cmd::set(&store, DEFAULT_TEAM_ID, &channel_type, room_id.as_deref()).await;
        }
        ChannelAction::List { encryption_key } => {
            let store = open_store(&encryption_key).await;
            channel_cmd::list(&store, DEFAULT_TEAM_ID).await;
        }
        ChannelAction::Remove {
            encryption_key,
            name,
        } => {
            let store = open_store(&encryption_key).await;
            channel_cmd::remove(&store, DEFAULT_TEAM_ID, &name).await;
        }
    }
}

async fn open_store(encryption_key: &str) -> ConfigStore {
    let key_bytes = match hex::decode(encryption_key) {
        Ok(b) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            k
        }
        _ => {
            eprintln!("Error: TAP_ENCRYPTION_KEY must be 64 hex chars (32 bytes)");
            std::process::exit(1);
        }
    };
    let database_url = std::env::var("POSTGRES_DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("Error: POSTGRES_DATABASE_URL environment variable is required");
        std::process::exit(1);
    });
    let store = match ConfigStore::new(&database_url, key_bytes).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error connecting to database: {e}");
            std::process::exit(1);
        }
    };
    // Self-hosted deployments have no signup flow to create a team, so the CLI
    // owns bootstrapping its default team.
    if let Err(e) = store.ensure_team(DEFAULT_TEAM_ID, DEFAULT_TEAM_ID).await {
        eprintln!("Error ensuring default team: {e}");
        std::process::exit(1);
    }
    store
}

use tap_core::store::ConfigStore;

const DEFAULT_TEAM_ID: &str = "default";

async fn cmd_agent(action: AgentAction) {
    match action {
        AgentAction::List { encryption_key } => {
            let store = open_store(&encryption_key).await;
            agent_cmd::list(&store, DEFAULT_TEAM_ID).await;
        }
        AgentAction::Create {
            encryption_key,
            name,
            description,
            roles,
            credentials,
            rate_limit,
        } => {
            let store = open_store(&encryption_key).await;
            agent_cmd::create(
                &store,
                DEFAULT_TEAM_ID,
                &name,
                description.as_deref(),
                &roles,
                &credentials,
                rate_limit,
            )
            .await;
        }
        AgentAction::Show {
            encryption_key,
            name,
        } => {
            let store = open_store(&encryption_key).await;
            agent_cmd::show(&store, DEFAULT_TEAM_ID, &name).await;
        }
        AgentAction::Disable {
            encryption_key,
            name,
        } => {
            let store = open_store(&encryption_key).await;
            agent_cmd::disable(&store, DEFAULT_TEAM_ID, &name).await;
        }
        AgentAction::Enable {
            encryption_key,
            name,
        } => {
            let store = open_store(&encryption_key).await;
            agent_cmd::enable(&store, DEFAULT_TEAM_ID, &name).await;
        }
        AgentAction::Delete {
            encryption_key,
            name,
        } => {
            let store = open_store(&encryption_key).await;
            agent_cmd::delete(&store, DEFAULT_TEAM_ID, &name).await;
        }
    }
}

async fn cmd_role(action: RoleAction) {
    match action {
        RoleAction::List { encryption_key } => {
            let store = open_store(&encryption_key).await;
            role_cmd::list(&store, DEFAULT_TEAM_ID).await;
        }
        RoleAction::Create {
            encryption_key,
            name,
            description,
            credentials,
            rate_limit,
        } => {
            let store = open_store(&encryption_key).await;
            role_cmd::create(
                &store,
                DEFAULT_TEAM_ID,
                &name,
                description.as_deref(),
                &credentials,
                rate_limit,
            )
            .await;
        }
        RoleAction::AddCredential {
            encryption_key,
            role,
            credential,
        } => {
            let store = open_store(&encryption_key).await;
            role_cmd::add_credential(&store, DEFAULT_TEAM_ID, &role, &credential).await;
        }
        RoleAction::RemoveCredential {
            encryption_key,
            role,
            credential,
        } => {
            let store = open_store(&encryption_key).await;
            role_cmd::remove_credential(&store, DEFAULT_TEAM_ID, &role, &credential).await;
        }
        RoleAction::Delete {
            encryption_key,
            name,
        } => {
            let store = open_store(&encryption_key).await;
            role_cmd::delete(&store, DEFAULT_TEAM_ID, &name).await;
        }
    }
}

async fn cmd_status(proxy_url: &str) {
    println!("TAP Status");
    println!("===============");
    let health_url = format!("{proxy_url}/health");
    match reqwest::get(&health_url).await {
        Ok(resp) if resp.status().is_success() => {
            println!("  {health_url} -> OK");
        }
        Ok(resp) => {
            println!("  {health_url} -> HTTP {}", resp.status());
        }
        Err(e) => {
            println!("  {health_url} -> UNREACHABLE ({e})");
        }
    }
}

fn cmd_logs(log_file: &Path, tail: usize) {
    let content = match std::fs::read_to_string(log_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: cannot read {}: {e}", log_file.display());
            std::process::exit(1);
        }
    };

    let lines: Vec<&str> = content.lines().collect();
    let display_lines = if tail > 0 && lines.len() > tail {
        &lines[lines.len() - tail..]
    } else {
        &lines[..]
    };

    if display_lines.is_empty() {
        println!("No audit log entries found.");
        return;
    }

    for line in display_lines {
        match logs::parse_log_line(line) {
            Ok(entry) => println!("{}", logs::format_entry(&entry)),
            Err(_) => eprintln!("  (skipped malformed line)"),
        }
    }
}

async fn cmd_add(
    encryption_key: &str,
    name: Option<String>,
    description: Option<String>,
    auth: Option<String>,
    api_base: Option<String>,
    relative_target: bool,
    value: Option<String>,
) {
    let interactive = name.is_none() || description.is_none() || auth.is_none();
    let result = if let (Some(name), Some(desc), Some(auth_type)) = (name, description, auth) {
        match add::from_flags(name, desc, &auth_type, api_base, relative_target) {
            Some(r) => r,
            None => std::process::exit(1),
        }
    } else {
        match add::interactive_add() {
            Some(r) => r,
            None => std::process::exit(1),
        }
    };

    // The proxy only reads credential values from the database, so a
    // credential without a value can't forward anything. Collect it here when
    // we're already talking to a human.
    let value = match (value, interactive) {
        (Some(v), _) => Some(v),
        (None, true) => {
            let v = add::prompt_value(&result.auth_method);
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        (None, false) => None,
    };
    if value.is_none() {
        eprintln!(
            "Warning: no --value supplied — credential '{}' is stored without a secret and can't forward requests until one is set.",
            result.name
        );
    }

    let store = open_store(encryption_key).await;
    let connector = match result.auth_method {
        add::AuthMethod::ApiKey => "direct",
        _ => "sidecar",
    };
    match store
        .create_credential(
            DEFAULT_TEAM_ID,
            &result.name,
            &result.description,
            connector,
            result.api_base.as_deref(),
            relative_target,
            None,
            None,
            value.as_deref().map(str::as_bytes),
        )
        .await
    {
        Ok(()) => add::print_instructions(&result, value.is_some()),
        Err(e) => {
            eprintln!("Error creating credential: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_status_subcommand_parses() {
        let cli = Cli::try_parse_from(["tap", "status"]).unwrap();
        assert!(matches!(cli.command, Commands::Status { .. }));
    }

    #[test]
    fn cli_status_with_account_parses() {
        let cli = Cli::try_parse_from(["tap", "status", "--account", "work"]).unwrap();
        match cli.command {
            Commands::Status { account } => {
                assert_eq!(account.as_deref(), Some("work"));
            }
            _ => panic!("Expected Status"),
        }
    }

    #[test]
    fn cli_logs_subcommand_parses() {
        let cli = Cli::try_parse_from(["tap", "logs"]).unwrap();
        assert!(matches!(cli.command, Commands::Logs { .. }));
    }

    #[test]
    fn cli_logs_with_tail_parses() {
        let cli = Cli::try_parse_from(["tap", "logs", "--tail", "50"]).unwrap();
        match cli.command {
            Commands::Logs { tail, .. } => assert_eq!(tail, 50),
            _ => panic!("Expected Logs"),
        }
    }

    #[test]
    fn cli_add_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "tap",
            "add",
            "--encryption-key",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .unwrap();
        assert!(matches!(cli.command, Commands::Add { .. }));
    }

    #[test]
    fn cli_add_with_flags_parses() {
        let cli = Cli::try_parse_from([
            "tap",
            "add",
            "--encryption-key",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--name",
            "my-api",
            "--description",
            "My API",
            "--auth",
            "api-key",
            "--api-base",
            "https://api.example.com",
        ])
        .unwrap();
        match cli.command {
            Commands::Add {
                name,
                description,
                auth,
                api_base,
                relative_target,
                ..
            } => {
                assert_eq!(name.unwrap(), "my-api");
                assert_eq!(description.unwrap(), "My API");
                assert_eq!(auth.unwrap(), "api-key");
                assert_eq!(api_base.unwrap(), "https://api.example.com");
                assert!(!relative_target);
            }
            _ => panic!("Expected Add"),
        }
    }

    #[test]
    fn cli_unknown_subcommand_errors() {
        let result = Cli::try_parse_from(["tap", "deploy"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_help_does_not_panic() {
        // --help causes clap to exit, so we just check try_parse doesn't panic
        let result = Cli::try_parse_from(["tap", "--help"]);
        // This returns Err because --help triggers early exit in clap
        assert!(result.is_err());
    }
}
