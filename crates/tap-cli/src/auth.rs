//! User-facing web-auth CLI: `tap login` (device flow), whoami, logout, account.
//!
//! The session TOKEN is stored in the OS secret store (keyring), never on disk.
//! `~/.tap/config.json` holds only non-secret metadata (accounts + the active
//! pointer), so a leaked config file carries no bearer token.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

const KEYRING_SERVICE: &str = "tap-cli";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub active: Option<String>,
    #[serde(default)]
    pub accounts: BTreeMap<String, Account>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub proxy: String,
    pub email: String,
    pub team_id: String,
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
fn config_dir() -> PathBuf {
    home_dir().join(".tap")
}
fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

pub fn load_config() -> Config {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_config(cfg: &Config) -> std::io::Result<()> {
    std::fs::create_dir_all(config_dir())?;
    let path = config_path();
    std::fs::write(&path, serde_json::to_string_pretty(cfg).unwrap())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// -- Token storage: OS secret store only, never the config file. --------------

fn store_token(account: &str, token: &str) -> keyring::Result<()> {
    keyring::Entry::new(KEYRING_SERVICE, account)?.set_password(token)
}
pub(crate) fn get_token(account: &str) -> keyring::Result<String> {
    keyring::Entry::new(KEYRING_SERVICE, account)?.get_password()
}
fn delete_token(account: &str) {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, account) {
        let _ = entry.delete_password();
    }
}

pub(crate) fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

fn format_code(raw: &str) -> String {
    if raw.len() > 4 {
        format!("{}-{}", &raw[..4], &raw[4..])
    } else {
        raw.to_string()
    }
}

pub(crate) fn resolve_account(cfg: &Config, override_name: Option<String>) -> Option<String> {
    override_name.or_else(|| cfg.active.clone())
}

// -- Commands -----------------------------------------------------------------

pub async fn cmd_login(proxy: &str, as_profile: Option<String>) {
    let proxy = proxy.trim_end_matches('/').to_string();
    let client = reqwest::Client::new();

    // 1. Start the device authorization.
    let auth: serde_json::Value = match client.post(format!("{proxy}/device/authorize")).send().await
    {
        Ok(r) => match r.json().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Unexpected response from proxy: {e}");
                return;
            }
        },
        Err(e) => {
            eprintln!("Could not reach {proxy}: {e}");
            return;
        }
    };
    let device_code = auth["device_code"].as_str().unwrap_or_default().to_string();
    let user_code = auth["user_code"].as_str().unwrap_or_default().to_string();
    let interval = auth["interval"].as_u64().unwrap_or(3).max(1);
    let expires_in = auth["expires_in"].as_u64().unwrap_or(600);
    if device_code.is_empty() || user_code.is_empty() {
        eprintln!("Proxy did not return a device code. Is this a TAP proxy?");
        return;
    }
    // Never let server-provided strings reach a shell: the code must be plain
    // alphanumeric, and we build the URL from our own pinned proxy + a FIXED path
    // (never a server-provided path) so a rogue proxy can't inject via open_browser.
    if !user_code.chars().all(|c| c.is_ascii_alphanumeric()) {
        eprintln!("Proxy returned a malformed user code — aborting.");
        return;
    }
    let verify_url = format!("{proxy}/dashboard#/device?code={user_code}");

    println!();
    println!("  To finish signing in, open this URL in your browser:");
    println!("      {verify_url}");
    println!();
    println!("  and confirm this code:   {}", format_code(&user_code));
    println!();
    println!("  Waiting for you to approve in the browser…");
    open_browser(&verify_url);

    // 2. Poll for the session (minted server-side once you approve).
    let mut waited = 0u64;
    let session = loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        waited += interval;
        if waited > expires_in {
            eprintln!("\nTimed out waiting for approval. Run `tap login` again.");
            return;
        }
        let resp = match client
            .post(format!("{proxy}/device/token"))
            .json(&serde_json::json!({ "device_code": device_code }))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("\nNetwork error while polling: {e}");
                return;
            }
        };
        let status = resp.status();
        if status.as_u16() == 202 {
            continue; // authorization_pending
        } else if status.is_success() {
            match resp.json::<serde_json::Value>().await {
                Ok(v) => break v,
                Err(e) => {
                    eprintln!("\nUnexpected token response: {e}");
                    return;
                }
            }
        } else if status.as_u16() == 403 {
            eprintln!("\nApproval was denied.");
            return;
        } else {
            eprintln!("\nCode expired or invalid. Run `tap login` again.");
            return;
        }
    };

    let token = session["session_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let email = session["email"].as_str().unwrap_or("").to_string();
    let team_id = session["team_id"].as_str().unwrap_or("").to_string();
    if token.is_empty() {
        eprintln!("\nProxy did not return a session token.");
        return;
    }

    let profile = as_profile.unwrap_or_else(|| {
        if email.is_empty() {
            "default".to_string()
        } else {
            email.clone()
        }
    });

    if let Err(e) = store_token(&profile, &token) {
        eprintln!("\nCould not store the session in the OS keychain: {e}");
        eprintln!("  (On Linux this needs a running Secret Service / gnome-keyring.)");
        return;
    }
    let mut cfg = load_config();
    cfg.accounts.insert(
        profile.clone(),
        Account {
            proxy: proxy.clone(),
            email: email.clone(),
            team_id,
        },
    );
    cfg.active = Some(profile.clone());
    if let Err(e) = save_config(&cfg) {
        eprintln!("\nLogged in but failed to save config: {e}");
        return;
    }

    println!("\n✓ Logged in as {email}  (profile: {profile})");
    println!("  {proxy}");
}

pub async fn cmd_whoami(account: Option<String>) {
    let cfg = load_config();
    let Some(name) = resolve_account(&cfg, account) else {
        eprintln!("Not logged in. Run `tap login`.");
        return;
    };
    let Some(acct) = cfg.accounts.get(&name) else {
        eprintln!("No such account: {name}");
        return;
    };
    let token = match get_token(&name) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("No stored session for '{name}'. Run `tap login`.");
            return;
        }
    };
    let client = reqwest::Client::new();
    let resp = match client
        .get(format!("{}/user/me", acct.proxy))
        .bearer_auth(&token)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Could not reach {}: {e}", acct.proxy);
            return;
        }
    };
    if !resp.status().is_success() {
        eprintln!(
            "Session invalid or expired ({}). Run `tap login`.",
            resp.status()
        );
        return;
    }
    let me: serde_json::Value = resp.json().await.unwrap_or_default();
    let active = cfg.active.as_deref() == Some(name.as_str());
    println!("Profile : {name}{}", if active { " (active)" } else { "" });
    println!("Email   : {}", me["email"].as_str().unwrap_or("?"));
    println!("Team    : {}", me["team_id"].as_str().unwrap_or("?"));
    println!("Role    : {}", me["member_role"].as_str().unwrap_or("?"));
    println!("Proxy   : {}", acct.proxy);
}

pub async fn cmd_logout(account: Option<String>) {
    let mut cfg = load_config();
    let Some(name) = resolve_account(&cfg, account) else {
        eprintln!("Not logged in.");
        return;
    };
    if let Some(acct) = cfg.accounts.get(&name).cloned() {
        if let Ok(token) = get_token(&name) {
            let client = reqwest::Client::new();
            let _ = client
                .post(format!("{}/logout", acct.proxy))
                .bearer_auth(&token)
                .send()
                .await;
        }
    }
    delete_token(&name);
    cfg.accounts.remove(&name);
    if cfg.active.as_deref() == Some(name.as_str()) {
        cfg.active = cfg.accounts.keys().next().cloned();
    }
    let _ = save_config(&cfg);
    println!("✓ Logged out '{name}'");
}

pub fn cmd_account_list() {
    let cfg = load_config();
    if cfg.accounts.is_empty() {
        println!("No accounts. Run `tap login`.");
        return;
    }
    for (name, a) in &cfg.accounts {
        let marker = if cfg.active.as_deref() == Some(name.as_str()) {
            "*"
        } else {
            " "
        };
        println!("{marker} {name}  {}  {}", a.email, a.proxy);
    }
}

pub fn cmd_account_use(name: &str) {
    let mut cfg = load_config();
    if !cfg.accounts.contains_key(name) {
        eprintln!("No such account: {name}");
        return;
    }
    cfg.active = Some(name.to_string());
    let _ = save_config(&cfg);
    println!("✓ Active account: {name}");
}

/// Live-probe one account: validate its stored session against /user/me. Returns
/// the fetched identity, or an error string describing why it's not usable.
async fn probe(name: &str, acct: &Account) -> Result<serde_json::Value, String> {
    let token = get_token(name).map_err(|_| "no stored session".to_string())?;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/user/me", acct.proxy))
        .bearer_auth(&token)
        .send()
        .await
        .map_err(|_| "proxy unreachable".to_string())?;
    if !resp.status().is_success() {
        return Err(format!("session {}", resp.status().as_u16()));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|_| "bad response".to_string())
}

/// `tap status` — show which account(s) you're logged in to and whether each
/// session is still valid (gh auth status style). The active one is marked →.
pub async fn cmd_status(_account: Option<String>) {
    let cfg = load_config();
    if cfg.accounts.is_empty() {
        println!("Not logged in. Run `tap login`.");
        return;
    }
    for (name, acct) in &cfg.accounts {
        let mark = if cfg.active.as_deref() == Some(name.as_str()) {
            "→"
        } else {
            " "
        };
        match probe(name, acct).await {
            Ok(me) => {
                println!("{mark} {name}  ✓ connected");
                println!("    {}", acct.proxy);
                println!(
                    "    email {}   team {}   role {}",
                    me["email"].as_str().unwrap_or(&acct.email),
                    me["team_id"].as_str().unwrap_or("?"),
                    me["member_role"].as_str().unwrap_or("?"),
                );
            }
            Err(e) => {
                println!("{mark} {name}  ✗ {e}");
                println!("    {}  — run `tap login`", acct.proxy);
            }
        }
    }
}
