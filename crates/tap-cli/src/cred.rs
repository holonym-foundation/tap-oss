//! `tap cred set` — dashboard-free credential setup.
//!
//! The secret is typed at a HIDDEN prompt (never argv, so never the shell
//! history or `ps`), sent to TAP over the `tap login` session, and stored
//! pending + encrypted. It becomes a live credential only after the human
//! approves it with a passkey on the dashboard. The agent never sees the secret;
//! it only suggests the command.

use crate::auth::{get_token, load_config, open_browser, resolve_account};
use std::time::Duration;

pub struct CredSetOpts {
    pub name: String,
    pub hosts: Vec<String>,
    pub description: Option<String>,
    pub header_format: Option<String>,
    pub api_base: Option<String>,
    pub account: Option<String>,
    pub stdin: bool,
    /// Gate every agent action on this credential behind a passkey approval.
    pub require_passkey: bool,
}

/// Returns true if the credential was staged and activated, false on any failure
/// (so callers like `tap recipe` can stop the flow instead of claiming success).
pub async fn cmd_cred_set(opts: CredSetOpts) -> bool {
    let cfg = load_config();
    let Some(profile) = resolve_account(&cfg, opts.account.clone()) else {
        eprintln!("Not logged in. Run `tap login` first.");
        return false;
    };
    let Some(acct) = cfg.accounts.get(&profile).cloned() else {
        eprintln!("No such account: {profile}");
        return false;
    };
    let token = match get_token(&profile) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("No stored session for '{profile}'. Run `tap login`.");
            return false;
        }
    };

    // Read the secret WITHOUT it ever reaching argv (shell history / ps).
    let secret = if opts.stdin {
        use std::io::Read;
        let mut s = String::new();
        if std::io::stdin().read_to_string(&mut s).is_err() {
            eprintln!("Failed to read the secret from stdin.");
            return false;
        }
        s.trim_end_matches(['\n', '\r']).to_string()
    } else {
        match rpassword::prompt_password(format!("Enter the secret for '{}' (hidden): ", opts.name)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Could not read the secret: {e}");
                return false;
            }
        }
    };
    if secret.is_empty() {
        eprintln!("No secret entered — aborting.");
        return false;
    }
    if opts.hosts.is_empty() {
        eprintln!(
            "  ⚠ No --host given: this credential won't be bound to a destination host.\n    Recommended: re-run with --host api.example.com so a rogue agent can't exfiltrate it."
        );
    }

    let proxy = acct.proxy.trim_end_matches('/').to_string();
    let client = reqwest::Client::new();

    // 1. Stage the pending credential over the session.
    let mut body = serde_json::json!({ "name": opts.name, "value": secret });
    if let Some(d) = &opts.description {
        body["description"] = serde_json::json!(d);
    }
    if let Some(f) = &opts.header_format {
        body["auth_header_format"] = serde_json::json!(f);
    }
    if let Some(a) = &opts.api_base {
        body["api_base"] = serde_json::json!(a);
        body["connector"] = serde_json::json!("sidecar");
    }
    if opts.require_passkey {
        body["require_passkey"] = serde_json::json!(true);
    }
    if !opts.hosts.is_empty() {
        body["allowed_hosts"] = serde_json::json!(opts.hosts);
    }

    let resp = match client
        .post(format!("{proxy}/cred/setup"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Could not reach {proxy}: {e}");
            return false;
        }
    };
    if resp.status().as_u16() == 401 {
        eprintln!("Session invalid or expired. Run `tap login`.");
        return false;
    }
    if !resp.status().is_success() {
        let msg = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or_else(|| "request rejected".into());
        eprintln!("Could not start credential setup: {msg}");
        return false;
    }
    let setup: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Unexpected response from proxy: {e}");
            return false;
        }
    };
    let setup_id = setup["setup_id"].as_str().unwrap_or_default().to_string();
    let interval = setup["interval"].as_u64().unwrap_or(3).max(1);
    let expires_in = setup["expires_in"].as_u64().unwrap_or(900);
    if setup_id.is_empty() {
        eprintln!("Proxy did not return a setup id.");
        return false;
    }
    // Never let a server-provided string reach a shell: the setup id must be
    // plain (alphanumeric + `-`/`_`), and we build the URL from our own pinned
    // proxy + a FIXED path — so a rogue/MITM'd proxy can't inject via the
    // `cmd /C start "" <url>` opener on Windows. Mirrors `tap login`.
    if !setup_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        eprintln!("Proxy returned a malformed setup id — aborting.");
        return false;
    }

    let verify_url = format!("{proxy}/dashboard#/cred-setup?id={setup_id}");
    println!();
    println!("  Secret received (encrypted, pending). To finish, approve it with your passkey:");
    println!("      {verify_url}");
    println!();
    println!("  Waiting for you to approve in the browser…");
    open_browser(&verify_url);

    // 2. Poll until the human activates it in the dashboard.
    let mut waited = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        waited += interval;
        if waited > expires_in {
            eprintln!("\nTimed out waiting for approval. Run the command again.");
            return false;
        }
        let r = match client
            .get(format!("{proxy}/cred/setup/{setup_id}"))
            .bearer_auth(&token)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("\nNetwork error while polling: {e}");
                return false;
            }
        };
        if !r.status().is_success() {
            eprintln!("\nThis setup is no longer available (expired or removed).");
            return false;
        }
        let v: serde_json::Value = match r.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        match v["status"].as_str().unwrap_or("") {
            "activated" => {
                println!("\n✓ Credential '{}' is live and ready to use.", opts.name);
                return true;
            }
            "expired" => {
                eprintln!("\nThis setup expired before it was approved. Run the command again.");
                return false;
            }
            _ => continue, // still pending
        }
    }
}

pub struct CredOauthOpts {
    pub name: String,
    /// OAuth provider — "google" today. Kept explicit so other providers
    /// (microsoft, …) can slot in without changing the command surface.
    pub provider: String,
    /// Least-privilege scope bundle ids (from the proxy's scope catalog).
    pub scopes: Vec<String>,
    pub account: Option<String>,
}

/// `tap cred oauth <name>` — set up an OAuth credential from the CLI. Unlike
/// `cred set` there is no secret to type: this opens the dashboard connect page,
/// where the human picks which agent key(s) get the credential and approves with
/// a passkey, and only then consents with the provider. The agent never drives
/// any of it. Returns true only on a human-confirmed connect (so `tap recipe`
/// can gate on it, exactly like `cmd_cred_set`).
pub async fn cmd_cred_oauth(opts: CredOauthOpts) -> bool {
    let cfg = load_config();
    let Some(profile) = resolve_account(&cfg, opts.account.clone()) else {
        eprintln!("Not logged in. Run `tap login` first.");
        return false;
    };
    let Some(acct) = cfg.accounts.get(&profile).cloned() else {
        eprintln!("No such account: {profile}");
        return false;
    };
    let proxy = acct.proxy.trim_end_matches('/').to_string();

    // Only Google is wired today; keep the surface open for other providers.
    let provider = opts.provider.trim().to_ascii_lowercase();
    let connect_path = match provider.as_str() {
        "google" | "gmail" => "connect-google",
        other => {
            eprintln!("OAuth provider '{other}' isn't supported yet (only 'google').");
            return false;
        }
    };

    // `name` and `scopes` are interpolated into the browser URL, which on Windows
    // is launched via `cmd /C start "" <url>` — so they must be plain tokens with
    // no shell metacharacters (same guard as `tap login`/`tap cred set`). The
    // name must also satisfy the server rule (lowercase alnum + hyphen).
    let name = opts.name.trim().to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        eprintln!("Credential name must be 1-64 lowercase letters, digits, or hyphens.");
        return false;
    }
    let mut clean_scopes = Vec::new();
    for s in &opts.scopes {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            eprintln!("Invalid scope bundle id: '{s}'.");
            return false;
        }
        clean_scopes.push(s.to_string());
    }

    let scope_q = if clean_scopes.is_empty() {
        String::new()
    } else {
        format!("&scopes={}", clean_scopes.join(","))
    };
    let url = format!("{proxy}/dashboard#/{connect_path}?name={name}{scope_q}");

    println!();
    println!("  Connecting “{name}” via {provider} OAuth.");
    println!("  In the browser: choose the agent key(s), approve with your passkey,");
    println!("  then complete the {provider} consent.");
    println!("      {url}");
    open_browser(&url);

    // The CLI runs on a scoped session that can't list credentials, so we can't
    // auto-verify. Ask the human — never assume success, or a denied/failed
    // consent would still read as "connected".
    use std::io::Write;
    print!("  Did the browser confirm “{name}” is connected? [y/N]: ");
    let _ = std::io::stdout().flush();
    let mut ans = String::new();
    let _ = std::io::stdin().read_line(&mut ans);
    let ans = ans.trim().to_ascii_lowercase();
    if ans != "y" && ans != "yes" {
        eprintln!("  ✗ “{name}” isn't connected. Re-run `tap cred oauth {name}` when it is.");
        return false;
    }
    println!("  ✓ “{name}” connected.");
    true
}
