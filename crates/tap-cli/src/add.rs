//! `tap add` — interactive credential setup.
//!
//! Collects service info and writes to the database via ConfigStore.

use std::io::{self, Write};

/// Auth method as presented to the user.
#[derive(Debug, Clone, Copy)]
pub enum AuthMethod {
    ApiKey,
    OAuth2,
    OAuth1,
    Custom,
    /// Cryptographic signing key (a signer, not a wallet — used via POST /sign).
    Signing,
}

/// Result of the interactive flow.
pub struct AddResult {
    pub name: String,
    pub description: String,
    pub auth_method: AuthMethod,
    pub api_base: Option<String>,
}

/// Prompt for a line of input with a label.
fn prompt(label: &str) -> String {
    print!("{label}: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

/// Prompt with a default value.
fn prompt_default(label: &str, default: &str) -> String {
    print!("{label} [{default}]: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let val = input.trim();
    if val.is_empty() {
        default.to_string()
    } else {
        val.to_string()
    }
}

/// Run the interactive add flow. Returns None if user cancels.
pub fn interactive_add() -> Option<AddResult> {
    println!("Add a new service to TAP");
    println!("=============================\n");

    let name = prompt("Service name (e.g., google-workspace, telegram, my-api)");
    if name.is_empty() {
        eprintln!("Name is required.");
        return None;
    }

    let description = prompt("Description (e.g., Gmail + Calendar + Drive)");
    if description.is_empty() {
        eprintln!("Description is required.");
        return None;
    }

    println!("\nHow does this service authenticate?");
    println!("  1) API key or bearer token (paste a key, works forever)");
    println!("  2) OAuth 2.0 (Google, GitHub — sign in once, auto-refreshes)");
    println!("  3) OAuth 1.0a (Twitter — signed requests)");
    println!("  4) Custom protocol (Telegram, Discord — needs a connector)");
    println!("  5) Cryptographic signing key (sign digests/messages — a signer, not a wallet)");

    let choice = prompt("\nChoice [1-5]");
    let auth_method = match choice.as_str() {
        "1" => AuthMethod::ApiKey,
        "2" => AuthMethod::OAuth2,
        "3" => AuthMethod::OAuth1,
        "4" => AuthMethod::Custom,
        "5" => AuthMethod::Signing,
        _ => {
            eprintln!("Invalid choice.");
            return None;
        }
    };

    let api_base = match auth_method {
        AuthMethod::ApiKey => {
            let base = prompt("API base URL (e.g., https://api.example.com)");
            if base.is_empty() {
                None
            } else {
                Some(base)
            }
        }
        // Google/Microsoft/Twitter OAuth are handled inline by the proxy —
        // it recognizes the JSON bundle stored as the credential value, so no
        // sidecar URL is needed.
        AuthMethod::OAuth2 | AuthMethod::OAuth1 => None,
        AuthMethod::Custom => {
            let url = prompt("Connector service URL (e.g., http://telegram-client:8082)");
            if url.is_empty() {
                eprintln!("URL is required for custom connectors.");
                return None;
            }
            Some(url)
        }
        // Signing keys have no HTTP upstream; the sentinel marks them so /forward
        // redirects to POST /sign.
        AuthMethod::Signing => Some("tap:sign".to_string()),
    };

    Some(AddResult {
        name,
        description,
        auth_method,
        api_base,
    })
}

/// Non-interactive add from CLI flags.
pub fn from_flags(
    name: String,
    description: String,
    auth: &str,
    api_base: Option<String>,
    _relative_target: bool,
) -> Option<AddResult> {
    let auth_method = match auth {
        "api-key" | "token" | "bearer" => AuthMethod::ApiKey,
        "oauth2" => AuthMethod::OAuth2,
        "oauth1" => AuthMethod::OAuth1,
        "custom" => AuthMethod::Custom,
        "signing" | "signer" => AuthMethod::Signing,
        _ => {
            eprintln!("Unknown auth type: {auth}. Use: api-key, oauth2, oauth1, custom, signing");
            return None;
        }
    };
    // Signing keys carry a non-HTTP sentinel api_base.
    let api_base = if matches!(auth_method, AuthMethod::Signing) {
        Some("tap:sign".to_string())
    } else {
        api_base
    };

    Some(AddResult {
        name,
        description,
        auth_method,
        api_base,
    })
}

/// Prompt for the secret value appropriate to the auth method. The value is
/// stored AES-256-GCM-encrypted in the database — the proxy no longer reads
/// `TAP_CRED_*` environment variables.
pub fn prompt_value(auth_method: &AuthMethod) -> String {
    let label = match auth_method {
        AuthMethod::ApiKey => "API key / token (stored encrypted; empty to skip)",
        AuthMethod::OAuth2 => {
            "OAuth2 JSON bundle {\"client_id\",\"client_secret\",\"refresh_token\"} (empty to skip)"
        }
        AuthMethod::OAuth1 => {
            "OAuth 1.0a JSON bundle {\"consumer_key\",\"consumer_secret\",\"access_token\",\"access_token_secret\"} (empty to skip)"
        }
        AuthMethod::Custom => "Credential value for the connector (empty to skip)",
        AuthMethod::Signing => {
            "Signing key JSON bundle {\"algorithm\",\"private_key\",\"key_encoding\"} (empty to skip)"
        }
    };
    prompt(label)
}

/// Print post-add instructions.
pub fn print_instructions(result: &AddResult, value_stored: bool) {
    println!("\n✓ Service '{}' configured\n", result.name);

    if !value_stored && !matches!(result.auth_method, AuthMethod::Signing) {
        println!("No secret stored yet — re-run with --value to set one:");
        println!("  tap add --name {} ... --value <secret>", result.name);
        println!();
    }

    match result.auth_method {
        AuthMethod::ApiKey | AuthMethod::OAuth2 | AuthMethod::OAuth1 | AuthMethod::Custom => {
            println!("Next steps:");
            println!(
                "  1. Assign '{}' to an agent: tap agent create --name my-agent --credentials {}",
                result.name, result.name
            );
            println!("  2. Configure policies via the team API (defaults: reads auto-approved, writes need approval)");
            println!("  3. The proxy picks up DB changes automatically — no restart needed");
        }
        AuthMethod::Signing => {
            println!("Next steps (a signer, not a wallet — used via POST /sign):");
            println!("  1. Store the key as a JSON bundle via --value:");
            println!("       {{\"algorithm\":\"secp256k1|ed25519|p256\",\"private_key\":\"...\",\"key_encoding\":\"hex\"}}");
            println!("     It is stored encrypted; only signatures ever leave TAP.");
            println!(
                "  2. Assign '{}' to agents via: tap agent create --credentials {}",
                result.name, result.name
            );
            println!(
                "  3. Sign: POST /sign with X-TAP-Credential and {{payload, encoding, prehash}}."
            );
            println!("     secp256k1/p256 sign a 32-byte digest; ed25519 signs the message.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_flags_api_key() {
        let r = from_flags(
            "test".to_string(),
            "Test".to_string(),
            "api-key",
            Some("https://api.example.com".to_string()),
            false,
        )
        .unwrap();
        assert!(matches!(r.auth_method, AuthMethod::ApiKey));
        assert_eq!(r.name, "test");
    }

    #[test]
    fn from_flags_oauth2() {
        let r = from_flags(
            "google".to_string(),
            "Google".to_string(),
            "oauth2",
            Some("http://oauth2-refresher:8081".to_string()),
            false,
        )
        .unwrap();
        assert!(matches!(r.auth_method, AuthMethod::OAuth2));
    }

    #[test]
    fn from_flags_unknown_auth_returns_none() {
        let r = from_flags("test".to_string(), "Test".to_string(), "magic", None, false);
        assert!(r.is_none());
    }
}
