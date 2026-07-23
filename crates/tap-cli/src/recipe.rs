//! `tap recipe` — one-command use-case setup ("starter packs").
//!
//! A recipe is a curated pack for ONE use case (e.g. "scan your email for
//! invoices and pay them"). `tap recipe run <name>` connects you if needed and
//! sets up every credential the use case requires — each via the dashboard-free,
//! passkey-gated `tap cred set` (or an OAuth consent link) — then hands you a
//! ready-to-paste prompt so your agent can do the task. The point is speed: zero
//! → working agent in one command.
//!
//! v1 keeps the catalog as in-code data. Adding a recipe = adding an entry.

use crate::auth::{load_config, resolve_account};
use crate::cred::{cmd_cred_oauth, cmd_cred_set, CredOauthOpts, CredSetOpts};

/// How a credential is provisioned.
#[derive(Clone, Copy, PartialEq)]
pub enum CredKind {
    /// A plain API-key/token secret → `tap cred set` (hidden prompt + passkey).
    ApiKey,
    /// An OAuth service (Google, etc.) → dashboard consent flow.
    OAuth,
}

pub struct RecipeCred {
    pub name: &'static str,
    pub host: &'static str,
    pub kind: CredKind,
    /// Gate every agent action on this credential behind a passkey approval —
    /// true for money-moving / high-stakes creds (e.g. a bank), false for reads.
    pub require_passkey: bool,
    /// OAuth scope bundle ids (from the proxy's `GOOGLE_SCOPE_BUNDLES`) to request
    /// — least privilege for the use case. Empty ⇒ the connect page's default.
    /// Ignored for API-key creds.
    pub scopes: &'static [&'static str],
    /// Auth header template for API-key creds (e.g. "Bot {value}" for Discord).
    /// None ⇒ the proxy default (Bearer).
    pub header_format: Option<&'static str>,
    /// Set for API-key creds whose stored value is a JSON bundle the proxy
    /// recognizes and signs with (e.g. the Twitter OAuth 1.0a 4-field bundle) —
    /// `tap cred set` then flags the sidecar connector so routing detects it.
    pub api_base: Option<&'static str>,
    pub note: &'static str,
}

/// A platform variant of a recipe (same use case, different service) — e.g. the
/// social ghostwriter on Mastodon vs Discord vs X. `run` asks which one.
pub struct RecipeFlavor {
    pub id: &'static str,
    pub label: &'static str,
    pub credentials: &'static [RecipeCred],
    pub prompt: &'static str,
}

pub struct Recipe {
    pub name: &'static str,
    pub pitch: &'static str,
    /// Used when `flavors` is empty; otherwise each flavor carries its own.
    pub credentials: &'static [RecipeCred],
    /// The task prompt handed to the user's coding agent once setup is done.
    pub prompt: &'static str,
    /// Platform variants. Non-empty ⇒ `run` prompts for one and uses the
    /// flavor's credentials + prompt instead of the recipe-level ones.
    pub flavors: &'static [RecipeFlavor],
    /// Manual dashboard steps printed after a successful setup — for the policy
    /// bits the CLI rails can't set yet (e.g. auto-approve URL patterns).
    pub post_setup: &'static [&'static str],
}

/// The curated catalog. One entry per use case.
pub fn catalog() -> &'static [Recipe] {
    &[
        Recipe {
            name: "invoice-payer",
            pitch: "Scan your email for invoices and pay them from your bank",
            credentials: &[
                RecipeCred {
                    name: "gmail",
                    host: "gmail.googleapis.com",
                    kind: CredKind::OAuth,
                    require_passkey: false,
                    // Read-only: the recipe only scans for invoices, never sends/deletes.
                    scopes: &["gmail-readonly"],
                    header_format: None,
                    api_base: None,
                    note: "read your inbox for invoices",
                },
                RecipeCred {
                    name: "mercury",
                    host: "api.mercury.com",
                    kind: CredKind::ApiKey,
                    require_passkey: true,
                    scopes: &[],
                    header_format: None,
                    api_base: None,
                    note: "pay invoices from your bank — every payment needs your passkey",
                },
            ],
            prompt: "You are an invoice assistant with TAP access to Gmail (read) and \
Mercury (payments). Search Gmail for unpaid invoices, extract the amount, payee, \
and due date for each, show me a summary, and — once I confirm — pay each via \
Mercury. Every payment is gated behind my passkey approval, so send them through \
TAP and wait for me to approve.",
            flavors: &[],
            post_setup: &[],
        },
        Recipe {
            name: "social-ghostwriter",
            pitch: "Draft and publish social posts — nothing goes out without your tap",
            credentials: &[],
            prompt: "",
            flavors: &[
                RecipeFlavor {
                    id: "mastodon",
                    label: "Mastodon (free API — access token)",
                    credentials: &[RecipeCred {
                        name: "mastodon",
                        host: "mastodon.social",
                        kind: CredKind::ApiKey,
                        require_passkey: false,
                        scopes: &[],
                        header_format: None,
                        api_base: None,
                        note: "your access token (Preferences → Development). On another \
instance? Edit the credential's allowed host in the dashboard after",
                    }],
                    prompt: "You are my social ghostwriter with TAP access to Mastodon \
(credential 'mastodon'). Read my notifications and recent posts — reads are instant — \
then draft replies and posts. Publishing is the chokepoint: every status POST goes \
through TAP approval showing the exact text, so publish one at a time and wait for \
my tap before the next.",
                },
                RecipeFlavor {
                    id: "discord",
                    label: "Discord (free API — bot token)",
                    credentials: &[RecipeCred {
                        name: "discord-bot",
                        host: "discord.com",
                        kind: CredKind::ApiKey,
                        require_passkey: false,
                        scopes: &[],
                        // Discord bot auth is `Authorization: Bot <token>`.
                        header_format: Some("Bot {value}"),
                        api_base: None,
                        note: "your bot token (discord.com/developers) — announcements \
only go out after your tap",
                    }],
                    prompt: "You are my community announcer with TAP access to a Discord \
bot (credential 'discord-bot'). Read the channels the bot can see to catch up — reads \
are instant — and draft the announcements or replies I ask for. Every message send \
goes through TAP approval showing the exact text, so post one at a time and wait for \
my tap before the next.",
                },
                RecipeFlavor {
                    id: "x",
                    label: "X / Twitter (paid API — OAuth 1.0a bundle)",
                    credentials: &[RecipeCred {
                        name: "twitter",
                        host: "api.x.com",
                        kind: CredKind::ApiKey,
                        require_passkey: false,
                        scopes: &[],
                        header_format: None,
                        // The stored value is the 4-field OAuth 1.0a JSON bundle; the
                        // sidecar connector makes routing detect it and sign per request.
                        api_base: Some("https://api.x.com"),
                        note: "paste your OAuth 1.0a JSON bundle: {\"consumer_key\":…, \
\"consumer_secret\":…, \"access_token\":…, \"access_token_secret\":…}",
                    }],
                    prompt: "You are my social ghostwriter with TAP access to X/Twitter \
(credential 'twitter'). Read my mentions and timeline — reads are instant — then draft \
replies and tweets. Publishing is the chokepoint: every tweet POST goes through TAP \
approval showing the exact text, so publish one at a time and wait for my tap before \
the next.",
                },
            ],
            post_setup: &[],
        },
        Recipe {
            name: "pr-ci-copilot",
            pitch: "Triage your PRs and CI; repo actions only run on your approval",
            credentials: &[RecipeCred {
                name: "github",
                host: "api.github.com",
                kind: CredKind::ApiKey,
                require_passkey: false,
                scopes: &[],
                header_format: None,
                api_base: None,
                note: "a fine-grained personal access token \
(github.com/settings/personal-access-tokens) with repo + actions access",
            }],
            prompt: "You are my repo copilot with TAP access to the GitHub API \
(credential 'github'). Triage my repos: list open PRs, failing checks, and reviews \
waiting on me — reads are instant — and give me a \"what's blocking\" summary. When I \
ask you to act — re-run a failed workflow, merge an approved green PR, post a comment \
— each write goes through TAP approval, so fire it and wait for my tap before the \
next action.",
            flavors: &[],
            post_setup: &[],
        },
        Recipe {
            name: "support-refund-agent",
            pitch: "Review Stripe disputes and refund customers — passkey on every refund",
            credentials: &[RecipeCred {
                name: "stripe",
                host: "api.stripe.com",
                kind: CredKind::ApiKey,
                // Money leaves on a POST here — same tier as the bank cred above.
                require_passkey: true,
                scopes: &[],
                header_format: None,
                api_base: None,
                note: "your Stripe secret key (a test-mode key works for trying it) — \
every refund needs your passkey",
            }],
            prompt: "You are my support assistant with TAP access to Stripe (credential \
'stripe'). Review recent charges and disputes — reads are instant — and flag which \
refund requests look legitimate, with your reasoning. Once I agree, process each \
refund via TAP: refunds are passkey-gated, so send the refund POST, then wait for me \
to approve it with my passkey. One refund at a time, never batch.",
            flavors: &[],
            post_setup: &[],
        },
        Recipe {
            name: "meeting-scheduler",
            pitch: "Negotiate meeting times over email and manage your calendar itself",
            credentials: &[RecipeCred {
                name: "google-scheduler",
                host: "*.googleapis.com",
                kind: CredKind::OAuth,
                require_passkey: false,
                // One Google credential, two APIs: full Gmail (it must SEND the
                // scheduling emails — each send is still approval-gated) + Calendar.
                scopes: &["gmail", "calendar"],
                header_format: None,
                api_base: None,
                note: "read your calendar, email invitees (every send needs your tap), \
and manage events",
            }],
            prompt: "You are my scheduling assistant with TAP access to Google \
(credential 'google-scheduler': Gmail + Calendar). To schedule a meeting: check my \
calendar for free slots — reads are instant — then email the invitee two or three \
options. Every outgoing email is approval-gated, so send it via TAP and wait for my \
tap. Read their reply, and once a time is agreed, create the calendar event yourself \
with sendUpdates=none (event writes on my own calendar are auto-approved once the \
policy below is set), then send a short confirmation email (gated, like every email). \
Never send an email without my approval; the calendar is yours to manage.",
            flavors: &[],
            post_setup: &[
                "To let the agent create/update events autonomously (the point of this \
recipe), add these auto-approve URL patterns to the 'google-scheduler' policy in the \
dashboard (Policies tab):",
                "    www.googleapis.com/calendar/v3/freeBusy",
                "    www.googleapis.com/calendar/v3/calendars/primary/events",
                "Emails are NOT affected: every Gmail send stays approval-gated — that's \
this recipe's chokepoint.",
            ],
        },
    ]
}

fn find(name: &str) -> Option<&'static Recipe> {
    catalog().iter().find(|r| r.name == name)
}

fn print_cred_line(c: &RecipeCred, indent: &str) {
    let kind = match c.kind {
        CredKind::ApiKey => "API key",
        CredKind::OAuth => "OAuth",
    };
    println!("{indent}• {:<16} ({}) → {}  [{}]", c.name, kind, c.host, c.note);
}

pub fn cmd_list() {
    println!();
    println!("  Available recipes (one-command use-case setup):");
    println!();
    for r in catalog() {
        println!("    {:<22} {}", r.name, r.pitch);
    }
    println!();
    println!("  Run one with:  tap recipe run <name>");
    println!();
}

pub fn cmd_show(name: &str) {
    let Some(r) = find(name) else {
        eprintln!("No such recipe: {name}. Try `tap recipe list`.");
        return;
    };
    println!();
    println!("  {}  —  {}", r.name, r.pitch);
    println!();
    if r.flavors.is_empty() {
        println!("  Sets up:");
        for c in r.credentials {
            print_cred_line(c, "    ");
        }
        println!();
        println!("  Then your agent runs:");
        println!("    {}", r.prompt);
    } else {
        println!("  Comes in {} flavors (run asks which):", r.flavors.len());
        for f in r.flavors {
            println!();
            println!("    {} — {}", f.id, f.label);
            for c in f.credentials {
                print_cred_line(c, "      ");
            }
        }
    }
    println!();
}

/// Ask the user to pick a flavor (by number or id). None ⇒ no/invalid choice.
fn pick_flavor(flavors: &'static [RecipeFlavor]) -> Option<&'static RecipeFlavor> {
    use std::io::Write;
    println!("  This recipe comes in {} flavors:", flavors.len());
    for (i, f) in flavors.iter().enumerate() {
        println!("    {}. {:<10} {}", i + 1, f.id, f.label);
    }
    print!("  Pick one [1-{}]: ", flavors.len());
    let _ = std::io::stdout().flush();
    let mut ans = String::new();
    let _ = std::io::stdin().read_line(&mut ans);
    let ans = ans.trim().to_ascii_lowercase();
    let by_number = ans
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| flavors.get(i));
    let picked = by_number.or_else(|| flavors.iter().find(|f| f.id == ans))?;
    println!("  → {}", picked.id);
    println!();
    Some(picked)
}

pub async fn cmd_run(name: &str, account: Option<String>) {
    let Some(r) = find(name) else {
        eprintln!("No such recipe: {name}. Try `tap recipe list`.");
        return;
    };

    println!();
    println!("  ▶ Setting up “{}” — {}", r.name, r.pitch);
    println!();

    // 1. Make sure we're connected. The recipe can't set anything up without a
    //    session; `cmd_cred_set`/`cmd_cred_oauth` also check, but fail early with
    //    a clear message.
    let cfg = load_config();
    if resolve_account(&cfg, account.clone()).is_none() {
        eprintln!("  You're not logged in. Run `tap login` first, then re-run this recipe.");
        return;
    }

    // 2. Flavored recipe? Same use case, different platform — pick one and use
    //    its credential set + prompt.
    let (creds, prompt): (&[RecipeCred], &str) = if r.flavors.is_empty() {
        (r.credentials, r.prompt)
    } else {
        let Some(f) = pick_flavor(r.flavors) else {
            eprintln!("  ✗ No flavor picked — aborting. Re-run `tap recipe run {}`.", r.name);
            return;
        };
        (f.credentials, f.prompt)
    };

    // 3. Provision each credential the use case needs.
    for (i, c) in creds.iter().enumerate() {
        println!("  [{}/{}] {} — {}", i + 1, creds.len(), c.name, c.note);
        match c.kind {
            CredKind::ApiKey => {
                // Reuse the dashboard-free, passkey-gated `tap cred set` flow.
                let ok = cmd_cred_set(CredSetOpts {
                    name: c.name.to_string(),
                    hosts: vec![c.host.to_string()],
                    description: Some(format!("{} (via {} recipe)", c.note, r.name)),
                    header_format: c.header_format.map(str::to_string),
                    api_base: c.api_base.map(str::to_string),
                    account: account.clone(),
                    stdin: false,
                    require_passkey: c.require_passkey,
                })
                .await;
                if !ok {
                    eprintln!(
                        "\n  ✗ Setup stopped — '{}' wasn't set up. Fix that, then re-run `tap recipe run {}`.",
                        c.name, r.name
                    );
                    return;
                }
            }
            CredKind::OAuth => {
                // Reuse the shared `tap cred oauth` flow: it opens the connect-
                // with-passkey page (agent choice + passkey → provider consent)
                // and confirms the connect before continuing. Least-privilege
                // scopes come from the catalog (e.g. gmail-readonly). Google is
                // the only wired provider today.
                let ok = cmd_cred_oauth(CredOauthOpts {
                    name: c.name.to_string(),
                    provider: "google".to_string(),
                    scopes: c.scopes.iter().map(|s| s.to_string()).collect(),
                    account: account.clone(),
                })
                .await;
                if !ok {
                    eprintln!(
                        "\n  ✗ Setup stopped — '{}' wasn't connected. Re-run `tap recipe run {}` when it is.",
                        c.name, r.name
                    );
                    return;
                }
            }
        }
        println!();
    }

    // 4. Any policy bits the CLI rails can't set yet — one copy-paste in the
    //    dashboard, spelled out instead of silently skipped.
    if !r.post_setup.is_empty() {
        println!("  One manual step:");
        for line in r.post_setup {
            println!("  {line}");
        }
        println!();
    }

    // 5. Hand the user the ready-to-use prompt for their coding agent. Each
    //    credential was granted to the agent key(s) chosen on its passkey page
    //    (the cred-set activation for API keys, the connect page for OAuth), so
    //    there's no separate wiring step — the privileged assign already happened
    //    in the browser under a passkey, where a scoped agent session can't reach.
    println!(
        "  These credentials were granted to the agent key(s) you selected. If you"
    );
    println!(
        "  didn't select one (or have none yet), assign them from the dashboard."
    );
    println!();
    println!("  ✓ “{}” is set up. Paste this to that agent to run it:", r.name);
    println!();
    println!("  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄");
    println!("  {}", prompt);
    println!("  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄");
    println!();
}
