//! Deterministic, template-based one-line summaries of proxied API calls.
//!
//! Approval surfaces (dashboard inbox, Telegram, Matrix) render the raw
//! method/URL/body; this module adds a human-readable "what does this call
//! actually do" line for well-known services, matched purely on
//! host + path + method + body fields. No LLM involved — the output is a
//! pure function of the request, so all surfaces show the same text.
//!
//! Summaries are plain text: callers are responsible for HTML escaping.
//! Unknown services return `None` and surfaces keep their existing rendering.

use crate::types::HttpMethod;

/// Truncation cap for interpolated user-controlled strings (subjects, message
/// texts, …) so a summary stays a one-liner.
const VALUE_MAX_CHARS: usize = 120;

/// Cap on decoded Gmail `raw` payloads — we only need the header block.
const GMAIL_RAW_DECODE_MAX: usize = 64 * 1024;

/// Produce a one-line, plain-text summary of what a proxied request does,
/// or `None` when the service/endpoint isn't recognized.
///
/// `body` is the pre-substitution body (placeholders, never real secrets).
pub fn summarize_request(
    target_url: &str,
    method: &HttpMethod,
    body: Option<&[u8]>,
) -> Option<String> {
    let (host, path) = host_and_path(target_url)?;
    let json = body.and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());

    match host.as_str() {
        "gmail.googleapis.com" => gmail(&path, method, json.as_ref()),
        "api.sendgrid.com" => sendgrid(&path, method, json.as_ref()),
        "slack.com" => slack(&path, method, json.as_ref()),
        "api.github.com" => github(&path, method, json.as_ref()),
        "api.stripe.com" => stripe(&path, method, body),
        "api.telegram.org" => telegram(&path, method, json.as_ref()),
        "api.x.com" | "api.twitter.com" => twitter(&path, method, json.as_ref()),
        "api.openai.com" | "api.anthropic.com" => llm(&path, method, json.as_ref()),
        _ => None,
    }
}

/// Extract (lowercased host, path without query/fragment) from an http(s) URL.
///
/// Parsing uses `url::Url` — the **same** WHATWG parser that reqwest (the code
/// that actually forwards the request) and the SSRF guard use — so the host the
/// approver is shown can never diverge from the host the request is sent to. A
/// hand-rolled parser that ended the authority at the first `/` (ignoring that
/// `\`, `?`, `#` also terminate it and `\` normalizes to `/`) let an agent craft
/// `https://evil.com\@gmail.googleapis.com/…` that rendered as gmail while
/// reqwest forwarded to evil.com — approver spoofing. A parse failure returns
/// `None` so the summary fails safe (no friendly line, just the raw URL) rather
/// than emitting a misleading action.
fn host_and_path(target_url: &str) -> Option<(String, String)> {
    let parsed = url::Url::parse(target_url).ok()?;
    let host = parsed.host_str()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_ascii_lowercase(), parsed.path().to_string()))
}

/// Sanitize an interpolated user value: single-line, truncated, and never a
/// credential placeholder. `None` means the whole matcher must bail.
///
/// Beyond whitespace normalization, this strips Unicode control characters and
/// bidirectional-format codepoints (the LRE/RLE/PDF/LRO/RLO block U+202A–U+202E
/// and the isolate block U+2066–U+2069). Without this an agent-supplied subject/
/// text/channel could embed a bidi override that visually reorders the rendered
/// "Action:" line — spoofing the approver into reading a different action than
/// the one actually forwarded.
fn clean(value: &str) -> Option<String> {
    if value.contains("<CREDENTIAL:") {
        return None;
    }
    let stripped: String = value.chars().filter(|c| !is_unsafe_display_char(*c)).collect();
    let one_line: String = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = one_line.chars().take(VALUE_MAX_CHARS).collect();
    if one_line.chars().count() > VALUE_MAX_CHARS {
        out.push('…');
    }
    Some(out)
}

/// True for control characters and bidirectional-format codepoints that must
/// never reach a rendered summary line. (`split_whitespace` already collapses
/// ordinary whitespace; this additionally removes non-whitespace controls and
/// the bidi-override/isolate codepoints used for visual-reordering spoofs.)
fn is_unsafe_display_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Join a recipient list as "a, b, c (+N more)".
fn join_recipients(recipients: &[String]) -> Option<String> {
    if recipients.is_empty() {
        return None;
    }
    let shown = recipients
        .iter()
        .take(3)
        .map(|r| clean(r))
        .collect::<Option<Vec<_>>>()?
        .join(", ");
    Some(if recipients.len() > 3 {
        format!("{shown} (+{} more)", recipients.len() - 3)
    } else {
        shown
    })
}

fn str_field<'a>(json: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    json?.get(key)?.as_str()
}

fn email_summary(to: &str, subject: Option<&str>, cc: Option<&str>) -> Option<String> {
    let to = clean(to)?;
    let mut msg = format!("Send an email to {to}");
    if let Some(subject) = subject {
        let subject = clean(subject)?;
        msg.push_str(&format!(" — subject \"{subject}\""));
    }
    if let Some(cc) = cc {
        let cc = clean(cc)?;
        msg.push_str(&format!(" (+cc {cc})"));
    }
    Some(msg)
}

// -- Gmail ----------------------------------------------------------------------

fn gmail(path: &str, method: &HttpMethod, json: Option<&serde_json::Value>) -> Option<String> {
    if *method != HttpMethod::Post || !path.contains("/messages/send") {
        return None;
    }
    let raw = str_field(json, "raw")?;
    let text = decode_base64url_capped(raw)?;
    // Scan the RFC822 header block (lines before the first blank line).
    let (mut to, mut cc, mut subject) = (None, None, None);
    for line in text.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("to") {
                to = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("cc") {
                cc = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("subject") {
                subject = Some(value.to_string());
            }
        }
    }
    email_summary(&to?, subject.as_deref(), cc.as_deref())
}

/// Padding-tolerant base64url decode, capped so a huge MIME payload can't
/// balloon the summary path. Returns lossy UTF-8 text.
fn decode_base64url_capped(raw: &str) -> Option<String> {
    if !raw.is_ascii() {
        return None;
    }
    let raw = raw.trim_end_matches('=');
    // 4 base64 chars decode to 3 bytes; cap the input to cap the output.
    let max_in = GMAIL_RAW_DECODE_MAX / 3 * 4;
    let slice = if raw.len() > max_in {
        &raw[..max_in - max_in % 4]
    } else {
        raw
    };
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD
        .decode(slice.as_bytes())
        .or_else(|_| STANDARD_NO_PAD.decode(slice.as_bytes()))
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

// -- SendGrid -------------------------------------------------------------------

fn sendgrid(path: &str, method: &HttpMethod, json: Option<&serde_json::Value>) -> Option<String> {
    if *method != HttpMethod::Post || !path.starts_with("/v3/mail/send") {
        return None;
    }
    let personalization = json?.get("personalizations")?.get(0)?;
    let recipients: Vec<String> = personalization
        .get("to")?
        .as_array()?
        .iter()
        .filter_map(|t| t.get("email")?.as_str().map(str::to_string))
        .collect();
    let to = join_recipients(&recipients)?;
    let subject = json
        .and_then(|j| j.get("subject"))
        .or_else(|| personalization.get("subject"))
        .and_then(|s| s.as_str());
    email_summary(&to, subject, None)
}

// -- Slack ----------------------------------------------------------------------

fn slack(path: &str, method: &HttpMethod, json: Option<&serde_json::Value>) -> Option<String> {
    if *method != HttpMethod::Post || !path.contains("/api/chat.postMessage") {
        return None;
    }
    let channel = clean(str_field(json, "channel")?)?;
    let text = clean(str_field(json, "text")?)?;
    Some(format!("Post a Slack message to {channel}: \"{text}\""))
}

// -- GitHub ---------------------------------------------------------------------

fn github(path: &str, method: &HttpMethod, json: Option<&serde_json::Value>) -> Option<String> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match (method, segments.as_slice()) {
        (HttpMethod::Post, ["repos", owner, repo, "issues"]) => {
            let title = clean(str_field(json, "title")?)?;
            let repo = clean(&format!("{owner}/{repo}"))?;
            Some(format!("Create a GitHub issue in {repo}: \"{title}\""))
        }
        (HttpMethod::Post, ["repos", owner, repo, "issues", number, "comments"]) => {
            let body = clean(str_field(json, "body")?)?;
            let target = clean(&format!("{owner}/{repo}#{number}"))?;
            Some(format!("Comment on {target}: \"{body}\""))
        }
        (HttpMethod::Post, ["repos", owner, repo, "pulls"]) => {
            let title = clean(str_field(json, "title")?)?;
            let repo = clean(&format!("{owner}/{repo}"))?;
            Some(format!("Open a pull request in {repo}: \"{title}\""))
        }
        (HttpMethod::Delete, ["repos", owner, repo]) => {
            let repo = clean(&format!("{owner}/{repo}"))?;
            Some(format!("\u{26a0} Delete the repository {repo}"))
        }
        _ => None,
    }
}

// -- Stripe (form-encoded bodies) -------------------------------------------------

fn stripe(path: &str, method: &HttpMethod, body: Option<&[u8]>) -> Option<String> {
    if *method != HttpMethod::Post {
        return None;
    }
    let form = parse_form(std::str::from_utf8(body?).ok()?);
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    if path.starts_with("/v1/refunds") {
        let target = clean(get("charge").or_else(|| get("payment_intent"))?)?;
        Some(match get("amount").and_then(format_minor_units) {
            Some(amount) => format!("Refund {amount} on {target}"),
            None => format!("Refund on {target}"),
        })
    } else if path.starts_with("/v1/payment_intents") {
        let amount = format_minor_units(get("amount")?)?;
        let currency = clean(get("currency")?)?.to_uppercase();
        Some(format!("Create a payment of {amount} {currency}"))
    } else {
        None
    }
}

/// Stripe amounts are integer minor units (cents); render "1050" as "10.50".
fn format_minor_units(amount: &str) -> Option<String> {
    let minor: u64 = amount.parse().ok()?;
    Some(format!("{}.{:02}", minor / 100, minor % 100))
}

/// Minimal application/x-www-form-urlencoded parser ('+' as space, %XX escapes).
fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) =
                    u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
                {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// -- Telegram Bot API -------------------------------------------------------------

fn telegram(path: &str, method: &HttpMethod, json: Option<&serde_json::Value>) -> Option<String> {
    if *method != HttpMethod::Post || !path.contains("/sendMessage") {
        return None;
    }
    let json = json?;
    let chat_id = match json.get("chat_id")? {
        serde_json::Value::String(s) => clean(s)?,
        serde_json::Value::Number(n) => n.to_string(),
        _ => return None,
    };
    let text = clean(str_field(Some(json), "text")?)?;
    Some(format!(
        "Send a Telegram message to chat {chat_id}: \"{text}\""
    ))
}

// -- X / Twitter -------------------------------------------------------------------

fn twitter(path: &str, method: &HttpMethod, json: Option<&serde_json::Value>) -> Option<String> {
    if *method != HttpMethod::Post || path.trim_end_matches('/') != "/2/tweets" {
        return None;
    }
    let text = clean(str_field(json, "text")?)?;
    Some(format!("Post a tweet: \"{text}\""))
}

// -- OpenAI / Anthropic completions ------------------------------------------------

fn llm(path: &str, method: &HttpMethod, json: Option<&serde_json::Value>) -> Option<String> {
    let is_completion =
        path.starts_with("/v1/chat/completions") || path.starts_with("/v1/messages");
    if *method != HttpMethod::Post || !is_completion {
        return None;
    }
    let model = clean(str_field(json, "model")?)?;
    let n = json?.get("messages")?.as_array()?.len();
    let plural = if n == 1 { "message" } else { "messages" };
    Some(format!("Run a {model} completion ({n} {plural})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(url: &str, body: &str) -> Option<String> {
        summarize_request(url, &HttpMethod::Post, Some(body.as_bytes()))
    }

    #[test]
    fn gmail_send_decodes_raw_headers() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let rfc822 = "From: bot@example.com\r\nTo: alice@example.com\r\nCc: bob@example.com\r\nSubject: Hello\r\n\r\nBody text";
        let raw = URL_SAFE_NO_PAD.encode(rfc822);
        let body = serde_json::json!({ "raw": raw }).to_string();
        let s = post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            &body,
        )
        .unwrap();
        assert_eq!(
            s,
            "Send an email to alice@example.com — subject \"Hello\" (+cc bob@example.com)"
        );
    }

    #[test]
    fn gmail_send_tolerates_padding_and_missing_cc() {
        use base64::engine::general_purpose::URL_SAFE;
        use base64::Engine;
        let raw = URL_SAFE.encode("To: x@y.z\r\nSubject: Hi\r\n\r\nhello"); // padded
        let body = serde_json::json!({ "raw": raw }).to_string();
        let s = post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            &body,
        )
        .unwrap();
        assert_eq!(s, "Send an email to x@y.z — subject \"Hi\"");
    }

    #[test]
    fn gmail_wrong_path_or_method_is_none() {
        assert_eq!(
            post(
                "https://gmail.googleapis.com/gmail/v1/users/me/labels",
                "{}"
            ),
            None
        );
        assert_eq!(
            summarize_request(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                &HttpMethod::Get,
                None,
            ),
            None
        );
    }

    #[test]
    fn sendgrid_send_lists_recipients() {
        let body = serde_json::json!({
            "personalizations": [{"to": [
                {"email": "a@x.com"}, {"email": "b@x.com"}, {"email": "c@x.com"}, {"email": "d@x.com"}
            ]}],
            "subject": "Weekly report",
        })
        .to_string();
        let s = post("https://api.sendgrid.com/v3/mail/send", &body).unwrap();
        assert_eq!(
            s,
            "Send an email to a@x.com, b@x.com, c@x.com (+1 more) — subject \"Weekly report\""
        );
    }

    #[test]
    fn slack_post_message() {
        let body = serde_json::json!({"channel": "#general", "text": "Deploy done"}).to_string();
        let s = post("https://slack.com/api/chat.postMessage", &body).unwrap();
        assert_eq!(s, "Post a Slack message to #general: \"Deploy done\"");
    }

    #[test]
    fn github_matchers() {
        let s = post(
            "https://api.github.com/repos/octo/hello/issues",
            &serde_json::json!({"title": "Bug: crash on start"}).to_string(),
        )
        .unwrap();
        assert_eq!(
            s,
            "Create a GitHub issue in octo/hello: \"Bug: crash on start\""
        );

        let s = post(
            "https://api.github.com/repos/octo/hello/issues/42/comments",
            &serde_json::json!({"body": "LGTM"}).to_string(),
        )
        .unwrap();
        assert_eq!(s, "Comment on octo/hello#42: \"LGTM\"");

        let s = post(
            "https://api.github.com/repos/octo/hello/pulls",
            &serde_json::json!({"title": "Add feature", "head": "f", "base": "main"}).to_string(),
        )
        .unwrap();
        assert_eq!(s, "Open a pull request in octo/hello: \"Add feature\"");

        let s = summarize_request(
            "https://api.github.com/repos/octo/hello",
            &HttpMethod::Delete,
            None,
        )
        .unwrap();
        assert_eq!(s, "\u{26a0} Delete the repository octo/hello");
    }

    #[test]
    fn stripe_refund_and_payment_intent() {
        let s = post(
            "https://api.stripe.com/v1/refunds",
            "charge=ch_123&amount=1050",
        )
        .unwrap();
        assert_eq!(s, "Refund 10.50 on ch_123");

        let s = post("https://api.stripe.com/v1/refunds", "payment_intent=pi_9").unwrap();
        assert_eq!(s, "Refund on pi_9");

        let s = post(
            "https://api.stripe.com/v1/payment_intents",
            "amount=250000&currency=usd",
        )
        .unwrap();
        assert_eq!(s, "Create a payment of 2500.00 USD");
    }

    #[test]
    fn telegram_send_message() {
        let body = serde_json::json!({"chat_id": -1001234, "text": "ping"}).to_string();
        let s = post(
            "https://api.telegram.org/bot<CREDENTIAL:tg>/sendMessage",
            &body,
        )
        .unwrap();
        assert_eq!(s, "Send a Telegram message to chat -1001234: \"ping\"");
    }

    #[test]
    fn tweet_post() {
        let body = serde_json::json!({"text": "Hello world"}).to_string();
        let s = post("https://api.x.com/2/tweets", &body).unwrap();
        assert_eq!(s, "Post a tweet: \"Hello world\"");
        let s = post("https://api.twitter.com/2/tweets", &body).unwrap();
        assert_eq!(s, "Post a tweet: \"Hello world\"");
    }

    #[test]
    fn llm_completions() {
        let body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
        })
        .to_string();
        let s = post("https://api.openai.com/v1/chat/completions", &body).unwrap();
        assert_eq!(s, "Run a gpt-4o completion (1 message)");

        let body = serde_json::json!({
            "model": "claude-sonnet-4-5",
            "messages": [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}],
        })
        .to_string();
        let s = post("https://api.anthropic.com/v1/messages", &body).unwrap();
        assert_eq!(s, "Run a claude-sonnet-4-5 completion (2 messages)");
    }

    #[test]
    fn unknown_host_is_none() {
        assert_eq!(post("https://api.example.com/v1/things", "{}"), None);
    }

    #[test]
    fn credential_placeholder_in_value_bails() {
        let body = serde_json::json!({"channel": "#general", "text": "key is <CREDENTIAL:slack>"})
            .to_string();
        assert_eq!(post("https://slack.com/api/chat.postMessage", &body), None);
    }

    #[test]
    fn long_values_are_truncated_with_ellipsis() {
        let long = "x".repeat(500);
        let body = serde_json::json!({"text": long}).to_string();
        let s = post("https://api.x.com/2/tweets", &body).unwrap();
        assert!(s.ends_with("…\""));
        // "Post a tweet: \"" + 120 chars + "…\""
        assert_eq!(s.chars().count(), 15 + VALUE_MAX_CHARS + 2);
    }

    #[test]
    fn host_matching_is_exact_not_substring() {
        // A look-alike host must not match.
        assert_eq!(
            post(
                "https://api.x.com.evil.com/2/tweets",
                &serde_json::json!({"text": "hi"}).to_string()
            ),
            None
        );
        // Query strings can't smuggle a path.
        assert_eq!(
            post(
                "https://evil.com/?u=https://slack.com/api/chat.postMessage",
                &serde_json::json!({"channel": "c", "text": "t"}).to_string()
            ),
            None
        );
    }

    #[test]
    fn backslash_authority_trick_uses_whatwg_host_not_spoof() {
        // `https://evil.com\@gmail.googleapis.com/...`: the hand-rolled parser
        // ended the authority at the first `/` and did rsplit('@'), yielding the
        // spoofed `gmail.googleapis.com`. reqwest/`url::Url` apply WHATWG rules
        // (`\`→`/` terminates the authority), so the real host is `evil.com`.
        let target = "https://evil.com\\@gmail.googleapis.com/gmail/v1/users/me/messages/send";

        // host_and_path must agree with url::Url exactly (same parser reqwest uses).
        let (host, _path) = host_and_path(target).unwrap();
        let whatwg_host = url::Url::parse(target).unwrap().host_str().unwrap().to_string();
        assert_eq!(host, whatwg_host);
        assert_eq!(host, "evil.com");
        assert_ne!(host, "gmail.googleapis.com");

        // And the summary must NOT render a gmail "Send an email" line for a
        // request that actually forwards to evil.com — evil.com is unknown ⇒ None.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let raw = URL_SAFE_NO_PAD.encode("To: victim@example.com\r\nSubject: Hi\r\n\r\nbody");
        let body = serde_json::json!({ "raw": raw }).to_string();
        assert_eq!(post(target, &body), None);
    }

    #[test]
    fn unparseable_target_fails_safe_to_none() {
        // A target `url::Url` can't parse yields no friendly line (raw URL shown).
        assert_eq!(host_and_path("not a url"), None);
        assert_eq!(host_and_path("gmail.googleapis.com/messages/send"), None);
    }

    #[test]
    fn clean_strips_bidi_and_control_codepoints() {
        // Bidi override (U+202E) between text must be stripped so it can't
        // visually reorder the rendered Action line.
        assert_eq!(clean("hello\u{202E}world").unwrap(), "helloworld");
        // Isolates (U+2066–U+2069) and a raw control char are stripped too.
        assert_eq!(
            clean("a\u{2066}b\u{2069}c\u{0007}d").unwrap(),
            "abcd"
        );

        // End-to-end: a tweet whose text carries a bidi override renders clean.
        let body = serde_json::json!({"text": "safe\u{202E}evil"}).to_string();
        let s = post("https://api.x.com/2/tweets", &body).unwrap();
        assert_eq!(s, "Post a tweet: \"safeevil\"");
        assert!(!s.contains('\u{202E}'));
    }

    #[test]
    fn malformed_bodies_are_tolerated() {
        assert_eq!(
            post("https://slack.com/api/chat.postMessage", "not json"),
            None
        );
        assert_eq!(
            summarize_request(
                "https://slack.com/api/chat.postMessage",
                &HttpMethod::Post,
                None
            ),
            None
        );
        assert_eq!(post("https://api.stripe.com/v1/refunds", "amount"), None);
    }
}
