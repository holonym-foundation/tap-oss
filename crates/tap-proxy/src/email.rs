//! Email sending via Resend API.

use serde_json::json;
use tap_core::error::AgentSecError;
use tap_core::http_client::{build_client, ClientRoute};

/// Send an email verification code via Resend.
pub async fn send_verification_email(
    to: &str,
    code: &str,
    team_name: &str,
) -> Result<(), AgentSecError> {
    let api_key = std::env::var("RESEND_API_KEY").map_err(|_| {
        AgentSecError::Config("RESEND_API_KEY not set — cannot send verification emails".into())
    })?;
    // Use RESEND_FROM_EMAIL if set, otherwise Resend's shared test domain.
    // For production, set RESEND_FROM_EMAIL to a verified domain (e.g., noreply@tap.human.tech).
    let from = std::env::var("RESEND_FROM_EMAIL")
        .unwrap_or_else(|_| "TAP <onboarding@resend.dev>".to_string());

    let body = json!({
        "from": from,
        "to": [to],
        "subject": format!("TAP — verify your email for team '{}'", team_name),
        "text": format!(
            "Your TAP verification code is:\n\n  {}\n\nThis code expires in 15 minutes.\n\nIf you didn't sign up for TAP, you can ignore this email.",
            code
        ),
    });

    let client = build_client(ClientRoute::EgressProxy)
        .map_err(|e| AgentSecError::Internal(format!("Failed to create HTTP client: {e}")))?;
    let resp = client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| AgentSecError::Internal(format!("Failed to send email: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AgentSecError::Internal(format!(
            "Resend API error ({status}): {body}"
        )));
    }

    Ok(())
}

/// Send a password reset link via Resend.
pub async fn send_password_reset_email(to: &str, reset_url: &str) -> Result<(), AgentSecError> {
    let api_key = std::env::var("RESEND_API_KEY").map_err(|_| {
        AgentSecError::Config("RESEND_API_KEY not set — cannot send password reset emails".into())
    })?;
    let from = std::env::var("RESEND_FROM_EMAIL")
        .unwrap_or_else(|_| "TAP <onboarding@resend.dev>".to_string());

    let body = json!({
        "from": from,
        "to": [to],
        "subject": "TAP — reset your password",
        "text": format!(
            "You requested a password reset for your TAP account.\n\nClick the link below to set a new password (expires in 1 hour):\n\n  {reset_url}\n\nIf you did not request this, you can ignore this email — your password has not been changed.",
        ),
    });

    let client = build_client(ClientRoute::EgressProxy)
        .map_err(|e| AgentSecError::Internal(format!("Failed to create HTTP client: {e}")))?;
    let resp = client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| AgentSecError::Internal(format!("Failed to send email: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AgentSecError::Internal(format!(
            "Resend API error ({status}): {body}"
        )));
    }

    Ok(())
}

/// Send a team member invite email via Resend.
pub async fn send_invite_email(
    to: &str,
    invited_by_email: &str,
    team_name: &str,
    accept_url: &str,
) -> Result<(), AgentSecError> {
    let api_key = std::env::var("RESEND_API_KEY").map_err(|_| {
        AgentSecError::Config("RESEND_API_KEY not set — cannot send invite emails".into())
    })?;
    let from = std::env::var("RESEND_FROM_EMAIL")
        .unwrap_or_else(|_| "TAP <onboarding@resend.dev>".to_string());

    let body = json!({
        "from": from,
        "to": [to],
        "subject": format!("{} invited you to join '{}' on TAP", invited_by_email, team_name),
        "text": format!(
            "{} has invited you to join the '{}' team on TAP (Tool Authorization Protocol).\n\nAccept your invitation:\n\n  {}\n\nThis invitation expires in 48 hours.\n\nIf you weren't expecting this, you can safely ignore it.",
            invited_by_email, team_name, accept_url
        ),
    });

    let client = build_client(ClientRoute::EgressProxy)
        .map_err(|e| AgentSecError::Internal(format!("Failed to create HTTP client: {e}")))?;
    let resp = client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| AgentSecError::Internal(format!("Failed to send email: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AgentSecError::Internal(format!(
            "Resend API error ({status}): {body}"
        )));
    }

    Ok(())
}
