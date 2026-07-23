//! Recipe catalog served to agents — the "agent as distributor" surface.
//!
//! The catalog data lives in `crates/tap-proxy/recipes.json` (single source of
//! truth, shared with the dashboard which imports the same file at build time).
//! Agents see it in two places:
//!
//! - a compact top-level `recipes` block in `GET /agent/services` (id + pitch +
//!   setup_url — enough to OFFER a recipe to their user without another fetch),
//! - `GET /agent/recipes` for the full detail (credentials, flavors, CLI name).
//!
//! The agent can only ever *offer* a recipe: `setup_url` deep-links into the
//! dashboard onboarding wizard (`#/onboarding?recipe=<id>`), which runs under
//! the human's session and passkey — there is no agent-reachable setup path.

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::LazyLock;

/// One credential a recipe provisions. Only the fields agents care about —
/// presentation fields in the JSON (keyUrl, keyHint, headerFormat, …) are
/// dashboard concerns and deliberately not deserialized here.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeCred {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// A platform variant (same use case, different service).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeFlavor {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub creds: Vec<RecipeCred>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipe {
    pub id: String,
    pub title: String,
    pub pitch: String,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub creds: Vec<RecipeCred>,
    #[serde(default)]
    pub flavors: Vec<RecipeFlavor>,
}

#[derive(Deserialize)]
struct Catalog {
    recipes: Vec<Recipe>,
}

/// Parsed once at first use. A malformed catalog is a build artifact bug, not
/// a runtime condition — panicking on first access surfaces it in tests/CI
/// (see `catalog_parses`) long before it could ship.
static CATALOG: LazyLock<Vec<Recipe>> = LazyLock::new(|| {
    let raw = include_str!("../recipes.json");
    serde_json::from_str::<Catalog>(raw)
        .expect("recipes.json must parse — validated by the catalog_parses test")
        .recipes
});

pub fn catalog() -> &'static [Recipe] {
    &CATALOG
}

pub fn setup_url(recipe_id: &str) -> String {
    format!(
        "{}/dashboard#/onboarding?recipe={}",
        crate::proxy::configured_proxy_url(),
        recipe_id
    )
}

/// The compact showcase embedded top-level in `GET /agent/services`, next to
/// `services`: what the agent HAS vs what it COULD have. Kept to id + pitch +
/// setup_url so the constant per-session context cost stays small.
pub fn discover_block() -> serde_json::Value {
    let available: Vec<serde_json::Value> = catalog()
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "pitch": r.pitch,
                "setup_url": setup_url(&r.id),
            })
        })
        .collect();
    json!({
        "hint": "Ready-made use-case packs your user can enable in ~2 minutes. If your user asks for one of these — or anything similar your services don't cover — share its setup_url: they complete a guided setup in their browser (their session, their passkey), and you're immediately equipped. You cannot and must not run the setup yourself.",
        "available": available,
        "details_url": "/agent/recipes",
    })
}

/// The recipe (if any) that would provision a credential with this name —
/// used to enrich the missing-credential error with a full-pack alternative.
pub fn recipe_providing_credential(cred_name: &str) -> Option<&'static Recipe> {
    catalog().iter().find(|r| {
        r.creds.iter().any(|c| c.name == cred_name)
            || r.flavors
                .iter()
                .any(|f| f.creds.iter().any(|c| c.name == cred_name))
    })
}

/// GET /agent/recipes — full catalog detail for agents (agent-key auth, read
/// only; the catalog is public data, auth just keeps the surface consistent
/// with the other /agent/* routes).
pub async fn handle_agent_recipes(
    axum::extract::State(state): axum::extract::State<crate::proxy::AppState>,
    headers: HeaderMap,
) -> Response {
    let api_key = match headers.get("x-tap-key").and_then(|v| v.to_str().ok()) {
        Some(k) => k.to_string(),
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing X-TAP-Key header", "safe_to_retry": true})),
            )
                .into_response();
        }
    };
    // Multi-key lists are accepted everywhere else; any valid key will do here.
    let mut authed = false;
    for key in api_key.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        if matches!(state.authenticate(key).await, Ok(Some(_))) {
            authed = true;
            break;
        }
    }
    if !authed {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid API key"})),
        )
            .into_response();
    }

    let recipes: Vec<serde_json::Value> = catalog()
        .iter()
        .map(|r| {
            let creds: Vec<serde_json::Value> = r
                .creds
                .iter()
                .map(|c| json!({"name": c.name, "kind": c.kind, "note": c.note}))
                .collect();
            let flavors: Vec<serde_json::Value> = r
                .flavors
                .iter()
                .map(|f| {
                    json!({
                        "id": f.id,
                        "label": f.label,
                        "credentials": f.creds.iter().map(|c| json!({"name": c.name, "kind": c.kind})).collect::<Vec<_>>(),
                    })
                })
                .collect();
            json!({
                "id": r.id,
                "title": r.title,
                "pitch": r.pitch,
                "services": r.services,
                "credentials": creds,
                "flavors": flavors,
                "setup_url": setup_url(&r.id),
                "cli": format!("tap recipe run {}", r.id),
            })
        })
        .collect();

    Json(json!({
        "recipes": recipes,
        "how_to_offer": "Share a recipe's setup_url with your user — setup happens in their browser under their session and passkey. You cannot run it yourself.",
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_parses() {
        let recipes = catalog();
        assert_eq!(recipes.len(), 5, "expected the 5 shipped recipes");
        for r in recipes {
            assert!(!r.id.is_empty() && !r.pitch.is_empty());
            assert!(
                !r.creds.is_empty() || !r.flavors.is_empty(),
                "recipe {} provisions nothing",
                r.id
            );
        }
    }

    #[test]
    fn credential_lookup_covers_direct_and_flavored() {
        assert_eq!(
            recipe_providing_credential("github").map(|r| r.id.as_str()),
            Some("pr-ci-copilot")
        );
        // Flavored: discord-bot lives inside social-ghostwriter's discord flavor.
        assert_eq!(
            recipe_providing_credential("discord-bot").map(|r| r.id.as_str()),
            Some("social-ghostwriter")
        );
        assert!(recipe_providing_credential("nonexistent").is_none());
    }

    #[test]
    fn discover_block_shape() {
        let block = discover_block();
        let available = block["available"].as_array().unwrap();
        assert_eq!(available.len(), 5);
        for entry in available {
            assert!(entry["setup_url"]
                .as_str()
                .unwrap()
                .contains("#/onboarding?recipe="));
        }
    }
}
