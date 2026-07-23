//! `tap init`: parse config, encrypt credentials, generate agent API keys.

use rand::RngCore;
use std::path::Path;

use tap_core::error::AgentSecError;

/// Generate a random 32-byte API key as a 64-char hex string.
pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Write a .env file for an agent.
pub fn write_env_file(
    dir: &Path,
    agent_name: &str,
    api_key: &str,
    proxy_url: &str,
) -> Result<(), AgentSecError> {
    let path = dir.join(format!("{agent_name}.env"));
    let content = format!("TAP_API_KEY={api_key}\nTAP_PROXY_URL={proxy_url}\n");
    std::fs::write(&path, content)
        .map_err(|e| AgentSecError::Internal(format!("Failed to write {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generate_api_key_format() {
        for _ in 0..5 {
            let key = generate_api_key();
            assert_eq!(key.len(), 64);
            assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        }
        // All different
        let keys: HashSet<String> = (0..5).map(|_| generate_api_key()).collect();
        assert_eq!(keys.len(), 5);
    }

    #[test]
    fn generate_api_key_randomness() {
        let keys: HashSet<String> = (0..100).map(|_| generate_api_key()).collect();
        assert_eq!(keys.len(), 100);
    }

    #[test]
    fn write_env_file_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_api_key();
        write_env_file(dir.path(), "openclaw", &key, "http://localhost:3100").unwrap();

        let path = dir.path().join("openclaw.env");
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(&format!("TAP_API_KEY={key}")));
        assert!(content.contains("TAP_PROXY_URL=http://localhost:3100"));
    }

    #[test]
    fn write_env_files_for_multiple_agents() {
        let dir = tempfile::tempdir().unwrap();

        let key1 = generate_api_key();
        let key2 = generate_api_key();
        assert_ne!(key1, key2);

        write_env_file(dir.path(), "openclaw", &key1, "http://localhost:3100").unwrap();
        write_env_file(dir.path(), "hermes", &key2, "http://localhost:3100").unwrap();

        assert!(dir.path().join("openclaw.env").exists());
        assert!(dir.path().join("hermes.env").exists());

        let content1 = std::fs::read_to_string(dir.path().join("openclaw.env")).unwrap();
        let content2 = std::fs::read_to_string(dir.path().join("hermes.env")).unwrap();
        assert!(content1.contains(&key1));
        assert!(content2.contains(&key2));
    }
}
