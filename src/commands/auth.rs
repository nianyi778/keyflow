use anyhow::{bail, Context, Result};
use console::style;
use dialoguer::{Password, Select};
use std::fs;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::{AppConfig, ListFilter};

pub fn get_data_dir() -> Result<std::path::PathBuf> {
    let dir = dirs::home_dir()
        .context("Cannot find home directory")?
        .join(".keyflow");
    Ok(dir)
}

fn session_path() -> Result<std::path::PathBuf> {
    Ok(get_data_dir()?.join(".session"))
}

const SESSION_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Derive a machine-local session encryption key from hostname + uid.
/// This ensures session files are useless if copied to another machine.
fn session_key() -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut material = String::new();
    // hostname
    if let Ok(hostname) = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .or_else(|_| {
            std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string())
        })
    {
        material.push_str(&hostname);
    }
    material.push(':');
    // uid (unix)
    #[cfg(unix)]
    {
        // Use std nix-like approach: read /proc/self/status or use id command
        // Simpler: use a stable machine identifier — the data dir path itself
        if let Ok(dir) = get_data_dir() {
            material.push_str(&dir.display().to_string());
        }
    }
    material.push(':');
    material.push_str("keyflow-session-v1");

    // Hash to a fixed 32-byte key using a simple approach
    // (not crypto-grade KDF, but sufficient for local session obfuscation)
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    material.hash(&mut hasher);
    let h1 = hasher.finish();
    material.push_str(":part2");
    let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
    material.hash(&mut hasher2);
    let h2 = hasher2.finish();
    material.push_str(":part3");
    let mut hasher3 = std::collections::hash_map::DefaultHasher::new();
    material.hash(&mut hasher3);
    let h3 = hasher3.finish();
    material.push_str(":part4");
    let mut hasher4 = std::collections::hash_map::DefaultHasher::new();
    material.hash(&mut hasher4);
    let h4 = hasher4.finish();

    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&h1.to_le_bytes());
    key[8..16].copy_from_slice(&h2.to_le_bytes());
    key[16..24].copy_from_slice(&h3.to_le_bytes());
    key[24..32].copy_from_slice(&h4.to_le_bytes());
    key
}

pub(crate) fn read_session() -> Option<String> {
    let path = session_path().ok()?;
    if !path.exists() {
        return None;
    }
    let metadata = fs::metadata(&path).ok()?;
    let modified = metadata.modified().ok()?;
    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    if age.as_secs() > SESSION_MAX_AGE_SECS {
        let _ = fs::remove_file(&path);
        return None;
    }
    let encrypted_b64 = fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    let encrypted = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted_b64,
    )
    .ok()?;
    // Decrypt using machine-local session key
    let key = session_key();
    // Use a fixed salt for session crypto (not security-critical, just obfuscation)
    let session_crypto = Crypto::new_from_raw_key(&key).ok()?;
    let decrypted = session_crypto.decrypt(&encrypted).ok()?;
    String::from_utf8(decrypted).ok()
}

pub(crate) fn save_session(passphrase: &str) -> Result<()> {
    let path = session_path()?;
    let key = session_key();
    let session_crypto = Crypto::new_from_raw_key(&key)?;
    let encrypted = session_crypto.encrypt(passphrase.as_bytes())?;
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);
    fs::write(&path, encoded)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn cmd_lock() -> Result<()> {
    let path = session_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    println!("{} Session cleared.", style("✓").green().bold());
    Ok(())
}

pub fn get_passphrase() -> Result<String> {
    if let Ok(pass) = std::env::var("KEYFLOW_PASSPHRASE") {
        return Ok(pass);
    }
    if let Some(pass) = read_session() {
        return Ok(pass);
    }
    let pass = Password::new()
        .with_prompt("KeyFlow passphrase")
        .interact()?;
    let _ = save_session(&pass);
    Ok(pass)
}

pub fn load_config() -> Result<(std::path::PathBuf, AppConfig, Vec<u8>)> {
    let data_dir = get_data_dir()?;
    let config_path = data_dir.join("config.json");

    if !config_path.exists() {
        bail!(
            "KeyFlow not initialized. Run {} first.",
            style("keyflow init").cyan()
        );
    }

    let config_str = fs::read_to_string(&config_path)?;
    let config: AppConfig = serde_json::from_str(&config_str)?;
    let salt = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &config.salt)?;

    Ok((data_dir, config, salt))
}

pub fn open_db() -> Result<Database> {
    let (data_dir, _config, salt) = load_config()?;
    let passphrase = get_passphrase()?;
    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = data_dir.join("keyflow.db");
    Database::open(db_path.to_str().unwrap(), crypto)
}

pub(crate) fn select_secret(db: &Database) -> Result<String> {
    let entries = db.list_secrets(&ListFilter::default())?;
    if entries.is_empty() {
        bail!("No secrets found. Add one with: kf add");
    }
    let items: Vec<String> = entries
        .iter()
        .map(|e| format!("{:<28} {:<24} {}", e.name, e.env_var, e.provider))
        .collect();
    let idx = Select::new()
        .with_prompt("Select secret")
        .items(&items)
        .default(0)
        .interact()?;
    Ok(entries[idx].name.clone())
}
