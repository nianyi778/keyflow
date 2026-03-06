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

pub(crate) fn read_session() -> Option<String> {
    let path = session_path().ok()?;
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_session(passphrase: &str) -> Result<()> {
    let path = session_path()?;
    fs::write(&path, passphrase)?;
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
