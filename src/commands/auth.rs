use anyhow::{bail, Context, Result};
use console::style;
use dialoguer::{FuzzySelect, Password};
use std::fs;
use std::io::IsTerminal;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::{AppConfig, ListFilter};
use crate::paths;
use crate::services::secrets::SecretService;

pub fn get_data_dir() -> Result<std::path::PathBuf> {
    paths::data_dir()
}

fn keyfile_path() -> Result<std::path::PathBuf> {
    Ok(get_data_dir()?.join(".passphrase"))
}

fn read_keyfile() -> Option<String> {
    let path = keyfile_path().ok()?;
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn save_keyfile(passphrase: &str) -> Result<()> {
    let path = keyfile_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, passphrase)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn cmd_lock() -> Result<()> {
    let path = keyfile_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
        println!(
            "{} Keyfile removed. Passphrase required on next use.",
            style("✓").green().bold()
        );
    } else {
        println!("{} Already locked.", style("✓").green().bold());
    }
    Ok(())
}

/// Prompt for passphrase using a native OS dialog (no terminal needed).
/// Works when called from AI tools, MCP servers, or other non-interactive contexts.
fn get_passphrase_gui() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("osascript")
            .arg("-e")
            .arg(
                r#"display dialog "Enter KeyFlow passphrase:" default answer "" with hidden answer buttons {"OK", "Cancel"} default button "OK" with title "KeyFlow 🔑""#,
            )
            .arg("-e")
            .arg("text returned of result")
            .output()
            .context("Failed to launch macOS password dialog")?;
        if !output.status.success() {
            bail!("Password dialog was cancelled");
        }
        let pass = String::from_utf8(output.stdout)?.trim().to_string();
        if pass.is_empty() {
            bail!("Passphrase cannot be empty");
        }
        Ok(pass)
    }
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("zenity")
            .args(["--password", "--title=KeyFlow 🔑"])
            .output()
            .context("Failed to launch password dialog (is zenity installed?)")?;
        if !output.status.success() {
            bail!("Password dialog was cancelled");
        }
        let pass = String::from_utf8(output.stdout)?.trim().to_string();
        if pass.is_empty() {
            bail!("Passphrase cannot be empty");
        }
        Ok(pass)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        bail!("No terminal available and no GUI dialog supported on this platform. Set KEYFLOW_PASSPHRASE environment variable.");
    }
}

pub fn get_passphrase() -> Result<String> {
    get_passphrase_inner(false)
}

/// Non-interactive variant: only env var + keyfile, no prompts or GUI dialogs.
/// Used by MCP serve to avoid blocking stdio.
pub fn get_passphrase_noninteractive() -> Result<String> {
    get_passphrase_inner(true)
}

fn get_passphrase_inner(noninteractive: bool) -> Result<String> {
    // 1. Environment variable (CI/scripting)
    if let Ok(pass) = std::env::var("KEYFLOW_PASSPHRASE") {
        return Ok(pass);
    }
    // 2. Saved keyfile (permanent, survives across all contexts including MCP)
    if let Some(pass) = read_keyfile() {
        return Ok(pass);
    }
    if noninteractive {
        bail!("Vault locked. Run any `kf` command first to unlock, or set KEYFLOW_PASSPHRASE.");
    }
    // 3. Interactive terminal prompt
    if std::io::stdin().is_terminal() {
        let pass = Password::new()
            .with_prompt("KeyFlow passphrase")
            .interact()?;
        let _ = save_keyfile(&pass);
        return Ok(pass);
    }
    // 4. Native OS dialog (for AI tools, MCP, non-terminal contexts)
    let pass = get_passphrase_gui()?;
    let _ = save_keyfile(&pass);
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

pub(crate) fn select_secret(service: &SecretService<'_>) -> Result<String> {
    let entries = service.list_entries(&ListFilter::default())?;
    if entries.is_empty() {
        bail!("No secrets found. Add one with: kf add");
    }
    let items: Vec<String> = entries
        .iter()
        .map(|e| format!("{:<28} {:<24} {}", e.name, e.env_var, e.provider))
        .collect();
    let idx = FuzzySelect::new()
        .with_prompt("Select secret (type to filter)")
        .items(&items)
        .default(0)
        .interact()?;
    Ok(entries[idx].name.clone())
}
