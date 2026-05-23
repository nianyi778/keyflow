use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use console::style;
use dialoguer::{FuzzySelect, Password};
use std::fs;
use std::io::IsTerminal;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::{AppConfig, ListFilter, SecretEntry};
use crate::paths;
use crate::services::secrets::SecretService;

pub fn get_data_dir() -> Result<std::path::PathBuf> {
    paths::data_dir()
}

fn keyfile_path() -> Result<std::path::PathBuf> {
    Ok(get_data_dir()?.join(".passphrase"))
}

/// On-disk shape of the cached-passphrase keyfile.
#[derive(serde::Serialize, serde::Deserialize)]
struct Keyfile {
    passphrase: String,
    /// When the cached passphrase expires; `None` means it never expires.
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

fn read_keyfile() -> Option<String> {
    let path = keyfile_path().ok()?;
    let raw = fs::read_to_string(&path).ok()?;
    // Current format is JSON with an optional TTL. Older versions stored the
    // bare passphrase as plain text; still accept that as a non-expiring cache.
    let passphrase = match serde_json::from_str::<Keyfile>(&raw) {
        Ok(keyfile) => {
            if let Some(expiry) = keyfile.expires_at {
                if Utc::now() >= expiry {
                    let _ = fs::remove_file(&path);
                    return None;
                }
            }
            keyfile.passphrase
        }
        Err(_) => raw,
    };
    let passphrase = passphrase.trim().to_string();
    if passphrase.is_empty() {
        None
    } else {
        Some(passphrase)
    }
}

/// Persist the master passphrase to the keyfile. `expires_at` of `None` caches
/// it indefinitely. Only `kf unlock` calls this — KeyFlow never caches the
/// passphrase implicitly.
fn save_keyfile(passphrase: &str, expires_at: Option<DateTime<Utc>>) -> Result<()> {
    let path = keyfile_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let keyfile = Keyfile {
        passphrase: passphrase.to_string(),
        expires_at,
    };
    let raw = serde_json::to_string(&keyfile)?;
    crate::secure_fs::write_private(&path, raw)
}

/// Remove any cached passphrase keyfile. Used after the passphrase changes so a
/// stale keyfile holding the old passphrase cannot linger.
pub(crate) fn clear_keyfile() -> Result<()> {
    let path = keyfile_path()?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Cache `passphrase` to the keyfile with a TTL of `ttl_hours` (`0` = no
/// expiry) and return the computed expiry. Callers must be explicit user
/// actions (`kf unlock`, `kf setup`) — KeyFlow never caches implicitly.
pub(crate) fn cache_passphrase(passphrase: &str, ttl_hours: u64) -> Result<Option<DateTime<Utc>>> {
    let expires_at = if ttl_hours == 0 {
        None
    } else {
        Some(Utc::now() + chrono::Duration::hours(ttl_hours as i64))
    };
    save_keyfile(passphrase, expires_at)?;
    Ok(expires_at)
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

/// Cache the master passphrase locally so subsequent commands (and the MCP
/// server) don't prompt. The cache expires after `ttl_hours` hours; `0`
/// disables expiry. KeyFlow never caches the passphrase unless `kf unlock` is
/// run explicitly.
pub fn cmd_unlock(ttl_hours: u64) -> Result<()> {
    let (data_dir, _config, salt) = load_config()?;

    let passphrase = if let Ok(p) = std::env::var("KEYFLOW_PASSPHRASE") {
        p
    } else if std::io::stdin().is_terminal() {
        Password::new()
            .with_prompt("KeyFlow passphrase")
            .interact()?
    } else {
        get_passphrase_gui()?
    };
    if passphrase.trim().is_empty() {
        bail!("Passphrase cannot be empty");
    }

    // Best-effort verification: if the vault holds any secret, confirm the
    // passphrase actually decrypts it before caching a possibly-wrong value.
    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = data_dir.join("keyflow.db");
    let db = Database::open(&db_path, crypto)?;
    if let Some((_, encrypted)) = db.get_all_raw()?.first() {
        db.decrypt_raw(encrypted)
            .map_err(|_| anyhow::anyhow!("Wrong passphrase — vault not unlocked"))?;
    }

    let expires_at = cache_passphrase(&passphrase, ttl_hours)?;

    match expires_at {
        Some(expiry) => println!(
            "{} Vault unlocked. Passphrase cached until {}.",
            style("✓").green().bold(),
            style(expiry.format("%Y-%m-%d %H:%M UTC")).dim()
        ),
        None => println!(
            "{} Vault unlocked. Passphrase cached with no expiry — run {} to clear it.",
            style("✓").green().bold(),
            style("kf lock").cyan()
        ),
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
        bail!("Vault locked. Run `kf unlock` first, or set KEYFLOW_PASSPHRASE.");
    }
    // 3. Interactive terminal prompt
    if std::io::stdin().is_terminal() {
        let pass = Password::new()
            .with_prompt("KeyFlow passphrase")
            .interact()?;
        return Ok(pass);
    }
    // 4. Native OS dialog (for AI tools, MCP, non-terminal contexts)
    get_passphrase_gui()
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
    Database::open(&db_path, crypto)
}

pub(crate) fn resolve_secret(
    service: &SecretService<'_>,
    name: Option<String>,
    project: Option<&str>,
) -> Result<SecretEntry> {
    let name = match name {
        Some(n) => n,
        None => return select_secret_entry(service, project),
    };

    let mut entries = service.get_entries_by_name(&name)?;
    if entries.is_empty() {
        bail!("Secret '{}' not found", name);
    }

    if let Some(proj) = project {
        entries.retain(|e| e.projects.iter().any(|p| p == proj));
        if entries.is_empty() {
            bail!("Secret '{}' not found in project '{}'", name, proj);
        }
    }

    if entries.len() == 1 {
        return Ok(entries.remove(0));
    }

    // Multiple matches — interactive picker
    let items: Vec<String> = entries
        .iter()
        .map(|e| {
            let projects = if e.projects.is_empty() {
                "(global)".to_string()
            } else {
                format!("({})", e.projects.join(", "))
            };
            format!(
                "{:<28} {:<20} {:<16} {:?}",
                e.name,
                projects,
                e.provider,
                e.status()
            )
        })
        .collect();

    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "Secret '{}' has multiple matches ({} entries). Specify the full name:\n{}",
            style(name).cyan(),
            items.len(),
            items
                .iter()
                .enumerate()
                .map(|(i, n)| format!("  {}. {}", i + 1, n))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    let idx = FuzzySelect::new()
        .with_prompt(format!("Multiple secrets named '{}' — select one", name))
        .items(&items)
        .default(0)
        .interact()?;

    Ok(entries.remove(idx))
}

fn select_secret_entry(service: &SecretService<'_>, project: Option<&str>) -> Result<SecretEntry> {
    let filter = ListFilter {
        project: project.map(|s| s.to_string()),
        ..Default::default()
    };
    let entries = service.list_entries(&filter)?;
    if entries.is_empty() {
        bail!("No secrets found. Add one with: kf add");
    }
    let items: Vec<String> = entries
        .iter()
        .map(|e| {
            let projects = if e.projects.is_empty() {
                "(global)".to_string()
            } else {
                format!("({})", e.projects.join(", "))
            };
            format!(
                "{:<28} {:<20} {:<24} {}",
                e.name, projects, e.env_var, e.provider
            )
        })
        .collect();
    let idx = FuzzySelect::new()
        .with_prompt("Select secret (type to filter)")
        .items(&items)
        .default(0)
        .interact()?;
    Ok(entries[idx].clone())
}
