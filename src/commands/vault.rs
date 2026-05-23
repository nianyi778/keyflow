use anyhow::{bail, Context, Result};
use chrono::Utc;
use console::style;
use dialoguer::{Confirm, Password};
use std::fs;
use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use crate::commands::auth::{clear_keyfile, get_data_dir, get_passphrase, load_config, open_db};
use crate::commands::helpers::{BackupFile, BACKUP_FORMAT_VERSION};
use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::{AppConfig, ListFilter, SecretEntry};

pub fn cmd_init(passphrase_arg: Option<String>) -> Result<()> {
    let data_dir = get_data_dir()?;

    if data_dir.join("config.json").exists() {
        if passphrase_arg.is_some() {
        } else if !Confirm::new()
            .with_prompt(
                "KeyFlow is already initialized. Re-initialize? (this won't delete existing secrets)",
            )
            .default(false)
            .interact()?
        {
            return Ok(());
        }
    }

    fs::create_dir_all(&data_dir)?;

    println!("{}", style("Welcome to KeyFlow!").bold().cyan());

    let passphrase = if let Some(p) = passphrase_arg {
        p
    } else {
        println!("Set a master passphrase to encrypt your secrets.\n");
        Password::new()
            .with_prompt("Master passphrase")
            .with_confirmation("Confirm passphrase", "Passphrases don't match")
            .interact()?
    };

    if passphrase.len() < 6 {
        bail!("Passphrase must be at least 6 characters");
    }

    let salt = Crypto::generate_salt();
    let salt_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt);

    let config = AppConfig { salt: salt_b64 };
    let config_str = serde_json::to_string_pretty(&config)?;
    crate::secure_fs::write_private(&data_dir.join("config.json"), &config_str)?;

    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = data_dir.join("keyflow.db");
    Database::open(&db_path, crypto)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
    }

    println!(
        "\n{} KeyFlow initialized at {}",
        style("✓").green().bold(),
        style(data_dir.display()).dim()
    );
    println!("\n{}", style("Next steps:").bold());
    println!("  1. Add secrets:     {}", style("kf add").cyan());
    println!("  2. Connect AI tools: {}", style("kf setup").cyan());

    if std::io::stdin().is_terminal() {
        let cwd = std::env::current_dir().unwrap_or_default();
        let has_env_files = cwd.join(".env").exists()
            || cwd.join(".env.local").exists()
            || cwd.join(".env.example").exists();

        if has_env_files {
            println!();
            if Confirm::new()
                .with_prompt(format!(
                    "Found .env files in current directory ({}). Scan and import?",
                    style(cwd.display()).cyan()
                ))
                .default(true)
                .interact()?
            {
                let crypto = Crypto::new(&passphrase, &salt)?;
                let db = Database::open(&db_path, crypto)?;
                let service = crate::services::secrets::SecretService::new(db);
                let import_result = service.import_path(crate::services::secrets::ImportRequest {
                    path: &cwd,
                    provider: "imported",
                    account_name: "",
                    project_override: None,
                    source: Some("init-scan"),
                    on_conflict: "skip",
                    recursive: false,
                });
                match import_result {
                    Ok(stats) => {
                        if stats.imported > 0 {
                            println!(
                                "  {} Imported {} secrets from current directory",
                                style("✓").green().bold(),
                                stats.imported
                            );
                        } else {
                            println!(
                                "  {} No importable secrets found (keys may be empty or skipped)",
                                style("ℹ").blue()
                            );
                        }
                    }
                    Err(_) => {
                        println!(
                            "  {} Could not import from current directory (this is fine, add secrets manually)",
                            style("ℹ").blue()
                        );
                    }
                }
            }
        }
    }

    println!(
        "\nTip: Run {} or set {} to skip passphrase prompts.",
        style("kf unlock").cyan(),
        style("KEYFLOW_PASSPHRASE").yellow()
    );

    Ok(())
}

pub fn cmd_passwd(old_arg: Option<String>, new_arg: Option<String>) -> Result<()> {
    let (data_dir, _config, old_salt) = load_config()?;

    let old_pass = match old_arg {
        Some(p) => p,
        None => {
            if let Ok(p) = std::env::var("KEYFLOW_PASSPHRASE") {
                p
            } else {
                Password::new()
                    .with_prompt("Current passphrase")
                    .interact()?
            }
        }
    };

    let old_crypto = Crypto::new(&old_pass, &old_salt)?;
    let db_path = data_dir.join("keyflow.db");
    let db = Database::open(&db_path, old_crypto)?;

    let raw_entries = db.get_all_raw()?;
    let mut decrypted_pairs: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, encrypted) in &raw_entries {
        let plaintext = db.decrypt_raw(encrypted)?;
        decrypted_pairs.push((name.clone(), plaintext));
    }

    let new_pass = match new_arg {
        Some(p) => p,
        None => Password::new()
            .with_prompt("New passphrase")
            .with_confirmation("Confirm new passphrase", "Passphrases don't match")
            .interact()?,
    };

    if new_pass.len() < 6 {
        bail!("Passphrase must be at least 6 characters");
    }

    let new_salt = Crypto::generate_salt();
    let new_crypto = Crypto::new(&new_pass, &new_salt)?;

    // Back up the vault DB (and its WAL sidecars) before re-encrypting. If the
    // process dies after reencrypt_all commits but before the new salt is
    // written, the vault is briefly unreadable — restoring these files returns
    // it to its pre-passwd state.
    let backup_files: Vec<(std::path::PathBuf, std::path::PathBuf)> = ["", "-wal", "-shm"]
        .iter()
        .map(|suffix| {
            (
                data_dir.join(format!("keyflow.db{suffix}")),
                data_dir.join(format!("keyflow.db.pre-passwd.bak{suffix}")),
            )
        })
        .filter(|(src, _)| src.exists())
        .collect();
    for (src, dst) in &backup_files {
        fs::copy(src, dst).context("Failed to back up the vault before changing the passphrase")?;
    }

    db.reencrypt_all(&decrypted_pairs, &new_crypto)?;

    let new_salt_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &new_salt);
    let new_config = AppConfig { salt: new_salt_b64 };
    let config_str = serde_json::to_string_pretty(&new_config)?;
    // Atomic: the new salt either fully replaces the old one or not at all, so
    // config.json is never left half-written.
    crate::secure_fs::write_private_atomic(&data_dir.join("config.json"), &config_str)?;

    // Rekey completed end to end — drop the pre-passwd backup.
    for (_, dst) in &backup_files {
        let _ = fs::remove_file(dst);
    }

    // The old cached passphrase no longer decrypts the vault — drop it.
    clear_keyfile()?;

    println!(
        "{} Passphrase changed. {} secrets re-encrypted.",
        style("✓").green().bold(),
        decrypted_pairs.len()
    );
    println!(
        "  Run {} to re-cache, and update your {} if set.",
        style("kf unlock").cyan(),
        style("KEYFLOW_PASSPHRASE").yellow()
    );

    Ok(())
}

pub fn cmd_backup(output: Option<String>) -> Result<()> {
    let db = open_db()?;
    let entries = db.list_secrets(&ListFilter {
        inactive: true,
        ..Default::default()
    })?;

    let mut backup_data: Vec<serde_json::Value> = Vec::new();
    for entry in &entries {
        let value = db.get_secret_value(&entry.id)?;
        let mut obj = serde_json::to_value(entry)?;
        obj.as_object_mut()
            .unwrap()
            .insert("_value".to_string(), serde_json::Value::String(value));
        backup_data.push(obj);
    }

    let backup_json = serde_json::json!({
        "version": BACKUP_FORMAT_VERSION,
        "created_at": Utc::now().to_rfc3339(),
        "secrets": backup_data,
    });

    let backup_str = serde_json::to_string_pretty(&backup_json)?;

    let (_data_dir, _config, salt) = load_config()?;
    let passphrase = get_passphrase()?;
    let crypto = Crypto::new(&passphrase, &salt)?;
    let encrypted = crypto.encrypt(backup_str.as_bytes())?;
    let backup_file = BackupFile {
        version: BACKUP_FORMAT_VERSION.to_string(),
        created_at: Utc::now().to_rfc3339(),
        salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt),
        ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted),
    };

    let output_path = match output {
        Some(p) => p,
        None => {
            let date = Utc::now().format("%Y%m%d-%H%M%S");
            format!("keyflow-backup-{}.enc", date)
        }
    };

    fs::write(&output_path, serde_json::to_vec_pretty(&backup_file)?)?;
    println!(
        "{} Backed up {} secrets to {}",
        style("✓").green().bold(),
        entries.len(),
        style(&output_path).cyan()
    );

    Ok(())
}

pub fn cmd_restore(file: &str, passphrase_arg: Option<String>) -> Result<()> {
    let path = Path::new(file);
    if !path.exists() {
        bail!("Backup file not found: {}", file);
    }

    let backup_file = fs::read(path)?;

    let pass = match passphrase_arg {
        Some(p) => p,
        None => {
            if let Ok(p) = std::env::var("KEYFLOW_PASSPHRASE") {
                p
            } else {
                Password::new()
                    .with_prompt(
                        "Backup passphrase (the passphrase used when the backup was created)",
                    )
                    .interact()?
            }
        }
    };

    let backup_wrapper: BackupFile =
        serde_json::from_slice(&backup_file).context("Invalid backup file format")?;
    let salt = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &backup_wrapper.salt,
    )
    .context("Backup salt is invalid")?;
    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &backup_wrapper.ciphertext,
    )
    .context("Backup ciphertext is invalid")?;
    let crypto = Crypto::new(&pass, &salt)?;
    let decrypted = crypto
        .decrypt(&ciphertext)
        .context("Failed to decrypt backup. Wrong passphrase or corrupted file?")?;

    let backup_str = String::from_utf8(decrypted)?;
    let backup: serde_json::Value = serde_json::from_str(&backup_str)?;

    let secrets = backup
        .get("secrets")
        .and_then(|s| s.as_array())
        .context("Invalid backup format")?;

    let db = open_db()?;
    let mut restored = 0;
    let mut skipped = 0;

    for secret in secrets {
        let name = secret.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let value = secret.get("_value").and_then(|v| v.as_str()).unwrap_or("");

        if name.is_empty() || value.is_empty() {
            continue;
        }

        if !db.get_secrets_by_name(name)?.is_empty() {
            println!("{} Skipping '{}' (already exists)", style("⊘").dim(), name);
            skipped += 1;
            continue;
        }

        let entry: SecretEntry =
            serde_json::from_value(secret.clone()).unwrap_or_else(|_| SecretEntry {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.to_string(),
                env_var: name.to_uppercase().replace(['-', ' ', '.'], "_"),
                provider: String::new(),
                account_name: String::new(),
                org_name: String::new(),
                description: "Restored from backup".to_string(),
                source: "restore".to_string(),
                environment: String::new(),
                permission_profile: String::new(),
                scopes: vec![],
                projects: vec![],
                apply_url: String::new(),
                expires_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                last_used_at: None,
                last_verified_at: Some(Utc::now()),
                is_active: true,
            });

        db.add_secret(&entry, value)?;
        println!("{} Restored '{}'", style("✓").green(), style(name).cyan());
        restored += 1;
    }

    println!(
        "\n{} Restored {} secrets ({} skipped)",
        style("✓").green().bold(),
        restored,
        skipped
    );
    Ok(())
}

pub fn cmd_upgrade() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("Current version: {}", style(current).cyan());
    print!("Checking latest release... ");

    let latest = fetch_latest_version()?;
    println!("{}", style(&latest).cyan());

    if latest == current {
        println!("{} Already up to date.", style("✓").green().bold());
        return Ok(());
    }

    println!(
        "{} New version available: {}",
        style("↑").yellow().bold(),
        style(&latest).yellow().bold()
    );

    if is_homebrew_install() {
        println!("Detected Homebrew installation. Running `brew upgrade keyflow`...\n");
        let status = Command::new("brew")
            .args(["upgrade", "keyflow"])
            .status()
            .context("Failed to run brew")?;
        if !status.success() {
            bail!("brew upgrade keyflow failed");
        }
    } else if is_cargo_install() {
        println!("Detected cargo installation. Running `cargo install keyflow`...\n");
        let status = Command::new("cargo")
            .args(["install", "keyflow"])
            .status()
            .context("Failed to run cargo")?;
        if !status.success() {
            bail!("cargo install keyflow failed");
        }
    } else {
        println!(
            "To upgrade, run one of:\n  {} brew upgrade keyflow\n  {} cargo install keyflow\n  {} Download from https://github.com/nianyi778/keyflow/releases/tag/v{}",
            style("•").dim(),
            style("•").dim(),
            style("•").dim(),
            latest,
        );
    }

    Ok(())
}

fn fetch_latest_version() -> Result<String> {
    let mut resp = ureq::get("https://api.github.com/repos/nianyi778/keyflow/releases/latest")
        .header("User-Agent", "keyflow-cli")
        .call()
        .map_err(|e| anyhow::anyhow!("Failed to check for updates: {e}"))?;
    let payload: serde_json::Value = resp
        .body_mut()
        .read_json()
        .context("Failed to parse GitHub release response")?;
    let tag = payload
        .get("tag_name")
        .and_then(|v| v.as_str())
        .context("Missing tag_name in GitHub response")?;
    Ok(tag.trim_start_matches('v').to_string())
}

fn is_homebrew_install() -> bool {
    // Check if keyflow binary lives under a Homebrew Cellar path
    if let Ok(exe) = std::env::current_exe() {
        let path = exe.to_string_lossy();
        if path.contains("/Cellar/")
            || path.contains("/homebrew/")
            || path.contains("/opt/homebrew/")
        {
            return true;
        }
    }
    // Fallback: brew list reports it
    Command::new("brew")
        .args(["list", "keyflow"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_cargo_install() -> bool {
    if let Ok(exe) = std::env::current_exe() {
        exe.to_string_lossy().contains("/.cargo/bin/")
    } else {
        false
    }
}
