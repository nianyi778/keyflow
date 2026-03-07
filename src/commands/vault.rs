use anyhow::{bail, Context, Result};
use chrono::Utc;
use console::style;
use dialoguer::{Confirm, Password};
use std::fs;
use std::path::Path;

use crate::commands::auth::{get_data_dir, get_passphrase, load_config, open_db, save_session};
use crate::commands::helpers::{decrypt_backup_contents, BackupFile, BACKUP_FORMAT_VERSION};
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

    let _ = save_session(&passphrase);

    let salt = Crypto::generate_salt();
    let salt_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt);

    let config = AppConfig { salt: salt_b64 };
    let config_str = serde_json::to_string_pretty(&config)?;
    fs::write(data_dir.join("config.json"), config_str)?;

    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = data_dir.join("keyflow.db");
    Database::open(db_path.to_str().unwrap(), crypto)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(
            data_dir.join("config.json"),
            fs::Permissions::from_mode(0o600),
        )?;
    }

    println!(
        "\n{} KeyFlow initialized at {}",
        style("✓").green().bold(),
        style(data_dir.display()).dim()
    );
    println!("\n{}", style("Next steps:").bold());
    println!("  1. Add secrets:     {}", style("kf add").cyan());
    println!("  2. Connect AI tools: {}", style("kf setup").cyan());
    println!(
        "\nTip: Set {} to skip passphrase prompts.",
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
    let db = Database::open(db_path.to_str().unwrap(), old_crypto)?;

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

    let _ = save_session(&new_pass);

    let new_salt = Crypto::generate_salt();
    let new_crypto = Crypto::new(&new_pass, &new_salt)?;

    db.reencrypt_all(&decrypted_pairs, &new_crypto)?;

    let new_salt_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &new_salt);
    let new_config = AppConfig { salt: new_salt_b64 };
    let config_str = serde_json::to_string_pretty(&new_config)?;
    fs::write(data_dir.join("config.json"), config_str)?;

    println!(
        "{} Passphrase changed. {} secrets re-encrypted.",
        style("✓").green().bold(),
        decrypted_pairs.len()
    );
    println!(
        "  Update your {} if set.",
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
        let value = db.get_secret_value(&entry.name)?;
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

    let decrypted = decrypt_backup_contents(&backup_file, &pass, || {
        let (_data_dir, _config, salt) = load_config()?;
        Ok(salt)
    })?;

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

        if db.secret_exists(name)? {
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
                key_group: String::new(),
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
