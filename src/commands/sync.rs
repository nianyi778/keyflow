use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use console::style;
use dialoguer::{Confirm, Password};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::cli::{ConflictStrategy, SyncCommands};
use crate::commands::auth::{get_passphrase, open_db};
use crate::crypto::Crypto;
use crate::db::{Database, MetadataUpdate};
use crate::models::{ListFilter, SecretEntry};
use crate::paths::data_dir;
use crate::services::secrets::SecretService;

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncConfig {
    pub endpoint: String,
    pub user_id: String,
    pub token: String,
    pub sync_salt: String,
    pub last_seq: i64,
    pub last_sync_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncEntry {
    pub id: String,
    pub name: String,
    pub env_var: String,
    pub value: String,
    pub provider: String,
    pub account_name: String,
    pub org_name: String,
    pub description: String,
    pub source: String,
    pub environment: String,
    pub permission_profile: String,
    pub scopes: Vec<String>,
    pub projects: Vec<String>,
    pub apply_url: String,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
    pub last_verified_at: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConflictLogEntry {
    ts: String,
    name: String,
    local_updated_at: String,
    remote_updated_at: String,
    local_preview: String,
    remote_preview: String,
    resolution: String,
}

fn sync_config_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("sync.json"))
}

fn conflict_log_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("sync-conflicts.jsonl"))
}

fn load_sync_config() -> Result<SyncConfig> {
    let path = sync_config_path()?;
    if !path.exists() {
        bail!("Sync not configured. Run `kf sync init` first.");
    }

    let raw = fs::read_to_string(&path).with_context(|| {
        format!(
            "Failed to read sync configuration at {}",
            path.to_string_lossy()
        )
    })?;
    let config: SyncConfig =
        serde_json::from_str(&raw).context("Failed to parse sync configuration")?;
    Ok(config)
}

fn save_sync_config(config: &SyncConfig) -> Result<()> {
    let path = sync_config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(config)?;
    fs::write(&path, raw).with_context(|| {
        format!(
            "Failed to write sync configuration to {}",
            path.to_string_lossy()
        )
    })?;
    Ok(())
}

fn encrypt_entry(entry: &SyncEntry, crypto: &Crypto) -> Result<String> {
    let json = serde_json::to_vec(entry)?;
    let encrypted = crypto.encrypt(&json)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(encrypted))
}

fn decrypt_entry(blob: &str, crypto: &Crypto) -> Result<SyncEntry> {
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .context("Invalid sync payload encoding")?;
    let decrypted = crypto.decrypt(&encrypted)?;
    let entry: SyncEntry =
        serde_json::from_slice(&decrypted).context("Invalid decrypted sync entry")?;
    Ok(entry)
}

fn make_sync_crypto(passphrase: &str, salt: &str) -> Result<Crypto> {
    let salt_bytes = base64::engine::general_purpose::STANDARD
        .decode(salt)
        .context("Invalid sync salt in config")?;
    Crypto::new(passphrase, &salt_bytes)
}

fn parse_ts(value: &str, field: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("Invalid {field} timestamp: {value}"))
        .map(|dt| dt.with_timezone(&Utc))
}

fn parse_opt_ts(value: Option<&str>, field: &str) -> Result<Option<DateTime<Utc>>> {
    match value {
        Some(v) if !v.is_empty() => Ok(Some(parse_ts(v, field)?)),
        _ => Ok(None),
    }
}

fn to_sync_entry(entry: &SecretEntry, value: String) -> SyncEntry {
    SyncEntry {
        id: entry.id.clone(),
        name: entry.name.clone(),
        env_var: entry.env_var.clone(),
        value,
        provider: entry.provider.clone(),
        account_name: entry.account_name.clone(),
        org_name: entry.org_name.clone(),
        description: entry.description.clone(),
        source: entry.source.clone(),
        environment: entry.environment.clone(),
        permission_profile: entry.permission_profile.clone(),
        scopes: entry.scopes.clone(),
        projects: entry.projects.clone(),
        apply_url: entry.apply_url.clone(),
        expires_at: entry.expires_at.map(|v| v.to_rfc3339()),
        created_at: entry.created_at.to_rfc3339(),
        updated_at: entry.updated_at.to_rfc3339(),
        last_used_at: entry.last_used_at.map(|v| v.to_rfc3339()),
        last_verified_at: entry.last_verified_at.map(|v| v.to_rfc3339()),
        is_active: entry.is_active,
    }
}

fn to_secret_entry(sync: &SyncEntry) -> Result<SecretEntry> {
    Ok(SecretEntry {
        id: sync.id.clone(),
        name: sync.name.clone(),
        env_var: sync.env_var.clone(),
        provider: sync.provider.clone(),
        account_name: sync.account_name.clone(),
        org_name: sync.org_name.clone(),
        description: sync.description.clone(),
        source: sync.source.clone(),
        environment: sync.environment.clone(),
        permission_profile: sync.permission_profile.clone(),
        scopes: sync.scopes.clone(),
        projects: sync.projects.clone(),
        apply_url: sync.apply_url.clone(),
        expires_at: parse_opt_ts(sync.expires_at.as_deref(), "expires_at")?,
        created_at: parse_ts(&sync.created_at, "created_at")?,
        updated_at: parse_ts(&sync.updated_at, "updated_at")?,
        last_used_at: parse_opt_ts(sync.last_used_at.as_deref(), "last_used_at")?,
        last_verified_at: parse_opt_ts(sync.last_verified_at.as_deref(), "last_verified_at")?,
        is_active: sync.is_active,
    })
}

fn parse_boolish(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(v)) => *v,
        Some(serde_json::Value::Number(v)) => v.as_i64().unwrap_or_default() != 0,
        Some(serde_json::Value::String(v)) => {
            let lower = v.trim().to_lowercase();
            lower == "1" || lower == "true" || lower == "yes"
        }
        _ => false,
    }
}

fn parse_i64ish(value: Option<&serde_json::Value>) -> Option<i64> {
    match value {
        Some(serde_json::Value::Number(v)) => v.as_i64(),
        Some(serde_json::Value::String(v)) => v.parse::<i64>().ok(),
        _ => None,
    }
}

fn parse_count(value: Option<&serde_json::Value>, fallback: usize) -> usize {
    if let Some(v) = value {
        if let Some(n) = v.as_u64() {
            return n as usize;
        }
        if let Some(arr) = v.as_array() {
            return arr.len();
        }
        if let Some(s) = v.as_str() {
            if let Ok(n) = s.parse::<usize>() {
                return n;
            }
        }
    }
    fallback
}

fn ensure_unique_name(db: &Database, base: &str, projects: &[String]) -> Result<String> {
    let existing = db.get_secrets_by_name(base)?;
    let has_overlap = existing.iter().any(|e| {
        projects.iter().any(|p| e.projects.contains(p))
            || (projects.is_empty() && e.projects.is_empty())
    });
    if !has_overlap {
        return Ok(base.to_string());
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}-sync-{suffix}");
        let existing = db.get_secrets_by_name(&candidate)?;
        let has_overlap = existing.iter().any(|e| {
            projects.iter().any(|p| e.projects.contains(p))
                || (projects.is_empty() && e.projects.is_empty())
        });
        if !has_overlap {
            return Ok(candidate);
        }
        suffix += 1;
    }
}

/// Mask a secret value for display in conflict previews.
/// Values with length <= 8 are shown as "••••".
/// Longer values show first 4 chars + "••••" + last 4 chars.
fn mask_value(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() <= 8 {
        "••••".to_string()
    } else {
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{}••••{}", prefix, suffix)
    }
}

fn append_conflict_log(entry: &ConflictLogEntry) -> Result<()> {
    let path = conflict_log_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let line = serde_json::to_string(entry)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Failed to open conflict log at {}", path.to_string_lossy()))?;
    writeln!(file, "{}", line)?;
    Ok(())
}

pub fn cmd_sync(sub: SyncCommands) -> Result<()> {
    match sub {
        SyncCommands::Init { endpoint } => cmd_sync_init(endpoint),
        SyncCommands::Push => cmd_sync_push(),
        SyncCommands::Pull { strategy } => cmd_sync_pull(strategy),
        SyncCommands::Run { strategy } => cmd_sync_run(strategy),
        SyncCommands::Status => cmd_sync_status(),
        SyncCommands::Deploy => cmd_sync_deploy(),
        SyncCommands::Disconnect => cmd_sync_disconnect(),
        SyncCommands::Conflicts { clear } => cmd_sync_conflicts(clear),
    }
}

fn cmd_sync_init(endpoint: String) -> Result<()> {
    let endpoint = endpoint.trim_end_matches('/').to_string();

    let mut start_response = ureq::post(&format!("{}/api/device/start", endpoint))
        .header("Content-Type", "application/json")
        .send_json(serde_json::json!({}))
        .map_err(|e| anyhow::anyhow!("Failed to start device authorization: {e}"))?;
    let start_payload: serde_json::Value = start_response
        .body_mut()
        .read_json()
        .context("Failed to parse device start response")?;

    let device_code = start_payload
        .get("device_code")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .context("Sync server response missing device_code")?;
    let verification_url = start_payload
        .get("verification_url")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .context("Sync server response missing verification_url")?;

    println!("Opening browser for Google sign-in...");
    println!(
        "If browser doesn't open, visit: {}",
        style(&verification_url).cyan()
    );
    if let Err(err) = open::that(&verification_url) {
        println!(
            "{} Could not open browser automatically: {err}",
            style("!").yellow()
        );
    }

    print!("Waiting for device approval");
    io::stdout().flush()?;

    let mut approved_user_id: Option<String> = None;
    let mut approved_token: Option<String> = None;
    for attempt in 0..40 {
        if attempt > 0 {
            thread::sleep(Duration::from_secs(3));
        }

        let poll_result = ureq::post(&format!("{}/api/device/poll", endpoint))
            .header("Content-Type", "application/json")
            .send_json(serde_json::json!({
                "device_code": &device_code
            }));

        let mut poll_response = match poll_result {
            Ok(response) => response,
            Err(err) => {
                println!();
                bail!("Device authorization failed while polling: {err}");
            }
        };

        let poll_payload: serde_json::Value = poll_response
            .body_mut()
            .read_json()
            .context("Failed to parse device poll response")?;
        let status = poll_payload
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if status == "pending" {
            print!(".");
            io::stdout().flush()?;
            continue;
        }

        if status == "approved" {
            approved_user_id = poll_payload
                .get("user_id")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());
            approved_token = poll_payload
                .get("token")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());
            break;
        }

        println!();
        bail!("Device authorization failed: unexpected poll status '{status}'");
    }

    println!();

    let user_id = approved_user_id.context(
        "Timed out waiting for device approval (120s). Run `kf sync init` and approve in browser.",
    )?;
    let token = approved_token.context("Device approval succeeded but token was missing")?;

    let passphrase = match get_passphrase() {
        Ok(pass) => pass,
        Err(_) => Password::new()
            .with_prompt("Enter vault passphrase (will also be used for sync):")
            .with_confirmation("Confirm passphrase", "Passphrases don't match")
            .interact()?,
    };

    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty");
    }

    let sync_salt_bytes = Crypto::generate_salt();
    let sync_salt = base64::engine::general_purpose::STANDARD.encode(sync_salt_bytes);

    let config = SyncConfig {
        endpoint,
        user_id,
        token,
        sync_salt,
        last_seq: 0,
        last_sync_at: None,
    };

    save_sync_config(&config)?;
    println!(
        "{} Sync initialized. Run `kf sync` to start syncing.",
        style("✓").green().bold()
    );
    Ok(())
}

pub fn try_background_push() {
    let config_path = match sync_config_path() {
        Ok(p) => p,
        Err(_) => return,
    };
    if !config_path.exists() {
        return;
    }
    thread::spawn(|| {
        if let Err(e) = cmd_sync_push() {
            eprintln!(
                "{} Background sync failed: {e}",
                console::style("!").yellow()
            );
        }
    });
}

fn cmd_sync_push() -> Result<()> {
    let mut config = load_sync_config()?;
    let vault_passphrase = get_passphrase()?;
    let sync_crypto = make_sync_crypto(&vault_passphrase, &config.sync_salt)?;
    let service = SecretService::new(open_db()?);
    let db = service.db();

    let entries = db.list_secrets(&ListFilter {
        inactive: true,
        ..Default::default()
    })?;
    let all_raw = db.get_all_raw()?;

    let mut value_map: HashMap<String, String> = HashMap::new();
    for (name, encrypted) in &all_raw {
        let decrypted = db.decrypt_raw(encrypted)?;
        let value = String::from_utf8(decrypted)
            .with_context(|| format!("Secret '{}' has invalid UTF-8 value", name))?;
        value_map.insert(name.clone(), value);
    }

    let last_sync_cutoff = match config.last_sync_at.as_deref() {
        Some(ts) => Some(parse_ts(ts, "last_sync_at")?),
        None => None,
    };

    let to_push_entries: Vec<&SecretEntry> = entries
        .iter()
        .filter(|entry| {
            if let Some(cutoff) = last_sync_cutoff {
                entry.updated_at > cutoff
            } else {
                true
            }
        })
        .collect();

    let mut payload_entries = Vec::with_capacity(to_push_entries.len());
    for entry in to_push_entries {
        let value = value_map
            .get(&entry.name)
            .cloned()
            .with_context(|| format!("Missing raw value for secret '{}'", entry.name))?;
        let sync_entry = to_sync_entry(entry, value);
        let encrypted_blob = encrypt_entry(&sync_entry, &sync_crypto)?;
        payload_entries.push(serde_json::json!({
            "id": sync_entry.id,
            "encrypted_blob": encrypted_blob,
            "updated_at": sync_entry.updated_at,
            "is_deleted": !sync_entry.is_active,
        }));
    }

    let mut response = ureq::post(&format!("{}/api/push", config.endpoint))
        .header("Content-Type", "application/json")
        .header("Authorization", &format!("Bearer {}", config.token))
        .send_json(serde_json::json!({
            "entries": payload_entries,
            "since_seq": config.last_seq,
        }))
        .map_err(|e| anyhow::anyhow!("Failed to push sync changes: {e}"))?;
    let payload: serde_json::Value = response
        .body_mut()
        .read_json()
        .context("Failed to parse sync push response")?;

    let pushed = parse_count(payload.get("pushed"), 0);
    let conflicts = parse_count(payload.get("conflicts"), 0);
    if let Some(seq) = parse_i64ish(payload.get("latest_seq")) {
        config.last_seq = seq;
    }
    config.last_sync_at = Some(Utc::now().to_rfc3339());
    save_sync_config(&config)?;

    println!(
        "{} Pushed {} entries ({} conflicts)",
        style("✓").green().bold(),
        pushed,
        conflicts
    );
    Ok(())
}

fn cmd_sync_pull(strategy: ConflictStrategy) -> Result<()> {
    let mut config = load_sync_config()?;
    let vault_passphrase = get_passphrase()?;
    let sync_crypto = make_sync_crypto(&vault_passphrase, &config.sync_salt)?;
    let service = SecretService::new(open_db()?);
    let db = service.db();

    // Parse last_sync_at for conflict detection
    let last_sync_at: Option<DateTime<Utc>> = match config.last_sync_at.as_deref() {
        Some(ts) => Some(parse_ts(ts, "last_sync_at")?),
        None => None,
    };

    let local_entries = db.list_secrets(&ListFilter {
        inactive: true,
        ..Default::default()
    })?;
    // Fetch local raw values for Ask-mode preview
    let all_raw = db.get_all_raw()?;
    let mut local_value_map: HashMap<String, String> = HashMap::new();
    for (name, encrypted) in &all_raw {
        if let Ok(decrypted) = db.decrypt_raw(encrypted) {
            if let Ok(value) = String::from_utf8(decrypted) {
                local_value_map.insert(name.clone(), value);
            }
        }
    }

    let mut local_by_id: HashMap<String, SecretEntry> = HashMap::new();
    for entry in local_entries {
        local_by_id.insert(entry.id.clone(), entry);
    }

    let mut response = ureq::post(&format!("{}/api/pull", config.endpoint))
        .header("Content-Type", "application/json")
        .header("Authorization", &format!("Bearer {}", config.token))
        .send_json(serde_json::json!({
            "since_seq": config.last_seq,
        }))
        .map_err(|e| anyhow::anyhow!("Failed to pull sync changes: {e}"))?;
    let payload: serde_json::Value = response
        .body_mut()
        .read_json()
        .context("Failed to parse sync pull response")?;

    let changes = payload
        .get("entries")
        .or_else(|| payload.get("changes"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut inserted = 0usize;
    let mut updated = 0usize;
    let mut deactivated = 0usize;
    let mut skipped = 0usize;
    let mut conflicts_resolved = 0usize;

    for change in &changes {
        let encrypted_blob = change
            .get("encrypted_blob")
            .and_then(|v| v.as_str())
            .context("Sync pull change missing encrypted_blob")?;
        let is_deleted = parse_boolish(change.get("is_deleted"));

        let remote_entry = decrypt_entry(encrypted_blob, &sync_crypto)?;
        let remote_updated = parse_ts(&remote_entry.updated_at, "updated_at")?;

        if let Some(local) = local_by_id.get(&remote_entry.id) {
            if is_deleted {
                if local.is_active {
                    db.update_secret_metadata(
                        &local.id,
                        &MetadataUpdate {
                            is_active: Some(false),
                            ..Default::default()
                        },
                    )?;
                    deactivated += 1;
                } else {
                    skipped += 1;
                }
                continue;
            }

            // Conflict detection
            // local_dirty: local was modified after last sync
            // remote_dirty: remote was modified after last sync (or no last_sync = always true)
            let local_dirty = last_sync_at
                .map(|t| local.updated_at > t)
                .unwrap_or(false);
            let remote_dirty = last_sync_at
                .map(|t| remote_updated > t)
                .unwrap_or(true);

            if local_dirty && remote_dirty {
                // True conflict: both sides changed since last sync
                let local_val = local_value_map.get(&local.name).cloned().unwrap_or_default();
                let local_preview = mask_value(&local_val);
                let remote_preview = mask_value(&remote_entry.value);

                let resolution = resolve_conflict(
                    &strategy,
                    &remote_entry.name,
                    &local.updated_at.to_rfc3339(),
                    &remote_updated.to_rfc3339(),
                    &local_preview,
                    &remote_preview,
                )?;

                // Log the conflict
                let log_entry = ConflictLogEntry {
                    ts: Utc::now().to_rfc3339(),
                    name: remote_entry.name.clone(),
                    local_updated_at: local.updated_at.to_rfc3339(),
                    remote_updated_at: remote_updated.to_rfc3339(),
                    local_preview: local_preview.clone(),
                    remote_preview: remote_preview.clone(),
                    resolution: resolution.clone(),
                };
                if let Err(e) = append_conflict_log(&log_entry) {
                    eprintln!("{} Failed to write conflict log: {e}", style("!").yellow());
                }

                match resolution.as_str() {
                    "cloud" => {
                        // Apply remote value and metadata
                        apply_remote_entry(db, local, &remote_entry)?;
                        updated += 1;
                    }
                    "local" => {
                        // Keep local value, but refresh updated_at so push will include it
                        db.update_secret_metadata(
                            &local.id,
                            &MetadataUpdate {
                                ..Default::default()
                            },
                        )?;
                        skipped += 1;
                    }
                    _ => {
                        // "skip" - do nothing
                        skipped += 1;
                    }
                }
                conflicts_resolved += 1;
                continue;
            }

            if remote_dirty {
                // Safe update: only remote changed
                apply_remote_entry(db, local, &remote_entry)?;
                updated += 1;
            } else {
                skipped += 1;
            }
            continue;
        }

        if is_deleted {
            skipped += 1;
            continue;
        }

        let mut entry = to_secret_entry(&remote_entry)?;
        if !db.get_secrets_by_name(&entry.name)?.is_empty() {
            let unique = ensure_unique_name(db, &entry.name, &entry.projects)?;
            entry.name = unique;
        }
        db.add_secret(&entry, &remote_entry.value)?;
        inserted += 1;
    }

    if let Some(seq) = parse_i64ish(payload.get("latest_seq")) {
        config.last_seq = seq;
    }
    config.last_sync_at = Some(Utc::now().to_rfc3339());
    save_sync_config(&config)?;

    println!(
        "{} Pulled {} changes (inserted {}, updated {}, deactivated {}, skipped {}, conflicts {})",
        style("✓").green().bold(),
        changes.len(),
        inserted,
        updated,
        deactivated,
        skipped,
        conflicts_resolved,
    );
    Ok(())
}

/// Apply a remote entry's value and metadata to the local database.
fn apply_remote_entry(db: &Database, local: &SecretEntry, remote: &SyncEntry) -> Result<()> {
    db.update_secret_value(&local.id, &remote.value)?;
    let expires_at = parse_opt_ts(remote.expires_at.as_deref(), "expires_at")?;
    let last_verified_at =
        parse_opt_ts(remote.last_verified_at.as_deref(), "last_verified_at")?;
    db.update_secret_metadata(
        &local.id,
        &MetadataUpdate {
            provider: Some(&remote.provider),
            account_name: Some(&remote.account_name),
            org_name: Some(&remote.org_name),
            description: Some(&remote.description),
            source: Some(&remote.source),
            environment: Some(&remote.environment),
            permission_profile: Some(&remote.permission_profile),
            scopes: Some(&remote.scopes),
            projects: Some(&remote.projects),
            apply_url: Some(&remote.apply_url),
            expires_at: Some(expires_at),
            last_verified_at: Some(last_verified_at),
            is_active: Some(remote.is_active),
        },
    )?;
    Ok(())
}

/// Resolve a conflict according to the chosen strategy.
/// Returns "cloud", "local", or "skip".
fn resolve_conflict(
    strategy: &ConflictStrategy,
    name: &str,
    local_updated_at: &str,
    remote_updated_at: &str,
    local_preview: &str,
    remote_preview: &str,
) -> Result<String> {
    match strategy {
        ConflictStrategy::Cloud => {
            println!(
                "{} Conflict on {}: cloud wins (local: {}, remote: {})",
                style("!").yellow(),
                style(name).bold(),
                local_preview,
                remote_preview,
            );
            Ok("cloud".to_string())
        }
        ConflictStrategy::Local => {
            println!(
                "{} Conflict on {}: local wins (local: {}, remote: {})",
                style("!").yellow(),
                style(name).bold(),
                local_preview,
                remote_preview,
            );
            Ok("local".to_string())
        }
        ConflictStrategy::Ask => {
            println!();
            println!(
                "{} Conflict detected: {}",
                style("!").yellow().bold(),
                style(name).bold()
            );
            println!(
                "  Local  ({}): {}",
                style(local_updated_at).dim(),
                style(local_preview).cyan()
            );
            println!(
                "  Remote ({}): {}",
                style(remote_updated_at).dim(),
                style(remote_preview).cyan()
            );
            println!("  Resolution: [c]loud / [l]ocal / [s]kip ?");
            print!("  > ");
            io::stdout().flush()?;

            let stdin = io::stdin();
            let mut input = String::new();
            stdin.lock().read_line(&mut input)?;
            let choice = input.trim().to_lowercase();

            match choice.as_str() {
                "l" | "local" => Ok("local".to_string()),
                "s" | "skip" => Ok("skip".to_string()),
                _ => {
                    // Default to cloud for anything else including "c"
                    Ok("cloud".to_string())
                }
            }
        }
    }
}

fn cmd_sync_run(strategy: ConflictStrategy) -> Result<()> {
    println!("Pulling remote changes...");
    cmd_sync_pull(strategy)?;
    println!("Pushing local changes...");
    cmd_sync_push()?;
    println!("Sync complete.");
    Ok(())
}

fn cmd_sync_status() -> Result<()> {
    let config = load_sync_config()?;

    let mut response = ureq::get(&format!("{}/api/status", config.endpoint))
        .header("Authorization", &format!("Bearer {}", config.token))
        .call()
        .map_err(|e| anyhow::anyhow!("Failed to fetch sync status: {e}"))?;
    let payload: serde_json::Value = response
        .body_mut()
        .read_json()
        .context("Failed to parse sync status response")?;

    let remote_total = parse_count(
        payload
            .get("total")
            .or_else(|| payload.get("total_entries"))
            .or_else(|| payload.get("entries")),
        0,
    );

    println!("Endpoint: {}", style(&config.endpoint).cyan());
    println!("Remote entries: {}", remote_total);
    println!(
        "Last sync: {}",
        config.last_sync_at.as_deref().unwrap_or("never")
    );
    println!("Sync cursor: {}", config.last_seq);
    Ok(())
}

fn cmd_sync_deploy() -> Result<()> {
    let npx_ok = Command::new("npx")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !npx_ok {
        bail!("`npx` is required for deployment. Install Node.js first.");
    }

    let worker_dir = find_worker_dir()?;

    let whoami = Command::new("npx")
        .args(["wrangler", "whoami"])
        .output()
        .context("Failed to run `npx wrangler whoami`")?;
    if !whoami.status.success() {
        println!(
            "{} Wrangler not logged in. Opening login flow...",
            style("▸").dim()
        );
        let login_status = Command::new("npx")
            .args(["wrangler", "login"])
            .status()
            .context("Failed to run `npx wrangler login`")?;
        if !login_status.success() {
            bail!("Wrangler login failed");
        }
    }

    println!("Installing worker dependencies...");
    let install_status = Command::new("npm")
        .arg("install")
        .current_dir(&worker_dir)
        .status()
        .context("Failed to run `npm install` in worker directory")?;
    if !install_status.success() {
        bail!("`npm install` failed in worker directory");
    }

    println!();
    println!("{} Worker setup prepared.", style("✓").green().bold());
    println!("Run these commands manually to finish deploy:");
    println!("  cd {}", worker_dir.to_string_lossy());
    println!("  npx wrangler d1 create keyflow-sync");
    println!("  npx wrangler kv namespace create SYNC_KV");
    println!("  npx wrangler secret put JWT_SECRET");
    println!("  npx wrangler d1 execute keyflow-sync --file=./schema.sql");
    println!("  npx wrangler deploy");
    println!("After deploy, run: kf sync init --endpoint <your-worker-url>");
    Ok(())
}

fn find_worker_dir() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("Failed to read current directory")?;
    if let Some(found) = find_worker_from(&cwd) {
        return Ok(found);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if let Some(found) = find_worker_from(parent) {
                return Ok(found);
            }
        }
    }

    bail!("Could not find worker/ directory. Expected worker/ in current repo.");
}

fn find_worker_from(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let candidate = dir.join("worker");
        if candidate.is_dir() && candidate.join("package.json").exists() {
            return Some(candidate);
        }
    }
    None
}

fn cmd_sync_disconnect() -> Result<()> {
    let path = sync_config_path()?;
    if !path.exists() {
        bail!("Sync not configured. Run `kf sync init` first.");
    }

    let confirmed = Confirm::new()
        .with_prompt("This will remove sync configuration. Remote data is NOT deleted. Continue?")
        .default(false)
        .interact()?;
    if !confirmed {
        println!("Cancelled.");
        return Ok(());
    }

    fs::remove_file(&path).with_context(|| {
        format!(
            "Failed to remove sync configuration file at {}",
            path.to_string_lossy()
        )
    })?;
    println!("{} Sync disconnected.", style("✓").green().bold());
    Ok(())
}

fn cmd_sync_conflicts(clear: bool) -> Result<()> {
    let path = conflict_log_path()?;

    if clear {
        if path.exists() {
            fs::remove_file(&path).with_context(|| {
                format!(
                    "Failed to remove conflict log at {}",
                    path.to_string_lossy()
                )
            })?;
            println!("{} Conflict log cleared.", style("✓").green().bold());
        } else {
            println!("No conflict log found.");
        }
        return Ok(());
    }

    if !path.exists() {
        println!("No conflict log found. (Conflicts are logged to {})", path.to_string_lossy());
        return Ok(());
    }

    let file = fs::File::open(&path)
        .with_context(|| format!("Failed to open conflict log at {}", path.to_string_lossy()))?;
    let reader = io::BufReader::new(file);
    let mut count = 0usize;

    println!("{}", style("Sync Conflict Log").bold().underlined());
    println!();

    for line in reader.lines() {
        let line = line.context("Failed to read conflict log line")?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ConflictLogEntry>(&line) {
            Ok(entry) => {
                count += 1;
                println!(
                    "{} {} {}",
                    style(&entry.ts).dim(),
                    style(&entry.name).bold(),
                    style(format!("[{}]", entry.resolution)).yellow()
                );
                println!(
                    "  Local  ({}): {}",
                    style(&entry.local_updated_at).dim(),
                    style(&entry.local_preview).cyan()
                );
                println!(
                    "  Remote ({}): {}",
                    style(&entry.remote_updated_at).dim(),
                    style(&entry.remote_preview).cyan()
                );
                println!();
            }
            Err(e) => {
                eprintln!("{} Failed to parse conflict log entry: {e}", style("!").yellow());
            }
        }
    }

    if count == 0 {
        println!("No conflict entries found.");
    } else {
        println!("{} total conflict(s) logged.", count);
        println!(
            "Log file: {}",
            style(path.to_string_lossy()).dim()
        );
        println!("Run `kf sync conflicts --clear` to clear the log.");
    }

    Ok(())
}
