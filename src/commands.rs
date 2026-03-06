use anyhow::{bail, Context, Result};
use chrono::{NaiveDate, TimeZone, Utc};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table, Cell, Color};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::fs;
use std::path::Path;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::{AppConfig, ListFilter, SecretEntry};

const PROVIDERS: &[&str] = &[
    "google",
    "github",
    "cloudflare",
    "aws",
    "azure",
    "openai",
    "anthropic",
    "stripe",
    "vercel",
    "supabase",
    "firebase",
    "twilio",
    "sendgrid",
    "slack",
    "docker",
    "npm",
    "pypi",
    "other",
];

pub fn get_data_dir() -> Result<std::path::PathBuf> {
    let dir = dirs::home_dir()
        .context("Cannot find home directory")?
        .join(".keyflow");
    Ok(dir)
}

pub fn get_passphrase() -> Result<String> {
    // Check env var first
    if let Ok(pass) = std::env::var("KEYFLOW_PASSPHRASE") {
        return Ok(pass);
    }
    // Interactive prompt
    let pass = Password::new()
        .with_prompt("KeyFlow passphrase")
        .interact()?;
    Ok(pass)
}

pub fn open_db() -> Result<Database> {
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

    let salt = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &config.salt,
    )?;

    let passphrase = get_passphrase()?;
    let crypto = Crypto::new(&passphrase, &salt)?;

    let db_path = data_dir.join("keyflow.db");
    Database::open(db_path.to_str().unwrap(), crypto)
}

// === INIT ===

pub fn cmd_init(passphrase_arg: Option<String>) -> Result<()> {
    let data_dir = get_data_dir()?;

    if data_dir.join("config.json").exists() {
        if passphrase_arg.is_some() {
            // Non-interactive: skip confirmation
        } else if !Confirm::new()
            .with_prompt("KeyFlow is already initialized. Re-initialize? (this won't delete existing secrets)")
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
    let salt_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &salt,
    );

    let config = AppConfig { salt: salt_b64 };
    let config_str = serde_json::to_string_pretty(&config)?;
    fs::write(data_dir.join("config.json"), config_str)?;

    // Verify crypto works
    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = data_dir.join("keyflow.db");
    Database::open(db_path.to_str().unwrap(), crypto)?;

    // Set restrictive permissions on the data directory
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(data_dir.join("config.json"), fs::Permissions::from_mode(0o600))?;
    }

    println!(
        "\n{} KeyFlow initialized at {}",
        style("✓").green().bold(),
        style(data_dir.display()).dim()
    );
    println!(
        "\nTip: Set {} to avoid passphrase prompts.",
        style("KEYFLOW_PASSPHRASE").yellow()
    );
    println!(
        "     Add to your shell profile or use: {} keyflow <command>",
        style("KEYFLOW_PASSPHRASE=xxx").dim()
    );

    Ok(())
}

// === ADD ===

pub fn cmd_add(
    name: Option<String>,
    env_var: Option<String>,
    value: Option<String>,
    provider: Option<String>,
    desc: Option<String>,
    scopes: Option<String>,
    projects: Option<String>,
    url: Option<String>,
    expires: Option<String>,
) -> Result<()> {
    let db = open_db()?;

    // Detect non-interactive mode: name and value both provided via flags
    let non_interactive = name.is_some() && value.is_some();

    let name = match name {
        Some(n) => n,
        None => Input::new()
            .with_prompt("Secret name (human-readable)")
            .interact_text()?,
    };

    if db.secret_exists(&name)? {
        bail!("Secret '{}' already exists. Use 'keyflow update' to modify.", name);
    }

    let env_var = match env_var {
        Some(e) => e,
        None if non_interactive => name.to_uppercase().replace(['-', ' ', '.'], "_"),
        None => {
            let suggested = name.to_uppercase().replace(['-', ' ', '.'], "_");
            Input::new()
                .with_prompt("Environment variable name")
                .default(suggested)
                .interact_text()?
        }
    };

    let secret_value = match value {
        Some(v) => v,
        None => Password::new()
            .with_prompt("Secret value")
            .interact()?,
    };

    let provider = match provider {
        Some(p) => p,
        None if non_interactive => "other".to_string(),
        None => {
            let idx = Select::new()
                .with_prompt("Provider")
                .items(PROVIDERS)
                .default(0)
                .interact()?;
            PROVIDERS[idx].to_string()
        }
    };

    let description = match desc {
        Some(d) => d,
        None if non_interactive => String::new(),
        None => Input::new()
            .with_prompt("Description (what is this key for?)")
            .default(String::new())
            .interact_text()?,
    };

    let parse_csv = |s: String| -> Vec<String> {
        s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    };

    let scopes_vec: Vec<String> = match scopes {
        Some(s) => parse_csv(s),
        None if non_interactive => vec![],
        None => {
            let s: String = Input::new()
                .with_prompt("Scopes/permissions (comma-separated, optional)")
                .default(String::new())
                .interact_text()?;
            parse_csv(s)
        }
    };

    let projects_vec: Vec<String> = match projects {
        Some(p) => parse_csv(p),
        None if non_interactive => vec![],
        None => {
            let p: String = Input::new()
                .with_prompt("Project tags (comma-separated, optional)")
                .default(String::new())
                .interact_text()?;
            parse_csv(p)
        }
    };

    let apply_url = match url {
        Some(u) => u,
        None if non_interactive => get_default_url(&provider),
        None => Input::new()
            .with_prompt("Management URL (where to renew/manage)")
            .default(get_default_url(&provider))
            .interact_text()?,
    };

    let expires_at = match expires {
        Some(e) => parse_date(&e)?,
        None if non_interactive => None,
        None => {
            let e: String = Input::new()
                .with_prompt("Expiry date (YYYY-MM-DD, empty for none)")
                .default(String::new())
                .interact_text()?;
            if e.is_empty() {
                None
            } else {
                parse_date(&e)?
            }
        }
    };

    let now = Utc::now();
    let entry = SecretEntry {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.clone(),
        env_var,
        provider,
        description,
        scopes: scopes_vec,
        projects: projects_vec,
        apply_url,
        expires_at,
        created_at: now,
        updated_at: now,
        last_used_at: None,
        is_active: true,
    };

    db.add_secret(&entry, &secret_value)?;
    println!(
        "\n{} Secret '{}' added (env: {})",
        style("✓").green().bold(),
        style(&entry.name).cyan(),
        style(&entry.env_var).yellow()
    );

    Ok(())
}

// === LIST ===

pub fn cmd_list(provider: Option<String>, project: Option<String>, expiring: bool, inactive: bool) -> Result<()> {
    let db = open_db()?;
    let entries = db.list_secrets(&ListFilter {
        provider,
        project,
        expiring,
        inactive,
    })?;

    if entries.is_empty() {
        println!("{}", style("No secrets found.").dim());
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Name", "Env Var", "Provider", "Projects", "Expires", "Status"]);

    for entry in &entries {
        let status = entry.status();
        let status_cell = match status {
            crate::models::KeyStatus::Active => Cell::new("Active").fg(Color::Green),
            crate::models::KeyStatus::ExpiringSoon => Cell::new("Expiring Soon").fg(Color::Yellow),
            crate::models::KeyStatus::Expired => Cell::new("EXPIRED").fg(Color::Red),
            crate::models::KeyStatus::Inactive => Cell::new("Inactive").fg(Color::DarkGrey),
            crate::models::KeyStatus::Unknown => Cell::new("Unknown").fg(Color::DarkGrey),
        };

        let expires_str = entry
            .expires_at
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "-".to_string());

        let projects_str = if entry.projects.is_empty() {
            "-".to_string()
        } else {
            entry.projects.join(", ")
        };

        table.add_row(vec![
            Cell::new(&entry.name),
            Cell::new(&entry.env_var).fg(Color::Yellow),
            Cell::new(&entry.provider),
            Cell::new(&projects_str),
            Cell::new(&expires_str),
            status_cell,
        ]);
    }

    println!("{table}");
    println!(
        "\n{} Total: {} secrets",
        style("ℹ").blue(),
        entries.len()
    );

    Ok(())
}

// === GET ===

pub fn cmd_get(name: &str, raw: bool) -> Result<()> {
    let db = open_db()?;
    let value = db.get_secret_value(name)?;

    if raw {
        print!("{}", value);
    } else {
        let entry = db.get_secret(name)?;
        println!(
            "{}: {} = {}",
            style(&entry.name).cyan(),
            style(&entry.env_var).yellow(),
            style(&value).dim()
        );
    }

    Ok(())
}

// === REMOVE ===

pub fn cmd_remove(name: &str, force: bool) -> Result<()> {
    let db = open_db()?;

    if !db.secret_exists(name)? {
        bail!("Secret '{}' not found", name);
    }

    if !force {
        let confirmed = Confirm::new()
            .with_prompt(format!("Remove secret '{}'?", name))
            .default(false)
            .interact()?;
        if !confirmed {
            println!("Cancelled.");
            return Ok(());
        }
    }

    db.remove_secret(name)?;
    println!(
        "{} Secret '{}' removed",
        style("✓").green().bold(),
        name
    );

    Ok(())
}

// === UPDATE ===

pub fn cmd_update(
    name: &str,
    value: Option<String>,
    provider: Option<String>,
    desc: Option<String>,
    scopes: Option<String>,
    projects: Option<String>,
    url: Option<String>,
    expires: Option<String>,
    active: Option<bool>,
) -> Result<()> {
    let db = open_db()?;

    if !db.secret_exists(name)? {
        bail!("Secret '{}' not found", name);
    }

    if let Some(v) = value {
        db.update_secret_value(name, &v)?;
        println!(
            "{} Secret value updated for '{}'",
            style("✓").green().bold(),
            name
        );
    }

    let scopes_vec = scopes.map(|s| {
        s.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    });
    let projects_vec = projects.map(|p| {
        p.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    });
    let expires_at = match expires {
        Some(ref e) if e.is_empty() => Some(None), // Clear expiry
        Some(ref e) => Some(parse_date(e)?),
        None => None,
    };

    db.update_secret_metadata(
        name,
        provider.as_deref(),
        desc.as_deref(),
        scopes_vec.as_deref(),
        projects_vec.as_deref(),
        url.as_deref(),
        expires_at,
        active,
    )?;

    println!(
        "{} Metadata updated for '{}'",
        style("✓").green().bold(),
        name
    );
    Ok(())
}

// === RUN ===

pub fn cmd_run(project: Option<String>, command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        bail!("No command specified");
    }

    let db = open_db()?;
    let env_pairs = db.get_all_for_env(project.as_deref())?;

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (key, val) in &env_pairs {
        cmd.env(key, val);
    }

    let status = cmd.status().context("Failed to execute command")?;

    std::process::exit(status.code().unwrap_or(1));
}

// === IMPORT ===

pub fn cmd_import(file: &str, provider: Option<String>, project: Option<String>) -> Result<()> {
    let path = Path::new(file);
    if !path.exists() {
        bail!("File not found: {}", file);
    }

    let content = fs::read_to_string(path)?;
    let db = open_db()?;
    let mut count = 0;

    let provider = provider.unwrap_or_else(|| "imported".to_string());
    let projects = project.map(|p| vec![p]).unwrap_or_default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"').trim_matches('\'');

            if key.is_empty() || val.is_empty() {
                continue;
            }

            let name = key.to_lowercase().replace('_', "-");

            if db.secret_exists(&name)? {
                println!(
                    "{} Skipping '{}' (already exists)",
                    style("⊘").dim(),
                    name
                );
                continue;
            }

            let now = Utc::now();
            let entry = SecretEntry {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.clone(),
                env_var: key.to_string(),
                provider: provider.clone(),
                description: format!("Imported from {}", file),
                scopes: vec![],
                projects: projects.clone(),
                apply_url: String::new(),
                expires_at: None,
                created_at: now,
                updated_at: now,
                last_used_at: None,
                is_active: true,
            };

            db.add_secret(&entry, val)?;
            println!(
                "{} Imported '{}' ({})",
                style("✓").green(),
                style(&name).cyan(),
                style(key).yellow()
            );
            count += 1;
        }
    }

    println!(
        "\n{} Imported {} secrets from {}",
        style("✓").green().bold(),
        count,
        file
    );
    Ok(())
}

// === EXPORT ===

pub fn cmd_export(project: Option<String>, output: Option<String>) -> Result<()> {
    let db = open_db()?;
    let entries = db.list_secrets(&ListFilter {
        project,
        ..Default::default()
    })?;

    let mut lines = Vec::new();
    lines.push("# Generated by KeyFlow".to_string());
    lines.push(format!("# Date: {}", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    lines.push(String::new());

    let mut current_provider = String::new();
    for entry in &entries {
        if entry.provider != current_provider {
            if !current_provider.is_empty() {
                lines.push(String::new());
            }
            lines.push(format!("# === {} ===", entry.provider.to_uppercase()));
            current_provider = entry.provider.clone();
        }

        let value = db.get_secret_value(&entry.name)?;
        lines.push(format!("{}={}", entry.env_var, value));
    }

    let content = lines.join("\n") + "\n";

    match output {
        Some(path) => {
            fs::write(&path, &content)?;
            println!(
                "{} Exported {} secrets to {}",
                style("✓").green().bold(),
                entries.len(),
                path
            );
        }
        None => {
            print!("{}", content);
        }
    }

    Ok(())
}

// === HEALTH ===

pub fn cmd_health() -> Result<()> {
    let db = open_db()?;
    let entries = db.list_secrets(&ListFilter {
        inactive: true,
        ..Default::default()
    })?;

    let now = Utc::now();
    let mut issues = 0;

    println!("{}", style("KeyFlow Health Report").bold().cyan());
    println!("{}", style("═".repeat(50)).dim());

    // Expired
    let expired: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::Expired))
        .collect();
    if !expired.is_empty() {
        issues += expired.len();
        println!("\n{} {} Expired Keys:", style("✗").red().bold(), expired.len());
        for e in &expired {
            println!(
                "  {} {} (expired {})",
                style("•").red(),
                style(&e.name).cyan(),
                e.expires_at
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default()
            );
            if !e.apply_url.is_empty() {
                println!("    Renew at: {}", style(&e.apply_url).underlined());
            }
        }
    }

    // Expiring soon
    let expiring: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::ExpiringSoon))
        .collect();
    if !expiring.is_empty() {
        issues += expiring.len();
        println!(
            "\n{} {} Keys Expiring Within 7 Days:",
            style("⚠").yellow().bold(),
            expiring.len()
        );
        for e in &expiring {
            let days_left = e
                .expires_at
                .map(|d| (d - now).num_days())
                .unwrap_or(0);
            println!(
                "  {} {} ({} days left)",
                style("•").yellow(),
                style(&e.name).cyan(),
                days_left
            );
            if !e.apply_url.is_empty() {
                println!("    Renew at: {}", style(&e.apply_url).underlined());
            }
        }
    }

    // Unused > 30 days
    let unused: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.is_active && {
                let last = e.last_used_at.unwrap_or(e.created_at);
                (now - last).num_days() > 30
            }
        })
        .collect();
    if !unused.is_empty() {
        println!(
            "\n{} {} Keys Unused for 30+ Days:",
            style("ℹ").blue().bold(),
            unused.len()
        );
        for e in &unused {
            let days = e
                .last_used_at
                .map(|d| (now - d).num_days())
                .unwrap_or_else(|| (now - e.created_at).num_days());
            println!(
                "  {} {} ({} days since last use)",
                style("•").dim(),
                style(&e.name).cyan(),
                days
            );
        }
    }

    // Inactive
    let inactive: Vec<_> = entries.iter().filter(|e| !e.is_active).collect();
    if !inactive.is_empty() {
        println!(
            "\n{} {} Inactive Keys:",
            style("⊘").dim(),
            inactive.len()
        );
        for e in &inactive {
            println!("  {} {}", style("•").dim(), style(&e.name).dim());
        }
    }

    println!("{}", style("═".repeat(50)).dim());
    if issues == 0 && inactive.is_empty() && unused.is_empty() {
        println!(
            "\n{} All {} secrets are healthy!",
            style("✓").green().bold(),
            entries.len()
        );
    } else {
        println!(
            "\nTotal: {} secrets, {} issues to address",
            entries.len(),
            issues
        );
    }

    Ok(())
}

// === SEARCH ===

pub fn cmd_search(query: &str) -> Result<()> {
    let db = open_db()?;
    let entries = db.search_secrets(query)?;

    if entries.is_empty() {
        println!("No secrets matching '{}' found.", style(query).yellow());
        return Ok(());
    }

    println!(
        "Found {} secrets matching '{}':\n",
        entries.len(),
        style(query).yellow()
    );

    for entry in &entries {
        let status = entry.status();
        let status_str = match status {
            crate::models::KeyStatus::Active => style(status.to_string()).green(),
            crate::models::KeyStatus::ExpiringSoon => style(status.to_string()).yellow(),
            crate::models::KeyStatus::Expired => style(status.to_string()).red(),
            _ => style(status.to_string()).dim(),
        };

        println!("  {} {}", style("▸").bold(), style(&entry.name).cyan().bold());
        println!("    env: {}  provider: {}  status: {}",
            style(&entry.env_var).yellow(),
            &entry.provider,
            status_str,
        );
        if !entry.description.is_empty() {
            println!("    {}", style(&entry.description).dim());
        }
        if !entry.projects.is_empty() {
            println!("    projects: {}", entry.projects.join(", "));
        }
        println!();
    }

    Ok(())
}

// === SERVE ===

pub fn cmd_serve() -> Result<()> {
    let db = open_db()?;
    crate::mcp::serve(&db)
}

// === Helpers ===

fn parse_date(s: &str) -> Result<Option<chrono::DateTime<Utc>>> {
    if s.is_empty() {
        return Ok(None);
    }
    let date = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .context("Invalid date format, expected YYYY-MM-DD")?;
    let datetime = date.and_hms_opt(0, 0, 0).unwrap();
    Ok(Some(Utc.from_utc_datetime(&datetime)))
}

fn get_default_url(provider: &str) -> String {
    match provider {
        "google" => "https://console.cloud.google.com/apis/credentials".to_string(),
        "github" => "https://github.com/settings/tokens".to_string(),
        "cloudflare" => "https://dash.cloudflare.com/profile/api-tokens".to_string(),
        "aws" => "https://console.aws.amazon.com/iam/home#/security_credentials".to_string(),
        "openai" => "https://platform.openai.com/api-keys".to_string(),
        "anthropic" => "https://console.anthropic.com/settings/keys".to_string(),
        "stripe" => "https://dashboard.stripe.com/apikeys".to_string(),
        "vercel" => "https://vercel.com/account/tokens".to_string(),
        "supabase" => "https://supabase.com/dashboard/account/tokens".to_string(),
        "firebase" => "https://console.firebase.google.com/project/_/settings/serviceaccounts".to_string(),
        "twilio" => "https://console.twilio.com/".to_string(),
        "sendgrid" => "https://app.sendgrid.com/settings/api_keys".to_string(),
        "slack" => "https://api.slack.com/apps".to_string(),
        "docker" => "https://hub.docker.com/settings/security".to_string(),
        "npm" => "https://www.npmjs.com/settings/~/tokens".to_string(),
        _ => String::new(),
    }
}
