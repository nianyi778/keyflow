use anyhow::{bail, Context, Result};
use chrono::Utc;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::auth::{open_db, select_secret};
use crate::commands::helpers::{
    detect_project_name, detect_project_name_in_dir, get_default_url, infer_provider, parse_csv,
    parse_date, PROVIDERS,
};
use crate::models::{KeyStatus, ListFilter, SecretEntry, TEMPLATES};

pub struct AddArgs {
    pub env_var: Option<String>,
    pub value: Option<String>,
    pub provider: Option<String>,
    pub account: Option<String>,
    pub org: Option<String>,
    pub projects: Option<String>,
    pub group: Option<String>,
    pub desc: Option<String>,
    pub source: Option<String>,
    pub expires: Option<String>,
    pub environment: Option<String>,
    pub permission: Option<String>,
    pub paste: bool,
}

pub struct UpdateArgs {
    pub name: Option<String>,
    pub value: Option<String>,
    pub provider: Option<String>,
    pub account: Option<String>,
    pub org: Option<String>,
    pub desc: Option<String>,
    pub source: Option<String>,
    pub environment: Option<String>,
    pub permission: Option<String>,
    pub scopes: Option<String>,
    pub projects: Option<String>,
    pub url: Option<String>,
    pub expires: Option<String>,
    pub active: Option<bool>,
    pub group: Option<String>,
    pub verify: bool,
}

#[derive(Clone)]
struct ImportSource {
    path: PathBuf,
    project_name: Option<String>,
}

#[derive(Clone)]
struct ScanCandidate {
    env_var: String,
    provider: String,
    file: PathBuf,
    project_name: Option<String>,
}

#[derive(Default)]
struct ImportStats {
    imported: usize,
    overwritten: usize,
    skipped: usize,
}

fn collect_import_sources(path: &Path) -> Result<Vec<ImportSource>> {
    collect_import_sources_inner(path, false)
}

fn collect_import_sources_recursive(path: &Path) -> Result<Vec<ImportSource>> {
    collect_import_sources_inner(path, true)
}

fn collect_import_sources_inner(path: &Path, recursive: bool) -> Result<Vec<ImportSource>> {
    if path.is_file() {
        return Ok(vec![ImportSource {
            path: path.to_path_buf(),
            project_name: path.parent().and_then(detect_project_name_in_dir),
        }]);
    }

    if !path.is_dir() {
        bail!("Path not found: {}", path.display());
    }

    let mut files = Vec::new();

    if recursive {
        for entry in walkdir::WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_str().unwrap_or("");
                !name.starts_with('.') || name.starts_with(".env") || e.depth() == 0
            })
        {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let candidate = entry.path();
            let Some(name) = candidate.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
                let project_name = candidate.parent().and_then(detect_project_name_in_dir);
                files.push(ImportSource {
                    path: candidate.to_path_buf(),
                    project_name,
                });
            }
        }
    } else {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let candidate = entry.path();
            if !candidate.is_file() {
                continue;
            }
            let Some(name) = candidate.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
                files.push(ImportSource {
                    path: candidate,
                    project_name: detect_project_name_in_dir(path),
                });
            }
        }
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));

    if files.is_empty() {
        bail!("No .env files found in '{}'", path.display());
    }

    Ok(files)
}

fn import_env_file(
    db: &crate::db::Database,
    path: &Path,
    provider: &str,
    account_name: &str,
    projects: &[String],
    source: Option<&str>,
    on_conflict: &str,
) -> Result<ImportStats> {
    let content = fs::read_to_string(path)?;
    let mut stats = ImportStats::default();
    let source_label = source
        .map(str::to_string)
        .unwrap_or_else(|| format!("import:{}", path.display()));

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

            let mut name = key.to_lowercase().replace('_', "-");

            if db.secret_exists(&name)? {
                match on_conflict {
                    "skip" => {
                        println!(
                            "{} Skipping '{}' from {} (already exists)",
                            style("⊘").dim(),
                            name,
                            path.display()
                        );
                        stats.skipped += 1;
                        continue;
                    }
                    "overwrite" => {
                        db.update_secret_value(&name, val)?;
                        db.update_secret_metadata(
                            &name,
                            &crate::db::MetadataUpdate {
                                provider: Some(provider),
                                account_name: Some(account_name),
                                description: None,
                                source: Some(&source_label),
                                scopes: None,
                                projects: Some(projects),
                                apply_url: None,
                                expires_at: None,
                                last_verified_at: Some(Some(Utc::now())),
                                is_active: Some(true),
                                key_group: None,
                                org_name: None,
                                environment: None,
                                permission_profile: None,
                            },
                        )?;
                        println!(
                            "{} Overwritten '{}' from {}",
                            style("↻").yellow(),
                            style(&name).cyan(),
                            path.display()
                        );
                        stats.overwritten += 1;
                        continue;
                    }
                    "rename" => {
                        let mut suffix = 2;
                        loop {
                            let candidate = format!("{}-{}", name, suffix);
                            if !db.secret_exists(&candidate)? {
                                name = candidate;
                                break;
                            }
                            suffix += 1;
                        }
                    }
                    _ => unreachable!(),
                }
            }

            let now = Utc::now();
            let entry = SecretEntry {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.clone(),
                env_var: key.to_string(),
                provider: provider.to_string(),
                account_name: account_name.to_string(),
                org_name: String::new(),
                description: format!("Imported from {}", path.display()),
                source: source_label.clone(),
                environment: String::new(),
                permission_profile: String::new(),
                scopes: vec![],
                projects: projects.to_vec(),
                apply_url: String::new(),
                expires_at: None,
                created_at: now,
                updated_at: now,
                last_used_at: None,
                last_verified_at: Some(now),
                is_active: true,
                key_group: String::new(),
            };

            db.add_secret(&entry, val)?;
            println!(
                "{} Imported '{}' ({}) from {}",
                style("✓").green(),
                style(&name).cyan(),
                style(key).yellow(),
                path.display()
            );
            stats.imported += 1;
        }
    }

    Ok(stats)
}

fn collect_scan_candidates(
    path: &Path,
    recursive: bool,
    skip_common: bool,
    new_only: bool,
    db: Option<&crate::db::Database>,
) -> Result<Vec<ScanCandidate>> {
    use crate::commands::helpers::SKIP_VARS;

    let sources = if recursive {
        collect_import_sources_recursive(path)?
    } else {
        collect_import_sources(path)?
    };

    let mut candidates = Vec::new();
    for source in sources {
        let content = fs::read_to_string(&source.path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, _)) = line.split_once('=') {
                let env_var = key.trim();
                if env_var.is_empty() {
                    continue;
                }
                if skip_common && SKIP_VARS.contains(&env_var.to_uppercase().as_str()) {
                    continue;
                }
                if new_only {
                    if let Some(db) = db {
                        let name = env_var.to_lowercase().replace('_', "-");
                        if db.secret_exists(&name).unwrap_or(false) {
                            continue;
                        }
                    }
                }
                candidates.push(ScanCandidate {
                    env_var: env_var.to_string(),
                    provider: infer_provider(env_var).unwrap_or("other").to_string(),
                    file: source.path.clone(),
                    project_name: source.project_name.clone(),
                });
            }
        }
    }
    Ok(candidates)
}

pub fn cmd_add(args: AddArgs) -> Result<()> {
    let AddArgs {
        env_var,
        value,
        provider,
        account,
        org,
        projects,
        group,
        desc,
        source,
        expires,
        environment,
        permission,
        paste,
    } = args;
    let db = open_db()?;
    let interactive = atty::is(atty::Stream::Stdin);

    let env_var = match env_var {
        Some(e) => e,
        None if interactive => Input::new()
            .with_prompt("Env var name (e.g. GOOGLE_CLIENT_ID)")
            .interact_text()?,
        None => bail!("Env var name is required in non-interactive mode"),
    };

    let name = env_var.to_lowercase().replace('_', "-");

    if db.secret_exists(&name)? {
        bail!(
            "Secret '{}' already exists. Use 'kf update {}' to modify.",
            name,
            name
        );
    }

    let secret_value = if paste {
        let output = std::process::Command::new("pbpaste")
            .output()
            .context("Failed to read clipboard (pbpaste). Are you on macOS?")?;
        let val = String::from_utf8(output.stdout)?.trim().to_string();
        if val.is_empty() {
            bail!("Clipboard is empty");
        }
        val
    } else if let Some(v) = value {
        if v == "-" {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf.trim().to_string()
        } else {
            v
        }
    } else if !interactive {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf.trim().to_string()
    } else {
        Password::new().with_prompt("Secret value").interact()?
    };

    if secret_value.is_empty() {
        bail!("Secret value cannot be empty");
    }

    let provider = match provider {
        Some(p) => p,
        None => {
            let inferred = infer_provider(&env_var);
            if let Some(ref p) = inferred {
                println!(
                    "  {} provider: {}",
                    style("▸").dim(),
                    style(p).cyan()
                );
            }
            if interactive && inferred.is_none() {
                let idx = Select::new()
                    .with_prompt("Provider")
                    .items(PROVIDERS)
                    .default(PROVIDERS.len() - 1)
                    .interact()?;
                PROVIDERS[idx].to_string()
            } else {
                inferred.unwrap_or("other").to_string()
            }
        }
    };

    let projects_vec: Vec<String> = match projects {
        Some(p) => parse_csv(&p),
        None => {
            let detected = detect_project_name().unwrap_or_default();
            if !detected.is_empty() {
                println!(
                    "  {} project: {} (from current dir)",
                    style("▸").dim(),
                    style(&detected).cyan()
                );
            }
            if interactive {
                let p: String = Input::new()
                    .with_prompt("Project tags (comma-separated)")
                    .default(detected)
                    .interact_text()?;
                parse_csv(&p)
            } else {
                parse_csv(&detected)
            }
        }
    };

    let description = desc.unwrap_or_default();
    let account_name = account.unwrap_or_default();
    let org_name = org.unwrap_or_default();
    let environment_val = environment.unwrap_or_default();
    let permission_profile = permission.unwrap_or_default();
    let key_group = group.unwrap_or_default();
    let source = source.unwrap_or_else(|| "manual".to_string());
    let apply_url = get_default_url(&provider);
    let expires_at = match expires {
        Some(e) => parse_date(&e)?,
        None => None,
    };

    let now = Utc::now();
    let entry = SecretEntry {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.clone(),
        env_var,
        provider,
        account_name,
        org_name,
        description,
        source,
        environment: environment_val,
        permission_profile,
        scopes: vec![],
        projects: projects_vec,
        apply_url,
        expires_at,
        created_at: now,
        updated_at: now,
        last_used_at: None,
        last_verified_at: Some(now),
        is_active: true,
        key_group,
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

pub fn cmd_list(
    provider: Option<String>,
    project: Option<String>,
    group: Option<String>,
    expiring: bool,
    inactive: bool,
) -> Result<()> {
    let db = open_db()?;
    let entries = db.list_secrets(&ListFilter {
        provider,
        project,
        group,
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
        .set_header(vec![
            "Name", "Env Var", "Provider", "Account", "Group", "Projects", "Verified", "Expires",
            "Status",
        ]);

    for entry in &entries {
        let status = entry.status();
        let status_cell = match status {
            KeyStatus::Active => Cell::new("Active").fg(Color::Green),
            KeyStatus::ExpiringSoon => Cell::new("Expiring Soon").fg(Color::Yellow),
            KeyStatus::Expired => Cell::new("EXPIRED").fg(Color::Red),
            KeyStatus::Inactive => Cell::new("Inactive").fg(Color::DarkGrey),
            KeyStatus::Unknown => Cell::new("Unknown").fg(Color::DarkGrey),
        };

        let expires_str = entry
            .expires_at
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "-".to_string());
        let verified_str = entry
            .last_verified_at
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "-".to_string());

        let projects_str = if entry.projects.is_empty() {
            "-".to_string()
        } else {
            entry.projects.join(", ")
        };

        let group_str = if entry.key_group.is_empty() {
            "-"
        } else {
            &entry.key_group
        };

        table.add_row(vec![
            Cell::new(&entry.name),
            Cell::new(&entry.env_var).fg(Color::Yellow),
            Cell::new(&entry.provider),
            Cell::new(if entry.account_name.is_empty() {
                "-"
            } else {
                &entry.account_name
            }),
            Cell::new(group_str),
            Cell::new(&projects_str),
            Cell::new(&verified_str),
            Cell::new(&expires_str),
            status_cell,
        ]);
    }

    println!("{table}");
    println!("\n{} Total: {} secrets", style("ℹ").blue(), entries.len());

    Ok(())
}

pub fn cmd_get(name: Option<String>, raw: bool, copy: bool) -> Result<()> {
    let db = open_db()?;
    let name = match name {
        Some(n) => n,
        None => select_secret(&db)?,
    };
    let value = db.get_secret_value(&name)?;

    if copy {
        let mut child = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("Failed to copy (pbcopy). Are you on macOS?")?;
        use std::io::Write;
        child.stdin.take().unwrap().write_all(value.as_bytes())?;
        child.wait()?;
        println!("{} Copied to clipboard.", style("✓").green().bold());
    } else if raw {
        print!("{}", value);
    } else {
        let entry = db.get_secret(&name)?;
        println!(
            "{}: {} = {}",
            style(&entry.name).cyan(),
            style(&entry.env_var).yellow(),
            style(&value).dim()
        );
        if !entry.account_name.is_empty() {
            println!("  account: {}", style(&entry.account_name).blue());
        }
        if !entry.source.is_empty() {
            println!("  source: {}", style(&entry.source).dim());
        }
        if let Some(verified) = entry.last_verified_at {
            println!(
                "  verified: {}",
                style(verified.format("%Y-%m-%d").to_string()).green()
            );
        }
    }

    Ok(())
}

pub fn cmd_remove(name: Option<String>, force: bool) -> Result<()> {
    let db = open_db()?;
    let name = match name {
        Some(n) => {
            if !db.secret_exists(&n)? {
                bail!("Secret '{}' not found", n);
            }
            n
        }
        None => select_secret(&db)?,
    };

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

    db.remove_secret(&name)?;
    println!("{} Secret '{}' removed", style("✓").green().bold(), name);

    Ok(())
}

pub fn cmd_update(args: UpdateArgs) -> Result<()> {
    let UpdateArgs {
        name,
        value,
        provider,
        account,
        org,
        desc,
        source,
        environment,
        permission,
        scopes,
        projects,
        url,
        expires,
        active,
        group,
        verify,
    } = args;
    let db = open_db()?;
    let name = match name {
        Some(n) => {
            if !db.secret_exists(&n)? {
                bail!("Secret '{}' not found", n);
            }
            n
        }
        None => select_secret(&db)?,
    };

    if let Some(v) = value {
        db.update_secret_value(&name, &v)?;
        println!(
            "{} Secret value updated for '{}'",
            style("✓").green().bold(),
            name
        );
    }

    let scopes_vec = scopes.map(|s| parse_csv(&s));
    let projects_vec = projects.map(|p| parse_csv(&p));
    let expires_at = match expires {
        Some(ref e) if e.is_empty() => Some(None),
        Some(ref e) => Some(parse_date(e)?),
        None => None,
    };

    let last_verified_at = if verify { Some(Some(Utc::now())) } else { None };

    db.update_secret_metadata(
        &name,
        &crate::db::MetadataUpdate {
            provider: provider.as_deref(),
            account_name: account.as_deref(),
            org_name: org.as_deref(),
            description: desc.as_deref(),
            source: source.as_deref(),
            environment: environment.as_deref(),
            permission_profile: permission.as_deref(),
            scopes: scopes_vec.as_deref(),
            projects: projects_vec.as_deref(),
            apply_url: url.as_deref(),
            expires_at,
            last_verified_at,
            is_active: active,
            key_group: group.as_deref(),
        },
    )?;

    if verify {
        println!(
            "{} Verified and metadata updated for '{}'",
            style("✓").green().bold(),
            name
        );
    } else {
        println!(
            "{} Metadata updated for '{}'",
            style("✓").green().bold(),
            name
        );
    }
    Ok(())
}

pub fn cmd_run(
    project: Option<String>,
    group: Option<String>,
    all: bool,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        bail!("No command specified");
    }

    let db = open_db()?;
    let project = if all {
        None
    } else {
        project.or_else(|| {
            let detected = detect_project_name();
            if let Some(ref name) = detected {
                eprintln!(
                    "  {} injecting secrets for project: {} (auto-detected)",
                    style("▸").dim(),
                    style(name).cyan()
                );
                eprintln!("  {} use --all to inject all secrets", style("ℹ").blue());
            }
            detected
        })
    };

    let env_pairs = db.get_all_for_env(project.as_deref(), group.as_deref())?;

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (key, val) in &env_pairs {
        cmd.env(key, val);
    }

    let status = cmd.status().context("Failed to execute command")?;
    std::process::exit(status.code().unwrap_or(1));
}

pub fn cmd_import(
    file: &str,
    provider: Option<String>,
    account: Option<String>,
    project: Option<String>,
    source: Option<String>,
    on_conflict: &str,
) -> Result<()> {
    let path = Path::new(file);
    if !path.exists() {
        bail!("File not found: {}", file);
    }

    if !["skip", "overwrite", "rename"].contains(&on_conflict) {
        bail!("Invalid --on-conflict value. Use: skip, overwrite, rename");
    }

    let db = open_db()?;
    let provider = provider.unwrap_or_else(|| "imported".to_string());
    let account_name = account.unwrap_or_default();
    let import_sources = collect_import_sources(path)?;
    let mut imported = 0;
    let mut overwritten = 0;
    let mut skipped = 0;

    for import_source in import_sources {
        let projects = match &project {
            Some(project) => vec![project.clone()],
            None => import_source
                .project_name
                .clone()
                .map(|name| vec![name])
                .unwrap_or_default(),
        };

        let stats = import_env_file(
            &db,
            &import_source.path,
            &provider,
            &account_name,
            &projects,
            source.as_deref(),
            on_conflict,
        )?;

        imported += stats.imported;
        overwritten += stats.overwritten;
        skipped += stats.skipped;
    }

    println!(
        "\n{} Imported: {}, Overwritten: {}, Skipped: {}",
        style("✓").green().bold(),
        imported,
        overwritten,
        skipped
    );
    Ok(())
}

pub fn cmd_export(
    project: Option<String>,
    group: Option<String>,
    output: Option<String>,
) -> Result<()> {
    let db = open_db()?;
    let entries = db.list_secrets(&ListFilter {
        project,
        group,
        ..Default::default()
    })?;

    let mut lines = Vec::new();
    lines.push("# Generated by KeyFlow".to_string());
    lines.push(format!(
        "# Date: {}",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));
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

pub fn cmd_health() -> Result<()> {
    use crate::models::find_duplicate_groups;

    let db = open_db()?;
    let entries = db.list_secrets(&ListFilter {
        inactive: true,
        ..Default::default()
    })?;

    let now = Utc::now();
    let mut issues = 0;

    println!("{}", style("KeyFlow Health Report").bold().cyan());
    println!("{}", style("═".repeat(50)).dim());

    let expired: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.status(), KeyStatus::Expired))
        .collect();
    if !expired.is_empty() {
        issues += expired.len();
        println!(
            "\n{} {} Expired Keys:",
            style("✗").red().bold(),
            expired.len()
        );
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

    let expiring: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.status(), KeyStatus::ExpiringSoon))
        .collect();
    if !expiring.is_empty() {
        issues += expiring.len();
        println!(
            "\n{} {} Keys Expiring Within 7 Days:",
            style("⚠").yellow().bold(),
            expiring.len()
        );
        for e in &expiring {
            let days_left = e.expires_at.map(|d| (d - now).num_days()).unwrap_or(0);
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

    let duplicates = find_duplicate_groups(&entries);
    if !duplicates.is_empty() {
        issues += duplicates.len();
        println!(
            "\n{} {} Duplicate / Overlapping Key Groups:",
            style("⚠").yellow().bold(),
            duplicates.len()
        );
        for group in &duplicates {
            println!(
                "  {} {} → {}",
                style("•").yellow(),
                style(&group.env_var).yellow(),
                group
                    .names
                    .iter()
                    .map(|n| style(n).cyan().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let mut provider_old_keys: std::collections::HashMap<&str, Vec<&SecretEntry>> =
        std::collections::HashMap::new();
    for e in &entries {
        if e.is_active && !e.provider.is_empty() && e.is_unused_for_days(now, 60) {
            provider_old_keys.entry(&e.provider).or_default().push(e);
        }
    }
    let multi_old: Vec<_> = provider_old_keys
        .iter()
        .filter(|(_, keys)| keys.len() > 1)
        .collect();
    if !multi_old.is_empty() {
        println!(
            "\n{} Same Provider, Multiple Old Keys:",
            style("⚠").yellow().bold()
        );
        for (provider, keys) in &multi_old {
            println!(
                "  {} {} ({} keys unused 60+ days): {}",
                style("•").yellow(),
                style(provider).cyan(),
                keys.len(),
                keys.iter()
                    .map(|k| k.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let active_entries: Vec<_> = entries.iter().filter(|e| e.is_active).collect();
    let mut quality_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for e in &active_entries {
        *quality_counts
            .entry(e.source_quality().to_string())
            .or_insert(0) += 1;
    }
    if !quality_counts.is_empty() {
        println!("\n{} Source Quality Breakdown:", style("ℹ").blue().bold());
        let order = ["template", "import", "manual", "mcp", "other", "unknown"];
        for tier in &order {
            if let Some(count) = quality_counts.get(*tier) {
                println!("  {} {}: {}", style("•").dim(), tier, count);
            }
        }
    }

    let unverified_30: Vec<_> = active_entries
        .iter()
        .filter(|e| {
            let days = e.unverified_days(now);
            (30..60).contains(&days)
        })
        .collect();
    let unverified_60: Vec<_> = active_entries
        .iter()
        .filter(|e| {
            let days = e.unverified_days(now);
            (60..90).contains(&days)
        })
        .collect();
    let unverified_90: Vec<_> = active_entries
        .iter()
        .filter(|e| e.unverified_days(now) >= 90)
        .collect();
    if !unverified_30.is_empty() || !unverified_60.is_empty() || !unverified_90.is_empty() {
        println!("\n{} Unverified Keys:", style("!").yellow().bold());
        if !unverified_90.is_empty() {
            println!(
                "  {} 90+ days ({}): {}",
                style("•").red(),
                unverified_90.len(),
                unverified_90
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !unverified_60.is_empty() {
            println!(
                "  {} 60-89 days ({}): {}",
                style("•").yellow(),
                unverified_60.len(),
                unverified_60
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !unverified_30.is_empty() {
            println!(
                "  {} 30-59 days ({}): {}",
                style("•").dim(),
                unverified_30.len(),
                unverified_30
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let unused: Vec<_> = entries
        .iter()
        .filter(|e| e.is_unused_for_days(now, 30))
        .collect();
    if !unused.is_empty() {
        println!(
            "\n{} {} Keys Unused for 30+ Days:",
            style("ℹ").blue().bold(),
            unused.len()
        );
        for e in &unused {
            let days = e.days_since_last_seen(now);
            println!(
                "  {} {} ({} days since last use)",
                style("•").dim(),
                style(&e.name).cyan(),
                days
            );
        }
    }

    let metadata_gaps: Vec<_> = entries
        .iter()
        .filter(|e| e.is_active && e.has_metadata_gaps())
        .collect();
    if !metadata_gaps.is_empty() {
        println!(
            "\n{} {} Keys Need Metadata Review:",
            style("!").yellow().bold(),
            metadata_gaps.len()
        );
        for e in &metadata_gaps {
            println!(
                "  {} {} ({})",
                style("•").yellow(),
                style(&e.name).cyan(),
                e.metadata_gaps().join(", ")
            );
        }
    }

    let inactive: Vec<_> = entries.iter().filter(|e| !e.is_active).collect();
    if !inactive.is_empty() {
        println!("\n{} {} Inactive Keys:", style("⊘").dim(), inactive.len());
        for e in &inactive {
            println!("  {} {}", style("•").dim(), style(&e.name).dim());
        }
    }

    println!("{}", style("═".repeat(50)).dim());
    if issues == 0 && inactive.is_empty() && unused.is_empty() && metadata_gaps.is_empty() {
        println!(
            "\n{} All {} secrets are healthy!",
            style("✓").green().bold(),
            entries.len()
        );
    } else {
        println!(
            "\nTotal: {} secrets, {} expiry issues, {} duplicates, {} review items",
            entries.len(),
            issues - duplicates.len(),
            duplicates.len(),
            inactive.len() + unused.len() + metadata_gaps.len()
        );
    }

    Ok(())
}

pub fn cmd_verify(name: Option<String>, all: bool) -> Result<()> {
    let db = open_db()?;
    let names = if all {
        db.list_secrets(&ListFilter {
            inactive: true,
            ..Default::default()
        })?
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>()
    } else {
        vec![match name {
            Some(name) => name,
            None => select_secret(&db)?,
        }]
    };

    let now = Utc::now();
    for name in &names {
        db.update_secret_metadata(
            name,
            &crate::db::MetadataUpdate {
                last_verified_at: Some(Some(now)),
                ..Default::default()
            },
        )?;
        println!(
            "{} Verified '{}' at {}",
            style("✓").green().bold(),
            style(name).cyan(),
            style(now.format("%Y-%m-%d").to_string()).green()
        );
    }

    Ok(())
}

pub fn cmd_search(query: Option<String>) -> Result<()> {
    let query = match query {
        Some(q) => q,
        None => Input::new().with_prompt("Search").interact_text()?,
    };
    let db = open_db()?;
    let entries = db.search_secrets(&query)?;

    if entries.is_empty() {
        println!("No secrets matching '{}' found.", style(&query).yellow());
        return Ok(());
    }

    println!(
        "Found {} secrets matching '{}':\n",
        entries.len(),
        style(&query).yellow()
    );

    for entry in &entries {
        let status = entry.status();
        let status_str = match status {
            KeyStatus::Active => style(status.to_string()).green(),
            KeyStatus::ExpiringSoon => style(status.to_string()).yellow(),
            KeyStatus::Expired => style(status.to_string()).red(),
            _ => style(status.to_string()).dim(),
        };

        println!(
            "  {} {}",
            style("▸").bold(),
            style(&entry.name).cyan().bold()
        );
        println!(
            "    env: {}  provider: {}  status: {}",
            style(&entry.env_var).yellow(),
            &entry.provider,
            status_str,
        );
        if !entry.account_name.is_empty() {
            println!("    account: {}", style(&entry.account_name).blue());
        }
        if !entry.description.is_empty() {
            println!("    {}", style(&entry.description).dim());
        }
        if !entry.source.is_empty() {
            println!("    source: {}", style(&entry.source).dim());
        }
        if let Some(verified) = entry.last_verified_at {
            println!(
                "    verified: {}",
                style(verified.format("%Y-%m-%d").to_string()).green()
            );
        }
        if !entry.key_group.is_empty() {
            println!("    group: {}", style(&entry.key_group).magenta());
        }
        if !entry.projects.is_empty() {
            println!("    projects: {}", entry.projects.join(", "));
        }
        println!();
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn cmd_scan(
    path: &str,
    apply: bool,
    recursive: bool,
    new_only: bool,
    skip_common: bool,
    export: Option<String>,
    provider: Option<String>,
    account: Option<String>,
    project: Option<String>,
    source: Option<String>,
    on_conflict: &str,
) -> Result<()> {
    let scan_path = Path::new(path);
    if !scan_path.exists() {
        bail!("Path not found: {}", path);
    }

    let db = if new_only { Some(open_db()?) } else { None };
    let candidates =
        collect_scan_candidates(scan_path, recursive, skip_common, new_only, db.as_ref())?;
    if candidates.is_empty() {
        println!("{}", style("No candidate keys found.").dim());
        return Ok(());
    }

    if let Some(ref export_path) = export {
        let data: Vec<serde_json::Value> = candidates
            .iter()
            .map(|c| {
                serde_json::json!({
                    "env_var": c.env_var,
                    "provider": c.provider,
                    "file": c.file.display().to_string(),
                    "project": c.project_name,
                })
            })
            .collect();

        if export_path.ends_with(".csv") {
            let mut lines = vec!["env_var,provider,file,project".to_string()];
            for c in &candidates {
                lines.push(format!(
                    "{},{},{},{}",
                    c.env_var,
                    c.provider,
                    c.file.display(),
                    c.project_name.as_deref().unwrap_or("")
                ));
            }
            fs::write(export_path, lines.join("\n") + "\n")?;
        } else {
            fs::write(export_path, serde_json::to_string_pretty(&data)?)?;
        }

        println!(
            "{} Exported {} candidates to {}",
            style("✓").green().bold(),
            candidates.len(),
            style(export_path).cyan()
        );
        return Ok(());
    }

    println!(
        "{} Found {} candidate keys:\n",
        style("▸").cyan().bold(),
        candidates.len()
    );
    for candidate in &candidates {
        println!(
            "  {} {}  provider: {}  file: {}{}",
            style("•").dim(),
            style(&candidate.env_var).yellow(),
            style(&candidate.provider).cyan(),
            candidate.file.display(),
            candidate
                .project_name
                .as_ref()
                .map(|project| format!("  project: {}", project))
                .unwrap_or_default()
        );
    }

    let should_import = if apply {
        true
    } else if atty::is(atty::Stream::Stdout) {
        Confirm::new()
            .with_prompt("Import these candidate keys into KeyFlow?")
            .default(false)
            .interact()?
    } else {
        false
    };

    if !should_import {
        println!(
            "\n{} Preview only. Run {} to import without prompt.",
            style("ℹ").blue(),
            style(format!("kf scan {} --apply", path)).cyan()
        );
        return Ok(());
    }

    cmd_import(path, provider, account, project, source, on_conflict)
}

pub fn cmd_group_list() -> Result<()> {
    let db = open_db()?;
    let groups = db.list_groups()?;

    if groups.is_empty() {
        println!("{}", style("No groups found. Use --group flag when adding secrets, or use 'keyflow template use'.").dim());
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Group", "Keys"]);

    for (name, count) in &groups {
        table.add_row(vec![Cell::new(name).fg(Color::Magenta), Cell::new(count)]);
    }

    println!("{table}");
    Ok(())
}

pub fn cmd_group_show(name: &str) -> Result<()> {
    let db = open_db()?;
    let entries = db.list_secrets(&ListFilter {
        group: Some(name.to_string()),
        ..Default::default()
    })?;

    if entries.is_empty() {
        println!("No secrets in group '{}'.", style(name).magenta());
        return Ok(());
    }

    println!("Group: {}\n", style(name).magenta().bold());
    for entry in &entries {
        println!(
            "  {} {} = {}",
            style("•").green(),
            style(&entry.env_var).yellow(),
            style(&entry.description).dim()
        );
    }
    println!(
        "\nUse {} to get values.",
        style(format!("keyflow export --group {}", name)).cyan()
    );
    Ok(())
}

pub fn cmd_group_export(name: &str, output: Option<String>) -> Result<()> {
    cmd_export(None, Some(name.to_string()), output)
}

pub fn cmd_template_list() -> Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Template", "Provider", "Keys", "Description"]);

    for t in TEMPLATES {
        let keys_str: Vec<&str> = t.keys.iter().map(|k| k.env_var).collect();
        table.add_row(vec![
            Cell::new(t.name).fg(Color::Cyan),
            Cell::new(t.provider),
            Cell::new(keys_str.join(", ")).fg(Color::Yellow),
            Cell::new(t.description),
        ]);
    }

    println!("{table}");
    println!(
        "\nUsage: {} <template-name> [--projects myapp] [--prefix MYAPP_]",
        style("keyflow template use").cyan()
    );
    Ok(())
}

pub fn cmd_template_use(
    template_name: &str,
    projects: Option<String>,
    expires: Option<String>,
    prefix: Option<String>,
) -> Result<()> {
    let template = TEMPLATES
        .iter()
        .find(|t| t.name == template_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Template '{}' not found. Run {} to see available templates.",
                template_name,
                style("keyflow template list").cyan()
            )
        })?;

    println!(
        "{} Using template: {} ({})",
        style("▸").bold(),
        style(template.name).cyan().bold(),
        template.description
    );
    println!(
        "  Provider: {}  URL: {}\n",
        template.provider,
        style(template.apply_url).underlined()
    );

    let db = open_db()?;
    let projects_vec: Vec<String> = projects.map(|p| parse_csv(&p)).unwrap_or_default();
    let expires_at = expires.as_deref().map(parse_date).transpose()?.flatten();
    let prefix = prefix.unwrap_or_default();
    let group_name = template.name.to_string();
    let now = Utc::now();

    let mut created = 0;
    for tkey in template.keys {
        let env_var = format!("{}{}", prefix, tkey.env_var);
        let secret_name = env_var.to_lowercase().replace('_', "-");

        if db.secret_exists(&secret_name)? {
            println!(
                "{} Skipping '{}' (already exists)",
                style("⊘").dim(),
                secret_name
            );
            continue;
        }

        println!("  {} {}", style("→").cyan(), style(&env_var).yellow());
        println!("    {}", style(tkey.description).dim());

        let value = if tkey.is_secret {
            Password::new()
                .with_prompt(format!("  Enter {}", tkey.env_var))
                .interact()?
        } else {
            Input::new()
                .with_prompt(format!("  Enter {}", tkey.env_var))
                .interact_text()?
        };

        let entry = SecretEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name: secret_name.clone(),
            env_var,
            provider: template.provider.to_string(),
            account_name: String::new(),
            org_name: String::new(),
            description: tkey.description.to_string(),
            source: format!("template:{}", template.name),
            environment: String::new(),
            permission_profile: String::new(),
            scopes: vec![],
            projects: projects_vec.clone(),
            apply_url: template.apply_url.to_string(),
            expires_at,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            last_verified_at: Some(now),
            is_active: true,
            key_group: group_name.clone(),
        };

        db.add_secret(&entry, &value)?;
        println!("  {}\n", style("✓ Saved").green());
        created += 1;
    }

    println!(
        "\n{} Created {} secrets in group '{}'",
        style("✓").green().bold(),
        created,
        style(&group_name).magenta()
    );
    Ok(())
}
