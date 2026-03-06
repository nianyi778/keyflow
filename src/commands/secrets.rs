use anyhow::{bail, Context, Result};
use chrono::Utc;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::fs;
use std::path::Path;

use crate::commands::auth::{open_db, select_secret};
use crate::commands::helpers::{
    detect_project_name, get_default_url, infer_provider, parse_csv, parse_date, PROVIDERS,
};
use crate::models::{KeyStatus, ListFilter, SecretEntry, TEMPLATES};

pub struct AddArgs {
    pub env_var: Option<String>,
    pub value: Option<String>,
    pub provider: Option<String>,
    pub projects: Option<String>,
    pub group: Option<String>,
    pub desc: Option<String>,
    pub expires: Option<String>,
    pub paste: bool,
}

pub struct UpdateArgs {
    pub name: Option<String>,
    pub value: Option<String>,
    pub provider: Option<String>,
    pub desc: Option<String>,
    pub scopes: Option<String>,
    pub projects: Option<String>,
    pub url: Option<String>,
    pub expires: Option<String>,
    pub active: Option<bool>,
    pub group: Option<String>,
}

pub fn cmd_add(args: AddArgs) -> Result<()> {
    let AddArgs {
        env_var,
        value,
        provider,
        projects,
        group,
        desc,
        expires,
        paste,
    } = args;
    let db = open_db()?;

    let env_var = match env_var {
        Some(e) => e,
        None => Input::new()
            .with_prompt("Env var name (e.g. GOOGLE_CLIENT_ID)")
            .interact_text()?,
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
    } else if !atty::is(atty::Stream::Stdin) {
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
            if let Some(inferred) = infer_provider(&env_var) {
                println!(
                    "  {} provider: {}",
                    style("▸").dim(),
                    style(inferred).cyan()
                );
                inferred.to_string()
            } else {
                let idx = Select::new()
                    .with_prompt("Provider")
                    .items(PROVIDERS)
                    .default(PROVIDERS.len() - 1)
                    .interact()?;
                PROVIDERS[idx].to_string()
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
            let p: String = Input::new()
                .with_prompt("Project tags (comma-separated)")
                .default(detected)
                .interact_text()?;
            parse_csv(&p)
        }
    };

    let description = desc.unwrap_or_default();
    let key_group = group.unwrap_or_default();
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
        description,
        scopes: vec![],
        projects: projects_vec,
        apply_url,
        expires_at,
        created_at: now,
        updated_at: now,
        last_used_at: None,
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
            "Name", "Env Var", "Provider", "Group", "Projects", "Expires", "Status",
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
            Cell::new(group_str),
            Cell::new(&projects_str),
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
        desc,
        scopes,
        projects,
        url,
        expires,
        active,
        group,
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

    db.update_secret_metadata(
        &name,
        &crate::db::MetadataUpdate {
            provider: provider.as_deref(),
            description: desc.as_deref(),
            scopes: scopes_vec.as_deref(),
            projects: projects_vec.as_deref(),
            apply_url: url.as_deref(),
            expires_at,
            is_active: active,
            key_group: group.as_deref(),
        },
    )?;

    println!(
        "{} Metadata updated for '{}'",
        style("✓").green().bold(),
        name
    );
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
    project: Option<String>,
    on_conflict: &str,
) -> Result<()> {
    let path = Path::new(file);
    if !path.exists() {
        bail!("File not found: {}", file);
    }

    if !["skip", "overwrite", "rename"].contains(&on_conflict) {
        bail!("Invalid --on-conflict value. Use: skip, overwrite, rename");
    }

    let content = fs::read_to_string(path)?;
    let db = open_db()?;
    let mut imported = 0;
    let mut overwritten = 0;
    let mut skipped = 0;

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

            let mut name = key.to_lowercase().replace('_', "-");

            if db.secret_exists(&name)? {
                match on_conflict {
                    "skip" => {
                        println!("{} Skipping '{}' (already exists)", style("⊘").dim(), name);
                        skipped += 1;
                        continue;
                    }
                    "overwrite" => {
                        db.update_secret_value(&name, val)?;
                        println!(
                            "{} Overwritten '{}'",
                            style("↻").yellow(),
                            style(&name).cyan()
                        );
                        overwritten += 1;
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
                key_group: String::new(),
            };

            db.add_secret(&entry, val)?;
            println!(
                "{} Imported '{}' ({})",
                style("✓").green(),
                style(&name).cyan(),
                style(key).yellow()
            );
            imported += 1;
        }
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

    let inactive: Vec<_> = entries.iter().filter(|e| !e.is_active).collect();
    if !inactive.is_empty() {
        println!("\n{} {} Inactive Keys:", style("⊘").dim(), inactive.len());
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
        if !entry.description.is_empty() {
            println!("    {}", style(&entry.description).dim());
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
            description: tkey.description.to_string(),
            scopes: vec![],
            projects: projects_vec.clone(),
            apply_url: template.apply_url.to_string(),
            expires_at,
            created_at: now,
            updated_at: now,
            last_used_at: None,
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
