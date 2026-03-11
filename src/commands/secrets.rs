use anyhow::{bail, Context, Result};
use chrono::Utc;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use std::fs;
use std::path::Path;

use crate::commands::auth::{open_db, select_secret};
use crate::commands::helpers::{
    detect_project_name, get_default_url, infer_provider, parse_csv, PROVIDERS,
};
use crate::models::{KeyStatus, ListFilter};
use crate::services::secrets::{
    parse_expires, parse_optional_expires, ImportRequest, SecretDraft, SecretService, SecretUpdate,
};

pub struct AddArgs {
    pub env_var: Option<String>,
    pub value: Option<String>,
    pub provider: Option<String>,
    pub account: Option<String>,
    pub org: Option<String>,
    pub projects: Option<String>,
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
    pub verify: bool,
}

pub fn cmd_add(args: AddArgs) -> Result<()> {
    let AddArgs {
        env_var,
        value,
        provider,
        account,
        org,
        projects,
        desc,
        source,
        expires,
        environment,
        permission,
        paste,
    } = args;
    let service = SecretService::new(open_db()?);
    let interactive = atty::is(atty::Stream::Stdin);

    let env_var = match env_var {
        Some(e) => e,
        None if interactive => Input::new()
            .with_prompt("Env var name (e.g. GOOGLE_CLIENT_ID)")
            .interact_text()?,
        None => bail!("Env var name is required in non-interactive mode"),
    };

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
                println!("  {} provider: {}", style("▸").dim(), style(p).cyan());
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
    let source = source.unwrap_or_else(|| "manual".to_string());
    let apply_url = get_default_url(&provider);
    let entry = service.create_secret(SecretDraft {
        env_var,
        value: secret_value,
        provider,
        account_name,
        org_name,
        description,
        source,
        environment: environment_val,
        permission_profile,
        projects: projects_vec,
        apply_url,
        expires_at: parse_expires(expires)?,
    })?;
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
    expiring: bool,
    inactive: bool,
    limit: usize,
    offset: usize,
) -> Result<()> {
    if limit == 0 {
        bail!("--limit must be greater than 0");
    }

    let service = SecretService::new(open_db()?);
    let entries = service.list_entries(&ListFilter {
        provider,
        project,
        expiring,
        inactive,
    })?;

    if entries.is_empty() {
        println!("{}", style("No secrets found.").dim());
        return Ok(());
    }

    if offset >= entries.len() {
        println!(
            "{} No secrets in this page. Total matching secrets: {}",
            style("ℹ").blue(),
            entries.len()
        );
        return Ok(());
    }

    let page_entries: Vec<_> = entries.iter().skip(offset).take(limit).collect();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            "Name", "Env Var", "Provider", "Account", "Projects", "Verified", "Expires", "Status",
        ]);

    for entry in &page_entries {
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

        table.add_row(vec![
            Cell::new(&entry.name),
            Cell::new(&entry.env_var).fg(Color::Yellow),
            Cell::new(&entry.provider),
            Cell::new(if entry.account_name.is_empty() {
                "-"
            } else {
                &entry.account_name
            }),
            Cell::new(&projects_str),
            Cell::new(&verified_str),
            Cell::new(&expires_str),
            status_cell,
        ]);
    }

    println!("{table}");
    let shown_end = offset + page_entries.len();
    println!(
        "\n{} Showing {}-{} of {} secrets",
        style("ℹ").blue(),
        offset + 1,
        shown_end,
        entries.len()
    );

    Ok(())
}

pub fn cmd_get(name: Option<String>, raw: bool, copy: bool) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let name = match name {
        Some(n) => n,
        None => select_secret(service.db())?,
    };
    let view = service.inspect_secret(&name)?;

    if copy {
        let mut child = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("Failed to copy (pbcopy). Are you on macOS?")?;
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(view.value.as_bytes())?;
        child.wait()?;
        println!("{} Copied to clipboard.", style("✓").green().bold());
    } else if raw {
        print!("{}", view.value);
    } else {
        println!(
            "{}: {} = {}",
            style(&view.entry.name).cyan(),
            style(&view.entry.env_var).yellow(),
            style(&view.value).dim()
        );
        if !view.entry.account_name.is_empty() {
            println!("  account: {}", style(&view.entry.account_name).blue());
        }
        if !view.entry.source.is_empty() {
            println!("  source: {}", style(&view.entry.source).dim());
        }
        if let Some(verified) = view.entry.last_verified_at {
            println!(
                "  verified: {}",
                style(verified.format("%Y-%m-%d").to_string()).green()
            );
        }
    }

    Ok(())
}

pub fn cmd_remove(name: Option<String>, force: bool) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let name = match name {
        Some(n) => {
            if !service.secret_exists(&n)? {
                bail!("Secret '{}' not found", n);
            }
            n
        }
        None => select_secret(service.db())?,
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

    service.remove_secret(&name)?;
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
        verify,
    } = args;
    let service = SecretService::new(open_db()?);
    let name = match name {
        Some(n) => {
            if !service.db().secret_exists(&n)? {
                bail!("Secret '{}' not found", n);
            }
            n
        }
        None => select_secret(service.db())?,
    };

    let scopes_vec = scopes.map(|s| parse_csv(&s));
    let projects_vec = projects.map(|p| parse_csv(&p));
    let had_value_update = value.is_some();
    service.update_secret(
        &name,
        SecretUpdate {
            value,
            provider,
            account_name: account,
            org_name: org,
            description: desc,
            source,
            environment,
            permission_profile: permission,
            scopes: scopes_vec,
            projects: projects_vec,
            apply_url: url,
            expires_at: parse_optional_expires(expires)?,
            active,
            verify,
        },
    )?;

    if verify && had_value_update {
        println!(
            "{} Secret value verified and metadata updated for '{}'",
            style("✓").green().bold(),
            name
        );
    } else if verify {
        println!(
            "{} Verified and metadata updated for '{}'",
            style("✓").green().bold(),
            name
        );
    } else if had_value_update {
        println!(
            "{} Secret value and metadata updated for '{}'",
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

pub fn cmd_run(project: Option<String>, all: bool, command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        bail!("No command specified");
    }

    let service = SecretService::new(open_db()?);
    let detected = detect_project_name();
    let resolution = service.resolve_run_env_pairs(project, all, detected.clone())?;
    let project = resolution.project;
    let env_pairs = resolution.env_pairs;
    if let Some(name) = project.as_ref().filter(|_| !all).or(detected.as_ref()) {
        eprintln!(
            "  {} injecting secrets for project: {} (auto-detected)",
            style("▸").dim(),
            style(name).cyan()
        );
        eprintln!("  {} use --all to inject all secrets", style("ℹ").blue());
    }

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

    let service = SecretService::new(open_db()?);
    let provider = provider.unwrap_or_else(|| "imported".to_string());
    let account_name = account.unwrap_or_default();
    let stats = service.import_path(ImportRequest {
        path,
        provider: &provider,
        account_name: &account_name,
        project_override: project.as_deref(),
        source: source.as_deref(),
        on_conflict,
        recursive: false,
    })?;

    println!(
        "\n{} Imported: {}, Overwritten: {}, Skipped: {}",
        style("✓").green().bold(),
        stats.imported,
        stats.overwritten,
        stats.skipped
    );
    Ok(())
}

pub fn cmd_export(project: Option<String>, output: Option<String>) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let (entries, content) = service.export_project_env(project)?;

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
    let service = SecretService::new(open_db()?);
    let health = service.health_view()?;

    println!("{}", style("KeyFlow Health Report").bold().cyan());
    println!("{}", style("═".repeat(50)).dim());

    if !health.expired.is_empty() {
        println!(
            "\n{} {} Expired Keys:",
            style("✗").red().bold(),
            health.expired.len()
        );
        for e in &health.expired {
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

    if !health.expiring.is_empty() {
        println!(
            "\n{} {} Keys Expiring Within 7 Days:",
            style("⚠").yellow().bold(),
            health.expiring.len()
        );
        for e in &health.expiring {
            let days_left = e
                .expires_at
                .map(|d| (d - Utc::now()).num_days())
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

    if !health.duplicates.is_empty() {
        println!(
            "\n{} {} Duplicate / Overlapping Key Groups:",
            style("⚠").yellow().bold(),
            health.duplicates.len()
        );
        for group in &health.duplicates {
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

    if !health.provider_old_keys.is_empty() {
        println!(
            "\n{} Same Provider, Multiple Old Keys:",
            style("⚠").yellow().bold()
        );
        for (provider, keys) in &health.provider_old_keys {
            println!(
                "  {} {} ({} keys unused 60+ days): {}",
                style("•").yellow(),
                style(provider).cyan(),
                keys.len(),
                keys.join(", ")
            );
        }
    }

    if !health.report.source_quality.is_empty() {
        println!("\n{} Source Quality Breakdown:", style("ℹ").blue().bold());
        let order = ["import", "manual", "mcp", "other", "unknown"];
        for tier in &order {
            if let Some(count) = health.report.source_quality.get(*tier) {
                println!("  {} {}: {}", style("•").dim(), tier, count);
            }
        }
    }

    if !health.unverified_30.is_empty()
        || !health.unverified_60.is_empty()
        || !health.unverified_90.is_empty()
    {
        println!("\n{} Unverified Keys:", style("!").yellow().bold());
        if !health.unverified_90.is_empty() {
            println!(
                "  {} 90+ days ({}): {}",
                style("•").red(),
                health.unverified_90.len(),
                health.unverified_90.join(", ")
            );
        }
        if !health.unverified_60.is_empty() {
            println!(
                "  {} 60-89 days ({}): {}",
                style("•").yellow(),
                health.unverified_60.len(),
                health.unverified_60.join(", ")
            );
        }
        if !health.unverified_30.is_empty() {
            println!(
                "  {} 30-59 days ({}): {}",
                style("•").dim(),
                health.unverified_30.len(),
                health.unverified_30.join(", ")
            );
        }
    }

    if !health.unused.is_empty() {
        println!(
            "\n{} {} Keys Unused for 30+ Days:",
            style("ℹ").blue().bold(),
            health.unused.len()
        );
        for (name, days) in &health.unused {
            println!(
                "  {} {} ({} days since last use)",
                style("•").dim(),
                style(name).cyan(),
                days
            );
        }
    }

    if !health.metadata_gaps.is_empty() {
        println!(
            "\n{} {} Keys Need Metadata Review:",
            style("!").yellow().bold(),
            health.metadata_gaps.len()
        );
        for (name, gaps) in &health.metadata_gaps {
            println!(
                "  {} {} ({})",
                style("•").yellow(),
                style(name).cyan(),
                gaps.join(", ")
            );
        }
    }

    if !health.inactive.is_empty() {
        println!(
            "\n{} {} Inactive Keys:",
            style("⊘").dim(),
            health.inactive.len()
        );
        for name in &health.inactive {
            println!("  {} {}", style("•").dim(), style(name).dim());
        }
    }

    println!("{}", style("═".repeat(50)).dim());
    if health.summary.expiry_issues == 0
        && health.summary.inactive_count == 0
        && health.summary.unused_count == 0
        && health.summary.metadata_review_count == 0
        && health.summary.duplicate_count == 0
    {
        println!(
            "\n{} All {} secrets are healthy!",
            style("✓").green().bold(),
            health.summary.total
        );
    } else {
        println!(
            "\nTotal: {} secrets, {} expiry issues, {} duplicates, {} review items",
            health.summary.total,
            health.summary.expiry_issues,
            health.summary.duplicate_count,
            health.summary.inactive_count
                + health.summary.unused_count
                + health.summary.metadata_review_count
        );
    }

    Ok(())
}

pub fn cmd_verify(name: Option<String>, all: bool) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let names = if all {
        service.all_secret_names(true)?
    } else {
        vec![match name {
            Some(name) => name,
            None => select_secret(service.db())?,
        }]
    };

    let now = service.verify_names(&names)?;
    for name in &names {
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
    let service = SecretService::new(open_db()?);
    let entries = service.search_entries(&query)?;

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

    let service = SecretService::new(open_db()?);
    let candidates = service.scan_path(scan_path, recursive, skip_common, new_only)?;
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
