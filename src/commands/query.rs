//! Query commands: list, search, health, verify.
//!
//! Extracted from commands/secrets.rs to further thin the main handler.

use anyhow::Result;
use chrono::Utc;
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use console::style;

use crate::commands::auth::open_db;
use crate::commands::prompts;
use crate::models::{KeyStatus, ListFilter};
use crate::services::secrets::SecretService;

pub fn cmd_list(
    provider: Option<String>,
    project: Option<String>,
    expiring: bool,
    inactive: bool,
) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let entries = service.list_entries(&ListFilter {
        provider,
        project,
        environment: None,
        expiring,
        inactive,
    })?;

    if entries.is_empty() {
        prompts::print_no_secrets_found();
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            "Name", "Env Var", "Provider", "Account", "Projects", "Verified", "Expires", "Status",
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
    println!("\n{} {} secrets total", style("ℹ").blue(), entries.len());

    let now = Utc::now();
    let attention: Vec<String> = entries
        .iter()
        .filter_map(|entry| match entry.status() {
            KeyStatus::Expired => Some(format!("{} (expired)", entry.name)),
            KeyStatus::ExpiringSoon => {
                let days = entry
                    .expires_at
                    .map(|expires| (expires - now).num_days().max(0))
                    .unwrap_or(0);
                Some(format!("{} (expiring in {} days)", entry.name, days))
            }
            _ => None,
        })
        .collect();
    if !attention.is_empty() {
        let preview_limit = 5;
        let mut preview: Vec<String> = attention.iter().take(preview_limit).cloned().collect();
        if attention.len() > preview_limit {
            preview.push(format!("... and {} more", attention.len() - preview_limit));
        }
        println!(
            "{} {} keys need attention: {}",
            style("⚠").yellow().bold(),
            style(attention.len()).yellow(),
            style(preview.join(", ")).yellow()
        );
    }

    Ok(())
}

pub fn cmd_search(query: Option<String>) -> Result<()> {
    let query = match query {
        Some(q) => q,
        None => prompts::input_search_query()?,
    };
    let service = SecretService::new(open_db()?);
    let entries = service.search_entries(&query)?;

    if entries.is_empty() {
        println!("No secrets matching '{}' found.", style(&query).yellow());
        return Ok(());
    }

    println!(
        "{} Found {} secrets matching '{}':",
        style("▸").cyan().bold(),
        entries.len(),
        style(&query).yellow()
    );

    for entry in &entries {
        // Note: plaintext value is not stored on SecretEntry for security.
        // In a real implementation we'd fetch it, but for list/search we mask the concept.
        println!(
            "  {} {}  [{}]",
            style("•").dim(),
            style(&entry.name).cyan(),
            style(&entry.provider).dim()
        );
    }

    Ok(())
}

fn mask_value(val: &str) -> String {
    if val.len() <= 8 {
        val.to_string()
    } else {
        format!("{}...{}", &val[..4], &val[val.len() - 4..])
    }
}

pub fn cmd_health(verbose: bool) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let health = service.health_view()?;
    let detail_limit = if verbose { usize::MAX } else { 10 };

    if health.entries.is_empty() {
        prompts::print_no_secrets_found();
        return Ok(());
    }

    println!(
        "\n{} Health report for {} secrets",
        style("▸").cyan().bold(),
        health.entries.len()
    );

    let json = health.to_mcp_json();
    println!("{}", serde_json::to_string_pretty(&json)?);

    // Simple attention summary
    if !health.expired.is_empty() || !health.expiring.is_empty() {
        println!("\n{} Attention needed:", style("⚠").yellow().bold());
        for e in health.expired.iter().take(detail_limit) {
            println!("  EXPIRED: {}", e.name);
        }
        for e in health.expiring.iter().take(detail_limit) {
            println!("  EXPIRING SOON: {}", e.name);
        }
    }

    Ok(())
}

pub fn cmd_verify(name: Option<String>, all: bool, project: Option<String>) -> Result<()> {
    let service = SecretService::new(open_db()?);

    if all {
        let entries = service.list_entries(&ListFilter {
            project: project.clone(),
            ..Default::default()
        })?;
        let mut count = 0;
        for entry in entries {
            if entry.is_active {
                let mut update = crate::services::secrets::SecretUpdate::default();
                update.verify = true;
                if let Err(e) = service.update_secret(&entry.id, update) {
                    eprintln!("Failed to verify {}: {}", entry.name, e);
                } else {
                    count += 1;
                }
            }
        }
        println!("{} Verified {} secrets", style("✓").green().bold(), count);
    } else {
        let entry = crate::commands::auth::resolve_secret(&service, name, project.as_deref())?;
        let mut update = crate::services::secrets::SecretUpdate::default();
        update.verify = true;
        service.update_secret(&entry.id, update)?;
        println!(
            "{} Verified '{}'",
            style("✓").green().bold(),
            style(&entry.name).cyan()
        );
    }

    Ok(())
}
