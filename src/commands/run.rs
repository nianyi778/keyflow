//! Run command implementation (env injection + execution).
//!
//! Extracted from commands/secrets.rs.

use anyhow::{Context, Result};
use console::style;

use crate::commands::auth::open_db;
use crate::services::secrets::SecretService;

pub fn cmd_run(
    project: Option<String>,
    all: bool,
    dry_run: bool,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("No command provided after --");
    }

    let service = SecretService::new(open_db()?);
    let resolution = service.resolve_run_env_pairs(
        project,
        all,
        crate::commands::helpers::detect_project_name(),
    )?;

    if resolution.env_pairs.is_empty() {
        println!("{}", style("No secrets to inject for this context.").dim());
    } else {
        println!(
            "{} Injecting {} secrets for project: {}",
            style("▸").cyan().bold(),
            resolution.env_pairs.len(),
            style(resolution.project.as_deref().unwrap_or("all")).yellow()
        );
    }

    if dry_run {
        for (k, v) in &resolution.env_pairs {
            println!("  {}={}", k, style(v).dim());
        }
        println!("{}", style("(dry-run: not executing command)").yellow());
        return Ok(());
    }

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (key, val) in &resolution.env_pairs {
        cmd.env(key, val);
    }

    let status = cmd.status().context("Failed to execute command")?;
    let code = status.code().unwrap_or(1);

    // Must exit with child's code (skips destructors)
    drop(resolution.env_pairs);
    drop(service);
    std::process::exit(code);
}
