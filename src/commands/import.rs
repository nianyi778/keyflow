//! Import command implementation and related types.
//!
//! Extracted from commands/secrets.rs to reduce the size of the main
//! command handler file and improve separation of concerns.

use anyhow::{bail, Result};
use console::style;
use std::io::IsTerminal;
use std::path::Path;

use crate::commands::auth::open_db;
use crate::commands::prompts;
use crate::services::secrets::{ImportRequest, SecretService};

pub struct ImportArgs {
    pub file: String,
    pub provider: Option<String>,
    pub account: Option<String>,
    pub project: Option<String>,
    pub source: Option<String>,
    pub on_conflict: String,
    pub yes: bool,
}

pub fn cmd_import(args: ImportArgs) -> Result<()> {
    let path = Path::new(&args.file);
    if !path.exists() {
        bail!("File not found: {}", args.file);
    }

    if !["skip", "overwrite", "rename"].contains(&args.on_conflict.as_str()) {
        bail!("Invalid --on-conflict value. Use: skip, overwrite, rename");
    }

    if path.is_dir() && !args.yes && std::io::stdout().is_terminal() {
        let service_preview = SecretService::new(open_db()?);
        let candidates = match service_preview.scan_path(path, false, true, false) {
            Ok(candidates) => candidates,
            Err(err)
                if matches!(
                    err.downcast_ref::<crate::services::errors::SecretError>(),
                    Some(crate::services::errors::SecretError::NoEnvFilesFound { .. })
                ) =>
            {
                println!(
                    "{}",
                    style("No importable .env files found in directory.").dim()
                );
                return Ok(());
            }
            Err(err) => return Err(err),
        };

        if candidates.is_empty() {
            println!(
                "{}",
                style("No importable .env files found in directory.").dim()
            );
            return Ok(());
        }

        println!(
            "{} Found {} candidate keys in {}:\n",
            style("▸").cyan().bold(),
            candidates.len(),
            style(&args.file).cyan()
        );
        for candidate in candidates.iter().take(20) {
            println!(
                "  {} {}  provider: {}  file: {}",
                style("•").dim(),
                style(&candidate.env_var).yellow(),
                style(&candidate.provider).cyan(),
                candidate.file.display()
            );
        }
        if candidates.len() > 20 {
            println!("  ... and {} more", candidates.len() - 20);
        }

        // Show plan summary for directory import preview
        if let Ok(plan) = service_preview.build_import_plan(&ImportRequest {
            path,
            provider: "imported",
            account_name: "",
            project_override: None,
            source: None,
            on_conflict: "skip", // conservative for preview
            recursive: false,
        }) {
            println!();
            println!(
                "{} Planned import actions (using skip on conflict for preview):",
                style("▸").cyan().bold()
            );
            println!(
                "  {} new, {} overwrite, {} rename, {} skip",
                style(plan.summary.to_insert).green(),
                style(plan.summary.to_overwrite).yellow(),
                style(plan.summary.to_rename).blue(),
                style(plan.summary.to_skip).dim()
            );
        }

        println!();
        if !prompts::confirm("Import these keys?", true)? {
            prompts::print_cancelled();
            return Ok(());
        }
    }

    let service = SecretService::new(open_db()?);
    let provider = args.provider.unwrap_or_else(|| "imported".to_string());
    let account_name = args.account.unwrap_or_default();

    let request = ImportRequest {
        path,
        provider: &provider,
        account_name: &account_name,
        project_override: args.project.as_deref(),
        source: args.source.as_deref(),
        on_conflict: &args.on_conflict,
        recursive: false,
    };

    let plan = service.build_import_plan(&request)?;
    let stats = service.apply_import_plan(&plan, &provider, &account_name, "import")?;

    println!(
        "\n{} Imported: {}, Overwritten: {}, Renamed: {}, Skipped: {}",
        style("✓").green().bold(),
        stats.imported,
        stats.overwritten,
        stats.renamed,
        stats.skipped
    );
    Ok(())
}
