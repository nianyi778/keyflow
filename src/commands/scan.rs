//! Scan command implementation and related types.
//!
//! Extracted from commands/secrets.rs to reduce the size of the main
//! command handler file.

use anyhow::{bail, Result};
use console::style;
use std::fs;
use std::path::Path;

use crate::commands::auth::open_db;
use crate::commands::prompts;
use crate::services::secrets::{ImportRequest, ScanImportRequest, SecretService};

pub struct ScanArgs {
    pub path: String,
    pub apply: bool,
    pub recursive: bool,
    pub new_only: bool,
    pub skip_common: bool,
    pub limit: usize,
    pub export: Option<String>,
    pub provider: Option<String>,
    pub account: Option<String>,
    pub project: Option<String>,
    pub source: Option<String>,
    pub on_conflict: String,
}

pub fn cmd_scan(args: ScanArgs) -> Result<()> {
    let scan_path = Path::new(&args.path);
    if !scan_path.exists() {
        bail!("Path not found: {}", args.path);
    }

    if args.limit == 0 {
        bail!("--limit must be greater than 0");
    }

    if !["skip", "overwrite", "rename"].contains(&args.on_conflict.as_str()) {
        bail!("Invalid --on-conflict value. Use: skip, overwrite, rename");
    }

    let service = SecretService::new(open_db()?);
    let preview = service.scan_and_import_path(ScanImportRequest {
        path: scan_path,
        recursive: args.recursive,
        skip_common: args.skip_common,
        new_only: args.new_only,
        apply: false,
        provider: args.provider.as_deref().unwrap_or("imported"),
        account_name: args.account.as_deref().unwrap_or(""),
        project_override: args.project.as_deref(),
        source: args.source.as_deref(),
        on_conflict: &args.on_conflict,
    })?;
    let candidates = preview.candidates;
    if candidates.is_empty() {
        println!("{}", style("No candidate keys found.").dim());
        return Ok(());
    }

    if let Some(ref export_path) = args.export {
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
    let preview_candidates: Vec<_> = candidates.iter().take(args.limit).collect();
    for candidate in &preview_candidates {
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
    if candidates.len() > preview_candidates.len() {
        println!(
            "  {}",
            style(format!(
                "... and {} more candidates",
                candidates.len() - preview_candidates.len()
            ))
            .dim()
        );
    }

    // Rich preview using the new ImportPlan model
    let plan_preview = service.build_import_plan(&ImportRequest {
        path: scan_path,
        provider: args.provider.as_deref().unwrap_or("imported"),
        account_name: args.account.as_deref().unwrap_or(""),
        project_override: args.project.as_deref(),
        source: args.source.as_deref(),
        on_conflict: &args.on_conflict,
        recursive: args.recursive,
    });

    if let Ok(plan) = plan_preview {
        println!();
        println!(
            "{} Planned actions if imported now:",
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

    let should_import = if args.apply {
        true
    } else {
        prompts::confirm_import()?
    };

    if !should_import {
        println!(
            "\n{} Preview only. Run {} to import without prompt.",
            style("ℹ").blue(),
            style(format!("kf scan {} --apply", args.path)).cyan()
        );
        return Ok(());
    }

    let imported = service.scan_and_import_path(ScanImportRequest {
        path: scan_path,
        recursive: args.recursive,
        skip_common: args.skip_common,
        new_only: args.new_only,
        apply: true,
        provider: args.provider.as_deref().unwrap_or("imported"),
        account_name: args.account.as_deref().unwrap_or(""),
        project_override: args.project.as_deref(),
        source: args.source.as_deref(),
        on_conflict: &args.on_conflict,
    })?;
    let stats = imported.import_stats.unwrap_or_default();

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
