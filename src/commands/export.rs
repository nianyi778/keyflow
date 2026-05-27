//! Export command implementation.
//!
//! Extracted from commands/secrets.rs as part of B thinning.

use anyhow::Result;
use console::style;

use crate::commands::auth::open_db;
use crate::services::secrets::SecretService;

pub fn cmd_export(
    project: Option<String>,
    environment: Option<String>,
    output: Option<String>,
) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let (entries, content) = service.export_project_env(project, environment)?;

    match output {
        Some(path) => {
            crate::secure_fs::write_private(std::path::Path::new(&path), &content)?;
            println!(
                "{} Exported {} secrets to {}",
                style("✓").green().bold(),
                entries.len(),
                style(&path).cyan()
            );
            println!(
                "  {} {} contains plaintext secrets — keep it private and delete it when done.",
                style("!").yellow().bold(),
                style(&path).cyan()
            );
        }
        None => {
            print!("{}", content);
        }
    }

    Ok(())
}
