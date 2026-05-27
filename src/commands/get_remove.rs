//! Get and Remove command implementations.
//!
//! Extracted from commands/secrets.rs as part of aggressive B splitting.
//! These two commands share a lot of secret selection logic.

use anyhow::Result;
use console::style;

use crate::commands::auth::{open_db, resolve_secret};
use crate::commands::prompts;
use crate::services::secrets::SecretService;

pub fn cmd_get(name: Option<String>, raw: bool, copy: bool, project: Option<String>) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let entry = resolve_secret(&service, name, project.as_deref())?;

    let value = service.get_secret_value(&entry.id)?;

    if raw {
        println!("{}", value);
    } else if copy {
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("pbcopy").arg(&value).status();
            println!("{} Value copied to clipboard", style("✓").green().bold());
        }
        #[cfg(not(target_os = "macos"))]
        {
            println!(
                "{} Clipboard copy not implemented on this platform",
                style("!").yellow()
            );
            println!("{}", value);
        }
    } else {
        println!(
            "{} {} = {}",
            style("▸").cyan().bold(),
            style(&entry.name).cyan(),
            style(&value).yellow()
        );
    }

    // Best-effort background sync (non-blocking)
    crate::commands::sync::try_background_push();

    Ok(())
}

pub fn cmd_remove(
    name: Option<String>,
    force: bool,
    purge: bool,
    project: Option<String>,
) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let entry = resolve_secret(&service, name, project.as_deref())?;

    if !force && !prompts::confirm_remove(&entry.name)? {
        prompts::print_cancelled();
        return Ok(());
    }

    let removed = if purge {
        service.remove_secret(&entry.id)?
    } else {
        // Soft remove = deactivate
        let update = crate::services::secrets::SecretUpdate {
            active: Some(false),
            ..Default::default()
        };
        service.update_secret(&entry.id, update)?;
        true
    };

    if removed {
        println!(
            "{} Secret '{}' {}",
            style("✓").green().bold(),
            style(&entry.name).cyan(),
            if purge {
                "permanently removed"
            } else {
                "deactivated"
            }
        );
    } else {
        println!(
            "{} Secret '{}' not found or already removed",
            style("!").yellow(),
            style(&entry.name).cyan()
        );
    }

    Ok(())
}
