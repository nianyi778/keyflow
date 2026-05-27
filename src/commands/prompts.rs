//! Interactive prompt helpers.
//!
//! Extracted from `commands/secrets.rs` to reduce its size and
//! centralize dialoguer usage.

use anyhow::Context;
use console::style;
use dialoguer::{Confirm, Select};
use std::io::IsTerminal;

/// Ask the user to confirm an action.
#[allow(dead_code)]
pub fn confirm(prompt: &str, default: bool) -> anyhow::Result<bool> {
    if !std::io::stdout().is_terminal() {
        return Ok(default);
    }
    Ok(Confirm::new()
        .with_prompt(prompt)
        .default(default)
        .interact()?)
}

/// Let the user pick a provider from the known list.
#[allow(dead_code)]
pub fn select_provider(providers: &[&str], default_index: usize) -> anyhow::Result<String> {
    let idx = Select::new()
        .with_prompt("Provider")
        .items(providers)
        .default(default_index)
        .interact()?;
    Ok(providers[idx].to_string())
}

/// Print a nice "cancelled" message.
#[allow(dead_code)]
pub fn print_cancelled() {
    println!("{}", style("Cancelled.").dim());
}

/// Prompt for an environment variable name.
#[allow(dead_code)]
pub fn input_env_var_name() -> anyhow::Result<String> {
    Ok(dialoguer::Input::<String>::new()
        .with_prompt("Env var name (e.g. GOOGLE_CLIENT_ID)")
        .interact_text()?)
}

/// Prompt for a search query.
#[allow(dead_code)]
pub fn input_search_query() -> anyhow::Result<String> {
    Ok(dialoguer::Input::<String>::new()
        .with_prompt("Search")
        .interact_text()?)
}

/// Complex secret value input: supports paste, stdin, password prompt.
#[allow(dead_code)]
pub fn input_secret_value(paste: bool, interactive: bool) -> anyhow::Result<String> {
    if paste {
        let output = std::process::Command::new("pbpaste")
            .output()
            .context("Failed to read clipboard (pbpaste). Are you on macOS?")?;
        let val = String::from_utf8(output.stdout)?.trim().to_string();
        if val.is_empty() {
            anyhow::bail!("Clipboard is empty");
        }
        return Ok(val);
    }

    if !interactive {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        return Ok(buf.trim().to_string());
    }

    Ok(dialoguer::Password::new()
        .with_prompt("Secret value")
        .interact()?)
}

/// Ask for confirmation with a custom prompt (TTY-aware).
pub fn confirm_action(prompt: &str, default: bool) -> anyhow::Result<bool> {
    if !std::io::stdout().is_terminal() {
        return Ok(default);
    }
    Ok(Confirm::new()
        .with_prompt(prompt)
        .default(default)
        .interact()?)
}

/// Ask whether to proceed with import/scan.
pub fn confirm_import() -> anyhow::Result<bool> {
    confirm_action("Import these candidate keys into KeyFlow?", false)
}

/// Confirm deactivation of a secret.
#[allow(dead_code)]
pub fn confirm_deactivate(name: &str) -> anyhow::Result<bool> {
    confirm_action(&format!("Deactivate secret '{}'? ", name), false)
}

/// Confirm permanent removal of a secret.
pub fn confirm_remove(name: &str) -> anyhow::Result<bool> {
    confirm_action(
        &format!(
            "Permanently remove secret '{}' (this cannot be undone)? ",
            name
        ),
        false,
    )
}

/// Generic secret selection when multiple match (uses fuzzy select).
#[allow(dead_code)]
pub fn select_from_secrets(entries: &[crate::models::SecretEntry]) -> anyhow::Result<String> {
    if entries.is_empty() {
        anyhow::bail!("No secrets to select from");
    }

    let items: Vec<String> = entries
        .iter()
        .map(|e| {
            let projects = if e.projects.is_empty() {
                "global".to_string()
            } else {
                e.projects.join(",")
            };
            format!("{} ({}) [{}]", e.name, e.env_var, projects)
        })
        .collect();

    let idx = Select::new()
        .with_prompt("Multiple secrets match. Select one:")
        .items(&items)
        .interact()?;

    Ok(entries[idx].name.clone())
}

/// Print a nicely formatted success message for adding a secret.
#[allow(dead_code)]
pub fn print_secret_added(name: &str, env_var: &str) {
    println!(
        "\n{} Secret '{}' added (env: {})",
        style("✓").green().bold(),
        style(name).cyan(),
        style(env_var).yellow()
    );
}

/// Print a "no secrets found" message.
#[allow(dead_code)]
pub fn print_no_secrets_found() {
    println!("{}", style("No secrets found.").dim());
}
