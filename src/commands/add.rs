//! Add command implementation.
//!
//! Extracted from commands/secrets.rs as part of aggressive B splitting.

use anyhow::{bail, Result};
use console::style;
use std::io::IsTerminal;

use crate::commands::auth::open_db;
use crate::commands::helpers::{get_default_url, parse_csv, PROVIDERS};
use crate::commands::prompts;
use crate::services::secrets::{Provider, SecretDraft, SecretService};

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
    let interactive = std::io::stdin().is_terminal();

    let env_var = match env_var {
        Some(e) => e,
        None if interactive => prompts::input_env_var_name()?,
        None => bail!("Env var name is required in non-interactive mode"),
    };

    let secret_value = if let Some(v) = value {
        if v == "-" {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf.trim().to_string()
        } else {
            v
        }
    } else {
        prompts::input_secret_value(paste, interactive)?
    };

    if secret_value.is_empty() {
        bail!("Secret value cannot be empty");
    }

    let inferred_provider = service.infer_provider_for_env_var(&env_var);
    let provider = match provider {
        Some(p) => p,
        None => {
            if let Some(ref value) = inferred_provider {
                println!("  {} provider: {}", style("▸").dim(), style(value).cyan());
            }
            if interactive && inferred_provider.is_none() {
                prompts::select_provider(PROVIDERS, PROVIDERS.len() - 1)?
            } else {
                inferred_provider.unwrap_or_else(|| "other".to_string())
            }
        }
    };

    let projects_vec: Vec<String> = match projects {
        Some(p) => parse_csv(&p),
        None => {
            let detected = service.detect_current_project_name().unwrap_or_default();
            if !detected.is_empty() {
                println!(
                    "  {} project: {} (from current dir)",
                    style("▸").dim(),
                    style(&detected).cyan()
                );
                parse_csv(&detected)
            } else {
                vec![]
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
        provider: Provider::from(provider),
        account_name,
        org_name,
        description,
        source,
        environment: environment_val,
        permission_profile,
        scopes: vec![],
        projects: projects_vec,
        apply_url,
        expires_at: crate::services::secrets::parse_expires(expires)?,
    })?;

    println!(
        "\n{} Secret '{}' added (env: {})",
        style("✓").green().bold(),
        style(&entry.name).cyan(),
        style(&entry.env_var).yellow()
    );

    crate::commands::sync::try_background_push();

    Ok(())
}
