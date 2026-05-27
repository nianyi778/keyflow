//! Update command implementation.
//!
//! Extracted from commands/secrets.rs.

use anyhow::Result;
use console::style;

use crate::commands::auth::{open_db, resolve_secret};
use crate::services::secrets::{SecretService, SecretUpdate};

pub struct UpdateArgs {
    pub name: Option<String>,
    pub rename: Option<String>,
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
    pub project_filter: Option<String>,
}

pub fn cmd_update(args: UpdateArgs) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let entry = resolve_secret(&service, args.name, args.project_filter.as_deref())?;

    let mut update = SecretUpdate::default();

    if let Some(new_name) = args.rename {
        update.name = Some(new_name);
    }
    if let Some(v) = args.value {
        update.value = Some(v);
    }
    if let Some(p) = args.provider {
        update.provider = Some(p);
    }
    if let Some(a) = args.account {
        update.account_name = Some(a);
    }
    if let Some(o) = args.org {
        update.org_name = Some(o);
    }
    if let Some(d) = args.desc {
        update.description = Some(d);
    }
    if let Some(s) = args.source {
        update.source = Some(s);
    }
    if let Some(e) = args.environment {
        update.environment = Some(e);
    }
    if let Some(p) = args.permission {
        update.permission_profile = Some(p);
    }
    if let Some(sc) = args.scopes {
        update.scopes = Some(crate::commands::helpers::parse_csv(&sc));
    }
    if let Some(pr) = args.projects {
        update.projects = Some(crate::commands::helpers::parse_csv(&pr));
    }
    if let Some(u) = args.url {
        update.apply_url = Some(u);
    }
    if let Some(e) = args.expires {
        update.expires_at = crate::services::secrets::parse_optional_expires(Some(e))?;
    }
    if let Some(a) = args.active {
        update.active = Some(a);
    }
    update.verify = args.verify;

    service.update_secret(&entry.id, update)?;

    println!(
        "{} Secret '{}' updated",
        style("✓").green().bold(),
        style(&entry.name).cyan()
    );

    crate::commands::sync::try_background_push();

    Ok(())
}
