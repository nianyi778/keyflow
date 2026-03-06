mod cli;
mod commands;
mod crypto;
mod db;
mod mcp;
mod models;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, GroupAction, TemplateAction};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { passphrase } => commands::cmd_init(passphrase),

        Commands::Passwd { old, new } => commands::cmd_passwd(old, new),

        Commands::Backup { output } => commands::cmd_backup(output),

        Commands::Restore { file, passphrase } => commands::cmd_restore(&file, passphrase),

        Commands::Add {
            name, env_var, value, provider, desc,
            scopes, projects, url, expires, group,
        } => commands::cmd_add(name, env_var, value, provider, desc, scopes, projects, url, expires, group),

        Commands::List {
            provider, project, group, expiring, inactive,
        } => commands::cmd_list(provider, project, group, expiring, inactive),

        Commands::Get { name, raw } => commands::cmd_get(&name, raw),

        Commands::Remove { name, force } => commands::cmd_remove(&name, force),

        Commands::Update {
            name, value, provider, desc,
            scopes, projects, url, expires, active, group,
        } => commands::cmd_update(&name, value, provider, desc, scopes, projects, url, expires, active, group),

        Commands::Run { project, group, command } => commands::cmd_run(project, group, command),

        Commands::Import {
            file, provider, project, on_conflict,
        } => commands::cmd_import(&file, provider, project, &on_conflict),

        Commands::Export { project, group, output } => commands::cmd_export(project, group, output),

        Commands::Health => commands::cmd_health(),

        Commands::Search { query } => commands::cmd_search(&query),

        Commands::Group { action } => match action {
            GroupAction::List => commands::cmd_group_list(),
            GroupAction::Show { name } => commands::cmd_group_show(&name),
            GroupAction::Export { name, output } => commands::cmd_group_export(&name, output),
        },

        Commands::Template { action } => match action {
            TemplateAction::List => commands::cmd_template_list(),
            TemplateAction::Use { name, projects, expires, prefix } => {
                commands::cmd_template_use(&name, projects, expires, prefix)
            }
        },

        Commands::Serve => commands::cmd_serve(),
    }
}
