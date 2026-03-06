mod cli;
mod commands;
mod crypto;
mod dashboard;
mod db;
mod mcp;
mod models;
mod tui;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use cli::{Cli, Commands, GroupAction, TemplateAction};

fn main() -> Result<()> {
    // `kf` with no args → launch TUI
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            return tui::cmd_tui();
        }
        Err(e) => e.exit(),
    };

    match cli.command {
        Commands::Init { passphrase } => commands::cmd_init(passphrase),

        Commands::Passwd { old, new } => commands::cmd_passwd(old, new),

        Commands::Backup { output } => commands::cmd_backup(output),

        Commands::Restore { file, passphrase } => commands::cmd_restore(&file, passphrase),

        Commands::Add {
            env_var, value, provider, projects, group, desc, expires, paste,
        } => commands::cmd_add(env_var, value, provider, projects, group, desc, expires, paste),

        Commands::List {
            provider, project, group, expiring, inactive,
        } => commands::cmd_list(provider, project, group, expiring, inactive),

        Commands::Get { name, raw, copy } => commands::cmd_get(name, raw, copy),

        Commands::Remove { name, force } => commands::cmd_remove(name, force),

        Commands::Update {
            name, value, provider, desc,
            scopes, projects, url, expires, active, group,
        } => commands::cmd_update(name, value, provider, desc, scopes, projects, url, expires, active, group),

        Commands::Run { project, group, all, command } => commands::cmd_run(project, group, all, command),

        Commands::Import {
            file, provider, project, on_conflict,
        } => commands::cmd_import(&file, provider, project, &on_conflict),

        Commands::Export { project, group, output } => commands::cmd_export(project, group, output),

        Commands::Health => commands::cmd_health(),

        Commands::Search { query } => commands::cmd_search(query),

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

        Commands::Lock => commands::cmd_lock(),

        Commands::Serve => commands::cmd_serve(),

        Commands::Completions { shell } => {
            let bin_name = std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "keyflow".to_string());
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                &bin_name,
                &mut std::io::stdout(),
            );
            Ok(())
        }

        Commands::Ui => tui::cmd_tui(),

        Commands::Web { port } => dashboard::cmd_dashboard(port),
    }
}
