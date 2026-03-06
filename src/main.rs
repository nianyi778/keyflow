mod cli;
mod commands;
mod crypto;
mod db;
mod mcp;
mod models;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { passphrase } => commands::cmd_init(passphrase),

        Commands::Add {
            name,
            env_var,
            value,
            provider,
            desc,
            scopes,
            projects,
            url,
            expires,
        } => commands::cmd_add(name, env_var, value, provider, desc, scopes, projects, url, expires),

        Commands::List {
            provider,
            project,
            expiring,
            inactive,
        } => commands::cmd_list(provider, project, expiring, inactive),

        Commands::Get { name, raw } => commands::cmd_get(&name, raw),

        Commands::Remove { name, force } => commands::cmd_remove(&name, force),

        Commands::Update {
            name,
            value,
            provider,
            desc,
            scopes,
            projects,
            url,
            expires,
            active,
        } => commands::cmd_update(&name, value, provider, desc, scopes, projects, url, expires, active),

        Commands::Run { project, command } => commands::cmd_run(project, command),

        Commands::Import {
            file,
            provider,
            project,
        } => commands::cmd_import(&file, provider, project),

        Commands::Export { project, output } => commands::cmd_export(project, output),

        Commands::Health => commands::cmd_health(),

        Commands::Search { query } => commands::cmd_search(&query),

        Commands::Serve => commands::cmd_serve(),
    }
}
