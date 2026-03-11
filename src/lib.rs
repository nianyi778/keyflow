pub mod cli;
pub mod commands;
pub mod crypto;
pub mod db;
pub mod mcp;
pub mod models;
pub mod paths;
pub mod services;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Commands};

pub fn run() -> Result<()> {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    dispatch_command(cli)
}

fn dispatch_command(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init { passphrase } => commands::cmd_init(passphrase),
        Commands::Passwd { old, new } => commands::cmd_passwd(old, new),
        Commands::Backup { output } => commands::cmd_backup(output),
        Commands::Restore { file, passphrase } => commands::cmd_restore(&file, passphrase),
        Commands::Add {
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
        } => commands::cmd_add(commands::AddArgs {
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
        }),
        Commands::List {
            provider,
            project,
            expiring,
            inactive,
            limit,
            offset,
        } => commands::cmd_list(provider, project, expiring, inactive, limit, offset),
        Commands::Get { name, raw, copy } => commands::cmd_get(name, raw, copy),
        Commands::Remove { name, force } => commands::cmd_remove(name, force),
        Commands::Update {
            name,
            value,
            provider,
            account,
            org,
            desc,
            source,
            environment,
            permission,
            scopes,
            projects,
            url,
            expires,
            active,
            verify,
        } => commands::cmd_update(commands::UpdateArgs {
            name,
            value,
            provider,
            account,
            org,
            desc,
            source,
            environment,
            permission,
            scopes,
            projects,
            url,
            expires,
            active,
            verify,
        }),
        Commands::Run {
            project,
            all,
            command,
        } => commands::cmd_run(project, all, command),
        Commands::Import {
            file,
            provider,
            account,
            project,
            source,
            on_conflict,
        } => commands::cmd_import(&file, provider, account, project, source, &on_conflict),
        Commands::Export { project, output } => commands::cmd_export(project, output),
        Commands::Health => commands::cmd_health(),
        Commands::Verify { name, all } => commands::cmd_verify(name, all),
        Commands::Search { query } => commands::cmd_search(query),
        Commands::Scan {
            path,
            apply,
            recursive,
            new,
            skip_common,
            export,
            provider,
            account,
            project,
            source,
            on_conflict,
        } => commands::cmd_scan(
            &path,
            apply,
            recursive,
            new,
            skip_common,
            export,
            provider,
            account,
            project,
            source,
            &on_conflict,
        ),
        Commands::Lock => commands::cmd_lock(),
        Commands::Serve {
            transport,
            host,
            port,
        } => commands::cmd_serve(transport, host, port),
        Commands::Setup { tool, all, list } => commands::cmd_setup(tool, all, list),
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
    }
}
