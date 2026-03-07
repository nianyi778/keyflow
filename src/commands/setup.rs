use anyhow::{Context, Result};
use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, Table};
use console::style;
use std::fs;

use crate::commands::auth::{get_data_dir, get_passphrase, load_config, save_keyfile};
use crate::crypto::Crypto;
use crate::db::Database;

pub fn cmd_serve(transport: String, host: String, port: u16) -> Result<()> {
    match open_db_noninteractive() {
        Ok(db) => match transport.as_str() {
            "stdio" => crate::mcp::serve_stdio(&db),
            "http" => crate::mcp::serve_http(&db, &host, port),
            _ => anyhow::bail!("Unsupported MCP transport '{transport}'. Use 'stdio' or 'http'."),
        },
        Err(e) => {
            // Write a proper MCP JSON-RPC error to stdout so the client
            // gets a clear message instead of hanging on "connecting..."
            let err_msg = format_mcp_startup_error(&e);
            let error_response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32002,
                    "message": err_msg
                }
            });
            let body = serde_json::to_string(&error_response).unwrap();
            print!("Content-Length: {}\r\n\r\n{}", body.len(), body);
            anyhow::bail!("{}", err_msg);
        }
    }
}

fn format_mcp_startup_error(err: &anyhow::Error) -> String {
    let msg = err.to_string();
    if msg.contains("Vault locked")
        || msg.contains("Run any `kf` command first to unlock")
        || msg.contains("KEYFLOW_PASSPHRASE")
    {
        return format!(
            "KeyFlow vault is locked. Run any `kf` command first to unlock, or set KEYFLOW_PASSPHRASE. ({})",
            err
        );
    }

    if msg.contains("unable to open database file")
        || msg.contains("Unable to open the database file")
    {
        let db_path = get_data_dir()
            .map(|dir| dir.join("keyflow.db").display().to_string())
            .unwrap_or_else(|_| "<keyflow data dir>/keyflow.db".to_string());
        return format!(
            "KeyFlow cannot access its database at {}. If this MCP server is running inside a sandboxed AI tool, grant access to the KeyFlow data directory or disable sandboxing for the MCP process. ({})",
            db_path, err
        );
    }

    format!("KeyFlow MCP failed to start. ({})", err)
}

/// Open database without any interactive prompts (env + keyfile only).
fn open_db_noninteractive() -> Result<Database> {
    let (_data_dir, _config, salt) = load_config()?;
    let passphrase = crate::commands::auth::get_passphrase_noninteractive()?;
    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = _data_dir.join("keyflow.db");
    Database::open(db_path.to_str().unwrap(), crypto)
}

struct McpTool {
    name: &'static str,
    display: &'static str,
    config_path: McpConfigPath,
    server_key: &'static str,
    format: ConfigFormat,
}

enum McpConfigPath {
    Home(&'static str),
    #[cfg(target_os = "macos")]
    AppSupport(&'static str),
    #[cfg(target_os = "linux")]
    AppSupport(&'static str),
}

#[derive(PartialEq)]
enum ConfigFormat {
    Json,
    Toml,
}

impl McpTool {
    fn resolve_path(&self) -> Option<std::path::PathBuf> {
        let home = dirs::home_dir()?;
        match &self.config_path {
            McpConfigPath::Home(rel) => Some(home.join(rel)),
            #[cfg(target_os = "macos")]
            McpConfigPath::AppSupport(rel) => {
                Some(home.join("Library/Application Support").join(rel))
            }
            #[cfg(target_os = "linux")]
            McpConfigPath::AppSupport(rel) => Some(home.join(".config").join(rel)),
        }
    }

    fn is_detected(&self) -> bool {
        if let Some(path) = self.resolve_path() {
            path.parent().map(|p| p.exists()).unwrap_or(false)
        } else {
            false
        }
    }
}

const MCP_TOOLS: &[McpTool] = &[
    McpTool {
        name: "claude",
        display: "Claude Code",
        config_path: McpConfigPath::Home(".claude.json"),
        server_key: "mcpServers",
        format: ConfigFormat::Json,
    },
    McpTool {
        name: "cursor",
        display: "Cursor",
        config_path: McpConfigPath::Home(".cursor/mcp.json"),
        server_key: "mcpServers",
        format: ConfigFormat::Json,
    },
    McpTool {
        name: "windsurf",
        display: "Windsurf",
        config_path: McpConfigPath::Home(".codeium/windsurf/mcp_config.json"),
        server_key: "mcpServers",
        format: ConfigFormat::Json,
    },
    McpTool {
        name: "gemini",
        display: "Gemini CLI",
        config_path: McpConfigPath::Home(".gemini/settings.json"),
        server_key: "mcpServers",
        format: ConfigFormat::Json,
    },
    McpTool {
        name: "opencode",
        display: "OpenCode",
        config_path: McpConfigPath::Home(".config/opencode/opencode.json"),
        server_key: "mcp",
        format: ConfigFormat::Json,
    },
    McpTool {
        name: "codex",
        display: "Codex (OpenAI)",
        config_path: McpConfigPath::Home(".codex/config.toml"),
        server_key: "mcp_servers",
        format: ConfigFormat::Toml,
    },
    McpTool {
        name: "zed",
        display: "Zed",
        config_path: McpConfigPath::Home(".config/zed/settings.json"),
        server_key: "context_servers",
        format: ConfigFormat::Json,
    },
    #[cfg(target_os = "macos")]
    McpTool {
        name: "cline",
        display: "Cline (VS Code)",
        config_path: McpConfigPath::AppSupport(
            "Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        ),
        server_key: "mcpServers",
        format: ConfigFormat::Json,
    },
    #[cfg(target_os = "linux")]
    McpTool {
        name: "cline",
        display: "Cline (VS Code)",
        config_path: McpConfigPath::AppSupport(
            "Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        ),
        server_key: "mcpServers",
        format: ConfigFormat::Json,
    },
    #[cfg(target_os = "macos")]
    McpTool {
        name: "roo",
        display: "Roo Code",
        config_path: McpConfigPath::AppSupport(
            "Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        ),
        server_key: "mcpServers",
        format: ConfigFormat::Json,
    },
    #[cfg(target_os = "linux")]
    McpTool {
        name: "roo",
        display: "Roo Code",
        config_path: McpConfigPath::AppSupport(
            "Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        ),
        server_key: "mcpServers",
        format: ConfigFormat::Json,
    },
];

pub fn cmd_setup(tool: Option<String>, all: bool, list: bool) -> Result<()> {
    if list {
        return setup_list();
    }

    let kf_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "kf".to_string());

    let passphrase = get_passphrase()?;
    let _ = save_keyfile(&passphrase);

    if all {
        return setup_all(&kf_bin);
    }

    if let Some(name) = tool {
        let tool = MCP_TOOLS.iter().find(|t| t.name == name.to_lowercase());
        match tool {
            Some(t) => setup_tool(t, &kf_bin),
            None => {
                eprintln!("{} Unknown tool: {}", style("✗").red(), name);
                eprintln!(
                    "  Run {} to see all supported tools",
                    style("kf setup --list").cyan()
                );
                Ok(())
            }
        }
    } else {
        setup_interactive(&kf_bin)
    }
}

fn setup_list() -> Result<()> {
    println!("\n{}", style("  Supported AI Tools").bold());
    println!();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    table.set_header(vec![
        Cell::new("Tool").fg(Color::Cyan),
        Cell::new("Status").fg(Color::Cyan),
        Cell::new("Config Path").fg(Color::Cyan),
        Cell::new("Format").fg(Color::Cyan),
    ]);

    for tool in MCP_TOOLS {
        let path = tool
            .resolve_path()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let (status, color) = if tool.resolve_path().map(|p| p.exists()).unwrap_or(false) {
            ("✓ Configured", Color::Green)
        } else if tool.is_detected() {
            ("● Detected", Color::Yellow)
        } else {
            ("○ Not found", Color::DarkGrey)
        };
        let fmt = if tool.format == ConfigFormat::Toml {
            "TOML"
        } else {
            "JSON"
        };
        table.add_row(vec![
            Cell::new(tool.display),
            Cell::new(status).fg(color),
            Cell::new(&path),
            Cell::new(fmt),
        ]);
    }
    println!("{table}");
    println!(
        "\n  Usage: {} or {}\n",
        style("kf setup <tool>").cyan(),
        style("kf setup --all").cyan(),
    );
    Ok(())
}

fn print_security_notes() {
    println!("\n{}", style("  Security Notes").bold());
    println!(
        "  {} Your master passphrase is NOT stored in any AI tool config.",
        style("•").dim()
    );
    println!(
        "  {} Your local passphrase file is reused by CLI and MCP until you run kf lock.",
        style("•").dim()
    );
    println!(
        "  {} Run {} to immediately remove the local passphrase file.",
        style("•").dim(),
        style("kf lock").cyan()
    );
    println!(
        "  {} Run {} to create an encrypted backup.",
        style("•").dim(),
        style("kf backup").cyan()
    );
    println!(
        "  {} If you lose your passphrase, there is no recovery. Keep a backup.\n",
        style("•").dim()
    );
}

fn setup_interactive(kf_bin: &str) -> Result<()> {
    let detected: Vec<&McpTool> = MCP_TOOLS.iter().filter(|t| t.is_detected()).collect();

    if detected.is_empty() {
        println!("{}", style("No AI coding tools detected.").yellow());
        println!(
            "Run {} to see all supported tools.",
            style("kf setup --list").cyan()
        );
        return Ok(());
    }

    println!("\n{} Detected AI tools:\n", style("⚡").cyan());

    let labels: Vec<String> = detected
        .iter()
        .map(|t| {
            let configured = t.resolve_path().map(|p| p.exists()).unwrap_or(false);
            if configured {
                format!("{} (already configured)", t.display)
            } else {
                t.display.to_string()
            }
        })
        .collect();

    let selections: Vec<bool> = detected
        .iter()
        .map(|t| !t.resolve_path().map(|p| p.exists()).unwrap_or(false))
        .collect();

    let chosen = dialoguer::MultiSelect::new()
        .with_prompt("Select tools to configure (Space to toggle, Enter to confirm)")
        .items(&labels)
        .defaults(&selections)
        .interact()?;

    if chosen.is_empty() {
        println!("{}", style("Nothing selected.").yellow());
        return Ok(());
    }

    for &idx in &chosen {
        setup_tool(detected[idx], kf_bin)?;
    }

    println!(
        "\n{} Done! Restart your AI tools to pick up the new MCP config.",
        style("✓").green().bold()
    );
    print_security_notes();
    Ok(())
}

fn setup_all(kf_bin: &str) -> Result<()> {
    let detected: Vec<&McpTool> = MCP_TOOLS.iter().filter(|t| t.is_detected()).collect();

    if detected.is_empty() {
        println!("{}", style("No AI coding tools detected.").yellow());
        return Ok(());
    }

    for tool in &detected {
        setup_tool(tool, kf_bin)?;
    }

    println!(
        "\n{} Configured {} tool(s). Restart them to activate KeyFlow MCP.",
        style("✓").green().bold(),
        detected.len()
    );
    print_security_notes();
    Ok(())
}

fn setup_tool(tool: &McpTool, kf_bin: &str) -> Result<()> {
    let path = tool
        .resolve_path()
        .context("Cannot resolve home directory")?;

    if tool.format == ConfigFormat::Toml {
        setup_tool_toml(tool, &path, kf_bin)?;
        return Ok(());
    }

    let mut config: serde_json::Value = if path.exists() {
        let content = fs::read_to_string(&path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let server_entry = json_server_entry(tool, kf_bin);

    if config.get(tool.server_key).is_none() {
        config[tool.server_key] = serde_json::json!({});
    }

    let already = config[tool.server_key].get("keyflow").is_some();
    config[tool.server_key]["keyflow"] = server_entry;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let formatted = serde_json::to_string_pretty(&config)?;
    fs::write(&path, formatted)?;

    if tool.name == "claude" {
        ensure_claude_additional_directory()?;
    }

    if already {
        println!(
            "  {} {} — updated ({})",
            style("↻").yellow(),
            tool.display,
            path.display()
        );
    } else {
        println!(
            "  {} {} — configured ({})",
            style("✓").green(),
            tool.display,
            path.display()
        );
    }

    Ok(())
}

fn ensure_claude_additional_directory() -> Result<()> {
    let home = dirs::home_dir().context("Cannot resolve home directory")?;
    let path = home.join(".claude/settings.json");
    let data_dir = get_data_dir()?;
    ensure_additional_directory_in_settings(&path, &data_dir)
}

fn ensure_additional_directory_in_settings(
    path: &std::path::Path,
    additional_dir: &std::path::Path,
) -> Result<()> {
    let mut config: serde_json::Value = if path.exists() {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    if config
        .get("permissions")
        .and_then(|v| v.as_object())
        .is_none()
    {
        config["permissions"] = serde_json::json!({});
    }
    if config["permissions"]
        .get("additionalDirectories")
        .and_then(|v| v.as_array())
        .is_none()
    {
        config["permissions"]["additionalDirectories"] = serde_json::json!([]);
    }

    let additional = config["permissions"]["additionalDirectories"]
        .as_array_mut()
        .context("Claude settings permissions.additionalDirectories must be an array")?;
    let data_dir_str = additional_dir.display().to_string();
    let already = additional.iter().any(|v| v.as_str() == Some(&data_dir_str));
    if !already {
        additional.push(serde_json::Value::String(data_dir_str));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

fn json_server_entry(tool: &McpTool, kf_bin: &str) -> serde_json::Value {
    let data_dir = get_data_dir()
        .map(|dir| dir.display().to_string())
        .unwrap_or_else(|_| String::new());
    if tool.name == "opencode" {
        // OpenCode uses "environment" (not "env") for env vars
        serde_json::json!({
            "type": "local",
            "command": [kf_bin, "serve"],
            "environment": {
                "KEYFLOW_DATA_DIR": data_dir
            }
        })
    } else {
        serde_json::json!({
            "command": kf_bin,
            "args": ["serve"],
            "env": {
                "KEYFLOW_DATA_DIR": data_dir
            }
        })
    }
}

fn setup_tool_toml(tool: &McpTool, path: &std::path::Path, kf_bin: &str) -> Result<()> {
    let mut content = if path.exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };

    let already = content.contains("[mcp_servers.keyflow]");

    if already {
        let mut lines: Vec<&str> = content.lines().collect();
        if let Some(start) = lines
            .iter()
            .position(|l| l.trim() == "[mcp_servers.keyflow]")
        {
            let mut end = start + 1;
            while end < lines.len() {
                let line = lines[end].trim();
                if line.starts_with('[') && line != "[mcp_servers.keyflow.env]" {
                    break;
                }
                end += 1;
            }
            lines.drain(start..end);
            while lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
                lines.pop();
            }
            content = lines.join("\n");
            if !content.is_empty() {
                content.push('\n');
            }
        }
    }

    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&format!(
        "\n[mcp_servers.keyflow]\ncommand = \"{kf_bin}\"\nargs = [\"serve\"]\n\n[mcp_servers.keyflow.env]\nKEYFLOW_DATA_DIR = \"{}\"\n",
        get_data_dir()?.display()
    ));

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, &content)?;

    if already {
        println!(
            "  {} {} — updated ({})",
            style("↻").yellow(),
            tool.display,
            path.display()
        );
    } else {
        println!(
            "  {} {} — configured ({})",
            style("✓").green(),
            tool.display,
            path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opencode_entry_uses_local_command_array() {
        let tool = MCP_TOOLS
            .iter()
            .find(|tool| tool.name == "opencode")
            .unwrap();
        let entry = json_server_entry(tool, "/tmp/kf");

        assert_eq!(entry["type"], "local");
        assert_eq!(entry["command"], serde_json::json!(["/tmp/kf", "serve"]));
        assert!(entry["environment"]["KEYFLOW_DATA_DIR"].as_str().is_some());
        assert!(entry.get("args").is_none());
    }

    #[test]
    fn standard_json_entry_uses_command_and_args() {
        let tool = MCP_TOOLS.iter().find(|tool| tool.name == "cursor").unwrap();
        let entry = json_server_entry(tool, "/tmp/kf");

        assert_eq!(entry["command"], "/tmp/kf");
        assert_eq!(entry["args"], serde_json::json!(["serve"]));
        assert!(entry["env"]["KEYFLOW_DATA_DIR"].as_str().is_some());
        assert!(entry.get("type").is_none());
    }

    #[test]
    fn format_mcp_error_reports_db_access_issue() {
        let err = anyhow::anyhow!("unable to open database file");
        let msg = format_mcp_startup_error(&err);
        assert!(msg.contains("cannot access its database"));
        assert!(msg.contains("keyflow.db"));
    }

    #[test]
    fn format_mcp_error_reports_locked_vault() {
        let err = anyhow::anyhow!(
            "Vault locked. Run any `kf` command first to unlock, or set KEYFLOW_PASSPHRASE."
        );
        let msg = format_mcp_startup_error(&err);
        assert!(msg.contains("vault is locked"));
        assert!(msg.contains("KEYFLOW_PASSPHRASE"));
    }

    #[test]
    fn claude_settings_get_additional_directory() {
        let root = tempfile::tempdir().unwrap();
        let settings_path = root.path().join(".claude/settings.json");
        let data_dir = root.path().join("Library/Application Support/keyflow");
        ensure_additional_directory_in_settings(&settings_path, &data_dir).unwrap();
        let content = fs::read_to_string(settings_path).unwrap();
        assert!(content.contains(&data_dir.display().to_string()));
    }
}
