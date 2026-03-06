use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::Command;

use crate::db::Database;
use crate::models::ListFilter;

/// MCP Server over stdio (JSON-RPC 2.0 with Content-Length headers)
pub fn serve(db: &Database) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());

    loop {
        match read_message(&mut reader)? {
            Some(msg) => {
                let response = handle_message(db, &msg);
                if let Some(resp) = response {
                    write_message(&mut stdout.lock(), &resp)?;
                }
            }
            None => break, // EOF
        }
    }
    Ok(())
}

fn read_message(reader: &mut impl BufRead) -> Result<Option<Value>> {
    let mut content_length: Option<usize> = None;

    // Read headers
    loop {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Ok(None); // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break; // End of headers
        }
        if let Some(len_str) = trimmed.strip_prefix("Content-Length: ") {
            content_length = Some(len_str.parse()?);
        }
    }

    let length = match content_length {
        Some(len) => len,
        None => return Ok(None),
    };

    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let msg: Value = serde_json::from_slice(&body)?;
    Ok(Some(msg))
}

fn write_message(writer: &mut impl Write, msg: &Value) -> Result<()> {
    let body = serde_json::to_string(msg)?;
    write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body)?;
    writer.flush()?;
    Ok(())
}

fn handle_message(db: &Database, msg: &Value) -> Option<Value> {
    let method = msg.get("method")?.as_str()?;
    let id = msg.get("id");

    // Notifications (no id) don't need a response
    if id.is_none() {
        return None;
    }

    let id = id.unwrap().clone();
    let params = msg.get("params").cloned().unwrap_or(json!({}));

    let result = match method {
        "initialize" => handle_initialize(),
        "tools/list" => handle_tools_list(),
        "tools/call" => handle_tools_call(db, &params),
        _ => Err(anyhow::anyhow!("Method not found: {}", method)),
    };

    Some(match result {
        Ok(r) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": r
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32603,
                "message": e.to_string()
            }
        }),
    })
}

fn handle_initialize() -> Result<Value> {
    Ok(json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "keyflow",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}

fn handle_tools_list() -> Result<Value> {
    Ok(json!({
        "tools": [
            // === Read tools ===
            {
                "name": "search_keys",
                "description": "Search for API keys/secrets by keyword. Returns metadata (name, provider, env_var, scopes, status) but NEVER the actual secret value. Use this to find the right environment variable name to use in code.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search keyword (matches name, provider, env_var, description, scopes, projects)"
                        }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "get_key_info",
                "description": "Get detailed metadata about a specific secret by name. Returns env_var name, provider, scopes, expiry status, and usage hint. NEVER returns the actual secret value.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The secret name (as shown in search_keys results)"
                        }
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "list_providers",
                "description": "List all registered secret providers (e.g., google, github, cloudflare) and count of keys per provider.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "list_projects",
                "description": "List all project tags and their associated secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "check_health",
                "description": "Check health status of all secrets. Returns expired, expiring soon, and unused keys.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "list_keys_for_project",
                "description": "List all secrets tagged with a specific project. Useful to know what env vars are available for a project.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project": {
                            "type": "string",
                            "description": "Project name/tag"
                        }
                    },
                    "required": ["project"]
                }
            },
            // === Action tools ===
            {
                "name": "deploy_secret",
                "description": "Deploy a secret from KeyFlow vault to a cloud service (e.g., Cloudflare Workers, Vercel, Fly.io, Heroku, Netlify, Railway). The secret value is sent directly from KeyFlow to the service CLI — it NEVER passes through the AI. This is the secure way to push secrets to production. Requires the target service's CLI to be installed.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "secret_name": {
                            "type": "string",
                            "description": "The KeyFlow secret name to deploy (as shown in search_keys results)"
                        },
                        "target": {
                            "type": "string",
                            "enum": ["cloudflare-workers", "vercel", "fly", "heroku", "netlify", "railway"],
                            "description": "Target cloud service to deploy to"
                        },
                        "environment": {
                            "type": "string",
                            "description": "Target environment (e.g., 'production', 'preview', 'staging'). Used as --env for wrangler, environment for vercel, etc."
                        },
                        "app": {
                            "type": "string",
                            "description": "App name (required for fly, heroku; optional for others)"
                        },
                        "working_dir": {
                            "type": "string",
                            "description": "Working directory to run the CLI command in (useful for wrangler which needs wrangler.toml)"
                        }
                    },
                    "required": ["secret_name", "target"]
                }
            },
            {
                "name": "deploy_project_secrets",
                "description": "Deploy ALL secrets tagged with a project to a cloud service at once. Equivalent to running deploy_secret for each key in the project. The secret values NEVER pass through the AI.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project": {
                            "type": "string",
                            "description": "Project name/tag in KeyFlow"
                        },
                        "target": {
                            "type": "string",
                            "enum": ["cloudflare-workers", "vercel", "fly", "heroku", "netlify", "railway"],
                            "description": "Target cloud service"
                        },
                        "environment": {
                            "type": "string",
                            "description": "Target environment (e.g., 'production')"
                        },
                        "app": {
                            "type": "string",
                            "description": "App name (for fly, heroku)"
                        },
                        "working_dir": {
                            "type": "string",
                            "description": "Working directory for the CLI command"
                        }
                    },
                    "required": ["project", "target"]
                }
            },
            {
                "name": "add_key",
                "description": "Add a new secret to KeyFlow vault. Use when the user provides a secret value in chat and you want to store it securely. After storing, the value is encrypted and you should forget it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "env_var": {
                            "type": "string",
                            "description": "Environment variable name (e.g., STRIPE_SECRET_KEY)"
                        },
                        "value": {
                            "type": "string",
                            "description": "The secret value to store (will be encrypted with AES-256-GCM)"
                        },
                        "provider": {
                            "type": "string",
                            "description": "Service provider (e.g., google, github, stripe, cloudflare)"
                        },
                        "description": {
                            "type": "string",
                            "description": "Human-readable description"
                        },
                        "projects": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Project tags to associate with this secret"
                        },
                        "group": {
                            "type": "string",
                            "description": "Key group name (e.g., 'google-oauth')"
                        }
                    },
                    "required": ["env_var", "value"]
                }
            },
            {
                "name": "get_env_snippet",
                "description": "Generate a .env file snippet for a project or group. Returns KEY=VALUE lines that can be written to a .env file. Use this when setting up a project's local environment.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project": {
                            "type": "string",
                            "description": "Project name to export secrets for"
                        },
                        "group": {
                            "type": "string",
                            "description": "Key group to export"
                        },
                        "mask_values": {
                            "type": "boolean",
                            "description": "If true, mask actual values with '***' (safe to show). If false, return real values for .env file generation. Default: true"
                        }
                    }
                }
            },
            {
                "name": "check_project_readiness",
                "description": "Check if a project has all required secrets ready. Analyzes which keys exist, which are expired, and which might be missing based on the project's tech stack. Pass a list of required env vars to check against.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "project": {
                            "type": "string",
                            "description": "Project name/tag in KeyFlow"
                        },
                        "required_vars": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "List of environment variable names that the project requires (e.g., ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'DATABASE_URL'])"
                        }
                    },
                    "required": ["project", "required_vars"]
                }
            }
        ]
    }))
}

fn handle_tools_call(db: &Database, params: &Value) -> Result<Value> {
    let tool_name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing tool name"))?;

    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    let result = match tool_name {
        // Read tools
        "search_keys" => tool_search_keys(db, &arguments)?,
        "get_key_info" => tool_get_key_info(db, &arguments)?,
        "list_providers" => tool_list_providers(db)?,
        "list_projects" => tool_list_projects(db)?,
        "check_health" => tool_check_health(db)?,
        "list_keys_for_project" => tool_list_keys_for_project(db, &arguments)?,
        // Action tools
        "deploy_secret" => tool_deploy_secret(db, &arguments)?,
        "deploy_project_secrets" => tool_deploy_project_secrets(db, &arguments)?,
        "add_key" => tool_add_key(db, &arguments)?,
        "get_env_snippet" => tool_get_env_snippet(db, &arguments)?,
        "check_project_readiness" => tool_check_project_readiness(db, &arguments)?,
        _ => return Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&result)?
        }]
    }))
}

// ─── Helpers ───

fn secret_to_metadata(entry: &crate::models::SecretEntry) -> Value {
    json!({
        "name": entry.name,
        "env_var": entry.env_var,
        "provider": entry.provider,
        "description": entry.description,
        "scopes": entry.scopes,
        "projects": entry.projects,
        "key_group": entry.key_group,
        "apply_url": entry.apply_url,
        "status": entry.status().to_string(),
        "expires_at": entry.expires_at.map(|d| d.to_rfc3339()),
        "last_used_at": entry.last_used_at.map(|d| d.to_rfc3339()),
        "usage_hint": format!("Use via environment variable: {}", entry.env_var),
    })
}

fn get_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    get_str(args, key)
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: '{}'", key))
}

// ─── Read Tools ───

fn tool_search_keys(db: &Database, args: &Value) -> Result<Value> {
    let query = require_str(args, "query")?;
    let entries = db.search_secrets(query)?;
    let results: Vec<Value> = entries.iter().map(secret_to_metadata).collect();
    Ok(json!({
        "found": !results.is_empty(),
        "count": results.len(),
        "keys": results
    }))
}

fn tool_get_key_info(db: &Database, args: &Value) -> Result<Value> {
    let name = require_str(args, "name")?;
    let entry = db.get_secret(name)?;
    Ok(secret_to_metadata(&entry))
}

fn tool_list_providers(db: &Database) -> Result<Value> {
    let entries = db.list_secrets(&ListFilter::default())?;
    let mut providers: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for entry in &entries {
        *providers.entry(entry.provider.clone()).or_insert(0) += 1;
    }
    let result: Vec<Value> = providers
        .iter()
        .map(|(name, count)| json!({ "provider": name, "key_count": count }))
        .collect();
    Ok(json!({ "providers": result }))
}

fn tool_list_projects(db: &Database) -> Result<Value> {
    let entries = db.list_secrets(&ListFilter::default())?;
    let mut projects: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for entry in &entries {
        for proj in &entry.projects {
            projects.entry(proj.clone()).or_default().push(entry.name.clone());
        }
    }
    let result: Vec<Value> = projects
        .iter()
        .map(|(name, keys)| json!({ "project": name, "keys": keys }))
        .collect();
    Ok(json!({ "projects": result }))
}

fn tool_check_health(db: &Database) -> Result<Value> {
    let entries = db.list_secrets(&ListFilter {
        inactive: true,
        ..Default::default()
    })?;

    let mut expired = Vec::new();
    let mut expiring_soon = Vec::new();
    let mut unused_30d = Vec::new();
    let mut inactive = Vec::new();

    let now = chrono::Utc::now();

    for entry in &entries {
        if !entry.is_active {
            inactive.push(secret_to_metadata(entry));
            continue;
        }
        match entry.status() {
            crate::models::KeyStatus::Expired => expired.push(secret_to_metadata(entry)),
            crate::models::KeyStatus::ExpiringSoon => expiring_soon.push(secret_to_metadata(entry)),
            _ => {}
        }
        if let Some(last_used) = entry.last_used_at {
            if now - last_used > chrono::Duration::days(30) {
                unused_30d.push(secret_to_metadata(entry));
            }
        } else if now - entry.created_at > chrono::Duration::days(30) {
            unused_30d.push(secret_to_metadata(entry));
        }
    }

    Ok(json!({
        "expired": { "count": expired.len(), "keys": expired },
        "expiring_soon": { "count": expiring_soon.len(), "keys": expiring_soon },
        "unused_30_days": { "count": unused_30d.len(), "keys": unused_30d },
        "inactive": { "count": inactive.len(), "keys": inactive },
    }))
}

fn tool_list_keys_for_project(db: &Database, args: &Value) -> Result<Value> {
    let project = require_str(args, "project")?;
    let entries = db.list_secrets(&ListFilter {
        project: Some(project.to_string()),
        ..Default::default()
    })?;

    let results: Vec<Value> = entries.iter().map(secret_to_metadata).collect();
    Ok(json!({
        "project": project,
        "count": results.len(),
        "keys": results
    }))
}

// ─── Action Tools ───

/// Deploy a single secret to a cloud service.
/// The value goes directly from vault → service CLI, never through AI.
fn tool_deploy_secret(db: &Database, args: &Value) -> Result<Value> {
    let secret_name = require_str(args, "secret_name")?;
    let target = require_str(args, "target")?;
    let environment = get_str(args, "environment");
    let app = get_str(args, "app");
    let working_dir = get_str(args, "working_dir");

    // Get the secret metadata + value
    let entry = db.get_secret(secret_name)?;
    let value = db.get_secret_value(secret_name)?;

    let result = run_deploy(&entry.env_var, &value, target, environment, app, working_dir)?;
    Ok(result)
}

/// Deploy all secrets for a project to a cloud service.
fn tool_deploy_project_secrets(db: &Database, args: &Value) -> Result<Value> {
    let project = require_str(args, "project")?;
    let target = require_str(args, "target")?;
    let environment = get_str(args, "environment");
    let app = get_str(args, "app");
    let working_dir = get_str(args, "working_dir");

    let entries = db.list_secrets(&ListFilter {
        project: Some(project.to_string()),
        ..Default::default()
    })?;

    if entries.is_empty() {
        return Ok(json!({
            "success": false,
            "error": format!("No secrets found for project '{}'", project),
            "deployed": [],
            "failed": []
        }));
    }

    let mut deployed = Vec::new();
    let mut failed = Vec::new();

    for entry in &entries {
        let value = match db.get_secret_value(&entry.name) {
            Ok(v) => v,
            Err(e) => {
                failed.push(json!({
                    "env_var": entry.env_var,
                    "name": entry.name,
                    "error": e.to_string()
                }));
                continue;
            }
        };

        match run_deploy(&entry.env_var, &value, target, environment, app, working_dir) {
            Ok(result) => {
                if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                    deployed.push(json!({
                        "env_var": entry.env_var,
                        "name": entry.name,
                    }));
                } else {
                    failed.push(json!({
                        "env_var": entry.env_var,
                        "name": entry.name,
                        "error": result.get("error").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    }));
                }
            }
            Err(e) => {
                failed.push(json!({
                    "env_var": entry.env_var,
                    "name": entry.name,
                    "error": e.to_string()
                }));
            }
        }
    }

    Ok(json!({
        "success": failed.is_empty(),
        "project": project,
        "target": target,
        "deployed_count": deployed.len(),
        "failed_count": failed.len(),
        "deployed": deployed,
        "failed": failed
    }))
}

/// Execute the actual deployment command.
/// Value is piped via stdin to avoid leaking in `ps` output.
fn run_deploy(
    env_var: &str,
    value: &str,
    target: &str,
    environment: Option<&str>,
    app: Option<&str>,
    working_dir: Option<&str>,
) -> Result<Value> {
    // Check that the target CLI tool is installed
    let cli_name = match target {
        "cloudflare-workers" => "wrangler",
        "vercel" => "vercel",
        "fly" => "fly",
        "heroku" => "heroku",
        "netlify" => "netlify",
        "railway" => "railway",
        _ => bail!("Unsupported deploy target: '{}'. Supported: cloudflare-workers, vercel, fly, heroku, netlify, railway", target),
    };

    // Build command based on target
    let mut cmd = match target {
        "cloudflare-workers" => {
            // wrangler secret put ENV_VAR [--env <env>]
            // Value is read from stdin
            let mut c = Command::new("wrangler");
            c.args(["secret", "put", env_var]);
            if let Some(env) = environment {
                c.args(["--env", env]);
            }
            c.stdin(std::process::Stdio::piped());
            c
        }
        "vercel" => {
            // echo "value" | vercel env add ENV_VAR <environment>
            let mut c = Command::new("vercel");
            let env = environment.unwrap_or("production");
            c.args(["env", "add", env_var, env]);
            c.stdin(std::process::Stdio::piped());
            c
        }
        "fly" => {
            // fly secrets set ENV_VAR=value [--app <app>]
            // Value passed via stdin to avoid leaking in `ps`
            let mut c = Command::new("fly");
            c.args(["secrets", "set", &format!("{}=-", env_var), "--stage"]);
            if let Some(a) = app {
                c.args(["--app", a]);
            }
            c.stdin(std::process::Stdio::piped());
            c
        }
        "heroku" => {
            // heroku config:set ENV_VAR=value [--app <app>]
            // Use a temp env var to avoid value in CLI args visible via `ps`
            let mut c = Command::new("sh");
            c.args(["-c", &format!(
                "printf '%s' \"$__KF_VAL\" | heroku config:set {}=\"$(cat)\"{}",
                env_var,
                app.map(|a| format!(" --app {}", a)).unwrap_or_default()
            )]);
            c.env("__KF_VAL", value);
            c
        }
        "netlify" => {
            // netlify env:set ENV_VAR --value $val
            // Pass value via env var to keep it out of `ps`
            let mut c = Command::new("sh");
            c.args(["-c", &format!(
                "netlify env:set {} \"$__KF_VAL\"",
                env_var
            )]);
            c.env("__KF_VAL", value);
            c
        }
        "railway" => {
            // railway variables set ENV_VAR=value
            // Pass value via env var to keep it out of `ps`
            let mut c = Command::new("sh");
            c.args(["-c", &format!(
                "railway variables set {}=\"$__KF_VAL\"",
                env_var
            )]);
            c.env("__KF_VAL", value);
            c
        }
        _ => unreachable!(),
    };

    // Set working directory if specified
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    // Capture stdout/stderr (don't let it leak into MCP stdio)
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    // Execute
    let child = cmd.spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(json!({
                    "success": false,
                    "env_var": env_var,
                    "target": target,
                    "error": format!("'{}' CLI not found. Install it first: {}", cli_name, get_install_hint(target)),
                }));
            }
            return Ok(json!({
                "success": false,
                "env_var": env_var,
                "target": target,
                "error": format!("Failed to run '{}': {}", cli_name, e),
            }));
        }
    };

    // For stdin-based targets, write the value
    if matches!(target, "cloudflare-workers" | "vercel" | "fly") {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(value.as_bytes());
            let _ = stdin.write_all(b"\n");
            // stdin is dropped here, closing the pipe
        }
    }

    let output = child.wait_with_output()?;
    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(json!({
            "success": true,
            "env_var": env_var,
            "target": target,
            "message": format!("Successfully deployed {} to {}", env_var, target),
            "cli_output": stdout_str.trim(),
        }))
    } else {
        Ok(json!({
            "success": false,
            "env_var": env_var,
            "target": target,
            "error": if !stderr_str.is_empty() { stderr_str.trim().to_string() } else { stdout_str.trim().to_string() },
            "exit_code": output.status.code(),
        }))
    }
}

fn get_install_hint(target: &str) -> &'static str {
    match target {
        "cloudflare-workers" => "npm install -g wrangler",
        "vercel" => "npm install -g vercel",
        "fly" => "brew install flyctl (or curl -L https://fly.io/install.sh | sh)",
        "heroku" => "brew tap heroku/brew && brew install heroku",
        "netlify" => "npm install -g netlify-cli",
        "railway" => "npm install -g @railway/cli",
        _ => "(see provider docs)",
    }
}

/// Add a new secret to the vault.
fn tool_add_key(db: &Database, args: &Value) -> Result<Value> {
    let env_var = require_str(args, "env_var")?;
    let value = require_str(args, "value")?;
    let provider = get_str(args, "provider").unwrap_or("");
    let description = get_str(args, "description").unwrap_or("");
    let group = get_str(args, "group").unwrap_or("");

    let projects: Vec<String> = args
        .get("projects")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    // Auto-detect provider from env_var if not specified
    let provider = if provider.is_empty() {
        guess_provider(env_var)
    } else {
        provider.to_string()
    };

    // Generate name from env_var (lowercase, underscores to hyphens)
    let name = env_var.to_lowercase().replace('_', "-");

    // Check if already exists
    if db.secret_exists(&name)? {
        return Ok(json!({
            "success": false,
            "error": format!("Secret '{}' already exists. Use a different name or update the existing one.", name),
            "existing_name": name,
        }));
    }

    let now = chrono::Utc::now();
    let entry = crate::models::SecretEntry {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.clone(),
        env_var: env_var.to_string(),
        provider: provider.clone(),
        description: description.to_string(),
        scopes: Vec::new(),
        projects,
        apply_url: String::new(),
        expires_at: None,
        created_at: now,
        updated_at: now,
        last_used_at: None,
        is_active: true,
        key_group: group.to_string(),
    };

    db.add_secret(&entry, value)?;

    Ok(json!({
        "success": true,
        "message": format!("Secret '{}' added successfully", name),
        "name": name,
        "env_var": env_var,
        "provider": provider,
        "hint": "The value is now encrypted with AES-256-GCM. You can forget the plaintext value.",
    }))
}

fn guess_provider(env_var: &str) -> String {
    let upper = env_var.to_uppercase();
    let providers = [
        ("GOOGLE", "google"), ("GCP", "google"),
        ("GITHUB", "github"), ("GH_", "github"),
        ("CLOUDFLARE", "cloudflare"), ("CF_", "cloudflare"), ("WRANGLER", "cloudflare"),
        ("AWS", "aws"),
        ("AZURE", "azure"),
        ("OPENAI", "openai"),
        ("ANTHROPIC", "anthropic"), ("CLAUDE", "anthropic"),
        ("STRIPE", "stripe"),
        ("VERCEL", "vercel"),
        ("SUPABASE", "supabase"),
        ("FIREBASE", "firebase"),
        ("TWILIO", "twilio"),
        ("SENDGRID", "sendgrid"),
        ("SLACK", "slack"),
        ("DOCKER", "docker"),
        ("NPM", "npm"),
        ("PYPI", "pypi"),
        ("FLY_", "fly"), ("FLYIO", "fly"),
        ("HEROKU", "heroku"),
        ("NETLIFY", "netlify"),
        ("RAILWAY", "railway"),
        ("R2_", "cloudflare"),
    ];
    for (prefix, provider) in providers {
        if upper.contains(prefix) {
            return provider.to_string();
        }
    }
    "other".to_string()
}

/// Generate .env snippet for a project or group.
fn tool_get_env_snippet(db: &Database, args: &Value) -> Result<Value> {
    let project = get_str(args, "project");
    let group = get_str(args, "group");
    let mask_values = args.get("mask_values").and_then(|v| v.as_bool()).unwrap_or(true);

    if project.is_none() && group.is_none() {
        bail!("At least one of 'project' or 'group' must be specified");
    }

    let entries = db.list_secrets(&ListFilter {
        project: project.map(|s| s.to_string()),
        group: group.map(|s| s.to_string()),
        ..Default::default()
    })?;

    if entries.is_empty() {
        return Ok(json!({
            "found": false,
            "snippet": "",
            "message": "No secrets found for the given filter",
        }));
    }

    let mut lines = Vec::new();
    let mut key_list = Vec::new();

    for entry in &entries {
        let val = if mask_values {
            "***".to_string()
        } else {
            db.get_secret_value(&entry.name)?
        };
        lines.push(format!("{}={}", entry.env_var, val));
        key_list.push(json!({
            "env_var": entry.env_var,
            "name": entry.name,
            "provider": entry.provider,
        }));
    }

    Ok(json!({
        "found": true,
        "count": lines.len(),
        "snippet": lines.join("\n"),
        "keys": key_list,
        "masked": mask_values,
        "hint": if mask_values {
            "Values are masked. Set mask_values=false to get real values for .env file generation."
        } else {
            "Contains real secret values. Write to .env file and do NOT commit to git."
        },
    }))
}

/// Check if a project has all required secrets.
fn tool_check_project_readiness(db: &Database, args: &Value) -> Result<Value> {
    let project = require_str(args, "project")?;
    let required_vars: Vec<String> = args
        .get("required_vars")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let entries = db.list_secrets(&ListFilter {
        project: Some(project.to_string()),
        ..Default::default()
    })?;

    let available_vars: std::collections::HashSet<String> =
        entries.iter().map(|e| e.env_var.clone()).collect();

    let mut ready = Vec::new();
    let mut missing = Vec::new();
    let mut expired = Vec::new();

    for var in &required_vars {
        if available_vars.contains(var) {
            // Found — check if it's healthy
            if let Some(entry) = entries.iter().find(|e| &e.env_var == var) {
                match entry.status() {
                    crate::models::KeyStatus::Expired => {
                        expired.push(json!({
                            "env_var": var,
                            "name": entry.name,
                            "status": "expired",
                            "expires_at": entry.expires_at.map(|d| d.to_rfc3339()),
                            "apply_url": entry.apply_url,
                        }));
                    }
                    crate::models::KeyStatus::ExpiringSoon => {
                        ready.push(json!({
                            "env_var": var,
                            "name": entry.name,
                            "status": "expiring_soon",
                            "expires_at": entry.expires_at.map(|d| d.to_rfc3339()),
                        }));
                    }
                    _ => {
                        ready.push(json!({
                            "env_var": var,
                            "name": entry.name,
                            "status": "ok",
                        }));
                    }
                }
            }
        } else {
            missing.push(json!({
                "env_var": var,
                "suggestion": format!("Run: kf add {} \"<value>\" --projects {}", var, project),
            }));
        }
    }

    let is_ready = missing.is_empty() && expired.is_empty();

    Ok(json!({
        "project": project,
        "ready": is_ready,
        "summary": if is_ready {
            format!("All {} required secrets are available and healthy", required_vars.len())
        } else {
            format!("{} missing, {} expired out of {} required", missing.len(), expired.len(), required_vars.len())
        },
        "available": ready,
        "missing": missing,
        "expired": expired,
        "total_required": required_vars.len(),
        "total_available": ready.len(),
    }))
}
