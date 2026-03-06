use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};

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
        "search_keys" => tool_search_keys(db, &arguments)?,
        "get_key_info" => tool_get_key_info(db, &arguments)?,
        "list_providers" => tool_list_providers(db)?,
        "list_projects" => tool_list_projects(db)?,
        "check_health" => tool_check_health(db)?,
        "list_keys_for_project" => tool_list_keys_for_project(db, &arguments)?,
        _ => return Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&result)?
        }]
    }))
}

fn secret_to_metadata(entry: &crate::models::SecretEntry) -> Value {
    json!({
        "name": entry.name,
        "env_var": entry.env_var,
        "provider": entry.provider,
        "description": entry.description,
        "scopes": entry.scopes,
        "projects": entry.projects,
        "apply_url": entry.apply_url,
        "status": entry.status().to_string(),
        "expires_at": entry.expires_at.map(|d| d.to_rfc3339()),
        "last_used_at": entry.last_used_at.map(|d| d.to_rfc3339()),
        "usage_hint": format!("Use via environment variable: {}", entry.env_var),
    })
}

fn tool_search_keys(db: &Database, args: &Value) -> Result<Value> {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'query' argument"))?;

    let entries = db.search_secrets(query)?;
    let results: Vec<Value> = entries.iter().map(secret_to_metadata).collect();
    Ok(json!({
        "found": !results.is_empty(),
        "count": results.len(),
        "keys": results
    }))
}

fn tool_get_key_info(db: &Database, args: &Value) -> Result<Value> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'name' argument"))?;

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
        .map(|(name, count)| {
            json!({
                "provider": name,
                "key_count": count
            })
        })
        .collect();
    Ok(json!({ "providers": result }))
}

fn tool_list_projects(db: &Database) -> Result<Value> {
    let entries = db.list_secrets(&ListFilter::default())?;
    let mut projects: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for entry in &entries {
        for proj in &entry.projects {
            projects
                .entry(proj.clone())
                .or_default()
                .push(entry.name.clone());
        }
    }
    let result: Vec<Value> = projects
        .iter()
        .map(|(name, keys)| {
            json!({
                "project": name,
                "keys": keys
            })
        })
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
    let project = args
        .get("project")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'project' argument"))?;

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
