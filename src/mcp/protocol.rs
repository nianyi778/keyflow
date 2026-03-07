use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};

use crate::db::Database;

use super::prompts::PromptRegistry;
use super::service::VaultService;
use super::tools::ToolRegistry;

const PROTOCOL_VERSION: &str = "2025-03-26";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageFraming {
    ContentLength,
    LineDelimitedJson,
}

pub fn serve_stdio(db: &Database) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let service = VaultService::new(db);
    let prompts = PromptRegistry::new();
    let registry = ToolRegistry::new();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    while let Some((message, framing)) = read_message(&mut reader)? {
        if let Some(response) = handle_message(&service, &registry, &prompts, &message) {
            write_message(&mut writer, &response, framing)?;
        }
    }

    Ok(())
}

pub(crate) fn handle_message(
    service: &VaultService<'_>,
    registry: &ToolRegistry,
    prompts: &PromptRegistry,
    message: &Value,
) -> Option<Value> {
    let method = message.get("method")?.as_str()?;
    let id = message.get("id").cloned();
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

    if method.starts_with("notifications/") {
        return None;
    }

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {
                    "listChanged": false
                },
                "resources": {
                    "listChanged": false,
                    "subscribe": false
                },
                "prompts": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": "keyflow",
                "version": env!("CARGO_PKG_VERSION")
            }
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": registry.list() })),
        "tools/call" => handle_tool_call(service, registry, &params),
        "resources/list" => service.list_resources().map_err(McpError::from),
        "resources/read" => handle_resource_read(service, &params),
        "prompts/list" => Ok(prompts.list()),
        "prompts/get" => handle_prompt_get(prompts, &params),
        _ => Err(McpError::method_not_found(format!(
            "Method not found: {method}"
        ))),
    };

    let id = id?;
    Some(match result {
        Ok(value) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": value
        }),
        Err(error) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": error.to_json(),
        }),
    })
}

fn handle_tool_call(
    service: &VaultService<'_>,
    registry: &ToolRegistry,
    params: &Value,
) -> std::result::Result<Value, McpError> {
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::invalid_params("Missing tool name"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let result = registry
        .call(tool_name, service, arguments)
        .map_err(McpError::from)?;
    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
        }],
        "structuredContent": result
    }))
}

fn handle_resource_read(
    service: &VaultService<'_>,
    params: &Value,
) -> std::result::Result<Value, McpError> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::invalid_params("Missing resource uri"))?;
    service.read_resource(uri).map_err(McpError::from)
}

fn handle_prompt_get(
    prompts: &PromptRegistry,
    params: &Value,
) -> std::result::Result<Value, McpError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::invalid_params("Missing prompt name"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    prompts.get(name, &arguments).map_err(McpError::from)
}

fn read_message(reader: &mut impl BufRead) -> Result<Option<(Value, MessageFraming)>> {
    let mut content_length = None;

    loop {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Ok(None);
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if content_length.is_none() && trimmed.starts_with('{') {
            return Ok(Some((
                serde_json::from_str(trimmed)?,
                MessageFraming::LineDelimitedJson,
            )));
        }
        if trimmed.is_empty() {
            break;
        }

        let Some((name, value)) = trimmed.split_once(':') else {
            return Ok(Some((
                serde_json::from_str(trimmed)?,
                MessageFraming::LineDelimitedJson,
            )));
        };

        if name.trim().eq_ignore_ascii_case("Content-Length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| anyhow!("Invalid Content-Length header: {e}"))?,
            );
        }
    }

    let length = content_length.ok_or_else(|| anyhow!("Missing Content-Length header"))?;
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    Ok(Some((
        serde_json::from_slice(&body)?,
        MessageFraming::ContentLength,
    )))
}

fn write_message(writer: &mut impl Write, message: &Value, framing: MessageFraming) -> Result<()> {
    let body = serde_json::to_string(message)?;
    match framing {
        MessageFraming::ContentLength => {
            write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body)?;
        }
        MessageFraming::LineDelimitedJson => {
            writeln!(writer, "{body}")?;
        }
    }
    writer.flush()?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct McpError {
    code: i64,
    message: String,
    keyflow_code: &'static str,
    hint: Option<String>,
}

impl McpError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
            keyflow_code: "invalid_params",
            hint: None,
        }
    }

    fn method_not_found(message: impl Into<String>) -> Self {
        Self {
            code: -32601,
            message: message.into(),
            keyflow_code: "method_not_found",
            hint: None,
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        let mut value = json!({
            "code": self.code,
            "message": self.message,
            "data": {
                "keyflow_code": self.keyflow_code
            }
        });
        if let Some(hint) = &self.hint {
            value["data"]["hint"] = json!(hint);
        }
        value
    }
}

impl From<anyhow::Error> for McpError {
    fn from(value: anyhow::Error) -> Self {
        classify_anyhow_error(value)
    }
}

pub(crate) fn classify_anyhow_error(value: anyhow::Error) -> McpError {
    let message = value.to_string();

    if message.contains("Missing tool name")
        || message.contains("Missing resource uri")
        || message.contains("Missing prompt name")
        || message.contains("Missing required prompt argument")
        || message.contains("must be specified")
        || message.contains("Invalid environment variable name")
        || message.contains("Environment variable name cannot be empty")
    {
        return McpError {
            code: -32602,
            message,
            keyflow_code: "invalid_params",
            hint: Some(
                "Check the MCP input arguments against the tool, resource, or prompt schema."
                    .to_string(),
            ),
        };
    }

    if message.contains("Unknown resource URI") {
        return McpError {
            code: -32001,
            message,
            keyflow_code: "resource_not_found",
            hint: Some(
                "Call resources/list first, then use one of the advertised URIs.".to_string(),
            ),
        };
    }

    if message.contains("Unknown prompt:") {
        return McpError {
            code: -32001,
            message,
            keyflow_code: "prompt_not_found",
            hint: Some(
                "Call prompts/list first, then request one of the advertised prompt names."
                    .to_string(),
            ),
        };
    }

    if message.contains("Unknown tool:") {
        return McpError {
            code: -32001,
            message,
            keyflow_code: "tool_not_found",
            hint: Some(
                "Call tools/list first, then use one of the advertised tool names.".to_string(),
            ),
        };
    }

    if message == "Method not allowed. Use POST /mcp." {
        return McpError {
            code: -32004,
            message,
            keyflow_code: "http_method_not_allowed",
            hint: Some(
                "Use POST /mcp for JSON-RPC requests. GET is only supported on /healthz."
                    .to_string(),
            ),
        };
    }

    if message == "Not found" {
        return McpError {
            code: -32001,
            message,
            keyflow_code: "http_not_found",
            hint: Some(
                "Use POST /mcp for MCP requests or GET /healthz for liveness checks.".to_string(),
            ),
        };
    }

    if message.contains("not found") {
        return McpError {
            code: -32001,
            message,
            keyflow_code: "not_found",
            hint: Some(
                "Verify the requested secret, project, provider, or resource exists.".to_string(),
            ),
        };
    }

    if message.contains("Refusing to bind MCP HTTP transport") {
        return McpError {
            code: -32003,
            message,
            keyflow_code: "http_bind_rejected",
            hint: Some("Bind HTTP MCP to 127.0.0.1, localhost, or ::1. Set KEYFLOW_ALLOW_REMOTE_HTTP=1 only if you understand the exposure risk.".to_string()),
        };
    }

    if message.contains("Invalid JSON body")
        || message.contains("Missing HTTP request line")
        || message.contains("Missing HTTP method")
        || message.contains("Missing HTTP path")
        || message.contains("Invalid Content-Length header")
        || message.contains("Missing Content-Length header")
    {
        return McpError {
            code: -32700,
            message,
            keyflow_code: "parse_error",
            hint: Some(
                "Send a valid JSON-RPC request body and required HTTP or stdio framing headers."
                    .to_string(),
            ),
        };
    }

    McpError {
        code: -32000,
        message,
        keyflow_code: "internal_error",
        hint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;
    use crate::models::SecretEntry;
    use std::io::Cursor;
    use tempfile::tempdir;

    fn test_db() -> (tempfile::TempDir, Database) {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("keyflow.sqlite");
        let crypto = Crypto::new("pass123", b"01234567890123456789012345678901").unwrap();
        let db = Database::open(db_path.to_str().unwrap(), crypto).unwrap();
        (dir, db)
    }

    fn add_secret(db: &Database, name: &str, env_var: &str, provider: &str, projects: &[&str]) {
        let now = chrono::Utc::now();
        let entry = SecretEntry {
            id: format!("test-{name}"),
            name: name.to_string(),
            env_var: env_var.to_string(),
            provider: provider.to_string(),
            account_name: "acct".to_string(),
            org_name: String::new(),
            description: format!("desc {name}"),
            source: "manual:test".to_string(),
            environment: String::new(),
            permission_profile: String::new(),
            scopes: vec![],
            projects: projects.iter().map(|value| value.to_string()).collect(),
            apply_url: String::new(),
            expires_at: None,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            last_verified_at: Some(now),
            is_active: true,
        };
        db.add_secret(&entry, "secret-value").unwrap();
    }

    #[test]
    fn read_message_accepts_lowercase_content_length() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let raw = format!(
            "content-length: {}\r\ncontent-type: application/json\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let mut reader = Cursor::new(raw.into_bytes());
        let (message, framing) = read_message(&mut reader).unwrap().unwrap();
        assert_eq!(message["method"], "initialize");
        assert_eq!(framing, MessageFraming::ContentLength);
    }

    #[test]
    fn read_message_rejects_missing_content_length() {
        let raw = b"content-type: application/json\r\n\r\n{}";
        let mut reader = Cursor::new(raw.as_slice());
        let err = read_message(&mut reader).unwrap_err();
        assert!(err.to_string().contains("Missing Content-Length"));
    }

    #[test]
    fn read_message_accepts_line_delimited_json() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#;
        let mut reader = Cursor::new([raw.as_slice(), b"\n"].concat());
        let (message, framing) = read_message(&mut reader).unwrap().unwrap();
        assert_eq!(message["method"], "initialize");
        assert_eq!(message["params"]["protocolVersion"], "2025-11-25");
        assert_eq!(framing, MessageFraming::LineDelimitedJson);
    }

    #[test]
    fn write_message_uses_line_delimited_json_when_requested() {
        let message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        let mut out = Vec::new();
        write_message(&mut out, &message, MessageFraming::LineDelimitedJson).unwrap();
        let rendered = String::from_utf8(out).unwrap();
        assert_eq!(rendered, "{\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{}}\n");
    }

    #[test]
    fn initialize_advertises_resource_capability() {
        let (_dir, db) = test_db();
        let service = VaultService::new(&db);
        let registry = ToolRegistry::new();
        let prompts = PromptRegistry::new();
        let message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });

        let response = handle_message(&service, &registry, &prompts, &message).unwrap();
        assert_eq!(
            response["result"]["capabilities"]["resources"]["listChanged"],
            false
        );
        assert_eq!(
            response["result"]["capabilities"]["resources"]["subscribe"],
            false
        );
        assert_eq!(
            response["result"]["capabilities"]["prompts"]["listChanged"],
            false
        );
    }

    #[test]
    fn resources_list_and_read_project_snapshot() {
        let (_dir, db) = test_db();
        add_secret(&db, "openai-main", "OPENAI_API_KEY", "openai", &["demo"]);
        let service = VaultService::new(&db);
        let registry = ToolRegistry::new();
        let prompts = PromptRegistry::new();

        let list_message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        });
        let list_response = handle_message(&service, &registry, &prompts, &list_message).unwrap();
        let resources = list_response["result"]["resources"].as_array().unwrap();
        assert!(resources
            .iter()
            .any(|item| item["uri"] == "vault://summary"));
        assert!(resources
            .iter()
            .any(|item| item["uri"] == "vault://current-project"));
        assert!(resources.iter().any(|item| item["uri"] == "vault://health"));
        assert!(resources
            .iter()
            .any(|item| item["uri"] == "vault://provider/openai"));
        assert!(resources
            .iter()
            .any(|item| item["uri"] == "vault://project/demo"));

        let read_message = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": { "uri": "vault://project/demo" }
        });
        let read_response = handle_message(&service, &registry, &prompts, &read_message).unwrap();
        let text = read_response["result"]["contents"][0]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("\"project\": \"demo\""));
        assert!(text.contains("\"name\": \"openai-main\""));

        let provider_read_message = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": { "uri": "vault://provider/openai" }
        });
        let provider_read_response =
            handle_message(&service, &registry, &prompts, &provider_read_message).unwrap();
        let provider_text = provider_read_response["result"]["contents"][0]["text"]
            .as_str()
            .unwrap();
        assert!(provider_text.contains("\"provider\": \"openai\""));
        assert!(provider_text.contains("\"health\""));
    }

    #[test]
    fn prompts_list_and_get_work() {
        let (_dir, db) = test_db();
        let service = VaultService::new(&db);
        let registry = ToolRegistry::new();
        let prompts = PromptRegistry::new();

        let list_message = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "prompts/list",
            "params": {}
        });
        let list_response = handle_message(&service, &registry, &prompts, &list_message).unwrap();
        let items = list_response["result"]["prompts"].as_array().unwrap();
        assert!(items.iter().any(|item| item["name"] == "vault_audit"));
        assert!(items
            .iter()
            .any(|item| item["name"] == "project_secret_plan"));

        let get_message = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "prompts/get",
            "params": {
                "name": "provider_governance",
                "arguments": { "provider": "openai" }
            }
        });
        let get_response = handle_message(&service, &registry, &prompts, &get_message).unwrap();
        let text = get_response["result"]["messages"][0]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("vault://provider/openai"));
        assert!(text.contains("vault://providers"));
    }

    #[test]
    fn protocol_errors_include_keyflow_code_and_hint() {
        let (_dir, db) = test_db();
        let service = VaultService::new(&db);
        let registry = ToolRegistry::new();
        let prompts = PromptRegistry::new();

        let missing_prompt_arg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "prompts/get",
            "params": {
                "name": "provider_governance",
                "arguments": {}
            }
        });
        let response = handle_message(&service, &registry, &prompts, &missing_prompt_arg).unwrap();
        assert_eq!(response["error"]["data"]["keyflow_code"], "invalid_params");
        assert!(response["error"]["data"]["hint"].is_string());

        let missing_tool = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "does_not_exist",
                "arguments": {}
            }
        });
        let response = handle_message(&service, &registry, &prompts, &missing_tool).unwrap();
        assert_eq!(response["error"]["data"]["keyflow_code"], "tool_not_found");
    }
}
