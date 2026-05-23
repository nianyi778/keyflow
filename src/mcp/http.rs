use anyhow::{Context, Result};
use base64::Engine;
use rand::Rng;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};

use super::errors::McpProtocolError;

/// Upper bound on an MCP HTTP request body, so a forged Content-Length cannot
/// trigger a huge allocation.
const MAX_HTTP_BODY_BYTES: usize = 8 * 1024 * 1024;

use crate::db::Database;
use crate::services::secrets::SecretService;

use super::prompts::PromptRegistry;
use super::protocol::{classify_anyhow_error, handle_message};
use super::service::VaultService;
use super::tools::ToolRegistry;

pub fn serve_http(db: &Database, host: &str, port: u16) -> Result<()> {
    ensure_safe_bind_host(host)?;
    let token = resolve_http_token();
    let listener = TcpListener::bind((host, port))
        .with_context(|| format!("Failed to bind MCP HTTP server on {host}:{port}"))?;
    let secret_service = SecretService::new_ref(db);
    let service = VaultService::new(&secret_service);
    let prompts = PromptRegistry::new();
    let registry = ToolRegistry::new();

    eprintln!("KeyFlow MCP HTTP transport listening on http://{host}:{port}/mcp");
    eprintln!("Clients must authenticate with header:  Authorization: Bearer {token}");
    eprintln!("(pin this value by setting KEYFLOW_MCP_TOKEN before starting the server)");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(_) => continue,
        };

        if let Err(error) =
            handle_http_connection(&service, &registry, &prompts, &token, &mut stream)
        {
            let _ = write_http_mcp_error(&mut stream, 500, Value::Null, error);
        }
    }

    Ok(())
}

/// Resolve the bearer token required by the MCP HTTP transport. Uses
/// `KEYFLOW_MCP_TOKEN` when set (so the value can be pinned in client config),
/// otherwise generates a fresh random token for this run.
fn resolve_http_token() -> String {
    if let Ok(token) = std::env::var("KEYFLOW_MCP_TOKEN") {
        let token = token.trim();
        if !token.is_empty() {
            return token.to_string();
        }
    }
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes[..]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Length-checked, branch-free byte comparison so token checks don't leak the
/// token via response timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn ensure_safe_bind_host(host: &str) -> Result<()> {
    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return Ok(());
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            return Ok(());
        }
    }

    if std::env::var("KEYFLOW_ALLOW_REMOTE_HTTP")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return Ok(());
    }

    Err(McpProtocolError::BindRejected(format!(
        "Refusing to bind MCP HTTP transport to non-loopback host '{host}'. Use 127.0.0.1, localhost, or ::1. Set KEYFLOW_ALLOW_REMOTE_HTTP=1 to override."
    ))
    .into())
}

fn handle_http_connection(
    service: &VaultService<'_>,
    registry: &ToolRegistry,
    prompts: &PromptRegistry,
    token: &str,
    stream: &mut TcpStream,
) -> Result<()> {
    handle_http_io(service, registry, prompts, token, stream)
}

fn handle_http_io(
    service: &VaultService<'_>,
    registry: &ToolRegistry,
    prompts: &PromptRegistry,
    token: &str,
    stream: &mut (impl Read + Write),
) -> Result<()> {
    let request = read_http_request(stream)?;

    if request.method == "GET" && request.path == "/healthz" {
        return write_http_text(stream, 200, "ok");
    }

    // Reject browser-originated requests outright: the loopback MCP transport
    // is not a browser API, and a present Origin header is a DNS-rebinding
    // signal (per the MCP spec's Origin-validation guidance).
    if request.origin.is_some() {
        return write_http_mcp_error(
            stream,
            403,
            Value::Null,
            McpProtocolError::OriginNotAllowed.into(),
        );
    }

    // Loopback binding does not authenticate the *calling process* — without a
    // token, any local program could read or delete vault secrets.
    let authorized = request
        .authorization
        .as_deref()
        .and_then(|header| header.strip_prefix("Bearer "))
        .map(|presented| constant_time_eq(presented.as_bytes(), token.as_bytes()))
        .unwrap_or(false);
    if !authorized {
        return write_http_mcp_error(
            stream,
            401,
            Value::Null,
            McpProtocolError::InvalidBearerToken.into(),
        );
    }

    if request.method != "POST" {
        return write_http_mcp_error(
            stream,
            405,
            Value::Null,
            McpProtocolError::MethodNotAllowed.into(),
        );
    }
    if request.path != "/mcp" {
        return write_http_mcp_error(
            stream,
            404,
            Value::Null,
            McpProtocolError::HttpNotFound.into(),
        );
    }

    let message: Value = serde_json::from_slice(&request.body)
        .context("Invalid JSON body for MCP HTTP transport")?;

    match handle_message(service, registry, prompts, &message) {
        Some(response) => write_http_json(stream, 200, &response),
        None => write_http_empty(stream, 204),
    }
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    authorization: Option<String>,
    origin: Option<String>,
}

fn read_http_request(stream: &mut impl Read) -> Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut header_text = String::new();
    let mut total_header_bytes = 0usize;

    loop {
        let mut line = String::new();
        let bytes_read = reader
            .read_line(&mut line)
            .context("Failed to read HTTP header line")?;
        if bytes_read == 0 {
            return Err(McpProtocolError::ParseError(
                "Unexpected EOF while reading HTTP headers".to_string(),
            )
            .into());
        }
        total_header_bytes += bytes_read;
        if total_header_bytes > 1024 * 1024 {
            return Err(McpProtocolError::ParseError("HTTP headers too large".to_string()).into());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        header_text.push_str(&line);
    }

    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines
        .next()
        .ok_or_else(|| McpProtocolError::ParseError("Missing HTTP request line".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| McpProtocolError::ParseError("Missing HTTP method".to_string()))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| McpProtocolError::ParseError("Missing HTTP path".to_string()))?
        .to_string();

    let mut content_length = 0usize;
    let mut authorization = None;
    let mut origin = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse::<usize>().map_err(|e| {
                    McpProtocolError::ParseError(format!("Invalid Content-Length header: {e}"))
                })?;
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("origin") {
                origin = Some(value.to_string());
            }
        }
    }

    if content_length > MAX_HTTP_BODY_BYTES {
        return Err(McpProtocolError::MessageTooLarge {
            length: content_length,
            max: MAX_HTTP_BODY_BYTES,
        }
        .into());
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(HttpRequest {
        method,
        path,
        body,
        authorization,
        origin,
    })
}

fn write_http_json(stream: &mut impl Write, status: u16, body: &Value) -> Result<()> {
    let payload = serde_json::to_vec(body)?;
    write_http_response(stream, status, "application/json", &payload)
}

fn write_http_mcp_error(
    stream: &mut impl Write,
    status: u16,
    id: Value,
    error: anyhow::Error,
) -> Result<()> {
    let error = classify_anyhow_error(error);
    write_http_json(
        stream,
        status,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": error.to_json()
        }),
    )
}

fn write_http_text(stream: &mut impl Write, status: u16, body: &str) -> Result<()> {
    write_http_response(stream, status, "text/plain; charset=utf-8", body.as_bytes())
}

fn write_http_empty(stream: &mut impl Write, status: u16) -> Result<()> {
    write_http_response(stream, status, "text/plain; charset=utf-8", &[])
}

fn write_http_response(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::test_helpers::{add_secret, test_db};
    use std::io::Cursor;

    struct TestStream {
        reader: Cursor<Vec<u8>>,
        writer: Vec<u8>,
    }

    impl TestStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                reader: Cursor::new(input),
                writer: Vec::new(),
            }
        }

        fn written_string(&self) -> String {
            String::from_utf8(self.writer.clone()).unwrap()
        }
    }

    impl Read for TestStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reader.read(buf)
        }
    }

    impl Write for TestStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writer.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn http_transport_handles_post_mcp_request() {
        let (_dir, db) = test_db();
        add_secret(
            &db,
            "openai-main",
            "OPENAI_API_KEY",
            "openai",
            &["demo"],
            true,
        );
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);
        let prompts = PromptRegistry::new();
        let registry = ToolRegistry::new();

        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": { "uri": "vault://project/demo" }
        })
        .to_string();
        let raw_request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut stream = TestStream::new(raw_request.into_bytes());
        handle_http_io(&service, &registry, &prompts, "test-token", &mut stream).unwrap();
        let response = stream.written_string();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\\\"project\\\": \\\"demo\\\""));
        assert!(response.contains("\\\"name\\\": \\\"openai-main\\\""));
    }

    #[test]
    fn http_transport_returns_structured_error_body() {
        let (_dir, db) = test_db();
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);
        let prompts = PromptRegistry::new();
        let registry = ToolRegistry::new();

        let raw_request =
            b"GET /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token\r\n\r\n"
                .to_vec();
        let mut stream = TestStream::new(raw_request);
        handle_http_io(&service, &registry, &prompts, "test-token", &mut stream).unwrap();
        let response = stream.written_string();

        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));
        assert!(response.contains("\"jsonrpc\":\"2.0\""));
        assert!(response.contains("\"keyflow_code\":\"http_method_not_allowed\""));
    }

    #[test]
    fn remote_bind_is_rejected_by_default() {
        let err = ensure_safe_bind_host("0.0.0.0").unwrap_err();
        assert!(err.to_string().contains("Refusing to bind"));
    }

    #[test]
    fn loopback_bind_is_allowed() {
        assert!(ensure_safe_bind_host("127.0.0.1").is_ok());
        assert!(ensure_safe_bind_host("localhost").is_ok());
        assert!(ensure_safe_bind_host("::1").is_ok());
    }

    #[test]
    fn http_transport_rejects_missing_token() {
        let (_dir, db) = test_db();
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);
        let prompts = PromptRegistry::new();
        let registry = ToolRegistry::new();

        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }).to_string();
        let raw_request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut stream = TestStream::new(raw_request.into_bytes());
        handle_http_io(&service, &registry, &prompts, "secret-token", &mut stream).unwrap();
        assert!(stream
            .written_string()
            .starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[test]
    fn http_transport_rejects_wrong_token() {
        let (_dir, db) = test_db();
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);
        let prompts = PromptRegistry::new();
        let registry = ToolRegistry::new();

        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }).to_string();
        let raw_request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut stream = TestStream::new(raw_request.into_bytes());
        handle_http_io(&service, &registry, &prompts, "secret-token", &mut stream).unwrap();
        assert!(stream
            .written_string()
            .starts_with("HTTP/1.1 401 Unauthorized"));
    }

    #[test]
    fn http_transport_rejects_browser_origin() {
        let (_dir, db) = test_db();
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);
        let prompts = PromptRegistry::new();
        let registry = ToolRegistry::new();

        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }).to_string();
        let raw_request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nOrigin: http://evil.example\r\nAuthorization: Bearer secret-token\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut stream = TestStream::new(raw_request.into_bytes());
        handle_http_io(&service, &registry, &prompts, "secret-token", &mut stream).unwrap();
        assert!(stream
            .written_string()
            .starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    fn http_transport_rejects_oversized_body() {
        let raw_request = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            MAX_HTTP_BODY_BYTES + 1
        );
        let mut stream = TestStream::new(raw_request.into_bytes());
        let err = read_http_request(&mut stream).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn constant_time_eq_matches_only_equal_slices() {
        assert!(constant_time_eq(b"abc123", b"abc123"));
        assert!(!constant_time_eq(b"abc123", b"abc124"));
        assert!(!constant_time_eq(b"abc", b"abc123"));
    }
}
