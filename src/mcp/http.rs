use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};

use crate::db::Database;

use super::prompts::PromptRegistry;
use super::protocol::{classify_anyhow_error, handle_message};
use super::service::VaultService;
use super::tools::ToolRegistry;

pub fn serve_http(db: &Database, host: &str, port: u16) -> Result<()> {
    ensure_safe_bind_host(host)?;
    let listener = TcpListener::bind((host, port))
        .with_context(|| format!("Failed to bind MCP HTTP server on {host}:{port}"))?;
    let service = VaultService::new(db);
    let prompts = PromptRegistry::new();
    let registry = ToolRegistry::new();

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(_) => continue,
        };

        if let Err(error) = handle_http_connection(&service, &registry, &prompts, &mut stream) {
            let _ = write_http_mcp_error(&mut stream, 500, Value::Null, error);
        }
    }

    Ok(())
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

    bail!(
        "Refusing to bind MCP HTTP transport to non-loopback host '{}'. Use 127.0.0.1, localhost, or ::1. Set KEYFLOW_ALLOW_REMOTE_HTTP=1 to override.",
        host
    )
}

fn handle_http_connection(
    service: &VaultService<'_>,
    registry: &ToolRegistry,
    prompts: &PromptRegistry,
    stream: &mut TcpStream,
) -> Result<()> {
    handle_http_io(service, registry, prompts, stream)
}

fn handle_http_io(
    service: &VaultService<'_>,
    registry: &ToolRegistry,
    prompts: &PromptRegistry,
    stream: &mut (impl Read + Write),
) -> Result<()> {
    let request = read_http_request(stream)?;

    if request.method == "GET" && request.path == "/healthz" {
        return write_http_text(stream, 200, "ok");
    }

    if request.method != "POST" {
        return write_http_mcp_error(
            stream,
            405,
            Value::Null,
            anyhow!("Method not allowed. Use POST /mcp."),
        );
    }
    if request.path != "/mcp" {
        return write_http_mcp_error(stream, 404, Value::Null, anyhow!("Not found"));
    }

    let message: Value = serde_json::from_slice(&request.body)
        .context("Invalid JSON body for MCP HTTP transport")?;

    match handle_message(service, registry, prompts, &message) {
        Some(response) => write_http_json(stream, 200, &response),
        None => write_http_empty(stream, 204),
    }
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
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
            bail!("Unexpected EOF while reading HTTP headers");
        }
        total_header_bytes += bytes_read;
        if total_header_bytes > 1024 * 1024 {
            bail!("HTTP headers too large");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        header_text.push_str(&line);
    }

    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("Missing HTTP request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("Missing HTTP method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow!("Missing HTTP path"))?
        .to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .context("Invalid Content-Length header")?;
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(HttpRequest { method, path, body })
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
        let service = VaultService::new(&db);
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
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut stream = TestStream::new(raw_request.into_bytes());
        handle_http_io(&service, &registry, &prompts, &mut stream).unwrap();
        let response = stream.written_string();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\\\"project\\\": \\\"demo\\\""));
        assert!(response.contains("\\\"name\\\": \\\"openai-main\\\""));
    }

    #[test]
    fn http_transport_returns_structured_error_body() {
        let (_dir, db) = test_db();
        let service = VaultService::new(&db);
        let prompts = PromptRegistry::new();
        let registry = ToolRegistry::new();

        let raw_request = b"GET /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
        let mut stream = TestStream::new(raw_request);
        handle_http_io(&service, &registry, &prompts, &mut stream).unwrap();
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
}
