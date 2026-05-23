//! Typed errors emitted by the MCP transport/protocol layer.
//!
//! These exist so `classify_anyhow_error` can branch on the *kind* of failure
//! without string-matching the formatted error message. Each variant maps to
//! a specific JSON-RPC error code and KeyFlow-specific `keyflow_code`.

use std::fmt;

#[derive(Debug)]
pub enum McpProtocolError {
    /// A required argument was missing from a tool/resource/prompt call.
    MissingArgument(&'static str),
    /// The client requested a resource URI we do not serve.
    UnknownResourceUri(String),
    /// The client requested an unknown prompt name.
    UnknownPrompt(String),
    /// The client requested an unknown tool name.
    UnknownTool(String),
    /// The HTTP transport received a non-POST request to /mcp.
    MethodNotAllowed,
    /// The HTTP transport received a request for an unknown path.
    HttpNotFound,
    /// `kf serve --transport http` refused to bind to the requested host.
    BindRejected(String),
    /// The MCP HTTP transport saw an `Origin` header (possible DNS rebinding).
    OriginNotAllowed,
    /// The MCP HTTP request was missing or had an invalid bearer token.
    InvalidBearerToken,
    /// A JSON-RPC or HTTP framing parse failure.
    ParseError(String),
    /// The peer advertised a `Content-Length` larger than the message cap.
    MessageTooLarge { length: usize, max: usize },
}

impl fmt::Display for McpProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            McpProtocolError::MissingArgument(name) => write!(f, "Missing {name}"),
            McpProtocolError::UnknownResourceUri(uri) => write!(f, "Unknown resource URI: {uri}"),
            McpProtocolError::UnknownPrompt(name) => write!(f, "Unknown prompt: {name}"),
            McpProtocolError::UnknownTool(name) => write!(f, "Unknown tool: {name}"),
            McpProtocolError::MethodNotAllowed => {
                write!(f, "Method not allowed. Use POST /mcp.")
            }
            McpProtocolError::HttpNotFound => write!(f, "Not found"),
            McpProtocolError::BindRejected(detail) => write!(f, "{detail}"),
            McpProtocolError::OriginNotAllowed => {
                write!(f, "Origin header is not allowed on the MCP HTTP transport")
            }
            McpProtocolError::InvalidBearerToken => {
                write!(f, "Missing or invalid bearer token")
            }
            McpProtocolError::ParseError(detail) => write!(f, "{detail}"),
            McpProtocolError::MessageTooLarge { length, max } => {
                write!(f, "Message too large ({length} bytes; max is {max} bytes)")
            }
        }
    }
}

impl std::error::Error for McpProtocolError {}
