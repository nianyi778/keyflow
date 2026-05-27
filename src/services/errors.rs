//! Typed errors emitted by the secrets service.
//!
//! These exist so callers can branch on the *kind* of failure without
//! string-matching the formatted error message. Anyhow wraps them, and
//! callers downcast via `error.downcast_ref::<SecretError>()`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    /// A secret with this name is already stored for the given scope.
    #[error("Secret '{name}' already exists: {detail}")]
    AlreadyExists { name: String, detail: String },

    /// No secret matches the requested name (optionally scoped to a project).
    #[error("Secret '{name}' not found")]
    NotFound {
        name: String,
        project: Option<String>,
    },

    /// The filesystem path used for import/scan does not exist.
    #[error("Path not found: {path}")]
    PathNotFound { path: String },

    /// A directory was scanned but contained no `.env` files.
    #[error("No .env files found in '{path}'")]
    NoEnvFilesFound { path: String },

    /// The provided env var name violates the `[A-Za-z0-9_]` rule.
    #[error("Invalid environment variable name '{0}': only [A-Za-z0-9_] allowed")]
    InvalidEnvVarName(String),

    /// Env var name was empty.
    #[error("Environment variable name cannot be empty")]
    EnvVarNameEmpty,
}
