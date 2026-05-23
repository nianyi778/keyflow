//! Typed errors emitted by the secrets service.
//!
//! These exist so callers can branch on the *kind* of failure without
//! string-matching the formatted error message. Anyhow wraps them, and
//! callers downcast via `error.downcast_ref::<SecretError>()`.

use std::fmt;

#[derive(Debug)]
pub enum SecretError {
    /// A secret with this name is already stored for the given scope.
    AlreadyExists {
        name: String,
        /// Free-form context (e.g. the conflicting project).
        detail: String,
    },
    /// No secret matches the requested name (optionally scoped to a project).
    NotFound {
        name: String,
        project: Option<String>,
    },
    /// The filesystem path used for import/scan does not exist.
    PathNotFound { path: String },
    /// A directory was scanned but contained no `.env` files.
    NoEnvFilesFound { path: String },
    /// The provided env var name violates the `[A-Za-z0-9_]` rule.
    InvalidEnvVarName(String),
    /// Env var name was empty.
    EnvVarNameEmpty,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::AlreadyExists { name, detail } => {
                if detail.is_empty() {
                    write!(f, "Secret '{name}' already exists")
                } else {
                    write!(f, "Secret '{name}' already exists: {detail}")
                }
            }
            SecretError::NotFound { name, project } => match project {
                Some(p) => write!(f, "Secret '{name}' not found in project '{p}'"),
                None => write!(f, "Secret '{name}' not found"),
            },
            SecretError::PathNotFound { path } => write!(f, "Path not found: {path}"),
            SecretError::NoEnvFilesFound { path } => {
                write!(f, "No .env files found in '{path}'")
            }
            SecretError::InvalidEnvVarName(name) => write!(
                f,
                "Invalid environment variable name '{name}': only [A-Za-z0-9_] allowed"
            ),
            SecretError::EnvVarNameEmpty => {
                write!(f, "Environment variable name cannot be empty")
            }
        }
    }
}

impl std::error::Error for SecretError {}
