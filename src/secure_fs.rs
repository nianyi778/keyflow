//! Helpers for creating and permissioning files that hold secrets.
//!
//! KeyFlow stores encrypted secrets and auth tokens on disk. SQLite and
//! `std::fs::write` create files using the process umask (commonly `0644`,
//! i.e. world-readable), so these helpers tighten such files to owner-only
//! `0600` on Unix. On non-Unix platforms the permission step is a no-op.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Restrict an existing file to owner-only read/write (`0600`) on Unix.
///
/// No-op if the file does not exist (e.g. an absent WAL sidecar) or on
/// non-Unix platforms.
pub fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("Failed to restrict permissions on {}", path.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Write `contents` to `path`, creating the file with owner-only permissions
/// (`0600`) on Unix and tightening permissions even if the file already
/// existed with a looser mode.
pub fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to open {} for writing", path.display()))?;
        file.write_all(contents.as_ref())
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents.as_ref())
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }
    // Tighten perms even if the file pre-existed with a looser mode.
    restrict_file(path)
}

/// Like [`write_private`], but atomic: the contents are written to a temp file
/// in the same directory and then renamed over `path`. A reader — or a crash —
/// never observes a partially written file; `path` ends up either fully
/// updated or untouched.
pub fn write_private_atomic(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => Path::new(".").to_path_buf(),
    };
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyflow-file".to_string());
    let tmp = parent.join(format!(".{file_name}.tmp"));
    write_private(&tmp, contents)?;
    fs::rename(&tmp, path)
        .with_context(|| format!("Failed to atomically replace {}", path.display()))?;
    Ok(())
}
