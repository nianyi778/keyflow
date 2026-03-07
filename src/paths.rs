use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn data_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("KEYFLOW_DATA_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    let base = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .or_else(dirs::home_dir)
        .context("Cannot find local data directory")?;

    if base == dirs::home_dir().unwrap_or_default() {
        return Ok(base.join(".keyflow"));
    }

    Ok(base.join("keyflow"))
}
