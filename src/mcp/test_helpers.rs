#![cfg(test)]

use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::SecretEntry;
use chrono::Utc;
use tempfile::tempdir;

pub fn test_db() -> (tempfile::TempDir, Database) {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("keyflow.sqlite");
    let crypto = Crypto::new("pass123", b"01234567890123456789012345678901").unwrap();
    let db = Database::open(db_path.to_str().unwrap(), crypto).unwrap();
    (dir, db)
}

pub fn add_secret(
    db: &Database,
    name: &str,
    env_var: &str,
    provider: &str,
    projects: &[&str],
    active: bool,
) {
    let now = Utc::now();
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
        is_active: active,
    };
    db.add_secret(&entry, "secret-value").unwrap();
}
