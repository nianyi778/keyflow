use chrono::{Duration, Utc};
use keyflow::crypto::Crypto;
use keyflow::db::{Database, MetadataUpdate};
use keyflow::models::SecretEntry;
use keyflow::services::secrets::{ImportRequest, SecretDraft, SecretService};
use tempfile::tempdir;

fn temp_service() -> (tempfile::TempDir, SecretService<'static>) {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("keyflow.sqlite");
    let crypto = Crypto::new("pass123", b"01234567890123456789012345678901").unwrap();
    let db = Database::open(db_path.to_str().unwrap(), crypto).unwrap();
    (dir, SecretService::new(db))
}

fn draft(env_var: &str, value: &str, provider: &str, projects: &[&str]) -> SecretDraft {
    SecretDraft {
        env_var: env_var.to_string(),
        value: value.to_string(),
        provider: provider.to_string(),
        account_name: "acct".to_string(),
        org_name: String::new(),
        description: format!("Secret for {env_var}"),
        source: "manual:test".to_string(),
        environment: String::new(),
        permission_profile: String::new(),
        scopes: vec![],
        projects: projects.iter().map(|value| value.to_string()).collect(),
        apply_url: format!("https://example.com/{provider}"),
        expires_at: None,
    }
}

fn make_entry(name: &str, env_var: &str, provider: &str, projects: &[&str]) -> SecretEntry {
    let now = Utc::now();
    SecretEntry {
        id: format!("test-{name}"),
        name: name.to_string(),
        env_var: env_var.to_string(),
        provider: provider.to_string(),
        account_name: "acct".to_string(),
        org_name: String::new(),
        description: format!("Secret for {env_var}"),
        source: "manual:test".to_string(),
        environment: String::new(),
        permission_profile: String::new(),
        scopes: vec![],
        projects: projects.iter().map(|value| value.to_string()).collect(),
        apply_url: format!("https://example.com/{provider}"),
        expires_at: None,
        created_at: now,
        updated_at: now,
        last_used_at: None,
        last_verified_at: Some(now),
        is_active: true,
    }
}

#[test]
fn health_view_returns_structured_buckets() {
    let (_dir, service) = temp_service();

    let expired = service
        .create_secret(draft("OPENAI_API_KEY", "sk-expired", "openai", &["demo"]))
        .unwrap();
    let expiring = service
        .create_secret(draft("OPENAI_ALT_KEY", "sk-expiring", "openai", &["demo"]))
        .unwrap();
    let duplicate = make_entry(
        "openai-api-key-shadow",
        "OPENAI_API_KEY",
        "openai",
        &["demo"],
    );
    let inactive = service
        .create_secret(draft("GITHUB_TOKEN", "ghp-inactive", "github", &[]))
        .unwrap();
    service.db().add_secret(&duplicate, "sk-duplicate").unwrap();

    service
        .db()
        .update_secret_metadata(
            &expired.id,
            &MetadataUpdate {
                expires_at: Some(Some(Utc::now() - Duration::days(1))),
                last_verified_at: Some(Some(Utc::now() - Duration::days(120))),
                ..Default::default()
            },
        )
        .unwrap();
    service
        .db()
        .update_secret_metadata(
            &expiring.id,
            &MetadataUpdate {
                expires_at: Some(Some(Utc::now() + Duration::days(3))),
                last_verified_at: Some(Some(Utc::now() - Duration::days(45))),
                ..Default::default()
            },
        )
        .unwrap();
    service
        .db()
        .update_secret_metadata(
            &duplicate.id,
            &MetadataUpdate {
                last_verified_at: Some(Some(Utc::now() - Duration::days(75))),
                ..Default::default()
            },
        )
        .unwrap();
    service
        .db()
        .update_secret_metadata(
            &inactive.id,
            &MetadataUpdate {
                is_active: Some(false),
                last_verified_at: Some(Some(Utc::now() - Duration::days(100))),
                ..Default::default()
            },
        )
        .unwrap();

    let health = service.health_view().unwrap();

    assert_eq!(health.summary.total, 4);
    assert_eq!(health.expired.len(), 1);
    assert_eq!(health.expiring.len(), 1);
    assert_eq!(health.duplicates.len(), 1);
    assert_eq!(health.inactive, vec![inactive.name]);
    assert_eq!(health.unverified_30, vec![expiring.name]);
    assert_eq!(health.unverified_60, vec![duplicate.name]);
    assert_eq!(health.unverified_90, vec![expired.name]);
    assert_eq!(health.summary.expiry_issues, 2);
    assert!(health.summary.metadata_review_count >= 1);
}

#[test]
fn import_export_and_run_resolution_follow_project_scope() {
    let (dir, service) = temp_service();
    let project_dir = dir.path().join("demo-app");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(
        project_dir.join("package.json"),
        r#"{ "name": "demo-app" }"#,
    )
    .unwrap();
    std::fs::write(
        project_dir.join(".env"),
        "OPENAI_API_KEY=sk-demo\nGITHUB_TOKEN=ghp-demo\n",
    )
    .unwrap();

    let stats = service
        .import_path(ImportRequest {
            path: &project_dir,
            provider: "imported",
            account_name: "acct",
            project_override: None,
            source: Some("import:test"),
            on_conflict: "skip",
            recursive: false,
        })
        .unwrap();
    assert_eq!(stats.imported, 2);

    let (entries, content) = service
        .export_project_env(Some("demo-app".to_string()), None)
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert!(content.contains("OPENAI_API_KEY=sk-demo"));
    assert!(content.contains("GITHUB_TOKEN=ghp-demo"));

    let resolution = service
        .resolve_run_env_pairs(None, false, Some("demo-app".to_string()))
        .unwrap();
    assert_eq!(resolution.project.as_deref(), Some("demo-app"));
    assert_eq!(resolution.env_pairs.len(), 2);
    assert!(resolution
        .env_pairs
        .iter()
        .any(|(key, value)| key == "OPENAI_API_KEY" && value == "sk-demo"));
    assert!(resolution
        .env_pairs
        .iter()
        .any(|(key, value)| key == "GITHUB_TOKEN" && value == "ghp-demo"));
}

#[test]
fn create_secret_persists_and_returns_plain_metadata() {
    let (_dir, service) = temp_service();
    let entry = service
        .create_secret(draft(
            "ANTHROPIC_API_KEY",
            "sk-ant",
            "anthropic",
            &["agent"],
        ))
        .unwrap();

    let loaded: SecretEntry = service.get_entry_by_id(&entry.id).unwrap();
    let value = service.get_secret_value(&entry.id).unwrap();

    assert_eq!(loaded.env_var, "ANTHROPIC_API_KEY");
    assert_eq!(loaded.projects, vec!["agent".to_string()]);
    assert_eq!(value, "sk-ant");
}

#[test]
fn test_duplicate_name_different_projects() {
    let (_dir, service) = temp_service();

    service.create_secret(draft("DATABASE_URL", "postgres://clipverse:5432", "custom", &["clipverse"])).unwrap();

    // Should succeed — same name, different project
    let result = service.create_secret(draft("DATABASE_URL", "postgres://starflix:5432", "custom", &["starflix"]));
    assert!(result.is_ok(), "Should allow same env_var for different projects");

    // Should fail — same name, overlapping project
    let result = service.create_secret(draft("DATABASE_URL", "postgres://other:5432", "custom", &["clipverse"]));
    assert!(result.is_err(), "Should reject same env_var for same project");
}
