use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("keyflow-{test_name}-{nanos}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_kf(home: &Path, args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_kf");
    Command::new(bin)
        .args(args)
        .env("HOME", home)
        .env("KEYFLOW_PASSPHRASE", "pass123")
        .output()
        .unwrap()
}

fn run_kf_in_dir(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_kf");
    Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("KEYFLOW_PASSPHRASE", "pass123")
        .output()
        .unwrap()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn data_dir_for_home(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support/keyflow")
    }
    #[cfg(target_os = "linux")]
    {
        home.join(".local/share/keyflow")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        home.join(".keyflow")
    }
}

#[test]
fn cli_main_flow_init_add_get_export_import_backup_restore() {
    let root = temp_root("main-flow");
    let home = root.join("home");
    let restore_home = root.join("restore-home");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&restore_home).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let add = run_kf(
        &home,
        &[
            "add",
            "OPENAI_API_KEY",
            "sk-test-value",
            "--provider",
            "openai",
            "--projects",
            "demo",
        ],
    );
    assert!(
        add.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let get = run_kf(&home, &["get", "openai-api-key", "--raw"]);
    assert!(
        get.status.success(),
        "get failed: {}",
        String::from_utf8_lossy(&get.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&get.stdout), "sk-test-value");

    let export_path = root.join("demo.env");
    let export = run_kf(
        &home,
        &[
            "export",
            "--project",
            "demo",
            "--output",
            export_path.to_str().unwrap(),
        ],
    );
    assert!(
        export.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let exported = fs::read_to_string(&export_path).unwrap();
    assert!(exported.contains("OPENAI_API_KEY=sk-test-value"));

    let backup_path = root.join("backup.enc");
    let backup = run_kf(
        &home,
        &["backup", "--output", backup_path.to_str().unwrap()],
    );
    assert!(
        backup.status.success(),
        "backup failed: {}",
        String::from_utf8_lossy(&backup.stderr)
    );
    let backup_json = fs::read_to_string(&backup_path).unwrap();
    assert!(backup_json.contains("\"salt\""));
    assert!(backup_json.contains("\"ciphertext\""));

    let restore_init = run_kf(&restore_home, &["init", "--passphrase", "pass123"]);
    assert!(
        restore_init.status.success(),
        "restore init failed: {}",
        String::from_utf8_lossy(&restore_init.stderr)
    );

    let restore = run_kf(
        &restore_home,
        &[
            "restore",
            backup_path.to_str().unwrap(),
            "--passphrase",
            "pass123",
        ],
    );
    assert!(
        restore.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );

    let restored_get = run_kf(&restore_home, &["get", "openai-api-key", "--raw"]);
    assert!(
        restored_get.status.success(),
        "restored get failed: {}",
        String::from_utf8_lossy(&restored_get.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&restored_get.stdout),
        "sk-test-value"
    );

    let import_env = root.join("import.env");
    fs::write(&import_env, "GITHUB_TOKEN=ghp_test_token\n").unwrap();
    let import = run_kf(
        &restore_home,
        &[
            "import",
            import_env.to_str().unwrap(),
            "--provider",
            "github",
            "--project",
            "demo",
        ],
    );
    assert!(
        import.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let list = run_kf(&restore_home, &["list", "--project", "demo", "--inactive"]);
    assert!(
        list.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(list_stdout.contains("openai-api-key"));
    assert!(list_stdout.contains("github-token"));
}

#[test]
fn backup_restore_survives_passphrase_rotation() {
    let root = temp_root("backup-rotation");
    let home = root.join("home");
    let restore_home = root.join("restore-home");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&restore_home).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let add = run_kf(
        &home,
        &[
            "add",
            "STRIPE_SECRET_KEY",
            "sk_live_rotated",
            "--provider",
            "stripe",
            "--projects",
            "billing",
        ],
    );
    assert!(
        add.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let backup_path = root.join("pre-rotate-backup.enc");
    let backup = run_kf(
        &home,
        &["backup", "--output", backup_path.to_str().unwrap()],
    );
    assert!(
        backup.status.success(),
        "backup failed: {}",
        String::from_utf8_lossy(&backup.stderr)
    );

    let rotate = Command::new(env!("CARGO_BIN_EXE_kf"))
        .args(["passwd", "--old", "pass123", "--new", "pass456"])
        .env("HOME", &home)
        .env("KEYFLOW_PASSPHRASE", "pass123")
        .output()
        .unwrap();
    assert!(
        rotate.status.success(),
        "passwd failed: {}",
        String::from_utf8_lossy(&rotate.stderr)
    );

    let restore_init = Command::new(env!("CARGO_BIN_EXE_kf"))
        .args(["init", "--passphrase", "pass123"])
        .env("HOME", &restore_home)
        .env("KEYFLOW_PASSPHRASE", "pass123")
        .output()
        .unwrap();
    assert!(
        restore_init.status.success(),
        "restore init failed: {}",
        String::from_utf8_lossy(&restore_init.stderr)
    );

    let restore = Command::new(env!("CARGO_BIN_EXE_kf"))
        .args([
            "restore",
            backup_path.to_str().unwrap(),
            "--passphrase",
            "pass123",
        ])
        .env("HOME", &restore_home)
        .env("KEYFLOW_PASSPHRASE", "pass123")
        .output()
        .unwrap();
    assert!(
        restore.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );

    let restored_get = Command::new(env!("CARGO_BIN_EXE_kf"))
        .args(["get", "stripe-secret-key", "--raw"])
        .env("HOME", &restore_home)
        .env("KEYFLOW_PASSPHRASE", "pass123")
        .output()
        .unwrap();
    assert!(
        restored_get.status.success(),
        "restored get failed: {}",
        String::from_utf8_lossy(&restored_get.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&restored_get.stdout),
        "sk_live_rotated"
    );
}

#[test]
fn setup_codex_writes_mcp_config() {
    let root = temp_root("setup-codex");
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let setup = run_kf(&home, &["setup", "codex"]);
    assert!(
        setup.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&setup.stderr)
    );

    let config_path = home.join(".codex/config.toml");
    let config = fs::read_to_string(&config_path).unwrap();
    assert!(config.contains("[mcp_servers.keyflow]"));
    assert!(config.contains("args = [\"serve\"]"));
    assert!(config.contains("[mcp_servers.keyflow.env]"));
    assert!(config.contains("KEYFLOW_DATA_DIR"));
    assert!(!config.contains("KEYFLOW_PASSPHRASE"));
    assert!(data_dir_for_home(&home).join(".passphrase").exists());
}

#[test]
fn setup_claude_writes_mcp_config_and_directory_access() {
    let root = temp_root("setup-claude");
    let home = root.join("home");
    fs::create_dir_all(home.join(".claude")).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let setup = run_kf(&home, &["setup", "claude"]);
    assert!(
        setup.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&setup.stderr)
    );

    let config = fs::read_to_string(home.join(".claude.json")).unwrap();
    assert!(config.contains("\"mcpServers\""));
    assert!(config.contains("\"keyflow\""));
    assert!(config.contains("\"serve\""));
    assert!(config.contains("KEYFLOW_DATA_DIR"));

    let settings = fs::read_to_string(home.join(".claude/settings.json")).unwrap();
    assert!(settings.contains("additionalDirectories"));
    assert!(settings.contains(&data_dir_for_home(&home).display().to_string()));
}

#[test]
fn setup_codex_is_idempotent() {
    let root = temp_root("setup-codex-idempotent");
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let first = run_kf(&home, &["setup", "codex"]);
    assert!(
        first.status.success(),
        "first setup failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let second = run_kf(&home, &["setup", "codex"]);
    assert!(
        second.status.success(),
        "second setup failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let config = fs::read_to_string(home.join(".codex/config.toml")).unwrap();
    assert_eq!(count_occurrences(&config, "[mcp_servers.keyflow]"), 1);
    assert_eq!(count_occurrences(&config, "[mcp_servers.keyflow.env]"), 1);
}

#[test]
fn run_injects_project_scoped_secrets_from_current_directory() {
    let root = temp_root("run-project");
    let home = root.join("home");
    let project_dir = root.join("demo-app");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(
        project_dir.join("package.json"),
        r#"{ "name": "demo-app" }"#,
    )
    .unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let add = run_kf(
        &home,
        &[
            "add",
            "OPENAI_API_KEY",
            "sk-run-value",
            "--provider",
            "openai",
            "--projects",
            "demo-app",
        ],
    );
    assert!(
        add.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let run = run_kf_in_dir(
        &home,
        &project_dir,
        &["run", "--", "sh", "-c", "printf %s \"$OPENAI_API_KEY\""],
    );
    assert!(
        run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&run.stdout), "sk-run-value");
}

#[test]
fn add_and_search_support_asset_metadata_and_resend_provider() {
    let root = temp_root("asset-metadata");
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let add = run_kf(
        &home,
        &[
            "add",
            "RESEND_API_KEY",
            "re_test_123",
            "--provider",
            "resend",
            "--account",
            "acme-mail",
            "--source",
            "manual:resend-dashboard",
            "--projects",
            "marketing-site",
            "--desc",
            "primary transactional mail",
        ],
    );
    assert!(
        add.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let search = run_kf(&home, &["search", "acme-mail"]);
    assert!(
        search.status.success(),
        "search failed: {}",
        String::from_utf8_lossy(&search.stderr)
    );
    let stdout = String::from_utf8_lossy(&search.stdout);
    assert!(stdout.contains("resend-api-key"));
    assert!(stdout.contains("provider: resend"));
    assert!(stdout.contains("account: acme-mail"));
    assert!(stdout.contains("source: manual:resend-dashboard"));
}

#[test]
fn import_directory_absorbs_env_files_and_detects_project_name() {
    let root = temp_root("import-directory");
    let home = root.join("home");
    let project_dir = root.join("marketing-site");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(
        project_dir.join("package.json"),
        r#"{ "name": "marketing-site" }"#,
    )
    .unwrap();
    fs::write(
        project_dir.join(".env"),
        "RESEND_API_KEY=re_primary\nOPENAI_API_KEY=sk_primary\n",
    )
    .unwrap();
    fs::write(project_dir.join(".env.local"), "CF_API_TOKEN=cf_local\n").unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let import = run_kf(
        &home,
        &[
            "import",
            project_dir.to_str().unwrap(),
            "--provider",
            "imported",
            "--account",
            "acme-labs",
        ],
    );
    assert!(
        import.status.success(),
        "directory import failed: {}",
        String::from_utf8_lossy(&import.stderr)
    );

    let search = run_kf(&home, &["search", "marketing-site"]);
    assert!(
        search.status.success(),
        "search failed: {}",
        String::from_utf8_lossy(&search.stderr)
    );
    let stdout = String::from_utf8_lossy(&search.stdout);
    assert!(stdout.contains("resend-api-key"));
    assert!(stdout.contains("openai-api-key"));
    assert!(stdout.contains("cf-api-token"));
    assert!(stdout.contains("account: acme-labs"));
    assert!(stdout.contains("projects: marketing-site"));
    assert!(stdout.contains("source: import:"));
}

#[test]
fn verify_updates_last_verified_and_search_shows_it() {
    let root = temp_root("verify-secret");
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let add = run_kf(
        &home,
        &[
            "add",
            "OPENAI_API_KEY",
            "sk-verify-test",
            "--provider",
            "openai",
            "--projects",
            "verify-demo",
        ],
    );
    assert!(
        add.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let verify = run_kf(&home, &["verify", "openai-api-key"]);
    assert!(
        verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let search = run_kf(&home, &["search", "openai-api-key"]);
    assert!(
        search.status.success(),
        "search failed: {}",
        String::from_utf8_lossy(&search.stderr)
    );
    let stdout = String::from_utf8_lossy(&search.stdout);
    assert!(stdout.contains("verified:"));
}

#[test]
fn scan_previews_candidates_without_importing_until_apply() {
    let root = temp_root("scan-preview");
    let home = root.join("home");
    let project_dir = root.join("scan-app");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project_dir).unwrap();
    fs::write(project_dir.join(".env"), "RESEND_API_KEY=re_scan_123\n").unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let preview = run_kf(&home, &["scan", project_dir.to_str().unwrap()]);
    assert!(
        preview.status.success(),
        "scan preview failed: {}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview_stdout = String::from_utf8_lossy(&preview.stdout);
    assert!(preview_stdout.contains("RESEND_API_KEY"));
    assert!(preview_stdout.contains("Preview only"));

    let search_before = run_kf(&home, &["search", "re_scan_123"]);
    assert!(search_before.status.success());
    assert!(String::from_utf8_lossy(&search_before.stdout).contains("No secrets matching"));

    let apply = run_kf(&home, &["scan", project_dir.to_str().unwrap(), "--apply"]);
    assert!(
        apply.status.success(),
        "scan apply failed: {}",
        String::from_utf8_lossy(&apply.stderr)
    );

    let search_after = run_kf(&home, &["search", "resend-api-key"]);
    assert!(search_after.status.success());
    assert!(String::from_utf8_lossy(&search_after.stdout).contains("resend-api-key"));
}

#[test]
fn health_reports_metadata_review_items_for_incomplete_assets() {
    let root = temp_root("health-metadata");
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let add = run_kf(
        &home,
        &[
            "add",
            "GITHUB_TOKEN",
            "ghp_health_test",
            "--provider",
            "github",
            "--projects",
            "",
        ],
    );
    assert!(
        add.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let health = run_kf(&home, &["health"]);
    assert!(
        health.status.success(),
        "health failed: {}",
        String::from_utf8_lossy(&health.stderr)
    );
    let stdout = String::from_utf8_lossy(&health.stdout);
    assert!(stdout.contains("Keys Need Metadata Review"));
    assert!(stdout.contains("github-token"));
    assert!(stdout.contains("account"));
    assert!(stdout.contains("project"));
    assert!(stdout.contains("expiry"));
}
