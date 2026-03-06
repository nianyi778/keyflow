use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use keyflow::crypto::Crypto;

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
            "--group",
            "llm",
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
    assert!(config.contains("KEYFLOW_PASSPHRASE = \"pass123\""));
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
    fs::write(project_dir.join("package.json"), r#"{ "name": "demo-app" }"#).unwrap();

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
fn restore_supports_legacy_raw_encrypted_backup() {
    let root = temp_root("legacy-backup");
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();

    let init = run_kf(&home, &["init", "--passphrase", "pass123"]);
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let config_path = home.join(".keyflow/config.json");
    let config: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    let salt = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        config.get("salt").unwrap().as_str().unwrap(),
    )
    .unwrap();

    let payload = serde_json::json!({
        "version": "0.2.0",
        "created_at": "2026-03-06T00:00:00Z",
        "secrets": [{
            "name": "legacy-openai-key",
            "env_var": "OPENAI_API_KEY",
            "provider": "openai",
            "description": "legacy backup",
            "scopes": [],
            "projects": ["legacy-demo"],
            "apply_url": "",
            "expires_at": null,
            "created_at": "2026-03-06T00:00:00Z",
            "updated_at": "2026-03-06T00:00:00Z",
            "last_used_at": null,
            "is_active": true,
            "key_group": "",
            "_value": "sk-legacy-value"
        }]
    });
    let crypto = Crypto::new("pass123", &salt).unwrap();
    let encrypted = crypto
        .encrypt(serde_json::to_string_pretty(&payload).unwrap().as_bytes())
        .unwrap();
    let legacy_backup_path = root.join("legacy-backup.enc");
    fs::write(&legacy_backup_path, encrypted).unwrap();

    let restore = run_kf(
        &home,
        &[
            "restore",
            legacy_backup_path.to_str().unwrap(),
            "--passphrase",
            "pass123",
        ],
    );
    assert!(
        restore.status.success(),
        "legacy restore failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );

    let get = run_kf(&home, &["get", "legacy-openai-key", "--raw"]);
    assert!(
        get.status.success(),
        "legacy get failed: {}",
        String::from_utf8_lossy(&get.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&get.stdout), "sk-legacy-value");
}
