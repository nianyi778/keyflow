use anyhow::{Context, Result};
use chrono::{NaiveDate, TimeZone, Utc};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(crate) const SKIP_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "LANG",
    "TERM",
    "PWD",
    "OLDPWD",
    "HOSTNAME",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "LESS",
    "LOGNAME",
    "SHLVL",
    "_",
    "TMPDIR",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "COLORTERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "LC_ALL",
    "LC_CTYPE",
    "MANPATH",
    "INFOPATH",
    "COLUMNS",
    "LINES",
    "LS_COLORS",
    "NODE_ENV",
    "RAILS_ENV",
    "RACK_ENV",
    "MIX_ENV",
    "RUST_LOG",
    "DEBUG",
    "VERBOSE",
    "CI",
    "TZ",
];

pub(crate) const PROVIDERS: &[&str] = &[
    "google",
    "github",
    "cloudflare",
    "aws",
    "azure",
    "openai",
    "anthropic",
    "stripe",
    "vercel",
    "supabase",
    "firebase",
    "twilio",
    "resend",
    "sendgrid",
    "slack",
    "docker",
    "npm",
    "pypi",
    "other",
];

pub(crate) fn detect_project_name() -> Option<String> {
    discover_project_context(Path::new(".")).map(|context| context.name)
}

pub(crate) fn detect_project_name_in_dir(dir: &Path) -> Option<String> {
    discover_project_context(dir).map(|context| context.name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectContext {
    pub name: String,
    pub root: PathBuf,
    pub detector: &'static str,
    pub workspace_root: Option<PathBuf>,
    pub workspace_detector: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectRequirements {
    pub vars: Vec<String>,
    pub sources: Vec<String>,
}

pub(crate) fn discover_project_context(start_dir: &Path) -> Option<ProjectContext> {
    let start = if start_dir.is_dir() {
        start_dir
    } else {
        start_dir.parent().unwrap_or(start_dir)
    };
    let workspace = discover_workspace_root(start);

    for dir in start.ancestors() {
        if let Some(name) = read_project_name_from_manifest(
            dir,
            "package.json",
            parse_project_name_from_package_json,
        ) {
            return Some(ProjectContext {
                name,
                root: dir.to_path_buf(),
                detector: "package.json",
                workspace_root: workspace
                    .as_ref()
                    .map(|(root, _)| root)
                    .filter(|root| *root != &dir.to_path_buf())
                    .cloned(),
                workspace_detector: workspace
                    .as_ref()
                    .filter(|(root, _)| *root != dir)
                    .map(|(_, detector)| *detector),
            });
        }
        if let Some(name) =
            read_project_name_from_manifest(dir, "Cargo.toml", parse_project_name_from_cargo_toml)
        {
            return Some(ProjectContext {
                name,
                root: dir.to_path_buf(),
                detector: "Cargo.toml",
                workspace_root: workspace
                    .as_ref()
                    .map(|(root, _)| root)
                    .filter(|root| *root != &dir.to_path_buf())
                    .cloned(),
                workspace_detector: workspace
                    .as_ref()
                    .filter(|(root, _)| *root != dir)
                    .map(|(_, detector)| *detector),
            });
        }
        if let Some(name) = read_project_name_from_manifest(
            dir,
            "pyproject.toml",
            parse_project_name_from_pyproject_toml,
        ) {
            return Some(ProjectContext {
                name,
                root: dir.to_path_buf(),
                detector: "pyproject.toml",
                workspace_root: workspace
                    .as_ref()
                    .map(|(root, _)| root)
                    .filter(|root| *root != &dir.to_path_buf())
                    .cloned(),
                workspace_detector: workspace
                    .as_ref()
                    .filter(|(root, _)| *root != dir)
                    .map(|(_, detector)| *detector),
            });
        }
        if let Some(name) =
            read_project_name_from_manifest(dir, "go.mod", parse_project_name_from_go_mod)
        {
            return Some(ProjectContext {
                name,
                root: dir.to_path_buf(),
                detector: "go.mod",
                workspace_root: workspace
                    .as_ref()
                    .map(|(root, _)| root)
                    .filter(|root| *root != &dir.to_path_buf())
                    .cloned(),
                workspace_detector: workspace
                    .as_ref()
                    .filter(|(root, _)| *root != dir)
                    .map(|(_, detector)| *detector),
            });
        }
        if let Some(name) =
            read_project_name_from_manifest(dir, "deno.json", parse_project_name_from_package_json)
        {
            return Some(ProjectContext {
                name,
                root: dir.to_path_buf(),
                detector: "deno.json",
                workspace_root: workspace
                    .as_ref()
                    .map(|(root, _)| root)
                    .filter(|root| *root != &dir.to_path_buf())
                    .cloned(),
                workspace_detector: workspace
                    .as_ref()
                    .filter(|(root, _)| *root != dir)
                    .map(|(_, detector)| *detector),
            });
        }
        if let Some(name) =
            read_project_name_from_manifest(dir, "deno.jsonc", parse_project_name_from_deno_jsonc)
        {
            return Some(ProjectContext {
                name,
                root: dir.to_path_buf(),
                detector: "deno.jsonc",
                workspace_root: workspace
                    .as_ref()
                    .map(|(root, _)| root)
                    .filter(|root| *root != &dir.to_path_buf())
                    .cloned(),
                workspace_detector: workspace
                    .as_ref()
                    .filter(|(root, _)| *root != dir)
                    .map(|(_, detector)| *detector),
            });
        }
    }

    workspace.map(|(root, detector)| ProjectContext {
        name: root
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("workspace")
            .to_string(),
        root: root.clone(),
        detector,
        workspace_root: None,
        workspace_detector: None,
    })
}

pub(crate) fn infer_required_env_vars(dir: &Path) -> ProjectRequirements {
    let scan_roots = discover_project_context(dir)
        .map(|context| {
            let mut roots = vec![context.root];
            if let Some(workspace_root) = context.workspace_root {
                roots.push(workspace_root);
            }
            roots
        })
        .unwrap_or_else(|| vec![dir.to_path_buf()]);
    let mut vars = BTreeSet::new();
    let mut sources = Vec::new();

    for root in dedup_paths(scan_roots) {
        for candidate in [
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.local.example",
            "example.env",
            ".env.defaults",
        ] {
            let path = root.join(candidate);
            if !path.exists() {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&path) {
                let before = vars.len();
                collect_env_vars_from_env_file(&content, &mut vars);
                if vars.len() > before {
                    sources.push(path.display().to_string());
                }
            }
        }

        let source_files = walkdir::WalkDir::new(&root)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                let name = entry.file_name().to_str().unwrap_or("");
                !matches!(
                    name,
                    ".git" | "node_modules" | "target" | "dist" | "build" | ".next"
                )
            })
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        matches!(ext, "js" | "jsx" | "ts" | "tsx" | "rs" | "py" | "go" | "sh")
                    })
            })
            .collect::<Vec<_>>();

        for entry in source_files {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                let before = vars.len();
                collect_env_vars_from_source(&content, &mut vars);
                if vars.len() > before {
                    sources.push(entry.path().display().to_string());
                }
            }
        }
    }

    ProjectRequirements {
        vars: vars.into_iter().collect(),
        sources,
    }
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.contains(&path) {
            deduped.push(path);
        }
    }
    deduped
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct BackupFile {
    pub version: String,
    pub created_at: String,
    pub salt: String,
    pub ciphertext: String,
}

pub(crate) const BACKUP_FORMAT_VERSION: &str = "0.3.0";

pub(crate) fn parse_csv(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

pub(crate) fn parse_project_name_from_package_json(content: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(content).ok()?;
    value
        .get("name")
        .and_then(|name| name.as_str())
        .map(str::to_string)
}

pub(crate) fn parse_project_name_from_cargo_toml(content: &str) -> Option<String> {
    let mut in_package = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_package = trimmed == "[package]";
            continue;
        }

        if !in_package || !trimmed.starts_with("name") {
            continue;
        }

        let (_, raw_value) = trimmed.split_once('=')?;
        let name = raw_value.trim().trim_matches('"').trim_matches('\'');
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    None
}

pub(crate) fn parse_project_name_from_pyproject_toml(content: &str) -> Option<String> {
    let mut in_project = false;
    let mut in_poetry = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_project = trimmed == "[project]";
            in_poetry = trimmed == "[tool.poetry]";
            continue;
        }

        if !(in_project || in_poetry) || !trimmed.starts_with("name") {
            continue;
        }

        let (_, raw_value) = trimmed.split_once('=')?;
        let name = raw_value.trim().trim_matches('"').trim_matches('\'');
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    None
}

pub(crate) fn parse_project_name_from_go_mod(content: &str) -> Option<String> {
    let module = content.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("module ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })?;
    module
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn parse_project_name_from_deno_jsonc(content: &str) -> Option<String> {
    let stripped = content
        .lines()
        .map(|line| line.split("//").next().unwrap_or("").trim_end())
        .collect::<Vec<_>>()
        .join("\n");
    parse_project_name_from_package_json(&stripped)
}

fn read_project_name_from_manifest(
    dir: &Path,
    manifest: &str,
    parser: fn(&str) -> Option<String>,
) -> Option<String> {
    let content = std::fs::read_to_string(dir.join(manifest)).ok()?;
    let parsed = parser(&content);
    parsed.or_else(|| {
        dir.file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn discover_workspace_root(start_dir: &Path) -> Option<(PathBuf, &'static str)> {
    let start = if start_dir.is_dir() {
        start_dir
    } else {
        start_dir.parent().unwrap_or(start_dir)
    };

    for dir in start.ancestors() {
        if has_package_workspaces(dir) {
            return Some((dir.to_path_buf(), "package.json#workspaces"));
        }
        if has_cargo_workspace(dir) {
            return Some((dir.to_path_buf(), "Cargo.toml#workspace"));
        }
        for (marker, detector) in [
            ("pnpm-workspace.yaml", "pnpm-workspace.yaml"),
            ("turbo.json", "turbo.json"),
            ("nx.json", "nx.json"),
            ("lerna.json", "lerna.json"),
        ] {
            if dir.join(marker).exists() {
                return Some((dir.to_path_buf(), detector));
            }
        }
    }

    None
}

fn has_package_workspaces(dir: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(dir.join("package.json")) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return false;
    };
    value
        .get("workspaces")
        .is_some_and(|workspaces| !workspaces.is_null())
}

fn has_cargo_workspace(dir: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
        return false;
    };
    content.lines().any(|line| line.trim() == "[workspace]")
}

fn collect_env_vars_from_env_file(content: &str, vars: &mut BTreeSet<String>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((key, _)) = trimmed.split_once('=') else {
            continue;
        };
        maybe_insert_env_var(key.trim(), vars);
    }
}

fn collect_env_vars_from_source(content: &str, vars: &mut BTreeSet<String>) {
    collect_after_prefix(content, "process.env.", vars, false);
    collect_after_prefix(content, "import.meta.env.", vars, false);
    collect_after_prefix(content, "env!(\"", vars, true);
    collect_after_prefix(content, "std::env::var(\"", vars, true);
    collect_after_prefix(content, "std::env::var_os(\"", vars, true);
    collect_after_prefix(content, "dotenv::var(\"", vars, true);
    collect_after_prefix(content, "os.getenv(\"", vars, true);
    collect_after_prefix(content, "os.environ.get(\"", vars, true);
    collect_after_prefix(content, "Deno.env.get(\"", vars, true);
}

fn collect_after_prefix(content: &str, prefix: &str, vars: &mut BTreeSet<String>, quoted: bool) {
    let mut remaining = content;
    while let Some(index) = remaining.find(prefix) {
        let tail = &remaining[index + prefix.len()..];
        let token = if quoted {
            tail.split('"').next().unwrap_or("").to_string()
        } else {
            tail.chars()
                .take_while(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || *ch == '_')
                .collect::<String>()
        };
        maybe_insert_env_var(&token, vars);
        remaining = tail;
        if remaining.is_empty() {
            break;
        }
    }
}

fn maybe_insert_env_var(value: &str, vars: &mut BTreeSet<String>) {
    if value.is_empty() {
        return;
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return;
    }
    if value.len() < 3 || SKIP_VARS.contains(&value) {
        return;
    }
    vars.insert(value.to_string());
}

pub(crate) fn parse_date(s: &str) -> Result<Option<chrono::DateTime<Utc>>> {
    if s.is_empty() {
        return Ok(None);
    }
    let date = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .context("Invalid date format, expected YYYY-MM-DD")?;
    let datetime = date.and_hms_opt(0, 0, 0).unwrap();
    Ok(Some(Utc.from_utc_datetime(&datetime)))
}

pub(crate) fn get_default_url(provider: &str) -> String {
    match provider {
        "google" => "https://console.cloud.google.com/apis/credentials".to_string(),
        "github" => "https://github.com/settings/tokens".to_string(),
        "cloudflare" => "https://dash.cloudflare.com/profile/api-tokens".to_string(),
        "aws" => "https://console.aws.amazon.com/iam/home#/security_credentials".to_string(),
        "openai" => "https://platform.openai.com/api-keys".to_string(),
        "anthropic" => "https://console.anthropic.com/settings/keys".to_string(),
        "stripe" => "https://dashboard.stripe.com/apikeys".to_string(),
        "vercel" => "https://vercel.com/account/tokens".to_string(),
        "supabase" => "https://supabase.com/dashboard/account/tokens".to_string(),
        "firebase" => {
            "https://console.firebase.google.com/project/_/settings/serviceaccounts".to_string()
        }
        "twilio" => "https://console.twilio.com/".to_string(),
        "resend" => "https://resend.com/api-keys".to_string(),
        "sendgrid" => "https://app.sendgrid.com/settings/api_keys".to_string(),
        "slack" => "https://api.slack.com/apps".to_string(),
        "docker" => "https://hub.docker.com/settings/security".to_string(),
        "npm" => "https://www.npmjs.com/settings/~/tokens".to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;

    #[test]
    fn infer_provider_matches_common_prefixes() {
        use crate::models::infer_provider;
        assert_eq!(infer_provider("OPENAI_API_KEY"), Some("openai"));
        assert_eq!(infer_provider("CF_API_TOKEN"), Some("cloudflare"));
        assert_eq!(infer_provider("UNKNOWN_KEY"), None);
    }

    #[test]
    fn parse_csv_discards_empty_values() {
        assert_eq!(parse_csv("a, b ,, c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_project_name_from_package_json_reads_name_field() {
        let json = r#"{ "name": "@acme/keyflow", "private": true }"#;
        assert_eq!(
            parse_project_name_from_package_json(json),
            Some("@acme/keyflow".to_string())
        );
    }

    #[test]
    fn parse_project_name_from_cargo_toml_only_reads_package_section() {
        let toml = r#"
[workspace]
members = ["cli"]

[package]
name = "keyflow"
version = "0.3.0"

[[bin]]
name = "kf"
"#;
        assert_eq!(
            parse_project_name_from_cargo_toml(toml),
            Some("keyflow".to_string())
        );
    }

    #[test]
    fn detect_project_name_in_dir_reads_package_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{ "name": "marketing-site" }"#,
        )
        .unwrap();

        assert_eq!(
            detect_project_name_in_dir(dir.path()),
            Some("marketing-site".to_string())
        );
    }

    #[test]
    fn detect_project_name_in_dir_walks_up_and_supports_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"agent-core\"\n",
        )
        .unwrap();
        let child = dir.path().join("src").join("pkg");
        std::fs::create_dir_all(&child).unwrap();

        let context = discover_project_context(&child).unwrap();
        assert_eq!(context.name, "agent-core");
        assert_eq!(context.detector, "pyproject.toml");
        assert_eq!(context.workspace_root, None);
    }

    #[test]
    fn discover_project_context_tracks_workspace_root_for_nested_package() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{ "private": true, "workspaces": ["apps/*"] }"#,
        )
        .unwrap();
        let app_dir = dir.path().join("apps/web");
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::write(app_dir.join("package.json"), r#"{ "name": "web-app" }"#).unwrap();

        let context = discover_project_context(&app_dir).unwrap();
        assert_eq!(context.name, "web-app");
        assert_eq!(context.detector, "package.json");
        assert_eq!(context.workspace_detector, Some("package.json#workspaces"));
        assert_eq!(context.workspace_root, Some(dir.path().to_path_buf()));
    }

    #[test]
    fn infer_required_env_vars_reads_examples_and_source_refs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{ "name": "demo-app" }"#).unwrap();
        std::fs::write(
            dir.path().join(".env.example"),
            "OPENAI_API_KEY=\n# comment\nexport RESEND_API_KEY=\nNODE_ENV=development\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src/app.ts"),
            r#"
const key = process.env.OPENAI_API_KEY;
const mail = process.env.RESEND_API_KEY;
const vite = import.meta.env.VITE_PUBLIC_BASE_URL;
"#,
        )
        .unwrap();

        let requirements = infer_required_env_vars(dir.path());
        assert!(requirements.vars.contains(&"OPENAI_API_KEY".to_string()));
        assert!(requirements.vars.contains(&"RESEND_API_KEY".to_string()));
        assert!(requirements
            .vars
            .contains(&"VITE_PUBLIC_BASE_URL".to_string()));
        assert!(!requirements.vars.contains(&"NODE_ENV".to_string()));
        assert!(!requirements.sources.is_empty());
    }

    #[test]
    fn infer_required_env_vars_collects_workspace_and_package_sources() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{ "private": true, "workspaces": ["apps/*"] }"#,
        )
        .unwrap();
        std::fs::write(dir.path().join(".env.example"), "ROOT_KEY=\n").unwrap();
        let app_dir = dir.path().join("apps/web");
        std::fs::create_dir_all(app_dir.join("src")).unwrap();
        std::fs::write(app_dir.join("package.json"), r#"{ "name": "web-app" }"#).unwrap();
        std::fs::write(app_dir.join(".env.sample"), "APP_KEY=\n").unwrap();
        std::fs::write(
            app_dir.join("src/main.ts"),
            "console.log(import.meta.env.VITE_PUBLIC_API_BASE)",
        )
        .unwrap();

        let requirements = infer_required_env_vars(&app_dir);
        assert!(requirements.vars.contains(&"ROOT_KEY".to_string()));
        assert!(requirements.vars.contains(&"APP_KEY".to_string()));
        assert!(requirements
            .vars
            .contains(&"VITE_PUBLIC_API_BASE".to_string()));
    }

    #[test]
    fn decrypt_backup_contents_supports_new_backup_format() {
        let salt = b"01234567890123456789012345678901";
        let crypto = Crypto::new("secret-passphrase", salt).unwrap();
        let plaintext = b"{\"secrets\":[]}";
        let ciphertext = crypto.encrypt(plaintext).unwrap();
        let backup = BackupFile {
            version: BACKUP_FORMAT_VERSION.to_string(),
            created_at: Utc::now().to_rfc3339(),
            salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &ciphertext,
            ),
        };

        let raw = serde_json::to_vec(&backup).unwrap();
        let parsed: BackupFile = serde_json::from_slice(&raw).unwrap();
        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &parsed.ciphertext,
        )
        .unwrap();
        let decrypted = Crypto::new("secret-passphrase", salt)
            .unwrap()
            .decrypt(&ciphertext)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
