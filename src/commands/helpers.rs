use anyhow::{Context, Result};
use chrono::{NaiveDate, TimeZone, Utc};

use crate::crypto::Crypto;

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
    "sendgrid",
    "slack",
    "docker",
    "npm",
    "pypi",
    "other",
];

pub(crate) fn infer_provider(env_var: &str) -> Option<&'static str> {
    let upper = env_var.to_uppercase();
    let patterns: &[(&[&str], &str)] = &[
        (&["GOOGLE", "GCLOUD", "GCP", "FIREBASE"], "google"),
        (&["GITHUB", "GH_"], "github"),
        (&["CLOUDFLARE", "CF_"], "cloudflare"),
        (&["AWS_", "AMAZON"], "aws"),
        (&["AZURE_"], "azure"),
        (&["OPENAI"], "openai"),
        (&["ANTHROPIC", "CLAUDE"], "anthropic"),
        (&["STRIPE"], "stripe"),
        (&["VERCEL"], "vercel"),
        (&["SUPABASE"], "supabase"),
        (&["TWILIO"], "twilio"),
        (&["SENDGRID"], "sendgrid"),
        (&["SLACK"], "slack"),
        (&["DOCKER"], "docker"),
        (&["NPM_"], "npm"),
    ];
    for (keywords, provider) in patterns {
        for kw in *keywords {
            if upper.contains(kw) {
                return Some(provider);
            }
        }
    }
    None
}

pub(crate) fn detect_project_name() -> Option<String> {
    if let Ok(content) = std::fs::read_to_string("package.json") {
        if let Some(name) = parse_project_name_from_package_json(&content) {
            return Some(name);
        }
    }
    if let Ok(content) = std::fs::read_to_string("Cargo.toml") {
        if let Some(name) = parse_project_name_from_cargo_toml(&content) {
            return Some(name);
        }
    }
    None
}

pub(crate) fn decrypt_backup_contents(
    backup_file: &[u8],
    passphrase: &str,
    fallback_salt_loader: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    if let Ok(wrapper) = serde_json::from_slice::<BackupFile>(backup_file) {
        let salt =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &wrapper.salt)
                .context("Backup salt is invalid")?;
        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &wrapper.ciphertext,
        )
        .context("Backup ciphertext is invalid")?;
        let crypto = Crypto::new(passphrase, &salt)?;
        return crypto
            .decrypt(&ciphertext)
            .context("Failed to decrypt backup. Wrong passphrase or corrupted file?");
    }

    let salt = fallback_salt_loader()?;
    let crypto = Crypto::new(passphrase, &salt)?;
    crypto.decrypt(backup_file).context(
        "Failed to decrypt legacy backup. Wrong passphrase, outdated salt, or corrupted file?",
    )
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

    #[test]
    fn infer_provider_matches_common_prefixes() {
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

        let decrypted = decrypt_backup_contents(
            &serde_json::to_vec(&backup).unwrap(),
            "secret-passphrase",
            || unreachable!(),
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
