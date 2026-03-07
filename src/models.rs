use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub env_var: String,
    pub provider: String,
    pub account_name: String,
    pub org_name: String,
    pub description: String,
    pub source: String,
    pub environment: String,
    pub permission_profile: String,
    pub scopes: Vec<String>,
    pub projects: Vec<String>,
    pub apply_url: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_verified_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyStatus {
    Active,
    ExpiringSoon,
    Expired,
    Inactive,
    Unknown,
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "Active"),
            KeyStatus::ExpiringSoon => write!(f, "Expiring Soon"),
            KeyStatus::Expired => write!(f, "Expired"),
            KeyStatus::Inactive => write!(f, "Inactive"),
            KeyStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

impl SecretEntry {
    pub fn status(&self) -> KeyStatus {
        if !self.is_active {
            return KeyStatus::Inactive;
        }

        match self.expires_at {
            Some(exp) => {
                let now = Utc::now();
                if exp < now {
                    KeyStatus::Expired
                } else if exp < now + chrono::Duration::days(7) {
                    KeyStatus::ExpiringSoon
                } else {
                    KeyStatus::Active
                }
            }
            None => KeyStatus::Active,
        }
    }

    pub fn days_since_last_seen(&self, now: DateTime<Utc>) -> i64 {
        let last = self.last_used_at.unwrap_or(self.created_at);
        (now - last).num_days()
    }

    pub fn is_unused_for_days(&self, now: DateTime<Utc>, days: i64) -> bool {
        self.is_active && self.days_since_last_seen(now) > days
    }

    pub fn metadata_gaps(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        let now = Utc::now();

        if self.account_name.trim().is_empty() {
            gaps.push("account");
        }
        if self.source.trim().is_empty() || self.source == "manual" || self.source == "imported" {
            gaps.push("source");
        }
        if self.projects.is_empty() {
            gaps.push("project");
        }
        if self.expires_at.is_none() {
            gaps.push("expiry");
        }
        if self.last_verified_at.unwrap_or(self.created_at) < now - chrono::Duration::days(90) {
            gaps.push("verification");
        }

        gaps
    }

    pub fn has_metadata_gaps(&self) -> bool {
        !self.metadata_gaps().is_empty()
    }

    pub fn source_quality(&self) -> SourceQuality {
        let source = self.source.trim();
        if source.is_empty() {
            return SourceQuality::Unknown;
        }
        if source.starts_with("import:") {
            return SourceQuality::Import;
        }
        if source.starts_with("mcp:") {
            return SourceQuality::Mcp;
        }
        if source.starts_with("manual:") || source == "manual" {
            return SourceQuality::Manual;
        }
        SourceQuality::Other
    }

    pub fn unverified_days(&self, now: DateTime<Utc>) -> i64 {
        let last = self.last_verified_at.unwrap_or(self.created_at);
        (now - last).num_days()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SourceQuality {
    Import,
    Manual,
    Mcp,
    Other,
    Unknown,
}

impl std::fmt::Display for SourceQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceQuality::Import => write!(f, "import"),
            SourceQuality::Manual => write!(f, "manual"),
            SourceQuality::Mcp => write!(f, "mcp"),
            SourceQuality::Other => write!(f, "other"),
            SourceQuality::Unknown => write!(f, "unknown"),
        }
    }
}

pub fn find_duplicate_groups(entries: &[SecretEntry]) -> Vec<DuplicateGroup> {
    let mut by_env_var: std::collections::HashMap<String, Vec<&SecretEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        if entry.is_active {
            by_env_var
                .entry(entry.env_var.to_uppercase())
                .or_default()
                .push(entry);
        }
    }

    let mut groups = Vec::new();
    for (env_var, keys) in &by_env_var {
        if keys.len() > 1 {
            groups.push(DuplicateGroup {
                env_var: env_var.clone(),
                names: keys.iter().map(|key| key.name.clone()).collect(),
            });
        }
    }

    let mut by_provider: std::collections::HashMap<String, Vec<&SecretEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        if entry.is_active && !entry.provider.is_empty() {
            by_provider
                .entry(entry.provider.clone())
                .or_default()
                .push(entry);
        }
    }

    for (provider, keys) in &by_provider {
        if keys.len() <= 1 {
            continue;
        }

        let mut seen_purposes: std::collections::HashMap<String, Vec<&str>> =
            std::collections::HashMap::new();
        for key in keys {
            let purpose = key
                .env_var
                .to_uppercase()
                .replace(&provider.to_uppercase(), "");
            let purpose = purpose.trim_matches('_').to_string();
            seen_purposes.entry(purpose).or_default().push(&key.name);
        }

        for names in seen_purposes.values() {
            if names.len() > 1 {
                let already_in = groups.iter().any(|group| {
                    names
                        .iter()
                        .all(|name| group.names.contains(&name.to_string()))
                });
                if !already_in {
                    groups.push(DuplicateGroup {
                        env_var: format!("{provider}:overlap"),
                        names: names.iter().map(|name| name.to_string()).collect(),
                    });
                }
            }
        }
    }

    groups
}

#[derive(Debug, Clone, Serialize)]
pub struct DuplicateGroup {
    pub env_var: String,
    pub names: Vec<String>,
}

#[derive(Debug, Default)]
pub struct ListFilter {
    pub provider: Option<String>,
    pub project: Option<String>,
    pub expiring: bool,
    pub inactive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub salt: String,
}

pub fn secret_to_json(entry: &SecretEntry) -> serde_json::Value {
    serde_json::json!({
        "name": entry.name,
        "env_var": entry.env_var,
        "provider": entry.provider,
        "account_name": entry.account_name,
        "org_name": entry.org_name,
        "description": entry.description,
        "source": entry.source,
        "environment": entry.environment,
        "permission_profile": entry.permission_profile,
        "last_verified_at": entry.last_verified_at.map(|d| d.format("%Y-%m-%d").to_string()),
        "metadata_gaps": entry.metadata_gaps(),
        "source_quality": entry.source_quality().to_string(),
        "scopes": entry.scopes,
        "projects": entry.projects,
        "apply_url": entry.apply_url,
        "status": entry.status().to_string(),
        "expires_at": entry.expires_at.map(|d| d.format("%Y-%m-%d").to_string()),
        "last_used_at": entry.last_used_at.map(|d| d.to_rfc3339()),
        "usage_hint": format!("Use via environment variable: {}", entry.env_var),
        "relevance_score": serde_json::Value::Null,
        "matched_fields": [],
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub expired: Vec<serde_json::Value>,
    pub expiring_soon: Vec<serde_json::Value>,
    pub unused_30d: Vec<serde_json::Value>,
    pub inactive: Vec<serde_json::Value>,
    pub metadata_review: Vec<serde_json::Value>,
    pub duplicate_groups: Vec<serde_json::Value>,
    pub source_quality: std::collections::HashMap<String, usize>,
    pub unverified_30: usize,
    pub unverified_60: usize,
    pub unverified_90: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthSummary {
    pub total: usize,
    pub expiry_issues: usize,
    pub duplicate_count: usize,
    pub inactive_count: usize,
    pub unused_count: usize,
    pub metadata_review_count: usize,
}

impl HealthReport {
    pub fn from_entries(entries: &[SecretEntry]) -> Self {
        let now = Utc::now();

        let mut expired = Vec::new();
        let mut expiring_soon = Vec::new();
        let mut unused_30d = Vec::new();
        let mut inactive = Vec::new();
        let mut metadata_review = Vec::new();

        for entry in entries {
            if !entry.is_active {
                inactive.push(secret_to_json(entry));
                continue;
            }

            match entry.status() {
                KeyStatus::Expired => expired.push(secret_to_json(entry)),
                KeyStatus::ExpiringSoon => expiring_soon.push(secret_to_json(entry)),
                _ => {}
            }

            if entry.is_unused_for_days(now, 30) {
                unused_30d.push(secret_to_json(entry));
            }
            if entry.has_metadata_gaps() {
                metadata_review.push(secret_to_json(entry));
            }
        }

        let duplicate_groups = find_duplicate_groups(entries)
            .into_iter()
            .map(|group| serde_json::json!({ "env_var": group.env_var, "names": group.names }))
            .collect();

        let active_entries: Vec<_> = entries.iter().filter(|entry| entry.is_active).collect();
        let mut source_quality = std::collections::HashMap::new();
        for entry in &active_entries {
            *source_quality
                .entry(entry.source_quality().to_string())
                .or_insert(0) += 1;
        }

        let unverified_30 = active_entries
            .iter()
            .filter(|entry| (30..60).contains(&entry.unverified_days(now)))
            .count();
        let unverified_60 = active_entries
            .iter()
            .filter(|entry| (60..90).contains(&entry.unverified_days(now)))
            .count();
        let unverified_90 = active_entries
            .iter()
            .filter(|entry| entry.unverified_days(now) >= 90)
            .count();

        Self {
            expired,
            expiring_soon,
            unused_30d,
            inactive,
            metadata_review,
            duplicate_groups,
            source_quality,
            unverified_30,
            unverified_60,
            unverified_90,
        }
    }
}

impl HealthSummary {
    pub fn from_report(report: &HealthReport, total: usize) -> Self {
        Self {
            total,
            expiry_issues: report.expired.len() + report.expiring_soon.len(),
            duplicate_count: report.duplicate_groups.len(),
            inactive_count: report.inactive.len(),
            unused_count: report.unused_30d.len(),
            metadata_review_count: report.metadata_review.len(),
        }
    }
}

pub fn infer_provider(env_var: &str) -> Option<&'static str> {
    let upper = env_var.to_uppercase();
    let patterns: &[(&[&str], &str)] = &[
        (&["GOOGLE", "GCLOUD", "GCP", "FIREBASE"], "google"),
        (&["GITHUB", "GH_"], "github"),
        (&["CLOUDFLARE", "CF_", "WRANGLER", "R2_"], "cloudflare"),
        (&["AWS_", "AMAZON"], "aws"),
        (&["AZURE_"], "azure"),
        (&["OPENAI"], "openai"),
        (&["ANTHROPIC", "CLAUDE"], "anthropic"),
        (&["STRIPE"], "stripe"),
        (&["VERCEL"], "vercel"),
        (&["SUPABASE"], "supabase"),
        (&["TWILIO"], "twilio"),
        (&["RESEND"], "resend"),
        (&["SENDGRID"], "sendgrid"),
        (&["SLACK"], "slack"),
        (&["DOCKER"], "docker"),
        (&["NPM_"], "npm"),
        (&["PYPI"], "pypi"),
        (&["FLY_", "FLYIO"], "fly"),
        (&["HEROKU"], "heroku"),
        (&["NETLIFY"], "netlify"),
        (&["RAILWAY"], "railway"),
    ];

    for (keywords, provider) in patterns {
        for keyword in *keywords {
            if upper.contains(keyword) {
                return Some(provider);
            }
        }
    }
    None
}
