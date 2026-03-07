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
    pub key_group: String,
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
        let s = self.source.trim();
        if s.is_empty() {
            return SourceQuality::Unknown;
        }
        if s.starts_with("template:") {
            return SourceQuality::Template;
        }
        if s.starts_with("import:") {
            return SourceQuality::Import;
        }
        if s.starts_with("mcp:") {
            return SourceQuality::Mcp;
        }
        if s.starts_with("manual:") || s == "manual" {
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
    Template,
    Import,
    Manual,
    Mcp,
    Other,
    Unknown,
}

impl std::fmt::Display for SourceQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceQuality::Template => write!(f, "template"),
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
                names: keys.iter().map(|k| k.name.clone()).collect(),
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
                let already_in = groups
                    .iter()
                    .any(|g| names.iter().all(|n| g.names.contains(&n.to_string())));
                if !already_in {
                    groups.push(DuplicateGroup {
                        env_var: format!("{}:overlap", provider),
                        names: names.iter().map(|n| n.to_string()).collect(),
                    });
                }
            }
        }
    }

    groups
}

#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    pub env_var: String,
    pub names: Vec<String>,
}

#[derive(Debug, Default)]
pub struct ListFilter {
    pub provider: Option<String>,
    pub project: Option<String>,
    pub group: Option<String>,
    pub expiring: bool,
    pub inactive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub salt: String,
}

/// Predefined template for common service key bundles
#[derive(Debug, Clone)]
pub struct KeyTemplate {
    pub name: &'static str,
    pub description: &'static str,
    pub provider: &'static str,
    pub keys: &'static [TemplateKey],
    pub apply_url: &'static str,
}

#[derive(Debug, Clone)]
pub struct TemplateKey {
    pub env_var: &'static str,
    pub description: &'static str,
    pub is_secret: bool,
}

pub const TEMPLATES: &[KeyTemplate] = &[
    KeyTemplate {
        name: "google-oauth",
        description: "Google OAuth 2.0 (Client ID + Secret + Redirect URI)",
        provider: "google",
        keys: &[
            TemplateKey {
                env_var: "GOOGLE_CLIENT_ID",
                description: "OAuth Client ID",
                is_secret: false,
            },
            TemplateKey {
                env_var: "GOOGLE_CLIENT_SECRET",
                description: "OAuth Client Secret",
                is_secret: true,
            },
            TemplateKey {
                env_var: "GOOGLE_REDIRECT_URI",
                description: "OAuth Redirect URI",
                is_secret: false,
            },
        ],
        apply_url: "https://console.cloud.google.com/apis/credentials",
    },
    KeyTemplate {
        name: "github-oauth",
        description: "GitHub OAuth App (Client ID + Secret)",
        provider: "github",
        keys: &[
            TemplateKey {
                env_var: "GITHUB_CLIENT_ID",
                description: "OAuth App Client ID",
                is_secret: false,
            },
            TemplateKey {
                env_var: "GITHUB_CLIENT_SECRET",
                description: "OAuth App Client Secret",
                is_secret: true,
            },
        ],
        apply_url: "https://github.com/settings/developers",
    },
    KeyTemplate {
        name: "github-token",
        description: "GitHub Personal Access Token",
        provider: "github",
        keys: &[TemplateKey {
            env_var: "GITHUB_TOKEN",
            description: "Personal Access Token",
            is_secret: true,
        }],
        apply_url: "https://github.com/settings/tokens",
    },
    KeyTemplate {
        name: "cloudflare-workers",
        description: "Cloudflare Workers (API Token + Account ID)",
        provider: "cloudflare",
        keys: &[
            TemplateKey {
                env_var: "CF_API_TOKEN",
                description: "API Token",
                is_secret: true,
            },
            TemplateKey {
                env_var: "CF_ACCOUNT_ID",
                description: "Account ID",
                is_secret: false,
            },
        ],
        apply_url: "https://dash.cloudflare.com/profile/api-tokens",
    },
    KeyTemplate {
        name: "cloudflare-r2",
        description: "Cloudflare R2 Storage (Access Key + Secret + Endpoint)",
        provider: "cloudflare",
        keys: &[
            TemplateKey {
                env_var: "R2_ACCESS_KEY_ID",
                description: "R2 Access Key ID",
                is_secret: false,
            },
            TemplateKey {
                env_var: "R2_SECRET_ACCESS_KEY",
                description: "R2 Secret Access Key",
                is_secret: true,
            },
            TemplateKey {
                env_var: "R2_ENDPOINT",
                description: "R2 Endpoint URL",
                is_secret: false,
            },
        ],
        apply_url: "https://dash.cloudflare.com/?to=/:account/r2/api-tokens",
    },
    KeyTemplate {
        name: "aws-iam",
        description: "AWS IAM (Access Key + Secret + Region)",
        provider: "aws",
        keys: &[
            TemplateKey {
                env_var: "AWS_ACCESS_KEY_ID",
                description: "Access Key ID",
                is_secret: false,
            },
            TemplateKey {
                env_var: "AWS_SECRET_ACCESS_KEY",
                description: "Secret Access Key",
                is_secret: true,
            },
            TemplateKey {
                env_var: "AWS_DEFAULT_REGION",
                description: "Default Region",
                is_secret: false,
            },
        ],
        apply_url: "https://console.aws.amazon.com/iam/home#/security_credentials",
    },
    KeyTemplate {
        name: "stripe",
        description: "Stripe (Publishable Key + Secret Key + Webhook Secret)",
        provider: "stripe",
        keys: &[
            TemplateKey {
                env_var: "STRIPE_PUBLISHABLE_KEY",
                description: "Publishable Key (pk_)",
                is_secret: false,
            },
            TemplateKey {
                env_var: "STRIPE_SECRET_KEY",
                description: "Secret Key (sk_)",
                is_secret: true,
            },
            TemplateKey {
                env_var: "STRIPE_WEBHOOK_SECRET",
                description: "Webhook Signing Secret (whsec_)",
                is_secret: true,
            },
        ],
        apply_url: "https://dashboard.stripe.com/apikeys",
    },
    KeyTemplate {
        name: "supabase",
        description: "Supabase (URL + Anon Key + Service Role Key)",
        provider: "supabase",
        keys: &[
            TemplateKey {
                env_var: "SUPABASE_URL",
                description: "Project URL",
                is_secret: false,
            },
            TemplateKey {
                env_var: "SUPABASE_ANON_KEY",
                description: "Anon/Public Key",
                is_secret: false,
            },
            TemplateKey {
                env_var: "SUPABASE_SERVICE_ROLE_KEY",
                description: "Service Role Key (admin)",
                is_secret: true,
            },
        ],
        apply_url: "https://supabase.com/dashboard/project/_/settings/api",
    },
    KeyTemplate {
        name: "openai",
        description: "OpenAI API Key + Org ID",
        provider: "openai",
        keys: &[
            TemplateKey {
                env_var: "OPENAI_API_KEY",
                description: "API Key",
                is_secret: true,
            },
            TemplateKey {
                env_var: "OPENAI_ORG_ID",
                description: "Organization ID",
                is_secret: false,
            },
        ],
        apply_url: "https://platform.openai.com/api-keys",
    },
    KeyTemplate {
        name: "anthropic",
        description: "Anthropic API Key",
        provider: "anthropic",
        keys: &[TemplateKey {
            env_var: "ANTHROPIC_API_KEY",
            description: "API Key",
            is_secret: true,
        }],
        apply_url: "https://console.anthropic.com/settings/keys",
    },
    KeyTemplate {
        name: "vercel",
        description: "Vercel Token + Team ID",
        provider: "vercel",
        keys: &[
            TemplateKey {
                env_var: "VERCEL_TOKEN",
                description: "Auth Token",
                is_secret: true,
            },
            TemplateKey {
                env_var: "VERCEL_TEAM_ID",
                description: "Team ID",
                is_secret: false,
            },
        ],
        apply_url: "https://vercel.com/account/tokens",
    },
    KeyTemplate {
        name: "firebase",
        description: "Firebase (API Key + Auth Domain + Project ID)",
        provider: "firebase",
        keys: &[
            TemplateKey {
                env_var: "FIREBASE_API_KEY",
                description: "Web API Key",
                is_secret: false,
            },
            TemplateKey {
                env_var: "FIREBASE_AUTH_DOMAIN",
                description: "Auth Domain",
                is_secret: false,
            },
            TemplateKey {
                env_var: "FIREBASE_PROJECT_ID",
                description: "Project ID",
                is_secret: false,
            },
        ],
        apply_url: "https://console.firebase.google.com/project/_/settings/general",
    },
    KeyTemplate {
        name: "sendgrid",
        description: "SendGrid API Key + From Email",
        provider: "sendgrid",
        keys: &[
            TemplateKey {
                env_var: "SENDGRID_API_KEY",
                description: "API Key",
                is_secret: true,
            },
            TemplateKey {
                env_var: "SENDGRID_FROM_EMAIL",
                description: "Verified Sender Email",
                is_secret: false,
            },
        ],
        apply_url: "https://app.sendgrid.com/settings/api_keys",
    },
    KeyTemplate {
        name: "resend",
        description: "Resend API Key + Sending Domain",
        provider: "resend",
        keys: &[
            TemplateKey {
                env_var: "RESEND_API_KEY",
                description: "API Key",
                is_secret: true,
            },
            TemplateKey {
                env_var: "RESEND_DOMAIN",
                description: "Verified sending domain",
                is_secret: false,
            },
        ],
        apply_url: "https://resend.com/api-keys",
    },
    KeyTemplate {
        name: "docker",
        description: "Docker Hub (Username + Token)",
        provider: "docker",
        keys: &[
            TemplateKey {
                env_var: "DOCKER_USERNAME",
                description: "Docker Hub Username",
                is_secret: false,
            },
            TemplateKey {
                env_var: "DOCKER_TOKEN",
                description: "Access Token",
                is_secret: true,
            },
        ],
        apply_url: "https://hub.docker.com/settings/security",
    },
    KeyTemplate {
        name: "google-cloud-sa",
        description: "Google Cloud Service Account (Project ID + Client Email + Private Key)",
        provider: "google",
        keys: &[
            TemplateKey {
                env_var: "GCP_PROJECT_ID",
                description: "Google Cloud Project ID",
                is_secret: false,
            },
            TemplateKey {
                env_var: "GCP_CLIENT_EMAIL",
                description: "Service Account Email",
                is_secret: false,
            },
            TemplateKey {
                env_var: "GCP_PRIVATE_KEY",
                description: "Service Account Private Key (PEM)",
                is_secret: true,
            },
        ],
        apply_url: "https://console.cloud.google.com/iam-admin/serviceaccounts",
    },
    KeyTemplate {
        name: "google-maps",
        description: "Google Maps API Key + Map ID",
        provider: "google",
        keys: &[
            TemplateKey {
                env_var: "GOOGLE_MAPS_API_KEY",
                description: "Maps API Key",
                is_secret: true,
            },
            TemplateKey {
                env_var: "GOOGLE_MAPS_MAP_ID",
                description: "Map ID",
                is_secret: false,
            },
        ],
        apply_url: "https://console.cloud.google.com/apis/credentials",
    },
    KeyTemplate {
        name: "github-app",
        description: "GitHub App (App ID + Private Key + Installation ID)",
        provider: "github",
        keys: &[
            TemplateKey {
                env_var: "GITHUB_APP_ID",
                description: "GitHub App ID",
                is_secret: false,
            },
            TemplateKey {
                env_var: "GITHUB_APP_PRIVATE_KEY",
                description: "App Private Key (PEM)",
                is_secret: true,
            },
            TemplateKey {
                env_var: "GITHUB_APP_INSTALLATION_ID",
                description: "Installation ID",
                is_secret: false,
            },
        ],
        apply_url: "https://github.com/settings/apps",
    },
    KeyTemplate {
        name: "cloudflare-pages",
        description: "Cloudflare Pages (API Token + Account ID)",
        provider: "cloudflare",
        keys: &[
            TemplateKey {
                env_var: "CF_PAGES_API_TOKEN",
                description: "Pages API Token",
                is_secret: true,
            },
            TemplateKey {
                env_var: "CF_PAGES_ACCOUNT_ID",
                description: "Account ID",
                is_secret: false,
            },
        ],
        apply_url: "https://dash.cloudflare.com/profile/api-tokens",
    },
    KeyTemplate {
        name: "cloudflare-dns",
        description: "Cloudflare DNS (API Token + Zone ID)",
        provider: "cloudflare",
        keys: &[
            TemplateKey {
                env_var: "CF_DNS_API_TOKEN",
                description: "DNS API Token",
                is_secret: true,
            },
            TemplateKey {
                env_var: "CF_ZONE_ID",
                description: "Zone ID",
                is_secret: false,
            },
        ],
        apply_url: "https://dash.cloudflare.com/profile/api-tokens",
    },
    KeyTemplate {
        name: "openai-org",
        description: "OpenAI Organization (API Key + Org ID + Project ID)",
        provider: "openai",
        keys: &[
            TemplateKey {
                env_var: "OPENAI_API_KEY",
                description: "API Key",
                is_secret: true,
            },
            TemplateKey {
                env_var: "OPENAI_ORG_ID",
                description: "Organization ID",
                is_secret: false,
            },
            TemplateKey {
                env_var: "OPENAI_PROJECT_ID",
                description: "Project ID",
                is_secret: false,
            },
        ],
        apply_url: "https://platform.openai.com/api-keys",
    },
    KeyTemplate {
        name: "stripe-connect",
        description: "Stripe Connect (Secret Key + Connect Client ID + Webhook Secret)",
        provider: "stripe",
        keys: &[
            TemplateKey {
                env_var: "STRIPE_SECRET_KEY",
                description: "Secret Key (sk_)",
                is_secret: true,
            },
            TemplateKey {
                env_var: "STRIPE_CONNECT_CLIENT_ID",
                description: "Connect Platform Client ID (ca_)",
                is_secret: false,
            },
            TemplateKey {
                env_var: "STRIPE_CONNECT_WEBHOOK_SECRET",
                description: "Connect Webhook Signing Secret",
                is_secret: true,
            },
        ],
        apply_url: "https://dashboard.stripe.com/settings/connect",
    },
];

/// Convert a SecretEntry to a JSON metadata representation (no secret value).
/// Shared by MCP server and Web dashboard.
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
        "last_verified_at": entry
            .last_verified_at
            .map(|d| d.format("%Y-%m-%d").to_string()),
        "metadata_gaps": entry.metadata_gaps(),
        "source_quality": entry.source_quality().to_string(),
        "scopes": entry.scopes,
        "projects": entry.projects,
        "key_group": entry.key_group,
        "apply_url": entry.apply_url,
        "status": entry.status().to_string(),
        "expires_at": entry.expires_at.map(|d| d.format("%Y-%m-%d").to_string()),
        "last_used_at": entry.last_used_at.map(|d| d.to_rfc3339()),
        "usage_hint": format!("Use via environment variable: {}", entry.env_var),
    })
}

/// Health report computed from a list of secrets.
/// Shared by MCP server and Web dashboard.
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

impl HealthReport {
    pub fn from_entries(entries: &[SecretEntry]) -> Self {
        let now = chrono::Utc::now();

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

        let duplicates = find_duplicate_groups(entries);
        let duplicate_groups: Vec<serde_json::Value> = duplicates
            .iter()
            .map(|g| serde_json::json!({"env_var": g.env_var, "names": g.names}))
            .collect();

        let active_entries: Vec<_> = entries.iter().filter(|e| e.is_active).collect();
        let mut source_quality: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for e in &active_entries {
            *source_quality
                .entry(e.source_quality().to_string())
                .or_insert(0) += 1;
        }

        let unverified_30 = active_entries
            .iter()
            .filter(|e| (30..60).contains(&e.unverified_days(now)))
            .count();
        let unverified_60 = active_entries
            .iter()
            .filter(|e| (60..90).contains(&e.unverified_days(now)))
            .count();
        let unverified_90 = active_entries
            .iter()
            .filter(|e| e.unverified_days(now) >= 90)
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

/// Infer provider from environment variable name.
/// Shared by MCP add_key and CLI import.
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
        for kw in *keywords {
            if upper.contains(kw) {
                return Some(provider);
            }
        }
    }
    None
}
