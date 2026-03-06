use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub env_var: String,
    pub provider: String,
    pub account_name: String,
    pub description: String,
    pub source: String,
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
];
