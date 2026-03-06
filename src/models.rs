use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub env_var: String,
    pub provider: String,
    pub description: String,
    pub scopes: Vec<String>,
    pub projects: Vec<String>,
    pub apply_url: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
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
