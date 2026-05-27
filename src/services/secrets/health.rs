//! Health reporting, readiness checks, and related logic.
//!
//! This module owns the health and readiness domain after extraction
//! from the main SecretService (following the pattern of import.rs and search.rs).

use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

use crate::commands::helpers::infer_required_env_vars;
use crate::db::Database;
use crate::models::{
    find_duplicate_groups, DuplicateGroup, HealthReport, HealthSummary, KeyStatus, ListFilter,
    SecretEntry,
};

#[derive(Debug, Clone, Serialize)]
pub struct HealthView {
    pub entries: Vec<SecretEntry>,
    pub report: HealthReport,
    pub summary: HealthSummary,
    pub expired: Vec<SecretEntry>,
    pub expiring: Vec<SecretEntry>,
    pub duplicates: Vec<DuplicateGroup>,
    pub provider_old_keys: Vec<(String, Vec<String>)>,
    pub unverified_30: Vec<String>,
    pub unverified_60: Vec<String>,
    pub unverified_90: Vec<String>,
    pub unused: Vec<(String, i64)>,
    pub metadata_gaps: Vec<(String, Vec<&'static str>)>,
    pub inactive: Vec<String>,
}

impl HealthView {
    pub fn to_mcp_json(&self) -> serde_json::Value {
        let duplicates: Vec<serde_json::Value> = self
            .duplicates
            .iter()
            .map(|group| serde_json::json!({ "env_var": group.env_var, "names": group.names }))
            .collect();

        let provider_old_keys: Vec<serde_json::Value> = self
            .provider_old_keys
            .iter()
            .map(|(provider, keys)| serde_json::json!({ "provider": provider, "keys": keys }))
            .collect();

        let status = if self.summary.expiry_issues == 0
            && self.summary.duplicate_count == 0
            && self.summary.inactive_count == 0
            && self.summary.metadata_review_count == 0
            && self.summary.unused_count == 0
        {
            "ok"
        } else {
            "attention"
        };

        serde_json::json!({
            "summary": self.summary,
            "status": status,
            "expired": { "count": self.report.expired.len(), "keys": self.report.expired },
            "expiring": { "count": self.report.expiring_soon.len(), "keys": self.report.expiring_soon },
            "unused": { "count": self.report.unused_30d.len(), "keys": self.report.unused_30d },
            "inactive": { "count": self.report.inactive.len(), "keys": self.report.inactive },
            "metadata_gaps": { "count": self.report.metadata_review.len(), "keys": self.report.metadata_review },
            "duplicates": { "count": duplicates.len(), "groups": duplicates },
            "provider_old_keys": { "count": provider_old_keys.len(), "groups": provider_old_keys },
            "source_quality": self.report.source_quality,
            "unverified": {
                "30_59_days": { "count": self.unverified_30.len(), "names": &self.unverified_30 },
                "60_89_days": { "count": self.unverified_60.len(), "names": &self.unverified_60 },
                "90_plus_days": { "count": self.unverified_90.len(), "names": &self.unverified_90 },
            }
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessAvailable {
    pub env_var: String,
    pub name: String,
    pub status: String,
    pub expires_at: Option<String>,
    pub severity: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessMissing {
    pub env_var: String,
    pub suggestion: String,
    pub severity: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessExpired {
    pub env_var: String,
    pub name: String,
    pub status: String,
    pub expires_at: Option<String>,
    pub apply_url: String,
    pub severity: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessReport {
    pub project: String,
    pub mode: String,
    pub status: String,
    pub ready: bool,
    pub summary: String,
    pub required_vars: Vec<String>,
    pub inference_sources: Vec<String>,
    pub available: Vec<ReadinessAvailable>,
    pub attention: Vec<ReadinessAvailable>,
    pub missing: Vec<ReadinessMissing>,
    pub expired: Vec<ReadinessExpired>,
    pub actions: Vec<String>,
    pub human_summary: String,
    pub next_steps: Vec<String>,
    pub total_required: usize,
    pub total_available: usize,
    pub healthy_count: usize,
    pub attention_count: usize,
    pub missing_count: usize,
    pub expired_count: usize,
}

#[allow(dead_code)]
pub(crate) fn readiness_priority(entry: &SecretEntry) -> i32 {
    match entry.status() {
        KeyStatus::Active => 5,
        KeyStatus::ExpiringSoon => 4,
        KeyStatus::Unknown => 3,
        KeyStatus::Inactive => 2,
        KeyStatus::Expired => 1,
    }
}

#[allow(dead_code)]
pub(crate) fn best_entry_for_env_var<'a>(entries: &[&'a SecretEntry]) -> Option<&'a SecretEntry> {
    entries.iter().copied().max_by(|a, b| {
        readiness_priority(a)
            .cmp(&readiness_priority(b))
            .then_with(|| {
                b.last_verified_at
                    .unwrap_or(b.created_at)
                    .cmp(&a.last_verified_at.unwrap_or(a.created_at))
            })
    })
}

pub fn health_report(
    db: &Database,
) -> anyhow::Result<(Vec<SecretEntry>, HealthReport, HealthSummary)> {
    let entries = db.list_secrets(&ListFilter {
        inactive: true,
        ..Default::default()
    })?;
    let report = HealthReport::from_entries(&entries);
    let summary = HealthSummary::from_report(&report, entries.len());
    Ok((entries, report, summary))
}

pub fn health_view(db: &Database) -> anyhow::Result<HealthView> {
    let (entries, report, summary) = health_report(db)?;
    let now = Utc::now();

    let expired = entries
        .iter()
        .filter(|entry| matches!(entry.status(), KeyStatus::Expired))
        .cloned()
        .collect();
    let expiring = entries
        .iter()
        .filter(|entry| matches!(entry.status(), KeyStatus::ExpiringSoon))
        .cloned()
        .collect();
    let duplicates = find_duplicate_groups(&entries);

    let mut by_provider: HashMap<String, Vec<String>> = HashMap::new();
    for entry in &entries {
        if entry.is_active && !entry.provider.is_empty() && entry.is_unused_for_days(now, 60) {
            by_provider
                .entry(entry.provider.clone())
                .or_default()
                .push(entry.name.clone());
        }
    }
    let provider_old_keys = by_provider
        .into_iter()
        .filter(|(_, keys)| keys.len() > 1)
        .collect();

    let active_entries: Vec<_> = entries.iter().filter(|entry| entry.is_active).collect();
    let unverified_30 = active_entries
        .iter()
        .filter(|entry| (30..60).contains(&entry.unverified_days(now)))
        .map(|entry| entry.name.clone())
        .collect();
    let unverified_60 = active_entries
        .iter()
        .filter(|entry| (60..90).contains(&entry.unverified_days(now)))
        .map(|entry| entry.name.clone())
        .collect();
    let unverified_90 = active_entries
        .iter()
        .filter(|entry| entry.unverified_days(now) >= 90)
        .map(|entry| entry.name.clone())
        .collect();
    let unused = entries
        .iter()
        .filter(|entry| entry.is_unused_for_days(now, 30))
        .map(|entry| (entry.name.clone(), entry.days_since_last_seen(now)))
        .collect();
    let metadata_gaps = entries
        .iter()
        .filter(|entry| entry.is_active && entry.has_metadata_gaps())
        .map(|entry| (entry.name.clone(), entry.metadata_gaps()))
        .collect();
    let inactive = entries
        .iter()
        .filter(|entry| !entry.is_active)
        .map(|entry| entry.name.clone())
        .collect();

    Ok(HealthView {
        entries,
        report,
        summary,
        expired,
        expiring,
        duplicates,
        provider_old_keys,
        unverified_30,
        unverified_60,
        unverified_90,
        unused,
        metadata_gaps,
        inactive,
    })
}

pub fn check_project_readiness(
    db: &Database,
    project: &str,
    required_vars: &[String],
    path: Option<&str>,
) -> anyhow::Result<ReadinessReport> {
    let discovery_path = path.unwrap_or(".");
    let inferred = if required_vars.is_empty() {
        Some(infer_required_env_vars(Path::new(discovery_path)))
    } else {
        None
    };
    let required_vars = inferred
        .as_ref()
        .map(|inferred| inferred.vars.clone())
        .unwrap_or_else(|| required_vars.to_vec());

    let entries = db.list_secrets(&ListFilter {
        project: Some(project.to_string()),
        ..Default::default()
    })?;
    let mut entries_by_env = HashMap::<String, Vec<&SecretEntry>>::new();
    for entry in &entries {
        entries_by_env
            .entry(entry.env_var.clone())
            .or_default()
            .push(entry);
    }

    let mut available = Vec::new();
    let mut attention = Vec::new();
    let mut missing = Vec::new();
    let mut expired = Vec::new();
    let mut actions = Vec::new();

    for env_var in &required_vars {
        match entries_by_env
            .get(env_var)
            .and_then(|candidates| best_entry_for_env_var(candidates))
        {
            Some(entry) => match entry.status() {
                KeyStatus::Expired => expired.push(ReadinessExpired {
                    env_var: env_var.clone(),
                    name: entry.name.clone(),
                    status: "expired".to_string(),
                    expires_at: entry.expires_at.map(|d| d.to_rfc3339()),
                    apply_url: entry.apply_url.clone(),
                    severity: "blocked".to_string(),
                    reason: "Attached key is expired and must be rotated before use.".to_string(),
                }),
                KeyStatus::ExpiringSoon => attention.push(ReadinessAvailable {
                    env_var: env_var.clone(),
                    name: entry.name.clone(),
                    status: "expiring_soon".to_string(),
                    expires_at: entry.expires_at.map(|d| d.to_rfc3339()),
                    severity: "warning".to_string(),
                    reason: "Attached key exists but expires soon. Rotate it proactively."
                        .to_string(),
                }),
                KeyStatus::Inactive => attention.push(ReadinessAvailable {
                    env_var: env_var.clone(),
                    name: entry.name.clone(),
                    status: "inactive".to_string(),
                    expires_at: None,
                    severity: "warning".to_string(),
                    reason: "Attached key exists but is inactive.".to_string(),
                }),
                KeyStatus::Unknown => attention.push(ReadinessAvailable {
                    env_var: env_var.clone(),
                    name: entry.name.clone(),
                    status: "unknown".to_string(),
                    expires_at: None,
                    severity: "warning".to_string(),
                    reason: "Attached key exists but its health is unclear.".to_string(),
                }),
                _ => available.push(ReadinessAvailable {
                    env_var: env_var.clone(),
                    name: entry.name.clone(),
                    status: "ok".to_string(),
                    expires_at: None,
                    severity: "healthy".to_string(),
                    reason: "Attached key is available for this project.".to_string(),
                }),
            },
            None => {
                let suggestion =
                    format!("Run: kf add {} \"<value>\" --projects {}", env_var, project);
                missing.push(ReadinessMissing {
                    env_var: env_var.clone(),
                    suggestion,
                    severity: "blocked".to_string(),
                    reason: "No attached key found for this required env var.".to_string(),
                });
            }
        }
    }

    if !missing.is_empty() {
        actions.push("Add the missing required keys to this project.".to_string());
    }
    if !expired.is_empty() {
        actions.push("Rotate expired keys before running the project.".to_string());
    }
    if !attention.is_empty() {
        actions.push("Review keys that are expiring soon or inactive.".to_string());
    }

    let is_ready = missing.is_empty() && expired.is_empty();
    let status = if !missing.is_empty() || !expired.is_empty() {
        "blocked"
    } else if !attention.is_empty() {
        "attention"
    } else {
        "ready"
    }
    .to_string();

    let human_summary = if is_ready && attention.is_empty() {
        format!(
            "Project '{}' is fully ready. All {} required secrets are healthy.",
            project,
            required_vars.len()
        )
    } else if is_ready {
        let attention_names: Vec<&str> =
            attention.iter().map(|item| item.env_var.as_str()).collect();
        format!(
            "Project '{}' can run but {} keys need attention: {}.",
            project,
            attention.len(),
            attention_names.join(", ")
        )
    } else {
        let missing_names: Vec<&str> = missing.iter().map(|item| item.env_var.as_str()).collect();
        let expired_names: Vec<&str> = expired.iter().map(|item| item.env_var.as_str()).collect();
        let mut parts = Vec::new();
        if !missing_names.is_empty() {
            parts.push(format!("missing: {}", missing_names.join(", ")));
        }
        if !expired_names.is_empty() {
            parts.push(format!("expired: {}", expired_names.join(", ")));
        }
        format!(
            "Project '{}' is NOT ready. {} out of {} required keys have issues. {}",
            project,
            missing.len() + expired.len(),
            required_vars.len(),
            parts.join("; ")
        )
    };

    let next_steps = missing
        .iter()
        .map(|item| item.suggestion.clone())
        .chain(expired.iter().map(|item| {
            if item.apply_url.is_empty() {
                format!("Rotate '{}' - expired key needs replacement", item.name)
            } else {
                format!("Rotate '{}' - renew at {}", item.name, item.apply_url)
            }
        }))
        .collect::<Vec<_>>();

    let summary = if status == "ready" {
        format!(
            "All {} required secrets are available and healthy",
            required_vars.len()
        )
    } else if status == "attention" {
        format!(
            "All {} required secrets exist, but {} need review",
            required_vars.len(),
            attention.len()
        )
    } else {
        format!(
            "{} missing, {} expired out of {} required",
            missing.len(),
            expired.len(),
            required_vars.len()
        )
    };

    let total_required = required_vars.len();
    Ok(ReadinessReport {
        project: project.to_string(),
        mode: if inferred.is_some() {
            "inferred".to_string()
        } else {
            "explicit".to_string()
        },
        status,
        ready: is_ready,
        summary,
        required_vars,
        inference_sources: inferred
            .as_ref()
            .map(|requirements| requirements.sources.clone())
            .unwrap_or_default(),
        available: available.clone(),
        attention: attention.clone(),
        missing: missing.clone(),
        expired: expired.clone(),
        actions,
        human_summary,
        next_steps,
        total_required,
        total_available: available.len() + attention.len(),
        healthy_count: available.len(),
        attention_count: attention.len(),
        missing_count: missing.len(),
        expired_count: expired.len(),
    })
}
