use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::helpers::{
    detect_project_name_in_dir, discover_project_context as discover_helper_project_context,
    infer_required_env_vars, parse_date, SKIP_VARS,
};
use crate::db::{Database, MetadataUpdate};
use crate::models::infer_provider;
use crate::models::{
    find_duplicate_groups, DuplicateGroup, HealthReport, HealthSummary, KeyStatus, ListFilter,
    SecretEntry,
};

#[derive(Clone)]
pub struct ImportSource {
    pub path: PathBuf,
    pub project_name: Option<String>,
}

pub struct ImportRequest<'a> {
    pub path: &'a Path,
    pub provider: &'a str,
    pub account_name: &'a str,
    pub project_override: Option<&'a str>,
    pub source: Option<&'a str>,
    pub on_conflict: &'a str,
    pub recursive: bool,
}

pub struct ScanImportRequest<'a> {
    pub path: &'a Path,
    pub recursive: bool,
    pub skip_common: bool,
    pub new_only: bool,
    pub apply: bool,
    pub provider: &'a str,
    pub account_name: &'a str,
    pub project_override: Option<&'a str>,
    pub source: Option<&'a str>,
    pub on_conflict: &'a str,
}

#[derive(Clone)]
pub struct ScanCandidate {
    pub env_var: String,
    pub provider: String,
    pub file: PathBuf,
    pub project_name: Option<String>,
}

pub struct ScanImportResult {
    pub candidates: Vec<ScanCandidate>,
    pub import_stats: Option<ImportStats>,
}

#[derive(Default)]
pub struct ImportStats {
    pub imported: usize,
    pub overwritten: usize,
    pub skipped: usize,
}

pub struct SecretDraft {
    pub env_var: String,
    pub value: String,
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
}

#[derive(Default)]
pub struct SecretUpdate {
    pub value: Option<String>,
    pub provider: Option<String>,
    pub account_name: Option<String>,
    pub org_name: Option<String>,
    pub description: Option<String>,
    pub source: Option<String>,
    pub environment: Option<String>,
    pub permission_profile: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub projects: Option<Vec<String>>,
    pub apply_url: Option<String>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub active: Option<bool>,
    pub verify: bool,
}

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

pub struct RunEnvResolution {
    pub project: Option<String>,
    pub env_pairs: Vec<(String, String)>,
}

pub struct SecretValueView {
    pub entry: SecretEntry,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RankedSecretEntry {
    pub entry: SecretEntry,
    pub relevance_score: i64,
    pub matched_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SearchFilter {
    pub provider: Option<String>,
    pub project: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub include_inactive: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub found: bool,
    pub total: usize,
    pub count: usize,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub keys: Vec<RankedSecretEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderCount {
    pub provider: String,
    pub key_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectKeys {
    pub project: String,
    pub keys: Vec<String>,
    pub key_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectListResult {
    pub total: usize,
    pub count: usize,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub projects: Vec<ProjectKeys>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectKeysResult {
    pub project: String,
    pub total: usize,
    pub count: usize,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub keys: Vec<RankedSecretEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectContext {
    pub found: bool,
    pub path: String,
    pub project: Option<String>,
    pub root: Option<String>,
    pub detector: Option<String>,
    pub workspace_root: Option<String>,
    pub workspace_detector: Option<String>,
    pub required_vars: Vec<String>,
    pub inference_sources: Vec<String>,
    pub attached_secret_count: usize,
    pub attached_secret_names: Vec<String>,
    pub scan_roots: Vec<String>,
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

enum DbHolder<'a> {
    Owned(Box<Database>),
    Borrowed(&'a Database),
}

impl<'a> std::ops::Deref for DbHolder<'a> {
    type Target = Database;
    fn deref(&self) -> &Database {
        match self {
            DbHolder::Owned(db) => db,
            DbHolder::Borrowed(db) => db,
        }
    }
}

pub struct SecretService<'a> {
    db: DbHolder<'a>,
}

impl<'a> SecretService<'a> {
    pub fn new(db: Database) -> SecretService<'static> {
        SecretService {
            db: DbHolder::Owned(Box::new(db)),
        }
    }

    pub fn new_ref(db: &'a Database) -> Self {
        Self {
            db: DbHolder::Borrowed(db),
        }
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn list_entries(&self, filter: &ListFilter) -> Result<Vec<SecretEntry>> {
        self.db.list_secrets(filter)
    }

    pub fn get_entry_by_id(&self, id: &str) -> Result<SecretEntry> {
        self.db.get_secret_by_id(id)
    }

    pub fn get_entries_by_name(&self, name: &str) -> Result<Vec<SecretEntry>> {
        self.db.get_secrets_by_name(name)
    }

    pub fn get_secret_value(&self, id: &str) -> Result<String> {
        self.db.get_secret_value(id)
    }

    pub fn inspect_secret_by_id(&self, id: &str) -> Result<SecretValueView> {
        Ok(SecretValueView {
            entry: self.get_entry_by_id(id)?,
            value: self.get_secret_value(id)?,
        })
    }

    pub fn remove_secret(&self, id: &str) -> Result<bool> {
        self.db.remove_secret(id)
    }

    pub fn search_entries(&self, query: &str) -> Result<Vec<SecretEntry>> {
        self.db.search_secrets(query)
    }

    pub fn infer_provider_for_env_var(&self, env_var: &str) -> Option<String> {
        infer_provider(env_var).map(str::to_string)
    }

    pub fn detect_current_project_name(&self) -> Option<String> {
        discover_helper_project_context(Path::new(".")).map(|context| context.name)
    }

    pub fn search_ranked(&self, query: &str, filter: &SearchFilter) -> Result<SearchResult> {
        let entries = self.db.search_secrets(query)?;
        let mut filtered = entries
            .into_iter()
            .filter(|entry| filter.include_inactive || entry.is_active)
            .filter(|entry| {
                filter
                    .provider
                    .as_ref()
                    .is_none_or(|provider| entry.provider == *provider)
            })
            .filter(|entry| {
                filter
                    .project
                    .as_ref()
                    .is_none_or(|project| entry.projects.iter().any(|item| item == project))
            })
            .collect::<Vec<_>>();
        let scored = rank_entries_for_query(filtered.as_mut_slice(), query);
        let total = filtered.len();
        let limit = clamp_limit(filter.limit);
        let offset = normalized_offset(filter.offset);
        let keys = paginate_items(scored, filter.limit, filter.offset);

        Ok(SearchResult {
            found: !keys.is_empty(),
            total,
            count: keys.len(),
            limit,
            offset,
            has_more: offset + keys.len() < total,
            keys,
        })
    }

    pub fn list_project_keys(
        &self,
        project: &str,
        query: Option<&str>,
        provider: Option<&str>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<ProjectKeysResult> {
        let entries = self.db.list_secrets(&ListFilter {
            project: Some(project.to_string()),
            ..Default::default()
        })?;
        let mut filtered = entries
            .into_iter()
            .filter(|entry| provider.is_none_or(|provider| entry.provider == provider))
            .filter(|entry| {
                query.is_none_or(|query| {
                    entry.name.contains(query)
                        || entry.env_var.contains(query)
                        || entry.description.contains(query)
                        || entry.provider.contains(query)
                })
            })
            .collect::<Vec<_>>();

        let scored = query
            .map(|query| rank_entries_for_query(filtered.as_mut_slice(), query))
            .unwrap_or_else(|| {
                filtered.sort_by(|a, b| a.name.cmp(&b.name));
                filtered
                    .into_iter()
                    .map(|entry| RankedSecretEntry {
                        entry,
                        relevance_score: 0,
                        matched_fields: Vec::new(),
                    })
                    .collect::<Vec<_>>()
            });

        let total = scored.len();
        let limit_clamped = clamp_limit(limit);
        let offset_normalized = normalized_offset(offset);
        let keys = paginate_items(scored, limit, offset);

        Ok(ProjectKeysResult {
            project: project.to_string(),
            total,
            count: keys.len(),
            limit: limit_clamped,
            offset: offset_normalized,
            has_more: offset_normalized + keys.len() < total,
            keys,
        })
    }

    pub fn list_providers(&self) -> Result<Vec<ProviderCount>> {
        let entries = self.db.list_secrets(&ListFilter::default())?;
        let mut counts = HashMap::<String, usize>::new();
        for entry in entries {
            *counts.entry(entry.provider).or_default() += 1;
        }

        let mut providers = counts
            .into_iter()
            .map(|(provider, key_count)| ProviderCount {
                provider,
                key_count,
            })
            .collect::<Vec<_>>();
        providers.sort_by(|a, b| a.provider.cmp(&b.provider));
        Ok(providers)
    }

    pub fn list_projects(
        &self,
        query: Option<&str>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<ProjectListResult> {
        let entries = self.db.list_secrets(&ListFilter::default())?;
        let mut projects = HashMap::<String, Vec<String>>::new();
        for entry in entries {
            for project in entry.projects {
                projects
                    .entry(project)
                    .or_default()
                    .push(entry.name.clone());
            }
        }

        let mut values = projects
            .into_iter()
            .filter(|(project, _)| query.is_none_or(|query| project.contains(query)))
            .map(|(project, mut keys)| {
                keys.sort();
                ProjectKeys {
                    project,
                    key_count: keys.len(),
                    keys,
                }
            })
            .collect::<Vec<_>>();
        values.sort_by(|a, b| a.project.cmp(&b.project));
        let total = values.len();
        let limit_clamped = clamp_limit(limit);
        let offset_normalized = normalized_offset(offset);
        let projects = paginate_items(values, limit, offset);

        Ok(ProjectListResult {
            total,
            count: projects.len(),
            limit: limit_clamped,
            offset: offset_normalized,
            has_more: offset_normalized + projects.len() < total,
            projects,
        })
    }

    pub fn discover_project_context(
        &self,
        path: Option<&str>,
        project: Option<&str>,
    ) -> Result<ProjectContext> {
        let path = path.unwrap_or(".").to_string();
        let root = Path::new(&path);
        let context = discover_helper_project_context(root);
        let requirements = infer_required_env_vars(root);

        let project_name = project
            .map(str::to_string)
            .or_else(|| context.as_ref().map(|ctx| ctx.name.clone()));
        let attached = if let Some(project) = &project_name {
            self.db.list_secrets(&ListFilter {
                project: Some(project.clone()),
                ..Default::default()
            })?
        } else {
            Vec::new()
        };

        Ok(ProjectContext {
            found: context.is_some(),
            path: path.clone(),
            project: project_name,
            root: context.as_ref().map(|ctx| ctx.root.display().to_string()),
            detector: context.as_ref().map(|ctx| ctx.detector.to_string()),
            workspace_root: context
                .as_ref()
                .and_then(|ctx| ctx.workspace_root.as_ref())
                .map(|workspace_root| workspace_root.display().to_string()),
            workspace_detector: context
                .as_ref()
                .and_then(|ctx| ctx.workspace_detector)
                .map(str::to_string),
            required_vars: requirements.vars,
            inference_sources: requirements.sources,
            attached_secret_count: attached.len(),
            attached_secret_names: attached.into_iter().map(|entry| entry.name).collect(),
            scan_roots: context
                .as_ref()
                .map(|ctx| {
                    let mut roots = vec![ctx.root.display().to_string()];
                    if let Some(workspace_root) = &ctx.workspace_root {
                        roots.push(workspace_root.display().to_string());
                    }
                    roots
                })
                .unwrap_or_else(|| vec![path]),
        })
    }

    pub fn check_project_readiness(
        &self,
        project: &str,
        required_vars: &[String],
        path: Option<&str>,
    ) -> Result<ReadinessReport> {
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

        let entries = self.db.list_secrets(&ListFilter {
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
                        reason: "Attached key is expired and must be rotated before use."
                            .to_string(),
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
            let missing_names: Vec<&str> =
                missing.iter().map(|item| item.env_var.as_str()).collect();
            let expired_names: Vec<&str> =
                expired.iter().map(|item| item.env_var.as_str()).collect();
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

    pub fn health_report(&self) -> Result<(Vec<SecretEntry>, HealthReport, HealthSummary)> {
        let entries = self.db.list_secrets(&ListFilter {
            inactive: true,
            ..Default::default()
        })?;
        let report = HealthReport::from_entries(&entries);
        let summary = HealthSummary::from_report(&report, entries.len());
        Ok((entries, report, summary))
    }

    pub fn health_view(&self) -> Result<HealthView> {
        let (entries, report, summary) = self.health_report()?;
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

        let mut by_provider: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
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

    pub fn update_secret(&self, id: &str, update: SecretUpdate) -> Result<()> {
        if let Some(value) = update.value {
            self.db.update_secret_value(id, &value)?;
        }

        let last_verified_at = if update.verify {
            Some(Some(Utc::now()))
        } else {
            None
        };

        self.db.update_secret_metadata(
            id,
            &MetadataUpdate {
                provider: update.provider.as_deref(),
                account_name: update.account_name.as_deref(),
                org_name: update.org_name.as_deref(),
                description: update.description.as_deref(),
                source: update.source.as_deref(),
                environment: update.environment.as_deref(),
                permission_profile: update.permission_profile.as_deref(),
                scopes: update.scopes.as_deref(),
                projects: update.projects.as_deref(),
                apply_url: update.apply_url.as_deref(),
                expires_at: update.expires_at,
                last_verified_at,
                is_active: update.active,
            },
        )?;

        Ok(())
    }

    pub fn verify_names(&self, names: &[String]) -> Result<DateTime<Utc>> {
        let now = Utc::now();
        for name in names {
            let entries = self.db.get_secrets_by_name(name)?;
            for entry in entries {
                self.db.update_secret_metadata(
                    &entry.id,
                    &MetadataUpdate {
                        last_verified_at: Some(Some(now)),
                        ..Default::default()
                    },
                )?;
            }
        }
        Ok(now)
    }

    pub fn all_secret_names(&self, include_inactive: bool) -> Result<Vec<String>> {
        self.db
            .list_secrets(&ListFilter {
                inactive: include_inactive,
                ..Default::default()
            })?
            .into_iter()
            .map(|entry| Ok(entry.name))
            .collect()
    }

    pub fn create_secret(&self, draft: SecretDraft) -> Result<SecretEntry> {
        let name = draft.env_var.to_lowercase().replace('_', "-");

        let existing = self.db.get_secrets_by_name(&name)?;
        if draft.projects.is_empty() {
            if existing.iter().any(|e| e.projects.is_empty()) {
                bail!(
                    "Secret '{}' already exists as a global key. Use 'kf update {}' to modify.",
                    name,
                    name
                );
            }
        } else {
            for entry in &existing {
                for project in &draft.projects {
                    if entry.projects.contains(project) {
                        bail!(
                            "Secret '{}' already exists for project '{}'. Use 'kf update' to modify.",
                            name,
                            project
                        );
                    }
                }
            }
        }

        let now = Utc::now();
        let entry = SecretEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            env_var: draft.env_var,
            provider: draft.provider,
            account_name: draft.account_name,
            org_name: draft.org_name,
            description: draft.description,
            source: draft.source,
            environment: draft.environment,
            permission_profile: draft.permission_profile,
            scopes: draft.scopes,
            projects: draft.projects,
            apply_url: draft.apply_url,
            expires_at: draft.expires_at,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            last_verified_at: Some(now),
            is_active: true,
        };

        self.db.add_secret(&entry, &draft.value)?;
        Ok(entry)
    }

    pub fn collect_import_sources(path: &Path, recursive: bool) -> Result<Vec<ImportSource>> {
        if path.is_file() {
            return Ok(vec![ImportSource {
                path: path.to_path_buf(),
                project_name: path.parent().and_then(detect_project_name_in_dir),
            }]);
        }

        if !path.is_dir() {
            bail!("Path not found: {}", path.display());
        }

        let mut files = Vec::new();
        if recursive {
            for entry in walkdir::WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_entry(|entry| {
                    let name = entry.file_name().to_str().unwrap_or("");
                    !name.starts_with('.') || name.starts_with(".env") || entry.depth() == 0
                })
            {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let candidate = entry.path();
                let Some(name) = candidate.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
                    files.push(ImportSource {
                        path: candidate.to_path_buf(),
                        project_name: candidate.parent().and_then(detect_project_name_in_dir),
                    });
                }
            }
        } else {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let candidate = entry.path();
                if !candidate.is_file() {
                    continue;
                }
                let Some(name) = candidate.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
                    files.push(ImportSource {
                        path: candidate,
                        project_name: detect_project_name_in_dir(path),
                    });
                }
            }
        }

        files.sort_by(|a, b| a.path.cmp(&b.path));
        if files.is_empty() {
            bail!("No .env files found in '{}'", path.display());
        }
        Ok(files)
    }

    pub fn import_path(&self, request: ImportRequest<'_>) -> Result<ImportStats> {
        let sources = Self::collect_import_sources(request.path, request.recursive)?;
        let mut totals = ImportStats::default();

        for import_source in sources {
            let projects = match request.project_override {
                Some(project) => vec![project.to_string()],
                None => import_source
                    .project_name
                    .clone()
                    .map(|name| vec![name])
                    .unwrap_or_default(),
            };

            let stats = self.import_env_file(
                &import_source.path,
                request.provider,
                request.account_name,
                &projects,
                request.source,
                request.on_conflict,
            )?;
            totals.imported += stats.imported;
            totals.overwritten += stats.overwritten;
            totals.skipped += stats.skipped;
        }

        Ok(totals)
    }

    fn import_env_file(
        &self,
        path: &Path,
        provider: &str,
        account_name: &str,
        projects: &[String],
        source: Option<&str>,
        on_conflict: &str,
    ) -> Result<ImportStats> {
        let content = fs::read_to_string(path)?;
        let mut stats = ImportStats::default();
        let source_label = source
            .map(str::to_string)
            .unwrap_or_else(|| format!("import:{}", path.display()));

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, val)) = line.split_once('=') else {
                continue;
            };

            let key = key.trim();
            let val = val.trim().trim_matches('"').trim_matches('\'');
            if key.is_empty() || val.is_empty() {
                continue;
            }

            let mut name = key.to_lowercase().replace('_', "-");
            let existing = self.db.get_secrets_by_name(&name)?;
            let conflict = existing.iter().find(|e| {
                projects.iter().any(|p| e.projects.contains(p))
                    || (projects.is_empty() && e.projects.is_empty())
            });

            if let Some(conflicting) = conflict {
                match on_conflict {
                    "skip" => {
                        stats.skipped += 1;
                        continue;
                    }
                    "overwrite" => {
                        self.db.update_secret_value(&conflicting.id, val)?;
                        self.db.update_secret_metadata(
                            &conflicting.id,
                            &MetadataUpdate {
                                provider: Some(provider),
                                account_name: Some(account_name),
                                description: None,
                                source: Some(&source_label),
                                scopes: None,
                                projects: Some(projects),
                                apply_url: None,
                                expires_at: None,
                                last_verified_at: Some(Some(Utc::now())),
                                is_active: Some(true),
                                org_name: None,
                                environment: None,
                                permission_profile: None,
                            },
                        )?;
                        stats.overwritten += 1;
                        continue;
                    }
                    "rename" => {
                        let mut suffix = 2;
                        loop {
                            let candidate = format!("{}-{}", name, suffix);
                            if self.db.get_secrets_by_name(&candidate)?.is_empty() {
                                name = candidate;
                                break;
                            }
                            suffix += 1;
                        }
                    }
                    _ => bail!("Invalid --on-conflict value. Use: skip, overwrite, rename"),
                }
            }

            let now = Utc::now();
            let entry = SecretEntry {
                id: uuid::Uuid::new_v4().to_string(),
                name,
                env_var: key.to_string(),
                provider: provider.to_string(),
                account_name: account_name.to_string(),
                org_name: String::new(),
                description: format!("Imported from {}", path.display()),
                source: source_label.clone(),
                environment: String::new(),
                permission_profile: String::new(),
                scopes: vec![],
                projects: projects.to_vec(),
                apply_url: String::new(),
                expires_at: None,
                created_at: now,
                updated_at: now,
                last_used_at: None,
                last_verified_at: Some(now),
                is_active: true,
            };

            self.db.add_secret(&entry, val)?;
            stats.imported += 1;
        }

        Ok(stats)
    }

    pub fn scan_path(
        &self,
        path: &Path,
        recursive: bool,
        skip_common: bool,
        new_only: bool,
    ) -> Result<Vec<ScanCandidate>> {
        let sources = Self::collect_import_sources(path, recursive)?;
        let mut candidates = Vec::new();

        for source in sources {
            let content = fs::read_to_string(&source.path)?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((key, _)) = line.split_once('=') else {
                    continue;
                };
                let env_var = key.trim();
                if env_var.is_empty() {
                    continue;
                }
                if skip_common && SKIP_VARS.contains(&env_var.to_uppercase().as_str()) {
                    continue;
                }
                if new_only {
                    let name = env_var.to_lowercase().replace('_', "-");
                    if !self.db.get_secrets_by_name(&name)?.is_empty() {
                        continue;
                    }
                }
                candidates.push(ScanCandidate {
                    env_var: env_var.to_string(),
                    provider: infer_provider(env_var).unwrap_or("other").to_string(),
                    file: source.path.clone(),
                    project_name: source.project_name.clone(),
                });
            }
        }

        Ok(candidates)
    }

    pub fn scan_and_import_path(&self, request: ScanImportRequest<'_>) -> Result<ScanImportResult> {
        let candidates = self.scan_path(
            request.path,
            request.recursive,
            request.skip_common,
            request.new_only,
        )?;

        let import_stats = if request.apply && !candidates.is_empty() {
            Some(self.import_path(ImportRequest {
                path: request.path,
                provider: request.provider,
                account_name: request.account_name,
                project_override: request.project_override,
                source: request.source,
                on_conflict: request.on_conflict,
                recursive: false,
            })?)
        } else {
            None
        };

        Ok(ScanImportResult {
            candidates,
            import_stats,
        })
    }

    pub fn export_project_env(
        &self,
        project: Option<String>,
        environment: Option<String>,
    ) -> Result<(Vec<SecretEntry>, String)> {
        let entries = self.db.list_secrets(&ListFilter {
            project,
            environment,
            ..Default::default()
        })?;

        let mut lines = Vec::new();
        lines.push("# Generated by KeyFlow".to_string());
        lines.push(format!(
            "# Date: {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        lines.push(String::new());

        let mut current_provider = String::new();
        for entry in &entries {
            if entry.provider != current_provider {
                if !current_provider.is_empty() {
                    lines.push(String::new());
                }
                lines.push(format!("# === {} ===", entry.provider.to_uppercase()));
                current_provider = entry.provider.clone();
            }
            lines.push(format!(
                "{}={}",
                entry.env_var,
                self.db.get_secret_value(&entry.id)?
            ));
        }

        Ok((entries, lines.join("\n") + "\n"))
    }

    pub fn resolve_run_env_pairs(
        &self,
        project: Option<String>,
        all: bool,
        detected_project: Option<String>,
    ) -> Result<RunEnvResolution> {
        let project = if all {
            None
        } else {
            project.or(detected_project)
        };
        let env_pairs = self.db.get_all_for_env(project.as_deref())?;
        Ok(RunEnvResolution { project, env_pairs })
    }
}

fn clamp_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(20).clamp(1, 100)
}

fn normalized_offset(offset: Option<usize>) -> usize {
    offset.unwrap_or(0)
}

fn paginate_items<T>(items: Vec<T>, limit: Option<usize>, offset: Option<usize>) -> Vec<T> {
    let offset = normalized_offset(offset);
    let limit = clamp_limit(limit);
    items.into_iter().skip(offset).take(limit).collect()
}

fn rank_entries_for_query(entries: &mut [SecretEntry], query: &str) -> Vec<RankedSecretEntry> {
    let query = query.trim();
    let mut scored = entries
        .iter()
        .cloned()
        .map(|entry| {
            let (score, matched_fields) = score_entry(&entry, query);
            RankedSecretEntry {
                entry,
                relevance_score: score,
                matched_fields: matched_fields.into_iter().map(str::to_string).collect(),
            }
        })
        .collect::<Vec<_>>();
    scored.sort_by(|a, b| {
        b.relevance_score
            .cmp(&a.relevance_score)
            .then_with(|| b.entry.is_active.cmp(&a.entry.is_active))
            .then_with(|| {
                a.entry
                    .metadata_gaps()
                    .len()
                    .cmp(&b.entry.metadata_gaps().len())
            })
            .then_with(|| a.entry.name.cmp(&b.entry.name))
    });
    scored
}

fn score_entry(entry: &SecretEntry, query: &str) -> (i64, Vec<&'static str>) {
    let query_lower = query.to_ascii_lowercase();
    let query_upper = query.to_ascii_uppercase();
    let mut score = 0;
    let mut fields = Vec::new();

    let name_lower = entry.name.to_ascii_lowercase();
    let env_upper = entry.env_var.to_ascii_uppercase();
    let provider_lower = entry.provider.to_ascii_lowercase();
    let account_lower = entry.account_name.to_ascii_lowercase();
    let org_lower = entry.org_name.to_ascii_lowercase();
    let description_lower = entry.description.to_ascii_lowercase();

    if entry.name == query || name_lower == query_lower {
        score += 120;
        fields.push("name");
    } else if name_lower.contains(&query_lower) {
        score += 70;
        fields.push("name");
    }

    if entry.env_var == query || env_upper == query_upper {
        score += 140;
        fields.push("env_var");
    } else if env_upper.contains(&query_upper) {
        score += 90;
        fields.push("env_var");
    }

    if entry.provider == query || provider_lower == query_lower {
        score += 80;
        fields.push("provider");
    } else if provider_lower.contains(&query_lower) {
        score += 45;
        fields.push("provider");
    }

    if account_lower.contains(&query_lower) {
        score += 30;
        fields.push("account_name");
    }
    if org_lower.contains(&query_lower) {
        score += 25;
        fields.push("org_name");
    }
    if description_lower.contains(&query_lower) {
        score += 20;
        fields.push("description");
    }
    if entry.projects.iter().any(|project| {
        project.eq_ignore_ascii_case(query) || project.to_ascii_lowercase().contains(&query_lower)
    }) {
        score += 55;
        fields.push("projects");
    }
    if entry
        .scopes
        .iter()
        .any(|scope| scope.to_ascii_lowercase().contains(&query_lower))
    {
        score += 15;
        fields.push("scopes");
    }

    if entry.is_active {
        score += 5;
    }
    if matches!(entry.status(), KeyStatus::Expired) {
        score -= 15;
    }

    fields.sort_unstable();
    fields.dedup();
    (score, fields)
}

fn best_entry_for_env_var<'a>(entries: &[&'a SecretEntry]) -> Option<&'a SecretEntry> {
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

fn readiness_priority(entry: &SecretEntry) -> i32 {
    match entry.status() {
        KeyStatus::Active => 5,
        KeyStatus::ExpiringSoon => 4,
        KeyStatus::Unknown => 3,
        KeyStatus::Inactive => 2,
        KeyStatus::Expired => 1,
    }
}

pub fn validate_env_var_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("Environment variable name cannot be empty");
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!(
            "Invalid environment variable name '{}': only [A-Za-z0-9_] allowed",
            name
        );
    }
    Ok(())
}

pub fn parse_expires(expires: Option<String>) -> Result<Option<DateTime<Utc>>> {
    match expires {
        Some(value) => parse_date(&value),
        None => Ok(None),
    }
}

pub fn parse_optional_expires(expires: Option<String>) -> Result<Option<Option<DateTime<Utc>>>> {
    match expires {
        Some(value) if value.is_empty() => Ok(Some(None)),
        Some(value) => Ok(Some(parse_date(&value)?)),
        None => Ok(None),
    }
}
