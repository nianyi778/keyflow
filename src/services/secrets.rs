use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::helpers::{detect_project_name_in_dir, parse_date, SKIP_VARS};
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

#[derive(Clone)]
pub struct ScanCandidate {
    pub env_var: String,
    pub provider: String,
    pub file: PathBuf,
    pub project_name: Option<String>,
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
    pub projects: Vec<String>,
    pub apply_url: String,
    pub expires_at: Option<DateTime<Utc>>,
}

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

    pub fn get_entry(&self, name: &str) -> Result<SecretEntry> {
        self.db.get_secret(name)
    }

    pub fn get_secret_value(&self, name: &str) -> Result<String> {
        self.db.get_secret_value(name)
    }

    pub fn inspect_secret(&self, name: &str) -> Result<SecretValueView> {
        Ok(SecretValueView {
            entry: self.get_entry(name)?,
            value: self.get_secret_value(name)?,
        })
    }

    pub fn remove_secret(&self, name: &str) -> Result<bool> {
        self.db.remove_secret(name)
    }

    pub fn secret_exists(&self, name: &str) -> Result<bool> {
        self.db.secret_exists(name)
    }

    pub fn search_entries(&self, query: &str) -> Result<Vec<SecretEntry>> {
        self.db.search_secrets(query)
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

    pub fn update_secret(&self, name: &str, update: SecretUpdate) -> Result<()> {
        if let Some(value) = update.value {
            self.db.update_secret_value(name, &value)?;
        }

        let last_verified_at = if update.verify {
            Some(Some(Utc::now()))
        } else {
            None
        };

        self.db.update_secret_metadata(
            name,
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
            self.db.update_secret_metadata(
                name,
                &MetadataUpdate {
                    last_verified_at: Some(Some(now)),
                    ..Default::default()
                },
            )?;
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
        if self.db.secret_exists(&name)? {
            bail!(
                "Secret '{}' already exists. Use 'kf update {}' to modify.",
                name,
                name
            );
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
            scopes: vec![],
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
            if self.db.secret_exists(&name)? {
                match on_conflict {
                    "skip" => {
                        stats.skipped += 1;
                        continue;
                    }
                    "overwrite" => {
                        self.db.update_secret_value(&name, val)?;
                        self.db.update_secret_metadata(
                            &name,
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
                            if !self.db.secret_exists(&candidate)? {
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
                    if self.db.secret_exists(&name)? {
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
                self.db.get_secret_value(&entry.name)?
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
