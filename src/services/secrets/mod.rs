use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

use crate::commands::helpers::{
    discover_project_context as discover_helper_project_context, infer_required_env_vars,
    parse_date,
};
use crate::db::{Database, MetadataUpdate};
use crate::models::infer_provider;
use crate::models::{HealthReport, HealthSummary, ListFilter, SecretEntry};
use crate::services::errors::SecretError;

mod health;
mod import;
mod search;

pub use import::{
    ImportRequest, ImportSource, ImportStats, ScanCandidate, ScanImportRequest, ScanImportResult,
};
pub(crate) use search::{clamp_limit, normalized_offset, paginate_items, rank_entries_for_query};
pub use search::{RankedSecretEntry, SearchFilter, SearchResult};

// Re-export the pure helpers so the rest of the module (and tests) can use the canonical versions.
pub use import::{CanonicalName, EnvVarName, Provider};
pub(crate) use import::canonical_name; // used by create_secret for name normalization + validation

pub struct SecretDraft {
    pub env_var: String,
    pub value: String,
    pub provider: Provider,
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
    pub name: Option<String>,
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

impl SecretUpdate {
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }
    pub fn with_account_name(mut self, account_name: impl Into<String>) -> Self {
        self.account_name = Some(account_name.into());
        self
    }
    pub fn with_org_name(mut self, org_name: impl Into<String>) -> Self {
        self.org_name = Some(org_name.into());
        self
    }
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }
    pub fn with_environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }
    pub fn with_permission_profile(mut self, permission_profile: impl Into<String>) -> Self {
        self.permission_profile = Some(permission_profile.into());
        self
    }
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = Some(scopes);
        self
    }
    pub fn with_projects(mut self, projects: Vec<String>) -> Self {
        self.projects = Some(projects);
        self
    }
    pub fn with_apply_url(mut self, apply_url: impl Into<String>) -> Self {
        self.apply_url = Some(apply_url.into());
        self
    }
    pub fn with_expires_at(mut self, expires_at: Option<DateTime<Utc>>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
    pub fn with_active(mut self, active: bool) -> Self {
        self.active = Some(active);
        self
    }
    pub fn set_verify(mut self) -> Self {
        self.verify = true;
        self
    }
}

pub use health::{
    HealthView, ReadinessAvailable, ReadinessExpired, ReadinessMissing, ReadinessReport,
};

pub struct RunEnvResolution {
    pub project: Option<String>,
    pub env_pairs: Vec<(String, String)>,
}

pub struct SecretValueView {
    pub entry: SecretEntry,
    pub value: String,
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
        Ok(search::search_ranked_impl(entries, query, filter))
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
            .map(|query| rank_entries_for_query(filtered.as_mut_slice(), &canonical_name(query)))
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
        health::check_project_readiness(self.db(), project, required_vars, path)
    }

    pub fn health_report(&self) -> Result<(Vec<SecretEntry>, HealthReport, HealthSummary)> {
        health::health_report(self.db())
    }

    pub fn health_view(&self) -> Result<HealthView> {
        health::health_view(self.db())
    }

    pub fn update_secret(&self, id: &str, update: SecretUpdate) -> Result<()> {
        if let Some(new_name) = &update.name {
            let conflicts = self.db.get_secrets_by_name(new_name)?;
            let conflict = conflicts.iter().find(|e| e.id != id);
            if conflict.is_some() {
                return Err(SecretError::AlreadyExists {
                    name: new_name.clone(),
                    detail: String::new(),
                }
                .into());
            }
        }

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
                name: update.name.as_deref(),
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
        let name = canonical_name(&draft.env_var);

        let existing = self.db.get_secrets_by_name(name.as_str())?;
        if draft.projects.is_empty() {
            if existing.iter().any(|e| e.projects.is_empty()) {
                return Err(SecretError::AlreadyExists {
                    name: name.to_string(),
                    detail: format!("global key — run `kf update {name}` to modify"),
                }
                .into());
            }
        } else {
            for entry in &existing {
                for project in &draft.projects {
                    if entry.projects.contains(project) {
                        return Err(SecretError::AlreadyExists {
                            name: name.to_string(),
                            detail: format!("project '{project}' — run `kf update` to modify"),
                        }
                        .into());
                    }
                }
            }
        }

        let now = Utc::now();
        let entry = SecretEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            env_var: draft.env_var,
            provider: draft.provider.to_string(),
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
        import::collect_import_sources(path, recursive)
    }

    pub fn import_path(&self, request: ImportRequest<'_>) -> Result<ImportStats> {
        import::import_path(self.db(), request)
    }

    pub fn build_import_plan(&self, request: &ImportRequest<'_>) -> Result<import::ImportPlan> {
        import::build_import_plan(self.db(), request)
    }

    pub fn apply_import_plan(
        &self,
        plan: &import::ImportPlan,
        provider: &str,
        account_name: &str,
        source_prefix: &str,
    ) -> Result<ImportStats> {
        import::apply_import_plan(self.db(), plan, provider, account_name, source_prefix)
    }

    pub fn scan_path(
        &self,
        path: &Path,
        recursive: bool,
        skip_common: bool,
        new_only: bool,
    ) -> Result<Vec<ScanCandidate>> {
        import::scan_path(self.db(), path, recursive, skip_common, new_only)
    }

    pub fn scan_and_import_path(&self, request: ScanImportRequest<'_>) -> Result<ScanImportResult> {
        import::scan_and_import_path(self.db(), request)
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

pub fn validate_env_var_name(name: &str) -> Result<EnvVarName> {
    if name.is_empty() {
        return Err(SecretError::EnvVarNameEmpty.into());
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(SecretError::InvalidEnvVarName(name.to_string()).into());
    }
    Ok(EnvVarName::from(name))
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
