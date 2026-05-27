//! Import and scan pipeline types and helpers.
//!
//! This module owns the data structures, pure functions, and implementation
//! logic related to importing .env files and scanning directories for secrets.
//! The public methods on `SecretService` delegate here.

use anyhow::Result;
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

use crate::commands::helpers::{detect_project_name_in_dir, PROVIDERS, SKIP_VARS};
use crate::db::{Database, MetadataUpdate};
use crate::models::infer_provider;
use crate::models::SecretEntry;
use crate::services::errors::SecretError;

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
    pub provider: Provider,
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
    pub renamed: usize,
}

/// The action decided for a single candidate during import planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportAction {
    /// Insert as a brand new secret.
    Insert,
    /// Overwrite the value (and some metadata) of an existing secret.
    Overwrite { existing_id: String },
    /// Rename to avoid conflict (e.g. KEY-2, KEY-3...).
    Rename { new_name: String },
    /// Skip this candidate.
    Skip { reason: String },
}

/// A fully decided candidate ready for preview or execution.
#[derive(Debug, Clone)]
pub struct ImportCandidate {
    pub env_var: String,
    pub value: String,
    pub file: PathBuf,
    #[allow(dead_code)]
    pub detected_project: Option<String>,
    pub proposed_name: String,
    pub action: ImportAction,
    /// The final projects that should be attached to this secret (after override logic).
    pub final_projects: Vec<String>,
}

#[derive(Default, Debug, Clone)]
pub struct ImportPlanSummary {
    pub total_candidates: usize,
    pub to_insert: usize,
    pub to_overwrite: usize,
    pub to_rename: usize,
    pub to_skip: usize,
}

#[derive(Debug, Clone)]
pub struct ImportPlan {
    pub candidates: Vec<ImportCandidate>,
    #[allow(dead_code)]
    pub summary: ImportPlanSummary,
    #[allow(dead_code)]
    pub on_conflict: String,
}

// --- Pure helpers ---

/// Newtype for the canonical (normalized) name used for duplicate detection.
/// Prepared for future stricter typing across the codebase (see Phase 4 direction in plan).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalName(pub String);

impl CanonicalName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CanonicalName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for CanonicalName {
    fn from(s: &str) -> Self {
        Self(s.to_lowercase().replace('_', "-"))
    }
}

impl AsRef<str> for CanonicalName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for CanonicalName {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(crate) fn canonical_name(env_var: &str) -> CanonicalName {
    CanonicalName::from(env_var)
}

/// Newtype for environment variable names (Phase 4 / C direction).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnvVarName(pub String);

/// High-value newtype for provider identifiers (e.g. "openai", "aws", "github").
/// This is the 3rd major newtype in the C direction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Provider(pub String);

impl Provider {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns true if this provider is in the known list (from helpers::PROVIDERS).
    pub fn is_known(&self) -> bool {
        PROVIDERS.contains(&self.0.as_str())
    }
}

impl From<&str> for Provider {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for Provider {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Provider {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Provider {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EnvVarName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for EnvVarName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for EnvVarName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for EnvVarName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EnvVarName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub(crate) fn parse_env_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, val) = line.split_once('=')?;
    let key = key.trim();
    let val = val.trim().trim_matches('"').trim_matches('\'');
    if key.is_empty() || val.is_empty() {
        return None;
    }
    Some((key.to_string(), val.to_string()))
}

pub(crate) fn project_overlaps(a: &[String], b: &[String]) -> bool {
    if a.is_empty() && b.is_empty() {
        return true;
    }
    a.iter().any(|p| b.contains(p))
}

/// Pure decision function: given existing secrets for a name and the desired projects + strategy,
/// decide what action to take.
fn decide_action(
    existing: &[SecretEntry],
    desired_projects: &[String],
    on_conflict: &str,
) -> ImportAction {
    let conflict = existing
        .iter()
        .find(|e| project_overlaps(&e.projects, desired_projects));

    match conflict {
        None => ImportAction::Insert,
        Some(c) => match on_conflict {
            "skip" => ImportAction::Skip {
                reason: "name already exists with overlapping project scope".to_string(),
            },
            "overwrite" => ImportAction::Overwrite {
                existing_id: c.id.clone(),
            },
            "rename" => {
                // The actual rename computation happens later with DB checks,
                // here we just mark the intent.
                ImportAction::Rename {
                    new_name: String::new(), // placeholder, resolved at apply time
                }
            }
            _ => ImportAction::Skip {
                reason: format!("invalid on_conflict strategy: {}", on_conflict),
            },
        },
    }
}

// --- Implementation functions (called by SecretService delegates) ---

pub fn collect_import_sources(path: &Path, recursive: bool) -> Result<Vec<ImportSource>> {
    if path.is_file() {
        return Ok(vec![ImportSource {
            path: path.to_path_buf(),
            project_name: path.parent().and_then(detect_project_name_in_dir),
        }]);
    }

    if !path.is_dir() {
        return Err(SecretError::PathNotFound {
            path: path.display().to_string(),
        }
        .into());
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
        return Err(SecretError::NoEnvFilesFound {
            path: path.display().to_string(),
        }
        .into());
    }
    Ok(files)
}

/// Build a complete import plan (decisions for every candidate).
/// This is the single source of truth for both preview and apply.
pub fn build_import_plan(db: &Database, request: &ImportRequest<'_>) -> Result<ImportPlan> {
    let sources = collect_import_sources(request.path, request.recursive)?;
    let mut candidates = Vec::new();

    for import_source in sources {
        let projects = match request.project_override {
            Some(project) => vec![project.to_string()],
            None => import_source
                .project_name
                .clone()
                .map(|name| vec![name])
                .unwrap_or_default(),
        };

        let content = fs::read_to_string(&import_source.path)?;

        for line in content.lines() {
            let Some((key, val)) = parse_env_line(line) else {
                continue;
            };

            let proposed_name = canonical_name(&key);
            let existing = db.get_secrets_by_name(proposed_name.as_str())?;
            let action = decide_action(&existing, &projects, request.on_conflict);

            candidates.push(ImportCandidate {
                env_var: key,
                value: val,
                file: import_source.path.clone(),
                detected_project: import_source.project_name.clone(),
                proposed_name: proposed_name.to_string(),
                action,
                // We store the *final* projects to use (override wins)
                final_projects: projects.clone(),
            });
        }
    }

    let mut summary = ImportPlanSummary {
        total_candidates: candidates.len(),
        ..Default::default()
    };

    for c in &candidates {
        match &c.action {
            ImportAction::Insert => summary.to_insert += 1,
            ImportAction::Overwrite { .. } => summary.to_overwrite += 1,
            ImportAction::Rename { .. } => summary.to_rename += 1,
            ImportAction::Skip { .. } => summary.to_skip += 1,
        }
    }

    Ok(ImportPlan {
        candidates,
        summary,
        on_conflict: request.on_conflict.to_string(),
    })
}

/// Execute a previously built plan.
pub fn apply_import_plan(
    db: &Database,
    plan: &ImportPlan,
    provider: impl Into<Provider>,
    account_name: &str,
    source_label_prefix: &str,
) -> Result<ImportStats> {
    let provider: Provider = provider.into();
    let mut stats = ImportStats::default();

    for cand in &plan.candidates {
        let mut final_name = cand.proposed_name.clone();
        let source_label = format!("{}:{}", source_label_prefix, cand.file.display());

        match &cand.action {
            ImportAction::Skip { .. } => {
                stats.skipped += 1;
                continue;
            }
            ImportAction::Overwrite { existing_id } => {
                db.update_secret_value(existing_id, &cand.value)?;
                db.update_secret_metadata(
                    existing_id,
                    &MetadataUpdate {
                        name: None,
                        provider: Some(provider.as_str()),
                        account_name: Some(account_name),
                        description: None,
                        source: Some(&source_label),
                        scopes: None,
                        projects: None,
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
            ImportAction::Rename { .. } => {
                let mut suffix = 2;
                loop {
                    let candidate = format!("{}-{}", cand.proposed_name, suffix);
                    if db.get_secrets_by_name(&candidate)?.is_empty() {
                        final_name = candidate;
                        break;
                    }
                    suffix += 1;
                }
                stats.renamed += 1;
            }
            ImportAction::Insert => {}
        }

        let now = Utc::now();
        let entry = SecretEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name: final_name,
            env_var: cand.env_var.clone(),
            provider: provider.to_string(),  // keep SecretEntry as String for now (gradual adoption)
            account_name: account_name.to_string(),
            org_name: String::new(),
            description: format!("Imported from {}", cand.file.display()),
            source: source_label,
            environment: String::new(),
            permission_profile: String::new(),
            scopes: vec![],
            projects: cand.final_projects.clone(),
            apply_url: String::new(),
            expires_at: None,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            last_verified_at: Some(now),
            is_active: true,
        };

        db.add_secret(&entry, &cand.value)?;
        stats.imported += 1;
    }

    Ok(stats)
}

// Legacy thin wrapper kept for backward compatibility
pub fn import_path(db: &Database, request: ImportRequest<'_>) -> Result<ImportStats> {
    let plan = build_import_plan(db, &request)?;
    apply_import_plan(db, &plan, request.provider, request.account_name, "import")
}

pub fn scan_path(
    db: &Database,
    path: &Path,
    recursive: bool,
    skip_common: bool,
    new_only: bool,
) -> Result<Vec<ScanCandidate>> {
    let sources = collect_import_sources(path, recursive)?;
    let mut candidates = Vec::new();

    for source in sources {
        let content = fs::read_to_string(&source.path)?;
        for line in content.lines() {
            let Some((env_var, _)) = parse_env_line(line) else {
                continue;
            };
            if env_var.is_empty() {
                continue;
            }
            if skip_common && SKIP_VARS.contains(&env_var.to_uppercase().as_str()) {
                continue;
            }
            if new_only {
                let name = canonical_name(&env_var);
                if !db.get_secrets_by_name(name.as_str())?.is_empty() {
                    continue;
                }
            }
            candidates.push(ScanCandidate {
                env_var: env_var.to_string(),
                provider: Provider::from(infer_provider(&env_var).unwrap_or("other")),
                file: source.path.clone(),
                project_name: source.project_name.clone(),
            });
        }
    }

    Ok(candidates)
}

pub fn scan_and_import_path(
    db: &Database,
    request: ScanImportRequest<'_>,
) -> Result<ScanImportResult> {
    // First, produce the (possibly filtered) preview candidates the user sees
    let preview_candidates = scan_path(
        db,
        request.path,
        request.recursive,
        request.skip_common,
        request.new_only,
    )?;

    let import_stats = if request.apply && !preview_candidates.is_empty() {
        // When applying from scan, we still go through the full plan path
        // so conflict decisions are consistent.
        let import_req = ImportRequest {
            path: request.path,
            provider: request.provider,
            account_name: request.account_name,
            project_override: request.project_override,
            source: request.source,
            on_conflict: request.on_conflict,
            recursive: request.recursive,
        };
        let plan = build_import_plan(db, &import_req)?;
        Some(apply_import_plan(
            db,
            &plan,
            request.provider,
            request.account_name,
            "scan",
        )?)
    } else {
        None
    };

    Ok(ScanImportResult {
        candidates: preview_candidates,
        import_stats,
    })
}
