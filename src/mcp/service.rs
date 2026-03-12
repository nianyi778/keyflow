use anyhow::{bail, Result};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use crate::commands::helpers::{discover_project_context, infer_required_env_vars};
use crate::db::Database;
use crate::models::{self, KeyStatus, ListFilter, SecretEntry};

pub struct VaultService<'a> {
    db: &'a Database,
}

impl<'a> VaultService<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn search_keys(&self, request: SearchKeysRequest) -> Result<Value> {
        let entries = self.db.search_secrets(&request.query)?;
        let mut filtered = entries
            .into_iter()
            .filter(|entry| request.include_inactive || entry.is_active)
            .filter(|entry| {
                request
                    .provider
                    .as_ref()
                    .is_none_or(|provider| entry.provider == *provider)
            })
            .filter(|entry| {
                request
                    .project
                    .as_ref()
                    .is_none_or(|project| entry.projects.iter().any(|item| item == project))
            })
            .collect::<Vec<_>>();
        let scored = rank_entries_for_query(filtered.as_mut_slice(), &request.query);
        let total = filtered.len();
        let keys = paginate_scored_entries(scored, request.limit, request.offset)
            .into_iter()
            .map(scored_entry_to_json)
            .collect::<Vec<_>>();
        Ok(json!({
            "found": !keys.is_empty(),
            "total": total,
            "count": keys.len(),
            "limit": clamp_limit(request.limit),
            "offset": request.offset.unwrap_or(0),
            "has_more": request.offset.unwrap_or(0) + keys.len() < total,
            "keys": keys
        }))
    }

    pub fn list_resources(&self) -> Result<Value> {
        let entries = self.db.list_secrets(&ListFilter {
            inactive: true,
            ..Default::default()
        })?;
        let mut project_names = entries
            .iter()
            .flat_map(|entry| entry.projects.clone())
            .collect::<Vec<_>>();
        project_names.sort();
        project_names.dedup();
        let mut provider_names = entries
            .iter()
            .map(|entry| entry.provider.clone())
            .filter(|provider| !provider.is_empty())
            .collect::<Vec<_>>();
        provider_names.sort();
        provider_names.dedup();

        let mut resources = vec![
            json!({
                "uri": "vault://summary",
                "name": "Vault Summary",
                "description": "High-level vault health, counts, and status.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "vault://providers",
                "name": "Provider Index",
                "description": "All providers with current key counts.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "vault://health",
                "name": "Vault Health",
                "description": "Structured vault health report and issue buckets.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "vault://projects",
                "name": "Project Index",
                "description": "All projects with attached key names and counts.",
                "mimeType": "application/json"
            }),
            json!({
                "uri": "vault://current-project",
                "name": "Current Project Context",
                "description": "Detected project context, inferred required env vars, and attached vault secrets for the current working tree.",
                "mimeType": "application/json"
            }),
        ];

        resources.extend(project_names.into_iter().map(|project| {
            json!({
                "uri": format!("vault://project/{project}"),
                "name": format!("Project: {project}"),
                "description": format!("Secrets attached to project '{project}'."),
                "mimeType": "application/json"
            })
        }));
        resources.extend(provider_names.into_iter().map(|provider| {
            json!({
                "uri": format!("vault://provider/{provider}"),
                "name": format!("Provider: {provider}"),
                "description": format!("Secrets and health context for provider '{provider}'."),
                "mimeType": "application/json"
            })
        }));

        Ok(json!({ "resources": resources }))
    }

    pub fn read_resource(&self, uri: &str) -> Result<Value> {
        let (resource_uri, name, body) = match uri {
            "vault://summary" => {
                let body = json!({
                    "health": self.check_health()?,
                    "providers": self.list_providers()?,
                    "projects": self.list_projects(ListProjectsRequest {
                        query: None,
                        limit: Some(100),
                        offset: Some(0),
                    })?
                });
                (
                    "vault://summary".to_string(),
                    "Vault Summary".to_string(),
                    body,
                )
            }
            "vault://providers" => (
                "vault://providers".to_string(),
                "Provider Index".to_string(),
                self.list_providers()?,
            ),
            "vault://health" => (
                "vault://health".to_string(),
                "Vault Health".to_string(),
                self.check_health()?,
            ),
            "vault://projects" => (
                "vault://projects".to_string(),
                "Project Index".to_string(),
                self.list_projects(ListProjectsRequest {
                    query: None,
                    limit: Some(100),
                    offset: Some(0),
                })?,
            ),
            "vault://current-project" => (
                "vault://current-project".to_string(),
                "Current Project Context".to_string(),
                self.discover_project_context(DiscoverProjectRequest {
                    path: Some(".".to_string()),
                    project: None,
                })?,
            ),
            _ if uri.starts_with("vault://project/") => {
                let project = uri.trim_start_matches("vault://project/");
                if project.is_empty() {
                    bail!("Invalid resource URI '{uri}': missing project name");
                }
                let body = self.list_keys_for_project(ListProjectKeysRequest {
                    project: project.to_string(),
                    query: None,
                    provider: None,
                    limit: Some(100),
                    offset: Some(0),
                })?;
                (uri.to_string(), format!("Project: {project}"), body)
            }
            _ if uri.starts_with("vault://provider/") => {
                let provider = uri.trim_start_matches("vault://provider/");
                if provider.is_empty() {
                    bail!("Invalid resource URI '{uri}': missing provider name");
                }
                let entries = self.db.list_secrets(&ListFilter {
                    provider: Some(provider.to_string()),
                    inactive: true,
                    ..Default::default()
                })?;
                let body = json!({
                    "provider": provider,
                    "total": entries.len(),
                    "active": entries.iter().filter(|entry| entry.is_active).count(),
                    "inactive": entries.iter().filter(|entry| !entry.is_active).count(),
                    "keys": paginate_entries(entries.clone(), Some(100), Some(0))
                        .iter()
                        .map(models::secret_to_json)
                        .collect::<Vec<_>>(),
                    "health": provider_health_snapshot(provider, &entries),
                });
                (uri.to_string(), format!("Provider: {provider}"), body)
            }
            _ => bail!("Unknown resource URI: {uri}"),
        };

        Ok(json!({
            "contents": [{
                "uri": resource_uri,
                "mimeType": "application/json",
                "text": serde_json::to_string_pretty(&body)?,
                "name": name
            }]
        }))
    }

    pub fn get_key_info(&self, name: String) -> Result<Value> {
        let entry = self.db.get_secret(&name)?;
        Ok(models::secret_to_json(&entry))
    }

    pub fn list_providers(&self) -> Result<Value> {
        let entries = self.db.list_secrets(&ListFilter::default())?;
        let mut counts = HashMap::<String, usize>::new();
        for entry in entries {
            *counts.entry(entry.provider).or_default() += 1;
        }

        let mut providers = counts
            .into_iter()
            .map(|(provider, key_count)| json!({ "provider": provider, "key_count": key_count }))
            .collect::<Vec<_>>();
        providers.sort_by(|a, b| a["provider"].as_str().cmp(&b["provider"].as_str()));

        Ok(json!({ "providers": providers }))
    }

    pub fn list_projects(&self, request: ListProjectsRequest) -> Result<Value> {
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
            .filter(|(project, _)| {
                request
                    .query
                    .as_ref()
                    .is_none_or(|query| project.contains(query))
            })
            .map(|(project, mut keys)| {
                keys.sort();
                json!({ "project": project, "keys": keys, "key_count": keys.len() })
            })
            .collect::<Vec<_>>();
        values.sort_by(|a, b| a["project"].as_str().cmp(&b["project"].as_str()));
        let total = values.len();
        let values = paginate_values(values, request.limit, request.offset);

        Ok(json!({
            "total": total,
            "count": values.len(),
            "limit": clamp_limit(request.limit),
            "offset": request.offset.unwrap_or(0),
            "has_more": request.offset.unwrap_or(0) + values.len() < total,
            "projects": values
        }))
    }

    pub fn discover_project_context(&self, request: DiscoverProjectRequest) -> Result<Value> {
        let path = request.path.unwrap_or_else(|| ".".to_string());
        let root = Path::new(&path);
        let context = discover_project_context(root);
        let requirements = infer_required_env_vars(root);

        let project_name = request
            .project
            .or_else(|| context.as_ref().map(|ctx| ctx.name.clone()));
        let attached = if let Some(project) = &project_name {
            self.db.list_secrets(&ListFilter {
                project: Some(project.clone()),
                ..Default::default()
            })?
        } else {
            Vec::new()
        };

        Ok(json!({
            "found": context.is_some(),
            "path": path,
            "project": project_name,
            "root": context.as_ref().map(|ctx| ctx.root.display().to_string()),
            "detector": context.as_ref().map(|ctx| ctx.detector),
            "workspace_root": context
                .as_ref()
                .and_then(|ctx| ctx.workspace_root.as_ref())
                .map(|root| root.display().to_string()),
            "workspace_detector": context.as_ref().and_then(|ctx| ctx.workspace_detector),
            "required_vars": requirements.vars,
            "inference_sources": requirements.sources,
            "attached_secret_count": attached.len(),
            "attached_secret_names": attached.into_iter().map(|entry| entry.name).collect::<Vec<_>>(),
            "scan_roots": context
                .as_ref()
                .map(|ctx| {
                    let mut roots = vec![ctx.root.display().to_string()];
                    if let Some(workspace_root) = &ctx.workspace_root {
                        roots.push(workspace_root.display().to_string());
                    }
                    roots
                })
                .unwrap_or_else(|| vec![path.clone()])
        }))
    }

    pub fn check_health(&self) -> Result<Value> {
        let service = crate::services::secrets::SecretService::new_ref(self.db);
        let health = service.health_view()?;
        Ok(health.to_mcp_json())
    }

    pub fn list_keys_for_project(&self, request: ListProjectKeysRequest) -> Result<Value> {
        let entries = self.db.list_secrets(&ListFilter {
            project: Some(request.project.clone()),
            ..Default::default()
        })?;
        let mut filtered = entries
            .into_iter()
            .filter(|entry| {
                request
                    .provider
                    .as_ref()
                    .is_none_or(|provider| entry.provider == *provider)
            })
            .filter(|entry| {
                request.query.as_ref().is_none_or(|query| {
                    entry.name.contains(query)
                        || entry.env_var.contains(query)
                        || entry.description.contains(query)
                        || entry.provider.contains(query)
                })
            })
            .collect::<Vec<_>>();
        let scored = request
            .query
            .as_ref()
            .map(|query| rank_entries_for_query(filtered.as_mut_slice(), query))
            .unwrap_or_else(|| {
                filtered.sort_by(|a, b| a.name.cmp(&b.name));
                filtered
                    .into_iter()
                    .map(|entry| ScoredEntry {
                        entry,
                        relevance_score: 0,
                        matched_fields: Vec::new(),
                    })
                    .collect()
            });
        let total = scored.len();
        let keys = paginate_scored_entries(scored, request.limit, request.offset)
            .into_iter()
            .map(scored_entry_to_json)
            .collect::<Vec<_>>();
        Ok(json!({
            "project": request.project,
            "total": total,
            "count": keys.len(),
            "limit": clamp_limit(request.limit),
            "offset": request.offset.unwrap_or(0),
            "has_more": request.offset.unwrap_or(0) + keys.len() < total,
            "keys": keys
        }))
    }

    pub fn add_key(&self, request: AddKeyRequest) -> Result<Value> {
        validate_env_var_name(&request.env_var)?;
        let name = request.env_var.to_lowercase().replace('_', "-");
        let provider = request.provider.unwrap_or_else(|| {
            models::infer_provider(&request.env_var)
                .unwrap_or("other")
                .to_string()
        });
        if self.db.secret_exists(&name)? {
            return Ok(json!({
                "success": false,
                "code": "already_exists",
                "name": name,
                "env_var": request.env_var,
                "provider": provider,
                "message": "Secret already exists in KeyFlow.",
                "error": "Use update flow instead.",
                "existing_name": name,
                "hint": "Call get_key_info first, then update the existing secret if needed."
            }));
        }
        let now = Utc::now();

        let entry = SecretEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.clone(),
            env_var: request.env_var.clone(),
            provider: provider.clone(),
            account_name: request.account_name.unwrap_or_default(),
            org_name: request.org_name.unwrap_or_default(),
            description: request.description.unwrap_or_default(),
            source: request.source.unwrap_or_else(|| "mcp:add_key".to_string()),
            environment: request.environment.unwrap_or_default(),
            permission_profile: request.permission_profile.unwrap_or_default(),
            scopes: request.scopes.unwrap_or_default(),
            projects: request.projects.unwrap_or_default(),
            apply_url: request.apply_url.unwrap_or_default(),
            expires_at: None,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            last_verified_at: Some(now),
            is_active: true,
        };

        self.db.add_secret(&entry, &request.value)?;

        Ok(json!({
            "success": true,
            "code": "created",
            "name": name,
            "env_var": entry.env_var,
            "provider": provider,
            "message": format!("Secret '{}' added successfully", entry.name),
            "error": Value::Null,
            "existing_name": Value::Null,
            "hint": "Value stored securely and encrypted at rest."
        }))
    }

    pub fn get_env_snippet(&self, filter: EnvSnippetRequest) -> Result<Value> {
        if filter.project.is_none() {
            bail!("'project' must be specified");
        }

        let entries = self.db.list_secrets(&ListFilter {
            project: filter.project.clone(),
            ..Default::default()
        })?;

        if entries.is_empty() {
            return Ok(json!({
                "found": false,
                "snippet": "",
                "message": "No secrets found for the given filter"
            }));
        }

        let mut lines = Vec::new();
        let mut keys = Vec::new();
        for entry in entries {
            let value = if filter.mask_values {
                "***".to_string()
            } else {
                self.db.get_secret_value(&entry.name)?
            };
            lines.push(format!("{}={}", entry.env_var, value));
            keys.push(json!({
                "name": entry.name,
                "env_var": entry.env_var,
                "provider": entry.provider
            }));
        }

        Ok(json!({
            "found": true,
            "count": lines.len(),
            "snippet": lines.join("\n"),
            "keys": keys,
            "masked": filter.mask_values
        }))
    }

    pub fn check_project_readiness(&self, request: ProjectReadinessRequest) -> Result<Value> {
        let discovery_path = request.path.clone().unwrap_or_else(|| ".".to_string());
        let inferred = if request.required_vars.is_empty() {
            Some(infer_required_env_vars(Path::new(&discovery_path)))
        } else {
            None
        };
        let required_vars = if let Some(inferred) = &inferred {
            inferred.vars.clone()
        } else {
            request.required_vars.clone()
        };
        let entries = self.db.list_secrets(&ListFilter {
            project: Some(request.project.clone()),
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
                    KeyStatus::Expired => expired.push(json!({
                        "env_var": env_var,
                        "name": entry.name,
                        "status": "expired",
                        "expires_at": entry.expires_at.map(|d| d.to_rfc3339()),
                        "apply_url": entry.apply_url,
                        "severity": "blocked",
                        "reason": "Attached key is expired and must be rotated before use."
                    })),
                    KeyStatus::ExpiringSoon => attention.push(json!({
                        "env_var": env_var,
                        "name": entry.name,
                        "status": "expiring_soon",
                        "expires_at": entry.expires_at.map(|d| d.to_rfc3339()),
                        "severity": "warning",
                        "reason": "Attached key exists but expires soon. Rotate it proactively."
                    })),
                    KeyStatus::Inactive => attention.push(json!({
                        "env_var": env_var,
                        "name": entry.name,
                        "status": "inactive",
                        "severity": "warning",
                        "reason": "Attached key exists but is inactive."
                    })),
                    KeyStatus::Unknown => attention.push(json!({
                        "env_var": env_var,
                        "name": entry.name,
                        "status": "unknown",
                        "severity": "warning",
                        "reason": "Attached key exists but its health is unclear."
                    })),
                    _ => available.push(json!({
                        "env_var": env_var,
                        "name": entry.name,
                        "status": "ok",
                        "severity": "healthy",
                        "reason": "Attached key is available for this project."
                    })),
                },
                None => {
                    let suggestion = format!(
                        "Run: kf add {} \"<value>\" --projects {}",
                        env_var, request.project
                    );
                    missing.push(json!({
                        "env_var": env_var,
                        "suggestion": suggestion,
                        "severity": "blocked",
                        "reason": "No attached key found for this required env var."
                    }));
                }
            }
        }

        if !missing.is_empty() {
            actions.push("Add the missing required keys to this project.");
        }
        if !expired.is_empty() {
            actions.push("Rotate expired keys before running the project.");
        }
        if !attention.is_empty() {
            actions.push("Review keys that are expiring soon or inactive.");
        }
        let is_ready = missing.is_empty() && expired.is_empty();
        let status = if !missing.is_empty() || !expired.is_empty() {
            "blocked"
        } else if !attention.is_empty() {
            "attention"
        } else {
            "ready"
        };
        Ok(json!({
            "project": request.project,
            "mode": if inferred.is_some() { "inferred" } else { "explicit" },
            "status": status,
            "ready": is_ready,
            "summary": if status == "ready" {
                format!("All {} required secrets are available and healthy", required_vars.len())
            } else if status == "attention" {
                format!("All {} required secrets exist, but {} need review", required_vars.len(), attention.len())
            } else {
                format!("{} missing, {} expired out of {} required", missing.len(), expired.len(), required_vars.len())
            },
            "required_vars": required_vars,
            "inference_sources": inferred
                .as_ref()
                .map(|requirements| requirements.sources.clone())
                .unwrap_or_default(),
            "available": available,
            "attention": attention,
            "missing": missing,
            "expired": expired,
            "actions": actions,
            "total_required": required_vars.len(),
            "total_available": available.len() + attention.len(),
            "healthy_count": available.len(),
            "attention_count": attention.len(),
            "missing_count": missing.len(),
            "expired_count": expired.len(),
        }))
    }
}

fn clamp_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(20).clamp(1, 100)
}

fn normalized_offset(offset: Option<usize>) -> usize {
    offset.unwrap_or(0)
}

fn paginate_entries(
    entries: Vec<SecretEntry>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Vec<SecretEntry> {
    let offset = normalized_offset(offset);
    let limit = clamp_limit(limit);
    entries.into_iter().skip(offset).take(limit).collect()
}

fn paginate_scored_entries(
    entries: Vec<ScoredEntry>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Vec<ScoredEntry> {
    let offset = normalized_offset(offset);
    let limit = clamp_limit(limit);
    entries.into_iter().skip(offset).take(limit).collect()
}

fn paginate_values(values: Vec<Value>, limit: Option<usize>, offset: Option<usize>) -> Vec<Value> {
    let offset = normalized_offset(offset);
    let limit = clamp_limit(limit);
    values.into_iter().skip(offset).take(limit).collect()
}

fn provider_health_snapshot(provider: &str, entries: &[SecretEntry]) -> Value {
    let now = Utc::now();
    let expired = entries
        .iter()
        .filter(|entry| matches!(entry.status(), KeyStatus::Expired))
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    let expiring = entries
        .iter()
        .filter(|entry| matches!(entry.status(), KeyStatus::ExpiringSoon))
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    let inactive = entries
        .iter()
        .filter(|entry| !entry.is_active)
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();
    let metadata_gaps = entries
        .iter()
        .filter(|entry| entry.has_metadata_gaps())
        .map(|entry| {
            json!({
                "name": entry.name,
                "gaps": entry.metadata_gaps(),
            })
        })
        .collect::<Vec<_>>();
    let stale = entries
        .iter()
        .filter(|entry| entry.is_unused_for_days(now, 30))
        .map(|entry| {
            json!({
                "name": entry.name,
                "days_unused": entry.days_since_last_seen(now),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "provider": provider,
        "expired": expired,
        "expiring": expiring,
        "inactive": inactive,
        "metadata_gaps": metadata_gaps,
        "stale": stale,
    })
}

#[derive(Debug)]
struct ScoredEntry {
    entry: SecretEntry,
    relevance_score: i64,
    matched_fields: Vec<&'static str>,
}

fn rank_entries_for_query(entries: &mut [SecretEntry], query: &str) -> Vec<ScoredEntry> {
    let query = query.trim();
    let mut scored = entries
        .iter()
        .cloned()
        .map(|entry| {
            let (score, matched_fields) = score_entry(&entry, query);
            ScoredEntry {
                entry,
                relevance_score: score,
                matched_fields,
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

fn scored_entry_to_json(scored: ScoredEntry) -> Value {
    let mut value = models::secret_to_json(&scored.entry);
    value["relevance_score"] = json!(scored.relevance_score);
    value["matched_fields"] = json!(scored.matched_fields);
    value
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

fn validate_env_var_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("Environment variable name cannot be empty");
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("Invalid environment variable name '{name}': only [A-Za-z0-9_] allowed");
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct AddKeyRequest {
    pub env_var: String,
    pub value: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub projects: Option<Vec<String>>,
    #[serde(default)]
    pub account_name: Option<String>,
    #[serde(default)]
    pub org_name: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub permission_profile: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub apply_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SearchKeysRequest {
    pub query: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub include_inactive: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListProjectsRequest {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ListProjectKeysRequest {
    pub project: String,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DiscoverProjectRequest {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnvSnippetRequest {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default = "default_true")]
    pub mask_values: bool,
}

#[derive(Debug, Deserialize)]
pub struct ProjectReadinessRequest {
    pub project: String,
    #[serde(default)]
    pub required_vars: Vec<String>,
    #[serde(default)]
    pub path: Option<String>,
}

fn default_true() -> bool {
    true
}

pub fn parse_args<T>(value: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::test_helpers::{add_secret, test_db as test_service};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn search_keys_supports_filter_and_pagination() {
        let (_dir, db) = test_service();
        add_secret(
            &db,
            "openai-main",
            "OPENAI_API_KEY",
            "openai",
            &["demo"],
            true,
        );
        add_secret(
            &db,
            "openai-shadow",
            "OPENAI_ALT_KEY",
            "openai",
            &["demo"],
            false,
        );
        add_secret(&db, "github-main", "GITHUB_TOKEN", "github", &["ops"], true);
        let service = VaultService::new(&db);

        let result = service
            .search_keys(SearchKeysRequest {
                query: "KEY".to_string(),
                provider: Some("openai".to_string()),
                project: Some("demo".to_string()),
                limit: Some(1),
                offset: Some(0),
                include_inactive: false,
            })
            .unwrap();

        assert_eq!(result["total"], 1);
        assert_eq!(result["count"], 1);
        assert_eq!(result["limit"], 1);
        assert_eq!(result["offset"], 0);
        assert_eq!(result["has_more"], false);
        assert_eq!(result["keys"][0]["name"], "openai-main");
        assert!(result["keys"][0]["relevance_score"].as_i64().unwrap() > 0);
        assert!(result["keys"][0]["matched_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "env_var"));

        let with_inactive = service
            .search_keys(SearchKeysRequest {
                query: "openai".to_string(),
                provider: Some("openai".to_string()),
                project: None,
                limit: Some(1),
                offset: Some(1),
                include_inactive: true,
            })
            .unwrap();
        assert_eq!(with_inactive["total"], 2);
        assert_eq!(with_inactive["count"], 1);
        assert_eq!(with_inactive["has_more"], false);
    }

    #[test]
    fn search_keys_prioritizes_exact_env_var_matches() {
        let (_dir, db) = test_service();
        add_secret(
            &db,
            "openai-main",
            "OPENAI_API_KEY",
            "openai",
            &["demo"],
            true,
        );
        add_secret(
            &db,
            "openai-helper",
            "OPENAI_API_KEY_ROTATED",
            "openai",
            &["demo"],
            true,
        );
        let service = VaultService::new(&db);

        let result = service
            .search_keys(SearchKeysRequest {
                query: "OPENAI_API_KEY".to_string(),
                provider: None,
                project: None,
                limit: Some(10),
                offset: Some(0),
                include_inactive: true,
            })
            .unwrap();

        assert_eq!(result["keys"][0]["name"], "openai-main");
        assert!(
            result["keys"][0]["relevance_score"].as_i64().unwrap()
                > result["keys"][1]["relevance_score"].as_i64().unwrap()
        );
    }

    #[test]
    fn list_projects_and_project_keys_support_pagination() {
        let (_dir, db) = test_service();
        add_secret(&db, "a-key", "ALPHA_KEY", "alpha", &["alpha"], true);
        add_secret(&db, "b-key", "BETA_KEY", "beta", &["beta"], true);
        add_secret(&db, "b-extra", "BETA_EXTRA", "beta", &["beta"], true);
        let service = VaultService::new(&db);

        let projects = service
            .list_projects(ListProjectsRequest {
                query: Some("b".to_string()),
                limit: Some(10),
                offset: Some(0),
            })
            .unwrap();
        assert_eq!(projects["total"], 1);
        assert_eq!(projects["projects"][0]["project"], "beta");
        assert_eq!(projects["projects"][0]["key_count"], 2);

        let keys = service
            .list_keys_for_project(ListProjectKeysRequest {
                project: "beta".to_string(),
                query: Some("extra".to_string()),
                provider: Some("beta".to_string()),
                limit: Some(5),
                offset: Some(0),
            })
            .unwrap();
        assert_eq!(keys["total"], 1);
        assert_eq!(keys["count"], 1);
        assert_eq!(keys["keys"][0]["name"], "b-extra");
    }

    #[test]
    fn discover_project_context_and_inferred_readiness_work() {
        let (_dir, db) = test_service();
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{ "private": true, "workspaces": ["apps/*"] }"#,
        )
        .unwrap();
        let app_dir = temp.path().join("apps/demo-app");
        fs::create_dir_all(app_dir.join("src")).unwrap();
        fs::write(app_dir.join("package.json"), r#"{ "name": "demo-app" }"#).unwrap();
        fs::write(
            temp.path().join(".env.example"),
            "OPENAI_API_KEY=\nWORKSPACE_ONLY_KEY=\n",
        )
        .unwrap();
        fs::write(app_dir.join(".env.sample"), "RESEND_API_KEY=\n").unwrap();
        fs::write(
            app_dir.join("src/index.ts"),
            "const base = import.meta.env.VITE_PUBLIC_BASE_URL;\n",
        )
        .unwrap();

        add_secret(
            &db,
            "openai-main",
            "OPENAI_API_KEY",
            "openai",
            &["demo-app"],
            true,
        );
        let service = VaultService::new(&db);

        let discovered = service
            .discover_project_context(DiscoverProjectRequest {
                path: Some(app_dir.display().to_string()),
                project: None,
            })
            .unwrap();
        assert_eq!(discovered["found"], true);
        assert_eq!(discovered["project"], "demo-app");
        assert_eq!(
            discovered["workspace_root"],
            temp.path().display().to_string()
        );
        assert!(discovered["required_vars"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "OPENAI_API_KEY"));
        assert!(discovered["required_vars"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "WORKSPACE_ONLY_KEY"));
        assert!(discovered["required_vars"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "VITE_PUBLIC_BASE_URL"));

        let readiness = service
            .check_project_readiness(ProjectReadinessRequest {
                project: "demo-app".to_string(),
                required_vars: vec![],
                path: Some(app_dir.display().to_string()),
            })
            .unwrap();

        assert_eq!(readiness["mode"], "inferred");
        assert_eq!(readiness["status"], "blocked");
        assert_eq!(readiness["total_required"], 4);
        assert_eq!(readiness["total_available"], 1);
        assert!(readiness["missing"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["env_var"] == "RESEND_API_KEY"));
        assert!(readiness["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "Add the missing required keys to this project."));
    }

    #[test]
    fn readiness_reports_attention_for_expiring_keys() {
        let (_dir, db) = test_service();
        let now = Utc::now();
        let entry = SecretEntry {
            id: "test-expiring".to_string(),
            name: "expiring-openai".to_string(),
            env_var: "OPENAI_API_KEY".to_string(),
            provider: "openai".to_string(),
            account_name: "acct".to_string(),
            org_name: String::new(),
            description: "desc expiring".to_string(),
            source: "manual:test".to_string(),
            environment: String::new(),
            permission_profile: String::new(),
            scopes: vec![],
            projects: vec!["demo-app".to_string()],
            apply_url: "https://platform.openai.com/api-keys".to_string(),
            expires_at: Some(now + chrono::Duration::days(2)),
            created_at: now,
            updated_at: now,
            last_used_at: None,
            last_verified_at: Some(now),
            is_active: true,
        };
        db.add_secret(&entry, "secret-value").unwrap();
        let service = VaultService::new(&db);

        let readiness = service
            .check_project_readiness(ProjectReadinessRequest {
                project: "demo-app".to_string(),
                required_vars: vec!["OPENAI_API_KEY".to_string()],
                path: None,
            })
            .unwrap();

        assert_eq!(readiness["status"], "attention");
        assert_eq!(readiness["ready"], true);
        assert_eq!(readiness["attention_count"], 1);
        assert_eq!(readiness["available"].as_array().unwrap().len(), 0);
        assert_eq!(readiness["attention"][0]["status"], "expiring_soon");
    }
}
