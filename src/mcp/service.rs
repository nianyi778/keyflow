use anyhow::{bail, Result};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::models::{self, KeyStatus, ListFilter, SecretEntry};
use crate::services::secrets::{
    validate_env_var_name, ProjectKeysResult, SearchFilter, SearchResult, SecretDraft,
    SecretService,
};

pub struct VaultService<'a> {
    secrets: &'a SecretService<'a>,
}

impl<'a> VaultService<'a> {
    pub fn new(secrets: &'a SecretService<'a>) -> Self {
        Self { secrets }
    }

    pub fn search_keys(&self, request: SearchKeysRequest) -> Result<Value> {
        let result = self.secrets.search_ranked(
            &request.query,
            &SearchFilter {
                provider: request.provider,
                project: request.project,
                limit: request.limit,
                offset: request.offset,
                include_inactive: request.include_inactive,
            },
        )?;
        Ok(search_result_to_json(result))
    }

    pub fn list_resources(&self) -> Result<Value> {
        let entries = self.secrets.list_entries(&ListFilter {
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
                let entries = self.secrets.list_entries(&ListFilter {
                    provider: Some(provider.to_string()),
                    inactive: true,
                    ..Default::default()
                })?;
                let body = json!({
                    "provider": provider,
                    "total": entries.len(),
                    "active": entries.iter().filter(|entry| entry.is_active).count(),
                    "inactive": entries.iter().filter(|entry| !entry.is_active).count(),
                    "keys": entries
                        .iter()
                        .take(100)
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
        let entry = self.secrets.get_entry(&name)?;
        Ok(models::secret_to_json(&entry))
    }

    pub fn list_providers(&self) -> Result<Value> {
        let providers = self
            .secrets
            .list_providers()?
            .into_iter()
            .map(|provider| json!({ "provider": provider.provider, "key_count": provider.key_count }))
            .collect::<Vec<_>>();

        Ok(json!({ "providers": providers }))
    }

    pub fn list_projects(&self, request: ListProjectsRequest) -> Result<Value> {
        let result =
            self.secrets
                .list_projects(request.query.as_deref(), request.limit, request.offset)?;

        Ok(json!({
            "total": result.total,
            "count": result.count,
            "limit": result.limit,
            "offset": result.offset,
            "has_more": result.has_more,
            "projects": result
                .projects
                .into_iter()
                .map(|project| {
                    json!({
                        "project": project.project,
                        "keys": project.keys,
                        "key_count": project.key_count
                    })
                })
                .collect::<Vec<_>>()
        }))
    }

    pub fn discover_project_context(&self, request: DiscoverProjectRequest) -> Result<Value> {
        let context = self
            .secrets
            .discover_project_context(request.path.as_deref(), request.project.as_deref())?;
        serde_json::to_value(context).map_err(Into::into)
    }

    pub fn check_health(&self) -> Result<Value> {
        let health = self.secrets.health_view()?;
        Ok(health.to_mcp_json())
    }

    pub fn list_keys_for_project(&self, request: ListProjectKeysRequest) -> Result<Value> {
        let result = self.secrets.list_project_keys(
            &request.project,
            request.query.as_deref(),
            request.provider.as_deref(),
            request.limit,
            request.offset,
        )?;
        Ok(project_keys_result_to_json(result))
    }

    pub fn add_key(&self, request: AddKeyRequest) -> Result<Value> {
        validate_env_var_name(&request.env_var)?;
        let name = request.env_var.to_lowercase().replace('_', "-");
        let provider = request.provider.unwrap_or_else(|| {
            self.secrets
                .infer_provider_for_env_var(&request.env_var)
                .unwrap_or_else(|| "other".to_string())
        });

        let AddKeyRequest {
            env_var,
            value,
            provider: _,
            description,
            projects,
            account_name,
            org_name,
            source,
            environment,
            permission_profile,
            scopes,
            apply_url,
        } = request;

        let result = self.secrets.create_secret(SecretDraft {
            env_var: env_var.clone(),
            value,
            provider: provider.clone(),
            account_name: account_name.unwrap_or_default(),
            org_name: org_name.unwrap_or_default(),
            description: description.unwrap_or_default(),
            source: source.unwrap_or_else(|| "mcp:add_key".to_string()),
            environment: environment.unwrap_or_default(),
            permission_profile: permission_profile.unwrap_or_default(),
            scopes: scopes.unwrap_or_default(),
            projects: projects.unwrap_or_default(),
            apply_url: apply_url.unwrap_or_default(),
            expires_at: None,
        });

        match result {
            Ok(entry) => Ok(json!({
                "success": true,
                "code": "created",
                "name": name,
                "env_var": entry.env_var,
                "provider": provider,
                "message": format!("Secret '{}' added successfully", entry.name),
                "error": Value::Null,
                "existing_name": Value::Null,
                "hint": "Value stored securely and encrypted at rest."
            })),
            Err(error) if error.to_string().contains("already exists") => Ok(json!({
                "success": false,
                "code": "already_exists",
                "name": name,
                "env_var": env_var,
                "provider": provider,
                "message": "Secret already exists in KeyFlow.",
                "error": "Use update flow instead.",
                "existing_name": name,
                "hint": "Call inspect_key first, then update the existing secret if needed."
            })),
            Err(error) => Err(error),
        }
    }

    pub fn get_env_snippet(&self, filter: EnvSnippetRequest) -> Result<Value> {
        if filter.project.is_none() {
            bail!("'project' must be specified");
        }

        let entries = self.secrets.list_entries(&ListFilter {
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
                self.secrets.get_secret_value(&entry.name)?
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
        let report = self.secrets.check_project_readiness(
            &request.project,
            &request.required_vars,
            request.path.as_deref(),
        )?;
        serde_json::to_value(report).map_err(Into::into)
    }
}

fn search_result_to_json(result: SearchResult) -> Value {
    let keys = result
        .keys
        .into_iter()
        .map(scored_entry_to_json)
        .collect::<Vec<_>>();
    json!({
        "found": result.found,
        "total": result.total,
        "count": result.count,
        "limit": result.limit,
        "offset": result.offset,
        "has_more": result.has_more,
        "keys": keys
    })
}

fn project_keys_result_to_json(result: ProjectKeysResult) -> Value {
    let keys = result
        .keys
        .into_iter()
        .map(scored_entry_to_json)
        .collect::<Vec<_>>();
    json!({
        "project": result.project,
        "total": result.total,
        "count": result.count,
        "limit": result.limit,
        "offset": result.offset,
        "has_more": result.has_more,
        "keys": keys
    })
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
fn scored_entry_to_json(scored: crate::services::secrets::RankedSecretEntry) -> Value {
    let mut value = models::secret_to_json(&scored.entry);
    value["relevance_score"] = json!(scored.relevance_score);
    value["matched_fields"] = json!(scored.matched_fields);
    value
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
    use crate::services::secrets::SecretService;
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
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);

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
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);

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
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);

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
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);

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
        let secret_service = SecretService::new_ref(&db);
        let service = VaultService::new(&secret_service);

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
