use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use super::service::{
    parse_args, AddKeyRequest, DiscoverProjectRequest, EnvSnippetRequest, ListProjectKeysRequest,
    ListProjectsRequest, ProjectReadinessRequest, SearchKeysRequest, VaultService,
};

type ToolHandler = fn(&VaultService<'_>, Value) -> Result<Value>;

pub struct ToolRegistry {
    tools: Vec<ToolDefinition>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: vec![
                ToolDefinition::read_with_output(
                    "search_keys",
                    "Search secrets by keyword and return only metadata, never plaintext values.",
                    json!({
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Keyword matching name, env_var, provider, description, scopes, or projects."
                            },
                            "provider": { "type": "string" },
                            "project": { "type": "string" },
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                            "offset": { "type": "integer", "minimum": 0, "default": 0 },
                            "include_inactive": { "type": "boolean", "default": false }
                        },
                        "required": ["query"]
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "found": { "type": "boolean" },
                            "total": { "type": "integer" },
                            "count": { "type": "integer" },
                            "limit": { "type": "integer" },
                            "offset": { "type": "integer" },
                            "has_more": { "type": "boolean" },
                            "keys": {
                                "type": "array",
                                "items": key_metadata_schema()
                            }
                        },
                        "required": ["found", "total", "count", "limit", "offset", "has_more", "keys"]
                    }),
                    |service, args| {
                        let args: SearchKeysRequest = parse_args(args)?;
                        service.search_keys(args)
                    },
                ),
                ToolDefinition::read_with_output(
                    "get_key_info",
                    "Get detailed metadata for one secret by its KeyFlow name.",
                    json!({
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Secret name returned by search_keys."
                            }
                        },
                        "required": ["name"]
                    }),
                    key_metadata_schema(),
                    |service, args| {
                        #[derive(serde::Deserialize)]
                        struct Args {
                            name: String,
                        }
                        let args: Args = parse_args(args)?;
                        service.get_key_info(args.name)
                    },
                ),
                ToolDefinition::read_with_output(
                    "list_providers",
                    "List all providers currently stored in the vault with key counts.",
                    json!({"type": "object", "properties": {}}),
                    json!({
                        "type": "object",
                        "properties": {
                            "providers": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "provider": { "type": "string" },
                                        "key_count": { "type": "integer" }
                                    },
                                    "required": ["provider", "key_count"]
                                }
                            }
                        },
                        "required": ["providers"]
                    }),
                    |service, _| service.list_providers(),
                ),
                ToolDefinition::read_with_output(
                    "list_projects",
                    "List all projects and the secret names attached to each project.",
                    json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string", "description": "Substring match for project name." },
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                            "offset": { "type": "integer", "minimum": 0, "default": 0 }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "total": { "type": "integer" },
                            "count": { "type": "integer" },
                            "limit": { "type": "integer" },
                            "offset": { "type": "integer" },
                            "has_more": { "type": "boolean" },
                            "projects": {
                                "type": "array",
                                "items": project_keys_schema()
                            }
                        },
                        "required": ["total", "count", "limit", "offset", "has_more", "projects"]
                    }),
                    |service, args| {
                        let args: ListProjectsRequest = parse_args(args)?;
                        service.list_projects(args)
                    },
                ),
                ToolDefinition::read_with_output(
                    "check_health",
                    "Summarize vault health: expired keys, expiring keys, inactive keys, metadata gaps, duplicates, and verification age.",
                    json!({"type": "object", "properties": {}}),
                    json!({
                        "type": "object",
                        "properties": {
                            "summary": {
                                "type": "object",
                                "properties": {
                                    "total": { "type": "integer" },
                                    "expiry_issues": { "type": "integer" },
                                    "duplicate_count": { "type": "integer" },
                                    "inactive_count": { "type": "integer" },
                                    "unused_count": { "type": "integer" },
                                    "metadata_review_count": { "type": "integer" }
                                },
                                "required": [
                                    "total",
                                    "expiry_issues",
                                    "duplicate_count",
                                    "inactive_count",
                                    "unused_count",
                                    "metadata_review_count"
                                ]
                            },
                            "status": {
                                "type": "string",
                                "enum": ["ok", "attention"]
                            },
                            "expired": { "$ref": "#/$defs/keyBucket" },
                            "expiring": { "$ref": "#/$defs/keyBucket" },
                            "unused": { "$ref": "#/$defs/keyBucket" },
                            "inactive": { "$ref": "#/$defs/keyBucket" },
                            "metadata_gaps": { "$ref": "#/$defs/keyBucket" },
                            "duplicates": {
                                "type": "object",
                                "properties": {
                                    "count": { "type": "integer" },
                                    "groups": {
                                        "type": "array",
                                        "items": { "$ref": "#/$defs/duplicateGroup" }
                                    }
                                },
                                "required": ["count", "groups"]
                            },
                            "provider_old_keys": {
                                "type": "object",
                                "properties": {
                                    "count": { "type": "integer" },
                                    "groups": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "provider": { "type": "string" },
                                                "keys": {
                                                    "type": "array",
                                                    "items": { "type": "string" }
                                                }
                                            },
                                            "required": ["provider", "keys"]
                                        }
                                    }
                                },
                                "required": ["count", "groups"]
                            },
                            "source_quality": {
                                "type": "object",
                                "additionalProperties": { "type": "integer" }
                            },
                            "unverified": {
                                "type": "object",
                                "properties": {
                                    "30_59_days": { "$ref": "#/$defs/nameBucket" },
                                    "60_89_days": { "$ref": "#/$defs/nameBucket" },
                                    "90_plus_days": { "$ref": "#/$defs/nameBucket" }
                                },
                                "required": ["30_59_days", "60_89_days", "90_plus_days"]
                            }
                        },
                        "required": [
                            "summary",
                            "status",
                            "expired",
                            "expiring",
                            "unused",
                            "inactive",
                            "metadata_gaps",
                            "duplicates",
                            "provider_old_keys",
                            "source_quality",
                            "unverified"
                        ],
                        "$defs": {
                            "keyBucket": {
                                "type": "object",
                                "properties": {
                                    "count": { "type": "integer" },
                                    "keys": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "additionalProperties": true
                                        }
                                    }
                                },
                                "required": ["count", "keys"]
                            },
                            "duplicateGroup": {
                                "type": "object",
                                "properties": {
                                    "env_var": { "type": "string" },
                                    "names": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    }
                                },
                                "required": ["env_var", "names"]
                            },
                            "nameBucket": {
                                "type": "object",
                                "properties": {
                                    "count": { "type": "integer" },
                                    "names": {
                                        "type": "array",
                                        "items": { "type": "string" }
                                    }
                                },
                                "required": ["count", "names"]
                            }
                        }
                    }),
                    |service, _| service.check_health(),
                ),
                ToolDefinition::read_with_output(
                    "list_keys_for_project",
                    "List all secrets available to a specific project.",
                    json!({
                        "type": "object",
                        "properties": {
                            "project": {
                                "type": "string",
                                "description": "Project tag stored in KeyFlow."
                            },
                            "query": { "type": "string" },
                            "provider": { "type": "string" },
                            "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                            "offset": { "type": "integer", "minimum": 0, "default": 0 }
                        },
                        "required": ["project"]
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "project": { "type": "string" },
                            "total": { "type": "integer" },
                            "count": { "type": "integer" },
                            "limit": { "type": "integer" },
                            "offset": { "type": "integer" },
                            "has_more": { "type": "boolean" },
                            "keys": {
                                "type": "array",
                                "items": key_metadata_schema()
                            }
                        },
                        "required": ["project", "total", "count", "limit", "offset", "has_more", "keys"]
                    }),
                    |service, args| {
                        let args: ListProjectKeysRequest = parse_args(args)?;
                        service.list_keys_for_project(args)
                    },
                ),
                ToolDefinition::write_with_output(
                    "add_key",
                    "Store a new secret in KeyFlow. The plaintext value is encrypted immediately.",
                    json!({
                        "type": "object",
                        "properties": {
                            "env_var": { "type": "string", "description": "Environment variable name, for example OPENAI_API_KEY." },
                            "value": { "type": "string", "description": "Plaintext secret to encrypt and store." },
                            "provider": { "type": "string" },
                            "description": { "type": "string" },
                            "projects": { "type": "array", "items": { "type": "string" } },
                            "account_name": { "type": "string" },
                            "org_name": { "type": "string" },
                            "source": { "type": "string" },
                            "environment": { "type": "string" },
                            "permission_profile": { "type": "string" },
                            "scopes": { "type": "array", "items": { "type": "string" } },
                            "apply_url": { "type": "string" }
                        },
                        "required": ["env_var", "value"]
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "success": { "type": "boolean" },
                            "code": { "type": "string", "enum": ["created", "already_exists"] },
                            "name": { "type": "string" },
                            "env_var": { "type": "string" },
                            "provider": { "type": "string" },
                            "message": { "type": "string" },
                            "error": { "type": ["string", "null"] },
                            "existing_name": { "type": ["string", "null"] },
                            "hint": { "type": ["string", "null"] }
                        },
                        "required": [
                            "success",
                            "code",
                            "name",
                            "env_var",
                            "provider",
                            "message",
                            "error",
                            "existing_name",
                            "hint"
                        ]
                    }),
                    |service, args| {
                        let args: AddKeyRequest = parse_args(args)?;
                        service.add_key(args)
                    },
                ),
                ToolDefinition::read_with_output(
                    "get_env_snippet",
                    "Build a .env snippet for a project. Values can be masked or returned as real plaintext.",
                    json!({
                        "type": "object",
                        "properties": {
                            "project": { "type": "string" },
                            "mask_values": { "type": "boolean", "default": true }
                        },
                        "required": ["project"]
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "found": { "type": "boolean" },
                            "count": { "type": "integer" },
                            "snippet": { "type": "string" },
                            "keys": {
                                "type": "array",
                                "items": snippet_key_schema()
                            },
                            "masked": { "type": "boolean" },
                            "message": { "type": "string" }
                        },
                        "required": ["found", "snippet"]
                    }),
                    |service, args| {
                        let args: EnvSnippetRequest = parse_args(args)?;
                        service.get_env_snippet(args)
                    },
                ),
                ToolDefinition::read_with_output(
                    "discover_project_context",
                    "Detect project root/name from a path and infer likely required env vars from examples and source references.",
                    json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "Directory or file path to inspect. Defaults to current directory." },
                            "project": { "type": "string", "description": "Optional explicit project tag to compare against vault entries." }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "found": { "type": "boolean" },
                            "path": { "type": "string" },
                            "project": { "type": ["string", "null"] },
                            "root": { "type": ["string", "null"] },
                            "detector": { "type": ["string", "null"] },
                            "workspace_root": { "type": ["string", "null"] },
                            "workspace_detector": { "type": ["string", "null"] },
                            "scan_roots": { "type": "array", "items": { "type": "string" } },
                            "required_vars": { "type": "array", "items": { "type": "string" } },
                            "inference_sources": { "type": "array", "items": { "type": "string" } },
                            "attached_secret_count": { "type": "integer" },
                            "attached_secret_names": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": [
                            "found",
                            "path",
                            "project",
                            "root",
                            "detector",
                            "workspace_root",
                            "workspace_detector",
                            "scan_roots",
                            "required_vars",
                            "inference_sources",
                            "attached_secret_count",
                            "attached_secret_names"
                        ]
                    }),
                    |service, args| {
                        let args: DiscoverProjectRequest = parse_args(args)?;
                        service.discover_project_context(args)
                    },
                ),
                ToolDefinition::read_with_output(
                    "check_project_readiness",
                    "Check whether a project has a complete and healthy set of required env vars.",
                    json!({
                        "type": "object",
                        "properties": {
                            "project": { "type": "string" },
                            "path": { "type": "string", "description": "Optional directory or file path used for inferred required var discovery." },
                            "required_vars": { "type": "array", "items": { "type": "string" } }
                        },
                        "required": ["project"]
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "project": { "type": "string" },
                            "mode": { "type": "string", "enum": ["explicit", "inferred"] },
                            "status": { "type": "string", "enum": ["ready", "attention", "blocked"] },
                            "ready": { "type": "boolean" },
                            "summary": { "type": "string" },
                            "required_vars": {
                                "type": "array",
                                "items": { "type": "string" }
                            },
                            "inference_sources": {
                                "type": "array",
                                "items": { "type": "string" }
                            },
                            "available": {
                                "type": "array",
                                "items": readiness_available_schema()
                            },
                            "attention": {
                                "type": "array",
                                "items": readiness_available_schema()
                            },
                            "missing": {
                                "type": "array",
                                "items": readiness_missing_schema()
                            },
                            "expired": {
                                "type": "array",
                                "items": readiness_expired_schema()
                            },
                            "actions": {
                                "type": "array",
                                "items": { "type": "string" }
                            },
                            "total_required": { "type": "integer" },
                            "total_available": { "type": "integer" },
                            "healthy_count": { "type": "integer" },
                            "attention_count": { "type": "integer" },
                            "missing_count": { "type": "integer" },
                            "expired_count": { "type": "integer" }
                        },
                        "required": [
                            "project",
                            "mode",
                            "status",
                            "ready",
                            "summary",
                            "required_vars",
                            "inference_sources",
                            "available",
                            "attention",
                            "missing",
                            "expired",
                            "actions",
                            "total_required",
                            "total_available",
                            "healthy_count",
                            "attention_count",
                            "missing_count",
                            "expired_count"
                        ]
                    }),
                    |service, args| {
                        let args: ProjectReadinessRequest = parse_args(args)?;
                        service.check_project_readiness(args)
                    },
                ),
            ],
        }
    }

    pub fn list(&self) -> Vec<Value> {
        self.tools.iter().map(ToolDefinition::as_json).collect()
    }

    pub fn call(&self, name: &str, service: &VaultService<'_>, args: Value) -> Result<Value> {
        let tool = self
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .ok_or_else(|| anyhow!("Unknown tool: {name}"))?;
        (tool.handler)(service, args)
    }
}

fn key_metadata_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "env_var": { "type": "string" },
            "provider": { "type": "string" },
            "account_name": { "type": "string" },
            "org_name": { "type": "string" },
            "description": { "type": "string" },
            "source": { "type": "string" },
            "environment": { "type": "string" },
            "permission_profile": { "type": "string" },
            "last_verified_at": { "type": ["string", "null"] },
            "metadata_gaps": { "type": "array", "items": { "type": "string" } },
            "source_quality": { "type": "string" },
            "scopes": { "type": "array", "items": { "type": "string" } },
            "projects": { "type": "array", "items": { "type": "string" } },
            "apply_url": { "type": "string" },
            "status": { "type": "string" },
            "expires_at": { "type": ["string", "null"] },
            "last_used_at": { "type": ["string", "null"] },
            "usage_hint": { "type": "string" },
            "relevance_score": { "type": ["integer", "null"] },
            "matched_fields": { "type": "array", "items": { "type": "string" } }
        },
        "required": [
            "name",
            "env_var",
            "provider",
            "account_name",
            "org_name",
            "description",
            "source",
            "environment",
            "permission_profile",
            "last_verified_at",
            "metadata_gaps",
            "source_quality",
            "scopes",
            "projects",
            "apply_url",
            "status",
            "expires_at",
            "last_used_at",
            "usage_hint",
            "relevance_score",
            "matched_fields"
        ]
    })
}

fn project_keys_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "project": { "type": "string" },
            "key_count": { "type": "integer" },
            "keys": {
                "type": "array",
                "items": { "type": "string" }
            }
        },
        "required": ["project", "key_count", "keys"]
    })
}

fn snippet_key_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "env_var": { "type": "string" },
            "provider": { "type": "string" }
        },
        "required": ["name", "env_var", "provider"]
    })
}

fn readiness_available_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "env_var": { "type": "string" },
            "name": { "type": "string" },
            "status": { "type": "string" },
            "expires_at": { "type": ["string", "null"] },
            "severity": { "type": "string" },
            "reason": { "type": "string" }
        },
        "required": ["env_var", "name", "status", "severity", "reason"]
    })
}

fn readiness_missing_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "env_var": { "type": "string" },
            "suggestion": { "type": "string" },
            "severity": { "type": "string" },
            "reason": { "type": "string" }
        },
        "required": ["env_var", "suggestion", "severity", "reason"]
    })
}

fn readiness_expired_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "env_var": { "type": "string" },
            "name": { "type": "string" },
            "status": { "type": "string" },
            "expires_at": { "type": ["string", "null"] },
            "apply_url": { "type": "string" },
            "severity": { "type": "string" },
            "reason": { "type": "string" }
        },
        "required": ["env_var", "name", "status", "expires_at", "apply_url", "severity", "reason"]
    })
}

struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
    output_schema: Option<Value>,
    annotations: Value,
    handler: ToolHandler,
}

impl ToolDefinition {
    fn write_with_output(
        name: &'static str,
        description: &'static str,
        input_schema: Value,
        output_schema: Value,
        handler: ToolHandler,
    ) -> Self {
        Self {
            name,
            description,
            input_schema,
            output_schema: Some(output_schema),
            annotations: json!({
                "readOnlyHint": false,
                "destructiveHint": false,
                "idempotentHint": false,
                "openWorldHint": true
            }),
            handler,
        }
    }

    fn read_with_output(
        name: &'static str,
        description: &'static str,
        input_schema: Value,
        output_schema: Value,
        handler: ToolHandler,
    ) -> Self {
        Self {
            name,
            description,
            input_schema,
            output_schema: Some(output_schema),
            annotations: json!({
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }),
            handler,
        }
    }

    fn as_json(&self) -> Value {
        let mut value = json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": self.annotations
        });
        if let Some(output_schema) = &self.output_schema {
            value["outputSchema"] = output_schema.clone();
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::ToolRegistry;

    #[test]
    fn high_value_tools_publish_output_schema() {
        let tools = ToolRegistry::new().list();

        for name in [
            "search_keys",
            "get_key_info",
            "list_providers",
            "list_projects",
            "check_health",
            "list_keys_for_project",
            "add_key",
            "discover_project_context",
            "get_env_snippet",
            "check_project_readiness",
        ] {
            let tool = tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("missing tool {name}"));
            assert!(
                tool.get("outputSchema").is_some(),
                "tool {name} should publish outputSchema"
            );
        }
    }
}
