use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub struct PromptRegistry;

impl PromptRegistry {
    pub fn new() -> Self {
        Self
    }

    pub fn list(&self) -> Value {
        json!({
            "prompts": [
                prompt_definition(
                    "vault_audit",
                    "Audit vault health, identify risk clusters, and recommend next actions.",
                    vec![
                        prompt_arg(
                            "focus",
                            "Optional focus area such as health, stale, duplicates, or metadata.",
                            false
                        )
                    ]
                ),
                prompt_definition(
                    "project_secret_plan",
                    "Review one project's secret posture and produce a concrete remediation plan.",
                    vec![
                        prompt_arg("project", "Project name stored in KeyFlow.", true),
                        prompt_arg(
                            "required_vars",
                            "Optional comma-separated env var names that the project must have.",
                            false
                        )
                    ]
                ),
                prompt_definition(
                    "provider_governance",
                    "Review one provider's secrets, hygiene issues, and cleanup opportunities.",
                    vec![prompt_arg("provider", "Provider name stored in KeyFlow.", true)]
                )
            ]
        })
    }

    pub fn get(&self, name: &str, arguments: &Value) -> Result<Value> {
        match name {
            "vault_audit" => Ok(vault_audit_prompt(arguments)),
            "project_secret_plan" => project_secret_plan_prompt(arguments),
            "provider_governance" => provider_governance_prompt(arguments),
            _ => Err(anyhow!("Unknown prompt: {name}")),
        }
    }
}

fn prompt_definition(name: &str, description: &str, arguments: Vec<Value>) -> Value {
    json!({
        "name": name,
        "description": description,
        "arguments": arguments
    })
}

fn prompt_arg(name: &str, description: &str, required: bool) -> Value {
    json!({
        "name": name,
        "description": description,
        "required": required
    })
}

fn vault_audit_prompt(arguments: &Value) -> Value {
    let focus = arguments
        .get("focus")
        .and_then(Value::as_str)
        .unwrap_or("overall");
    let text = format!(
        "Audit the KeyFlow vault with focus on '{focus}'. First read vault://summary and vault://health. \
Then identify the highest-risk issues, cluster them by root cause, and recommend a prioritized action plan. \
Use concrete counts, project names, and provider names where available. Do not ask for plaintext secret values."
    );

    json!({
        "description": "Audit the current vault and produce a prioritized remediation plan.",
        "messages": [{
            "role": "user",
            "content": [{
                "type": "text",
                "text": text
            }]
        }]
    })
}

fn project_secret_plan_prompt(arguments: &Value) -> Result<Value> {
    let project = arguments
        .get("project")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Missing required prompt argument: project"))?;
    let required_vars = arguments
        .get("required_vars")
        .and_then(Value::as_str)
        .unwrap_or("");
    let text = if required_vars.is_empty() {
        format!(
            "Review the secret posture for project '{project}'. First read vault://project/{project}. \
Then inspect relevant tools or resources to identify missing metadata, stale keys, expiry risk, and cleanup work. \
Return a practical action plan for this project only."
        )
    } else {
        format!(
            "Review the secret posture for project '{project}'. The required env vars are: {required_vars}. \
First read vault://project/{project}, then use maintain_project_readiness for the required vars. \
Return a gap analysis and a concrete remediation checklist."
        )
    };

    Ok(json!({
        "description": format!("Review project '{project}' and produce a remediation plan."),
        "messages": [{
            "role": "user",
            "content": [{
                "type": "text",
                "text": text
            }]
        }]
    }))
}

fn provider_governance_prompt(arguments: &Value) -> Result<Value> {
    let provider = arguments
        .get("provider")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Missing required prompt argument: provider"))?;
    let text = format!(
        "Review provider '{provider}' in KeyFlow. First read vault://provider/{provider} and vault://providers. \
Then identify redundant keys, inactive assets, expiry risks, metadata gaps, and stale credentials. \
Produce a provider-specific cleanup and governance plan."
    );

    Ok(json!({
        "description": format!("Review provider '{provider}' and produce governance recommendations."),
        "messages": [{
            "role": "user",
            "content": [{
                "type": "text",
                "text": text
            }]
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_exposes_core_prompts() {
        let prompts = PromptRegistry::new().list();
        let items = prompts["prompts"].as_array().unwrap();
        assert!(items.iter().any(|item| item["name"] == "vault_audit"));
        assert!(items
            .iter()
            .any(|item| item["name"] == "project_secret_plan"));
        assert!(items
            .iter()
            .any(|item| item["name"] == "provider_governance"));
    }

    #[test]
    fn get_requires_named_arguments() {
        let registry = PromptRegistry::new();
        let err = registry.get("project_secret_plan", &json!({})).unwrap_err();
        assert!(err.to_string().contains("project"));
    }
}
