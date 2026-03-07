# KeyFlow MCP Contract

> Last updated: 2026-03-07
> Scope: stable contract for `tools`, `resources`, `prompts`, `errors`, and `transports`

## Overview

KeyFlow exposes a local MCP server for AI coding tools.

The MCP surface is designed around one core goal:

- help an AI understand what secrets already exist
- help it understand which project or provider context it is operating in
- help it reuse secrets safely without exposing plaintext by default

The contract is intentionally local-first:

- local encrypted vault
- local MCP transport
- local project discovery

## Transports

### stdio

Default transport.

CLI:

```bash
kf serve
# or
kf serve --transport stdio
```

Use this for AI tools that launch MCP servers as child processes.

### HTTP

Optional local HTTP transport.

CLI:

```bash
kf serve --transport http --host 127.0.0.1 --port 8765
```

Endpoints:

- `POST /mcp`
- `GET /healthz`

Security boundary:

- only loopback bind is allowed by default
- allowed examples: `127.0.0.1`, `localhost`, `::1`
- non-loopback bind requires `KEYFLOW_ALLOW_REMOTE_HTTP=1`

KeyFlow does not recommend exposing the HTTP MCP server to LAN or public internet.

## Capabilities

`initialize` advertises:

- `tools`
- `resources`
- `prompts`

Current capability flags:

- `tools.listChanged = false`
- `resources.listChanged = false`
- `resources.subscribe = false`
- `prompts.listChanged = false`

## Tool Groups

KeyFlow tools roughly fall into four groups:

- `discover`
- `inspect`
- `reuse`
- `maintain`

### discover

#### `discover_project_context`

Purpose:

- detect project name and root from a path
- infer likely required env vars
- show which vault secrets are already attached

Key inputs:

- `path`
- `project`

Key outputs:

- `found`
- `project`
- `root`
- `detector`
- `required_vars`
- `inference_sources`
- `attached_secret_count`
- `attached_secret_names`

### inspect

#### `search_keys`

Purpose:

- search secret metadata without returning plaintext values

Key inputs:

- `query`
- `provider`
- `project`
- `limit`
- `offset`
- `include_inactive`

Key outputs:

- `found`
- `total`
- `count`
- `limit`
- `offset`
- `has_more`
- `keys`

#### `get_key_info`

Purpose:

- fetch detailed metadata for one secret by KeyFlow name

Input:

- `name`

Output:

- one metadata object

#### `list_providers`

Purpose:

- list providers and key counts

#### `list_projects`

Purpose:

- list projects and attached key names

Key inputs:

- `query`
- `limit`
- `offset`

Key outputs:

- `total`
- `count`
- `limit`
- `offset`
- `has_more`
- `projects`

#### `list_keys_for_project`

Purpose:

- list secret metadata for one project

Key inputs:

- `project`
- `query`
- `provider`
- `limit`
- `offset`

Key outputs:

- `project`
- `total`
- `count`
- `limit`
- `offset`
- `has_more`
- `keys`

#### `check_health`

Purpose:

- get structured vault health buckets

Key outputs:

- `summary`
- `status`
- `expired`
- `expiring`
- `unused`
- `inactive`
- `metadata_gaps`
- `duplicates`
- `provider_old_keys`
- `source_quality`
- `unverified`

### reuse

#### `get_env_snippet`

Purpose:

- build a `.env` snippet for one project

Key inputs:

- `project`
- `mask_values`

#### `check_project_readiness`

Purpose:

- compare one project’s required vars against attached secrets

Key inputs:

- `project`
- `path`
- `required_vars`

Behavior:

- if `required_vars` is present and non-empty, readiness runs in `explicit` mode
- if `required_vars` is empty, KeyFlow infers vars from project files and runs in `inferred` mode

Key outputs:

- `project`
- `mode`
- `ready`
- `summary`
- `required_vars`
- `inference_sources`
- `available`
- `missing`
- `expired`
- `total_required`
- `total_available`

### maintain

#### `add_key`

Purpose:

- add a new secret to the vault

Key inputs:

- `env_var`
- `value`
- optional metadata such as `provider`, `projects`, `account_name`

Key outputs:

- `success`
- `code`
- `name`
- `env_var`
- `provider`
- `message`
- `error`
- `existing_name`
- `hint`

Current `code` values:

- `created`
- `already_exists`

## Resources

Resources provide read-only context snapshots for AI clients.

### Global resources

- `vault://summary`
- `vault://health`
- `vault://providers`
- `vault://projects`
- `vault://current-project`

### Dynamic resources

- `vault://project/{name}`
- `vault://provider/{name}`

### Recommended read order

For project work:

1. read `vault://current-project`
2. read `vault://project/{name}` if a project name is available
3. call `check_project_readiness`
4. call `search_keys` or `add_key` only if needed

For provider cleanup:

1. read `vault://providers`
2. read `vault://provider/{name}`
3. read `vault://health`
4. call `get_key_info` or `search_keys` only if needed

## Prompts

Prompts provide reusable task templates for AI clients.

### `vault_audit`

Purpose:

- audit vault health and suggest remediation

Arguments:

- `focus` optional

### `project_secret_plan`

Purpose:

- review one project’s secret posture and generate a remediation plan

Arguments:

- `project` required
- `required_vars` optional

### `provider_governance`

Purpose:

- review one provider’s secret hygiene and cleanup opportunities

Arguments:

- `provider` required

## Project Discovery Rules

Project name detection currently checks upward from the given path and supports:

- `package.json`
- `Cargo.toml`
- `pyproject.toml`
- `go.mod`
- `deno.json`
- `deno.jsonc`

Required env var inference currently uses:

- `.env.example`
- `.env.sample`
- `.env.template`
- `.env.local.example`
- `example.env`
- `.env.defaults`

It also scans source references such as:

- `process.env.X`
- `import.meta.env.X`
- `env!("X")`
- `std::env::var("X")`
- `os.getenv("X")`
- `Deno.env.get("X")`

Ignored directories include:

- `.git`
- `node_modules`
- `target`
- `dist`
- `build`
- `.next`

## Error Model

All MCP JSON-RPC errors are normalized to:

```json
{
  "code": -32001,
  "message": "Unknown tool: foo",
  "data": {
    "keyflow_code": "tool_not_found",
    "hint": "Call tools/list first, then use one of the advertised tool names."
  }
}
```

### Current `keyflow_code` values

- `invalid_params`
- `method_not_found`
- `tool_not_found`
- `prompt_not_found`
- `resource_not_found`
- `http_method_not_allowed`
- `http_not_found`
- `http_bind_rejected`
- `parse_error`
- `not_found`
- `internal_error`

Clients should branch primarily on `data.keyflow_code`, not on free-form `message`.

## Stability Notes

The following are intended to be stable integration surfaces:

- tool names
- resource URI patterns
- prompt names
- `error.data.keyflow_code`
- pagination fields: `total`, `count`, `limit`, `offset`, `has_more`

The following may still evolve:

- exact metadata fields inside secret objects
- prompt wording
- inferred env var heuristics
- additional resources or tools

## Non-Goals

This MCP contract does not attempt to provide:

- remote multi-user auth
- hosted SaaS behavior
- provider deployment orchestration
- cloud sync
- broad DevOps control plane features
