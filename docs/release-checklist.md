# KeyFlow Release Checklist

> Last updated: 2026-03-07
> Scope: pre-release checklist for the current core-only KeyFlow

## Release Goal

This checklist is for releasing the current KeyFlow core:

- local encrypted vault
- CLI workflows
- MCP `tools / resources / prompts`
- `stdio + HTTP` transport

It is not a checklist for hosted, team, or SaaS behavior.

## Product Boundary

Before release, confirm these are still true:

- no Web UI
- no TUI
- no template system
- no group or bundle model
- no deploy control plane
- no historical compatibility layer reintroduced

If any of the above has reappeared, stop and review scope.

## Core CLI

Verify these commands work in a clean environment:

- `kf init`
- `kf add`
- `kf list`
- `kf search`
- `kf get`
- `kf update`
- `kf remove`
- `kf import`
- `kf export`
- `kf scan`
- `kf run`
- `kf health`
- `kf verify`
- `kf backup`
- `kf restore`
- `kf setup`
- `kf serve`

Manual checks:

- add a secret and retrieve it
- import a project directory with `.env` files
- run a project command with injected env vars
- export a project `.env`
- verify health output is understandable

## Vault Safety

Confirm:

- secret values are encrypted at rest
- plaintext values are not returned by metadata search tools
- backup and restore still work with current format only
- passphrase is not written into MCP tool config files
- startup failure when vault is locked remains explicit and actionable

## MCP Tools

Confirm these tools are listed and callable:

- `discover_project_context`
- `search_keys`
- `get_key_info`
- `list_providers`
- `list_projects`
- `check_health`
- `list_keys_for_project`
- `add_key`
- `get_env_snippet`
- `check_project_readiness`

Contract checks:

- high-value tools publish `outputSchema`
- paginated tools expose `total / count / limit / offset / has_more`
- `add_key` returns stable success/failure codes
- tool errors expose `error.data.keyflow_code`

## MCP Resources

Confirm these resources appear in `resources/list`:

- `vault://summary`
- `vault://health`
- `vault://providers`
- `vault://projects`
- `vault://current-project`
- `vault://project/{name}`
- `vault://provider/{name}`

Manual checks:

- `vault://current-project` returns current project context
- `vault://project/{name}` returns attached secret metadata
- `vault://provider/{name}` returns provider health snapshot

## MCP Prompts

Confirm these prompts appear in `prompts/list`:

- `vault_audit`
- `project_secret_plan`
- `provider_governance`

Manual checks:

- required prompt arguments are enforced
- prompt text references the correct resources and tools

## Project Discovery

Confirm project detection still works for at least:

- `package.json`
- `Cargo.toml`
- `pyproject.toml`
- `go.mod`

Confirm readiness inference still works from:

- `.env.example`
- `.env.sample`
- source env references such as `process.env.X` and `std::env::var("X")`

Confirm ignored directories remain ignored:

- `.git`
- `node_modules`
- `target`
- `dist`
- `build`
- `.next`

## HTTP Transport

Confirm:

- `kf serve --transport http --host 127.0.0.1 --port 8765` starts
- `GET /healthz` returns success
- `POST /mcp` accepts JSON-RPC requests
- non-loopback bind is rejected by default
- `KEYFLOW_ALLOW_REMOTE_HTTP=1` is required for non-loopback bind

Manual checks:

- invalid method returns structured JSON-RPC error body
- invalid path returns structured JSON-RPC error body

## Error Model

Confirm the following still hold:

- JSON-RPC errors include `code`
- JSON-RPC errors include `message`
- JSON-RPC errors include `data.keyflow_code`
- when possible, JSON-RPC errors include `data.hint`

Spot-check common error codes:

- `invalid_params`
- `tool_not_found`
- `prompt_not_found`
- `resource_not_found`
- `http_method_not_allowed`
- `http_bind_rejected`
- `parse_error`

## Documentation

Before release, read and verify:

- `README.md`
- `docs/mcp-contract.md`
- this checklist

Confirm docs are aligned with actual behavior for:

- `kf serve --transport http`
- MCP tool names
- resource URI names
- prompt names
- current product boundary

## Verification Commands

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Optional local smoke checks:

```bash
kf serve
kf serve --transport http --host 127.0.0.1 --port 8765
```

## Release Decision

Release only if all are true:

- scope is still core-only
- docs match current behavior
- no dead code or warning regressions
- no historical compatibility layer has crept back in
- CLI and MCP smoke checks both pass

If any item fails, fix it before tagging a release.
