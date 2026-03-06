<div align="center">

# KeyFlow

**Developer Key Vault For Repeatable Work**

Store the API keys you already created, find them later, and reuse them across projects with or without AI coding assistants.

[![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-8A2BE2)](#mcp-server-ai-integration)

</div>

---

## What It Solves

KeyFlow is built for a common developer workflow:
- You already created API keys for Google, GitHub, Cloudflare, Resend, OpenAI, Stripe, and others
- A few weeks later, you forget which key still works, which env var name you used, and which project it belongs to
- You end up creating new keys again because the old ones are hard to find
- AI coding assistants can write code faster, but they do not know which secrets you already have

**KeyFlow turns those one-off keys into a reusable local asset library.**

Use it to:
- store keys once and search them later
- tag them by project, provider, and group
- export or inject them back into local development
- track expiration and stale credentials
- optionally let AI tools discover metadata about available keys

## How It Works

```
You                          KeyFlow
 │                              │
 │  create / import a key      │
 │ ──────────────────────────► │  encrypted local vault
 │                              │
 │  kf search github           │
 │ ◄────────────────────────── │  find reusable keys
 │                              │
 │  kf run -- npm dev          │
 │ ◄────────────────────────── │  inject env vars at runtime
 │                              │
 │  optional: MCP for AI       │
 │ ◄────────────────────────── │  expose metadata, not values
```

---

## Screenshots

### Web Dashboard — `kf web`

Dark-themed local dashboard at `http://127.0.0.1:9876` with stat cards, searchable table, provider badges, and i18n (EN/ZH/JA).

<p align="center">
  <img src="docs/web-dashboard.png" alt="Web Dashboard" width="720" />
</p>

### TUI — `kf ui`

Full-featured terminal interface built with [Ratatui](https://ratatui.rs). Navigate with vim keys, search in real-time, copy secrets to clipboard.

<p align="center">
  <img src="docs/tui.png" alt="TUI" width="720" />
</p>

### CLI

<table>
<tr>
<td width="50%">

**`kf list`** — View all secrets at a glance

<img src="docs/cli-list.png" alt="kf list" width="480" />
</td>
<td width="50%">

**`kf search`** — Find secrets across all fields

<img src="docs/cli-search.png" alt="kf search" width="480" />
</td>
</tr>
<tr>
<td width="50%">

**`kf health`** — Expired & expiring key report

<img src="docs/cli-health.png" alt="kf health" width="480" />
</td>
<td width="50%">

**`kf template list`** — 14 predefined service templates

<img src="docs/cli-templates.png" alt="kf template list" width="480" />
</td>
</tr>
</table>

---

## Quick Start

```bash
# Install from source
cargo install --path .

# Or install via Homebrew
brew tap nianyi778/keyflow
brew install keyflow

# Initialize vault
kf init

# Add a key you already created
kf add GOOGLE_CLIENT_ID xxx --provider google --projects myapp
kf add CF_API_TOKEN xxx --provider cloudflare --projects myapp

# List and search what you already have
kf list
kf search cloudflare

# Reuse them in local development
kf run --project myapp -- npm start
kf export --project myapp -o .env

# Check what needs cleanup
kf health

# Optional: connect AI tools later
kf setup
```

> `kf` is the shorthand for `keyflow`. Both commands are identical.

## New User Flow

For a new user, the recommended path is:
1. `kf init`
2. Add 3-5 keys you already use often
3. Tag them with `--projects` so they are easy to reuse
4. Use `kf list`, `kf search`, `kf run`, and `kf export` in a real project
5. Only after that, connect AI tools with `kf setup`

If you never use AI, KeyFlow still works as a local developer key vault.

## Interactive Interfaces

### TUI (Terminal UI)

```bash
kf ui
```

| Key | Action |
|-----|--------|
| `j` / `k` / `↑` / `↓` | Navigate rows |
| `Tab` / `h` / `l` | Switch tabs (Secrets / Health / Groups) |
| `/` | Search mode (real-time filter) |
| `Enter` | Toggle detail panel |
| `y` | Copy secret value to clipboard |
| `g` / `G` | Jump to first / last row |
| `r` | Reload data |
| `q` / `Ctrl+C` | Quit |

### Web Dashboard

```bash
kf web
```

Opens a local-only dark-themed web dashboard at `http://127.0.0.1:9876` with:
- Overview stat cards (Total / Active / Expired / Expiring / Groups)
- Searchable secrets table with provider badges and status indicators
- Health panels for expired and expiring keys
- Filter by provider, project, group
- i18n support: English, Chinese, Japanese

## AI Integration

KeyFlow includes a built-in MCP server for AI coding assistants, but this is an enhancement layer, not the core product.

The core product is local key storage, search, reuse, export, and health tracking.
The AI layer helps assistants discover which env vars and providers already exist without exposing actual secret values.

### Optional Setup

```bash
kf setup          # Auto-detect & configure all installed AI tools
kf setup --list   # See supported tools and their status
```

Supports: **Claude Code**, **Cursor**, **Windsurf**, **Gemini CLI**, **OpenCode**, **Codex**, **Zed**, **Cline**, **Roo Code**

### Manual Setup

If you prefer manual configuration, add to your AI tool's MCP config:

```json
{
  "mcpServers": {
    "keyflow": {
      "command": "kf",
      "args": ["serve"],
      "env": {
        "KEYFLOW_PASSPHRASE": "your-master-passphrase"
      }
    }
  }
}
```

### What AI Sees

Metadata only, never the actual secret:

```json
{
  "name": "google-oauth-client",
  "env_var": "GOOGLE_CLIENT_ID",
  "provider": "google",
  "scopes": ["openid", "email", "profile"],
  "status": "Active",
  "expires_at": "2027-01-15",
  "usage_hint": "Use via environment variable: GOOGLE_CLIENT_ID"
}
```

### MCP Tools

**Read** — AI discovers your secret metadata (never actual values):

| Tool | Description |
|------|-------------|
| `search_keys` | Search secrets by keyword |
| `get_key_info` | Get metadata for a specific secret |
| `list_providers` | List all providers and key counts |
| `list_projects` | List all project tags |
| `check_health` | Check for expired/expiring keys |
| `list_keys_for_project` | List secrets for a project |

**Optional actions** — AI can help with storage and delivery workflows (values never pass through AI):

| Tool | Description |
|------|-------------|
| `deploy_secret` | Deliver a secret to a supported cloud target. Value goes directly from vault to the target CLI. |
| `deploy_project_secrets` | Deliver all secrets for a project to a supported cloud target |
| `add_key` | Add a new secret to the vault (AI stores it, then forgets the value) |
| `get_env_snippet` | Generate `.env` file content for a project (with optional value masking) |
| `check_project_readiness` | Check if a project has all required secrets ready |

## Commands

| Command | Description |
|---------|-------------|
| `kf init` | Initialize vault with master passphrase |
| `kf add` | Add a secret (interactive or `--flags`) |
| `kf list` | List secrets (`--provider`, `--project`, `--group`, `--expiring`, `--inactive`) |
| `kf get <name>` | Get secret value (`--raw` for plain output) |
| `kf search <query>` | Search across all fields |
| `kf update <name>` | Update value or metadata (`--value`, `--group`, `--active`, etc.) |
| `kf remove <name>` | Remove a secret (`-f` to skip confirmation) |
| `kf run -- <cmd>` | Run with secrets as env vars (`--project`, `--group`) |
| `kf import <file>` | Import from `.env` (`--on-conflict overwrite\|skip\|rename`) |
| `kf export` | Export as `.env` (`--project`, `--group`, `-o file`) |
| `kf health` | Health check report |
| `kf group list` | List all key groups |
| `kf group show <name>` | Show secrets in a group |
| `kf group export <name>` | Export a group as `.env` |
| `kf template list` | List predefined templates (14 services) |
| `kf template use <name>` | Create secrets from a template |
| `kf passwd` | Change master passphrase |
| `kf backup` | Backup vault to encrypted file |
| `kf restore <file>` | Restore vault from backup |
| `kf serve` | Start MCP server (stdio) |
| `kf setup` | Auto-configure optional MCP integration for AI tools |
| `kf ui` | Launch interactive TUI |
| `kf web` | Open web dashboard |
| `kf completions <shell>` | Generate shell completions (zsh/bash/fish) |

## Templates

14 predefined service templates to quickly set up common key bundles:

```bash
kf template list
kf template use google-oauth --projects myapp --expires 2027-01-15
```

Available: `google-oauth`, `github-oauth`, `github-token`, `cloudflare-workers`, `cloudflare-r2`, `aws-iam`, `stripe`, `supabase`, `openai`, `anthropic`, `vercel`, `firebase`, `sendgrid`, `docker`

## Security

- **AES-256-GCM** encryption for all secret values
- **Argon2** key derivation from master passphrase
- Secrets stored locally in `~/.keyflow/` with `0700` permissions
- MCP server **never exposes actual secret values** to AI — only metadata
- Runtime injection via `kf run` (secrets never written to disk as plaintext)
- Web dashboard listens on `127.0.0.1` only (not accessible from network)

## Supported Providers

Auto-suggests management URLs for: Google, GitHub, Cloudflare, AWS, Azure, OpenAI, Anthropic, Stripe, Vercel, Supabase, Firebase, Twilio, SendGrid, Slack, Docker, npm, PyPI.

See [docs/product-architecture.md](/Users/likai/personage/pachong/keyflow/docs/product-architecture.md) for the current product boundaries, and [docs/product-roadmap.md](/Users/likai/personage/pachong/keyflow/docs/product-roadmap.md) for delivery priorities.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KEYFLOW_PASSPHRASE` | Skip interactive passphrase prompt |

## Install

```bash
# From source
cargo install --path .

# This installs both `keyflow` and `kf` binaries
```

## License

[MIT](LICENSE) - Copyright (c) 2026 nianyi778
