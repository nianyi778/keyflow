<div align="center">

# KeyFlow

**AI-Native Secret Manager**

Let AI coding assistants automatically discover and use your API keys.

[![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-8A2BE2)](#mcp-server-ai-integration)

</div>

---

## The Problem

Every developer has experienced this:
- New project? Go to Google Console, GitHub Settings, Cloudflare Dashboard to create new keys...again
- Key expired? Production goes down, you scramble to find where to renew it
- AI assistant writes code? You have to manually tell it which env var to use every single time
- CF Workers deploy fails? Forgot which token with what permissions you need

**KeyFlow bridges the gap between your secrets and your AI coding tools.**

## How It Works

```
You                          KeyFlow                        AI Assistant
 │                              │                               │
 │  kf add google-key          │                               │
 │ ──────────────────────────► │                               │
 │                              │  MCP Server (search_keys)    │
 │                              │ ◄──────────────────────────── │
 │                              │  {env_var: "GOOGLE_API_KEY",  │
 │                              │   status: "active",           │
 │                              │   scopes: ["Maps API"]}       │
 │                              │ ────────────────────────────► │
 │                              │                               │
 │                              │  AI writes:                   │
 │                              │  api_key = os.environ[        │
 │                              │    "GOOGLE_API_KEY"            │
 │                              │  ]                             │
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
# Install
cargo install --path .

# Initialize vault
kf init

# Add secrets (interactive)
kf add

# Or non-interactive
kf add --name google-oauth \
  --env-var GOOGLE_CLIENT_ID \
  --value "your-client-id" \
  --provider google \
  --desc "OAuth for web login" \
  --projects "myapp,webapp" \
  --expires "2027-01-15"

# List all secrets
kf list

# Search
kf search cloudflare

# Check health (expired/expiring keys)
kf health

# Run command with secrets injected
kf run -- npm start
kf run --project myapp -- python app.py

# Export as .env
kf export --project myapp -o .env

# Import from .env
kf import .env --provider imported --project myapp
```

> `kf` is the shorthand for `keyflow`. Both commands are identical.

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

## MCP Server (AI Integration)

KeyFlow includes a built-in MCP server that lets AI coding assistants (Claude Code, Cursor, Windsurf, etc.) discover your secrets **without ever seeing the actual values**.

### Setup for Claude Code

Add to `~/.claude/.mcp.json`:

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

### What AI sees (metadata only, never the actual secret):

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

| Tool | Description |
|------|-------------|
| `search_keys` | Search secrets by keyword |
| `get_key_info` | Get metadata for a specific secret |
| `list_providers` | List all providers and key counts |
| `list_projects` | List all project tags |
| `check_health` | Check for expired/expiring keys |
| `list_keys_for_project` | List secrets for a project |

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
| `kf ui` | Launch interactive TUI |
| `kf web` | Open web dashboard |
| `kf completions <shell>` | Generate shell completions (zsh/bash/fish) |

## Templates

14 predefined service templates to quickly set up key bundles:

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

MIT
