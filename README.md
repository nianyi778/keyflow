# KeyFlow

**AI-Native Secret Manager** — Let AI coding assistants automatically discover and use your API keys.

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
 │  keyflow add google-key     │                               │
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

## Quick Start

```bash
# Initialize vault
keyflow init

# Add secrets (interactive)
keyflow add

# Or non-interactive
keyflow add --name google-oauth \
  --env-var GOOGLE_CLIENT_ID \
  --value "your-client-id" \
  --provider google \
  --desc "OAuth for web login" \
  --projects "myapp,webapp" \
  --expires "2027-01-15"

# List all secrets
keyflow list

# Search
keyflow search cloudflare

# Check health (expired/expiring keys)
keyflow health

# Run command with secrets injected
keyflow run -- npm start
keyflow run --project myapp -- python app.py

# Export as .env
keyflow export --project myapp -o .env

# Import from .env
keyflow import .env --provider imported --project myapp
```

## MCP Server (AI Integration)

KeyFlow includes a built-in MCP server that lets AI coding assistants (Claude Code, Cursor, Windsurf, etc.) discover your secrets **without ever seeing the actual values**.

### Setup for Claude Code

Add to your Claude Code MCP config (`~/.claude/claude_desktop_config.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "keyflow": {
      "command": "keyflow",
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

### MCP Tools Available

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
| `keyflow init` | Initialize vault with master passphrase |
| `keyflow add` | Add a secret (interactive or `--flags`) |
| `keyflow list` | List secrets (`--provider`, `--project`, `--expiring`) |
| `keyflow get <name>` | Get secret value (`--raw` for plain output) |
| `keyflow search <query>` | Search across all fields |
| `keyflow update <name>` | Update value or metadata |
| `keyflow remove <name>` | Remove a secret |
| `keyflow run -- <cmd>` | Run with secrets as env vars |
| `keyflow import <file>` | Import from `.env` file |
| `keyflow export` | Export as `.env` format |
| `keyflow health` | Health check report |
| `keyflow serve` | Start MCP server |

## Security

- **AES-256-GCM** encryption for all secret values
- **Argon2** key derivation from master passphrase
- Secrets stored locally in `~/.keyflow/` with `0700` permissions
- MCP server **never exposes actual secret values** to AI — only metadata
- Runtime injection via `keyflow run` (secrets never written to disk as plaintext)

## Supported Providers

Auto-suggests management URLs for: Google, GitHub, Cloudflare, AWS, Azure, OpenAI, Anthropic, Stripe, Vercel, Supabase, Firebase, Twilio, SendGrid, Slack, Docker, npm, PyPI.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KEYFLOW_PASSPHRASE` | Skip interactive passphrase prompt |

## Install

```bash
cargo install --path .
```

## License

MIT
