# Product Architecture

## Product Definition

KeyFlow is a local developer key vault.

Its primary job is to help developers:
- store API keys they already created
- find them later
- reuse them across projects
- avoid re-creating the same credentials
- track expiration and stale secrets over time

AI integration is an enhancement layer, not the product definition.

## Core Value

These are the jobs the product must do well:
- Local encrypted storage for developer secrets
- Fast search by provider, env var, description, group, and project
- Reuse in local workflows via `kf run` and `kf export`
- Import existing `.env` files into a durable vault
- Health visibility for expired, expiring, inactive, and stale keys
- Lightweight metadata that helps users remember what a key is for

If these are weak, the product loses its reason to exist.

## AI-Enhanced Value

These capabilities make the core product more powerful for AI-assisted development:
- MCP metadata discovery for available keys
- AI-readable env var and provider hints
- Project readiness checks
- Assisted key entry and retrieval workflows
- Optional setup for Claude, Codex, Cursor, Windsurf, and similar tools

These features should reduce friction, not redefine the product.

## Deferred Value

These areas are useful, but they should not dominate the roadmap until the core is solid:
- AI-driven deployment actions
- Broad cloud secret sync and rotation orchestration
- Full secret lifecycle automation across external services
- Enterprise/team workflows
- Browser-based hosted vault behavior

They increase complexity, safety burden, and support surface quickly.

## Product Guardrails

When deciding whether to add a feature, prefer it if it strengthens one of these:
- easier key capture
- easier search and recall
- easier safe reuse
- better visibility into key health and ownership

Be cautious if a feature mainly does one of these:
- turns the product into a deployment tool
- stores more sensitive material outside the local vault
- makes AI the only believable entry point
- adds provider-specific complexity without improving reuse

## Ideal User Journey

1. A developer initializes the vault.
2. They add keys they already use for Google, GitHub, Cloudflare, Resend, OpenAI, Stripe, and others.
3. They tag each key with project and purpose.
4. They reuse those keys with `kf search`, `kf run`, and `kf export`.
5. They use `kf health` to see what needs cleanup or rotation.
6. They optionally connect AI tools so assistants can discover metadata and suggest the right env vars.

## Current Product Tension

There are two competing narratives:
- "developer key vault"
- "AI-native secret operations toolkit"

The first should remain primary.
The second should stay secondary until the storage, search, reuse, and health story is clearly dominant.
