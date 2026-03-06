# Product Roadmap

## Must Do

These are the capabilities that define the product.

- Make key capture easier:
  import from `.env`, paste from clipboard, templates for common providers, and better metadata defaults
- Make reuse obvious:
  stronger search, project-based reuse, better `kf run`, better `kf export`
- Make recall trustworthy:
  provider, account, project, purpose, expiration, and status should be easy to understand at a glance
- Make health actionable:
  expired, expiring, inactive, and stale keys should lead to cleanup decisions
- Align product messaging:
  present KeyFlow as a developer key vault first, AI-enhanced second
- Improve high-frequency provider coverage:
  especially Google, GitHub, Cloudflare, Resend, OpenAI, Stripe

If these are weak, users will keep re-creating keys instead of reusing them.

## Should Do

These strengthen the product once the core workflow is solid.

- Passive key capture:
  scan local `.env` files, remember reused env vars, and reduce manual `kf add`
- Better metadata model:
  account/org, environment, permission profile, source, last verified time
- Stronger AI assistance:
  better MCP read tools, project readiness checks, env var recommendations
- Better setup experience:
  safer AI config setup, clearer guidance, less plain-text secret handling
- Public cloud delivery:
  improve secret delivery to supported cloud CLIs and project targets
- Private deployment packaging:
  Docker, Compose, and self-hosted deployment path for users who want full control

## Defer

These are useful, but they should not drive the roadmap yet.

- Full AI-driven deployment orchestration
- Broad provider-by-provider secret rotation automation
- Hosted multi-tenant team product before single-user workflows are sharp
- Complex enterprise permission systems
- Turning KeyFlow into a general DevOps control plane

## Version Matrix

### Local Edition

- CLI, TUI, local web dashboard
- local encrypted vault
- import, search, export, run, backup, restore
- optional AI integration

### Hosted Edition

- your managed service
- easier onboarding and sync
- web-first experience
- managed release channel and integrations

### Self-Hosted Edition

- user deploys it themselves
- private control over data and runtime
- suitable for homelab, internal team, or regulated environments

## Decision Rule

Prefer a feature if it helps users do one of these faster:
- capture a key
- find a key
- trust a key
- reuse a key
- safely deliver a key to an environment

Be cautious if a feature mostly adds:
- provider-specific maintenance burden
- AI-only workflows with weak non-AI value
- deployment complexity without improving reuse
- new operational risk around secret exposure
