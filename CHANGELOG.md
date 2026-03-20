# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-03-20

### Added

- **Per-project scoped keys**: same env var name (e.g. `DATABASE_URL`) can now store different values for different projects
- `--project` flag on `kf get`, `kf remove`, `kf verify` to select a specific project's key
- `--project-filter` flag on `kf update` for the same purpose
- Interactive picker when multiple secrets share the same name — uses fuzzy search to select
- MCP `inspect_key` now accepts optional `project` parameter to filter results

### Changed

- **Breaking (MCP):** `inspect_key` response changed from a single metadata object to `{ keys: [...], count: N }` — clients consuming this tool need to update
- DB uniqueness constraint moved from `name` column to `id` (UUID) — existing vaults are migrated automatically on first run
- All internal DB operations now use UUID-based lookups instead of name-based
- `kf import --on-conflict` now checks name + project overlap instead of name alone
- `kf health` duplicate detection is now project-aware — same key in different projects is not flagged as a duplicate
- Cloud sync (`kf sync pull`) now considers project overlap when resolving name collisions

## [0.5.0] - 2026-03-16

### Added

- MCP server with 10 tools (discover / inspect / reuse / maintain)
- `kf setup` for one-command AI tool integration
- Cloud sync with end-to-end encryption
- Provider auto-detection for 20+ services
- `kf health` for vault hygiene checks
- `kf scan` for .env candidate discovery

## [0.4.0] - 2026-03-07

### Added

- Initial public release
- AES-256-GCM encrypted local vault
- CLI commands: init, add, get, list, search, update, remove, verify, run, import, export
- Backup and restore
- Homebrew formula
