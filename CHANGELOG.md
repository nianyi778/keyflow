# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Sync push wire format**: `is_deleted` is now serialized as an integer (the
  worker rejected the previous boolean shape; non-empty pushes returned HTTP
  400). Added a regression test.
- **File permissions**: `keyflow.db` + WAL/SHM sidecars, `sync.json`,
  `config.json`, `.passphrase`, and the new MCP audit log are all created /
  tightened to `0600` via a new `secure_fs` helper.
- **Master passphrase**: no longer cached implicitly. Added `kf unlock
  [--ttl <hours>]` (default 8h, `0` = no expiry) as the only path that writes
  the keyfile; `kf passwd` clears the stale cache after rekey.
- **MCP plaintext disclosure**: `reuse_env_snippet` masks values by default;
  plaintext is returned only when the operator starts the server with
  `KEYFLOW_MCP_ALLOW_REVEAL=1`. Every reveal is appended to
  `<data_dir>/mcp-audit.jsonl`.
- **MCP HTTP transport**: requires a bearer token (`KEYFLOW_MCP_TOKEN`, or a
  freshly generated value printed at startup); browser `Origin` headers are
  rejected. Constant-time token compare.
- **Message size caps**: both stdio and HTTP MCP transports cap inbound
  `Content-Length` at 8 MiB to prevent allocation DoS.
- **Argon2id parameters** pinned explicitly (values match the 0.5.x defaults
  so existing vaults stay decryptable); a future `argon2` upgrade can no
  longer silently change the derived key.
- **`kf passwd`** now backs the vault DB up to `keyflow.db.pre-passwd.bak`
  before re-encrypting and writes `config.json` atomically (temp file +
  rename), so an interrupted rekey is recoverable.
- **`kf run`** drops the SQLite connection and in-memory secret buffers
  before `process::exit`.
- **`kf sync`** rejects non-HTTPS endpoints (loopback excepted) and uses
  PKCE on the device flow.
- **`kf export -o <file>`** writes the `.env` file `0600` and prints a
  plaintext-on-disk warning.

### Worker

- OAuth `state` is a random nonce stored in KV (CSRF protection); Google
  `id_token` is verified via JWKS (`iss`, `aud === GOOGLE_CLIENT_ID`, `exp`).
- Device flow uses PKCE with constant-time verifier compare; sessions are
  one-time and deleted on first successful poll.
- Token lifetime cut from 365 d to 7 d; new `tv` (token_version) claim is
  checked on every authenticated request, with `/api/revoke` and `/api/logout`
  bumping the version (D1 migration `002_token_version.sql`).
- `/api/push` caps `entries.length`, per-blob byte size, and per-user storage
  quota; `server_seq` is monotonically assigned in a single D1 batch to
  eliminate a concurrent-push race.
- Rate limiting switched from racy KV counters to Cloudflare-native
  bindings (`API_RATE_LIMITER`, `AUTH_RATE_LIMITER`).
- 27 new tests covering JWT verification, token-version revocation, IDOR
  isolation, PKCE.

### Added

- `Database::open` takes `&Path` (was `&str`), eliminating 9
  `to_str().unwrap()` panic sites.
- `MCP delete_key` accepts an optional `project` to disambiguate same-named
  secrets; multi-match calls return a structured `ambiguous` error listing
  candidates instead of silently deleting `entries[0]`.
- Typed error enums (`SecretError`, `McpProtocolError`) replace
  `error.to_string().contains(...)` matching in `classify_anyhow_error`,
  `add_key`, and `cmd_import`.

### Fixed

- `row_to_entry` no longer silently substitutes `Default::default()` for
  corrupt `scopes` / `projects` JSON or `Utc::now()` for corrupt
  `created_at`/`updated_at` — corruption is surfaced with the secret id.
- AES-GCM `decrypt` error message no longer interpolates the opaque library
  error; tamper-detection test added.

### Breaking

- The deprecated keyfile-auto-cache UX is removed; users must run
  `kf unlock` (or set `KEYFLOW_PASSPHRASE`) to skip future prompts.
- Worker tokens issued before this release lack the `tv` claim and will
  fail verification — running `kf sync init` again issues a fresh token.

## [0.9.0] - 2026-04-22

### Added

- `kf update --rename <new-name>` — rename a key in-place without delete + recreate
- Uniqueness validation for rename at the service layer (returns an error if the new name conflicts)
- Open Graph image (1200×630 PNG) for social sharing
- `sitemap.xml` and `robots.txt` for search engine indexing
- Twitter Card and JSON-LD `SoftwareApplication` structured data on the landing page

### Changed

- Landing page: improved meta description, canonical URL, and keyword density for SEO
- Feature copy: "Military-Grade Security" → "AES-256-GCM · Argon2 · Local-First"

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
