# Scoped Key Names: Allow Same Name Across Projects

> Date: 2026-03-20
> Status: Approved

## Problem

KeyFlow enforces `name TEXT NOT NULL UNIQUE` on the secrets table. The `name` is derived from `env_var` via `env_var.to_lowercase().replace('_', "-")`. This means `DATABASE_URL` always becomes `database-url`, and only one secret can hold that name — even if different projects need different values for the same env var.

## Decision

Remove the UNIQUE constraint on `name`. Use the existing UUID (`id`) as the sole uniqueness guarantee. Allow multiple secrets with the same `name` as long as their project associations do not overlap.

## Design

### 1. DB Schema Migration

**Before:**

```sql
name TEXT NOT NULL UNIQUE
```

**After:**

```sql
name TEXT NOT NULL
```

**Migration steps** (SQLite cannot drop constraints in-place):

1. Detect schema version (check if UNIQUE exists on `name`)
2. Begin transaction
3. `CREATE TABLE secrets_new (...)` with same columns but without UNIQUE on `name`
4. `INSERT INTO secrets_new SELECT * FROM secrets`
5. `DROP TABLE secrets`
6. `ALTER TABLE secrets_new RENAME TO secrets`
7. Recreate indexes
8. Commit transaction

This follows the same table-recreation pattern already used in the codebase. Existing data is preserved as-is.

### 2. DB Layer: Migrate All Name-Based Lookups to ID

The following `db.rs` methods currently use `WHERE name = ?` and assume a single row. All must be migrated to use `WHERE id = ?`:

| Method | Current behavior | Change |
|--------|-----------------|--------|
| `get_secret(name)` | `query_row` by name | Change to `get_secret_by_id(id)`. Add `get_secrets_by_name(name) -> Vec` for lookup. |
| `get_secret_value(name)` | Single row by name, updates `last_used_at` | Change to `get_secret_value_by_id(id)` |
| `remove_secret(name)` | `DELETE WHERE name` — deletes ALL with that name | Change to `remove_secret_by_id(id)` |
| `update_secret_value(name)` | `UPDATE WHERE name` — updates ALL | Change to `update_secret_value_by_id(id)` |
| `update_secret_metadata(name)` | `UPDATE WHERE name` — updates ALL | Change to `update_secret_metadata_by_id(id)` |
| `secret_exists(name)` | Boolean check | Change to `secrets_by_name(name) -> Vec` |
| `reencrypt_all` | Iterates `(name, plaintext)`, updates by name | Change to iterate `(id, plaintext)`, update by `id` |

The general pattern: **resolve name → ID at the CLI/service layer** (with interactive picker if ambiguous), then pass `id` to all DB write operations.

### 3. Application-Layer Dedup in `create_secret`

Old logic:

```
if name exists → error
```

New logic:

```
find all entries with same name
if draft.projects is empty (global key):
    if any existing entry also has empty projects → error "global key already exists"
if draft.projects is non-empty:
    for each existing entry with same name:
        if intersection(draft.projects, entry.projects) is non-empty → error "key already exists for project X"
allow creation
```

### 4. CLI: Interactive Selection + `--project` Flag

When `kf get`, `kf update`, `kf remove`, or `kf verify` finds multiple entries with the same name, present a `dialoguer::FuzzySelect` picker:

```
? Multiple secrets named "database-url":
> [1] database-url  (clipverse)    openai     active
  [2] database-url  (starflix)     custom     active
```

- Adding `--project <name>` to any of these commands skips the picker and selects directly
- If only one match, behave as before (no picker)
- `--project` flag needs to be added to the CLI arg definitions in `src/cli.rs`

### 5. MCP Changes

#### `inspect_key` — **Breaking change**

- Add optional `project` parameter
- Response changes from single object to array of metadata objects
- When `project` is specified: filter to matching entry
- **This is a breaking MCP contract change.** Bump MCP version and document in `docs/mcp-contract.md`.

#### `add_key`

- `already_exists` check changes from "name exists" to "name + project overlap"
- Response unchanged: `code: "created"` or `code: "already_exists"`

#### `get_env_snippet`

- Currently calls `get_secret_value(&entry.name)` internally — must change to ID-based lookup

#### Other MCP tools

- `search_keys`, `list_keys_for_project`, `discover_*`: already return arrays, no change needed

### 6. `kf import`

Conflict detection changes from "name exists" to "name exists AND project matches":

- `--on-conflict skip`: skip only if name + project match
- `--on-conflict overwrite`: overwrite only the matching name + project entry (by ID)
- `--on-conflict rename`: only trigger rename if name + project collide

### 7. `kf run --project`

Mostly unchanged. `best_entry_for_env_var()` already handles priority selection by env_var. One fix needed: `get_all_for_env` must deduplicate by `env_var` when multiple entries share the same env_var — ensure only one value per env_var is injected (the winner from `best_entry_for_env_var`).

### 8. `kf export`

`export_project_env` calls `get_secret_value(&entry.name)` — must change to ID-based lookup to avoid ambiguity.

### 9. Cloud Sync

`ensure_unique_name()` in `sync.rs` currently appends `-2`, `-3` suffixes on name collision during pull. This changes to: collision = same name + overlapping projects. If no project overlap, allow the duplicate name.

### 10. `kf health` Duplicate Detection

`find_duplicate_groups` in `models.rs` currently groups by env_var value. Update to consider name + project scope — two entries with the same name but different projects are NOT duplicates.

### 11. Not Changed

- Existing data: preserved as-is, old keys keep their names
- UUID primary key: unchanged
- Encryption: unchanged
- `kf list`, `kf search`: already return lists

## Affected Files

| File | Change |
|------|--------|
| `src/db.rs` | Remove UNIQUE on name, add migration, migrate all name-based methods to ID-based |
| `src/services/secrets.rs` | `create_secret` dedup logic, add `secrets_by_name`, `verify_names` uses ID, `export_project_env` uses ID |
| `src/commands/secrets.rs` | Add interactive picker for get/update/remove/verify, resolve name→ID before DB calls |
| `src/cli.rs` | Add `--project` flag to get/update/remove/verify subcommands |
| `src/mcp/service.rs` | `inspect_key` returns array, `add_key` dedup change, `get_env_snippet` uses ID |
| `src/mcp/tools.rs` | `inspect_key` schema: add project param, response becomes array |
| `src/commands/sync.rs` | `ensure_unique_name` considers project overlap |
| `src/commands/auth.rs` | `select_secret` helper shows project in picker for disambiguation |
| `src/models.rs` | `find_duplicate_groups` considers project scope |
| `docs/mcp-contract.md` | Document `inspect_key` breaking change, version bump |
| `tests/` | Add tests for dedup logic, interactive picker, multi-name scenarios |
