# Scoped Key Names: Allow Same Name Across Projects

> Date: 2026-03-20
> Status: Approved

## Problem

KeyFlow enforces `name TEXT NOT NULL UNIQUE` on the secrets table. The `name` is derived from `env_var` via `env_var.to_lowercase().replace('_', "-")`. This means `DATABASE_URL` always becomes `database-url`, and only one secret can hold that name — even if different projects need different values for the same env var.

## Decision

Remove the UNIQUE constraint on `name`. Use the existing UUID (`id`) as the sole uniqueness guarantee. Allow multiple secrets with the same `name` as long as their project associations do not overlap.

## Design

### 1. DB Schema

**Before:**

```sql
name TEXT NOT NULL UNIQUE
```

**After:**

```sql
name TEXT NOT NULL
```

No migration needed for existing data — removing UNIQUE is backward-compatible. SQLite does not support `ALTER TABLE ... DROP CONSTRAINT`, so the change is applied via table recreation on first run (standard SQLite migration pattern already used in the codebase).

### 2. Application-Layer Dedup in `create_secret`

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

### 3. CLI Interactive Selection

When `kf get`, `kf update`, `kf remove`, or `kf verify` finds multiple entries with the same name, present a `dialoguer::FuzzySelect` picker:

```
? Multiple secrets named "database-url":
> [1] database-url  (clipverse)    openai     active
  [2] database-url  (starflix)     custom     active
```

Adding `--project <name>` to any of these commands skips the picker and selects directly.

If only one match, behave as before (no picker).

### 4. MCP Changes

#### `inspect_key`

- Add optional `project` parameter
- When name matches multiple entries: return array of metadata objects
- When `project` is specified: filter to matching entry, return single-element array

#### `add_key`

- `already_exists` check changes from "name exists" to "name + project overlap"
- Response unchanged: `code: "created"` or `code: "already_exists"`

#### Other MCP tools

- `search_keys`, `list_keys_for_project`, `discover_*`: already return arrays, no change needed
- `get_env_snippet`: already filters by project, no change needed

### 5. `kf import`

Conflict detection changes from "name exists" to "name exists AND project matches":

- `--on-conflict skip`: skip only if name + project match
- `--on-conflict overwrite`: overwrite only the matching name + project entry
- `--on-conflict rename`: only trigger rename if name + project collide

### 6. `kf run --project`

No change. Key resolution uses `env_var` field (not `name`) and `best_entry_for_env_var()` already handles multiple entries per env_var with priority-based selection.

### 7. Cloud Sync

`ensure_unique_name()` in `sync.rs` currently appends `-2`, `-3` suffixes on name collision during pull. This changes to: collision = same name + overlapping projects. If no project overlap, allow the duplicate name.

### 8. Not Changed

- Existing data: no migration, old keys keep their names
- UUID primary key: unchanged
- Encryption: unchanged
- `kf list`, `kf search`: already return lists
- `kf health` duplicate detection: update to consider name + project (not just env_var value)

## Affected Files

| File | Change |
|------|--------|
| `src/db.rs` | Remove UNIQUE on name, add migration |
| `src/services/secrets.rs` | `create_secret` dedup logic, `secret_exists` → `secrets_by_name` |
| `src/commands/secrets.rs` | Add interactive picker for get/update/remove/verify, add `--project` flag |
| `src/mcp/service.rs` | `inspect_key` returns array, `add_key` dedup change |
| `src/mcp/tools.rs` | `inspect_key` schema: add project param, response becomes array |
| `src/commands/sync.rs` | `ensure_unique_name` considers project overlap |
