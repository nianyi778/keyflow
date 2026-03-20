# Scoped Key Names Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow multiple secrets with the same name across different projects by removing the UNIQUE constraint on `name` and migrating all DB operations to use UUID `id`.

**Architecture:** Remove `name UNIQUE` from SQLite schema via table recreation. Migrate all single-row DB methods from `WHERE name = ?` to `WHERE id = ?`. Add a new `get_secrets_by_name()` method returning `Vec<SecretEntry>`. CLI commands resolve name → entry (with interactive picker if ambiguous), then pass `id` to DB layer.

**Tech Stack:** Rust, rusqlite, dialoguer (FuzzySelect), serde_json, clap

**Spec:** `docs/superpowers/specs/2026-03-20-scoped-key-names-design.md`

---

### Task 1: DB Schema Migration — Remove UNIQUE on name

**Files:**
- Modify: `src/db.rs:41-70`

- [ ] **Step 1: Write the failing test**

```rust
// tests/service_secrets.rs — add at bottom
// Uses existing helpers: temp_service() and draft(env_var, value, provider, projects)
#[test]
fn test_duplicate_name_different_projects() {
    let (_dir, service) = temp_service();

    service.create_secret(draft("DATABASE_URL", "postgres://clipverse:5432", "custom", &["clipverse"])).unwrap();

    // Should succeed — same name, different project
    let result = service.create_secret(draft("DATABASE_URL", "postgres://starflix:5432", "custom", &["starflix"]));
    assert!(result.is_ok(), "Should allow same env_var for different projects");

    // Should fail — same name, overlapping project
    let result = service.create_secret(draft("DATABASE_URL", "postgres://other:5432", "custom", &["clipverse"]));
    assert!(result.is_err(), "Should reject same env_var for same project");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_duplicate_name_different_projects -- --nocapture`
Expected: FAIL — current UNIQUE constraint or `secret_exists` check blocks the second insert.

- [ ] **Step 3: Add schema migration in `init_tables`**

In `src/db.rs`, replace `init_tables()` (lines 41-70) with migration-aware version:

```rust
fn init_tables(&self) -> Result<()> {
    // Check if migration needed (UNIQUE on name)
    let needs_migration = self.has_unique_name_constraint()?;

    if needs_migration {
        self.migrate_remove_name_unique()?;
    } else {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                env_var TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                provider TEXT NOT NULL DEFAULT '',
                account_name TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                scopes TEXT NOT NULL DEFAULT '[]',
                projects TEXT NOT NULL DEFAULT '[]',
                apply_url TEXT NOT NULL DEFAULT '',
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                last_verified_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                org_name TEXT NOT NULL DEFAULT '',
                environment TEXT NOT NULL DEFAULT '',
                permission_profile TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_secrets_env_var ON secrets(env_var);
            CREATE INDEX IF NOT EXISTS idx_secrets_provider ON secrets(provider);
            CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);",
        )?;
    }
    Ok(())
}

fn has_unique_name_constraint(&self) -> Result<bool> {
    let sql: String = self.conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='secrets'",
        [],
        |row| row.get(0),
    ).unwrap_or_default();
    // Check specifically for "name TEXT NOT NULL UNIQUE" to avoid matching PRIMARY KEY
    Ok(sql.contains("name TEXT NOT NULL UNIQUE"))
}

fn migrate_remove_name_unique(&self) -> Result<()> {
    let tx = self.conn.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE TABLE secrets_new (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            env_var TEXT NOT NULL,
            encrypted_value BLOB NOT NULL,
            provider TEXT NOT NULL DEFAULT '',
            account_name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            scopes TEXT NOT NULL DEFAULT '[]',
            projects TEXT NOT NULL DEFAULT '[]',
            apply_url TEXT NOT NULL DEFAULT '',
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_used_at TEXT,
            last_verified_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            org_name TEXT NOT NULL DEFAULT '',
            environment TEXT NOT NULL DEFAULT '',
            permission_profile TEXT NOT NULL DEFAULT ''
        );
        INSERT INTO secrets_new SELECT * FROM secrets;
        DROP TABLE secrets;
        ALTER TABLE secrets_new RENAME TO secrets;
        CREATE INDEX idx_secrets_env_var ON secrets(env_var);
        CREATE INDEX idx_secrets_provider ON secrets(provider);
        CREATE INDEX idx_secrets_name ON secrets(name);"
    )?;
    tx.commit()?;
    Ok(())
}
```

- [ ] **Step 4: Run test to verify migration works**

Run: `cargo test test_duplicate_name_different_projects -- --nocapture`
Expected: Still FAIL — migration works but `create_secret` still uses `secret_exists` check. That's expected, fixed in Task 2.

- [ ] **Step 5: Commit**

```bash
git add src/db.rs
git commit -m "feat(db): remove UNIQUE constraint on name, add migration"
```

---

### Task 2: DB Layer — Migrate Methods from Name to ID

**Files:**
- Modify: `src/db.rs:159-392`

- [ ] **Step 1: Add `get_secrets_by_name` returning Vec**

Add after current `get_secret` (line 168):

```rust
pub fn get_secrets_by_name(&self, name: &str) -> Result<Vec<SecretEntry>> {
    let mut stmt = self.conn.prepare(&format!(
        "SELECT {} FROM secrets WHERE name = ?1",
        SECRET_COLUMNS
    ))?;
    let rows = stmt.query_map(params![name], |row| Ok(self.row_to_entry(row)))?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(row??);
    }
    Ok(entries)
}
```

- [ ] **Step 2: Add `get_secret_by_id`**

```rust
pub fn get_secret_by_id(&self, id: &str) -> Result<SecretEntry> {
    let mut stmt = self.conn.prepare(&format!(
        "SELECT {} FROM secrets WHERE id = ?1",
        SECRET_COLUMNS
    ))?;
    let entry = stmt
        .query_row(params![id], |row| Ok(self.row_to_entry(row)))
        .context(format!("Secret with id '{id}' not found"))??;
    Ok(entry)
}
```

- [ ] **Step 3: Migrate `get_secret_value` to ID-based**

Change `get_secret_value` (line 170) from name to id:

```rust
pub fn get_secret_value(&self, id: &str) -> Result<String> {
    let mut stmt = self
        .conn
        .prepare("SELECT encrypted_value FROM secrets WHERE id = ?1")?;
    let encrypted: Vec<u8> = stmt
        .query_row(params![id], |row| row.get(0))
        .context(format!("Secret with id '{id}' not found"))?;

    self.conn.execute(
        "UPDATE secrets SET last_used_at = ?1 WHERE id = ?2",
        params![Utc::now().to_rfc3339(), id],
    )?;

    let decrypted = self.crypto.decrypt(&encrypted)?;
    String::from_utf8(decrypted).context("Secret value is not valid UTF-8")
}
```

- [ ] **Step 4: Migrate `remove_secret` to ID-based**

```rust
pub fn remove_secret(&self, id: &str) -> Result<bool> {
    let affected = self
        .conn
        .execute("DELETE FROM secrets WHERE id = ?1", params![id])?;
    Ok(affected > 0)
}
```

- [ ] **Step 5: Migrate `update_secret_value` to ID-based**

```rust
pub fn update_secret_value(&self, id: &str, new_value: &str) -> Result<()> {
    let encrypted = self.crypto.encrypt(new_value.as_bytes())?;
    let now = Utc::now().to_rfc3339();
    self.conn.execute(
        "UPDATE secrets SET encrypted_value = ?1, updated_at = ?2 WHERE id = ?3",
        params![encrypted, now, id],
    )?;
    Ok(())
}
```

- [ ] **Step 6: Migrate `update_secret_metadata` to ID-based**

Change line 204 signature from `name: &str` to `id: &str`, and line 257-261:

```rust
pub fn update_secret_metadata(&self, id: &str, update: &MetadataUpdate<'_>) -> Result<()> {
    // ... existing set_clause logic unchanged ...

    bind_values.push(id.to_string());
    let sql = format!(
        "UPDATE secrets SET {} WHERE id = ?{}",
        set_clauses.join(", "),
        bind_values.len()
    );
    // ... rest unchanged ...
}
```

- [ ] **Step 7: Migrate `reencrypt_all` to ID-based**

Change `get_all_raw` to return `(id, encrypted_value)` and `reencrypt_all` to use id:

```rust
pub fn get_all_raw(&self) -> Result<Vec<(String, Vec<u8>)>> {
    let mut stmt = self
        .conn
        .prepare("SELECT id, encrypted_value FROM secrets")?;
    // ... rest unchanged ...
}

pub fn reencrypt_all(&self, pairs: &[(String, Vec<u8>)], new_crypto: &Crypto) -> Result<()> {
    let tx = self.conn.unchecked_transaction()?;
    for (id, plaintext) in pairs {
        let new_encrypted = new_crypto.encrypt(plaintext)?;
        tx.execute(
            "UPDATE secrets SET encrypted_value = ?1 WHERE id = ?2",
            params![new_encrypted, id],
        )?;
    }
    tx.commit()?;
    Ok(())
}
```

- [ ] **Step 8: Migrate `get_all_for_env` to use ID for batch update**

Change `get_all_for_env` (line 293) to select `id` instead of `name`, and use `id` for the `last_used_at` batch update:

```rust
pub fn get_all_for_env(&self, project: Option<&str>) -> Result<Vec<(String, String)>> {
    let mut sql =
        "SELECT env_var, encrypted_value, id FROM secrets WHERE is_active = 1".to_string();
    // ... project filter unchanged ...

    sql.push_str(" ORDER BY provider, name");

    let mut stmt = self.conn.prepare(&sql)?;
    // ...
    let rows = stmt.query_map(params.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,  // id instead of name
        ))
    })?;

    let now = Utc::now().to_rfc3339();
    let mut result = Vec::new();
    let mut ids = Vec::new();
    for row in rows {
        let (env_var, encrypted, id) = row?;
        let decrypted = self.crypto.decrypt(&encrypted)?;
        let value = String::from_utf8(decrypted).context("Secret value is not valid UTF-8")?;
        result.push((env_var, value));
        ids.push(id);
    }

    // Batch update last_used_at using id
    if !ids.is_empty() {
        let placeholders: Vec<String> =
            (1..=ids.len()).map(|i| format!("?{}", i + 1)).collect();
        let update_sql = format!(
            "UPDATE secrets SET last_used_at = ?1 WHERE id IN ({})",
            placeholders.join(", ")
        );
        let mut update_params: Vec<&dyn rusqlite::types::ToSql> = vec![&now];
        for id in &ids {
            update_params.push(id);
        }
        self.conn.execute(&update_sql, update_params.as_slice())?;
    }

    Ok(result)
}
```

- [ ] **Step 9: Remove old `get_secret` and `secret_exists` (replaced by new methods)**

Delete `get_secret` (lines 159-168) and `secret_exists` (lines 354-360). All callers will be updated in subsequent tasks.

- [ ] **Step 10: Run all tests**

Run: `cargo test`
Expected: Compilation errors in callers of changed methods — that's expected, fixed in Tasks 3-6. **Note:** Task 2 intentionally breaks callers; Tasks 2+3 should be developed together for compilability. The commit boundary is here for logical grouping, but you may combine Tasks 2+3 into a single commit if preferred.

- [ ] **Step 11: Commit**

```bash
git add src/db.rs
git commit -m "feat(db): migrate all single-row methods from name to id"
```

---

### Task 3: Service Layer — Update `create_secret` Dedup + Fix Callers

**Files:**
- Modify: `src/services/secrets.rs:924-984, 1095-1165, 1257-1293`

- [ ] **Step 1: Update `create_secret` dedup logic**

Replace lines 949-957 in `services/secrets.rs`:

```rust
pub fn create_secret(&self, draft: SecretDraft) -> Result<SecretEntry> {
    let name = draft.env_var.to_lowercase().replace('_', "-");

    // Check for name+project overlap
    let existing = self.db.get_secrets_by_name(&name)?;
    if draft.projects.is_empty() {
        // Global key — reject if another global key with same name exists
        if existing.iter().any(|e| e.projects.is_empty()) {
            bail!(
                "Secret '{}' already exists as a global key. Use 'kf update {}' to modify.",
                name, name
            );
        }
    } else {
        // Project-scoped — reject if any existing entry has overlapping projects
        for entry in &existing {
            for project in &draft.projects {
                if entry.projects.contains(project) {
                    bail!(
                        "Secret '{}' already exists for project '{}'. Use 'kf update' to modify.",
                        name, project
                    );
                }
            }
        }
    }

    // ... rest of create_secret unchanged from line 959 ...
```

- [ ] **Step 2: Update `verify_names` to use ID**

Replace lines 924-936:

```rust
pub fn verify_names(&self, names: &[String]) -> Result<DateTime<Utc>> {
    let now = Utc::now();
    for name in names {
        let entries = self.db.get_secrets_by_name(name)?;
        for entry in entries {
            self.db.update_secret_metadata(
                &entry.id,
                &MetadataUpdate {
                    last_verified_at: Some(Some(now)),
                    ..Default::default()
                },
            )?;
        }
    }
    Ok(now)
}
```

- [ ] **Step 3: Update `export_project_env` to use ID**

Replace line 1288 in `export_project_env`:

```rust
// Before:
// self.db.get_secret_value(&entry.name)?
// After:
self.db.get_secret_value(&entry.id)?
```

- [ ] **Step 4: Update service-layer wrappers (lines 342-363)**

These thin wrappers in `services/secrets.rs` must be migrated:

```rust
// get_entry: change from name to id lookup
pub fn get_entry_by_id(&self, id: &str) -> Result<SecretEntry> {
    self.db.get_secret_by_id(id)
}

// get_secret_value: now takes id
pub fn get_secret_value(&self, id: &str) -> Result<String> {
    self.db.get_secret_value(id)
}

// inspect_secret: change to use id
pub fn inspect_secret_by_id(&self, id: &str) -> Result<SecretValueView> {
    Ok(SecretValueView {
        entry: self.get_entry_by_id(id)?,
        value: self.get_secret_value(id)?,
    })
}

// remove_secret: change to use id
pub fn remove_secret(&self, id: &str) -> Result<bool> {
    self.db.remove_secret(id)
}

// secret_exists: remove entirely, replaced by get_entries_by_name
```

- [ ] **Step 5: Update `update_secret` to use ID**

Find the `update_secret` method (around line 880-922). Change its `name` parameter to `id`:
- `self.db.update_secret_value(name, ...)` → `self.db.update_secret_value(id, ...)`
- `self.db.update_secret_metadata(name, ...)` → `self.db.update_secret_metadata(id, ...)`

- [ ] **Step 7: Ensure `resolve_run_env_pairs` deduplicates by env_var**

In `services/secrets.rs`, find `resolve_run_env_pairs` (around line 1295). With scoped names, `get_all_for_env` may return multiple entries with the same `env_var` (e.g. two `DATABASE_URL` entries for different projects). The existing `best_entry_for_env_var` logic handles priority, but verify that the service layer groups entries by `env_var` and picks only one winner per env var before passing to the process environment. If `get_all_for_env` already filters by project, this should be fine — but verify and add a dedup step if needed:

```rust
// After getting all pairs, dedup by env_var (first wins, since get_all_for_env is ordered)
let mut seen = std::collections::HashSet::new();
result.retain(|(env_var, _)| seen.insert(env_var.clone()));
```

- [ ] **Step 8: Update import `on_conflict` logic**

Replace lines 1110-1152 in `import_env_file`:

```rust
let existing = self.db.get_secrets_by_name(&name)?;
let conflict = existing.iter().find(|e| {
    // Conflict if projects overlap or both are global
    projects.iter().any(|p| e.projects.contains(p))
        || (projects.is_empty() && e.projects.is_empty())
});

if let Some(conflicting) = conflict {
    match on_conflict {
        "skip" => {
            stats.skipped += 1;
            continue;
        }
        "overwrite" => {
            self.db.update_secret_value(&conflicting.id, val)?;
            self.db.update_secret_metadata(
                &conflicting.id,
                &MetadataUpdate { /* ... same fields ... */ },
            )?;
            stats.overwritten += 1;
            continue;
        }
        "rename" => {
            let mut suffix = 2;
            loop {
                let candidate = format!("{}-{}", name, suffix);
                if self.db.get_secrets_by_name(&candidate)?.is_empty() {
                    name = candidate;
                    break;
                }
                suffix += 1;
            }
        }
        _ => bail!("Invalid --on-conflict value. Use: skip, overwrite, rename"),
    }
}
```

- [ ] **Step 8: Run the failing test from Task 1**

Run: `cargo test test_duplicate_name_different_projects -- --nocapture`
Expected: PASS

- [ ] **Step 9: Run all tests**

Run: `cargo test`
Expected: Compilation errors in CLI commands (fixed in Task 4) and MCP (fixed in Task 5).

- [ ] **Step 10: Commit**

```bash
git add src/services/secrets.rs
git commit -m "feat(service): scoped dedup logic, migrate callers to id-based"
```

---

### Task 4: CLI Commands — Interactive Picker + `--project` Flag

**Files:**
- Modify: `src/cli.rs:104-174, 236-243`
- Modify: `src/commands/secrets.rs:298-546, 1007-1029`
- Modify: `src/commands/auth.rs:163-178`

- [ ] **Step 1: Add `--project` flag to CLI args**

In `src/cli.rs`, add `project: Option<String>` to Get, Remove, Update, Verify:

```rust
Get {
    name: Option<String>,
    #[arg(long)]
    raw: bool,
    #[arg(short, long)]
    copy: bool,
    /// Filter by project (skip picker when multiple matches)
    #[arg(short, long)]
    project: Option<String>,
},

Remove {
    name: Option<String>,
    #[arg(long, short)]
    force: bool,
    #[arg(long)]
    purge: bool,
    #[arg(short = 'P', long)]
    project: Option<String>,
},

Update {
    name: Option<String>,
    // ... existing fields ...
    /// Filter by project (skip picker when multiple matches)
    #[arg(short = 'P', long = "project-filter")]
    project_filter: Option<String>,
    // Note: "projects" already exists as a metadata field, so use "project_filter" for disambiguation
},

Verify {
    name: Option<String>,
    #[arg(long)]
    all: bool,
    #[arg(short, long)]
    project: Option<String>,
},
```

- [ ] **Step 2: Create `resolve_secret` helper in `commands/auth.rs`**

Replace `select_secret` (lines 163-178) with a new `resolve_secret` that handles disambiguation:

```rust
pub(crate) fn resolve_secret(
    service: &SecretService<'_>,
    name: Option<String>,
    project: Option<&str>,
) -> Result<SecretEntry> {
    let name = match name {
        Some(n) => n,
        None => return select_secret_entry(service, project),
    };

    let mut entries = service.get_entries_by_name(&name)?;
    if entries.is_empty() {
        bail!("Secret '{}' not found", name);
    }

    // Filter by project if specified
    if let Some(proj) = project {
        entries.retain(|e| e.projects.iter().any(|p| p == proj));
        if entries.is_empty() {
            bail!("Secret '{}' not found in project '{}'", name, proj);
        }
    }

    if entries.len() == 1 {
        return Ok(entries.remove(0));
    }

    // Multiple matches — interactive picker
    let items: Vec<String> = entries
        .iter()
        .map(|e| {
            let projects = if e.projects.is_empty() {
                "(global)".to_string()
            } else {
                format!("({})", e.projects.join(", "))
            };
            format!("{:<28} {:<20} {:<16} {}", e.name, projects, e.provider, e.status())
        })
        .collect();

    let idx = FuzzySelect::new()
        .with_prompt(format!("Multiple secrets named '{}' — select one", name))
        .items(&items)
        .default(0)
        .interact()?;

    Ok(entries.remove(idx))
}

fn select_secret_entry(service: &SecretService<'_>, project: Option<&str>) -> Result<SecretEntry> {
    let filter = ListFilter {
        project: project.map(|s| s.to_string()),
        ..Default::default()
    };
    let entries = service.list_entries(&filter)?;
    if entries.is_empty() {
        bail!("No secrets found. Add one with: kf add");
    }
    let items: Vec<String> = entries
        .iter()
        .map(|e| {
            let projects = if e.projects.is_empty() {
                "(global)".to_string()
            } else {
                format!("({})", e.projects.join(", "))
            };
            format!("{:<28} {:<20} {:<24} {}", e.name, projects, e.env_var, e.provider)
        })
        .collect();
    let idx = FuzzySelect::new()
        .with_prompt("Select secret (type to filter)")
        .items(&items)
        .default(0)
        .interact()?;
    Ok(entries[idx].clone())
}
```

- [ ] **Step 3: Add `get_entries_by_name` to SecretService**

In `src/services/secrets.rs`:

```rust
pub fn get_entries_by_name(&self, name: &str) -> Result<Vec<SecretEntry>> {
    self.db.get_secrets_by_name(name)
}
```

- [ ] **Step 4: Update `cmd_get` to use `resolve_secret`**

Replace lines 298-303 in `commands/secrets.rs`:

```rust
pub fn cmd_get(name: Option<String>, raw: bool, copy: bool, project: Option<String>) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let entry = resolve_secret(&service, name, project.as_deref())?;
    let view = service.inspect_secret_by_id(&entry.id)?;
    // ... rest uses view as before ...
```

- [ ] **Step 5: Update `cmd_remove` to use `resolve_secret`**

Replace lines 392-402:

```rust
pub fn cmd_remove(name: Option<String>, force: bool, purge: bool, project: Option<String>) -> Result<()> {
    let service = SecretService::new(open_db()?);
    let entry = resolve_secret(&service, name, project.as_deref())?;

    // ... confirmation dialog uses entry.name ...
    // ... service.remove_secret(&entry.id) instead of &name ...
```

- [ ] **Step 6: Update `cmd_update` to use `resolve_secret`**

Replace lines 468-495. Add `project_filter` to UpdateArgs struct, resolve entry, then pass `entry.id` to `service.update_secret`.

- [ ] **Step 7: Update `cmd_verify` to use `resolve_secret`**

Replace lines 1007-1029:

```rust
pub fn cmd_verify(name: Option<String>, all: bool, project: Option<String>) -> Result<()> {
    let service = SecretService::new(open_db()?);
    if all {
        let names = service.all_secret_names(true)?;
        let now = service.verify_names(&names)?;
        // ... print all ...
    } else {
        let entry = resolve_secret(&service, name, project.as_deref())?;
        let now = service.verify_by_ids(&[&entry.id])?;
        println!(/* ... entry.name, now ... */);
    }
    Ok(())
}
```

- [ ] **Step 8: Update command dispatch in `src/lib.rs` (NOT main.rs)**

The actual dispatch is in `src/lib.rs:63-119`. Pass the new `project` fields from CLI args to the updated command functions:

```rust
// src/lib.rs — update match arms:
Commands::Get { name, raw, copy, project } => commands::cmd_get(name, raw, copy, project),
Commands::Remove { name, force, purge, project } => commands::cmd_remove(name, force, purge, project),
Commands::Update { name, /* ... existing fields ... */, project_filter } => commands::cmd_update(commands::UpdateArgs { /* ... */, project_filter }),
Commands::Verify { name, all, project } => commands::cmd_verify(name, all, project),
```

- [ ] **Step 9: Run all tests**

Run: `cargo test`
Expected: PASS (or MCP compilation errors fixed in Task 5).

- [ ] **Step 10: Commit**

```bash
git add src/cli.rs src/lib.rs src/commands/secrets.rs src/commands/auth.rs src/services/secrets.rs
git commit -m "feat(cli): interactive picker for duplicate names, --project flag"
```

---

### Task 5: MCP — `inspect_key` Array Response + `add_key` Dedup

**Files:**
- Modify: `src/mcp/tools.rs:58-80`
- Modify: `src/mcp/service.rs:203-332`

- [ ] **Step 1: Update `inspect_key` tool schema — add `project` param**

Replace lines 58-80 in `tools.rs`:

```rust
ToolDefinition::read_with_output(
    "inspect_key",
    "Get metadata for secrets by KeyFlow name. Returns an array (may contain multiple entries if the same name exists in different projects).",
    json!({
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Secret name returned by search_keys."
            },
            "project": {
                "type": "string",
                "description": "Optional project filter to narrow results."
            }
        },
        "required": ["name"]
    }),
    json!({
        "type": "object",
        "properties": {
            "keys": {
                "type": "array",
                "items": key_metadata_schema()
            },
            "count": { "type": "integer" }
        }
    }),
    |service, args| {
        #[derive(serde::Deserialize)]
        struct Args {
            name: String,
            project: Option<String>,
        }
        let args: Args = parse_args(args)?;
        service.get_key_info(args.name, args.project)
    },
),
```

- [ ] **Step 2: Update `get_key_info` in `service.rs` to return array**

Replace lines 203-206:

```rust
pub fn get_key_info(&self, name: String, project: Option<String>) -> Result<Value> {
    let mut entries = self.secrets.get_entries_by_name(&name)?;
    if let Some(proj) = &project {
        entries.retain(|e| e.projects.iter().any(|p| p == proj));
    }
    if entries.is_empty() {
        bail!("Secret '{}' not found", name);
    }
    let keys: Vec<Value> = entries.iter().map(|e| models::secret_to_json(e)).collect();
    Ok(json!({ "keys": keys, "count": keys.len() }))
}
```

- [ ] **Step 3: Update `add_key` dedup in `service.rs`**

Replace lines 267-331. The key change is the collision check:

```rust
pub fn add_key(&self, request: AddKeyRequest) -> Result<Value> {
    validate_env_var_name(&request.env_var)?;
    let name = request.env_var.to_lowercase().replace('_', "-");
    // ... provider inference unchanged ...

    let result = self.secrets.create_secret(SecretDraft { /* ... unchanged ... */ });

    match result {
        Ok(entry) => Ok(json!({ /* ... same "created" response ... */ })),
        Err(error) if error.to_string().contains("already exists") => Ok(json!({
            "success": false,
            "code": "already_exists",
            "name": name,
            "env_var": env_var,
            "provider": provider,
            "message": "Secret already exists for this project.",
            "error": "Use update flow instead.",
            "existing_name": name,
            "hint": "Call inspect_key with project filter, then update the existing secret."
        })),
        Err(error) => Err(error),
    }
}
```

- [ ] **Step 4: Update `get_env_snippet` to use ID**

In `service.rs`, find `get_env_snippet` (line 334+). Where it calls `get_secret_value(&entry.name)`, change to `get_secret_value(&entry.id)`.

- [ ] **Step 5: Run all tests**

Run: `cargo test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/mcp/tools.rs src/mcp/service.rs
git commit -m "feat(mcp): inspect_key returns array, add_key uses scoped dedup"
```

---

### Task 6: Sync + Health — Update Remaining Callers

**Files:**
- Modify: `src/commands/sync.rs:215-227`
- Modify: `src/models.rs:149-216`

- [ ] **Step 1: Update `ensure_unique_name` in sync.rs**

Replace lines 215-227:

```rust
fn ensure_unique_name(db: &Database, base: &str, projects: &[String]) -> Result<String> {
    let existing = db.get_secrets_by_name(base)?;
    // No collision if no project overlap
    let has_overlap = existing.iter().any(|e| {
        projects.iter().any(|p| e.projects.contains(p))
            || (projects.is_empty() && e.projects.is_empty())
    });
    if !has_overlap {
        return Ok(base.to_string());
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}-sync-{suffix}");
        let existing = db.get_secrets_by_name(&candidate)?;
        let has_overlap = existing.iter().any(|e| {
            projects.iter().any(|p| e.projects.contains(p))
                || (projects.is_empty() && e.projects.is_empty())
        });
        if !has_overlap {
            return Ok(candidate);
        }
        suffix += 1;
    }
}
```

Update the caller at line 575-576 to pass `entry.projects`.

- [ ] **Step 2: Update `find_duplicate_groups` in models.rs**

Replace lines 149-216. Add project-awareness: same env_var in different projects is NOT a duplicate.

```rust
pub fn find_duplicate_groups(entries: &[SecretEntry]) -> Vec<DuplicateGroup> {
    let mut by_env_var: std::collections::HashMap<String, Vec<&SecretEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        if entry.is_active {
            by_env_var
                .entry(entry.env_var.to_uppercase())
                .or_default()
                .push(entry);
        }
    }

    let mut groups = Vec::new();
    for (env_var, keys) in &by_env_var {
        if keys.len() <= 1 {
            continue;
        }
        // Only group keys whose projects overlap (or both are global)
        let mut overlapping: Vec<&str> = Vec::new();
        for (i, a) in keys.iter().enumerate() {
            for b in keys.iter().skip(i + 1) {
                let overlap = if a.projects.is_empty() && b.projects.is_empty() {
                    true
                } else {
                    a.projects.iter().any(|p| b.projects.contains(p))
                };
                if overlap {
                    if !overlapping.contains(&a.name.as_str()) {
                        overlapping.push(&a.name);
                    }
                    if !overlapping.contains(&b.name.as_str()) {
                        overlapping.push(&b.name);
                    }
                }
            }
        }
        if overlapping.len() > 1 {
            groups.push(DuplicateGroup {
                env_var: env_var.clone(),
                names: overlapping.into_iter().map(|s| s.to_string()).collect(),
            });
        }
    }

    // Provider overlap detection — keep existing logic but apply same project filter
    let mut by_provider: std::collections::HashMap<String, Vec<&SecretEntry>> =
        std::collections::HashMap::new();
    for entry in entries {
        if entry.is_active && !entry.provider.is_empty() {
            by_provider
                .entry(entry.provider.clone())
                .or_default()
                .push(entry);
        }
    }

    for (_provider, keys) in &by_provider {
        if keys.len() <= 1 {
            continue;
        }
        // ... existing purpose overlap logic, but skip pairs with non-overlapping projects ...
    }

    groups
}
```

- [ ] **Step 3: Run all tests**

Run: `cargo test`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/commands/sync.rs src/models.rs
git commit -m "feat: update sync and health for scoped names"
```

---

### Task 7: MCP Contract Docs + Integration Tests

**Files:**
- Modify: `docs/mcp-contract.md`
- Modify: `tests/service_secrets.rs`
- Modify: `tests/cli_flow.rs`

- [ ] **Step 1: Update MCP contract docs**

In `docs/mcp-contract.md`, update `inspect_key` section:

```markdown
#### `inspect_key`

Purpose:

- fetch metadata for secrets by KeyFlow name

Input:

- `name` (required)
- `project` (optional) — filter by project

Output:

- `keys` — array of metadata objects
- `count` — number of results

> **Breaking change (v0.5.0→v0.6.0):** Response changed from single object to `{ keys: [...], count: N }`.
```

- [ ] **Step 2: Add integration tests for scoped names**

In `tests/service_secrets.rs`, add:

```rust
#[test]
fn test_same_name_global_and_scoped() {
    // Global database-url + project-scoped database-url should coexist
}

#[test]
fn test_same_name_overlapping_projects_rejected() {
    // Two entries for same name+project should fail
}

#[test]
fn test_get_secrets_by_name_returns_all() {
    // get_secrets_by_name("database-url") returns both entries
}

#[test]
fn test_import_conflict_scoped() {
    // Import with on_conflict=skip only skips when project matches
}
```

- [ ] **Step 3: Run full test suite**

Run: `cargo test`
Expected: ALL PASS

- [ ] **Step 4: Build release to verify no warnings**

Run: `cargo build --release 2>&1 | head -50`
Expected: Clean build, no warnings.

- [ ] **Step 5: Commit**

```bash
git add docs/mcp-contract.md tests/
git commit -m "docs: update mcp contract for inspect_key breaking change, add scoped name tests"
```

- [ ] **Step 6: Bump version**

In `Cargo.toml`, change `version = "0.5.0"` to `version = "0.6.0"`.

```bash
git add Cargo.toml
git commit -m "chore: bump version to 0.6.0 for scoped key names"
```
