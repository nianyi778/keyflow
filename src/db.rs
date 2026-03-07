use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use crate::crypto::Crypto;
use crate::models::{ListFilter, SecretEntry};

#[derive(Default)]
pub struct MetadataUpdate<'a> {
    pub provider: Option<&'a str>,
    pub account_name: Option<&'a str>,
    pub org_name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub source: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub permission_profile: Option<&'a str>,
    pub scopes: Option<&'a [String]>,
    pub projects: Option<&'a [String]>,
    pub apply_url: Option<&'a str>,
    pub expires_at: Option<Option<DateTime<Utc>>>,
    pub last_verified_at: Option<Option<DateTime<Utc>>>,
    pub is_active: Option<bool>,
    pub key_group: Option<&'a str>,
}

/// Column list for SELECT queries — single source of truth.
const SECRET_COLUMNS: &str = "id, name, env_var, provider, account_name, description, source, scopes, projects, apply_url, expires_at, created_at, updated_at, last_used_at, last_verified_at, is_active, key_group, org_name, environment, permission_profile";

pub struct Database {
    conn: Connection,
    crypto: Crypto,
}

impl Database {
    pub fn open(db_path: &str, crypto: Crypto) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        // WAL mode: better concurrent read/write performance for MCP server & web dashboard
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let db = Self { conn, crypto };
        db.init_tables()?;
        db.migrate()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
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
        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        // Add key_group column if missing (v0.2.0 migration)
        let has_key_group: bool = self
            .conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name='key_group'")?
            .query_row([], |row| row.get::<_, i64>(0))
            .map(|c| c > 0)?;

        if !has_key_group {
            self.conn.execute_batch(
                "ALTER TABLE secrets ADD COLUMN key_group TEXT NOT NULL DEFAULT '';
                 CREATE INDEX IF NOT EXISTS idx_secrets_key_group ON secrets(key_group);",
            )?;
        }

        self.add_column_if_missing("account_name", "TEXT NOT NULL DEFAULT ''")?;
        self.add_column_if_missing("source", "TEXT NOT NULL DEFAULT ''")?;
        self.add_column_if_missing("last_verified_at", "TEXT")?;
        self.add_column_if_missing("org_name", "TEXT NOT NULL DEFAULT ''")?;
        self.add_column_if_missing("environment", "TEXT NOT NULL DEFAULT ''")?;
        self.add_column_if_missing("permission_profile", "TEXT NOT NULL DEFAULT ''")?;
        Ok(())
    }

    fn add_column_if_missing(&self, column: &str, definition: &str) -> Result<()> {
        // Whitelist check: only allow known safe identifiers
        if !column.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            bail!("Invalid column name: {}", column);
        }
        if !definition
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'\'' || b == b'[' || b == b']')
        {
            bail!("Invalid column definition: {}", definition);
        }
        let exists: bool = self
            .conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name = ?1")?
            .query_row([column], |row| row.get::<_, i64>(0))
            .map(|c| c > 0)?;
        if !exists {
            self.conn.execute_batch(&format!(
                "ALTER TABLE secrets ADD COLUMN {column} {definition};"
            ))?;
        }
        Ok(())
    }

    pub fn add_secret(&self, entry: &SecretEntry, value: &str) -> Result<()> {
        let encrypted = self.crypto.encrypt(value.as_bytes())?;
        let scopes_json = serde_json::to_string(&entry.scopes)?;
        let projects_json = serde_json::to_string(&entry.projects)?;

        self.conn.execute(
            "INSERT INTO secrets (id, name, env_var, encrypted_value, provider, account_name, description, source, scopes, projects, apply_url, expires_at, created_at, updated_at, last_verified_at, is_active, key_group, org_name, environment, permission_profile)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                entry.id,
                entry.name,
                entry.env_var,
                encrypted,
                entry.provider,
                entry.account_name,
                entry.description,
                entry.source,
                scopes_json,
                projects_json,
                entry.apply_url,
                entry.expires_at.map(|d| d.to_rfc3339()),
                entry.created_at.to_rfc3339(),
                entry.updated_at.to_rfc3339(),
                entry.last_verified_at.map(|d| d.to_rfc3339()),
                entry.is_active,
                entry.key_group,
                entry.org_name,
                entry.environment,
                entry.permission_profile,
            ],
        )?;
        Ok(())
    }

    pub fn list_secrets(&self, filter: &ListFilter) -> Result<Vec<SecretEntry>> {
        let mut sql = format!(
            "SELECT {} FROM secrets WHERE 1=1",
            SECRET_COLUMNS,
        );
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(ref provider) = filter.provider {
            bind_values.push(provider.clone());
            sql.push_str(&format!(" AND provider = ?{}", bind_values.len()));
        }
        if let Some(ref project) = filter.project {
            let escaped = project.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
            bind_values.push(format!("%\"{}\"%", escaped));
            sql.push_str(&format!(" AND projects LIKE ?{} ESCAPE '\\'", bind_values.len()));
        }
        if let Some(ref group) = filter.group {
            bind_values.push(group.clone());
            sql.push_str(&format!(" AND key_group = ?{}", bind_values.len()));
        }
        if !filter.inactive {
            sql.push_str(" AND is_active = 1");
        }

        sql.push_str(" ORDER BY provider, key_group, name");

        let mut stmt = self.conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::types::ToSql> = bind_values
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();
        let rows = stmt.query_map(params.as_slice(), |row| Ok(self.row_to_entry(row)))?;

        let mut entries = Vec::new();
        for row in rows {
            let entry = row??;
            if filter.expiring {
                match entry.status() {
                    crate::models::KeyStatus::Expired | crate::models::KeyStatus::ExpiringSoon => {
                        entries.push(entry);
                    }
                    _ => {}
                }
            } else {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    pub fn get_secret(&self, name: &str) -> Result<SecretEntry> {
        let mut stmt = self.conn.prepare(
            &format!("SELECT {} FROM secrets WHERE name = ?1", SECRET_COLUMNS),
        )?;
        let entry = stmt
            .query_row(params![name], |row| Ok(self.row_to_entry(row)))
            .context(format!("Secret '{}' not found", name))??;
        Ok(entry)
    }

    pub fn get_secret_value(&self, name: &str) -> Result<String> {
        let mut stmt = self
            .conn
            .prepare("SELECT encrypted_value FROM secrets WHERE name = ?1")?;
        let encrypted: Vec<u8> = stmt
            .query_row(params![name], |row| row.get(0))
            .context(format!("Secret '{}' not found", name))?;

        // Update last_used_at
        self.conn.execute(
            "UPDATE secrets SET last_used_at = ?1 WHERE name = ?2",
            params![Utc::now().to_rfc3339(), name],
        )?;

        let decrypted = self.crypto.decrypt(&encrypted)?;
        String::from_utf8(decrypted).context("Secret value is not valid UTF-8")
    }

    pub fn remove_secret(&self, name: &str) -> Result<bool> {
        let affected = self
            .conn
            .execute("DELETE FROM secrets WHERE name = ?1", params![name])?;
        Ok(affected > 0)
    }

    pub fn update_secret_value(&self, name: &str, new_value: &str) -> Result<()> {
        let encrypted = self.crypto.encrypt(new_value.as_bytes())?;
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE secrets SET encrypted_value = ?1, updated_at = ?2 WHERE name = ?3",
            params![encrypted, now, name],
        )?;
        Ok(())
    }

    pub fn update_secret_metadata(&self, name: &str, update: &MetadataUpdate<'_>) -> Result<()> {
        let MetadataUpdate {
            provider,
            account_name,
            org_name,
            description,
            source,
            environment,
            permission_profile,
            scopes,
            projects,
            apply_url,
            expires_at,
            last_verified_at,
            is_active,
            key_group,
        } = update;
        let now = Utc::now().to_rfc3339();
        let mut updates = vec!["updated_at = ?1".to_string()];
        let mut bind_idx = 2;
        let mut bind_values: Vec<String> = vec![now];

        if let Some(p) = provider {
            bind_values.push(p.to_string());
            updates.push(format!("provider = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(a) = account_name {
            bind_values.push(a.to_string());
            updates.push(format!("account_name = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(d) = description {
            bind_values.push(d.to_string());
            updates.push(format!("description = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(s) = source {
            bind_values.push(s.to_string());
            updates.push(format!("source = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(s) = scopes {
            bind_values.push(serde_json::to_string(s)?);
            updates.push(format!("scopes = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(p) = projects {
            bind_values.push(serde_json::to_string(p)?);
            updates.push(format!("projects = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(u) = apply_url {
            bind_values.push(u.to_string());
            updates.push(format!("apply_url = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(exp) = expires_at {
            bind_values.push(exp.map(|d| d.to_rfc3339()).unwrap_or_default());
            updates.push(format!("expires_at = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(verified) = last_verified_at {
            bind_values.push(verified.map(|d| d.to_rfc3339()).unwrap_or_default());
            updates.push(format!("last_verified_at = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(a) = *is_active {
            bind_values.push(if a { "1".to_string() } else { "0".to_string() });
            updates.push(format!("is_active = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(g) = key_group {
            bind_values.push(g.to_string());
            updates.push(format!("key_group = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(o) = org_name {
            bind_values.push(o.to_string());
            updates.push(format!("org_name = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(e) = environment {
            bind_values.push(e.to_string());
            updates.push(format!("environment = ?{}", bind_idx));
            bind_idx += 1;
        }
        if let Some(pp) = permission_profile {
            bind_values.push(pp.to_string());
            updates.push(format!("permission_profile = ?{}", bind_idx));
            bind_idx += 1;
        }

        let _ = bind_idx;
        bind_values.push(name.to_string());
        let sql = format!(
            "UPDATE secrets SET {} WHERE name = ?{}",
            updates.join(", "),
            bind_values.len()
        );

        let params: Vec<&dyn rusqlite::types::ToSql> = bind_values
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();
        self.conn.execute(&sql, params.as_slice())?;
        Ok(())
    }

    pub fn search_secrets(&self, query: &str) -> Result<Vec<SecretEntry>> {
        // Escape LIKE wildcards so % and _ in user input are matched literally
        let escaped = query.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        let pattern = format!("%{}%", escaped);
        let mut stmt = self.conn.prepare(
            &format!("SELECT {} FROM secrets WHERE name LIKE ?1 ESCAPE '\\' OR env_var LIKE ?1 ESCAPE '\\' OR provider LIKE ?1 ESCAPE '\\' OR account_name LIKE ?1 ESCAPE '\\' OR description LIKE ?1 ESCAPE '\\' OR source LIKE ?1 ESCAPE '\\' OR scopes LIKE ?1 ESCAPE '\\' OR projects LIKE ?1 ESCAPE '\\' OR key_group LIKE ?1 ESCAPE '\\' OR org_name LIKE ?1 ESCAPE '\\' ORDER BY name", SECRET_COLUMNS),
        )?;
        let rows = stmt.query_map(params![pattern], |row| Ok(self.row_to_entry(row)))?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row??);
        }
        Ok(entries)
    }

    pub fn get_all_for_env(
        &self,
        project: Option<&str>,
        group: Option<&str>,
    ) -> Result<Vec<(String, String)>> {
        let entries = self.list_secrets(&ListFilter {
            project: project.map(|s| s.to_string()),
            group: group.map(|s| s.to_string()),
            ..Default::default()
        })?;

        let mut result = Vec::new();
        for entry in &entries {
            let value = self.get_secret_value(&entry.name)?;
            result.push((entry.env_var.clone(), value));
        }
        Ok(result)
    }

    pub fn secret_exists(&self, name: &str) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM secrets WHERE name = ?1")?;
        let count: i64 = stmt.query_row(params![name], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Get all raw encrypted data for re-encryption (passwd command)
    pub fn get_all_raw(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, encrypted_value FROM secrets")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Decrypt a value using the current crypto
    pub fn decrypt_raw(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        self.crypto.decrypt(encrypted)
    }

    /// Re-encrypt all secrets atomically within a transaction.
    /// If any re-encryption fails, all changes are rolled back.
    pub fn reencrypt_all(
        &self,
        pairs: &[(String, Vec<u8>)],
        new_crypto: &Crypto,
    ) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| -> Result<()> {
            for (name, plaintext) in pairs {
                let new_encrypted = new_crypto.encrypt(plaintext)?;
                self.conn.execute(
                    "UPDATE secrets SET encrypted_value = ?1 WHERE name = ?2",
                    params![new_encrypted, name],
                )?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// List distinct groups
    pub fn list_groups(&self) -> Result<Vec<(String, usize)>> {
        let mut stmt = self.conn.prepare(
            "SELECT key_group, COUNT(*) FROM secrets WHERE key_group != '' AND is_active = 1 GROUP BY key_group ORDER BY key_group",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    fn row_to_entry(&self, row: &rusqlite::Row) -> Result<SecretEntry> {
        let scopes_str: String = row.get_unwrap("scopes");
        let projects_str: String = row.get_unwrap("projects");
        let expires_str: Option<String> = row.get_unwrap("expires_at");
        let last_used_str: Option<String> = row.get_unwrap("last_used_at");
        let last_verified_str: Option<String> = row.get_unwrap("last_verified_at");

        Ok(SecretEntry {
            id: row.get_unwrap("id"),
            name: row.get_unwrap("name"),
            env_var: row.get_unwrap("env_var"),
            provider: row.get_unwrap("provider"),
            account_name: row.get_unwrap("account_name"),
            description: row.get_unwrap("description"),
            source: row.get_unwrap("source"),
            scopes: serde_json::from_str(&scopes_str).unwrap_or_default(),
            projects: serde_json::from_str(&projects_str).unwrap_or_default(),
            apply_url: row.get_unwrap("apply_url"),
            expires_at: expires_str.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            created_at: DateTime::parse_from_rfc3339(
                &row.get::<_, String>(row.as_ref().column_index("created_at")?)?,
            )
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(
                &row.get::<_, String>(row.as_ref().column_index("updated_at")?)?,
            )
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
            last_used_at: last_used_str.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            last_verified_at: last_verified_str.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            is_active: row.get_unwrap("is_active"),
            key_group: row.get_unwrap("key_group"),
            org_name: row.get_unwrap("org_name"),
            environment: row.get_unwrap("environment"),
            permission_profile: row.get_unwrap("permission_profile"),
        })
    }
}
