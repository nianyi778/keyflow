use anyhow::{Context, Result};
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
}

const SECRET_COLUMNS: &str = "id, name, env_var, provider, account_name, description, source, scopes, projects, apply_url, expires_at, created_at, updated_at, last_used_at, last_verified_at, is_active, org_name, environment, permission_profile";

pub struct Database {
    conn: Connection,
    crypto: Crypto,
}

impl Database {
    pub fn open(db_path: &str, crypto: Crypto) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let db = Self { conn, crypto };
        db.init_tables()?;
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

    pub fn add_secret(&self, entry: &SecretEntry, value: &str) -> Result<()> {
        let encrypted = self.crypto.encrypt(value.as_bytes())?;
        let scopes_json = serde_json::to_string(&entry.scopes)?;
        let projects_json = serde_json::to_string(&entry.projects)?;

        self.conn.execute(
            "INSERT INTO secrets (id, name, env_var, encrypted_value, provider, account_name, description, source, scopes, projects, apply_url, expires_at, created_at, updated_at, last_verified_at, is_active, org_name, environment, permission_profile)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
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
                entry.org_name,
                entry.environment,
                entry.permission_profile,
            ],
        )?;
        Ok(())
    }

    pub fn list_secrets(&self, filter: &ListFilter) -> Result<Vec<SecretEntry>> {
        let mut sql = format!("SELECT {} FROM secrets WHERE 1=1", SECRET_COLUMNS);
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(provider) = &filter.provider {
            bind_values.push(provider.clone());
            sql.push_str(&format!(" AND provider = ?{}", bind_values.len()));
        }
        if let Some(project) = &filter.project {
            let escaped = project
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            bind_values.push(format!("%\"{}\"%", escaped));
            sql.push_str(&format!(
                " AND projects LIKE ?{} ESCAPE '\\'",
                bind_values.len()
            ));
        }
        if !filter.inactive {
            sql.push_str(" AND is_active = 1");
        }

        sql.push_str(" ORDER BY provider, name");

        let mut stmt = self.conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::types::ToSql> = bind_values
            .iter()
            .map(|value| value as &dyn rusqlite::types::ToSql)
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
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM secrets WHERE name = ?1",
            SECRET_COLUMNS
        ))?;
        let entry = stmt
            .query_row(params![name], |row| Ok(self.row_to_entry(row)))
            .context(format!("Secret '{name}' not found"))??;
        Ok(entry)
    }

    pub fn get_secret_value(&self, name: &str) -> Result<String> {
        let mut stmt = self
            .conn
            .prepare("SELECT encrypted_value FROM secrets WHERE name = ?1")?;
        let encrypted: Vec<u8> = stmt
            .query_row(params![name], |row| row.get(0))
            .context(format!("Secret '{name}' not found"))?;

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
        let now = Utc::now().to_rfc3339();
        let mut set_clauses = vec!["updated_at = ?1".to_string()];
        let mut bind_values: Vec<String> = vec![now];

        let mut push = |column: &str, value: String| {
            bind_values.push(value);
            set_clauses.push(format!("{} = ?{}", column, bind_values.len()));
        };

        if let Some(v) = update.provider {
            push("provider", v.to_string());
        }
        if let Some(v) = update.account_name {
            push("account_name", v.to_string());
        }
        if let Some(v) = update.description {
            push("description", v.to_string());
        }
        if let Some(v) = update.source {
            push("source", v.to_string());
        }
        if let Some(v) = update.scopes {
            push("scopes", serde_json::to_string(v)?);
        }
        if let Some(v) = update.projects {
            push("projects", serde_json::to_string(v)?);
        }
        if let Some(v) = update.apply_url {
            push("apply_url", v.to_string());
        }
        if let Some(v) = update.expires_at {
            push("expires_at", v.map(|d| d.to_rfc3339()).unwrap_or_default());
        }
        if let Some(v) = update.last_verified_at {
            push(
                "last_verified_at",
                v.map(|d| d.to_rfc3339()).unwrap_or_default(),
            );
        }
        if let Some(v) = update.is_active {
            push("is_active", if v { "1" } else { "0" }.to_string());
        }
        if let Some(v) = update.org_name {
            push("org_name", v.to_string());
        }
        if let Some(v) = update.environment {
            push("environment", v.to_string());
        }
        if let Some(v) = update.permission_profile {
            push("permission_profile", v.to_string());
        }

        bind_values.push(name.to_string());
        let sql = format!(
            "UPDATE secrets SET {} WHERE name = ?{}",
            set_clauses.join(", "),
            bind_values.len()
        );

        let params: Vec<&dyn rusqlite::types::ToSql> = bind_values
            .iter()
            .map(|value| value as &dyn rusqlite::types::ToSql)
            .collect();
        self.conn.execute(&sql, params.as_slice())?;
        Ok(())
    }

    pub fn search_secrets(&self, query: &str) -> Result<Vec<SecretEntry>> {
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{}%", escaped);
        let mut stmt = self.conn.prepare(
            &format!(
                "SELECT {} FROM secrets WHERE name LIKE ?1 ESCAPE '\\' OR env_var LIKE ?1 ESCAPE '\\' OR provider LIKE ?1 ESCAPE '\\' OR account_name LIKE ?1 ESCAPE '\\' OR description LIKE ?1 ESCAPE '\\' OR source LIKE ?1 ESCAPE '\\' OR scopes LIKE ?1 ESCAPE '\\' OR projects LIKE ?1 ESCAPE '\\' OR org_name LIKE ?1 ESCAPE '\\' ORDER BY name",
                SECRET_COLUMNS
            ),
        )?;
        let rows = stmt.query_map(params![pattern], |row| Ok(self.row_to_entry(row)))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row??);
        }
        Ok(entries)
    }

    pub fn get_all_for_env(&self, project: Option<&str>) -> Result<Vec<(String, String)>> {
        let mut sql =
            "SELECT env_var, encrypted_value, name FROM secrets WHERE is_active = 1".to_string();
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(project) = project {
            let escaped = project
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            bind_values.push(format!("%\"{}\"%", escaped));
            sql.push_str(&format!(
                " AND projects LIKE ?{} ESCAPE '\\'",
                bind_values.len()
            ));
        }

        sql.push_str(" ORDER BY provider, name");

        let mut stmt = self.conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::types::ToSql> = bind_values
            .iter()
            .map(|value| value as &dyn rusqlite::types::ToSql)
            .collect();
        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let now = Utc::now().to_rfc3339();
        let mut result = Vec::new();
        let mut names = Vec::new();
        for row in rows {
            let (env_var, encrypted, name) = row?;
            let decrypted = self.crypto.decrypt(&encrypted)?;
            let value = String::from_utf8(decrypted).context("Secret value is not valid UTF-8")?;
            result.push((env_var, value));
            names.push(name);
        }

        // Batch update last_used_at for all retrieved secrets
        if !names.is_empty() {
            let placeholders: Vec<String> =
                (1..=names.len()).map(|i| format!("?{}", i + 1)).collect();
            let update_sql = format!(
                "UPDATE secrets SET last_used_at = ?1 WHERE name IN ({})",
                placeholders.join(", ")
            );
            let mut update_params: Vec<&dyn rusqlite::types::ToSql> = vec![&now];
            for name in &names {
                update_params.push(name);
            }
            self.conn.execute(&update_sql, update_params.as_slice())?;
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

    pub fn decrypt_raw(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        self.crypto.decrypt(encrypted)
    }

    pub fn reencrypt_all(&self, pairs: &[(String, Vec<u8>)], new_crypto: &Crypto) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for (name, plaintext) in pairs {
            let new_encrypted = new_crypto.encrypt(plaintext)?;
            tx.execute(
                "UPDATE secrets SET encrypted_value = ?1 WHERE name = ?2",
                params![new_encrypted, name],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn row_to_entry(&self, row: &rusqlite::Row) -> Result<SecretEntry> {
        let idx = |col: &str| -> rusqlite::Result<usize> { row.as_ref().column_index(col) };

        let scopes_str: String = row.get(idx("scopes")?)?;
        let projects_str: String = row.get(idx("projects")?)?;
        let expires_str: Option<String> = row.get(idx("expires_at")?)?;
        let last_used_str: Option<String> = row.get(idx("last_used_at")?)?;
        let last_verified_str: Option<String> = row.get(idx("last_verified_at")?)?;
        let created_str: String = row.get(idx("created_at")?)?;
        let updated_str: String = row.get(idx("updated_at")?)?;

        Ok(SecretEntry {
            id: row.get(idx("id")?)?,
            name: row.get(idx("name")?)?,
            env_var: row.get(idx("env_var")?)?,
            provider: row.get(idx("provider")?)?,
            account_name: row.get(idx("account_name")?)?,
            org_name: row.get(idx("org_name")?)?,
            description: row.get(idx("description")?)?,
            source: row.get(idx("source")?)?,
            environment: row.get(idx("environment")?)?,
            permission_profile: row.get(idx("permission_profile")?)?,
            scopes: serde_json::from_str(&scopes_str).unwrap_or_default(),
            projects: serde_json::from_str(&projects_str).unwrap_or_default(),
            apply_url: row.get(idx("apply_url")?)?,
            expires_at: expires_str.and_then(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .ok()
                    .map(|date| date.with_timezone(&Utc))
            }),
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map(|date| date.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&updated_str)
                .map(|date| date.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_used_at: last_used_str.and_then(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .ok()
                    .map(|date| date.with_timezone(&Utc))
            }),
            last_verified_at: last_verified_str.and_then(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .ok()
                    .map(|date| date.with_timezone(&Utc))
            }),
            is_active: row.get(idx("is_active")?)?,
        })
    }
}
