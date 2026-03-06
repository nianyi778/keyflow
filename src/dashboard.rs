use anyhow::Result;
use console::style;
use serde_json::json;
use tiny_http::{Header, Method, Response, Server};

use crate::commands::{get_passphrase, load_config};
use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::ListFilter;

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

fn open_db_for_dashboard() -> Result<Database> {
    let (data_dir, _config, salt) = load_config()?;
    let passphrase = get_passphrase()?;
    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = data_dir.join("keyflow.db");
    Database::open(db_path.to_str().unwrap(), crypto)
}

pub fn cmd_dashboard(port: u16) -> Result<()> {
    let db = open_db_for_dashboard()?;

    let max_attempts = 10;
    let mut actual_port = port;
    let server = loop {
        let addr = format!("127.0.0.1:{}", actual_port);
        match Server::http(&addr) {
            Ok(s) => break s,
            Err(_) if actual_port < port + max_attempts => {
                actual_port += 1;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to start server on ports {}-{}: {}",
                    port,
                    port + max_attempts,
                    e
                ));
            }
        }
    };
    let addr = format!("127.0.0.1:{}", actual_port);

    if actual_port != port {
        println!(
            "  {} Port {} in use, using {} instead.",
            style("⚠").yellow(),
            port,
            style(actual_port).cyan()
        );
    }
    println!(
        "\n{} KeyFlow Dashboard running at {}",
        style("✓").green().bold(),
        style(format!("http://{}", addr)).cyan().underlined()
    );
    println!("  Press {} to stop.\n", style("Ctrl+C").yellow());

    // Try to open browser
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(format!("http://{}", addr))
            .spawn();
    }

    for request in server.incoming_requests() {
        let url = request.url().to_string();
        let method = request.method().clone();

        let response = match (method, url.as_str()) {
            (Method::Get, "/") => {
                let header =
                    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                        .unwrap();
                Response::from_string(DASHBOARD_HTML).with_header(header)
            }
            (Method::Get, "/api/stats") => json_response(&handle_stats(&db)),
            (Method::Get, "/api/secrets") => json_response(&handle_secrets(&db)),
            (Method::Get, "/api/health") => json_response(&handle_health(&db)),
            (Method::Get, "/api/groups") => json_response(&handle_groups(&db)),
            (Method::Get, path) if path.starts_with("/api/search") => {
                let query = path
                    .split("q=")
                    .nth(1)
                    .unwrap_or("")
                    .split('&')
                    .next()
                    .unwrap_or("");
                let decoded = urldecode(query);
                json_response(&handle_search(&db, &decoded))
            }
            (Method::Post, path) if path.starts_with("/api/verify/") => {
                let name = urldecode(&path["/api/verify/".len()..]);
                json_response(&handle_verify(&db, &name))
            }
            (Method::Post, path) if path.starts_with("/api/inactive/") => {
                let name = urldecode(&path["/api/inactive/".len()..]);
                json_response(&handle_mark_inactive(&db, &name))
            }
            (Method::Get, path) if path.starts_with("/api/secret/") => {
                let name = urldecode(&path["/api/secret/".len()..]);
                json_response(&handle_secret_detail(&db, &name))
            }
            _ => Response::from_string("404 Not Found").with_status_code(404),
        };

        let _ = request.respond(response);
    }

    Ok(())
}

fn json_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(
        &b"Content-Type"[..],
        &b"application/json; charset=utf-8"[..],
    )
    .unwrap();
    let cors = Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap();
    Response::from_string(body)
        .with_header(header)
        .with_header(cors)
}

fn urldecode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h = chars.next().unwrap_or(b'0');
            let l = chars.next().unwrap_or(b'0');
            let hex = format!("{}{}", h as char, l as char);
            if let Ok(val) = u8::from_str_radix(&hex, 16) {
                result.push(val as char);
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn secret_to_json(entry: &crate::models::SecretEntry) -> serde_json::Value {
    json!({
        "name": entry.name,
        "env_var": entry.env_var,
        "provider": entry.provider,
        "account_name": entry.account_name,
        "org_name": entry.org_name,
        "description": entry.description,
        "source": entry.source,
        "environment": entry.environment,
        "permission_profile": entry.permission_profile,
        "scopes": entry.scopes,
        "projects": entry.projects,
        "key_group": entry.key_group,
        "apply_url": entry.apply_url,
        "status": entry.status().to_string(),
        "expires_at": entry.expires_at.map(|d| d.format("%Y-%m-%d").to_string()),
        "last_used_at": entry.last_used_at.map(|d| d.format("%Y-%m-%d").to_string()),
        "last_verified_at": entry
            .last_verified_at
            .map(|d| d.format("%Y-%m-%d").to_string()),
        "metadata_gaps": entry.metadata_gaps(),
        "source_quality": entry.source_quality().to_string(),
    })
}

fn handle_stats(db: &Database) -> String {
    let all = db
        .list_secrets(&ListFilter {
            inactive: true,
            ..Default::default()
        })
        .unwrap_or_default();
    let active = all
        .iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::Active))
        .count();
    let expired = all
        .iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::Expired))
        .count();
    let expiring = all
        .iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::ExpiringSoon))
        .count();
    let groups = db.list_groups().unwrap_or_default().len();

    json!({
        "total": all.len(),
        "active": active,
        "expired": expired,
        "expiring_soon": expiring,
        "groups_count": groups,
    })
    .to_string()
}

fn handle_secrets(db: &Database) -> String {
    let entries = db
        .list_secrets(&ListFilter {
            inactive: true,
            ..Default::default()
        })
        .unwrap_or_default();
    let secrets: Vec<_> = entries.iter().map(secret_to_json).collect();
    json!(secrets).to_string()
}

fn handle_health(db: &Database) -> String {
    let entries = db
        .list_secrets(&ListFilter {
            inactive: true,
            ..Default::default()
        })
        .unwrap_or_default();
    let now = chrono::Utc::now();
    let seven_days_ago = now - chrono::Duration::days(7);

    let expired: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::Expired))
        .map(secret_to_json)
        .collect();
    let expiring: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::ExpiringSoon))
        .map(secret_to_json)
        .collect();
    let unused: Vec<_> = entries
        .iter()
        .filter(|e| e.is_unused_for_days(now, 30))
        .map(secret_to_json)
        .collect();
    let metadata_review: Vec<_> = entries
        .iter()
        .filter(|e| e.is_active && e.has_metadata_gaps())
        .map(secret_to_json)
        .collect();
    let recently_verified: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.last_verified_at
                .map(|v| v >= seven_days_ago)
                .unwrap_or(false)
        })
        .map(secret_to_json)
        .collect();

    let duplicates = crate::models::find_duplicate_groups(&entries);
    let duplicate_groups: Vec<_> = duplicates
        .iter()
        .map(|g| json!({"env_var": g.env_var, "names": g.names}))
        .collect();

    let active_entries: Vec<_> = entries.iter().filter(|e| e.is_active).collect();
    let mut source_quality: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for e in &active_entries {
        *source_quality
            .entry(e.source_quality().to_string())
            .or_insert(0) += 1;
    }

    let unverified_30 = active_entries
        .iter()
        .filter(|e| {
            let d = e.unverified_days(now);
            (30..60).contains(&d)
        })
        .count();
    let unverified_60 = active_entries
        .iter()
        .filter(|e| {
            let d = e.unverified_days(now);
            (60..90).contains(&d)
        })
        .count();
    let unverified_90 = active_entries
        .iter()
        .filter(|e| e.unverified_days(now) >= 90)
        .count();

    json!({
        "expired": expired,
        "expiring_soon": expiring,
        "unused_30_days": unused,
        "metadata_review": metadata_review,
        "recently_verified": recently_verified,
        "duplicates": duplicate_groups,
        "source_quality": source_quality,
        "unverified": {
            "30_59_days": unverified_30,
            "60_89_days": unverified_60,
            "90_plus_days": unverified_90,
        },
    })
    .to_string()
}

fn handle_groups(db: &Database) -> String {
    let entries = db.list_secrets(&ListFilter::default()).unwrap_or_default();
    let mut groups: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for entry in &entries {
        if !entry.key_group.is_empty() {
            groups
                .entry(entry.key_group.clone())
                .or_default()
                .push(secret_to_json(entry));
        }
    }
    let result: Vec<_> = groups
        .into_iter()
        .map(|(g, keys)| json!({"group": g, "keys": keys}))
        .collect();
    json!(result).to_string()
}

fn handle_verify(db: &Database, name: &str) -> String {
    let now = chrono::Utc::now();
    match db.update_secret_metadata(
        name,
        &crate::db::MetadataUpdate {
            last_verified_at: Some(Some(now)),
            ..Default::default()
        },
    ) {
        Ok(_) => json!({
            "ok": true,
            "verified_at": now.format("%Y-%m-%d").to_string()
        })
        .to_string(),
        Err(e) => json!({
            "ok": false,
            "error": e.to_string()
        })
        .to_string(),
    }
}

fn handle_mark_inactive(db: &Database, name: &str) -> String {
    match db.update_secret_metadata(
        name,
        &crate::db::MetadataUpdate {
            is_active: Some(false),
            ..Default::default()
        },
    ) {
        Ok(_) => json!({"ok": true}).to_string(),
        Err(e) => json!({"ok": false, "error": e.to_string()}).to_string(),
    }
}

fn handle_secret_detail(db: &Database, name: &str) -> String {
    match db.get_secret(name) {
        Ok(entry) => secret_to_json(&entry).to_string(),
        Err(e) => json!({"error": e.to_string()}).to_string(),
    }
}

fn handle_search(db: &Database, query: &str) -> String {
    if query.is_empty() {
        return handle_secrets(db);
    }
    let entries = db.search_secrets(query).unwrap_or_default();
    let secrets: Vec<_> = entries.iter().map(secret_to_json).collect();
    json!(secrets).to_string()
}
