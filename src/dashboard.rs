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
                let header = Header::from_bytes(
                    &b"Content-Type"[..],
                    &b"text/html; charset=utf-8"[..],
                ).unwrap();
                Response::from_string(DASHBOARD_HTML)
                    .with_header(header)
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
            _ => {
                Response::from_string("404 Not Found")
                    .with_status_code(404)
            }
        };

        let _ = request.respond(response);
    }

    Ok(())
}

fn json_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let header = Header::from_bytes(
        &b"Content-Type"[..],
        &b"application/json; charset=utf-8"[..],
    ).unwrap();
    let cors = Header::from_bytes(
        &b"Access-Control-Allow-Origin"[..],
        &b"*"[..],
    ).unwrap();
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
        "description": entry.description,
        "scopes": entry.scopes,
        "projects": entry.projects,
        "key_group": entry.key_group,
        "apply_url": entry.apply_url,
        "status": entry.status().to_string(),
        "expires_at": entry.expires_at.map(|d| d.format("%Y-%m-%d").to_string()),
        "last_used_at": entry.last_used_at.map(|d| d.format("%Y-%m-%d").to_string()),
    })
}

fn handle_stats(db: &Database) -> String {
    let all = db.list_secrets(&ListFilter { inactive: true, ..Default::default() }).unwrap_or_default();
    let active = all.iter().filter(|e| matches!(e.status(), crate::models::KeyStatus::Active)).count();
    let expired = all.iter().filter(|e| matches!(e.status(), crate::models::KeyStatus::Expired)).count();
    let expiring = all.iter().filter(|e| matches!(e.status(), crate::models::KeyStatus::ExpiringSoon)).count();
    let groups = db.list_groups().unwrap_or_default().len();

    json!({
        "total": all.len(),
        "active": active,
        "expired": expired,
        "expiring_soon": expiring,
        "groups_count": groups,
    }).to_string()
}

fn handle_secrets(db: &Database) -> String {
    let entries = db.list_secrets(&ListFilter { inactive: true, ..Default::default() }).unwrap_or_default();
    let secrets: Vec<_> = entries.iter().map(secret_to_json).collect();
    json!(secrets).to_string()
}

fn handle_health(db: &Database) -> String {
    let entries = db.list_secrets(&ListFilter { inactive: true, ..Default::default() }).unwrap_or_default();
    let now = chrono::Utc::now();

    let expired: Vec<_> = entries.iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::Expired))
        .map(secret_to_json).collect();
    let expiring: Vec<_> = entries.iter()
        .filter(|e| matches!(e.status(), crate::models::KeyStatus::ExpiringSoon))
        .map(secret_to_json).collect();
    let unused: Vec<_> = entries.iter()
        .filter(|e| {
            e.is_active && {
                let last = e.last_used_at.unwrap_or(e.created_at);
                (now - last).num_days() > 30
            }
        })
        .map(secret_to_json).collect();

    json!({
        "expired": expired,
        "expiring_soon": expiring,
        "unused_30_days": unused,
    }).to_string()
}

fn handle_groups(db: &Database) -> String {
    let entries = db.list_secrets(&ListFilter::default()).unwrap_or_default();
    let mut groups: std::collections::HashMap<String, Vec<serde_json::Value>> = std::collections::HashMap::new();
    for entry in &entries {
        if !entry.key_group.is_empty() {
            groups.entry(entry.key_group.clone()).or_default().push(secret_to_json(entry));
        }
    }
    let result: Vec<_> = groups.into_iter().map(|(g, keys)| json!({"group": g, "keys": keys})).collect();
    json!(result).to_string()
}

fn handle_search(db: &Database, query: &str) -> String {
    if query.is_empty() {
        return handle_secrets(db);
    }
    let entries = db.search_secrets(query).unwrap_or_default();
    let secrets: Vec<_> = entries.iter().map(secret_to_json).collect();
    json!(secrets).to_string()
}
