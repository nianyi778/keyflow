use anyhow::Result;
use console::style;
use serde_json::json;
use tiny_http::{Header, Method, Response, Server};

use crate::commands::{get_passphrase, load_config};
use crate::crypto::Crypto;
use crate::db::Database;
use crate::models::{self, ListFilter};

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

fn open_db_for_dashboard() -> Result<Database> {
    let (data_dir, _config, salt) = load_config()?;
    let passphrase = get_passphrase()?;
    let crypto = Crypto::new(&passphrase, &salt)?;
    let db_path = data_dir.join("keyflow.db");
    Database::open(db_path.to_str().unwrap(), crypto)
}

/// Generate a random URL-safe token for dashboard authentication.
fn generate_dashboard_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// Check if a request carries a valid auth token (query param or Authorization header).
fn check_auth(request: &tiny_http::Request, token: &str) -> bool {
    let url = request.url();
    // Check ?token=xxx query parameter
    if let Some(query) = url.split('?').nth(1) {
        for pair in query.split('&') {
            if let Some(val) = pair.strip_prefix("token=") {
                if val == token {
                    return true;
                }
            }
        }
    }
    // Check Authorization: Bearer xxx header
    for header in request.headers() {
        if header.field.as_str().to_ascii_lowercase() == "authorization" {
            if let Some(bearer_token) = header.value.as_str().strip_prefix("Bearer ") {
                if bearer_token == token {
                    return true;
                }
            }
        }
    }
    false
}

/// Strip the ?token=... query parameter from a URL path for routing.
fn strip_query(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

pub fn cmd_dashboard(port: u16) -> Result<()> {
    let db = open_db_for_dashboard()?;
    let token = generate_dashboard_token();

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
    let dashboard_url = format!("http://{}?token={}", addr, token);

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
        style(&dashboard_url).cyan().underlined()
    );
    println!("  Press {} to stop.\n", style("Ctrl+C").yellow());

    // Try to open browser
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(&dashboard_url)
            .spawn();
    }

    for request in server.incoming_requests() {
        let url = request.url().to_string();
        let method = request.method().clone();
        let path = strip_query(&url);

        // The main HTML page is served with token in query param;
        // it should inject the token into API calls via JS.
        // For the HTML page itself, allow access with token in query.
        // For API endpoints, require auth.
        let is_api = path.starts_with("/api/");
        if is_api && !check_auth(&request, &token) {
            let _ = request.respond(
                Response::from_string(r#"{"error":"unauthorized"}"#).with_status_code(401),
            );
            continue;
        }

        let response = match (method, path) {
            (Method::Get, "/") => {
                // Inject the token into the HTML so frontend JS can use it for API calls
                let html = DASHBOARD_HTML.replace(
                    "{{KEYFLOW_TOKEN}}",
                    &token,
                );
                let header =
                    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                        .unwrap();
                Response::from_string(html).with_header(header)
            }
            (Method::Get, "/api/stats") => json_response(&handle_stats(&db)),
            (Method::Get, "/api/secrets") => json_response(&handle_secrets(&db)),
            (Method::Get, "/api/health") => json_response(&handle_health(&db)),
            (Method::Get, "/api/groups") => json_response(&handle_groups(&db)),
            (Method::Get, p) if p.starts_with("/api/search") => {
                let query = url
                    .split("q=")
                    .nth(1)
                    .unwrap_or("")
                    .split('&')
                    .next()
                    .unwrap_or("");
                let decoded = urldecode(query);
                json_response(&handle_search(&db, &decoded))
            }
            (Method::Post, p) if p.starts_with("/api/verify/") => {
                let name = urldecode(&p["/api/verify/".len()..]);
                json_response(&handle_verify(&db, &name))
            }
            (Method::Post, p) if p.starts_with("/api/inactive/") => {
                let name = urldecode(&p["/api/inactive/".len()..]);
                json_response(&handle_mark_inactive(&db, &name))
            }
            (Method::Get, p) if p.starts_with("/api/secret/") => {
                let name = urldecode(&p["/api/secret/".len()..]);
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
    Response::from_string(body).with_header(header)
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
    models::secret_to_json(entry)
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
    let recently_verified: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.last_verified_at
                .map(|v| v >= seven_days_ago)
                .unwrap_or(false)
        })
        .map(secret_to_json)
        .collect();

    let h = models::HealthReport::from_entries(&entries);

    json!({
        "expired": h.expired,
        "expiring_soon": h.expiring_soon,
        "unused_30_days": h.unused_30d,
        "metadata_review": h.metadata_review,
        "recently_verified": recently_verified,
        "duplicates": h.duplicate_groups,
        "source_quality": h.source_quality,
        "unverified": {
            "30_59_days": h.unverified_30,
            "60_89_days": h.unverified_60,
            "90_plus_days": h.unverified_90,
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
