use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};

const DEFAULT_PORT: u16 = 8421;
const PROTOCOL_VERSION: &str = "2024-11-05";

fn sentinel_data_dir() -> Option<PathBuf> {
    if let Ok(appdata) = std::env::var("APPDATA") {
        if !appdata.trim().is_empty() {
            return Some(PathBuf::from(appdata).join("com.winpulse.sentinel"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return Some(PathBuf::from(home).join(".local/share/com.winpulse.sentinel"));
        }
    }
    None
}

fn resolve_mcp_port() -> u16 {
    if let Ok(raw) = std::env::var("WINPULSE_MCP_PORT") {
        if let Ok(p) = raw.trim().parse::<u16>() {
            if p >= 1024 {
                return p;
            }
        }
    }
    if let Some(dir) = sentinel_data_dir() {
        if let Ok(raw) = std::fs::read_to_string(dir.join("mcp_port.txt")) {
            if let Ok(p) = raw.trim().parse::<u16>() {
                if p >= 1024 {
                    return p;
                }
            }
        }
    }
    DEFAULT_PORT
}

fn resolve_mcp_token() -> Option<String> {
    if let Ok(raw) = std::env::var("WINPULSE_MCP_TOKEN") {
        let trimmed = raw.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    let dir = sentinel_data_dir()?;
    let raw = std::fs::read_to_string(dir.join("mcp_auth.token")).ok()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn forward_to_running_app(
    client: &reqwest::blocking::Client,
    port: u16,
    token: &str,
    line: &str,
) -> Option<String> {
    let url = format!("http://127.0.0.1:{port}/mcp");
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(line.to_string())
        .send()
        .ok()?;

    if resp.status() == reqwest::StatusCode::ACCEPTED {
        return Some(String::new());
    }
    if !resp.status().is_success() {
        return None;
    }
    resp.text().ok()
}

fn fallback_handle_offline(line: &str) -> Option<String> {
    let req: Value = serde_json::from_str(line).ok()?;
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let id_val = id.unwrap_or(Value::Null);

    let result = match method {
        "initialize" => json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "winpulse-sentinel-offline-db", "version": env!("CARGO_PKG_VERSION") }
        }),
        "ping" => json!({}),
        "tools/list" => json!({
            "tools": [
                {
                    "name": "sentinel_query_timeline",
                    "description": "Consulta a timeline offline do SQLite do WinPulse Sentinel (modo somente leitura).",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "limit": { "type": "integer" } }
                    }
                },
                {
                    "name": "sentinel_propose_remediation",
                    "description": "Requer o app WinPulse Sentinel Desktop aberto para aprovação humana.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "shell": { "type": "string" },
                            "command": { "type": "string" },
                            "rationale": { "type": "string" }
                        }
                    }
                }
            ]
        }),
        "tools/call" => {
            let name = req["params"]["name"].as_str().unwrap_or("");
            if name == "sentinel_query_timeline" {
                let limit = req["params"]["arguments"]["limit"].as_i64().unwrap_or(20).clamp(1, 100);
                let text = read_offline_timeline(limit)
                    .unwrap_or_else(|e| format!("Banco offline indisponível: {e}"));
                json!({ "content": [{ "type": "text", "text": text }], "isError": false })
            } else {
                json!({
                    "content": [{
                        "type": "text",
                        "text": "WinPulse Sentinel Desktop não está em execução no momento. Abra o app Desktop para habilitar execução assistida com aprovação humana e telemetria ao vivo."
                    }],
                    "isError": true
                })
            }
        }
        _ => {
            return Some(
                json!({
                    "jsonrpc": "2.0",
                    "id": id_val,
                    "error": { "code": -32601, "message": format!("Método indisponível em fallback offline: {method}") }
                })
                .to_string(),
            )
        }
    };

    Some(
        json!({
            "jsonrpc": "2.0",
            "id": id_val,
            "result": result
        })
        .to_string(),
    )
}

fn read_offline_timeline(limit: i64) -> Result<String, String> {
    let dir = sentinel_data_dir().ok_or_else(|| "diretório de dados não localizado".to_string())?;
    let db_path = dir.join("winpulse_sentinel.db");
    if !db_path.is_file() {
        return Err(format!("arquivo não encontrado: {}", db_path.display()));
    }
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp_utc, category, severity, friendly_title, event_id, provider_name
             FROM windows_events
             ORDER BY timestamp_ms DESC
             LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([limit], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "timestampUtc": row.get::<_, String>(1)?,
                "category": row.get::<_, String>(2)?,
                "severity": row.get::<_, String>(3)?,
                "title": row.get::<_, String>(4)?,
                "eventId": row.get::<_, u32>(5)?,
                "providerName": row.get::<_, String>(6)?,
            }))
        })
        .map_err(|e| e.to_string())?;

    let mut items = Vec::new();
    for row in rows {
        if let Ok(v) = row {
            items.push(v);
        }
    }
    serde_json::to_string_pretty(&items).map_err(|e| e.to_string())
}

fn main() {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(125))
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            eprintln!("winpulse-mcp client init failed: {err}");
            std::process::exit(1);
        }
    };

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line_res in stdin.lock().lines() {
        let Ok(line) = line_res else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let port = resolve_mcp_port();
        let maybe_resp = if let Some(token) = resolve_mcp_token() {
            forward_to_running_app(&client, port, &token, trimmed)
                .or_else(|| fallback_handle_offline(trimmed))
        } else {
            fallback_handle_offline(trimmed)
        };

        if let Some(resp) = maybe_resp {
            if !resp.is_empty() {
                if writeln!(stdout, "{resp}").is_err() {
                    break;
                }
                let _ = stdout.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_fallback_handles_initialize_and_blocks_remediation() {
        let init = fallback_handle_offline(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)
            .expect("init");
        let parsed: Value = serde_json::from_str(&init).expect("json");
        assert_eq!(parsed["result"]["protocolVersion"], PROTOCOL_VERSION);

        let rem = fallback_handle_offline(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sentinel_propose_remediation","arguments":{"shell":"cmd","command":"echo hi","rationale":"test"}}}"#,
        )
        .expect("rem");
        let rem_parsed: Value = serde_json::from_str(&rem).expect("json");
        assert_eq!(rem_parsed["result"]["isError"], true);
    }
}
