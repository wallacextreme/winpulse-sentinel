use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::db::Database;
use crate::error::SentinelError;
use crate::executor::ExecutionCoordinator;
use crate::models::{
    CommandShell, CommandSource, McpServerStatus, StagedCommandTicket, TimelineItemType,
};
use crate::sanitizer::sanitize_text;
use crate::secrets::mask_secret;
use crate::server::StatusProvider;
use crate::telemetry::SharedRingBuffer;
use crate::translator::KnowledgeBase;

pub const DEFAULT_MCP_PORT: u16 = 8421;
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

pub type ApprovalCallback = Arc<dyn Fn(StagedCommandTicket) + Send + Sync>;

#[derive(Clone)]
struct McpHttpState {
    db: Database,
    ring_buffer: SharedRingBuffer,
    kb: KnowledgeBase,
    status_provider: StatusProvider,
    executor: ExecutionCoordinator,
    token: Arc<Mutex<String>>,
    on_approval_requested: ApprovalCallback,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

fn generate_mcp_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub fn validate_mcp_port(port: Option<u16>) -> Result<u16, SentinelError> {
    let p = port.unwrap_or(DEFAULT_MCP_PORT);
    if p < 1024 {
        return Err(SentinelError::InvalidInput(
            "porta MCP deve estar entre 1024 e 65535".to_string(),
        ));
    }
    Ok(p)
}

fn verify_bearer(headers: &HeaderMap, expected_token: &str) -> bool {
    let Some(raw) = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Some(candidate) = raw.strip_prefix("Bearer ").map(str::trim) else {
        return false;
    };
    if candidate.is_empty() || candidate.len() != expected_token.len() {
        return false;
    }
    bool::from(candidate.as_bytes().ct_eq(expected_token.as_bytes()))
}

async fn mcp_health_handler() -> Json<Value> {
    Json(json!({ "status": "ok", "protocol": "mcp", "version": MCP_PROTOCOL_VERSION }))
}

async fn mcp_rpc_handler(
    State(state): State<McpHttpState>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    let expected = match state.token.lock() {
        Ok(g) => g.clone(),
        Err(_) => return SentinelError::Internal("mcp token lock poisoned".to_string()).into_response(),
    };

    if !verify_bearer(&headers, &expected) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Unauthorized MCP bearer token" })),
        )
            .into_response();
    }

    if req.id.is_none() || req.method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }

    let id = req.id.unwrap_or(Value::Null);
    let response = dispatch_rpc(&state, id, &req.method, &req.params).await;
    (StatusCode::OK, Json(response)).into_response()
}

async fn dispatch_rpc(
    state: &McpHttpState,
    id: Value,
    method: &str,
    params: &Value,
) -> JsonRpcResponse {
    match method {
        "initialize" => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": { "listChanged": false },
                    "resources": { "subscribe": false, "listChanged": false }
                },
                "serverInfo": {
                    "name": "winpulse-sentinel",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        },
        "ping" => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({})),
            error: None,
        },
        "tools/list" => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({ "tools": mcp_tools_schema() })),
            error: None,
        },
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or("");
            let args = &params["arguments"];
            match handle_tool_call(state, name, args).await {
                Ok(text_payload) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!({
                        "content": [{ "type": "text", "text": text_payload }],
                        "isError": false
                    })),
                    error: None,
                },
                Err(err_msg) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!({
                        "content": [{ "type": "text", "text": err_msg }],
                        "isError": true
                    })),
                    error: None,
                },
            }
        }
        "resources/list" => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({
                "resources": [
                    {
                        "uri": "winpulse://status",
                        "name": "Collector Status",
                        "description": "Estado em tempo real do coletor de telemetria e Event Log",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "winpulse://telemetry/recent",
                        "name": "Recent Telemetry Ring Buffer",
                        "description": "Últimos 60 segundos de CPU, RAM, Disco PDH e Rede",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "winpulse://knowledge-base",
                        "name": "Windows Knowledge Base PT-BR",
                        "description": "Catálogo local de erros Windows traduzidos",
                        "mimeType": "application/json"
                    }
                ]
            })),
            error: None,
        },
        "resources/read" => {
            let uri = params["uri"].as_str().unwrap_or("");
            let content = match uri {
                "winpulse://status" => serde_json::to_string_pretty(&(state.status_provider)()).ok(),
                "winpulse://telemetry/recent" => state
                    .ring_buffer
                    .read()
                    .ok()
                    .and_then(|g| serde_json::to_string_pretty(&g.as_vec()).ok()),
                "winpulse://knowledge-base" => {
                    serde_json::to_string_pretty(&state.kb.catalog()).ok()
                }
                _ => None,
            };
            match content {
                Some(text) => JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!({
                        "contents": [{ "uri": uri, "mimeType": "application/json", "text": text }]
                    })),
                    error: None,
                },
                None => JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: format!("Recurso desconhecido: {uri}"),
                    }),
                },
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Método MCP não suportado: {method}"),
            }),
        },
    }
}

fn mcp_tools_schema() -> Value {
    json!([
        {
            "name": "sentinel_get_status",
            "description": "Obtém o status atual do coletor WinPulse Sentinel (saúde, elevação UAC, uptime, buffer).",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "sentinel_get_recent_telemetry",
            "description": "Retorna as amostras recentes (até 60s) de CPU, RAM, Disco PDH e Rede.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "sentinel_query_timeline",
            "description": "Lista eventos do Windows Event Log e snapshots de gargalos correlacionados.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100 },
                    "category": { "type": "string" },
                    "severity": { "type": "string", "enum": ["medium", "high", "critical"] }
                }
            }
        },
        {
            "name": "sentinel_get_incident_detail",
            "description": "Obtém detalhes completos (com XML sanitizado de PII) e correlações [T-15s, T+5s] de um incidente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "itemType": { "type": "string", "enum": ["event", "snapshot"] },
                    "id": { "type": "integer" }
                },
                "required": ["itemType", "id"]
            }
        },
        {
            "name": "sentinel_search_knowledge_base",
            "description": "Busca na base de conhecimento PT-BR do WinPulse Sentinel por Event ID ou palavra-chave.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }
        },
        {
            "name": "sentinel_propose_remediation",
            "description": "Propõe um comando PowerShell ou CMD seguro para correção. Abre um modal de aprovação humana no WinPulse Sentinel Desktop e só executa se o usuário clicar em Aprovar.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "shell": { "type": "string", "enum": ["powershell", "cmd"] },
                    "command": { "type": "string" },
                    "rationale": { "type": "string" },
                    "requiresAdmin": { "type": "boolean" }
                },
                "required": ["shell", "command", "rationale"]
            }
        }
    ])
}

async fn handle_tool_call(
    state: &McpHttpState,
    name: &str,
    args: &Value,
) -> Result<String, String> {
    match name {
        "sentinel_get_status" => {
            let status = (state.status_provider)();
            serde_json::to_string_pretty(&status).map_err(|e| e.to_string())
        }
        "sentinel_get_recent_telemetry" => {
            let samples = state
                .ring_buffer
                .read()
                .map_err(|_| "ring buffer lock poisoned".to_string())?
                .as_vec();
            serde_json::to_string_pretty(&samples).map_err(|e| e.to_string())
        }
        "sentinel_query_timeline" => {
            let limit = args["limit"].as_u64().unwrap_or(25).clamp(1, 100) as u32;
            let category = args["category"].as_str();
            let severity = args["severity"].as_str();
            let items = state
                .db
                .get_timeline(limit, 0, category, severity)
                .map_err(|e| e.to_string())?;
            serde_json::to_string_pretty(&items).map_err(|e| e.to_string())
        }
        "sentinel_get_incident_detail" => {
            let item_type = match args["itemType"].as_str().unwrap_or("") {
                "event" => TimelineItemType::Event,
                "snapshot" => TimelineItemType::Snapshot,
                _ => return Err("itemType deve ser 'event' ou 'snapshot'".to_string()),
            };
            let id = args["id"]
                .as_i64()
                .ok_or_else(|| "id inteiro obrigatório".to_string())?;
            let mut detail = state
                .db
                .get_incident_detail(item_type, id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("Incidente {id} não encontrado"))?;
            if let Some(ev) = detail.event.as_mut() {
                ev.raw_xml = sanitize_text(&ev.raw_xml);
                ev.diagnostic_note = ev.diagnostic_note.as_deref().map(sanitize_text);
            }
            for ev in &mut detail.correlated_events {
                ev.raw_xml = sanitize_text(&ev.raw_xml);
                ev.diagnostic_note = ev.diagnostic_note.as_deref().map(sanitize_text);
            }
            detail.diagnostic_note = detail.diagnostic_note.as_deref().map(sanitize_text);
            serde_json::to_string_pretty(&detail).map_err(|e| e.to_string())
        }
        "sentinel_search_knowledge_base" => {
            let q = args["query"].as_str().unwrap_or("").trim().to_ascii_lowercase();
            let catalog = state.kb.catalog();
            let matched: Vec<_> = if q.is_empty() {
                catalog
            } else {
                catalog
                    .into_iter()
                    .filter(|entry| {
                        entry.friendly_title.to_ascii_lowercase().contains(&q)
                            || entry.category.to_ascii_lowercase().contains(&q)
                            || entry.event_id.to_string() == q
                            || entry.sources.iter().any(|s| s.to_ascii_lowercase().contains(&q))
                    })
                    .collect()
            };
            serde_json::to_string_pretty(&matched).map_err(|e| e.to_string())
        }
        "sentinel_propose_remediation" => {
            let shell = CommandShell::from_str_lossy(args["shell"].as_str().unwrap_or("powershell"));
            let command = args["command"]
                .as_str()
                .ok_or_else(|| "campo 'command' obrigatório".to_string())?;
            let rationale = args["rationale"]
                .as_str()
                .unwrap_or("Ação proposta por agente MCP conectado.");
            let requires_admin = args["requiresAdmin"].as_bool().unwrap_or(false);

            let (ticket, rx) = state
                .executor
                .stage_command_with_waiter(
                    CommandSource::Mcp,
                    shell,
                    command,
                    rationale,
                    requires_admin,
                )
                .map_err(|e| e.to_string())?;

            (state.on_approval_requested)(ticket.clone());

            match tokio::time::timeout(Duration::from_secs(120), rx).await {
                Ok(Ok(exec_res)) => {
                    serde_json::to_string_pretty(&exec_res).map_err(|e| e.to_string())
                }
                Ok(Err(_)) => Err("Pedido de aprovação cancelado antes da resposta.".to_string()),
                Err(_) => {
                    let _ = state.executor.reject_command(&ticket.approval_id);
                    Err("Tempo limite de 120s aguardando aprovação humana no Desktop.".to_string())
                }
            }
        }
        _ => Err(format!("Tool MCP desconhecida: {name}")),
    }
}

fn build_mcp_router(state: McpHttpState) -> Router {
    Router::new()
        .route("/health", get(mcp_health_handler))
        .route("/mcp", post(mcp_rpc_handler))
        .with_state(state)
}

pub struct McpServerController {
    enabled: bool,
    port: u16,
    token: Arc<Mutex<String>>,
    token_file: Option<PathBuf>,
    port_file: Option<PathBuf>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    db: Database,
    ring_buffer: SharedRingBuffer,
    kb: KnowledgeBase,
    status_provider: StatusProvider,
    executor: ExecutionCoordinator,
    on_approval_requested: ApprovalCallback,
}

impl McpServerController {
    pub fn new(
        db: Database,
        ring_buffer: SharedRingBuffer,
        kb: KnowledgeBase,
        status_provider: StatusProvider,
        executor: ExecutionCoordinator,
        app_data_dir: Option<PathBuf>,
        on_approval_requested: ApprovalCallback,
    ) -> Self {
        let token_file = app_data_dir.as_ref().map(|d| d.join("mcp_auth.token"));
        let port_file = app_data_dir.as_ref().map(|d| d.join("mcp_port.txt"));
        let token = load_or_create_token(token_file.as_deref());
        Self {
            enabled: false,
            port: DEFAULT_MCP_PORT,
            token: Arc::new(Mutex::new(token)),
            token_file,
            port_file,
            shutdown_tx: None,
            db,
            ring_buffer,
            kb,
            status_provider,
            executor,
            on_approval_requested,
        }
    }

    pub fn status(&self) -> McpServerStatus {
        let preview = self
            .token
            .lock()
            .map(|t| mask_secret(&t))
            .unwrap_or_else(|_| "••••••".to_string());
        McpServerStatus {
            enabled: self.enabled,
            port: self.port,
            endpoint_url: format!("http://127.0.0.1:{}/mcp", self.port),
            token_preview: preview,
            stdio_binary_name: "winpulse-mcp.exe".to_string(),
        }
    }

    pub async fn start(&mut self, port: Option<u16>) -> Result<McpServerStatus, SentinelError> {
        let target_port = validate_mcp_port(port.or(Some(self.port)))?;
        if self.enabled && self.port == target_port {
            return Ok(self.status());
        }
        self.stop();

        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), target_port);
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let bound_port = listener.local_addr()?.port();

        let state = McpHttpState {
            db: self.db.clone(),
            ring_buffer: Arc::clone(&self.ring_buffer),
            kb: self.kb.clone(),
            status_provider: Arc::clone(&self.status_provider),
            executor: self.executor.clone(),
            token: Arc::clone(&self.token),
            on_approval_requested: Arc::clone(&self.on_approval_requested),
        };
        let router = build_mcp_router(state);
        let (tx, rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let server = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = rx.await;
            });
            if let Err(err) = server.await {
                tracing::error!(error = %err, "MCP loopback server terminated with error");
            }
        });

        self.port = bound_port;
        self.enabled = true;
        self.shutdown_tx = Some(tx);
        persist_port_file(self.port_file.as_deref(), bound_port);
        tracing::info!(port = bound_port, "MCP loopback server started on 127.0.0.1");
        Ok(self.status())
    }

    pub fn stop(&mut self) -> McpServerStatus {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.enabled = false;
        self.status()
    }

    pub fn rotate_token(&mut self) -> Result<McpServerStatus, SentinelError> {
        let next = generate_mcp_token();
        {
            let mut guard = self
                .token
                .lock()
                .map_err(|_| SentinelError::Internal("mcp token lock poisoned".to_string()))?;
            *guard = next.clone();
        }
        persist_token_file(self.token_file.as_deref(), &next);
        Ok(self.status())
    }
}

fn load_or_create_token(path: Option<&Path>) -> String {
    if let Some(p) = path {
        if let Ok(existing) = std::fs::read_to_string(p) {
            let trimmed = existing.trim().to_string();
            if trimmed.len() >= 32 {
                return trimmed;
            }
        }
    }
    let fresh = generate_mcp_token();
    persist_token_file(path, &fresh);
    fresh
}

fn persist_token_file(path: Option<&Path>, token: &str) {
    if let Some(p) = path {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(p, token);
    }
}

fn persist_port_file(path: Option<&Path>, port: u16) {
    if let Some(p) = path {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(p, port.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CollectorStatus, HealthStatus};
    use crate::telemetry::new_shared_ring_buffer;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn make_mcp_test_state() -> (McpHttpState, String) {
        let db = Database::open_in_memory().expect("db");
        let rb = new_shared_ring_buffer();
        let kb = KnowledgeBase::from_embedded().unwrap_or_else(|_| unreachable!());
        let executor = ExecutionCoordinator::new(db.clone());
        let status_provider: StatusProvider = Arc::new(|| CollectorStatus {
            paused: false,
            uptime_secs: 15,
            ring_buffer_len: 0,
            event_watcher_active: true,
            is_elevated: false,
            health_status: HealthStatus::Stable,
        });
        let token = "test_mcp_token_1234567890abcdef1234567890".to_string();
        let state = McpHttpState {
            db,
            ring_buffer: rb,
            kb,
            status_provider,
            executor,
            token: Arc::new(Mutex::new(token.clone())),
            on_approval_requested: Arc::new(|_| {}),
        };
        (state, token)
    }

    #[tokio::test]
    async fn mcp_requires_bearer_token_and_handles_initialize_and_tools() {
        let (state, token) = make_mcp_test_state();
        let app = build_mcp_router(state);

        let unauth = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let init_res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(init_res.status(), StatusCode::OK);
        let bytes = init_res.into_body().collect().await.expect("bytes").to_bytes();
        let parsed: Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(parsed["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);

        let tools_res = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#))
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(tools_res.status(), StatusCode::OK);
        let t_bytes = tools_res.into_body().collect().await.expect("bytes").to_bytes();
        let t_parsed: Value = serde_json::from_slice(&t_bytes).expect("json");
        let tools = t_parsed["result"]["tools"].as_array().expect("tools array");
        assert!(tools.iter().any(|t| t["name"] == "sentinel_propose_remediation"));
    }

    #[tokio::test]
    async fn mcp_propose_remediation_waits_for_human_approval() {
        let (state, token) = make_mcp_test_state();
        let exec_clone = state.executor.clone();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel::<StagedCommandTicket>();
        let tx_cell = Arc::new(Mutex::new(Some(ticket_tx)));

        let mut state = state;
        state.on_approval_requested = Arc::new(move |ticket| {
            if let Ok(mut guard) = tx_cell.lock() {
                if let Some(tx) = guard.take() {
                    let _ = tx.send(ticket);
                }
            }
        });

        let app = build_mcp_router(state);
        tokio::spawn(async move {
            if let Ok(ticket) = ticket_rx.await {
                let _ = exec_clone
                    .approve_and_execute(&ticket.approval_id, &ticket.command, Some(10), |_| {})
                    .await;
            }
        });

        let call_res = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sentinel_propose_remediation","arguments":{"shell":"cmd","command":"echo mcp_approved","rationale":"Teste MCP"}}}"#,
                    ))
                    .expect("req"),
            )
            .await
            .expect("resp");

        assert_eq!(call_res.status(), StatusCode::OK);
        let bytes = call_res.into_body().collect().await.expect("bytes").to_bytes();
        let parsed: Value = serde_json::from_slice(&bytes).expect("json");
        let text = parsed["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("mcp_approved"));
        assert!(text.contains("succeeded"));
    }
}
