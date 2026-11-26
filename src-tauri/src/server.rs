use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State, WebSocketUpgrade};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ORIGIN};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, oneshot, watch};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use uuid::Uuid;

use crate::db::Database;
use crate::error::SentinelError;
use crate::models::{
    CollectorStatus, IncidentDetail, KnowledgeBaseEntry, RemoteServerStatus, TelemetrySample,
    TimelineItem, TimelineItemType, WsEnvelope,
};
use crate::telemetry::SharedRingBuffer;
use crate::translator::KnowledgeBase;

pub const DEFAULT_REMOTE_PORT: u16 = 8420;
const MAX_FAILED_ATTEMPTS_PER_IP: usize = 5;
const MAX_GLOBAL_FAILED_ATTEMPTS: usize = 20;
const MAX_TRACKED_FAILED_IPS: usize = 256;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const TOKEN_TTL_MS: i64 = 24 * 60 * 60 * 1000;
const WS_TICKET_TTL_MS: i64 = 30 * 1000;
const MAX_ACTIVE_SESSIONS: usize = 32;
const MAX_PENDING_WS_TICKETS: usize = 64;
const MAX_WS_CLIENTS: usize = 16;
const MAX_REQUEST_BODY_BYTES: usize = 4096;

pub type StatusProvider = Arc<dyn Fn() -> CollectorStatus + Send + Sync>;

#[derive(Debug)]
pub struct AuthStore {
    pin: String,
    tokens: HashMap<String, i64>,
    ws_tickets: HashMap<String, i64>,
    failed_attempts: HashMap<IpAddr, Vec<Instant>>,
    global_failures: Vec<Instant>,
}

impl AuthStore {
    pub fn new() -> Self {
        Self {
            pin: generate_pin(),
            tokens: HashMap::new(),
            ws_tickets: HashMap::new(),
            failed_attempts: HashMap::new(),
            global_failures: Vec::new(),
        }
    }

    pub fn pin(&self) -> &str {
        &self.pin
    }

    pub fn regenerate_pin(&mut self) -> String {
        self.pin = generate_pin();
        self.tokens.clear();
        self.ws_tickets.clear();
        self.failed_attempts.clear();
        self.global_failures.clear();
        self.pin.clone()
    }

    pub fn verify_pin(&mut self, ip: IpAddr, candidate_pin: &str) -> Result<String, SentinelError> {
        let now_instant = Instant::now();
        self.global_failures
            .retain(|ts| now_instant.duration_since(*ts) < RATE_LIMIT_WINDOW);
        if self.global_failures.len() >= MAX_GLOBAL_FAILED_ATTEMPTS {
            return Err(SentinelError::RateLimited);
        }

        self.failed_attempts.retain(|_, list| {
            list.retain(|ts| now_instant.duration_since(*ts) < RATE_LIMIT_WINDOW);
            !list.is_empty()
        });

        if let Some(ip_list) = self.failed_attempts.get(&ip) {
            if ip_list.len() >= MAX_FAILED_ATTEMPTS_PER_IP {
                return Err(SentinelError::RateLimited);
            }
        }

        let trimmed = candidate_pin.trim();
        let pin_matches = self.pin.len() == trimmed.len()
            && bool::from(self.pin.as_bytes().ct_eq(trimmed.as_bytes()));

        if !pin_matches {
            self.global_failures.push(now_instant);
            if !self.failed_attempts.contains_key(&ip)
                && self.failed_attempts.len() >= MAX_TRACKED_FAILED_IPS
            {
                if let Some(oldest_ip) = self
                    .failed_attempts
                    .iter()
                    .min_by_key(|(_, list)| list.last().copied().unwrap_or(now_instant))
                    .map(|(k, _)| *k)
                {
                    self.failed_attempts.remove(&oldest_ip);
                }
            }
            self.failed_attempts.entry(ip).or_default().push(now_instant);
            return Err(SentinelError::Unauthorized);
        }

        self.failed_attempts.remove(&ip);

        let now_ms = Utc::now().timestamp_millis();
        self.tokens.retain(|_, exp| *exp > now_ms);
        if self.tokens.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest_key) = self
                .tokens
                .iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                self.tokens.remove(&oldest_key);
            }
        }

        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        self.tokens.insert(token.clone(), now_ms + TOKEN_TTL_MS);
        Ok(token)
    }

    pub fn verify_token(&mut self, candidate: &str) -> bool {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return false;
        }
        let now_ms = Utc::now().timestamp_millis();
        self.tokens.retain(|_, exp| *exp > now_ms);

        let mut matched = false;
        for token in self.tokens.keys() {
            if token.len() == trimmed.len()
                && bool::from(token.as_bytes().ct_eq(trimmed.as_bytes()))
            {
                matched = true;
            }
        }
        matched
    }

    pub fn issue_ws_ticket(&mut self) -> String {
        let now_ms = Utc::now().timestamp_millis();
        self.ws_tickets.retain(|_, exp| *exp > now_ms);
        if self.ws_tickets.len() >= MAX_PENDING_WS_TICKETS {
            if let Some(oldest_key) = self
                .ws_tickets
                .iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                self.ws_tickets.remove(&oldest_key);
            }
        }
        let ticket = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        self.ws_tickets
            .insert(ticket.clone(), now_ms + WS_TICKET_TTL_MS);
        ticket
    }

    pub fn consume_ws_ticket(&mut self, candidate: &str) -> bool {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return false;
        }
        let now_ms = Utc::now().timestamp_millis();
        self.ws_tickets.retain(|_, exp| *exp > now_ms);

        let mut matched_key: Option<String> = None;
        for ticket in self.ws_tickets.keys() {
            if ticket.len() == trimmed.len()
                && bool::from(ticket.as_bytes().ct_eq(trimmed.as_bytes()))
            {
                matched_key = Some(ticket.clone());
            }
        }

        if let Some(key) = matched_key {
            self.ws_tickets.remove(&key);
            true
        } else {
            false
        }
    }
}

impl Default for AuthStore {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_pin() -> String {
    let mut rng = rand::rng();
    let code: u32 = rng.random_range(100_000..=999_999);
    format!("{code:06}")
}

#[derive(Clone)]
pub struct RemoteApiState {
    pub db: Database,
    pub ring_buffer: SharedRingBuffer,
    pub kb: KnowledgeBase,
    pub auth: Arc<Mutex<AuthStore>>,
    pub ws_tx: broadcast::Sender<WsEnvelope>,
    pub status_provider: StatusProvider,
    pub active_ws_clients: Arc<AtomicUsize>,
    pub auth_epoch_tx: watch::Sender<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub pin: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct WsTicketResponse {
    pub ticket: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub category: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WsAuthQuery {
    pub ticket: Option<String>,
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|t| t.trim().to_string())
}

struct ClientIp(IpAddr);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        Ok(Self(ip))
    }
}

async fn require_auth(
    State(state): State<RemoteApiState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, SentinelError> {
    let Some(token) = extract_bearer_token(request.headers()) else {
        return Err(SentinelError::Unauthorized);
    };

    let valid = state
        .auth
        .lock()
        .map_err(|_| SentinelError::Internal("auth mutex poisoned".to_string()))?
        .verify_token(&token);

    if !valid {
        return Err(SentinelError::Unauthorized);
    }

    Ok(next.run(request).await)
}

async fn security_headers_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    response
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn login_handler(
    State(state): State<RemoteApiState>,
    ClientIp(ip): ClientIp,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, SentinelError> {
    let token = state
        .auth
        .lock()
        .map_err(|_| SentinelError::Internal("auth mutex poisoned".to_string()))?
        .verify_pin(ip, &payload.pin)?;

    Ok(Json(LoginResponse { token }))
}

async fn ws_ticket_handler(
    State(state): State<RemoteApiState>,
) -> Result<Json<WsTicketResponse>, SentinelError> {
    let ticket = state
        .auth
        .lock()
        .map_err(|_| SentinelError::Internal("auth mutex poisoned".to_string()))?
        .issue_ws_ticket();

    Ok(Json(WsTicketResponse { ticket }))
}

async fn status_handler(State(state): State<RemoteApiState>) -> Json<CollectorStatus> {
    Json((state.status_provider)())
}

async fn knowledge_base_handler(
    State(state): State<RemoteApiState>,
) -> Json<Vec<KnowledgeBaseEntry>> {
    Json(state.kb.catalog())
}

async fn recent_telemetry_handler(
    State(state): State<RemoteApiState>,
) -> Result<Json<Vec<TelemetrySample>>, SentinelError> {
    let samples = state
        .ring_buffer
        .read()
        .map_err(|_| SentinelError::Internal("ring buffer lock poisoned".to_string()))?
        .as_vec();
    Ok(Json(samples))
}

async fn timeline_handler(
    State(state): State<RemoteApiState>,
    Query(q): Query<TimelineQuery>,
) -> Result<Json<Vec<TimelineItem>>, SentinelError> {
    let limit = q.limit.unwrap_or(100).min(500);
    let offset = q.offset.unwrap_or(0);
    let items = state.db.get_timeline(
        limit,
        offset,
        q.category.as_deref(),
        q.severity.as_deref(),
    )?;
    Ok(Json(items))
}

async fn incident_detail_handler(
    State(state): State<RemoteApiState>,
    Path((item_type, id)): Path<(String, i64)>,
) -> Result<Json<IncidentDetail>, SentinelError> {
    let parsed_type = match item_type.trim().to_ascii_lowercase().as_str() {
        "event" => TimelineItemType::Event,
        "snapshot" => TimelineItemType::Snapshot,
        _ => {
            return Err(SentinelError::InvalidInput(
                "item_type must be 'event' or 'snapshot'".to_string(),
            ))
        }
    };

    let detail = state
        .db
        .get_incident_detail(parsed_type, id)?
        .ok_or_else(|| SentinelError::NotFound(format!("{item_type} {id} not found")))?;

    Ok(Json(detail))
}

struct WsClientGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for WsClientGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<RemoteApiState>,
    headers: HeaderMap,
    Query(query): Query<WsAuthQuery>,
) -> Response {
    if let Some(origin) = headers.get(ORIGIN) {
        if !is_allowed_lan_origin(origin) {
            return SentinelError::Forbidden("origin not allowed".to_string()).into_response();
        }
    }

    if state.active_ws_clients.load(Ordering::Relaxed) >= MAX_WS_CLIENTS {
        return SentinelError::ServiceUnavailable("maximum remote clients reached".to_string())
            .into_response();
    }

    let authorized = if let Some(bearer) = extract_bearer_token(&headers) {
        match state.auth.lock() {
            Ok(mut auth) => auth.verify_token(&bearer),
            Err(_) => {
                return SentinelError::Internal("auth mutex poisoned".to_string()).into_response();
            }
        }
    } else if let Some(ticket) = query.ticket.as_deref() {
        match state.auth.lock() {
            Ok(mut auth) => auth.consume_ws_ticket(ticket),
            Err(_) => {
                return SentinelError::Internal("auth mutex poisoned".to_string()).into_response();
            }
        }
    } else {
        false
    };

    if !authorized {
        return SentinelError::Unauthorized.into_response();
    }

    ws.on_upgrade(move |socket| handle_ws_socket(socket, state))
}

async fn handle_ws_socket(mut socket: WebSocket, state: RemoteApiState) {
    state.active_ws_clients.fetch_add(1, Ordering::SeqCst);
    let _guard = WsClientGuard {
        counter: Arc::clone(&state.active_ws_clients),
    };

    let mut epoch_rx = state.auth_epoch_tx.subscribe();

    let status_env = WsEnvelope::Status((state.status_provider)());
    if let Ok(json) = serde_json::to_string(&status_env) {
        if socket.send(Message::Text(json.into())).await.is_err() {
            return;
        }
    }

    let recent_samples: Vec<TelemetrySample> = match state.ring_buffer.read() {
        Ok(guard) => guard.as_vec(),
        Err(_) => Vec::new(),
    };
    for sample in recent_samples {
        if let Ok(json) = serde_json::to_string(&WsEnvelope::Telemetry(sample)) {
            if socket.send(Message::Text(json.into())).await.is_err() {
                return;
            }
        }
    }

    let mut rx = state.ws_tx.subscribe();
    loop {
        tokio::select! {
            changed = epoch_rx.changed() => {
                if changed.is_ok() {
                    let _ = socket.send(Message::Close(None)).await;
                }
                break;
            }
            recv = rx.recv() => {
                match recv {
                    Ok(env) => {
                        if let Ok(json) = serde_json::to_string(&env) {
                            if socket.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}

pub fn is_allowed_lan_origin(origin: &HeaderValue) -> bool {
    let Ok(s) = origin.to_str() else {
        return false;
    };
    if s.contains('@') || s.contains('?') || s.contains('#') || s.chars().any(char::is_whitespace) {
        return false;
    }

    let Ok(uri) = s.parse::<Uri>() else {
        return false;
    };
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "tauri"
    ) {
        return false;
    }

    if let Some(pq) = uri.path_and_query() {
        if pq.as_str() != "/" {
            return false;
        }
    }

    let Some(authority) = uri.authority() else {
        return false;
    };
    if authority.as_str().contains('@') {
        return false;
    }

    let host = authority.host().to_ascii_lowercase();
    if host == "localhost" || host == "127.0.0.1" || host == "tauri.localhost" {
        return true;
    }

    if let Ok(IpAddr::V4(v4)) = host.parse::<IpAddr>() {
        return v4.is_private() || v4.is_loopback();
    }

    false
}

pub fn build_router(state: RemoteApiState, static_dist_dir: Option<PathBuf>) -> Router {
    let protected = Router::new()
        .route("/api/auth/ws-ticket", post(ws_ticket_handler))
        .route("/api/status", get(status_handler))
        .route("/api/knowledge-base", get(knowledge_base_handler))
        .route("/api/telemetry/recent", get(recent_telemetry_handler))
        .route("/api/timeline", get(timeline_handler))
        .route(
            "/api/incidents/{item_type}/{id}",
            get(incident_detail_handler),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin, _| {
            is_allowed_lan_origin(origin)
        }))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);

    let mut router = Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/ws", get(ws_handler))
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(cors)
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state);

    if let Some(dist) = static_dist_dir {
        if dist.is_dir() {
            let index_file = dist.join("index.html");
            let serve_dir = ServeDir::new(dist).fallback(ServeFile::new(index_file));
            router = router.fallback_service(serve_dir);
        }
    }

    router
}

pub fn discover_lan_urls(port: u16) -> Vec<String> {
    let mut urls = Vec::new();
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                let ip = local.ip();
                if !ip.is_loopback() {
                    urls.push(format!("http://{ip}:{port}"));
                }
            }
        }
    }
    urls.push(format!("http://127.0.0.1:{port}"));
    urls
}

pub struct RemoteServerController {
    enabled: bool,
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    auth: Arc<Mutex<AuthStore>>,
    active_ws_clients: Arc<AtomicUsize>,
    auth_epoch_tx: watch::Sender<u64>,
    db: Database,
    ring_buffer: SharedRingBuffer,
    kb: KnowledgeBase,
    ws_tx: broadcast::Sender<WsEnvelope>,
    status_provider: StatusProvider,
    static_dist_dir: Option<PathBuf>,
}

impl RemoteServerController {
    pub fn new(
        db: Database,
        ring_buffer: SharedRingBuffer,
        kb: KnowledgeBase,
        ws_tx: broadcast::Sender<WsEnvelope>,
        status_provider: StatusProvider,
        static_dist_dir: Option<PathBuf>,
    ) -> Self {
        let (auth_epoch_tx, _) = watch::channel(0_u64);
        Self {
            enabled: false,
            port: DEFAULT_REMOTE_PORT,
            shutdown_tx: None,
            auth: Arc::new(Mutex::new(AuthStore::new())),
            active_ws_clients: Arc::new(AtomicUsize::new(0)),
            auth_epoch_tx,
            db,
            ring_buffer,
            kb,
            ws_tx,
            status_provider,
            static_dist_dir,
        }
    }

    fn bump_auth_epoch(&self) {
        let next = self.auth_epoch_tx.borrow().saturating_add(1);
        let _ = self.auth_epoch_tx.send(next);
    }

    pub fn status(&self) -> RemoteServerStatus {
        let pin = if self.enabled {
            self.auth.lock().ok().map(|a| a.pin().to_string())
        } else {
            None
        };
        let lan_urls = if self.enabled {
            discover_lan_urls(self.port)
        } else {
            Vec::new()
        };
        RemoteServerStatus {
            enabled: self.enabled,
            port: self.port,
            lan_urls,
            pin,
            active_clients: self.active_ws_clients.load(Ordering::Relaxed),
        }
    }

    pub async fn start(&mut self, port: Option<u16>) -> Result<RemoteServerStatus, SentinelError> {
        if self.enabled {
            return Ok(self.status());
        }

        let target_port = port.unwrap_or(self.port);
        let addr = SocketAddr::from(([0, 0, 0, 0], target_port));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_port = listener.local_addr()?.port();

        if let Ok(mut auth) = self.auth.lock() {
            auth.regenerate_pin();
        }
        self.bump_auth_epoch();

        let api_state = RemoteApiState {
            db: self.db.clone(),
            ring_buffer: Arc::clone(&self.ring_buffer),
            kb: self.kb.clone(),
            auth: Arc::clone(&self.auth),
            ws_tx: self.ws_tx.clone(),
            status_provider: Arc::clone(&self.status_provider),
            active_ws_clients: Arc::clone(&self.active_ws_clients),
            auth_epoch_tx: self.auth_epoch_tx.clone(),
        };
        let app = build_router(api_state, self.static_dist_dir.clone());
        let (tx, rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(err) = server.await {
                tracing::error!(error = %err, "Axum LAN server stopped with error");
            }
        });

        self.port = bound_port;
        self.enabled = true;
        self.shutdown_tx = Some(tx);
        tracing::info!(port = bound_port, "Axum LAN remote server started");
        Ok(self.status())
    }

    pub fn stop(&mut self) -> RemoteServerStatus {
        self.bump_auth_epoch();
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.enabled = false;
        self.active_ws_clients.store(0, Ordering::Relaxed);
        tracing::info!("Axum LAN remote server stopped");
        self.status()
    }

    pub fn regenerate_pin(&mut self) -> Result<RemoteServerStatus, SentinelError> {
        self.auth
            .lock()
            .map_err(|_| SentinelError::Internal("auth mutex poisoned".to_string()))?
            .regenerate_pin();
        self.bump_auth_epoch();
        Ok(self.status())
    }
}

pub fn make_test_state(
    db: Database,
    ring_buffer: SharedRingBuffer,
) -> (RemoteApiState, String) {
    let auth = AuthStore::new();
    let pin = auth.pin().to_string();
    let (ws_tx, _) = broadcast::channel(64);
    let (auth_epoch_tx, _) = watch::channel(0_u64);
    let status_provider: StatusProvider = Arc::new(|| CollectorStatus {
        paused: false,
        uptime_secs: 42,
        ring_buffer_len: 1,
        event_watcher_active: true,
        is_elevated: false,
        health_status: crate::models::HealthStatus::Stable,
    });
    let kb = KnowledgeBase::from_embedded().unwrap_or_else(|_| {
        // Fallback impossible for embedded valid JSON, keeps signature clean without unwrap
        unreachable!()
    });
    let state = RemoteApiState {
        db,
        ring_buffer,
        kb,
        auth: Arc::new(Mutex::new(auth)),
        ws_tx,
        status_provider,
        active_ws_clients: Arc::new(AtomicUsize::new(0)),
        auth_epoch_tx,
    };
    (state, pin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::new_shared_ring_buffer;
    use axum::body::Body;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn cors_origin_validator_blocks_userinfo_bypass_and_external_hosts() {
        let valid = [
            "http://localhost:1420",
            "http://127.0.0.1:8420",
            "tauri://localhost",
            "http://192.168.1.42:8420",
            "http://10.0.0.5:8420",
        ];
        for o in valid {
            assert!(
                is_allowed_lan_origin(&HeaderValue::from_static(o)),
                "expected valid origin {o}"
            );
        }

        let malicious = [
            "http://127.0.0.1:80@evil.com",
            "http://192.168.1.10@evil.com",
            "https://evil.com",
            "http://localhost.evil.com",
            "http://8.8.8.8:8420",
            "http://localhost:1420/extra",
            "javascript:alert(1)",
        ];
        for o in malicious {
            assert!(
                !is_allowed_lan_origin(&HeaderValue::from_static(o)),
                "must reject malicious origin {o}"
            );
        }
    }

    #[tokio::test]
    async fn health_sets_security_headers_and_protected_routes_require_bearer_token() {
        let db = Database::open_in_memory().expect("db");
        let rb = new_shared_ring_buffer();
        let (state, _pin) = make_test_state(db, rb);
        let app = build_router(state, None);

        let health_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(health_res.status(), StatusCode::OK);
        assert_eq!(
            health_res.headers().get("x-content-type-options").and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            health_res.headers().get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY")
        );

        let unauth_res = app
            .oneshot(
                Request::builder()
                    .uri("/api/timeline")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_validates_pin_global_rate_limits_and_issues_single_use_ws_tickets() {
        let db = Database::open_in_memory().expect("db");
        let rb = new_shared_ring_buffer();
        let (state, _pin) = make_test_state(db, rb);
        let auth_ref = Arc::clone(&state.auth);
        let app = build_router(state, None);

        // Per-IP rate limit trips after 5 failures
        for attempt in 0..6 {
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/auth/login")
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"pin":"000000"}"#))
                        .expect("req"),
                )
                .await
                .expect("resp");
            if attempt < MAX_FAILED_ATTEMPTS_PER_IP {
                assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
            }
        }

        // Global rate limit trips across rotating IPs after 20 failures
        {
            let mut store = auth_ref.lock().expect("lock");
            store.regenerate_pin();
            for i in 0..MAX_GLOBAL_FAILED_ATTEMPTS {
                let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i + 10) as u8));
                assert!(matches!(
                    store.verify_pin(ip, "000000"),
                    Err(SentinelError::Unauthorized)
                ));
            }
            let next_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 250));
            assert!(matches!(
                store.verify_pin(next_ip, "000000"),
                Err(SentinelError::RateLimited)
            ));
        }

        // Valid login -> single-use WS ticket -> replay rejected
        let db2 = Database::open_in_memory().expect("db2");
        let rb2 = new_shared_ring_buffer();
        let (state2, pin2) = make_test_state(db2, rb2);
        let auth2 = Arc::clone(&state2.auth);
        let app2 = build_router(state2, None);

        let login_res = app2
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/login")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"pin":"{pin2}"}}"#)))
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(login_res.status(), StatusCode::OK);
        let bytes = login_res.into_body().collect().await.expect("body").to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let token = parsed["token"].as_str().expect("token");

        let ticket_res = app2
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/ws-ticket")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(ticket_res.status(), StatusCode::OK);
        let t_bytes = ticket_res.into_body().collect().await.expect("body").to_bytes();
        let t_parsed: serde_json::Value = serde_json::from_slice(&t_bytes).expect("json");
        let ticket = t_parsed["ticket"].as_str().expect("ticket");

        // Single-use ticket: first consume true, replay false
        {
            let mut store = auth2.lock().expect("lock");
            assert!(store.consume_ws_ticket(ticket));
            assert!(!store.consume_ws_ticket(ticket));
        }
    }

    #[tokio::test]
    async fn static_dir_never_exposes_parent_workspace_files() {
        let dir = std::env::temp_dir().join(format!("winpulse_dist_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("index.html"), "<html>ok</html>").expect("write");

        let db = Database::open_in_memory().expect("db");
        let rb = new_shared_ring_buffer();
        let (state, _) = make_test_state(db, rb);
        let app = build_router(state, Some(dir.clone()));

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/../Cargo.toml")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("resp");
        let body = res.into_body().collect().await.expect("body").to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("[workspace]"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn lan_router_never_exposes_ai_or_command_execution_routes() {
        let db = Database::open_in_memory().expect("db");
        let rb = new_shared_ring_buffer();
        let (state, pin) = make_test_state(db, rb);
        let app = build_router(state, None);

        let login_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/login")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"pin":"{pin}"}}"#)))
                    .expect("req"),
            )
            .await
            .expect("resp");
        let bytes = login_res.into_body().collect().await.expect("body").to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let token = parsed["token"].as_str().expect("token");

        for uri in ["/api/ai/diagnose", "/api/commands/execute", "/mcp"] {
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(uri)
                        .header(AUTHORIZATION, format!("Bearer {token}"))
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .expect("req"),
                )
                .await
                .expect("resp");
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "LAN route must not exist: {uri}");
        }
    }
}
