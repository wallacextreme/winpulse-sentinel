use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tauri::{AppHandle, Emitter, State};
use tokio::sync::{broadcast, Mutex};

use crate::ai::{
    probe_ollama as run_ollama_probe, run_diagnosis, validate_ollama_url, DEFAULT_AI_PROXY_URL,
    DEFAULT_OLLAMA_URL,
};
use crate::db::Database;
use crate::error::SentinelError;
use crate::eventlog::import_historical_events;
use crate::executor::ExecutionCoordinator;
use crate::mcp::McpServerController;
use crate::models::{
    AiDiagnosisResponse, AiProviderKind, AiSettings, CollectorStatus, CommandAuditEntry,
    CommandExecutionResult, CommandShell, CommandSource, DiagnoseRequest, HealthStatus,
    ImportHistoryResult, IncidentDetail, KnowledgeBaseEntry, McpServerStatus, OllamaProbeResult,
    RemoteServerStatus, SaveAiSettingsInput, StagedCommandTicket, TelemetrySample, TimelineItem,
    TimelineItemType, WsEnvelope,
};
use crate::sanitizer::sanitize_truncated;
use crate::secrets::{mask_secret, SecretStore, GEMINI_BYOK_TARGET};
use crate::server::RemoteServerController;
use crate::telemetry::SharedRingBuffer;
use crate::translator::KnowledgeBase;

pub struct AppState {
    pub db: Database,
    pub ring_buffer: SharedRingBuffer,
    pub kb: KnowledgeBase,
    pub paused: Arc<AtomicBool>,
    pub started_at: Instant,
    pub event_watcher_active: Arc<AtomicBool>,
    pub is_elevated: bool,
    pub ws_tx: broadcast::Sender<WsEnvelope>,
    pub remote_server: Arc<Mutex<RemoteServerController>>,
    pub executor: ExecutionCoordinator,
    pub secret_store: Arc<dyn SecretStore>,
    pub mcp_server: Arc<Mutex<McpServerController>>,
}

impl AppState {
    pub fn build_collector_status(&self) -> CollectorStatus {
        let (ring_len, health_status) = match self.ring_buffer.read() {
            Ok(guard) => {
                let health = guard
                    .latest()
                    .map(|s| s.health_status)
                    .unwrap_or(HealthStatus::Stable);
                (guard.len(), health)
            }
            Err(_) => (0, HealthStatus::Stable),
        };

        CollectorStatus {
            paused: self.paused.load(Ordering::Relaxed),
            uptime_secs: self.started_at.elapsed().as_secs(),
            ring_buffer_len: ring_len,
            event_watcher_active: self.event_watcher_active.load(Ordering::Relaxed),
            is_elevated: self.is_elevated,
            health_status,
        }
    }
}

#[tauri::command]
pub fn health_check() -> &'static str {
    "ok"
}

#[tauri::command]
pub fn get_collector_status(state: State<'_, AppState>) -> CollectorStatus {
    state.build_collector_status()
}

#[tauri::command]
pub fn get_recent_telemetry(
    state: State<'_, AppState>,
) -> Result<Vec<TelemetrySample>, SentinelError> {
    let guard = state
        .ring_buffer
        .read()
        .map_err(|_| SentinelError::Internal("ring buffer lock poisoned".to_string()))?;
    Ok(guard.as_vec())
}

#[tauri::command]
pub fn get_timeline(
    state: State<'_, AppState>,
    limit: Option<u32>,
    offset: Option<u32>,
    category: Option<String>,
    severity: Option<String>,
) -> Result<Vec<TimelineItem>, SentinelError> {
    state.db.get_timeline(
        limit.unwrap_or(100).min(500),
        offset.unwrap_or(0),
        category.as_deref(),
        severity.as_deref(),
    )
}

#[tauri::command]
pub fn get_incident_detail(
    state: State<'_, AppState>,
    item_type: String,
    id: i64,
) -> Result<IncidentDetail, SentinelError> {
    let parsed_type = match item_type.trim().to_ascii_lowercase().as_str() {
        "event" => TimelineItemType::Event,
        "snapshot" => TimelineItemType::Snapshot,
        _ => {
            return Err(SentinelError::InvalidInput(
                "item_type must be 'event' or 'snapshot'".to_string(),
            ))
        }
    };

    state
        .db
        .get_incident_detail(parsed_type, id)?
        .ok_or_else(|| SentinelError::NotFound(format!("{item_type} {id} not found")))
}

#[tauri::command]
pub fn set_collection_paused(
    state: State<'_, AppState>,
    paused: bool,
) -> Result<CollectorStatus, SentinelError> {
    state.paused.store(paused, Ordering::Relaxed);
    let _ = state
        .db
        .set_setting("collector_paused", if paused { "true" } else { "false" });
    let status = state.build_collector_status();
    let _ = state.ws_tx.send(WsEnvelope::Status(status.clone()));
    Ok(status)
}

#[tauri::command]
pub async fn get_remote_server_status(
    state: State<'_, AppState>,
) -> Result<RemoteServerStatus, SentinelError> {
    let controller = state.remote_server.lock().await;
    Ok(controller.status())
}

pub fn validate_remote_port(port: Option<u16>) -> Result<Option<u16>, SentinelError> {
    if let Some(p) = port {
        if p < 1024 {
            return Err(SentinelError::InvalidInput(
                "remote server port must be between 1024 and 65535".to_string(),
            ));
        }
    }
    Ok(port)
}

#[tauri::command]
pub async fn toggle_remote_server(
    state: State<'_, AppState>,
    enabled: bool,
    port: Option<u16>,
) -> Result<RemoteServerStatus, SentinelError> {
    let valid_port = validate_remote_port(port)?;
    let mut controller = state.remote_server.lock().await;
    if enabled {
        controller.start(valid_port).await
    } else {
        Ok(controller.stop())
    }
}

#[tauri::command]
pub async fn regenerate_remote_pin(
    state: State<'_, AppState>,
) -> Result<RemoteServerStatus, SentinelError> {
    let mut controller = state.remote_server.lock().await;
    controller.regenerate_pin()
}

#[tauri::command]
pub async fn import_windows_history(
    state: State<'_, AppState>,
    days: Option<u32>,
) -> Result<ImportHistoryResult, SentinelError> {
    let db = state.db.clone();
    let rb = Arc::clone(&state.ring_buffer);
    let kb = state.kb.clone();
    let lookback_days = days.unwrap_or(30).clamp(1, 90);

    tokio::task::spawn_blocking(move || {
        import_historical_events(&db, &rb, &kb, lookback_days, 250)
    })
    .await
    .map_err(|err| SentinelError::Internal(format!("history import task failed: {err}")))?
}

#[tauri::command]
pub fn get_knowledge_base(state: State<'_, AppState>) -> Vec<KnowledgeBaseEntry> {
    state.kb.catalog()
}

impl AppState {
    pub fn load_ai_settings(&self) -> Result<AiSettings, SentinelError> {
        let provider = self
            .db
            .get_setting("ai_provider")?
            .map(|v| AiProviderKind::from_str_lossy(&v))
            .unwrap_or(AiProviderKind::CloudProxy);
        let ollama_url = self
            .db
            .get_setting("ai_ollama_url")?
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_OLLAMA_URL.to_string());
        let ollama_model = self
            .db
            .get_setting("ai_ollama_model")?
            .unwrap_or_default();
        let existing_key = self.secret_store.get_secret(GEMINI_BYOK_TARGET)?;

        Ok(AiSettings {
            provider,
            ollama_url,
            ollama_model,
            has_byok_key: existing_key.is_some(),
            masked_byok_key: existing_key.as_deref().map(mask_secret),
            proxy_url: DEFAULT_AI_PROXY_URL.to_string(),
        })
    }

    fn build_incident_diagnose_request(
        &self,
        item_type: &str,
        id: i64,
        execution_feedback: Option<String>,
    ) -> Result<(String, DiagnoseRequest), SentinelError> {
        let parsed_type = match item_type.trim().to_ascii_lowercase().as_str() {
            "event" => TimelineItemType::Event,
            "snapshot" => TimelineItemType::Snapshot,
            _ => {
                return Err(SentinelError::InvalidInput(
                    "item_type must be 'event' or 'snapshot'".to_string(),
                ))
            }
        };

        let detail = self
            .db
            .get_incident_detail(parsed_type, id)?
            .ok_or_else(|| SentinelError::NotFound(format!("{item_type} {id} not found")))?;

        let uid = format!("{}-{}", item_type.trim().to_ascii_lowercase(), id);
        let mut summary_parts = Vec::new();
        let mut event_id = None;
        let mut provider_name = None;
        let mut channel = None;
        let mut raw_xml = None;

        if let Some(ev) = &detail.event {
            event_id = Some(ev.event_id);
            provider_name = Some(ev.provider_name.clone());
            channel = Some(ev.channel.clone());
            raw_xml = Some(ev.raw_xml.clone());
            summary_parts.push(format!(
                "{} (Event ID {}, Provider {}): {}",
                ev.friendly_title, ev.event_id, ev.provider_name, ev.what_happened
            ));
        }

        if let Some(snap) = &detail.snapshot {
            let procs: Vec<String> = snap
                .top_processes
                .iter()
                .take(3)
                .map(|p| {
                    format!(
                        "{} (CPU {:.1}%, RAM {:.0}MB)",
                        p.name, p.cpu_percent, p.memory_mb
                    )
                })
                .collect();
            summary_parts.push(format!(
                "Gargalo {}: pico {:.1} por {}s. CPU {:.1}%, RAM {:.1}%, Disco {:.1}% ({:.1}ms). Processos: {}",
                snap.violated_metric.label_pt(),
                snap.peak_value,
                snap.duration_secs,
                snap.cpu_percent,
                snap.ram_percent,
                snap.disk_active_percent,
                snap.disk_latency_ms,
                procs.join(", ")
            ));
        }

        if let Some(note) = &detail.diagnostic_note {
            summary_parts.push(format!("Correlação: {note}"));
        }

        let telemetry_context = self
            .ring_buffer
            .read()
            .ok()
            .and_then(|g| g.latest())
            .map(|s| {
                format!(
                    "Telemetria atual: CPU {:.1}%, RAM {:.1}% ({:.1}GB livres), Disco {:.1}% ({:.1}ms), Rede RX {:.0}/TX {:.0} kbps",
                    s.cpu_percent,
                    s.ram_percent,
                    s.ram_free_gb,
                    s.disk_active_percent,
                    s.disk_latency_ms,
                    s.net_rx_kbps,
                    s.net_tx_kbps
                )
            });

        let req = DiagnoseRequest {
            incident_summary: sanitize_truncated(&summary_parts.join(" | "), 3800),
            event_id,
            provider_name,
            channel,
            sanitized_xml: raw_xml.as_deref().map(|x| sanitize_truncated(x, 7800)),
            telemetry_context,
            execution_feedback: execution_feedback
                .as_deref()
                .map(|f| sanitize_truncated(f, 3800)),
        };
        Ok((uid, req))
    }
}

#[tauri::command]
pub fn get_ai_settings(state: State<'_, AppState>) -> Result<AiSettings, SentinelError> {
    state.load_ai_settings()
}

#[tauri::command]
pub fn save_ai_settings(
    state: State<'_, AppState>,
    input: SaveAiSettingsInput,
) -> Result<AiSettings, SentinelError> {
    state
        .db
        .set_setting("ai_provider", input.provider.as_str())?;
    if let Some(url) = input.ollama_url {
        let valid = validate_ollama_url(&url)?;
        state.db.set_setting("ai_ollama_url", &valid)?;
    }
    if let Some(model) = input.ollama_model {
        state.db.set_setting("ai_ollama_model", model.trim())?;
    }
    state.load_ai_settings()
}

#[tauri::command]
pub fn set_byok_api_key(
    state: State<'_, AppState>,
    api_key: String,
) -> Result<AiSettings, SentinelError> {
    let trimmed = api_key.trim();
    if trimmed.len() < 12 || trimmed.len() > 256 {
        return Err(SentinelError::InvalidInput(
            "chave de API inválida".to_string(),
        ));
    }
    state.secret_store.set_secret(GEMINI_BYOK_TARGET, trimmed)?;
    state.load_ai_settings()
}

#[tauri::command]
pub fn clear_byok_api_key(state: State<'_, AppState>) -> Result<AiSettings, SentinelError> {
    state.secret_store.delete_secret(GEMINI_BYOK_TARGET)?;
    state.load_ai_settings()
}

#[tauri::command]
pub async fn probe_ollama(
    state: State<'_, AppState>,
    base_url: Option<String>,
) -> Result<OllamaProbeResult, SentinelError> {
    let settings = state.load_ai_settings()?;
    let url = base_url.unwrap_or(settings.ollama_url);
    let selected = if settings.ollama_model.is_empty() {
        None
    } else {
        Some(settings.ollama_model.as_str())
    };
    Ok(run_ollama_probe(&url, selected).await)
}

#[tauri::command]
pub fn preview_sanitized_incident(
    state: State<'_, AppState>,
    item_type: String,
    id: i64,
) -> Result<DiagnoseRequest, SentinelError> {
    let (_uid, req) = state.build_incident_diagnose_request(&item_type, id, None)?;
    Ok(req)
}

#[tauri::command]
pub async fn analyze_incident_with_ai(
    state: State<'_, AppState>,
    item_type: String,
    id: i64,
    execution_feedback: Option<String>,
) -> Result<AiDiagnosisResponse, SentinelError> {
    let (uid, req) =
        state.build_incident_diagnose_request(&item_type, id, execution_feedback)?;
    let settings = state.load_ai_settings()?;
    let byok = if settings.provider == AiProviderKind::GeminiByok {
        state.secret_store.get_secret(GEMINI_BYOK_TARGET)?
    } else {
        None
    };
    let resp = run_diagnosis(&settings, byok.as_deref(), &req).await?;
    let _ = state
        .db
        .save_ai_diagnosis(&uid, &resp.provider_used, &resp.model_used, &resp);
    Ok(resp)
}

#[tauri::command]
pub async fn analyze_error_text_with_ai(
    state: State<'_, AppState>,
    error_text: String,
    execution_feedback: Option<String>,
) -> Result<AiDiagnosisResponse, SentinelError> {
    let settings = state.load_ai_settings()?;
    let byok = if settings.provider == AiProviderKind::GeminiByok {
        state.secret_store.get_secret(GEMINI_BYOK_TARGET)?
    } else {
        None
    };
    let req = DiagnoseRequest {
        incident_summary: sanitize_truncated(&error_text, 3800),
        event_id: None,
        provider_name: None,
        channel: None,
        sanitized_xml: None,
        telemetry_context: None,
        execution_feedback: execution_feedback
            .as_deref()
            .map(|f| sanitize_truncated(f, 3800)),
    };
    run_diagnosis(&settings, byok.as_deref(), &req).await
}

#[tauri::command]
pub fn stage_command_execution(
    state: State<'_, AppState>,
    source: CommandSource,
    shell: CommandShell,
    command: String,
    rationale: String,
    requires_admin: bool,
) -> Result<StagedCommandTicket, SentinelError> {
    state
        .executor
        .stage_command(source, shell, &command, &rationale, requires_admin)
}

#[tauri::command]
pub async fn approve_command_execution(
    app: AppHandle,
    state: State<'_, AppState>,
    approval_id: String,
    expected_command: String,
    timeout_secs: Option<u64>,
) -> Result<CommandExecutionResult, SentinelError> {
    state
        .executor
        .approve_and_execute(&approval_id, &expected_command, timeout_secs, move |ev| {
            let _ = app.emit("sentinel://command-output", &ev);
        })
        .await
}

#[tauri::command]
pub fn reject_command_execution(
    state: State<'_, AppState>,
    approval_id: String,
) -> Result<(), SentinelError> {
    state.executor.reject_command(&approval_id)
}

#[tauri::command]
pub fn cancel_command_execution(
    state: State<'_, AppState>,
    approval_id: String,
) -> Result<bool, SentinelError> {
    state.executor.cancel_running(&approval_id)
}

#[tauri::command]
pub fn get_command_audit_log(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Vec<CommandAuditEntry>, SentinelError> {
    state.db.list_command_audit_log(limit.unwrap_or(50))
}

#[tauri::command]
pub async fn get_mcp_status(
    state: State<'_, AppState>,
) -> Result<McpServerStatus, SentinelError> {
    let controller = state.mcp_server.lock().await;
    Ok(controller.status())
}

#[tauri::command]
pub async fn toggle_mcp_server(
    state: State<'_, AppState>,
    enabled: bool,
    port: Option<u16>,
) -> Result<McpServerStatus, SentinelError> {
    let mut controller = state.mcp_server.lock().await;
    let status = if enabled {
        let started = controller.start(port).await?;
        let _ = state.db.set_setting("mcp_enabled", "true");
        let _ = state.db.set_setting("mcp_port", &started.port.to_string());
        started
    } else {
        let stopped = controller.stop();
        let _ = state.db.set_setting("mcp_enabled", "false");
        stopped
    };
    Ok(status)
}

#[tauri::command]
pub async fn rotate_mcp_token(
    state: State<'_, AppState>,
) -> Result<McpServerStatus, SentinelError> {
    let mut controller = state.mcp_server.lock().await;
    controller.rotate_token()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_privileged_remote_ports() {
        assert!(validate_remote_port(Some(80)).is_err());
        assert!(validate_remote_port(Some(443)).is_err());
        assert!(validate_remote_port(Some(1023)).is_err());
        assert_eq!(validate_remote_port(Some(8420)).expect("ok"), Some(8420));
        assert_eq!(validate_remote_port(None).expect("ok"), None);
    }
}
