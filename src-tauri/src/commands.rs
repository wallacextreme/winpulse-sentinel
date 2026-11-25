use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tauri::State;
use tokio::sync::{broadcast, Mutex};

use crate::db::Database;
use crate::error::SentinelError;
use crate::eventlog::import_historical_events;
use crate::models::{
    CollectorStatus, HealthStatus, ImportHistoryResult, IncidentDetail, KnowledgeBaseEntry,
    RemoteServerStatus, TelemetrySample, TimelineItem, TimelineItemType, WsEnvelope,
};
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
