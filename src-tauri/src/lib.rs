pub mod ai;
pub mod commands;
pub mod correlator;
pub mod db;
pub mod error;
pub mod eventlog;
pub mod executor;
pub mod mcp;
pub mod models;
pub mod sanitizer;
pub mod secrets;
pub mod server;
pub mod telemetry;
pub mod translator;
pub mod tray;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tauri::{Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::{broadcast, Mutex};
use tracing_subscriber::EnvFilter;

use commands::AppState;
use db::Database;
use eventlog::{import_historical_events, is_process_elevated, spawn_eventlog_watcher, EventLogWatcher};
use executor::ExecutionCoordinator;
use mcp::{ApprovalCallback, McpServerController};
use models::{HealthStatus, Severity, WsEnvelope};
use secrets::default_secret_store;
use server::{RemoteServerController, StatusProvider};
use telemetry::{new_shared_ring_buffer, spawn_telemetry_loop};
use translator::KnowledgeBase;

struct WatcherHandleGuard {
    _watcher: Option<EventLogWatcher>,
}

fn resolve_db_path(app: &tauri::App) -> PathBuf {
    match app.path().app_data_dir() {
        Ok(dir) => dir.join("winpulse_sentinel.db"),
        Err(_) => std::env::temp_dir()
            .join("winpulse-sentinel")
            .join("winpulse_sentinel.db"),
    }
}

fn resolve_kb_override(app: &tauri::App) -> Option<PathBuf> {
    app.path()
        .app_data_dir()
        .ok()
        .map(|d| d.join("knowledge_base.json"))
}

fn resolve_static_dist_dir(app: &tauri::App) -> Option<PathBuf> {
    if let Ok(res_dir) = app.path().resource_dir() {
        let candidate = res_dir.join("dist");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    let dev_dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist");
    if dev_dist.is_dir() {
        Some(dev_dist)
    } else {
        None
    }
}

pub fn run() -> Result<(), tauri::Error> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("winpulse_sentinel=info,warn")),
        )
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let db_path = resolve_db_path(app);
            let db = Database::open(&db_path)?;

            let kb_override = resolve_kb_override(app);
            let kb = KnowledgeBase::load_with_override(kb_override.as_deref())?;

            let ring_buffer = new_shared_ring_buffer();
            let initial_paused = db
                .get_setting("collector_paused")
                .ok()
                .flatten()
                .map(|v| v == "true")
                .unwrap_or(false);
            let paused = Arc::new(AtomicBool::new(initial_paused));
            let event_watcher_active = Arc::new(AtomicBool::new(false));
            let is_elevated = is_process_elevated();
            let started_at = Instant::now();
            let (ws_tx, _) = broadcast::channel::<WsEnvelope>(256);

            let status_rb = Arc::clone(&ring_buffer);
            let status_paused = Arc::clone(&paused);
            let status_watcher = Arc::clone(&event_watcher_active);
            let status_provider: StatusProvider = Arc::new(move || {
                let (ring_len, health) = match status_rb.read() {
                    Ok(g) => (
                        g.len(),
                        g.latest()
                            .map(|s| s.health_status)
                            .unwrap_or(HealthStatus::Stable),
                    ),
                    Err(_) => (0, HealthStatus::Stable),
                };
                models::CollectorStatus {
                    paused: status_paused.load(Ordering::Relaxed),
                    uptime_secs: started_at.elapsed().as_secs(),
                    ring_buffer_len: ring_len,
                    event_watcher_active: status_watcher.load(Ordering::Relaxed),
                    is_elevated,
                    health_status: health,
                }
            });

            let static_dist = resolve_static_dist_dir(app);
            let remote_server = Arc::new(Mutex::new(RemoteServerController::new(
                db.clone(),
                Arc::clone(&ring_buffer),
                kb.clone(),
                ws_tx.clone(),
                Arc::clone(&status_provider),
                static_dist,
            )));

            let executor = ExecutionCoordinator::new(db.clone());
            let secret_store = default_secret_store();
            let app_data_dir = app.path().app_data_dir().ok();
            let approval_handle = app.handle().clone();
            let on_approval_requested: ApprovalCallback = Arc::new(move |ticket| {
                let _ = approval_handle.emit("sentinel://approval-requested", &ticket);
            });
            let mcp_server = Arc::new(Mutex::new(McpServerController::new(
                db.clone(),
                Arc::clone(&ring_buffer),
                kb.clone(),
                status_provider,
                executor.clone(),
                app_data_dir,
                on_approval_requested,
            )));

            let mcp_auto_enabled = db
                .get_setting("mcp_enabled")
                .ok()
                .flatten()
                .map(|v| v != "false")
                .unwrap_or(true);
            let mcp_saved_port = db
                .get_setting("mcp_port")
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u16>().ok());
            if mcp_auto_enabled {
                let mcp_boot = Arc::clone(&mcp_server);
                tauri::async_runtime::spawn(async move {
                    let mut controller = mcp_boot.lock().await;
                    if let Err(err) = controller.start(mcp_saved_port).await {
                        tracing::warn!(error = %err, "Failed to auto-start MCP loopback server");
                    }
                });
            }

            app.manage(AppState {
                db: db.clone(),
                ring_buffer: Arc::clone(&ring_buffer),
                kb: kb.clone(),
                paused: Arc::clone(&paused),
                started_at,
                event_watcher_active: Arc::clone(&event_watcher_active),
                is_elevated,
                ws_tx: ws_tx.clone(),
                remote_server,
                executor,
                secret_store,
                mcp_server,
            });

            // Forward telemetry broadcasts to Tauri frontend events
            let handle_tel = app.handle().clone();
            let mut tel_rx = ws_tx.subscribe();
            tauri::async_runtime::spawn(async move {
                loop {
                    match tel_rx.recv().await {
                        Ok(WsEnvelope::Telemetry(sample)) => {
                            let _ = handle_tel.emit("sentinel://telemetry", &sample);
                        }
                        Ok(WsEnvelope::Snapshot(snap)) => {
                            let _ = handle_tel.emit("sentinel://snapshot", &snap);
                        }
                        Ok(WsEnvelope::WindowsEvent(ev)) => {
                            let _ = handle_tel.emit("sentinel://event", &ev);
                        }
                        Ok(WsEnvelope::Status(st)) => {
                            let _ = handle_tel.emit("sentinel://status", &st);
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            });

            // Start Module A telemetry loop inside Tauri async runtime
            let db_tel = db.clone();
            let rb_tel = Arc::clone(&ring_buffer);
            let paused_tel = Arc::clone(&paused);
            let ws_tel = ws_tx.clone();
            let handle_snap = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                spawn_telemetry_loop(db_tel, rb_tel, paused_tel, ws_tel, move |snap| {
                    if snap.severity == Severity::Critical {
                        let _ = handle_snap
                            .notification()
                            .builder()
                            .title(format!(
                                "WinPulse Sentinel — Pico Crítico ({})",
                                snap.violated_metric.label_pt()
                            ))
                            .body(format!(
                                "Pico de {:.1} sustentado por {}s",
                                snap.peak_value, snap.duration_secs
                            ))
                            .show();
                    }
                });
            });

            // Auto-import last 30 days of Windows history on first launch if DB has no events yet
            let db_hist = db.clone();
            let rb_hist = Arc::clone(&ring_buffer);
            let kb_hist = kb.clone();
            let handle_hist = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if !db_hist.has_any_events().unwrap_or(true) {
                    let res = tokio::task::spawn_blocking(move || {
                        import_historical_events(&db_hist, &rb_hist, &kb_hist, 30, 150)
                    })
                    .await;
                    if let Ok(Ok(summary)) = res {
                        tracing::info!(
                            imported = summary.imported,
                            scanned = summary.scanned,
                            "Initial 30-day Windows Event Log import completed"
                        );
                        let _ = handle_hist.emit("sentinel://history-imported", &summary);
                    }
                }
            });

            // Start Module B real-time Windows Event Log watcher
            let handle_evt = app.handle().clone();
            let db_evt = db;
            let rb_evt = ring_buffer;
            let paused_evt = paused;
            let active_evt = event_watcher_active;
            let ws_evt = ws_tx;
            let watcher = tauri::async_runtime::block_on(async move {
                spawn_eventlog_watcher(
                    db_evt,
                    rb_evt,
                    kb,
                    paused_evt,
                    active_evt,
                    ws_evt,
                    move |record| {
                        if record.severity == Severity::Critical {
                            let _ = handle_evt
                                .notification()
                                .builder()
                                .title(format!("WinPulse Sentinel — {}", record.category))
                                .body(record.friendly_title.clone())
                                .show();
                        }
                    },
                )
            });

            app.manage(WatcherHandleGuard { _watcher: watcher });
            tray::setup_system_tray(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::health_check,
            commands::get_collector_status,
            commands::get_recent_telemetry,
            commands::get_timeline,
            commands::get_incident_detail,
            commands::set_collection_paused,
            commands::get_remote_server_status,
            commands::toggle_remote_server,
            commands::regenerate_remote_pin,
            commands::import_windows_history,
            commands::get_knowledge_base,
            commands::get_ai_settings,
            commands::save_ai_settings,
            commands::set_byok_api_key,
            commands::clear_byok_api_key,
            commands::probe_ollama,
            commands::preview_sanitized_incident,
            commands::analyze_incident_with_ai,
            commands::analyze_error_text_with_ai,
            commands::stage_command_execution,
            commands::approve_command_execution,
            commands::reject_command_execution,
            commands::cancel_command_execution,
            commands::get_command_audit_log,
            commands::get_mcp_status,
            commands::toggle_mcp_server,
            commands::rotate_mcp_token,
        ])
        .run(tauri::generate_context!())
}
