use std::sync::atomic::Ordering;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::commands::AppState;
use crate::models::WsEnvelope;

const MENU_OPEN: &str = "tray_open";
const MENU_TOGGLE_PAUSE: &str = "tray_toggle_pause";
const MENU_TOGGLE_REMOTE: &str = "tray_toggle_remote";
const MENU_QUIT: &str = "tray_quit";

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub fn setup_system_tray(app: &tauri::App) -> Result<(), tauri::Error> {
    let initial_paused = app
        .try_state::<AppState>()
        .map(|s| s.paused.load(Ordering::Relaxed))
        .unwrap_or(false);

    let open_item = MenuItem::with_id(
        app,
        MENU_OPEN,
        "Abrir WinPulse Sentinel",
        true,
        None::<&str>,
    )?;
    let pause_label = if initial_paused {
        "Retomar Coleta"
    } else {
        "Pausar Coleta"
    };
    let pause_item = MenuItem::with_id(app, MENU_TOGGLE_PAUSE, pause_label, true, None::<&str>)?;
    let remote_item = MenuItem::with_id(
        app,
        MENU_TOGGLE_REMOTE,
        "Ativar Modo Remoto PWA (LAN)",
        true,
        None::<&str>,
    )?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(app, MENU_QUIT, "Sair", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &open_item,
            &pause_item,
            &remote_item,
            &separator,
            &quit_item,
        ],
    )?;

    let mut builder = TrayIconBuilder::with_id("main-tray")
        .tooltip("WinPulse Sentinel — Monitoramento Ativo")
        .menu(&menu)
        .show_menu_on_left_click(false);

    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }

    let pause_item_handle = pause_item.clone();
    let remote_item_handle = remote_item.clone();

    builder
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .on_menu_event(move |app_handle, event| match event.id().as_ref() {
            MENU_OPEN => {
                show_main_window(app_handle);
            }
            MENU_TOGGLE_PAUSE => {
                if let Some(state) = app_handle.try_state::<AppState>() {
                    let was_paused = state.paused.load(Ordering::Relaxed);
                    let next_paused = !was_paused;
                    state.paused.store(next_paused, Ordering::Relaxed);
                    let _ = state.db.set_setting(
                        "collector_paused",
                        if next_paused { "true" } else { "false" },
                    );
                    let label = if next_paused {
                        "Retomar Coleta"
                    } else {
                        "Pausar Coleta"
                    };
                    let _ = pause_item_handle.set_text(label);
                    let status = state.build_collector_status();
                    let _ = state.ws_tx.send(WsEnvelope::Status(status.clone()));
                    let _ = app_handle.emit("sentinel://status", &status);
                }
            }
            MENU_TOGGLE_REMOTE => {
                let app_clone = app_handle.clone();
                let remote_label_item = remote_item_handle.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(state) = app_clone.try_state::<AppState>() {
                        let mut controller = state.remote_server.lock().await;
                        let currently_enabled = controller.status().enabled;
                        let res = if currently_enabled {
                            Ok(controller.stop())
                        } else {
                            controller.start(None).await
                        };
                        match res {
                            Ok(status) => {
                                let text = if status.enabled {
                                    "Desativar Modo Remoto PWA"
                                } else {
                                    "Ativar Modo Remoto PWA (LAN)"
                                };
                                let _ = remote_label_item.set_text(text);
                                let _ = app_clone.emit("sentinel://remote-status", &status);

                                if status.enabled {
                                    let url = status
                                        .lan_urls
                                        .first()
                                        .cloned()
                                        .unwrap_or_else(|| format!("http://127.0.0.1:{}", status.port));
                                    let pin = status.pin.unwrap_or_else(|| "------".to_string());
                                    let _ = app_clone
                                        .notification()
                                        .builder()
                                        .title("WinPulse Sentinel — Modo Remoto PWA")
                                        .body(format!("Acesse {url} | PIN: {pin}"))
                                        .show();
                                }
                            }
                            Err(err) => {
                                tracing::error!(error = %err, "Tray remote server toggle failed");
                            }
                        }
                    }
                });
            }
            MENU_QUIT => {
                let app_clone = app_handle.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(state) = app_clone.try_state::<AppState>() {
                        let mut controller = state.remote_server.lock().await;
                        if controller.status().enabled {
                            let _ = controller.stop();
                        }
                    }
                    app_clone.exit(0);
                });
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}
