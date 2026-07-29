mod commands;
mod discovery;
mod domain;
mod engine;
mod error;
mod fingerprint;
mod native;
mod network;
mod platform;
mod risk;
mod storage;

use std::sync::Arc;
use std::time::{Duration, Instant};

use commands::AppState;
use engine::ScanEngine;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::plugin::PermissionState;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WindowEvent};
use tauri_plugin_notification::NotificationExt;

/// Starts the native application runtime, local storage, tray, and background monitor.
///
/// # Panics
///
/// Panics if Tauri cannot initialize or run the main application event loop.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mayak=info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let database_path = app
                .path()
                .app_data_dir()
                .map_err(|error| error.to_string())?
                .join("mayak.sqlite3");
            let storage = Arc::new(
                storage::Storage::open(&database_path).map_err(|error| error.to_string())?,
            );
            let engine = Arc::new(ScanEngine::new(Arc::clone(&storage)));
            app.manage(AppState {
                storage: Arc::clone(&storage),
                engine: Arc::clone(&engine),
            });

            configure_tray(app)?;
            start_background_monitor(app.handle().clone(), storage, engine);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_snapshot,
            commands::run_scan,
            commands::get_history,
            commands::get_report,
            commands::save_settings,
            commands::set_device_trust,
            commands::request_location_permission,
            commands::request_notification_permission,
            commands::open_privacy_settings,
        ])
        .run(tauri::generate_context!())
        .expect("Маяк не смог запустить интерфейс");
}

fn configure_tray<R: tauri::Runtime>(app: &mut tauri::App<R>) -> tauri::Result<()> {
    let open = MenuItemBuilder::with_id("open", "Открыть Маяк").build(app)?;
    let scan = MenuItemBuilder::with_id("scan", "Быстрая проверка").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Завершить").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&open, &scan, &quit])
        .build()?;

    let mut builder = TrayIconBuilder::new()
        .tooltip("Маяк")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            "scan" => {
                show_main_window(app);
                let _ = app.emit("tray-scan-requested", ());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

fn show_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn start_background_monitor(
    app: tauri::AppHandle,
    storage: Arc<storage::Storage>,
    engine: Arc<ScanEngine>,
) {
    tauri::async_runtime::spawn(async move {
        let mut last_scan = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let Ok(settings) = storage.settings() else {
                continue;
            };
            if !settings.background_monitoring
                || last_scan.elapsed() < Duration::from_secs(settings.monitoring_interval_seconds)
            {
                continue;
            }
            last_scan = Instant::now();
            match Box::pin(engine.scan(settings.default_scan_mode, None)).await {
                Ok(report) => {
                    notify_for_report(&app, &settings, &report);
                    let _ = app.emit("monitor-report", report);
                }
                Err(error) => {
                    tracing::warn!("background scan skipped: {error}");
                }
            }
        }
    });
}

fn notify_for_report(
    app: &tauri::AppHandle,
    settings: &domain::AppSettings,
    report: &domain::ScanReport,
) {
    let new_devices = report
        .devices
        .iter()
        .filter(|device| device.is_unreviewed_new() && device.kind != domain::DeviceKind::Router)
        .count();
    let network_changed = report
        .assessment
        .findings
        .iter()
        .any(|finding| finding.category == "change");
    let body = if settings.notify_new_devices && new_devices > 0 {
        Some(format!(
            "В сети «{}» новых устройств: {new_devices}",
            report.network.ssid.as_deref().unwrap_or("Wi-Fi")
        ))
    } else if settings.notify_network_changes && network_changed {
        Some(format!(
            "Изменились параметры сети «{}». Откройте Маяк, чтобы сверить детали.",
            report.network.ssid.as_deref().unwrap_or("Wi-Fi")
        ))
    } else {
        None
    };

    let Some(body) = body else {
        return;
    };
    let notifications = app.notification();
    if notifications.permission_state().ok() != Some(PermissionState::Granted) {
        return;
    }
    if let Err(error) = notifications.builder().title("Маяк").body(body).show() {
        tracing::warn!("notification skipped: {error}");
    }
}
