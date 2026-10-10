mod commands;
mod discovery;
mod domain;
mod engine;
mod error;
mod fingerprint;
mod i18n;
mod native;
mod network;
mod platform;
mod risk;
mod storage;
mod vendor;

use std::sync::Arc;
use std::time::{Duration, Instant};

use commands::AppState;
use engine::ScanEngine;
use i18n::Language;
use tauri::menu::{MenuBuilder, MenuItem, MenuItemBuilder};
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

            let language = storage.settings().map_or_else(
                |_| Language::system(),
                |settings| settings.language.resolve(),
            );
            configure_tray(app, language)?;
            apply_language(app.handle(), language);
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
        .expect("Mayak could not start the user interface");
}

const TRAY_ID: &str = "main";

struct TrayMenu {
    open: MenuItem<tauri::Wry>,
    scan: MenuItem<tauri::Wry>,
    quit: MenuItem<tauri::Wry>,
}

fn app_name(language: Language) -> &'static str {
    language.pick("Маяк", "Mayak")
}

fn tray_labels(language: Language) -> [&'static str; 3] {
    match language {
        Language::Ru => ["Открыть Маяк", "Быстрая проверка", "Завершить"],
        Language::En => ["Open Mayak", "Quick check", "Quit"],
    }
}

/// Renames the window, tray tooltip, and tray menu to match the interface language.
pub(crate) fn apply_language(app: &tauri::AppHandle, language: Language) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_title(app_name(language));
    }
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(app_name(language)));
    }
    if let Some(menu) = app.try_state::<TrayMenu>() {
        let [open, scan, quit] = tray_labels(language);
        let _ = menu.open.set_text(open);
        let _ = menu.scan.set_text(scan);
        let _ = menu.quit.set_text(quit);
    }
}

fn configure_tray(app: &mut tauri::App, language: Language) -> tauri::Result<()> {
    let [open_label, scan_label, quit_label] = tray_labels(language);
    let open = MenuItemBuilder::with_id("open", open_label).build(app)?;
    let scan = MenuItemBuilder::with_id("scan", scan_label).build(app)?;
    let quit = MenuItemBuilder::with_id("quit", quit_label).build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&open, &scan, &quit])
        .build()?;
    app.manage(TrayMenu { open, scan, quit });

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip(app_name(language))
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
            let language = settings.language.resolve();
            match Box::pin(engine.scan(settings.default_scan_mode, language, None)).await {
                Ok(report) => {
                    notify_for_report(&app, &settings, &report, language);
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
    language: Language,
) {
    let network_name = report.network.ssid.as_deref().unwrap_or("Wi-Fi");
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
        Some(match language {
            Language::Ru => format!("В сети «{network_name}» новых устройств: {new_devices}"),
            Language::En => format!("New devices on “{network_name}”: {new_devices}"),
        })
    } else if settings.notify_network_changes && network_changed {
        Some(match language {
            Language::Ru => format!(
                "Изменились параметры сети «{network_name}». Откройте Маяк, чтобы сверить детали."
            ),
            Language::En => format!(
                "Settings of “{network_name}” have changed. Open Mayak to review the details."
            ),
        })
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
    if let Err(error) = notifications
        .builder()
        .title(app_name(language))
        .body(body)
        .show()
    {
        tracing::warn!("notification skipped: {error}");
    }
}
