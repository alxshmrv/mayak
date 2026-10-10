#![allow(
    clippy::needless_pass_by_value,
    reason = "Tauri commands deserialize owned parameters and require State extractors by value"
)]

use std::sync::Arc;

use tauri::plugin::PermissionState as PluginPermissionState;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::mpsc;

use crate::domain::{
    AppSettings, AppSnapshot, HistoryEntry, PermissionState, PermissionStatus, ScanMode,
    ScanReport, TrustState,
};
use crate::engine::ScanEngine;
use crate::i18n::Language;
use crate::native;
use crate::network::collect_network_context;
use crate::platform;
use crate::storage::Storage;

pub struct AppState {
    pub storage: Arc<Storage>,
    pub engine: Arc<ScanEngine>,
}

impl AppState {
    /// The interface language from saved settings, or the system language.
    pub fn language(&self) -> Language {
        self.storage.settings().map_or_else(
            |_| Language::system(),
            |settings| settings.language.resolve(),
        )
    }
}

#[tauri::command]
pub async fn get_app_snapshot(state: State<'_, AppState>) -> Result<AppSnapshot, String> {
    let language = state.language();
    let network = tokio::task::spawn_blocking(collect_network_context)
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.message(language))?;
    let latest_report = state
        .storage
        .latest_report()
        .map_err(|error| error.message(language))?;
    let local_network = latest_report
        .as_ref()
        .map_or(PermissionState::NotDetermined, |report| {
            let coverage = &report.coverage;
            let has_local_network_evidence = coverage.mdns_count > 0
                || coverage.ssdp_count > 0
                || coverage.onvif_count > 0
                || coverage.arp_count > 1
                || coverage.responsive_count > 1;
            if has_local_network_evidence {
                PermissionState::Allowed
            } else {
                // Neither supported desktop platform exposes a reliable,
                // cross-version Local Network permission state. A scan with no
                // peers is therefore inconclusive: the network may be isolated,
                // empty, or permission may be denied.
                PermissionState::Unknown
            }
        });
    let settings = state
        .storage
        .settings()
        .map_err(|error| error.message(language))?;

    Ok(AppSnapshot {
        network,
        permissions: PermissionStatus {
            location: native::location_permission_state(),
            local_network,
        },
        latest_report,
        settings,
        system_language: Language::system(),
    })
}

#[tauri::command]
pub async fn run_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: Option<ScanMode>,
) -> Result<ScanReport, String> {
    let mode = mode.unwrap_or_else(|| {
        state
            .storage
            .settings()
            .map_or(ScanMode::Safe, |settings| settings.default_scan_mode)
    });
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let progress_app = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(progress) = receiver.recv().await {
            let _ = progress_app.emit("scan-progress", progress);
        }
    });

    let language = state.language();
    let report = Box::pin(state.engine.scan(mode, language, Some(sender)))
        .await
        .map_err(|error| error.message(language))?;
    let _ = app.emit("scan-complete", &report);
    Ok(report)
}

#[tauri::command]
pub fn get_history(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<HistoryEntry>, String> {
    state
        .storage
        .history(limit.unwrap_or(50))
        .map_err(|error| error.message(state.language()))
}

#[tauri::command]
pub fn get_report(state: State<'_, AppState>, id: String) -> Result<Option<ScanReport>, String> {
    state
        .storage
        .report(&id)
        .map_err(|error| error.message(state.language()))
}

#[tauri::command]
pub fn save_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: AppSettings,
) -> Result<AppSettings, String> {
    let interval = settings.monitoring_interval_seconds.clamp(60, 86_400);
    let sanitized = AppSettings {
        monitoring_interval_seconds: interval,
        ..settings
    };
    let language = sanitized.language.resolve();
    state
        .storage
        .save_settings(&sanitized)
        .map_err(|error| error.message(language))?;
    crate::apply_language(&app, language);
    Ok(sanitized)
}

#[tauri::command]
pub fn set_device_trust(
    state: State<'_, AppState>,
    network_id: String,
    identity_key: String,
    trust_state: TrustState,
) -> Result<(), String> {
    state
        .storage
        .set_device_trust(&network_id, &identity_key, trust_state)
        .map_err(|error| error.message(state.language()))
}

#[tauri::command]
pub fn request_location_permission() -> PermissionStatus {
    native::request_location_permission();
    PermissionStatus {
        location: native::location_permission_state(),
        local_network: PermissionState::NotDetermined,
    }
}

#[tauri::command]
pub fn request_notification_permission(app: AppHandle) -> Result<bool, String> {
    let notifications = app.notification();
    let state = notifications
        .permission_state()
        .map_err(|error| error.to_string())?;
    let state = if state == PluginPermissionState::Prompt {
        notifications
            .request_permission()
            .map_err(|error| error.to_string())?
    } else {
        state
    };
    Ok(state == PluginPermissionState::Granted)
}

#[tauri::command]
pub fn open_privacy_settings(state: State<'_, AppState>, section: String) -> Result<(), String> {
    platform::open_privacy_settings(&section).map_err(|error| {
        tracing::warn!("privacy settings not opened: {error}");
        state
            .language()
            .pick(
                "Не удалось открыть системные настройки. Откройте их вручную.",
                "Couldn't open system settings. Please open them manually.",
            )
            .to_owned()
    })
}
