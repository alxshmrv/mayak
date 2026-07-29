#![allow(
    unsafe_code,
    reason = "This module is the single reviewed FFI boundary to the CoreWLAN Objective-C bridge"
)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use serde::Deserialize;

use crate::domain::{ChannelInfo, PermissionState};
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeWifiSnapshot {
    pub available: bool,
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub power_on: bool,
    #[serde(default)]
    pub ssid: Option<String>,
    #[serde(default)]
    pub bssid: Option<String>,
    #[serde(default)]
    pub rssi: i64,
    #[serde(default)]
    pub noise: i64,
    #[serde(default)]
    pub transmit_rate: f64,
    #[serde(default)]
    pub country_code: Option<String>,
    #[serde(default = "unknown")]
    pub security: String,
    #[serde(default)]
    pub phy_mode: Option<String>,
    #[serde(default)]
    pub channel: Option<ChannelInfo>,
}

fn unknown() -> String {
    "unknown".to_owned()
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mayak_copy_wifi_json() -> *mut c_char;
    fn mayak_free_string(value: *mut c_char);
    fn mayak_request_location_permission();
    fn mayak_location_authorization_status() -> c_int;
}

#[cfg(target_os = "macos")]
pub fn wifi_snapshot() -> AppResult<NativeWifiSnapshot> {
    // SAFETY: The Objective-C bridge returns either null or a heap-allocated,
    // NUL-terminated UTF-8 JSON string owned by the caller.
    let pointer = unsafe { mayak_copy_wifi_json() };
    if pointer.is_null() {
        return Err(AppError::Platform(
            "CoreWLAN не вернул данные Wi‑Fi".to_owned(),
        ));
    }

    // SAFETY: `pointer` was checked for null and the bridge guarantees a
    // NUL-terminated byte string that stays valid until `mayak_free_string`.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec();

    // SAFETY: The pointer was allocated by `mayak_copy_wifi_json`, has not
    // been freed yet, and is released exactly once by its matching function.
    unsafe { mayak_free_string(pointer) };

    let value = serde_json::from_slice(&bytes)?;
    Ok(value)
}

#[cfg(not(target_os = "macos"))]
pub fn wifi_snapshot() -> AppResult<NativeWifiSnapshot> {
    Err(AppError::Platform(
        "CoreWLAN доступен только на macOS".to_owned(),
    ))
}

#[cfg(target_os = "macos")]
pub fn request_location_permission() {
    // SAFETY: The bridge takes no pointers and schedules the CoreLocation
    // request on the main dispatch queue.
    unsafe { mayak_request_location_permission() };
}

#[cfg(not(target_os = "macos"))]
pub fn request_location_permission() {}

#[cfg(target_os = "macos")]
pub fn location_permission_state() -> PermissionState {
    // SAFETY: The bridge returns a scalar CLAuthorizationStatus value.
    match unsafe { mayak_location_authorization_status() } {
        0 => PermissionState::NotDetermined,
        1 => PermissionState::Restricted,
        2 => PermissionState::Denied,
        3 | 4 => PermissionState::Allowed,
        _ => PermissionState::Unknown,
    }
}

#[cfg(not(target_os = "macos"))]
pub fn location_permission_state() -> PermissionState {
    PermissionState::Unknown
}
