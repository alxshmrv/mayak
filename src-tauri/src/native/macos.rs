#![allow(
    unsafe_code,
    reason = "This module is the single reviewed FFI boundary to the CoreWLAN Objective-C bridge"
)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use crate::domain::PermissionState;
use crate::error::{AppError, AppResult};

use super::NativeWifiSnapshot;

unsafe extern "C" {
    fn mayak_copy_wifi_json() -> *mut c_char;
    fn mayak_free_string(value: *mut c_char);
    fn mayak_request_location_permission();
    fn mayak_location_authorization_status() -> c_int;
}

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

pub fn request_location_permission() {
    // SAFETY: The bridge takes no pointers and schedules the CoreLocation
    // request on the main dispatch queue.
    unsafe { mayak_request_location_permission() };
}

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
