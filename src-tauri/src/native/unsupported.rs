use crate::domain::PermissionState;
use crate::error::{AppError, AppResult};

use super::NativeWifiSnapshot;

pub fn wifi_snapshot() -> AppResult<NativeWifiSnapshot> {
    Err(AppError::Platform(
        "This operating system is not supported yet".to_owned(),
    ))
}

pub fn request_location_permission() {}

pub fn location_permission_state() -> PermissionState {
    PermissionState::Unknown
}
