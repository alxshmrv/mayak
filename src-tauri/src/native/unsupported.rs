use crate::domain::PermissionState;
use crate::error::{AppError, AppResult};

use super::NativeWifiSnapshot;

pub fn wifi_snapshot() -> AppResult<NativeWifiSnapshot> {
    Err(AppError::Platform(
        "Эта операционная система пока не поддерживается".to_owned(),
    ))
}

pub fn request_location_permission() {}

pub fn location_permission_state() -> PermissionState {
    PermissionState::Unknown
}
