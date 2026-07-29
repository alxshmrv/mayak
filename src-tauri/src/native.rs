use serde::Deserialize;

use crate::domain::ChannelInfo;

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
    pub signal_quality: Option<u8>,
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
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{location_permission_state, request_location_permission, wifi_snapshot};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{location_permission_state, request_location_permission, wifi_snapshot};

#[cfg(not(any(target_os = "macos", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "macos", windows)))]
pub use unsupported::{location_permission_state, request_location_permission, wifi_snapshot};
