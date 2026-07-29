#![allow(
    unsafe_code,
    reason = "This module is the single reviewed FFI boundary to the Windows Native Wi-Fi API"
)]

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null_mut;
use std::slice;

use ::windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_DATA, HANDLE};
use ::windows::Win32::NetworkManagement::WiFi::{
    DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGO_WEP, DOT11_CIPHER_ALGO_WEP40, DOT11_CIPHER_ALGO_WEP104,
    DOT11_PHY_TYPE, WLAN_API_VERSION_2_0, WLAN_BSS_ENTRY, WLAN_BSS_LIST,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO, WLAN_INTERFACE_INFO_LIST, WlanCloseHandle,
    WlanEnumInterfaces, WlanFreeMemory, WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface,
    dot11_phy_type_dmg, dot11_phy_type_dsss, dot11_phy_type_eht, dot11_phy_type_erp,
    dot11_phy_type_fhss, dot11_phy_type_he, dot11_phy_type_hrdsss, dot11_phy_type_ht,
    dot11_phy_type_irbaseband, dot11_phy_type_ofdm, dot11_phy_type_vht,
    wlan_interface_state_connected, wlan_interface_state_not_ready,
    wlan_intf_opcode_channel_number, wlan_intf_opcode_current_connection,
};
use ::windows::core::GUID;

use crate::domain::{ChannelInfo, PermissionState};
use crate::error::{AppError, AppResult};

use super::NativeWifiSnapshot;

struct WlanHandle(HANDLE);

impl Drop for WlanHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live handle returned by `WlanOpenHandle` and is
        // closed exactly once here.
        unsafe {
            WlanCloseHandle(self.0, None);
        }
    }
}

struct WlanMemory(*mut c_void);

impl Drop for WlanMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Native Wi-Fi allocated this block and documents
            // `WlanFreeMemory` as its matching release function.
            unsafe { WlanFreeMemory(self.0) };
        }
    }
}

struct WifiObservation {
    snapshot: NativeWifiSnapshot,
    metadata_access_denied: bool,
}

pub fn wifi_snapshot() -> AppResult<NativeWifiSnapshot> {
    observe_wifi().map(|observation| observation.snapshot)
}

pub fn request_location_permission() {
    // Querying the current WLAN connection is the Microsoft-documented point
    // at which Windows can show the one-time location consent prompt.
    let _ = observe_wifi();
}

pub fn location_permission_state() -> PermissionState {
    match observe_wifi() {
        Ok(observation) if observation.metadata_access_denied => PermissionState::Denied,
        Ok(observation)
            if observation.snapshot.ssid.is_some() || observation.snapshot.bssid.is_some() =>
        {
            PermissionState::Allowed
        }
        Ok(_) => PermissionState::Unknown,
        Err(_) => PermissionState::Unknown,
    }
}

fn observe_wifi() -> AppResult<WifiObservation> {
    let handle = open_wlan_handle()?;
    let (interfaces, _interface_memory) = enumerate_interfaces(&handle)?;
    let available = !interfaces.is_empty();
    let connected = interfaces
        .iter()
        .find(|interface| interface.isState == wlan_interface_state_connected);
    let power_on = interfaces
        .iter()
        .any(|interface| interface.isState != wlan_interface_state_not_ready);

    let Some(interface) = connected else {
        return Ok(WifiObservation {
            snapshot: empty_snapshot(available, power_on, interfaces.first().map(interface_id)),
            metadata_access_denied: false,
        });
    };

    let interface_name = Some(interface_id(interface));
    let connection = match query_interface::<WLAN_CONNECTION_ATTRIBUTES>(
        &handle,
        &interface.InterfaceGuid,
        wlan_intf_opcode_current_connection,
    ) {
        Ok(value) => value,
        Err(code) if code == ERROR_ACCESS_DENIED.0 => {
            return Ok(WifiObservation {
                snapshot: empty_snapshot(true, true, interface_name),
                metadata_access_denied: true,
            });
        }
        Err(code) => {
            return Err(AppError::Platform(format!(
                "Windows Native Wi-Fi вернул ошибку {code} при чтении подключения"
            )));
        }
    };

    let association = connection.wlanAssociationAttributes;
    let security_attributes = connection.wlanSecurityAttributes;
    let bss = current_bss(&handle, &interface.InterfaceGuid, &connection);
    let quality = association.wlanSignalQuality.min(100);
    let signal_quality = u8::try_from(quality).ok();
    let approximate_rssi = i64::from(bss.map_or_else(
        || i32::try_from(quality / 2).unwrap_or_default() - 100,
        |entry| entry.lRssi,
    ));
    let channel_number = query_interface::<u32>(
        &handle,
        &interface.InterfaceGuid,
        wlan_intf_opcode_channel_number,
    )
    .ok()
    .and_then(|value| u16::try_from(value).ok());
    let center_frequency_mhz = bss.map(|entry| entry.ulChCenterFrequency / 1_000);

    Ok(WifiObservation {
        snapshot: NativeWifiSnapshot {
            available: true,
            interface_name,
            power_on: true,
            ssid: ssid(&association.dot11Ssid),
            bssid: mac_address(&association.dot11Bssid),
            rssi: approximate_rssi,
            noise: 0,
            signal_quality,
            transmit_rate: f64::from(association.ulTxRate) / 1_000.0,
            country_code: None,
            security: security_name(
                security_attributes.bSecurityEnabled.as_bool(),
                security_attributes.dot11AuthAlgorithm,
                security_attributes.dot11CipherAlgorithm,
            ),
            phy_mode: phy_mode(association.dot11PhyType).map(str::to_owned),
            channel: channel_number.map(|number| ChannelInfo {
                number,
                band: channel_band(center_frequency_mhz, number).to_owned(),
                width: "не определена".to_owned(),
            }),
        },
        metadata_access_denied: false,
    })
}

fn empty_snapshot(
    available: bool,
    power_on: bool,
    interface_name: Option<String>,
) -> NativeWifiSnapshot {
    NativeWifiSnapshot {
        available,
        interface_name,
        power_on,
        ssid: None,
        bssid: None,
        rssi: 0,
        noise: 0,
        signal_quality: None,
        transmit_rate: 0.0,
        country_code: None,
        security: "unknown".to_owned(),
        phy_mode: None,
        channel: None,
    }
}

fn open_wlan_handle() -> AppResult<WlanHandle> {
    let mut negotiated_version = 0;
    let mut handle = HANDLE::default();
    // SAFETY: All output pointers refer to initialized local storage, and no
    // reserved parameter is supplied.
    let code = unsafe {
        WlanOpenHandle(
            WLAN_API_VERSION_2_0,
            None,
            &mut negotiated_version,
            &mut handle,
        )
    };
    if code == 0 {
        Ok(WlanHandle(handle))
    } else {
        Err(AppError::Platform(format!(
            "Windows Native Wi-Fi недоступен: ошибка {code}"
        )))
    }
}

fn enumerate_interfaces(handle: &WlanHandle) -> AppResult<(Vec<WLAN_INTERFACE_INFO>, WlanMemory)> {
    let mut pointer = null_mut::<WLAN_INTERFACE_INFO_LIST>();
    // SAFETY: `pointer` is a valid output location. The returned allocation is
    // immediately placed under `WlanMemory` ownership.
    let code = unsafe { WlanEnumInterfaces(handle.0, None, &mut pointer) };
    if code != 0 {
        return Err(AppError::Platform(format!(
            "Не удалось перечислить Wi‑Fi-интерфейсы Windows: ошибка {code}"
        )));
    }
    let memory = WlanMemory(pointer.cast());
    if pointer.is_null() {
        return Ok((Vec::new(), memory));
    }

    // SAFETY: `pointer` references the variable-length list returned by
    // `WlanEnumInterfaces`; its count defines the initialized trailing array.
    let list = unsafe { &*pointer };
    let count = usize::try_from(list.dwNumberOfItems).unwrap_or_default();
    // SAFETY: Native Wi-Fi guarantees `dwNumberOfItems` contiguous entries
    // beginning at `InterfaceInfo`.
    let interfaces = unsafe { slice::from_raw_parts(list.InterfaceInfo.as_ptr(), count) }.to_vec();
    Ok((interfaces, memory))
}

fn query_interface<T: Copy>(
    handle: &WlanHandle,
    interface_guid: &GUID,
    opcode: ::windows::Win32::NetworkManagement::WiFi::WLAN_INTF_OPCODE,
) -> Result<T, u32> {
    let mut size = 0;
    let mut pointer = null_mut::<c_void>();
    // SAFETY: Output size and pointer are valid local storage. The allocation
    // is owned by Native Wi-Fi and released before this function returns.
    let code = unsafe {
        WlanQueryInterface(
            handle.0,
            interface_guid,
            opcode,
            None,
            &mut size,
            &mut pointer,
            None,
        )
    };
    if code != 0 {
        return Err(code);
    }
    let _memory = WlanMemory(pointer);
    if pointer.is_null() || usize::try_from(size).unwrap_or_default() < size_of::<T>() {
        return Err(ERROR_INVALID_DATA.0);
    }

    // SAFETY: The API reported at least `size_of::<T>()` initialized bytes for
    // the requested opcode and keeps them alive through `_memory`.
    Ok(unsafe { pointer.cast::<T>().read() })
}

fn current_bss(
    handle: &WlanHandle,
    interface_guid: &GUID,
    connection: &WLAN_CONNECTION_ATTRIBUTES,
) -> Option<WLAN_BSS_ENTRY> {
    let association = &connection.wlanAssociationAttributes;
    let mut pointer = null_mut::<WLAN_BSS_LIST>();
    // SAFETY: The connection attributes and output pointer are valid for the
    // duration of the call. Returned memory is released by `WlanMemory`.
    let code = unsafe {
        WlanGetNetworkBssList(
            handle.0,
            interface_guid,
            Some(&association.dot11Ssid),
            association.dot11BssType,
            connection.wlanSecurityAttributes.bSecurityEnabled.as_bool(),
            None,
            &mut pointer,
        )
    };
    if code != 0 || pointer.is_null() {
        return None;
    }
    let _memory = WlanMemory(pointer.cast());
    // SAFETY: The pointer is non-null and was returned as a complete
    // variable-length `WLAN_BSS_LIST`.
    let list = unsafe { &*pointer };
    let count = usize::try_from(list.dwNumberOfItems).ok()?;
    // SAFETY: The API guarantees `dwNumberOfItems` contiguous BSS entries.
    let entries = unsafe { slice::from_raw_parts(list.wlanBssEntries.as_ptr(), count) };
    entries
        .iter()
        .copied()
        .find(|entry| entry.dot11Bssid == association.dot11Bssid)
}

fn interface_id(interface: &WLAN_INTERFACE_INFO) -> String {
    let guid = interface.InterfaceGuid;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

fn ssid(value: &::windows::Win32::NetworkManagement::WiFi::DOT11_SSID) -> Option<String> {
    let length = usize::try_from(value.uSSIDLength)
        .unwrap_or_default()
        .min(value.ucSSID.len());
    let bytes = &value.ucSSID[..length];
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned())
}

fn mac_address(value: &[u8; 6]) -> Option<String> {
    value.iter().any(|octet| *octet != 0).then(|| {
        value
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

fn security_name(
    enabled: bool,
    authentication: DOT11_AUTH_ALGORITHM,
    cipher: ::windows::Win32::NetworkManagement::WiFi::DOT11_CIPHER_ALGORITHM,
) -> String {
    if !enabled {
        return "open".to_owned();
    }
    if matches!(
        cipher,
        DOT11_CIPHER_ALGO_WEP | DOT11_CIPHER_ALGO_WEP40 | DOT11_CIPHER_ALGO_WEP104
    ) {
        return "wep".to_owned();
    }
    match authentication.0 {
        1 => "open",
        2 => "wep",
        3 => "wpa-enterprise",
        4 => "wpa-personal",
        5 => "wpa-personal",
        6 => "wpa2-enterprise",
        7 => "wpa2-personal",
        8 | 11 => "wpa3-enterprise",
        9 => "wpa3-personal",
        10 => "owe",
        _ => "unknown",
    }
    .to_owned()
}

fn phy_mode(value: DOT11_PHY_TYPE) -> Option<&'static str> {
    match value {
        value if value == dot11_phy_type_fhss => Some("802.11 FHSS"),
        value if value == dot11_phy_type_dsss || value == dot11_phy_type_hrdsss => Some("802.11b"),
        value if value == dot11_phy_type_irbaseband => Some("802.11 IR"),
        value if value == dot11_phy_type_ofdm => Some("802.11a"),
        value if value == dot11_phy_type_erp => Some("802.11g"),
        value if value == dot11_phy_type_ht => Some("802.11n / Wi‑Fi 4"),
        value if value == dot11_phy_type_vht => Some("802.11ac / Wi‑Fi 5"),
        value if value == dot11_phy_type_he => Some("802.11ax / Wi‑Fi 6"),
        value if value == dot11_phy_type_eht => Some("802.11be / Wi‑Fi 7"),
        value if value == dot11_phy_type_dmg => Some("802.11ad"),
        _ => None,
    }
}

fn channel_band(center_frequency_mhz: Option<u32>, channel: u16) -> &'static str {
    match center_frequency_mhz {
        Some(frequency) if (2_400..=2_500).contains(&frequency) => "2,4 ГГц",
        Some(frequency) if (5_000..=5_900).contains(&frequency) => "5 ГГц",
        Some(frequency) if (5_925..=7_125).contains(&frequency) => "6 ГГц",
        _ if channel <= 14 => "2,4 ГГц",
        _ => "не определён",
    }
}

#[cfg(test)]
mod tests {
    use super::{channel_band, mac_address, security_name};
    use ::windows::Win32::NetworkManagement::WiFi::{
        DOT11_AUTH_ALGO_RSNA_PSK, DOT11_AUTH_ALGO_WPA, DOT11_AUTH_ALGO_WPA3_SAE,
        DOT11_CIPHER_ALGO_CCMP,
    };

    #[test]
    fn maps_windows_security_modes() {
        assert_eq!(
            security_name(true, DOT11_AUTH_ALGO_RSNA_PSK, DOT11_CIPHER_ALGO_CCMP),
            "wpa2-personal"
        );
        assert_eq!(
            security_name(true, DOT11_AUTH_ALGO_WPA3_SAE, DOT11_CIPHER_ALGO_CCMP),
            "wpa3-personal"
        );
        assert_eq!(
            security_name(true, DOT11_AUTH_ALGO_WPA, DOT11_CIPHER_ALGO_CCMP),
            "wpa-enterprise"
        );
    }

    #[test]
    fn formats_bssid_and_band() {
        assert_eq!(
            mac_address(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]).as_deref(),
            Some("10:20:30:40:50:60")
        );
        assert_eq!(channel_band(Some(5_180), 36), "5 ГГц");
        assert_eq!(channel_band(Some(5_955), 1), "6 ГГц");
    }
}
