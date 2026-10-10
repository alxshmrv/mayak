use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::i18n::{Language, LanguagePreference};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelInfo {
    pub number: u16,
    pub band: String,
    pub width: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "This serializable snapshot intentionally mirrors independent operating-system network facts"
)]
pub struct NetworkContext {
    pub connected: bool,
    pub wifi_available: bool,
    pub interface_name: Option<String>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub security: String,
    pub phy_mode: Option<String>,
    pub channel: Option<ChannelInfo>,
    pub rssi: Option<i64>,
    pub noise: Option<i64>,
    pub signal_quality: Option<u8>,
    pub transmit_rate_mbps: Option<f64>,
    pub country_code: Option<String>,
    #[serde(default)]
    pub local_mac_address: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Vec<String>,
    pub subnet: Option<String>,
    pub router: Option<String>,
    pub dns_servers: Vec<String>,
    pub proxy_enabled: bool,
    pub vpn_active: bool,
    pub network_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionState {
    NotDetermined,
    Allowed,
    Denied,
    Restricted,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PermissionStatus {
    pub location: PermissionState,
    pub local_network: PermissionState,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    #[default]
    Safe,
    Deep,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Good,
    Warning,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VisibilityLevel {
    Limited,
    Partial,
    Good,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub recommendation: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub risk: Severity,
    pub visibility: VisibilityLevel,
    pub confidence: Confidence,
    pub summary: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEvidence {
    pub protocol: String,
    pub name: String,
    pub service_type: Option<String>,
    pub port: Option<u16>,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DeviceKind {
    Router,
    Computer,
    Phone,
    Tablet,
    Printer,
    Media,
    SmartHome,
    Camera,
    PossibleCamera,
    NetworkEquipment,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TrustState {
    #[default]
    Unknown,
    Mine,
    Known,
    Ignored,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObservedDevice {
    pub identity_key: String,
    pub display_name: String,
    pub kind: DeviceKind,
    pub type_confidence: Confidence,
    pub ip_addresses: Vec<String>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub hostnames: Vec<String>,
    pub open_ports: Vec<u16>,
    pub services: Vec<ServiceEvidence>,
    pub evidence: Vec<String>,
    pub trust_state: TrustState,
    pub is_new: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub response_time_ms: Option<u64>,
    pub findings: Vec<Finding>,
}

impl ObservedDevice {
    pub fn is_unreviewed_new(&self) -> bool {
        self.is_new && self.trust_state == TrustState::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanCoverage {
    pub target_count: usize,
    pub responsive_count: usize,
    pub arp_count: usize,
    pub mdns_count: usize,
    pub ssdp_count: usize,
    pub onvif_count: usize,
    pub methods: Vec<String>,
    pub limited_by_subnet_size: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub mode: ScanMode,
    pub network: NetworkContext,
    pub devices: Vec<ObservedDevice>,
    pub assessment: Assessment,
    pub coverage: ScanCoverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: String,
    pub completed_at: DateTime<Utc>,
    pub ssid: Option<String>,
    pub security: String,
    pub risk: Severity,
    pub visibility: VisibilityLevel,
    pub device_count: usize,
    pub new_device_count: usize,
    pub mode: ScanMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub background_monitoring: bool,
    pub monitoring_interval_seconds: u64,
    pub default_scan_mode: ScanMode,
    pub notify_new_devices: bool,
    pub notify_network_changes: bool,
    #[serde(default)]
    pub language: LanguagePreference,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            background_monitoring: true,
            monitoring_interval_seconds: 300,
            default_scan_mode: ScanMode::Safe,
            notify_new_devices: false,
            notify_network_changes: false,
            language: LanguagePreference::System,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppSnapshot {
    pub network: NetworkContext,
    pub permissions: PermissionStatus,
    pub latest_report: Option<ScanReport>,
    pub settings: AppSettings,
    pub system_language: Language,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub phase: String,
    pub title: String,
    pub detail: String,
    pub completed: usize,
    pub total: usize,
}
