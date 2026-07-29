use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::domain::{
    Confidence, DeviceKind, Finding, ObservedDevice, ServiceEvidence, Severity, TrustState,
};

#[derive(Debug, Clone)]
pub struct RawDevice {
    pub ip: Ipv4Addr,
    pub mac_address: Option<String>,
    pub hostnames: BTreeSet<String>,
    pub open_ports: BTreeSet<u16>,
    pub services: Vec<ServiceEvidence>,
    pub evidence: BTreeSet<String>,
    pub response_time_ms: Option<u64>,
    pub is_router: bool,
    pub is_local_mac: bool,
    pub onvif: bool,
}

impl RawDevice {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            mac_address: None,
            hostnames: BTreeSet::new(),
            open_ports: BTreeSet::new(),
            services: Vec::new(),
            evidence: BTreeSet::new(),
            response_time_ms: None,
            is_router: false,
            is_local_mac: false,
            onvif: false,
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.mac_address = self.mac_address.take().or(other.mac_address);
        self.hostnames.extend(other.hostnames);
        self.open_ports.extend(other.open_ports);
        for service in other.services {
            if !self.services.iter().any(|existing| {
                existing.protocol == service.protocol
                    && existing.name == service.name
                    && existing.port == service.port
            }) {
                self.services.push(service);
            }
        }
        self.evidence.extend(other.evidence);
        self.response_time_ms = match (self.response_time_ms, other.response_time_ms) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        };
        self.is_router |= other.is_router;
        self.is_local_mac |= other.is_local_mac;
        self.onvif |= other.onvif;
    }
}

pub fn finalize_device(raw: RawDevice, observed_at: DateTime<Utc>) -> ObservedDevice {
    let mac_address = raw.mac_address.as_deref().map(normalize_mac);
    let vendor = mac_address.as_deref().and_then(vendor_for_mac);
    let (kind, type_confidence) = infer_kind(&raw, vendor.as_deref());
    let display_name = display_name(&raw, kind, vendor.as_deref());
    let identity_key = identity_key(&raw, mac_address.as_deref());
    let findings = device_findings(&raw, kind, vendor.as_deref());

    ObservedDevice {
        identity_key,
        display_name,
        kind,
        type_confidence,
        ip_addresses: vec![raw.ip.to_string()],
        mac_address,
        vendor,
        hostnames: raw.hostnames.into_iter().collect(),
        open_ports: raw.open_ports.into_iter().collect(),
        services: raw.services,
        evidence: raw.evidence.into_iter().collect(),
        trust_state: if raw.is_local_mac {
            TrustState::Mine
        } else {
            TrustState::Unknown
        },
        is_new: !raw.is_local_mac,
        first_seen: observed_at,
        last_seen: observed_at,
        response_time_ms: raw.response_time_ms,
        findings,
    }
}

fn identity_key(raw: &RawDevice, mac: Option<&str>) -> String {
    if raw.is_local_mac {
        return format!("local:{}", raw.ip);
    }
    if let Some(mac) = mac {
        return format!("mac:{mac}");
    }

    let mut hasher = Sha256::new();
    hasher.update(raw.ip.octets());
    for hostname in &raw.hostnames {
        hasher.update(hostname.as_bytes());
        hasher.update([0]);
    }
    for service in &raw.services {
        hasher.update(service.protocol.as_bytes());
        hasher.update(service.name.as_bytes());
        hasher.update(service.port.unwrap_or_default().to_be_bytes());
    }
    format!("observed:{:x}", hasher.finalize())[..29].to_owned()
}

fn display_name(raw: &RawDevice, kind: DeviceKind, vendor: Option<&str>) -> String {
    if raw.is_local_mac {
        return "Этот Mac".to_owned();
    }
    if let Some(hostname) = raw.hostnames.iter().next() {
        return clean_hostname(hostname);
    }
    if raw.is_router {
        return "Шлюз сети".to_owned();
    }
    if let Some(service) = raw
        .services
        .iter()
        .find(|service| service.protocol == "mdns" && !service.name.trim().is_empty())
    {
        return clean_hostname(&service.name);
    }
    if let Some(vendor) = vendor {
        return format!("{vendor} · {}", kind_label(kind));
    }
    kind_label(kind).to_owned()
}

fn clean_hostname(value: &str) -> String {
    value
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .replace("\\032", " ")
}

fn infer_kind(raw: &RawDevice, vendor: Option<&str>) -> (DeviceKind, Confidence) {
    let service_text = raw
        .services
        .iter()
        .flat_map(|item| {
            [
                item.protocol.as_str(),
                item.name.as_str(),
                item.service_type.as_deref().unwrap_or_default(),
            ]
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let hostname_text = raw
        .hostnames
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let vendor_lower = vendor.unwrap_or_default().to_ascii_lowercase();

    if raw.is_router {
        return (DeviceKind::Router, Confidence::High);
    }
    if raw.is_local_mac {
        return (DeviceKind::Computer, Confidence::High);
    }
    if raw.onvif {
        return (DeviceKind::Camera, Confidence::High);
    }
    if contains_any(
        &service_text,
        &["_ipp.", "_ipps.", "_printer.", "_scanner."],
    ) || raw.open_ports.contains(&9100)
    {
        return (DeviceKind::Printer, Confidence::High);
    }
    if contains_any(
        &service_text,
        &["_airplay.", "_raop.", "_googlecast.", "plex"],
    ) || raw.open_ports.contains(&32400)
    {
        return (DeviceKind::Media, Confidence::High);
    }
    if contains_any(&service_text, &["_hap.", "homekit"]) {
        return (DeviceKind::SmartHome, Confidence::High);
    }
    if let Some(kind) = infer_kind_from_hostname(&hostname_text) {
        return (kind, Confidence::Medium);
    }
    if raw.open_ports.contains(&554) {
        let confidence = if contains_any(
            &vendor_lower,
            &["hikvision", "dahua", "axis", "reolink", "ezviz", "imou"],
        ) {
            Confidence::High
        } else {
            Confidence::Medium
        };
        return (DeviceKind::PossibleCamera, confidence);
    }
    if contains_any(
        &vendor_lower,
        &[
            "ubiquiti", "mikrotik", "tp-link", "netgear", "aruba", "cisco",
        ],
    ) {
        return (DeviceKind::NetworkEquipment, Confidence::Medium);
    }
    if contains_any(&service_text, &["_workstation.", "_ssh.", "_smb."])
        || raw.open_ports.contains(&22)
        || raw.open_ports.contains(&445)
    {
        return (DeviceKind::Computer, Confidence::Medium);
    }

    (DeviceKind::Unknown, Confidence::Low)
}

fn infer_kind_from_hostname(hostname: &str) -> Option<DeviceKind> {
    if contains_any(
        hostname,
        &["iphone", "android", "pixel", "galaxy-phone", "phone"],
    ) {
        return Some(DeviceKind::Phone);
    }
    if contains_any(hostname, &["ipad", "tablet"]) {
        return Some(DeviceKind::Tablet);
    }
    if contains_any(
        hostname,
        &[
            "washer",
            "dryer",
            "fridge",
            "thermostat",
            "vacuum",
            "roborock",
            "smart-plug",
            "smartplug",
        ],
    ) {
        return Some(DeviceKind::SmartHome);
    }
    contains_any(
        hostname,
        &[
            "desktop",
            "laptop",
            "macbook",
            "imac",
            "workstation",
            "notebook",
        ],
    )
    .then_some(DeviceKind::Computer)
}

fn device_findings(raw: &RawDevice, kind: DeviceKind, vendor: Option<&str>) -> Vec<Finding> {
    match kind {
        DeviceKind::Camera => vec![Finding {
            id: format!("camera-onvif-{}", raw.ip),
            category: "device".to_owned(),
            severity: Severity::High,
            title: "Камера подтверждена протоколом".to_owned(),
            description: "Устройство ответило на стандартный ONVIF/WS-Discovery запрос для сетевого видео.".to_owned(),
            recommendation: Some(
                "Проверьте владельца и расположение устройства. Маяк не подключался к видеопотоку и не выполнял авторизацию.".to_owned(),
            ),
            evidence: vec![
                "ONVIF NetworkVideoTransmitter".to_owned(),
                format!("IP {}", raw.ip),
            ],
        }],
        DeviceKind::PossibleCamera => {
            let mut evidence = vec![format!("Открыт RTSP-порт 554 на {}", raw.ip)];
            if let Some(vendor) = vendor {
                evidence.push(format!("Производитель MAC: {vendor}"));
            }
            vec![Finding {
                id: format!("camera-possible-{}", raw.ip),
                category: "device".to_owned(),
                severity: Severity::Warning,
                title: "Возможно, IP-камера".to_owned(),
                description: "Найдены признаки видеосервиса, но их недостаточно для категоричного определения устройства.".to_owned(),
                recommendation: Some(
                    "Сопоставьте устройство с оборудованием в помещении. Один RTSP-порт сам по себе не доказывает наличие камеры.".to_owned(),
                ),
                evidence,
            }]
        }
        _ => Vec::new(),
    }
}

fn normalize_mac(value: &str) -> String {
    value.trim().replace('-', ":").to_ascii_lowercase()
}

fn vendor_for_mac(mac: &str) -> Option<String> {
    let compact = mac.replace(':', "").to_ascii_uppercase();
    let prefix = compact.get(..6)?;
    let vendor = match prefix {
        "000C29" | "001C14" | "005056" => "VMware",
        "001A11" | "3C5AB4" | "F4F5D8" => "Google",
        "001E06" | "3C6104" | "F0D1A9" => "Wibrain / Networking",
        "0023AE" | "18E829" | "44D9E7" | "F09FC2" => "Ubiquiti",
        "001B63" | "001EC2" | "3C0754" | "A4C361" | "F01898" => "Apple",
        "000C43" | "50C7BF" | "B0BE76" => "TP-Link",
        "000F7C" | "4C60DE" | "C05627" => "Hikvision",
        "3C678C" | "A0BD1D" | "E0508B" => "Dahua",
        "00408C" | "B8A44F" | "ACCC8E" => "Axis",
        "EC71DB" | "2C9EFC" => "Reolink",
        "001788" | "ECB5FA" => "Philips Hue",
        "18B430" | "6854FD" | "FC65DE" => "Nest",
        "F0272D" | "A0D0DC" | "B4E62D" => "Amazon",
        "001018" | "00095B" | "A42B8C" => "Broadcom / Router",
        "D850E6" | "CC2D21" | "DC2C6E" => "ASUSTek",
        _ => return None,
    };
    Some(vendor.to_owned())
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

pub fn kind_label(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::Router => "Маршрутизатор",
        DeviceKind::Computer => "Компьютер",
        DeviceKind::Phone => "Телефон",
        DeviceKind::Tablet => "Планшет",
        DeviceKind::Printer => "Принтер",
        DeviceKind::Media => "Медиаустройство",
        DeviceKind::SmartHome => "Умный дом",
        DeviceKind::Camera => "IP-камера",
        DeviceKind::PossibleCamera => "Видеоустройство",
        DeviceKind::NetworkEquipment => "Сетевое оборудование",
        DeviceKind::Unknown => "Неизвестное устройство",
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::Utc;

    use super::{RawDevice, finalize_device};
    use crate::domain::{DeviceKind, ServiceEvidence};

    #[test]
    fn onvif_is_high_confidence_camera() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 20));
        raw.onvif = true;
        raw.services.push(ServiceEvidence {
            protocol: "onvif".to_owned(),
            name: "NetworkVideoTransmitter".to_owned(),
            service_type: Some("ws-discovery".to_owned()),
            port: Some(3702),
            details: Vec::new(),
        });

        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.kind, DeviceKind::Camera);
        assert_eq!(device.findings.len(), 1);
    }

    #[test]
    fn rtsp_alone_is_only_possible_camera() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 30));
        raw.open_ports.insert(554);
        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.kind, DeviceKind::PossibleCamera);
    }

    #[test]
    fn local_dns_name_becomes_the_visible_device_name() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 40));
        raw.hostnames.insert("lab-thermostat.local.".to_owned());
        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.display_name, "lab-thermostat");
        assert_eq!(device.kind, DeviceKind::SmartHome);
    }

    #[test]
    fn generic_tcp_service_is_not_used_as_a_device_name() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 50));
        raw.open_ports.insert(445);
        raw.services.push(ServiceEvidence {
            protocol: "tcp".to_owned(),
            name: "SMB".to_owned(),
            service_type: None,
            port: Some(445),
            details: Vec::new(),
        });
        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.display_name, "Компьютер");
    }
}
