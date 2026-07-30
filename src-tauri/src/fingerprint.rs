use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::domain::{
    Confidence, DeviceKind, Finding, ObservedDevice, ServiceEvidence, Severity, TrustState,
};
use crate::vendor::{is_locally_administered, vendor_for_mac};

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
    let uses_private_mac = mac_address.as_deref().is_some_and(is_locally_administered);
    let (kind, type_confidence) = infer_kind(&raw, vendor.as_deref());
    let display_name = display_name(&raw, kind, vendor.as_deref());
    let identity_key = identity_key(&raw, mac_address.as_deref());
    let findings = device_findings(&raw, kind, vendor.as_deref());
    let mut evidence = raw.evidence;
    if uses_private_mac {
        evidence
            .insert("Приватный MAC-адрес: производитель по IEEE OUI не определяется".to_owned());
    }

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
        evidence: evidence.into_iter().collect(),
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
        return "Этот компьютер".to_owned();
    }
    if raw.is_router {
        if let Some(product) = upnp_product_name(raw) {
            return product;
        }
        if let Some(hostname) = best_hostname(raw) {
            return hostname;
        }
        if let Some(vendor) = vendor {
            return format!("{vendor} · шлюз сети");
        }
        return "Шлюз сети".to_owned();
    }
    if let Some(hostname) = best_hostname(raw) {
        return hostname;
    }
    if let Some(service) = raw.services.iter().find(|service| {
        service.protocol == "mdns"
            && !service.name.trim().is_empty()
            && is_human_name(&service.name)
    }) {
        return clean_hostname(&service.name);
    }
    if let Some(vendor) = vendor {
        return format!("{vendor} · {}", kind_label(kind));
    }
    if raw
        .mac_address
        .as_deref()
        .is_some_and(is_locally_administered)
    {
        return "Устройство с приватным MAC".to_owned();
    }
    kind_label(kind).to_owned()
}

fn clean_hostname(value: &str) -> String {
    let cleaned = value
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .replace("\\032", " ");
    let lower = cleaned.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("yandex-station-") {
        let model = rest
            .rsplit_once('-')
            .filter(|(_, suffix)| looks_like_device_id(suffix))
            .map_or(rest, |(model, _)| model);
        return format!("Yandex Station {}", title_case_words(model));
    }
    cleaned
}

fn best_hostname(raw: &RawDevice) -> Option<String> {
    raw.hostnames
        .iter()
        .map(|hostname| clean_hostname(hostname))
        .find(|hostname| is_human_name(hostname))
}

fn is_human_name(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.parse::<Ipv4Addr>().is_ok() {
        return false;
    }
    let compact = trimmed
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>();
    if compact.len() == 12
        && trimmed
            .chars()
            .all(|character| character.is_ascii_hexdigit() || matches!(character, ':' | '-' | '.'))
    {
        return false;
    }
    let alphanumeric_count = trimmed.chars().filter(char::is_ascii_alphanumeric).count();
    let hex_count = trimmed.chars().filter(char::is_ascii_hexdigit).count();
    alphanumeric_count < 16 || hex_count * 4 < alphanumeric_count * 3
}

fn looks_like_device_id(value: &str) -> bool {
    value.len() >= 10
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
        && value.chars().any(|character| character.is_ascii_digit())
}

fn title_case_words(value: &str) -> String {
    value
        .split(['-', '_'])
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut characters = word.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + characters.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn upnp_product_name(raw: &RawDevice) -> Option<String> {
    let server = raw
        .services
        .iter()
        .find(|service| service.protocol == "ssdp")?
        .name
        .split_whitespace()
        .collect::<Vec<_>>();
    let product_start = server
        .iter()
        .position(|part| part.to_ascii_lowercase().starts_with("upnp/"))?
        + 1;
    let mut product = server.get(product_start..)?.to_vec();
    if let Some(last) = product.last_mut()
        && let Some((name, version)) = last.rsplit_once('/')
        && version
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
    {
        *last = name;
    }
    let value = product.join(" ");
    (!value.trim().is_empty()).then_some(value)
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
    if contains_any(&service_text, &["_matter.", "_matterc."]) {
        return (DeviceKind::SmartHome, Confidence::High);
    }
    if contains_any(
        &service_text,
        &["_yandexio.", "_androidtvremote", "_googlezone."],
    ) {
        return (DeviceKind::Media, Confidence::High);
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
    if contains_any(&vendor_lower, &["tuya", "philips hue"]) {
        return (DeviceKind::SmartHome, Confidence::Medium);
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
    let octets = value
        .trim()
        .split([':', '-'])
        .map(|octet| u8::from_str_radix(octet, 16))
        .collect::<Result<Vec<_>, _>>();
    if let Ok(octets) = octets
        && octets.len() == 6
    {
        return octets
            .into_iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<_>>()
            .join(":");
    }
    value.trim().replace('-', ":").to_ascii_lowercase()
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

    #[test]
    fn router_uses_product_from_ssdp_server_header() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 1));
        raw.is_router = true;
        raw.mac_address = Some("d8:44:89:3b:3c:00".to_owned());
        raw.hostnames.insert("192.168.1.1".to_owned());
        raw.services.push(ServiceEvidence {
            protocol: "ssdp".to_owned(),
            name: "TPOS/V1.0.0 UPnP/1.0 Archer C80/2.20".to_owned(),
            service_type: Some("upnp:rootdevice".to_owned()),
            port: None,
            details: Vec::new(),
        });

        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.display_name, "Archer C80");
        assert_eq!(device.vendor.as_deref(), Some("TP-Link"));
    }

    #[test]
    fn yandex_mdns_hostname_becomes_readable_media_name() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 104));
        raw.hostnames
            .insert("yandex-station-midi-R104ZT300FM43N.local.".to_owned());
        raw.services.push(ServiceEvidence {
            protocol: "mdns".to_owned(),
            name: "YandexIOReceiver-R104ZT300FM43N".to_owned(),
            service_type: Some("_yandexio._tcp.local.".to_owned()),
            port: Some(1961),
            details: vec!["platform: cucumber".to_owned()],
        });

        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.display_name, "Yandex Station Midi");
        assert_eq!(device.kind, DeviceKind::Media);
    }

    #[test]
    fn matter_service_identifies_smart_home_without_using_hex_as_a_name() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 107));
        raw.mac_address = Some("ac:ba:c0:b6:20:92".to_owned());
        raw.hostnames.insert("ACBAC0B62092.local.".to_owned());
        raw.services.push(ServiceEvidence {
            protocol: "mdns".to_owned(),
            name: "40C0B5E11EA59CE6-0000000000000102".to_owned(),
            service_type: Some("_matter._tcp.local.".to_owned()),
            port: Some(5540),
            details: vec!["T: 1".to_owned()],
        });

        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.display_name, "Intertech Services AG · Умный дом");
        assert_eq!(device.kind, DeviceKind::SmartHome);
    }

    #[test]
    fn private_mac_is_explained_without_claiming_a_vendor() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 108));
        raw.mac_address = Some("a2:e8:06:f2:e2:80".to_owned());

        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.display_name, "Устройство с приватным MAC");
        assert!(device.vendor.is_none());
        assert!(
            device
                .evidence
                .iter()
                .any(|item| item.starts_with("Приватный MAC-адрес"))
        );
    }

    #[test]
    fn macos_arp_short_octets_are_zero_padded_before_vendor_lookup() {
        let mut raw = RawDevice::new(Ipv4Addr::new(192, 168, 1, 105));
        raw.mac_address = Some("64:48:42:b4:7:ab".to_owned());

        let device = finalize_device(raw, Utc::now());
        assert_eq!(device.mac_address.as_deref(), Some("64:48:42:b4:07:ab"));
        assert_eq!(device.vendor.as_deref(), Some("Apple"));
    }
}
