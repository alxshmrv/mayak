use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use ipnet::Ipv4Net;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use regex::Regex;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Semaphore, mpsc::UnboundedSender};
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

use crate::domain::{
    DeviceKind, NetworkContext, ObservedDevice, ScanCoverage, ScanMode, ScanProgress,
    ServiceEvidence, TrustState,
};
use crate::error::{AppError, AppResult};
use crate::fingerprint::{RawDevice, finalize_device};
use crate::network::selected_ipv4;
use crate::platform;

pub struct DiscoveryOutput {
    pub devices: Vec<ObservedDevice>,
    pub coverage: ScanCoverage,
}

#[allow(
    clippy::too_many_lines,
    reason = "The ordered discovery pipeline keeps scan phases and coverage accounting auditable"
)]
pub async fn discover(
    context: &NetworkContext,
    mode: ScanMode,
    progress: Option<&UnboundedSender<ScanProgress>>,
) -> AppResult<DiscoveryOutput> {
    if !context.connected {
        return Err(AppError::NoWifi);
    }

    let local_ip = selected_ipv4(context)?;
    let subnet = context
        .subnet
        .as_deref()
        .ok_or(AppError::NoIpv4)?
        .parse::<Ipv4Net>()
        .map_err(|error| AppError::Network(error.to_string()))?;
    let limit = match mode {
        ScanMode::Safe => 254,
        ScanMode::Deep => 1_022,
    };
    let (mut targets, limited_by_subnet_size) = scan_targets(subnet, local_ip, limit);

    if let Some(router) = context
        .router
        .as_deref()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        && subnet.contains(&router)
        && !targets.contains(&router)
    {
        targets.push(router);
    }

    send_progress(
        progress,
        "prepare",
        "Определяем границы сети",
        &format!("{} адресов в текущей Wi‑Fi-подсети", targets.len()),
        0,
        targets.len(),
    );

    let mdns_duration = match mode {
        ScanMode::Safe => Duration::from_millis(1_600),
        ScanMode::Deep => Duration::from_millis(2_600),
    };
    let mdns_task = tokio::task::spawn_blocking(move || discover_mdns(mdns_duration));
    let tcp_future = scan_tcp_targets(targets.clone(), mode, progress);
    let ssdp_future = discover_ssdp(local_ip, mode);
    let onvif_future = discover_onvif(local_ip, mode);

    let (tcp_devices, ssdp_devices, onvif_devices, mdns_result) =
        tokio::join!(tcp_future, ssdp_future, onvif_future, mdns_task);

    send_progress(
        progress,
        "neighbors",
        "Сверяем соседей",
        "Читаем ARP-таблицу после активных проверок",
        targets.len(),
        targets.len(),
    );

    let interface_name = context.interface_name.clone();
    let arp_devices =
        tokio::task::spawn_blocking(move || read_arp_table(interface_name.as_deref()))
            .await
            .unwrap_or_default();
    let mdns_devices = mdns_result.unwrap_or_default();

    let mut merged = BTreeMap::<Ipv4Addr, RawDevice>::new();
    merge_records(&mut merged, tcp_devices);
    merge_records(&mut merged, arp_devices);
    merge_records(&mut merged, mdns_devices.clone());
    merge_records(&mut merged, ssdp_devices.clone());
    merge_records(&mut merged, onvif_devices.clone());

    let mut local = RawDevice::new(local_ip);
    local.is_local_mac = true;
    local
        .evidence
        .insert("Локальный интерфейс этого компьютера".to_owned());
    local.mac_address.clone_from(&context.local_mac_address);
    merged
        .entry(local_ip)
        .and_modify(|existing| existing.merge(local.clone()))
        .or_insert(local);

    if let Some(router_ip) = context
        .router
        .as_deref()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
    {
        let router = merged
            .entry(router_ip)
            .or_insert_with(|| RawDevice::new(router_ip));
        router.is_router = true;
        router.evidence.insert("Шлюз текущей Wi‑Fi-сети".to_owned());
    }

    let dns_targets = merged.keys().copied().collect::<Vec<_>>();
    let dns_devices = tokio::task::spawn_blocking(move || resolve_local_dns(dns_targets))
        .await
        .unwrap_or_default();
    merge_records(&mut merged, dns_devices);

    let observed_at = chrono::Utc::now();
    let mut devices = merged
        .into_values()
        .filter(|item| is_valid_observation(item, subnet))
        .map(|item| finalize_device(item, observed_at))
        .collect::<Vec<_>>();
    devices.sort_by_key(|item| {
        let rank = match (item.kind, item.trust_state) {
            (DeviceKind::Router, _) => 0,
            (_, TrustState::Mine) => 1,
            _ => 2,
        };
        (rank, item.ip_addresses.first().cloned().unwrap_or_default())
    });

    let responsive_count = devices
        .iter()
        .filter(|item| item.trust_state != TrustState::Mine)
        .count();
    let mut notes = Vec::new();
    if limited_by_subnet_size {
        notes.push(format!(
            "Подсеть {subnet} больше безопасного лимита режима; проверена ближайшая область из {limit} адресов."
        ));
    }
    if responsive_count <= 1 {
        notes.push(
            "Другие клиенты почти не отвечают. Возможны client isolation, фильтрация или пустая сеть."
                .to_owned(),
        );
    }
    notes.push(
        "Молчащие устройства, другие VLAN и устройства за изоляцией могут быть невидимы."
            .to_owned(),
    );

    Ok(DiscoveryOutput {
        coverage: ScanCoverage {
            target_count: targets.len(),
            responsive_count,
            arp_count: devices
                .iter()
                .filter(|item| item.evidence.iter().any(|value| value.contains("ARP")))
                .count(),
            mdns_count: mdns_devices.len(),
            ssdp_count: ssdp_devices.len(),
            onvif_count: onvif_devices.len(),
            methods: vec![
                "TCP connect".to_owned(),
                "ARP cache".to_owned(),
                "Локальный DNS".to_owned(),
                "Bonjour / mDNS".to_owned(),
                "SSDP".to_owned(),
                "ONVIF / WS-Discovery".to_owned(),
            ],
            limited_by_subnet_size,
            notes,
        },
        devices,
    })
}

fn merge_records(target: &mut BTreeMap<Ipv4Addr, RawDevice>, records: Vec<RawDevice>) {
    for record in records {
        target
            .entry(record.ip)
            .and_modify(|existing| existing.merge(record.clone()))
            .or_insert(record);
    }
}

fn is_valid_observation(record: &RawDevice, subnet: Ipv4Net) -> bool {
    if !subnet.contains(&record.ip)
        || record.ip == subnet.network()
        || record.ip == subnet.broadcast()
        || record.ip.is_broadcast()
        || record.ip.is_multicast()
        || record.ip.is_unspecified()
    {
        return false;
    }

    record
        .mac_address
        .as_deref()
        .is_none_or(|mac| !is_group_mac(mac))
}

fn is_group_mac(value: &str) -> bool {
    value
        .split([':', '-'])
        .next()
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        .is_some_and(|octet| octet & 1 == 1)
}

fn scan_targets(subnet: Ipv4Net, local_ip: Ipv4Addr, limit: usize) -> (Vec<Ipv4Addr>, bool) {
    let network = u32::from(subnet.network());
    let broadcast = u32::from(subnet.broadcast());
    let first = network.saturating_add(1);
    let last = broadcast.saturating_sub(1);
    if last < first {
        return (Vec::new(), false);
    }

    let total = usize::try_from(last - first + 1).unwrap_or(usize::MAX);
    if total <= limit {
        return (
            (first..=last)
                .map(Ipv4Addr::from)
                .filter(|value| *value != local_ip)
                .collect(),
            false,
        );
    }

    let local = u32::from(local_ip);
    let half = u32::try_from(limit / 2).unwrap_or(u32::MAX);
    let mut start = local.saturating_sub(half).max(first);
    let limit_u32 = u32::try_from(limit).unwrap_or(u32::MAX);
    if start.saturating_add(limit_u32).saturating_sub(1) > last {
        start = last.saturating_sub(limit_u32.saturating_sub(1)).max(first);
    }
    let end = start.saturating_add(limit_u32.saturating_sub(1)).min(last);

    (
        (start..=end)
            .map(Ipv4Addr::from)
            .filter(|value| *value != local_ip)
            .collect(),
        true,
    )
}

async fn scan_tcp_targets(
    targets: Vec<Ipv4Addr>,
    mode: ScanMode,
    progress: Option<&UnboundedSender<ScanProgress>>,
) -> Vec<RawDevice> {
    let total = targets.len();
    let ports: &'static [u16] = match mode {
        ScanMode::Safe => &[22, 80, 443, 445, 554, 631, 8080, 9100],
        ScanMode::Deep => &[
            21, 22, 23, 53, 80, 81, 139, 443, 445, 548, 554, 631, 5000, 7000, 8000, 8008, 8009,
            8080, 8443, 8888, 9100, 32400,
        ],
    };
    let per_probe_timeout = match mode {
        ScanMode::Safe => Duration::from_millis(260),
        ScanMode::Deep => Duration::from_millis(520),
    };
    let connection_limit = Arc::new(Semaphore::new(match mode {
        ScanMode::Safe => 64,
        ScanMode::Deep => 192,
    }));

    let mut stream = stream::iter(targets.into_iter().map(|ip| {
        let connection_limit = Arc::clone(&connection_limit);
        async move { probe_host(ip, ports, per_probe_timeout, connection_limit).await }
    }))
    .buffer_unordered(match mode {
        ScanMode::Safe => 64,
        ScanMode::Deep => 96,
    });

    let mut result = Vec::new();
    let mut completed = 0;
    while let Some(record) = stream.next().await {
        completed += 1;
        if let Some(record) = record {
            result.push(record);
        }
        if completed == total || completed % 16 == 0 {
            send_progress(
                progress,
                "tcp",
                "Ищем отвечающие устройства",
                &format!("Проверено {completed} из {total} адресов"),
                completed,
                total,
            );
        }
    }
    result
}

async fn probe_host(
    ip: Ipv4Addr,
    ports: &'static [u16],
    probe_timeout: Duration,
    connection_limit: Arc<Semaphore>,
) -> Option<RawDevice> {
    let started = Instant::now();
    let attempts = stream::iter(ports.iter().copied().map(|port| {
        let connection_limit = Arc::clone(&connection_limit);
        async move {
            let Ok(_permit) = connection_limit.acquire_owned().await else {
                return (port, false, false);
            };
            let address = SocketAddr::new(IpAddr::V4(ip), port);
            match timeout(probe_timeout, TcpStream::connect(address)).await {
                Ok(Ok(_stream)) => (port, true, true),
                Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => {
                    (port, false, true)
                }
                _ => (port, false, false),
            }
        }
    }))
    .buffer_unordered(ports.len())
    .collect::<Vec<_>>()
    .await;

    if !attempts.iter().any(|(_, _, responded)| *responded) {
        return None;
    }

    let mut record = RawDevice::new(ip);
    record.response_time_ms =
        Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    record
        .evidence
        .insert("Устройство ответило на TCP-проверку".to_owned());
    for (port, open, _) in attempts {
        if open {
            record.open_ports.insert(port);
            record.services.push(ServiceEvidence {
                protocol: "tcp".to_owned(),
                name: tcp_service_name(port).to_owned(),
                service_type: None,
                port: Some(port),
                details: Vec::new(),
            });
        }
    }
    Some(record)
}

fn read_arp_table(interface_name: Option<&str>) -> Vec<RawDevice> {
    platform::read_neighbors(interface_name)
        .into_iter()
        .filter_map(|neighbor| {
            if is_group_mac(&neighbor.mac_address) {
                return None;
            }
            let mut record = RawDevice::new(neighbor.ip);
            record.mac_address = Some(neighbor.mac_address);
            record
                .evidence
                .insert("MAC-адрес найден в таблице соседей (ARP)".to_owned());
            Some(record)
        })
        .collect()
}

fn resolve_local_dns(ips: Vec<Ipv4Addr>) -> Vec<RawDevice> {
    ips.into_iter()
        .filter_map(|ip| {
            let hostname = platform::resolve_hostname(ip)?;
            let mut record = RawDevice::new(ip);
            record.hostnames.insert(hostname);
            record
                .evidence
                .insert("Имя получено через локальный DNS".to_owned());
            Some(record)
        })
        .collect()
}

fn discover_mdns(duration: Duration) -> Vec<RawDevice> {
    let Ok(daemon) = ServiceDaemon::new() else {
        return Vec::new();
    };
    let service_types = [
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_workstation._tcp.local.",
        "_device-info._tcp.local.",
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_googlecast._tcp.local.",
        "_ipp._tcp.local.",
        "_ipps._tcp.local.",
        "_printer._tcp.local.",
        "_scanner._tcp.local.",
        "_smb._tcp.local.",
        "_ssh._tcp.local.",
        "_rtsp._tcp.local.",
        "_hap._tcp.local.",
    ];
    let receivers = service_types
        .iter()
        .filter_map(|service_type| {
            daemon
                .browse(service_type)
                .ok()
                .map(|receiver| (*service_type, receiver))
        })
        .collect::<Vec<_>>();
    let deadline = Instant::now() + duration;
    let mut records = BTreeMap::<Ipv4Addr, RawDevice>::new();

    while Instant::now() < deadline {
        for (service_type, receiver) in &receivers {
            if let Ok(ServiceEvent::ServiceResolved(info)) =
                receiver.recv_timeout(Duration::from_millis(12))
            {
                for address in info.get_addresses_v4() {
                    let record = records
                        .entry(address)
                        .or_insert_with(|| RawDevice::new(address));
                    record.hostnames.insert(info.get_hostname().to_owned());
                    record.services.push(ServiceEvidence {
                        protocol: "mdns".to_owned(),
                        name: service_instance_name(info.get_fullname()),
                        service_type: Some((*service_type).to_owned()),
                        port: Some(info.get_port()),
                        details: Vec::new(),
                    });
                    record.evidence.insert(format!("Bonjour: {service_type}"));
                }
            }
        }
    }

    for service_type in service_types {
        let _ = daemon.stop_browse(service_type);
    }
    let _ = daemon.shutdown();
    records.into_values().collect()
}

async fn discover_ssdp(local_ip: Ipv4Addr, mode: ScanMode) -> Vec<RawDevice> {
    let Ok(socket) = UdpSocket::bind(SocketAddr::new(IpAddr::V4(local_ip), 0)).await else {
        return Vec::new();
    };
    let request = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 1\r\n",
        "ST: ssdp:all\r\n\r\n"
    );
    if socket
        .send_to(request.as_bytes(), "239.255.255.250:1900")
        .await
        .is_err()
    {
        return Vec::new();
    }

    let duration = match mode {
        ScanMode::Safe => Duration::from_millis(1_200),
        ScanMode::Deep => Duration::from_secs(2),
    };
    let deadline = tokio::time::Instant::now() + duration;
    let mut buffer = [0_u8; 8_192];
    let mut records = BTreeMap::<Ipv4Addr, RawDevice>::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(Ok((length, sender))) = timeout(remaining, socket.recv_from(&mut buffer)).await
        else {
            break;
        };
        let IpAddr::V4(ip) = sender.ip() else {
            continue;
        };
        let headers = parse_httpish_headers(&String::from_utf8_lossy(&buffer[..length]));
        let name = headers
            .get("server")
            .or_else(|| headers.get("st"))
            .cloned()
            .unwrap_or_else(|| "UPnP-устройство".to_owned());
        let mut details = Vec::new();
        for key in ["st", "usn", "location"] {
            if let Some(value) = headers.get(key) {
                details.push(format!("{key}: {value}"));
            }
        }
        let record = records.entry(ip).or_insert_with(|| RawDevice::new(ip));
        if let Some(location) = headers.get("location")
            && let Ok(url) = Url::parse(location)
            && let Some(hostname) = url.host_str()
        {
            record.hostnames.insert(hostname.to_owned());
        }
        record.services.push(ServiceEvidence {
            protocol: "ssdp".to_owned(),
            name,
            service_type: headers.get("st").cloned(),
            port: None,
            details,
        });
        record
            .evidence
            .insert("Устройство ответило на SSDP/UPnP".to_owned());
    }
    records.into_values().collect()
}

async fn discover_onvif(local_ip: Ipv4Addr, mode: ScanMode) -> Vec<RawDevice> {
    let Ok(socket) = UdpSocket::bind(SocketAddr::new(IpAddr::V4(local_ip), 0)).await else {
        return Vec::new();
    };
    let message_id = Uuid::new_v4();
    let request = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" \
         xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
         xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" \
         xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">\
         <e:Header><w:MessageID>uuid:{message_id}</w:MessageID>\
         <w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>\
         <w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>\
         </e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>\
         </d:Probe></e:Body></e:Envelope>"
    );
    if socket
        .send_to(request.as_bytes(), "239.255.255.250:3702")
        .await
        .is_err()
    {
        return Vec::new();
    }

    let duration = match mode {
        ScanMode::Safe => Duration::from_millis(1_300),
        ScanMode::Deep => Duration::from_millis(2_200),
    };
    let deadline = tokio::time::Instant::now() + duration;
    let mut buffer = [0_u8; 16_384];
    let mut records = BTreeMap::<Ipv4Addr, RawDevice>::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(Ok((length, sender))) = timeout(remaining, socket.recv_from(&mut buffer)).await
        else {
            break;
        };
        let IpAddr::V4(ip) = sender.ip() else {
            continue;
        };
        let response = String::from_utf8_lossy(&buffer[..length]);
        let lower = response.to_ascii_lowercase();
        if !lower.contains("onvif") && !lower.contains("networkvideotransmitter") {
            continue;
        }
        let record = records.entry(ip).or_insert_with(|| RawDevice::new(ip));
        record.onvif = true;
        record.services.push(ServiceEvidence {
            protocol: "onvif".to_owned(),
            name: "NetworkVideoTransmitter".to_owned(),
            service_type: Some("WS-Discovery".to_owned()),
            port: Some(3702),
            details: extract_onvif_addresses(&response),
        });
        record
            .evidence
            .insert("ONVIF NetworkVideoTransmitter".to_owned());
    }
    records.into_values().collect()
}

fn extract_onvif_addresses(response: &str) -> Vec<String> {
    let Ok(pattern) = Regex::new(r"(?is)<(?:\w+:)?XAddrs>(?P<value>.*?)</(?:\w+:)?XAddrs>") else {
        return Vec::new();
    };
    pattern
        .captures(response)
        .and_then(|capture| capture.name("value"))
        .map(|value| {
            value
                .as_str()
                .split_whitespace()
                .take(4)
                .map(|item| format!("XAddr: {item}"))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_httpish_headers(value: &str) -> BTreeMap<String, String> {
    value
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect()
}

fn service_instance_name(fullname: &str) -> String {
    fullname
        .split("._")
        .next()
        .unwrap_or(fullname)
        .replace("\\032", " ")
}

fn tcp_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        53 => "DNS",
        80 | 81 | 8000 | 8008 | 8080 | 8888 => "HTTP",
        139 => "NetBIOS",
        443 | 8443 => "HTTPS",
        445 => "SMB",
        548 => "AFP",
        554 => "RTSP",
        631 => "IPP",
        5000 => "HTTP / устройство",
        7000 => "AirPlay / HTTP",
        8009 => "Google Cast",
        9100 => "JetDirect",
        32400 => "Plex",
        _ => "TCP-сервис",
    }
}

fn send_progress(
    sender: Option<&UnboundedSender<ScanProgress>>,
    phase: &str,
    title: &str,
    detail: &str,
    completed: usize,
    total: usize,
) {
    if let Some(sender) = sender {
        let _ = sender.send(ScanProgress {
            phase: phase.to_owned(),
            title: title.to_owned(),
            detail: detail.to_owned(),
            completed,
            total,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;

    use super::{RawDevice, extract_onvif_addresses, is_valid_observation, scan_targets};

    #[test]
    fn safe_scan_covers_a_whole_slash_24() {
        let subnet: Ipv4Net = "192.168.4.0/24".parse().expect("valid subnet");
        let (targets, limited) = scan_targets(subnet, Ipv4Addr::new(192, 168, 4, 20), 254);
        assert!(!limited);
        assert_eq!(targets.len(), 253);
        assert!(!targets.contains(&Ipv4Addr::new(192, 168, 4, 20)));
    }

    #[test]
    fn large_network_is_bounded_around_local_ip() {
        let subnet: Ipv4Net = "10.10.0.0/16".parse().expect("valid subnet");
        let local = Ipv4Addr::new(10, 10, 120, 44);
        let (targets, limited) = scan_targets(subnet, local, 254);
        assert!(limited);
        assert_eq!(targets.len(), 253);
        assert!(!targets.contains(&local));
    }

    #[test]
    fn subnet_broadcast_is_not_a_device() {
        let subnet: Ipv4Net = "192.0.2.0/24".parse().expect("valid subnet");
        let broadcast = RawDevice::new(Ipv4Addr::new(192, 0, 2, 255));
        assert!(!is_valid_observation(&broadcast, subnet));
    }

    #[test]
    fn extracts_onvif_xaddrs() {
        let response = "<d:XAddrs>http://192.0.2.9/onvif/device_service</d:XAddrs>";
        assert_eq!(
            extract_onvif_addresses(response),
            vec!["XAddr: http://192.0.2.9/onvif/device_service"]
        );
    }
}
