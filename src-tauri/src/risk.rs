use crate::domain::{
    Assessment, Confidence, DeviceKind, Finding, NetworkContext, ObservedDevice, ScanCoverage,
    ScanReport, Severity, VisibilityLevel,
};

pub fn assess(
    network: &NetworkContext,
    devices: &[ObservedDevice],
    coverage: &ScanCoverage,
    previous: Option<&ScanReport>,
) -> Assessment {
    let mut findings = Vec::new();
    findings.extend(security_findings(network));
    findings.extend(network_change_findings(network, previous));
    findings.extend(visibility_findings(coverage));
    findings.extend(device_findings(devices));

    let risk = findings
        .iter()
        .filter_map(|finding| match finding.severity {
            Severity::Warning | Severity::High | Severity::Critical => Some(finding.severity),
            Severity::Info | Severity::Good => None,
        })
        .max()
        .unwrap_or(Severity::Info);
    let visibility = visibility_level(coverage);
    let confidence = confidence_level(network, coverage);
    let summary = risk_summary(risk, visibility);

    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

    Assessment {
        risk,
        visibility,
        confidence,
        summary,
        findings,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "Keeping Wi-Fi security branches together makes the risk policy easier to audit"
)]
fn security_findings(network: &NetworkContext) -> Vec<Finding> {
    let security = network.security.to_ascii_lowercase();
    let mut findings = Vec::new();

    if matches!(
        security.as_str(),
        "open" | "wep" | "dynamic-wep" | "wpa-personal" | "wpa-enterprise"
    ) {
        findings.push(Finding {
            id: "wifi-weak-security".to_owned(),
            category: "network".to_owned(),
            severity: if security == "open" || security.contains("wep") {
                Severity::Critical
            } else {
                Severity::High
            },
            title: "Слабая защита Wi‑Fi".to_owned(),
            description: format!(
                "Текущий режим «{}» не обеспечивает современную защиту радиообмена.",
                human_security(&security)
            ),
            recommendation: Some(
                "Не передавайте чувствительные данные без VPN. Для своей сети включите WPA3 или WPA2 AES."
                    .to_owned(),
            ),
            evidence: vec![format!("Системный Wi‑Fi API: {security}")],
        });
    } else if security.contains("wpa3") || security == "owe" {
        findings.push(Finding {
            id: "wifi-modern-security".to_owned(),
            category: "network".to_owned(),
            severity: Severity::Good,
            title: "Современная защита радиообмена".to_owned(),
            description: format!(
                "Сеть использует {}. Это защищает соединение с точкой доступа, но не делает всю локальную сеть доверенной.",
                human_security(&security)
            ),
            recommendation: None,
            evidence: vec![format!("Системный Wi‑Fi API: {security}")],
        });
    } else if security.contains("wpa2") {
        findings.push(Finding {
            id: "wifi-wpa2-security".to_owned(),
            category: "network".to_owned(),
            severity: Severity::Info,
            title: "Защита WPA2".to_owned(),
            description: "WPA2 остаётся приемлемым при использовании AES и сильного пароля; WPA3 предпочтительнее.".to_owned(),
            recommendation: None,
            evidence: vec![format!("Системный Wi‑Fi API: {security}")],
        });
    } else {
        findings.push(Finding {
            id: "wifi-security-unknown".to_owned(),
            category: "coverage".to_owned(),
            severity: Severity::Warning,
            title: "Тип защиты не определён".to_owned(),
            description:
                "Операционная система не вернула режим безопасности или Wi‑Fi ещё не полностью подключён."
                    .to_owned(),
            recommendation: Some(
                "Разрешите доступ к геопозиции для Маяка и повторите проверку.".to_owned(),
            ),
            evidence: vec!["Системный Wi‑Fi API: unknown".to_owned()],
        });
    }

    if network.proxy_enabled {
        findings.push(Finding {
            id: "system-proxy-enabled".to_owned(),
            category: "network".to_owned(),
            severity: Severity::Warning,
            title: "В системе активен прокси".to_owned(),
            description: "Прокси может быть ожидаемой корпоративной настройкой, но в публичной сети его стоит проверить.".to_owned(),
            recommendation: Some(
                "Откройте настройки сети и убедитесь, что адрес прокси вам известен.".to_owned(),
            ),
            evidence: vec!["SystemConfiguration: proxy enabled".to_owned()],
        });
    }

    if network.vpn_active {
        findings.push(Finding {
            id: "vpn-active".to_owned(),
            category: "device".to_owned(),
            severity: Severity::Good,
            title: "VPN-интерфейс активен".to_owned(),
            description:
                "Системный туннель обнаружен. Маяк сканирует только прямую Wi‑Fi-подсеть и не затрагивает маршруты VPN."
                    .to_owned(),
            recommendation: None,
            evidence: vec!["Обнаружен активный туннельный или VPN-интерфейс".to_owned()],
        });
    }

    if let (Some(rssi), Some(quality)) = (network.rssi, network.signal_quality)
        && quality < 30
    {
        findings.push(Finding {
            id: "weak-signal".to_owned(),
            category: "quality".to_owned(),
            severity: Severity::Info,
            title: "Слабый сигнал Wi‑Fi".to_owned(),
            description: "Потери пакетов могут уменьшить полноту обнаружения устройств.".to_owned(),
            recommendation: Some(
                "Подойдите ближе к точке доступа и повторите проверку.".to_owned(),
            ),
            evidence: vec![format!("RSSI: {rssi} dBm, качество: {quality}%")],
        });
    }

    findings
}

fn network_change_findings(
    network: &NetworkContext,
    previous: Option<&ScanReport>,
) -> Vec<Finding> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let mut findings = Vec::new();

    if previous.network.ssid == network.ssid
        && previous.network.bssid.is_some()
        && network.bssid.is_some()
        && previous.network.bssid != network.bssid
    {
        findings.push(Finding {
            id: "bssid-changed".to_owned(),
            category: "change".to_owned(),
            severity: Severity::Info,
            title: "Изменилась точка доступа".to_owned(),
            description: "У сети с тем же именем другой BSSID. Это нормально для mesh и гостиниц, но изменение сохранено в истории.".to_owned(),
            recommendation: None,
            evidence: vec![
                format!(
                    "Раньше: {}",
                    previous.network.bssid.as_deref().unwrap_or("неизвестно")
                ),
                format!(
                    "Сейчас: {}",
                    network.bssid.as_deref().unwrap_or("неизвестно")
                ),
            ],
        });
    }

    if previous.network.ssid == network.ssid
        && previous.network.router.is_some()
        && network.router.is_some()
        && previous.network.router != network.router
    {
        findings.push(Finding {
            id: "gateway-changed".to_owned(),
            category: "change".to_owned(),
            severity: Severity::Warning,
            title: "Изменился шлюз знакомой сети".to_owned(),
            description: "У сети с тем же именем теперь другой адрес шлюза. В гостинице это может быть нормально; дома изменение требует проверки.".to_owned(),
            recommendation: Some(
                "Сверьте сеть с ожидаемым роутером и проверьте, не подключились ли вы к точке с похожим именем.".to_owned(),
            ),
            evidence: vec![
                format!(
                    "Раньше: {}",
                    previous.network.router.as_deref().unwrap_or("неизвестно")
                ),
                format!(
                    "Сейчас: {}",
                    network.router.as_deref().unwrap_or("неизвестно")
                ),
            ],
        });
    }

    findings
}

fn visibility_findings(coverage: &ScanCoverage) -> Vec<Finding> {
    let mut findings = Vec::new();
    if coverage.responsive_count <= 1 {
        findings.push(Finding {
            id: "visibility-limited".to_owned(),
            category: "coverage".to_owned(),
            severity: Severity::Info,
            title: "Видимость сети ограничена".to_owned(),
            description: "Почти никто, кроме шлюза, не отвечает. Возможны client isolation, фильтрация или отсутствие других активных устройств.".to_owned(),
            recommendation: None,
            evidence: vec![format!(
                "Наблюдается {} устройство при {} проверенных адресах",
                coverage.responsive_count, coverage.target_count
            )],
        });
    }
    if coverage.limited_by_subnet_size {
        findings.push(Finding {
            id: "subnet-scan-capped".to_owned(),
            category: "coverage".to_owned(),
            severity: Severity::Info,
            title: "Проверена ближайшая область подсети".to_owned(),
            description:
                "Сеть слишком велика для автоматического полного перебора без избыточного трафика."
                    .to_owned(),
            recommendation: Some(
                "Для расширенной проверки можно запустить глубокий режим вручную.".to_owned(),
            ),
            evidence: vec![format!("Проверено {} адресов", coverage.target_count)],
        });
    }
    findings
}

fn device_findings(devices: &[ObservedDevice]) -> Vec<Finding> {
    let mut findings = devices
        .iter()
        .flat_map(|device| device.findings.clone())
        .collect::<Vec<_>>();
    let new_unknown = devices
        .iter()
        .filter(|device| device.is_unreviewed_new() && device.kind != DeviceKind::Router)
        .count();
    if new_unknown > 0 {
        findings.push(Finding {
            id: "new-devices".to_owned(),
            category: "device".to_owned(),
            severity: Severity::Info,
            title: format!("Новых устройств: {new_unknown}"),
            description: "Они впервые появились в локальной истории Маяка. В публичной сети это ожидаемо и не означает угрозу.".to_owned(),
            recommendation: Some(
                "В своей сети отметьте знакомые устройства, чтобы следующие изменения были заметнее.".to_owned(),
            ),
            evidence: devices
                .iter()
                .filter(|device| {
                    device.is_unreviewed_new() && device.kind != DeviceKind::Router
                })
                .take(5)
                .map(|device| {
                    format!(
                        "{} ({})",
                        device.display_name,
                        device
                            .ip_addresses
                            .first()
                            .map_or("без IP", String::as_str)
                    )
                })
                .collect(),
        });
    }
    findings
}

fn visibility_level(coverage: &ScanCoverage) -> VisibilityLevel {
    if coverage.responsive_count <= 1 {
        VisibilityLevel::Limited
    } else if coverage.limited_by_subnet_size
        || (coverage.mdns_count == 0 && coverage.arp_count == 0)
    {
        VisibilityLevel::Partial
    } else {
        VisibilityLevel::Good
    }
}

fn confidence_level(network: &NetworkContext, coverage: &ScanCoverage) -> Confidence {
    if network.ssid.is_none() || network.security == "unknown" {
        Confidence::Low
    } else if coverage.responsive_count <= 1 || coverage.limited_by_subnet_size {
        Confidence::Medium
    } else {
        Confidence::High
    }
}

fn risk_summary(risk: Severity, visibility: VisibilityLevel) -> String {
    let base = match risk {
        Severity::Critical => "Обнаружен критичный риск сети.",
        Severity::High => "Есть серьёзные признаки риска.",
        Severity::Warning => "Есть моменты, которые стоит проверить.",
        Severity::Info | Severity::Good => "Явных рисков по доступным данным не найдено.",
    };
    if visibility == VisibilityLevel::Limited {
        format!("{base} Видимость других устройств ограничена.")
    } else {
        base.to_owned()
    }
}

fn human_security(value: &str) -> &'static str {
    match value {
        "open" => "открытая сеть",
        "wep" | "dynamic-wep" => "WEP",
        "wpa-personal" => "WPA Personal",
        "wpa-enterprise" => "WPA Enterprise",
        "wpa-wpa2-personal" => "WPA/WPA2",
        "wpa-wpa2-enterprise" => "WPA/WPA2 Enterprise",
        "wpa2-personal" => "WPA2 Personal",
        "wpa2-enterprise" => "WPA2 Enterprise",
        "wpa3-personal" => "WPA3 Personal",
        "wpa3-enterprise" => "WPA3 Enterprise",
        "wpa2-wpa3-transition" => "WPA2/WPA3",
        "owe" => "Enhanced Open (OWE)",
        "owe-transition" => "OWE Transition",
        _ => "неизвестная защита",
    }
}

#[cfg(test)]
mod tests {
    use super::assess;
    use crate::{
        domain::{
            ChannelInfo, NetworkContext, ScanCoverage, Severity, TrustState, VisibilityLevel,
        },
        fingerprint::{RawDevice, finalize_device},
    };
    use chrono::Utc;
    use std::net::Ipv4Addr;

    fn network(security: &str) -> NetworkContext {
        NetworkContext {
            connected: true,
            wifi_available: true,
            interface_name: Some("en0".to_owned()),
            ssid: Some("Test".to_owned()),
            bssid: Some("00:11:22:33:44:55".to_owned()),
            security: security.to_owned(),
            phy_mode: Some("Wi-Fi 6".to_owned()),
            channel: Some(ChannelInfo {
                number: 36,
                band: "5 GHz".to_owned(),
                width: "80 MHz".to_owned(),
            }),
            rssi: Some(-55),
            noise: Some(-92),
            signal_quality: Some(90),
            transmit_rate_mbps: Some(866.0),
            country_code: Some("RU".to_owned()),
            local_mac_address: Some("02:00:00:00:00:10".to_owned()),
            ipv4: Some("192.168.1.10".to_owned()),
            ipv6: Vec::new(),
            subnet: Some("192.168.1.0/24".to_owned()),
            router: Some("192.168.1.1".to_owned()),
            dns_servers: vec!["192.168.1.1".to_owned()],
            proxy_enabled: false,
            vpn_active: false,
            network_id: "test".to_owned(),
        }
    }

    fn coverage(responsive: usize) -> ScanCoverage {
        ScanCoverage {
            target_count: 253,
            responsive_count: responsive,
            arp_count: responsive,
            mdns_count: responsive.saturating_sub(1),
            ssdp_count: 0,
            onvif_count: 0,
            methods: vec!["TCP".to_owned()],
            limited_by_subnet_size: false,
            notes: Vec::new(),
        }
    }

    #[test]
    fn open_wifi_is_critical() {
        let assessment = assess(&network("open"), &[], &coverage(3), None);
        assert_eq!(assessment.risk, Severity::Critical);
    }

    #[test]
    fn wpa3_with_evidence_is_low_risk() {
        let assessment = assess(&network("wpa3-personal"), &[], &coverage(3), None);
        assert_eq!(assessment.risk, Severity::Info);
        assert_eq!(assessment.visibility, VisibilityLevel::Good);
    }

    #[test]
    fn one_visible_device_never_claims_full_visibility() {
        let assessment = assess(&network("wpa2-personal"), &[], &coverage(1), None);
        assert_eq!(assessment.visibility, VisibilityLevel::Limited);
    }

    #[test]
    fn reviewed_first_seen_device_is_not_reported_as_new() {
        let mut device =
            finalize_device(RawDevice::new(Ipv4Addr::new(192, 168, 1, 42)), Utc::now());
        assert!(device.is_unreviewed_new());

        device.trust_state = TrustState::Known;
        let assessment = assess(&network("wpa3-personal"), &[device], &coverage(3), None);

        assert!(
            assessment
                .findings
                .iter()
                .all(|finding| finding.id != "new-devices")
        );
    }
}
