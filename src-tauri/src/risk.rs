use crate::domain::{
    Assessment, Confidence, DeviceKind, Finding, NetworkContext, ObservedDevice, ScanCoverage,
    ScanReport, Severity, VisibilityLevel,
};
use crate::i18n::Language;

pub fn assess(
    network: &NetworkContext,
    devices: &[ObservedDevice],
    coverage: &ScanCoverage,
    previous: Option<&ScanReport>,
    language: Language,
) -> Assessment {
    let mut findings = Vec::new();
    findings.extend(security_findings(network, language));
    findings.extend(network_change_findings(network, previous, language));
    findings.extend(visibility_findings(coverage, language));
    findings.extend(device_findings(devices, language));

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
    let summary = risk_summary(risk, visibility, language);

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
fn security_findings(network: &NetworkContext, language: Language) -> Vec<Finding> {
    let l = language;
    let security = network.security.to_ascii_lowercase();
    let api_evidence = format!(
        "{}: {security}",
        l.pick("Системный Wi‑Fi API", "System Wi‑Fi API")
    );
    let mut findings = Vec::new();

    if matches!(
        security.as_str(),
        "open" | "wep" | "dynamic-wep" | "wpa-personal" | "wpa-enterprise"
    ) {
        let mode = human_security(&security, l);
        findings.push(Finding {
            id: "wifi-weak-security".to_owned(),
            category: "network".to_owned(),
            severity: if security == "open" || security.contains("wep") {
                Severity::Critical
            } else {
                Severity::High
            },
            title: l.pick("Слабая защита Wi‑Fi", "Weak Wi‑Fi security").to_owned(),
            description: match l {
                Language::Ru => format!(
                    "Текущий режим «{mode}» не обеспечивает современную защиту радиообмена."
                ),
                Language::En => format!(
                    "The current mode, {mode}, does not provide modern protection for wireless traffic."
                ),
            },
            recommendation: Some(
                l.pick(
                    "Не передавайте чувствительные данные без VPN. Для своей сети включите WPA3 или WPA2 AES.",
                    "Avoid sending sensitive data without a VPN. On your own network, enable WPA3 or WPA2 AES.",
                )
                .to_owned(),
            ),
            evidence: vec![api_evidence],
        });
    } else if security.contains("wpa3") || security == "owe" {
        let mode = human_security(&security, l);
        findings.push(Finding {
            id: "wifi-modern-security".to_owned(),
            category: "network".to_owned(),
            severity: Severity::Good,
            title: l
                .pick("Современная защита радиообмена", "Modern wireless security")
                .to_owned(),
            description: match l {
                Language::Ru => format!(
                    "Сеть использует {mode}. Это защищает соединение с точкой доступа, но не делает всю локальную сеть доверенной."
                ),
                Language::En => format!(
                    "The network uses {mode}. This protects the link to the access point but does not make the whole local network trustworthy."
                ),
            },
            recommendation: None,
            evidence: vec![api_evidence],
        });
    } else if security.contains("wpa2") {
        findings.push(Finding {
            id: "wifi-wpa2-security".to_owned(),
            category: "network".to_owned(),
            severity: Severity::Info,
            title: l.pick("Защита WPA2", "WPA2 security").to_owned(),
            description: l
                .pick(
                    "WPA2 остаётся приемлемым при использовании AES и сильного пароля; WPA3 предпочтительнее.",
                    "WPA2 remains acceptable with AES and a strong password; WPA3 is preferable.",
                )
                .to_owned(),
            recommendation: None,
            evidence: vec![api_evidence],
        });
    } else {
        findings.push(Finding {
            id: "wifi-security-unknown".to_owned(),
            category: "coverage".to_owned(),
            severity: Severity::Warning,
            title: l
                .pick("Тип защиты не определён", "Security type unknown")
                .to_owned(),
            description: l
                .pick(
                    "Операционная система не вернула режим безопасности или Wi‑Fi ещё не полностью подключён.",
                    "The operating system did not report the security mode, or Wi‑Fi is not fully connected yet.",
                )
                .to_owned(),
            recommendation: Some(
                l.pick(
                    "Разрешите доступ к геопозиции для Маяка и повторите проверку.",
                    "Allow location access for Mayak and run the check again.",
                )
                .to_owned(),
            ),
            evidence: vec![format!(
                "{}: unknown",
                l.pick("Системный Wi‑Fi API", "System Wi‑Fi API")
            )],
        });
    }

    if network.proxy_enabled {
        findings.push(Finding {
            id: "system-proxy-enabled".to_owned(),
            category: "network".to_owned(),
            severity: Severity::Warning,
            title: l
                .pick("В системе активен прокси", "A system proxy is active")
                .to_owned(),
            description: l
                .pick(
                    "Прокси может быть ожидаемой корпоративной настройкой, но в публичной сети его стоит проверить.",
                    "A proxy may be an expected corporate setting, but on a public network it is worth checking.",
                )
                .to_owned(),
            recommendation: Some(
                l.pick(
                    "Откройте настройки сети и убедитесь, что адрес прокси вам известен.",
                    "Open network settings and make sure you recognize the proxy address.",
                )
                .to_owned(),
            ),
            evidence: vec!["SystemConfiguration: proxy enabled".to_owned()],
        });
    }

    if network.vpn_active {
        findings.push(Finding {
            id: "vpn-active".to_owned(),
            category: "device".to_owned(),
            severity: Severity::Good,
            title: l.pick("VPN-интерфейс активен", "VPN interface active").to_owned(),
            description: l
                .pick(
                    "Системный туннель обнаружен. Маяк сканирует только прямую Wi‑Fi-подсеть и не затрагивает маршруты VPN.",
                    "A system tunnel was detected. Mayak scans only the directly connected Wi‑Fi subnet and does not touch VPN routes.",
                )
                .to_owned(),
            recommendation: None,
            evidence: vec![
                l.pick(
                    "Обнаружен активный туннельный или VPN-интерфейс",
                    "An active tunnel or VPN interface was detected",
                )
                .to_owned(),
            ],
        });
    }

    if let (Some(rssi), Some(quality)) = (network.rssi, network.signal_quality)
        && quality < 30
    {
        findings.push(Finding {
            id: "weak-signal".to_owned(),
            category: "quality".to_owned(),
            severity: Severity::Info,
            title: l
                .pick("Слабый сигнал Wi‑Fi", "Weak Wi‑Fi signal")
                .to_owned(),
            description: l
                .pick(
                    "Потери пакетов могут уменьшить полноту обнаружения устройств.",
                    "Packet loss can reduce how many devices are discovered.",
                )
                .to_owned(),
            recommendation: Some(
                l.pick(
                    "Подойдите ближе к точке доступа и повторите проверку.",
                    "Move closer to the access point and run the check again.",
                )
                .to_owned(),
            ),
            evidence: vec![match l {
                Language::Ru => format!("RSSI: {rssi} dBm, качество: {quality}%"),
                Language::En => format!("RSSI: {rssi} dBm, quality: {quality}%"),
            }],
        });
    }

    findings
}

fn change_evidence(before: Option<&str>, now: Option<&str>, language: Language) -> Vec<String> {
    let unknown = language.pick("неизвестно", "unknown");
    vec![
        format!(
            "{}: {}",
            language.pick("Раньше", "Before"),
            before.unwrap_or(unknown)
        ),
        format!(
            "{}: {}",
            language.pick("Сейчас", "Now"),
            now.unwrap_or(unknown)
        ),
    ]
}

fn network_change_findings(
    network: &NetworkContext,
    previous: Option<&ScanReport>,
    language: Language,
) -> Vec<Finding> {
    let l = language;
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
            title: l
                .pick("Изменилась точка доступа", "Access point changed")
                .to_owned(),
            description: l
                .pick(
                    "У сети с тем же именем другой BSSID. Это нормально для mesh и гостиниц, но изменение сохранено в истории.",
                    "A network with the same name now has a different BSSID. This is normal for mesh systems and hotels, but the change is saved in history.",
                )
                .to_owned(),
            recommendation: None,
            evidence: change_evidence(
                previous.network.bssid.as_deref(),
                network.bssid.as_deref(),
                l,
            ),
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
            title: l
                .pick("Изменился шлюз знакомой сети", "Gateway of a known network changed")
                .to_owned(),
            description: l
                .pick(
                    "У сети с тем же именем теперь другой адрес шлюза. В гостинице это может быть нормально; дома изменение требует проверки.",
                    "A network with the same name now has a different gateway address. That can be normal in a hotel; at home it deserves a closer look.",
                )
                .to_owned(),
            recommendation: Some(
                l.pick(
                    "Сверьте сеть с ожидаемым роутером и проверьте, не подключились ли вы к точке с похожим именем.",
                    "Compare the network with the router you expect and check that you have not joined an access point with a similar name.",
                )
                .to_owned(),
            ),
            evidence: change_evidence(
                previous.network.router.as_deref(),
                network.router.as_deref(),
                l,
            ),
        });
    }

    findings
}

fn visibility_findings(coverage: &ScanCoverage, language: Language) -> Vec<Finding> {
    let l = language;
    let mut findings = Vec::new();
    if coverage.responsive_count <= 1 {
        findings.push(Finding {
            id: "visibility-limited".to_owned(),
            category: "coverage".to_owned(),
            severity: Severity::Info,
            title: l
                .pick("Видимость сети ограничена", "Network visibility is limited")
                .to_owned(),
            description: l
                .pick(
                    "Почти никто, кроме шлюза, не отвечает. Возможны client isolation, фильтрация или отсутствие других активных устройств.",
                    "Almost nothing except the gateway responds. This may be client isolation, filtering, or simply no other active devices.",
                )
                .to_owned(),
            recommendation: None,
            evidence: vec![match l {
                Language::Ru => format!(
                    "Наблюдается {} устройство при {} проверенных адресах",
                    coverage.responsive_count, coverage.target_count
                ),
                Language::En => format!(
                    "{} device observed across {} checked addresses",
                    coverage.responsive_count, coverage.target_count
                ),
            }],
        });
    }
    if coverage.limited_by_subnet_size {
        findings.push(Finding {
            id: "subnet-scan-capped".to_owned(),
            category: "coverage".to_owned(),
            severity: Severity::Info,
            title: l
                .pick(
                    "Проверена ближайшая область подсети",
                    "Only the nearby part of the subnet was checked",
                )
                .to_owned(),
            description: l
                .pick(
                    "Сеть слишком велика для автоматического полного перебора без избыточного трафика.",
                    "The network is too large to sweep automatically without excessive traffic.",
                )
                .to_owned(),
            recommendation: Some(
                l.pick(
                    "Для расширенной проверки можно запустить глубокий режим вручную.",
                    "For a broader check, run a deep scan manually.",
                )
                .to_owned(),
            ),
            evidence: vec![match l {
                Language::Ru => format!("Проверено {} адресов", coverage.target_count),
                Language::En => format!("{} addresses checked", coverage.target_count),
            }],
        });
    }
    findings
}

fn device_findings(devices: &[ObservedDevice], language: Language) -> Vec<Finding> {
    let l = language;
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
            title: match l {
                Language::Ru => format!("Новых устройств: {new_unknown}"),
                Language::En => format!("New devices: {new_unknown}"),
            },
            description: l
                .pick(
                    "Они впервые появились в локальной истории Маяка. В публичной сети это ожидаемо и не означает угрозу.",
                    "They appeared in Mayak's local history for the first time. On a public network this is expected and does not indicate a threat.",
                )
                .to_owned(),
            recommendation: Some(
                l.pick(
                    "В своей сети отметьте знакомые устройства, чтобы следующие изменения были заметнее.",
                    "On your own network, mark devices you recognize so future changes stand out.",
                )
                .to_owned(),
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
                            .map_or(l.pick("без IP", "no IP"), String::as_str)
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

fn risk_summary(risk: Severity, visibility: VisibilityLevel, language: Language) -> String {
    let base = match risk {
        Severity::Critical => language.pick(
            "Обнаружен критичный риск сети.",
            "Critical network risk detected.",
        ),
        Severity::High => language.pick(
            "Есть серьёзные признаки риска.",
            "There are serious signs of risk.",
        ),
        Severity::Warning => language.pick(
            "Есть моменты, которые стоит проверить.",
            "A few things are worth checking.",
        ),
        Severity::Info | Severity::Good => language.pick(
            "Явных рисков по доступным данным не найдено.",
            "No obvious risks found in the available data.",
        ),
    };
    if visibility == VisibilityLevel::Limited {
        format!(
            "{base} {}",
            language.pick(
                "Видимость других устройств ограничена.",
                "Visibility of other devices is limited."
            )
        )
    } else {
        base.to_owned()
    }
}

fn human_security(value: &str, language: Language) -> &'static str {
    match value {
        "open" => language.pick("открытая сеть", "open network"),
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
        _ => language.pick("неизвестная защита", "unknown security"),
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
        i18n::Language,
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
        let assessment = assess(&network("open"), &[], &coverage(3), None, Language::Ru);
        assert_eq!(assessment.risk, Severity::Critical);
    }

    #[test]
    fn wpa3_with_evidence_is_low_risk() {
        let assessment = assess(
            &network("wpa3-personal"),
            &[],
            &coverage(3),
            None,
            Language::Ru,
        );
        assert_eq!(assessment.risk, Severity::Info);
        assert_eq!(assessment.visibility, VisibilityLevel::Good);
    }

    #[test]
    fn one_visible_device_never_claims_full_visibility() {
        let assessment = assess(
            &network("wpa2-personal"),
            &[],
            &coverage(1),
            None,
            Language::Ru,
        );
        assert_eq!(assessment.visibility, VisibilityLevel::Limited);
    }

    #[test]
    fn reviewed_first_seen_device_is_not_reported_as_new() {
        let mut device = finalize_device(
            RawDevice::new(Ipv4Addr::new(192, 168, 1, 42)),
            Utc::now(),
            Language::Ru,
        );
        assert!(device.is_unreviewed_new());

        device.trust_state = TrustState::Known;
        let assessment = assess(
            &network("wpa3-personal"),
            &[device],
            &coverage(3),
            None,
            Language::Ru,
        );

        assert!(
            assessment
                .findings
                .iter()
                .all(|finding| finding.id != "new-devices")
        );
    }

    #[test]
    fn english_findings_contain_no_cyrillic() {
        let assessment = assess(&network("open"), &[], &coverage(1), None, Language::En);
        let text = std::iter::once(assessment.summary.clone())
            .chain(assessment.findings.iter().flat_map(|finding| {
                [finding.title.clone(), finding.description.clone()]
                    .into_iter()
                    .chain(finding.recommendation.clone())
                    .chain(finding.evidence.clone())
            }))
            .collect::<String>();
        assert!(
            !text
                .chars()
                .any(|character| matches!(character, 'А'..='я' | 'Ё' | 'ё'))
        );
        assert!(
            assessment
                .summary
                .starts_with("Critical network risk detected.")
        );
    }
}
