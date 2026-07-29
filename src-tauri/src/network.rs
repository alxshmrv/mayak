use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use if_addrs::{IfAddr, Interface, get_if_addrs};
use sha2::{Digest, Sha256};

use crate::domain::NetworkContext;
use crate::error::{AppError, AppResult};
use crate::native::{NativeWifiSnapshot, wifi_snapshot};

pub fn collect_network_context() -> AppResult<NetworkContext> {
    let native = wifi_snapshot().unwrap_or_else(|_| NativeWifiSnapshot {
        available: false,
        interface_name: None,
        power_on: false,
        ssid: None,
        bssid: None,
        rssi: 0,
        noise: 0,
        transmit_rate: 0.0,
        country_code: None,
        security: "unknown".to_owned(),
        phy_mode: None,
        channel: None,
    });

    let interfaces = get_if_addrs().map_err(|error| AppError::Network(error.to_string()))?;
    let interface_name = select_wifi_interface(&native, &interfaces);
    let selected = interface_name
        .as_deref()
        .and_then(|name| collect_interface_addresses(name, &interfaces));

    let router = interface_name
        .as_deref()
        .and_then(default_router_for_interface);
    let dns_servers = read_dns_servers();
    let proxy_enabled = read_proxy_enabled();
    let vpn_active = interfaces.iter().any(is_active_vpn_interface);

    let ipv4 = selected.as_ref().and_then(|value| value.ipv4);
    let subnet = selected
        .as_ref()
        .and_then(|value| value.ipv4.zip(value.netmask))
        .and_then(|(ip, netmask)| subnet_notation(ip, netmask));
    let ipv6 = selected
        .as_ref()
        .map_or_else(Vec::new, |value| value.ipv6.clone());

    let connected = native.available && native.power_on && ipv4.is_some();
    let network_id = stable_network_id(
        native.ssid.as_deref(),
        native.bssid.as_deref(),
        router.as_deref(),
        subnet.as_deref(),
        interface_name.as_deref(),
    );

    Ok(NetworkContext {
        connected,
        wifi_available: native.available,
        interface_name,
        ssid: native.ssid,
        bssid: native.bssid,
        security: native.security,
        phy_mode: native.phy_mode.filter(|value| value != "unknown"),
        channel: native.channel,
        rssi: (native.rssi != 0).then_some(native.rssi),
        noise: (native.noise != 0).then_some(native.noise),
        signal_quality: signal_quality(native.rssi),
        transmit_rate_mbps: (native.transmit_rate > 0.0).then_some(native.transmit_rate),
        country_code: native.country_code,
        ipv4: ipv4.map(|value| value.to_string()),
        ipv6,
        subnet,
        router,
        dns_servers,
        proxy_enabled,
        vpn_active,
        network_id,
    })
}

#[derive(Debug, Clone)]
struct InterfaceAddresses {
    ipv4: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    ipv6: Vec<String>,
}

fn select_wifi_interface(native: &NativeWifiSnapshot, interfaces: &[Interface]) -> Option<String> {
    if let Some(name) = native.interface_name.as_ref()
        && interfaces
            .iter()
            .any(|item| item.name == *name && !item.addr.ip().is_loopback())
    {
        return Some(name.clone());
    }

    interfaces
        .iter()
        .find(|item| {
            item.name == "en0"
                && matches!(item.addr, IfAddr::V4(ref value) if !value.ip.is_loopback())
        })
        .or_else(|| {
            interfaces.iter().find(|item| {
                item.name.starts_with("en")
                    && matches!(item.addr, IfAddr::V4(ref value) if !value.ip.is_loopback())
            })
        })
        .map(|item| item.name.clone())
}

fn collect_interface_addresses(name: &str, interfaces: &[Interface]) -> Option<InterfaceAddresses> {
    let mut result = InterfaceAddresses {
        ipv4: None,
        netmask: None,
        ipv6: Vec::new(),
    };
    let mut found = false;

    for interface in interfaces.iter().filter(|item| item.name == name) {
        found = true;
        match &interface.addr {
            IfAddr::V4(value) if !value.ip.is_link_local() => {
                if result.ipv4.is_none() {
                    result.ipv4 = Some(value.ip);
                    result.netmask = Some(value.netmask);
                }
            }
            IfAddr::V6(value) if !value.ip.is_loopback() => {
                result.ipv6.push(value.ip.to_string());
            }
            _ => {}
        }
    }

    found.then_some(result)
}

fn default_router_for_interface(interface: &str) -> Option<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "-ifscope", interface, "default"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    parse_route_gateway(&String::from_utf8_lossy(&output.stdout))
}

fn parse_route_gateway(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        (key == "gateway").then(|| value.trim().to_owned())
    })
}

fn read_dns_servers() -> Vec<String> {
    let Some(output) = Command::new("/usr/sbin/scutil")
        .arg("--dns")
        .output()
        .ok()
        .filter(|value| value.status.success())
    else {
        return Vec::new();
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            key.starts_with("nameserver")
                .then(|| value.trim().to_owned())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn read_proxy_enabled() -> bool {
    let Some(output) = Command::new("/usr/sbin/scutil")
        .arg("--proxy")
        .output()
        .ok()
        .filter(|value| value.status.success())
    else {
        return false;
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .any(|(key, value)| key.ends_with("Enable") && value.trim() == "1")
}

fn is_active_vpn_interface(interface: &Interface) -> bool {
    let is_vpn_name = interface.name.starts_with("utun")
        || interface.name.starts_with("ipsec")
        || interface.name.starts_with("ppp");
    is_vpn_name && !interface.addr.ip().is_loopback()
}

fn subnet_notation(ip: Ipv4Addr, netmask: Ipv4Addr) -> Option<String> {
    let mask = u32::from(netmask);
    let prefix = mask.count_ones();
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if mask != expected {
        return None;
    }

    let network = Ipv4Addr::from(u32::from(ip) & mask);
    Some(format!("{network}/{prefix}"))
}

fn signal_quality(rssi: i64) -> Option<u8> {
    if rssi == 0 {
        return None;
    }
    let normalized = ((rssi + 100) * 2).clamp(0, 100);
    u8::try_from(normalized).ok()
}

pub(crate) fn stable_network_id(
    ssid: Option<&str>,
    bssid: Option<&str>,
    router: Option<&str>,
    subnet: Option<&str>,
    interface: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    let topology_is_available = router.is_some() || subnet.is_some();
    let components = if topology_is_available {
        [router, subnet, interface, None, None]
    } else {
        [ssid, bssid, interface, None, None]
    };
    for component in components {
        hasher.update(component.unwrap_or("?").as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())[..20].to_owned()
}

pub fn selected_ipv4(context: &NetworkContext) -> AppResult<Ipv4Addr> {
    context
        .ipv4
        .as_deref()
        .ok_or(AppError::NoIpv4)?
        .parse::<IpAddr>()
        .ok()
        .and_then(|value| match value {
            IpAddr::V4(value) => Some(value),
            IpAddr::V6(_) => None,
        })
        .ok_or(AppError::NoIpv4)
}

#[cfg(test)]
mod tests {
    use super::{parse_route_gateway, signal_quality, stable_network_id, subnet_notation};
    use std::net::Ipv4Addr;

    #[test]
    fn parses_scoped_route_gateway() {
        let output = "\n   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(parse_route_gateway(output).as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn derives_network_from_contiguous_mask() {
        assert_eq!(
            subnet_notation(
                Ipv4Addr::new(192, 168, 10, 42),
                Ipv4Addr::new(255, 255, 255, 0)
            )
            .as_deref(),
            Some("192.168.10.0/24")
        );
    }

    #[test]
    fn rejects_non_contiguous_mask() {
        assert!(
            subnet_notation(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 255, 0)).is_none()
        );
    }

    #[test]
    fn signal_quality_is_bounded() {
        assert_eq!(signal_quality(-100), Some(0));
        assert_eq!(signal_quality(-75), Some(50));
        assert_eq!(signal_quality(-50), Some(100));
        assert_eq!(signal_quality(-30), Some(100));
        assert_eq!(signal_quality(0), None);
    }

    #[test]
    fn stable_id_changes_when_gateway_changes() {
        let first = stable_network_id(
            Some("Hotel"),
            None,
            Some("10.0.0.1"),
            Some("10.0.0.0/24"),
            Some("en0"),
        );
        let second = stable_network_id(
            Some("Hotel"),
            None,
            Some("10.0.0.254"),
            Some("10.0.0.0/24"),
            Some("en0"),
        );
        assert_ne!(first, second);
    }

    #[test]
    fn stable_id_does_not_change_when_macos_hides_wifi_metadata() {
        let visible = stable_network_id(
            Some("Hotel"),
            Some("00:11:22:33:44:55"),
            Some("10.0.0.1"),
            Some("10.0.0.0/24"),
            Some("en0"),
        );
        let hidden = stable_network_id(
            None,
            None,
            Some("10.0.0.1"),
            Some("10.0.0.0/24"),
            Some("en0"),
        );

        assert_eq!(visible, hidden);
    }
}
