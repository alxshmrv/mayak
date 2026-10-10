use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::process::Command;

use regex::Regex;

use super::{NeighborEntry, SystemNetworkFacts};

pub fn network_facts(interface_name: &str, _interface_index: Option<u32>) -> SystemNetworkFacts {
    SystemNetworkFacts {
        router: default_router_for_interface(interface_name),
        dns_servers: read_dns_servers(),
        proxy_enabled: read_proxy_enabled(),
        interface_mac: read_interface_mac(interface_name),
    }
}

pub fn read_neighbors(interface_name: Option<&str>) -> Vec<NeighborEntry> {
    let Some(output) = Command::new("/usr/sbin/arp")
        .arg("-an")
        .output()
        .ok()
        .filter(|value| value.status.success())
    else {
        return Vec::new();
    };
    parse_arp_table(&String::from_utf8_lossy(&output.stdout), interface_name)
}

pub fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    let output = Command::new("/usr/bin/dscacheutil")
        .args(["-q", "host", "-a", "ip_address"])
        .arg(ip.to_string())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_dscacheutil_hostname(&String::from_utf8_lossy(&output.stdout))
}

pub fn open_privacy_settings(section: &str) -> Result<(), String> {
    let url = match section {
        "localNetwork" => {
            "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork"
        }
        _ => "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices",
    };
    let status = Command::new("/usr/bin/open")
        .arg(url)
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("macOS did not open Privacy & Security settings".to_owned())
    }
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

fn read_interface_mac(interface_name: &str) -> Option<String> {
    let output = Command::new("/sbin/ifconfig")
        .arg(interface_name)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("ether ").map(str::to_owned))
}

fn parse_arp_table(output: &str, interface_name: Option<&str>) -> Vec<NeighborEntry> {
    let Ok(pattern) = Regex::new(
        r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(?P<mac>[0-9a-fA-F:]{11,17})\s+on\s+(?P<interface>\S+)",
    ) else {
        return Vec::new();
    };

    pattern
        .captures_iter(output)
        .filter(|capture| {
            interface_name.is_none_or(|expected| {
                capture
                    .name("interface")
                    .is_some_and(|value| value.as_str() == expected)
            })
        })
        .filter_map(|capture| {
            let ip = capture.name("ip")?.as_str().parse::<Ipv4Addr>().ok()?;
            let mac_address = capture.name("mac")?.as_str().to_owned();
            Some(NeighborEntry { ip, mac_address })
        })
        .collect()
}

fn parse_dscacheutil_hostname(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line.trim().strip_prefix("name:")?.trim();
        (!value.is_empty()
            && value.parse::<Ipv4Addr>().is_err()
            && !value.ends_with(".in-addr.arpa"))
        .then(|| value.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{parse_arp_table, parse_dscacheutil_hostname, parse_route_gateway};

    #[test]
    fn parses_scoped_route_gateway() {
        let output = "\n   route to: default\ndestination: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(parse_route_gateway(output).as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn parses_only_selected_interface_arp_entries() {
        let output = "\
? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n\
? (10.0.0.1) at 00:11:22:33:44:55 on utun4 ifscope [ethernet]\n";
        let records = parse_arp_table(output, Some("en0"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn parses_router_provided_reverse_dns_name() {
        let output = "\
name: printer-lab\n\
alias: 189.2.0.192.in-addr.arpa\n\
ip_address: 192.0.2.189\n";
        assert_eq!(
            parse_dscacheutil_hostname(output).as_deref(),
            Some("printer-lab")
        );
    }
}
