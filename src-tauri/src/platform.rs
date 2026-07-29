use std::net::Ipv4Addr;

#[derive(Debug, Clone, Default)]
pub struct SystemNetworkFacts {
    pub router: Option<String>,
    pub dns_servers: Vec<String>,
    pub proxy_enabled: bool,
    pub interface_mac: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborEntry {
    pub ip: Ipv4Addr,
    pub mac_address: String,
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{network_facts, open_privacy_settings, read_neighbors, resolve_hostname};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{network_facts, open_privacy_settings, read_neighbors, resolve_hostname};

#[cfg(not(any(target_os = "macos", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "macos", windows)))]
pub use unsupported::{network_facts, open_privacy_settings, read_neighbors, resolve_hostname};
