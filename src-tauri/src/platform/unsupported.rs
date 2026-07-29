use std::net::Ipv4Addr;

use super::{NeighborEntry, SystemNetworkFacts};

pub fn network_facts(_interface_name: &str, _interface_index: Option<u32>) -> SystemNetworkFacts {
    SystemNetworkFacts::default()
}

pub fn read_neighbors(_interface_name: Option<&str>) -> Vec<NeighborEntry> {
    Vec::new()
}

pub fn resolve_hostname(_ip: Ipv4Addr) -> Option<String> {
    None
}

pub fn open_privacy_settings(_section: &str) -> Result<(), String> {
    Err("Настройки этой операционной системы пока не поддерживаются".to_owned())
}
