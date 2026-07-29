#![allow(
    unsafe_code,
    reason = "This module is the single reviewed FFI boundary to Windows IP Helper, Winsock, Registry, and Shell APIs"
)]

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use std::slice;

use ::windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, HINSTANCE, NO_ERROR};
use ::windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetIpNetTable2, IP_ADAPTER_ADDRESSES_LH, MIB_IPNET_TABLE2,
};
use ::windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, GetNameInfoW, IN_ADDR, IN_ADDR_0, IN_ADDR_0_0, NI_NAMEREQD,
    SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS, WSACleanup, WSADATA, WSAStartup,
    socklen_t,
};
use ::windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use ::windows::Win32::UI::Shell::ShellExecuteW;
use ::windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use ::windows::core::{PCWSTR, w};
use if_addrs::get_if_addrs;

use super::{NeighborEntry, SystemNetworkFacts};

const MAX_LINKED_ITEMS: usize = 256;

struct MibMemory(*mut c_void);

impl Drop for MibMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: IP Helper allocated this table and documents
            // `FreeMibTable` as its matching release function.
            unsafe { FreeMibTable(self.0) };
        }
    }
}

struct WinsockSession;

impl WinsockSession {
    fn start() -> Option<Self> {
        let mut data = WSADATA::default();
        // SAFETY: `data` is valid output storage and version 2.2 is supported
        // by all Windows versions supported by Tauri 2.
        (unsafe { WSAStartup(0x0202, &raw mut data) } == 0).then_some(Self)
    }
}

impl Drop for WinsockSession {
    fn drop(&mut self) {
        // SAFETY: Each successful `WSAStartup` in `start` is balanced exactly
        // once by this call.
        unsafe {
            WSACleanup();
        }
    }
}

pub fn network_facts(interface_name: &str, interface_index: Option<u32>) -> SystemNetworkFacts {
    let index = interface_index.or_else(|| interface_index_by_name(interface_name));
    let mut facts = index.and_then(adapter_facts).unwrap_or_default();
    facts.proxy_enabled = read_proxy_enabled();
    facts
}

pub fn read_neighbors(interface_name: Option<&str>) -> Vec<NeighborEntry> {
    let expected_index = interface_name.and_then(interface_index_by_name);
    let mut pointer = null_mut::<MIB_IPNET_TABLE2>();
    // SAFETY: `pointer` is valid output storage. A successful call transfers
    // an IP Helper allocation that is immediately owned by `MibMemory`.
    let result = unsafe { GetIpNetTable2(AF_INET, &raw mut pointer) };
    if result != NO_ERROR || pointer.is_null() {
        return Vec::new();
    }
    let _memory = MibMemory(pointer.cast());
    // SAFETY: The non-null pointer was returned as a complete variable-length
    // table by `GetIpNetTable2`.
    let table = unsafe { &*pointer };
    let count = usize::try_from(table.NumEntries).unwrap_or_default();
    // SAFETY: `NumEntries` defines the contiguous trailing `Table` array.
    let rows = unsafe { slice::from_raw_parts(table.Table.as_ptr(), count) };

    rows.iter()
        .filter(|row| expected_index.is_none_or(|index| row.InterfaceIndex == index))
        .filter_map(|row| {
            // SAFETY: The table was requested specifically for `AF_INET`, so
            // the IPv4 union member is active for every row.
            let socket = unsafe { row.Address.Ipv4 };
            let ip = ipv4_from_in_addr(socket.sin_addr);
            let length = usize::try_from(row.PhysicalAddressLength)
                .unwrap_or_default()
                .min(row.PhysicalAddress.len());
            let mac_address = format_mac(&row.PhysicalAddress[..length])?;
            Some(NeighborEntry { ip, mac_address })
        })
        .collect()
}

pub fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    let _winsock = WinsockSession::start()?;
    let socket = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_un_b: IN_ADDR_0_0 {
                    s_b1: ip.octets()[0],
                    s_b2: ip.octets()[1],
                    s_b3: ip.octets()[2],
                    s_b4: ip.octets()[3],
                },
            },
        },
        sin_zero: [0; 8],
    };
    let mut hostname = [0_u16; 256];
    // SAFETY: `socket` has the exact `SOCKADDR_IN` layout and remains alive
    // through the call; `hostname` is writable output storage.
    let result = unsafe {
        GetNameInfoW(
            (&raw const socket).cast::<SOCKADDR>(),
            socklen_t(i32::try_from(size_of::<SOCKADDR_IN>()).ok()?),
            Some(&mut hostname),
            None,
            i32::try_from(NI_NAMEREQD).ok()?,
        )
    };
    if result != 0 {
        return None;
    }
    let length = hostname
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(hostname.len());
    let value = String::from_utf16_lossy(&hostname[..length]);
    (!value.is_empty() && value.parse::<Ipv4Addr>().is_err()).then_some(value)
}

pub fn open_privacy_settings(section: &str) -> Result<(), String> {
    let target = if section == "localNetwork" {
        "ms-settings:network-wifi"
    } else {
        "ms-settings:privacy-location"
    };
    let wide = target
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: All string pointers are NUL-terminated and stay alive through
    // the call. `ShellExecuteW` does not retain them.
    let result: HINSTANCE = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize > 32 {
        Ok(())
    } else {
        Err("Windows не открыла системные настройки".to_owned())
    }
}

fn adapter_facts(expected_index: u32) -> Option<SystemNetworkFacts> {
    let buffer = adapter_buffer()?;
    let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    for _ in 0..MAX_LINKED_ITEMS {
        if current.is_null() {
            break;
        }
        // SAFETY: `current` points into the live `buffer` returned by
        // `GetAdaptersAddresses`; the linked list is valid until buffer drop.
        let adapter = unsafe { &*current };
        // SAFETY: `IfIndex` is the documented active member of this header
        // union for `IP_ADAPTER_ADDRESSES`.
        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        if index == expected_index {
            return Some(SystemNetworkFacts {
                router: first_ipv4(adapter.FirstGatewayAddress, |item| {
                    // SAFETY: The linked node is valid while `buffer` lives.
                    unsafe { ((*item).Address, (*item).Next) }
                })
                .map(|value| value.to_string()),
                dns_servers: all_ips(adapter.FirstDnsServerAddress, |item| {
                    // SAFETY: The linked node is valid while `buffer` lives.
                    unsafe { ((*item).Address, (*item).Next) }
                }),
                proxy_enabled: false,
                interface_mac: format_mac(
                    &adapter.PhysicalAddress[..usize::try_from(adapter.PhysicalAddressLength)
                        .unwrap_or_default()
                        .min(adapter.PhysicalAddress.len())],
                ),
            });
        }
        current = adapter.Next;
    }
    None
}

fn adapter_buffer() -> Option<Vec<u64>> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS.0 | GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0;
    let mut bytes = 15_000_u32;
    for _ in 0..3 {
        let byte_count = usize::try_from(bytes).ok()?;
        let word_count = byte_count.div_ceil(size_of::<u64>());
        let mut buffer = vec![0_u64; word_count];
        debug_assert!(align_of::<u64>() >= align_of::<IP_ADAPTER_ADDRESSES_LH>());
        // SAFETY: `buffer` is writable, sufficiently sized, and aligned for
        // `IP_ADAPTER_ADDRESSES_LH`; its size is supplied in bytes.
        let result = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                ::windows::Win32::NetworkManagement::IpHelper::GET_ADAPTERS_ADDRESSES_FLAGS(flags),
                None,
                Some(buffer.as_mut_ptr().cast()),
                &raw mut bytes,
            )
        };
        if result == ERROR_SUCCESS.0 {
            return Some(buffer);
        }
        if result != ERROR_BUFFER_OVERFLOW.0 {
            return None;
        }
    }
    None
}

fn interface_index_by_name(name: &str) -> Option<u32> {
    get_if_addrs().ok()?.into_iter().find_map(|interface| {
        (interface.name == name && matches!(interface.addr, if_addrs::IfAddr::V4(_)))
            .then_some(interface.index)
            .flatten()
    })
}

fn read_proxy_enabled() -> bool {
    let mut enabled = 0_u32;
    let mut size = u32::try_from(size_of::<u32>()).unwrap_or(4);
    // SAFETY: `enabled` and `size` are valid writable storage. The queried
    // value is constrained to `REG_DWORD`.
    let result = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
            w!("ProxyEnable"),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut enabled).cast()),
            Some(&raw mut size),
        )
    };
    result == ERROR_SUCCESS && enabled != 0
}

fn first_ipv4<T>(
    mut current: *mut T,
    next: impl Fn(*mut T) -> (SOCKET_ADDRESS, *mut T),
) -> Option<Ipv4Addr> {
    for _ in 0..MAX_LINKED_ITEMS {
        if current.is_null() {
            return None;
        }
        let (address, following) = next(current);
        if let Some(IpAddr::V4(ip)) = socket_address_ip(address) {
            return Some(ip);
        }
        current = following;
    }
    None
}

fn all_ips<T>(
    mut current: *mut T,
    next: impl Fn(*mut T) -> (SOCKET_ADDRESS, *mut T),
) -> Vec<String> {
    let mut values = BTreeSet::new();
    for _ in 0..MAX_LINKED_ITEMS {
        if current.is_null() {
            break;
        }
        let (address, following) = next(current);
        if let Some(ip) = socket_address_ip(address) {
            values.insert(ip.to_string());
        }
        current = following;
    }
    values.into_iter().collect()
}

fn socket_address_ip(address: SOCKET_ADDRESS) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() || address.iSockaddrLength <= 0 {
        return None;
    }
    // SAFETY: The pointer and length originate from `GetAdaptersAddresses`
    // and remain valid while its backing buffer lives.
    let family = unsafe { (*address.lpSockaddr).sa_family };
    if family == AF_INET
        && usize::try_from(address.iSockaddrLength).ok()? >= size_of::<SOCKADDR_IN>()
    {
        // SAFETY: The address family and size establish the concrete layout.
        // `read_unaligned` avoids relying on the weaker alignment expressed
        // by the generic `SOCKADDR` pointer type.
        let socket = unsafe { address.lpSockaddr.cast::<SOCKADDR_IN>().read_unaligned() };
        return Some(IpAddr::V4(ipv4_from_in_addr(socket.sin_addr)));
    }
    if family == AF_INET6
        && usize::try_from(address.iSockaddrLength).ok()? >= size_of::<SOCKADDR_IN6>()
    {
        // SAFETY: The address family and size establish the concrete layout.
        // `read_unaligned` avoids relying on the weaker alignment expressed
        // by the generic `SOCKADDR` pointer type.
        let socket = unsafe { address.lpSockaddr.cast::<SOCKADDR_IN6>().read_unaligned() };
        // SAFETY: `AF_INET6` establishes the active byte representation of
        // the initialized `IN6_ADDR` union.
        let bytes = unsafe { socket.sin6_addr.u.Byte };
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}

fn ipv4_from_in_addr(value: IN_ADDR) -> Ipv4Addr {
    // SAFETY: Reading the byte view of `IN_ADDR` is valid for every initialized
    // IPv4 address regardless of which union view populated it.
    let bytes = unsafe { value.S_un.S_un_b };
    Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4)
}

fn format_mac(bytes: &[u8]) -> Option<String> {
    (bytes.len() >= 6 && bytes.iter().take(6).any(|value| *value != 0)).then(|| {
        bytes
            .iter()
            .take(6)
            .map(|value| format!("{value:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

#[cfg(test)]
mod tests {
    use super::format_mac;

    #[test]
    fn formats_only_valid_physical_addresses() {
        assert_eq!(
            format_mac(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]).as_deref(),
            Some("10:20:30:40:50:60")
        );
        assert_eq!(format_mac(&[0; 6]), None);
        assert_eq!(format_mac(&[1, 2]), None);
    }
}
