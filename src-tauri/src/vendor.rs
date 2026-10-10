use std::collections::HashMap;
use std::sync::OnceLock;

const IEEE_ASSIGNMENTS: &str = include_str!("../data/ieee-ma.tsv");

static VENDORS: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

pub fn vendor_for_mac(mac: &str) -> Option<String> {
    if is_locally_administered(mac) {
        return None;
    }

    let compact = compact_mac(mac)?;
    let vendors = VENDORS.get_or_init(parse_assignments);
    [9, 7, 6]
        .into_iter()
        .filter_map(|length| compact.get(..length))
        .find_map(|prefix| vendors.get(prefix).copied())
        .map(readable_vendor)
        .map(str::to_owned)
}

pub fn is_locally_administered(mac: &str) -> bool {
    mac.split([':', '-'])
        .next()
        .and_then(|octet| u8::from_str_radix(octet, 16).ok())
        .is_some_and(|octet| octet & 0b10 != 0)
}

fn compact_mac(mac: &str) -> Option<String> {
    let compact = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|character| character.to_ascii_uppercase())
        .collect::<String>();
    (compact.len() == 12).then_some(compact)
}

fn parse_assignments() -> HashMap<&'static str, &'static str> {
    IEEE_ASSIGNMENTS
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.splitn(3, '\t');
            let _bits = fields.next()?;
            Some((fields.next()?, fields.next()?))
        })
        .collect()
}

fn readable_vendor(registered_name: &str) -> &str {
    match registered_name {
        "Apple, Inc." => "Apple",
        "Beijing Xiaomi Mobile Software Co., Ltd" => "Xiaomi",
        "TP-Link Systems Inc" => "TP-Link",
        "Tuya Smart Inc." => "Tuya",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::{is_locally_administered, vendor_for_mac};

    #[test]
    fn resolves_real_ieee_assignments_from_all_lengths() {
        assert_eq!(vendor_for_mac("50:8b:b9:62:28:f8").as_deref(), Some("Tuya"));
        assert_eq!(
            vendor_for_mac("1c:ea:ac:1d:71:e4").as_deref(),
            Some("Xiaomi")
        );
        assert_eq!(
            vendor_for_mac("d8:44:89:3b:3c:00").as_deref(),
            Some("TP-Link")
        );
    }

    #[test]
    fn randomized_mac_does_not_claim_a_vendor() {
        assert!(is_locally_administered("a2:e8:06:f2:e2:80"));
        assert_eq!(vendor_for_mac("a2:e8:06:f2:e2:80"), None);
    }
}
