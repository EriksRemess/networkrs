//! Best-effort MAC vendor lookup from an already-installed IEEE OUI database.
//!
//! This module never downloads vendor data. Locally administered MAC addresses
//! are deliberately classified as private/randomized because their prefix is
//! not reliable evidence of the hardware vendor.

use std::collections::HashMap;
use std::fs;

const DATABASE_PATHS: [&str; 3] = [
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/hwdata/oui.txt",
    "/usr/share/misc/oui.txt",
];

/// Mapping from a 24-bit organizational prefix to its registered vendor name.
pub type Vendors = HashMap<u32, String>;

/// Loads the first recognized system OUI database that is present.
///
/// Returns an empty map when no supported database exists or it cannot be read.
pub fn load() -> Vendors {
    let Some(contents) = DATABASE_PATHS
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
    else {
        return HashMap::new();
    };

    contents.lines().filter_map(parse_line).collect()
}

/// Returns the best-effort vendor label for a colon-delimited MAC address.
///
/// Locally administered addresses return `private/randomized`. Globally
/// administered addresses return `None` when their prefix is not in `vendors`
/// or when `address` is malformed.
pub fn vendor(address: &str, vendors: &Vendors) -> Option<String> {
    let mut octets = address.split(':');
    let first = u8::from_str_radix(octets.next()?, 16).ok()?;
    let second = u8::from_str_radix(octets.next()?, 16).ok()?;
    let third = u8::from_str_radix(octets.next()?, 16).ok()?;

    if first & 0x01 != 0 {
        return None;
    }
    if first & 0x02 != 0 {
        return Some("private/randomized".into());
    }
    vendors.get(&key(first, second, third)).cloned()
}

fn parse_line(line: &str) -> Option<(u32, String)> {
    let (prefix, vendor) = line.split_once("(hex)")?;
    let mut octets = prefix.trim().split('-');
    let first = u8::from_str_radix(octets.next()?, 16).ok()?;
    let second = u8::from_str_radix(octets.next()?, 16).ok()?;
    let third = u8::from_str_radix(octets.next()?, 16).ok()?;
    if octets.next().is_some() {
        return None;
    }
    let vendor = vendor.trim();
    if vendor.is_empty() {
        return None;
    }
    Some((key(first, second, third), vendor.into()))
}

const fn key(first: u8, second: u8, third: u8) -> u32 {
    ((first as u32) << 16) | ((second as u32) << 8) | third as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ieee_database_lines() {
        assert_eq!(
            parse_line("D0-11-E5   (hex)\t\tExample Networks"),
            Some((0xd011e5, "Example Networks".into()))
        );
        assert_eq!(parse_line("not an assignment"), None);
    }

    #[test]
    fn resolves_global_and_private_prefixes() {
        let vendors = HashMap::from([(0xd011e5, "Example Networks".into())]);
        assert_eq!(
            vendor("d0:11:e5:7d:e9:df", &vendors),
            Some("Example Networks".into())
        );
        assert_eq!(
            vendor("c6:46:71:6d:30:7f", &vendors),
            Some("private/randomized".into())
        );
        assert_eq!(vendor("01:00:5e:00:00:fb", &vendors), None);
    }
}
