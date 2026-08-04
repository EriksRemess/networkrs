//! Wi-Fi interface and association snapshots from Linux nl80211.
//!
//! The implementation follows `include/uapi/linux/nl80211.h` and resolves the
//! `nl80211` family dynamically through generic netlink. Driver and interface
//! state determine which optional attributes are returned. The snapshot is
//! passive: `GET_SCAN` reads the kernel's existing BSS cache and does not start
//! a wireless scan.

use crate::generic_netlink::{self, Attribute, Client, Message};
use std::collections::HashMap;
use std::io;

const CMD_GET_WIPHY: u8 = 1;
const CMD_GET_INTERFACE: u8 = 5;
const CMD_GET_STATION: u8 = 17;
const CMD_GET_SCAN: u8 = 32;
const CMD_GET_POWER_SAVE: u8 = 62;

const ATTR_WIPHY: u16 = 1;
const ATTR_WIPHY_NAME: u16 = 2;
const ATTR_IFINDEX: u16 = 3;
const ATTR_IFNAME: u16 = 4;
const ATTR_IFTYPE: u16 = 5;
const ATTR_MAC: u16 = 6;
const ATTR_STA_INFO: u16 = 21;
const ATTR_WIPHY_FREQ: u16 = 38;
const ATTR_BSS: u16 = 47;
const ATTR_PS_STATE: u16 = 93;

const BSS_BSSID: u16 = 1;
const BSS_FREQUENCY: u16 = 2;
const BSS_INFORMATION_ELEMENTS: u16 = 6;
const BSS_SIGNAL_MBM: u16 = 7;
const BSS_SIGNAL_UNSPEC: u16 = 8;
const BSS_STATUS: u16 = 9;
const BSS_SEEN_MS_AGO: u16 = 10;
const BSS_STATUS_AUTHENTICATED: u32 = 0;
const BSS_STATUS_ASSOCIATED: u32 = 1;

const STA_INACTIVE_TIME: u16 = 1;
const STA_SIGNAL: u16 = 7;
const STA_TX_BITRATE: u16 = 8;
const STA_RX_PACKETS: u16 = 9;
const STA_TX_PACKETS: u16 = 10;
const STA_TX_RETRIES: u16 = 11;
const STA_TX_FAILED: u16 = 12;
const STA_SIGNAL_AVG: u16 = 13;
const STA_RX_BITRATE: u16 = 14;
const STA_RX_BYTES64: u16 = 23;
const STA_TX_BYTES64: u16 = 24;

const RATE_BITRATE: u16 = 1;
const RATE_MCS: u16 = 2;
const RATE_WIDTH_40: u16 = 3;
const RATE_BITRATE32: u16 = 5;
const RATE_VHT_MCS: u16 = 6;
const RATE_VHT_NSS: u16 = 7;
const RATE_WIDTH_80: u16 = 8;
const RATE_WIDTH_160: u16 = 10;
const RATE_HE_MCS: u16 = 13;
const RATE_HE_NSS: u16 = 14;

/// Consolidated nl80211 view of one Wi-Fi interface.
#[derive(Debug, PartialEq)]
pub struct WifiInterface {
    /// Kernel interface index.
    pub interface_index: u32,
    /// Kernel interface name.
    pub name: String,
    /// Human-readable nl80211 interface type, such as `station`.
    pub interface_type: String,
    /// Interface MAC address in colon-delimited form.
    pub mac: Option<String>,
    /// Numeric wiphy/radio index.
    pub wiphy: Option<u32>,
    /// Kernel wiphy/radio name, such as `phy0`.
    pub wiphy_name: Option<String>,
    /// Current or associated BSS center frequency in MHz.
    pub frequency_mhz: Option<u32>,
    /// Associated network name decoded from the BSS information elements.
    pub ssid: Option<String>,
    /// Associated access-point MAC address.
    pub bssid: Option<String>,
    /// Associated BSS signal in dBm, including fractional mBm precision.
    pub signal_dbm: Option<f32>,
    /// Driver-defined signal quality from 0 through 100 when dBm is unavailable.
    pub signal_unspecified: Option<u8>,
    /// Milliseconds since the associated BSS cache entry was updated.
    pub seen_ms_ago: Option<u32>,
    /// Whether nl80211 power saving is enabled.
    pub power_save: Option<bool>,
    /// Associated peer/station statistics when available.
    pub station: Option<Station>,
}

/// Statistics and link rates for the associated station peer.
#[derive(Debug, PartialEq)]
pub struct Station {
    /// Milliseconds since the peer was last active.
    pub inactive_ms: Option<u32>,
    /// Most recent received signal strength in dBm.
    pub signal_dbm: Option<i8>,
    /// Running average received signal strength in dBm.
    pub average_signal_dbm: Option<i8>,
    /// Total bytes received from the peer.
    pub receive_bytes: Option<u64>,
    /// Total bytes transmitted to the peer.
    pub transmit_bytes: Option<u64>,
    /// Total packets received from the peer.
    pub receive_packets: Option<u32>,
    /// Total packets transmitted to the peer.
    pub transmit_packets: Option<u32>,
    /// Total link-layer transmission retries.
    pub transmit_retries: Option<u32>,
    /// Total failed link-layer transmissions.
    pub transmit_failures: Option<u32>,
    /// Current receive bitrate details.
    pub receive_bitrate: Option<Bitrate>,
    /// Current transmit bitrate details.
    pub transmit_bitrate: Option<Bitrate>,
}

/// Decoded nl80211 bitrate attributes.
#[derive(Debug, PartialEq)]
pub struct Bitrate {
    /// Nominal bitrate in megabits per second.
    pub mbps: f32,
    /// Channel width in MHz; 20 is used when no wider-width flag is present.
    pub width_mhz: Option<u16>,
    /// Modulation and coding scheme index.
    pub mcs: Option<u8>,
    /// Number of spatial streams for VHT or HE rates.
    pub spatial_streams: Option<u8>,
    /// PHY encoding name, currently `VHT` or `HE` when reported.
    pub encoding: Option<&'static str>,
}

/// Returns a passive snapshot of all visible nl80211 interfaces.
///
/// Interface enumeration is required; wiphy names, cached association data,
/// station counters, and power-save state are queried best effort per interface.
/// A failure of one optional per-interface query leaves those fields as `None`.
pub fn interfaces() -> io::Result<Vec<WifiInterface>> {
    let mut client = Client::connect("nl80211")?;
    let wiphys = client
        .request(CMD_GET_WIPHY, 1, true, &[])?
        .into_iter()
        .filter_map(|message| {
            Some((
                u32_attribute(&message, ATTR_WIPHY)?,
                string_attribute(&message, ATTR_WIPHY_NAME)?,
            ))
        })
        .collect::<HashMap<_, _>>();
    let messages = client.request(CMD_GET_INTERFACE, 1, true, &[])?;
    let mut interfaces = messages
        .iter()
        .filter_map(|message| parse_interface(message, &wiphys))
        .collect::<Vec<_>>();

    for interface in &mut interfaces {
        let selector = [Attribute::u32(ATTR_IFINDEX, interface.interface_index)];
        if let Ok(messages) = client.request(CMD_GET_SCAN, 1, true, &selector)
            && let Some(bss) = messages.iter().find_map(parse_connected_bss)
        {
            interface.frequency_mhz = bss.frequency_mhz.or(interface.frequency_mhz);
            interface.ssid = bss.ssid;
            interface.bssid = bss.bssid;
            interface.signal_dbm = bss.signal_dbm;
            interface.signal_unspecified = bss.signal_unspecified;
            interface.seen_ms_ago = bss.seen_ms_ago;
        }
        if let Ok(messages) = client.request(CMD_GET_STATION, 1, true, &selector) {
            interface.station = messages.iter().find_map(parse_station);
        }
        if let Ok(messages) = client.request(CMD_GET_POWER_SAVE, 1, false, &selector) {
            interface.power_save = messages
                .iter()
                .find_map(|message| u32_attribute(message, ATTR_PS_STATE))
                .map(|state| state == 1);
        }
    }
    interfaces.sort_by_key(|interface| interface.interface_index);
    Ok(interfaces)
}

fn parse_interface(message: &Message, wiphys: &HashMap<u32, String>) -> Option<WifiInterface> {
    let wiphy = u32_attribute(message, ATTR_WIPHY);
    Some(WifiInterface {
        interface_index: u32_attribute(message, ATTR_IFINDEX)?,
        name: string_attribute(message, ATTR_IFNAME)?,
        interface_type: interface_type(u32_attribute(message, ATTR_IFTYPE)?),
        mac: bytes_attribute(message, ATTR_MAC).map(format_mac),
        wiphy,
        wiphy_name: wiphy.and_then(|index| wiphys.get(&index).cloned()),
        frequency_mhz: u32_attribute(message, ATTR_WIPHY_FREQ),
        ssid: None,
        bssid: None,
        signal_dbm: None,
        signal_unspecified: None,
        seen_ms_ago: None,
        power_save: None,
        station: None,
    })
}

struct ConnectedBss {
    frequency_mhz: Option<u32>,
    ssid: Option<String>,
    bssid: Option<String>,
    signal_dbm: Option<f32>,
    signal_unspecified: Option<u8>,
    seen_ms_ago: Option<u32>,
}

fn parse_connected_bss(message: &Message) -> Option<ConnectedBss> {
    let attributes = generic_netlink::nested_attributes(bytes_attribute(message, ATTR_BSS)?)?;
    let status = nested_u32(&attributes, BSS_STATUS)?;
    if status != BSS_STATUS_ASSOCIATED && status != BSS_STATUS_AUTHENTICATED {
        return None;
    }
    let information_elements = nested_bytes(&attributes, BSS_INFORMATION_ELEMENTS);
    Some(ConnectedBss {
        frequency_mhz: nested_u32(&attributes, BSS_FREQUENCY),
        ssid: information_elements.and_then(parse_ssid),
        bssid: nested_bytes(&attributes, BSS_BSSID).map(format_mac),
        signal_dbm: nested_u32(&attributes, BSS_SIGNAL_MBM)
            .map(|signal| signal as i32 as f32 / 100.0),
        signal_unspecified: nested_bytes(&attributes, BSS_SIGNAL_UNSPEC)
            .and_then(|value| value.first().copied()),
        seen_ms_ago: nested_u32(&attributes, BSS_SEEN_MS_AGO),
    })
}

fn parse_station(message: &Message) -> Option<Station> {
    let attributes = generic_netlink::nested_attributes(bytes_attribute(message, ATTR_STA_INFO)?)?;
    Some(Station {
        inactive_ms: nested_u32(&attributes, STA_INACTIVE_TIME),
        signal_dbm: nested_i8(&attributes, STA_SIGNAL),
        average_signal_dbm: nested_i8(&attributes, STA_SIGNAL_AVG),
        receive_bytes: nested_u64(&attributes, STA_RX_BYTES64),
        transmit_bytes: nested_u64(&attributes, STA_TX_BYTES64),
        receive_packets: nested_u32(&attributes, STA_RX_PACKETS),
        transmit_packets: nested_u32(&attributes, STA_TX_PACKETS),
        transmit_retries: nested_u32(&attributes, STA_TX_RETRIES),
        transmit_failures: nested_u32(&attributes, STA_TX_FAILED),
        receive_bitrate: nested_bytes(&attributes, STA_RX_BITRATE).and_then(parse_bitrate),
        transmit_bitrate: nested_bytes(&attributes, STA_TX_BITRATE).and_then(parse_bitrate),
    })
}

fn parse_bitrate(value: &[u8]) -> Option<Bitrate> {
    let attributes = generic_netlink::nested_attributes(value)?;
    let mbps = nested_u32(&attributes, RATE_BITRATE32)
        .map(|rate| rate as f32 / 10.0)
        .or_else(|| nested_u16(&attributes, RATE_BITRATE).map(|rate| f32::from(rate) / 10.0))?;
    let (encoding, mcs) = if let Some(mcs) = nested_u8(&attributes, RATE_HE_MCS) {
        (Some("HE"), Some(mcs))
    } else if let Some(mcs) = nested_u8(&attributes, RATE_VHT_MCS) {
        (Some("VHT"), Some(mcs))
    } else {
        (None, nested_u8(&attributes, RATE_MCS))
    };
    Some(Bitrate {
        mbps,
        width_mhz: if has_attribute(&attributes, RATE_WIDTH_160) {
            Some(160)
        } else if has_attribute(&attributes, RATE_WIDTH_80) {
            Some(80)
        } else if has_attribute(&attributes, RATE_WIDTH_40) {
            Some(40)
        } else {
            Some(20)
        },
        mcs,
        spatial_streams: nested_u8(&attributes, RATE_HE_NSS)
            .or_else(|| nested_u8(&attributes, RATE_VHT_NSS)),
        encoding,
    })
}

fn parse_ssid(elements: &[u8]) -> Option<String> {
    let mut offset = 0;
    while elements.len().saturating_sub(offset) >= 2 {
        let kind = elements[offset];
        let length = usize::from(elements[offset + 1]);
        offset += 2;
        if length > elements.len() - offset {
            return None;
        }
        if kind == 0 {
            return std::str::from_utf8(&elements[offset..offset + length])
                .ok()
                .map(str::to_owned);
        }
        offset += length;
    }
    None
}

fn interface_type(kind: u32) -> String {
    match kind {
        1 => "ad-hoc".into(),
        2 => "station".into(),
        3 => "access-point".into(),
        4 => "access-point-vlan".into(),
        5 => "wds".into(),
        6 => "monitor".into(),
        7 => "mesh".into(),
        8 => "p2p-client".into(),
        9 => "p2p-go".into(),
        10 => "p2p-device".into(),
        11 => "ocb".into(),
        12 => "nan".into(),
        value => format!("type-{value}"),
    }
}

fn u32_attribute(message: &Message, kind: u16) -> Option<u32> {
    generic_netlink::native_u32(bytes_attribute(message, kind)?)
}

fn string_attribute(message: &Message, kind: u16) -> Option<String> {
    generic_netlink::string(bytes_attribute(message, kind)?)
}

fn bytes_attribute(message: &Message, kind: u16) -> Option<&[u8]> {
    message
        .attributes
        .iter()
        .find_map(|attribute| (attribute.kind == kind).then_some(attribute.value.as_slice()))
}

fn nested_bytes(attributes: &[Attribute], kind: u16) -> Option<&[u8]> {
    attributes
        .iter()
        .find_map(|attribute| (attribute.kind == kind).then_some(attribute.value.as_slice()))
}

fn nested_u8(attributes: &[Attribute], kind: u16) -> Option<u8> {
    nested_bytes(attributes, kind)?.first().copied()
}

fn nested_i8(attributes: &[Attribute], kind: u16) -> Option<i8> {
    nested_u8(attributes, kind).map(|value| value as i8)
}

fn nested_u16(attributes: &[Attribute], kind: u16) -> Option<u16> {
    generic_netlink::native_u16(nested_bytes(attributes, kind)?)
}

fn nested_u32(attributes: &[Attribute], kind: u16) -> Option<u32> {
    generic_netlink::native_u32(nested_bytes(attributes, kind)?)
}

fn nested_u64(attributes: &[Attribute], kind: u16) -> Option<u64> {
    generic_netlink::native_u64(nested_bytes(attributes, kind)?)
}

fn has_attribute(attributes: &[Attribute], kind: u16) -> bool {
    attributes.iter().any(|attribute| attribute.kind == kind)
}

fn format_mac(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssid_information_element() {
        assert_eq!(
            parse_ssid(&[1, 1, 0x82, 0, 4, b't', b'e', b's', b't']),
            Some("test".into())
        );
        assert_eq!(parse_ssid(&[0, 5, b't']), None);
    }

    #[test]
    fn formats_link_layer_address() {
        assert_eq!(format_mac(&[0, 1, 2, 3, 0xfe, 0xff]), "00:01:02:03:fe:ff");
    }
}
