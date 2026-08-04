//! Link hardware information from the Linux ethtool netlink family.
//!
//! Message and attribute constants follow
//! `include/uapi/linux/ethtool_netlink.h` and its generated companion header.
//! Driver identity is supplemented from sysfs. Drivers may implement only a
//! subset of ethtool operations, so most fields are optional and an empty list
//! can mean that the corresponding information was not supplied.

use crate::generic_netlink::{self, Attribute, Client, Message};
use crate::netlink;
use std::fs;
use std::io;
use std::path::Path;

const CMD_LINKINFO_GET: u8 = 2;
const CMD_LINKMODES_GET: u8 = 4;
const CMD_FEATURES_GET: u8 = 11;
const CMD_EEE_GET: u8 = 23;
const CMD_STATS_GET: u8 = 32;

const HEADER_DEV_INDEX: u16 = 1;

const LINKINFO_PORT: u16 = 2;
const LINKINFO_PHY_ADDRESS: u16 = 3;
const LINKINFO_TP_MDIX: u16 = 4;
const LINKINFO_TRANSCEIVER: u16 = 6;

const LINKMODES_AUTONEG: u16 = 2;
const LINKMODES_OURS: u16 = 3;
const LINKMODES_PEER: u16 = 4;
const LINKMODES_SPEED: u16 = 5;
const LINKMODES_DUPLEX: u16 = 6;
const LINKMODES_LANES: u16 = 9;

const FEATURES_HW: u16 = 2;
const FEATURES_WANTED: u16 = 3;
const FEATURES_ACTIVE: u16 = 4;

const EEE_MODES_OURS: u16 = 2;
const EEE_MODES_PEER: u16 = 3;
const EEE_ACTIVE: u16 = 4;
const EEE_ENABLED: u16 = 5;
const EEE_TX_LPI_ENABLED: u16 = 6;
const EEE_TX_LPI_TIMER: u16 = 7;

const BITSET_BITS: u16 = 3;
const BITSET_VALUE: u16 = 4;
const BITSET_NOMASK: u16 = 1;
const BITSET_SIZE: u16 = 2;
const BITSET_BITS_BIT: u16 = 1;
const BITSET_BIT_INDEX: u16 = 1;
const BITSET_BIT_NAME: u16 = 2;
const BITSET_BIT_VALUE: u16 = 3;

const STATS_HEADER: u16 = 2;
const STATS_GROUPS: u16 = 3;
const STATS_GROUP: u16 = 4;
const STATS_GROUP_ID: u16 = 2;
const STATS_GROUP_STAT: u16 = 4;
const STATS_GROUP_HIST_RX: u16 = 5;
const STATS_GROUP_HIST_TX: u16 = 6;
const STATS_HIST_LOW: u16 = 7;
const STATS_HIST_HIGH: u16 = 8;
const STATS_HIST_VALUE: u16 = 9;

/// Consolidated hardware and link-mode information for one interface.
#[derive(Debug)]
pub struct Device {
    /// Kernel interface index.
    pub interface_index: u32,
    /// Kernel interface name.
    pub name: String,
    /// Driver name resolved through the sysfs `driver` symlink.
    pub driver: Option<String>,
    /// Owning kernel module resolved through sysfs.
    pub driver_module: Option<String>,
    /// Kernel module version string when the module exports one.
    pub driver_version: Option<String>,
    /// Physical port medium, such as `twisted-pair` or `fibre`.
    pub port: Option<String>,
    /// MDIO PHY address when applicable.
    pub phy_address: Option<u8>,
    /// MDI/MDI-X crossover status.
    pub mdix: Option<String>,
    /// Whether the transceiver is internal or external.
    pub transceiver: Option<String>,
    /// Negotiated link speed in megabits per second.
    pub speed_mbps: Option<u32>,
    /// Negotiated duplex mode.
    pub duplex: Option<String>,
    /// Whether link autonegotiation is enabled.
    pub autonegotiation: Option<bool>,
    /// Number of active lanes when reported.
    pub lanes: Option<u32>,
    /// Link modes supported by the local device.
    pub supported_modes: Vec<String>,
    /// Link modes advertised by the peer.
    pub peer_modes: Vec<String>,
    /// Features implemented by the hardware/driver.
    pub hardware_features: Vec<String>,
    /// Feature state requested by the network stack.
    pub wanted_features: Vec<String>,
    /// Features currently active.
    pub active_features: Vec<String>,
    /// Whether Energy Efficient Ethernet is administratively enabled.
    pub eee_enabled: Option<bool>,
    /// Whether the link is currently using Energy Efficient Ethernet.
    pub eee_active: Option<bool>,
    /// Whether transmit low-power-idle mode is enabled.
    pub eee_tx_lpi_enabled: Option<bool>,
    /// Transmit low-power-idle timer in microseconds.
    pub eee_tx_lpi_timer_us: Option<u32>,
    /// Local link modes capable of Energy Efficient Ethernet.
    pub eee_modes: Vec<String>,
    /// Peer-advertised Energy Efficient Ethernet modes.
    pub eee_peer_modes: Vec<String>,
    /// Standardized hardware statistics supplied by the driver.
    pub statistics: Vec<Statistic>,
}

/// One standardized ethtool hardware counter.
#[derive(Debug, Eq, PartialEq)]
pub struct Statistic {
    /// Standard group name, such as `ethernet-mac`, `rmon`, or `phy`.
    pub group: &'static str,
    /// Stable descriptive counter name.
    pub name: String,
    /// Monotonic counter value reported by the driver.
    pub value: u64,
}

/// Returns ethtool information for every visible non-loopback interface.
///
/// Resolving the ethtool generic-netlink family and dumping links are required.
/// Individual ethtool operations are best effort so a driver that rejects one
/// request does not hide the rest of the device information.
pub fn devices() -> io::Result<Vec<Device>> {
    let links = netlink::links()?;
    let mut client = Client::connect("ethtool")?;
    let mut devices = Vec::new();
    for link in links {
        if link.flags.split('|').any(|flag| flag == "loopback") {
            continue;
        }
        let selector = [Attribute::nested(
            1,
            &[Attribute::u32(
                HEADER_DEV_INDEX,
                link.interface_index as u32,
            )],
        )];
        let link_info = query(&mut client, CMD_LINKINFO_GET, &selector);
        let link_modes = query(&mut client, CMD_LINKMODES_GET, &selector);
        let features = query(&mut client, CMD_FEATURES_GET, &selector);
        let eee = query(&mut client, CMD_EEE_GET, &selector);
        let stats_selector = [
            Attribute::nested(
                STATS_HEADER,
                &[Attribute::u32(
                    HEADER_DEV_INDEX,
                    link.interface_index as u32,
                )],
            ),
            requested_stat_groups(),
        ];
        let statistics = query(&mut client, CMD_STATS_GET, &stats_selector)
            .map(|message| parse_statistics(&message))
            .unwrap_or_default();
        let sysfs = Path::new("/sys/class/net").join(&link.name).join("device");
        let link_mode_names = link_modes
            .as_ref()
            .map(|message| bitset_entries(message, LINKMODES_OURS))
            .unwrap_or_default();
        let feature_names = features
            .as_ref()
            .map(|message| bitset_entries(message, FEATURES_HW))
            .unwrap_or_default();
        let eee_mode_names = eee
            .as_ref()
            .map(|message| bitset_entries(message, EEE_MODES_OURS))
            .unwrap_or_default();

        devices.push(Device {
            interface_index: link.interface_index as u32,
            name: link.name,
            driver: symlink_name(sysfs.join("driver")),
            driver_module: symlink_name(sysfs.join("driver/module")),
            driver_version: read_trimmed(sysfs.join("driver/module/version")),
            port: link_info
                .as_ref()
                .and_then(|message| u8_attribute(message, LINKINFO_PORT).map(port_name)),
            phy_address: link_info
                .as_ref()
                .and_then(|message| u8_attribute(message, LINKINFO_PHY_ADDRESS)),
            mdix: link_info
                .as_ref()
                .and_then(|message| u8_attribute(message, LINKINFO_TP_MDIX).map(mdix_name)),
            transceiver: link_info.as_ref().and_then(|message| {
                u8_attribute(message, LINKINFO_TRANSCEIVER).map(transceiver_name)
            }),
            speed_mbps: link_modes
                .as_ref()
                .and_then(|message| u32_attribute(message, LINKMODES_SPEED))
                .filter(|speed| *speed != u32::MAX),
            duplex: link_modes
                .as_ref()
                .and_then(|message| u8_attribute(message, LINKMODES_DUPLEX).map(duplex_name)),
            autonegotiation: link_modes
                .as_ref()
                .and_then(|message| u8_attribute(message, LINKMODES_AUTONEG))
                .map(|value| value != 0),
            lanes: link_modes
                .as_ref()
                .and_then(|message| u32_attribute(message, LINKMODES_LANES)),
            supported_modes: selected_entry_names(&link_mode_names),
            peer_modes: link_modes
                .as_ref()
                .map(|message| {
                    bitset_names_with_reference(message, LINKMODES_PEER, &link_mode_names)
                })
                .unwrap_or_default(),
            hardware_features: selected_entry_names(&feature_names),
            wanted_features: features
                .as_ref()
                .map(|message| {
                    bitset_names_with_reference(message, FEATURES_WANTED, &feature_names)
                })
                .unwrap_or_default(),
            active_features: features
                .as_ref()
                .map(|message| {
                    bitset_names_with_reference(message, FEATURES_ACTIVE, &feature_names)
                })
                .unwrap_or_default(),
            eee_enabled: eee
                .as_ref()
                .and_then(|message| u8_attribute(message, EEE_ENABLED))
                .map(|value| value != 0),
            eee_active: eee
                .as_ref()
                .and_then(|message| u8_attribute(message, EEE_ACTIVE))
                .map(|value| value != 0),
            eee_tx_lpi_enabled: eee
                .as_ref()
                .and_then(|message| u8_attribute(message, EEE_TX_LPI_ENABLED))
                .map(|value| value != 0),
            eee_tx_lpi_timer_us: eee
                .as_ref()
                .and_then(|message| u32_attribute(message, EEE_TX_LPI_TIMER)),
            eee_modes: selected_entry_names(&eee_mode_names),
            eee_peer_modes: eee
                .as_ref()
                .map(|message| {
                    bitset_names_with_reference(message, EEE_MODES_PEER, &eee_mode_names)
                })
                .unwrap_or_default(),
            statistics,
        });
    }
    Ok(devices)
}

fn requested_stat_groups() -> Attribute {
    // Compact ethtool bitset selecting all five currently defined standard groups.
    Attribute::nested(
        STATS_GROUPS,
        &[
            Attribute {
                kind: BITSET_NOMASK,
                value: Vec::new(),
            },
            Attribute::u32(BITSET_SIZE, 5),
            Attribute::u32(BITSET_VALUE, 0x1f),
        ],
    )
}

fn parse_statistics(message: &Message) -> Vec<Statistic> {
    let mut statistics = Vec::new();
    for attribute in message
        .attributes
        .iter()
        .filter(|attribute| attribute.kind == STATS_GROUP)
    {
        let Some(group_attributes) = generic_netlink::nested_attributes(&attribute.value) else {
            continue;
        };
        let Some(group_id) =
            nested_bytes(&group_attributes, STATS_GROUP_ID).and_then(generic_netlink::native_u32)
        else {
            continue;
        };
        for statistic in group_attributes
            .iter()
            .filter(|attribute| attribute.kind == STATS_GROUP_STAT)
        {
            let Some(values) = generic_netlink::nested_attributes(&statistic.value) else {
                continue;
            };
            for value in values {
                if let Some(count) = generic_netlink::native_u64(&value.value) {
                    statistics.push(Statistic {
                        group: statistic_group_name(group_id),
                        name: statistic_name(group_id, value.kind),
                        value: count,
                    });
                }
            }
        }
        for (kind, direction) in [
            (STATS_GROUP_HIST_RX, "receive"),
            (STATS_GROUP_HIST_TX, "transmit"),
        ] {
            for histogram in group_attributes
                .iter()
                .filter(|attribute| attribute.kind == kind)
            {
                let Some(bucket) = generic_netlink::nested_attributes(&histogram.value) else {
                    continue;
                };
                let Some(low) =
                    nested_bytes(&bucket, STATS_HIST_LOW).and_then(generic_netlink::native_u32)
                else {
                    continue;
                };
                let Some(high) =
                    nested_bytes(&bucket, STATS_HIST_HIGH).and_then(generic_netlink::native_u32)
                else {
                    continue;
                };
                let Some(value) =
                    nested_bytes(&bucket, STATS_HIST_VALUE).and_then(generic_netlink::native_u64)
                else {
                    continue;
                };
                statistics.push(Statistic {
                    group: statistic_group_name(group_id),
                    name: format!("{direction}-packets-{low}-{high}-bytes"),
                    value,
                });
            }
        }
    }
    statistics.sort_by(|left, right| {
        (left.group, left.name.as_str()).cmp(&(right.group, right.name.as_str()))
    });
    statistics
}

fn statistic_group_name(group: u32) -> &'static str {
    match group {
        0 => "ethernet-phy",
        1 => "ethernet-mac",
        2 => "ethernet-control",
        3 => "rmon",
        4 => "phy",
        _ => "unknown",
    }
}

fn statistic_name(group: u32, statistic: u16) -> String {
    let name = match (group, statistic) {
        (0, 0) => "symbol-errors",
        (1, 0) => "transmitted-packets",
        (1, 1) => "single-collision-frames",
        (1, 2) => "multiple-collision-frames",
        (1, 3) => "received-packets",
        (1, 4) => "frame-check-sequence-errors",
        (1, 5) => "alignment-errors",
        (1, 6) => "transmitted-bytes",
        (1, 7) => "deferred-transmissions",
        (1, 8) => "late-collisions",
        (1, 9) => "excessive-collisions",
        (1, 10) => "internal-transmit-errors",
        (1, 11) => "carrier-sense-errors",
        (1, 12) => "received-bytes",
        (1, 13) => "internal-receive-errors",
        (1, 14) => "transmitted-multicast-frames",
        (1, 15) => "transmitted-broadcast-frames",
        (1, 16) => "excessive-deferrals",
        (1, 17) => "received-multicast-frames",
        (1, 18) => "received-broadcast-frames",
        (1, 19) => "in-range-length-errors",
        (1, 20) => "out-of-range-length-errors",
        (1, 21) => "frame-too-long-errors",
        (2, 0) => "transmitted-control-frames",
        (2, 1) => "received-control-frames",
        (2, 2) => "unsupported-opcodes-received",
        (3, 0) => "undersize-packets",
        (3, 1) => "oversize-packets",
        (3, 2) => "fragments",
        (3, 3) => "jabbers",
        (4, 0) => "received-packets",
        (4, 1) => "received-bytes",
        (4, 2) => "receive-errors",
        (4, 3) => "transmitted-packets",
        (4, 4) => "transmitted-bytes",
        (4, 5) => "transmit-errors",
        _ => return format!("statistic-{statistic}"),
    };
    name.into()
}

fn query(client: &mut Client, command: u8, selector: &[Attribute]) -> Option<Message> {
    client
        .request(command, 1, false, selector)
        .ok()?
        .into_iter()
        .next()
}

fn bitset_entries(message: &Message, kind: u16) -> Vec<(u32, String, bool)> {
    let Some(bitset) = bytes_attribute(message, kind).and_then(generic_netlink::nested_attributes)
    else {
        return Vec::new();
    };
    let Some(bits) =
        nested_bytes(&bitset, BITSET_BITS).and_then(generic_netlink::nested_attributes)
    else {
        return Vec::new();
    };
    // Ethtool supports verbose list and verbose mask/value encodings. In list
    // form (`NOMASK`) the presence of a bit entry means it is selected; there
    // is intentionally no per-entry VALUE flag. In mask/value form VALUE marks
    // selection. Treating both forms alike is a subtle decoder bug.
    let list = bitset
        .iter()
        .any(|attribute| attribute.kind == BITSET_NOMASK);
    let mut entries = bits
        .iter()
        .filter(|attribute| attribute.kind == BITSET_BITS_BIT)
        .filter_map(|attribute| {
            let bit = generic_netlink::nested_attributes(&attribute.value)?;
            Some((
                nested_bytes(&bit, BITSET_BIT_INDEX).and_then(generic_netlink::native_u32)?,
                nested_bytes(&bit, BITSET_BIT_NAME).and_then(generic_netlink::string)?,
                list || bit
                    .iter()
                    .any(|attribute| attribute.kind == BITSET_BIT_VALUE),
            ))
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|(index, _, _)| *index);
    entries
}

fn selected_entry_names(entries: &[(u32, String, bool)]) -> Vec<String> {
    let mut names = entries
        .iter()
        .filter(|(_, _, selected)| *selected)
        .map(|(_, name, _)| name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn bitset_names_with_reference(
    message: &Message,
    kind: u16,
    reference: &[(u32, String, bool)],
) -> Vec<String> {
    // Some replies carry only indices or a compact bitmap. Use the fully named
    // hardware/supported bitset as the dictionary for wanted, active, and peer
    // values so callers still receive stable names.
    let entries = bitset_entries(message, kind);
    let selected = selected_entry_names(&entries);
    if !selected.is_empty() {
        return selected;
    }
    let Some(bitset) = bytes_attribute(message, kind).and_then(generic_netlink::nested_attributes)
    else {
        return Vec::new();
    };
    if let Some(bits) =
        nested_bytes(&bitset, BITSET_BITS).and_then(generic_netlink::nested_attributes)
    {
        let selected_indices = bits
            .iter()
            .filter(|attribute| attribute.kind == BITSET_BITS_BIT)
            .filter_map(|attribute| {
                let bit = generic_netlink::nested_attributes(&attribute.value)?;
                bit.iter()
                    .any(|attribute| attribute.kind == BITSET_BIT_VALUE)
                    .then(|| {
                        nested_bytes(&bit, BITSET_BIT_INDEX).and_then(generic_netlink::native_u32)
                    })?
            })
            .collect::<Vec<_>>();
        if !selected_indices.is_empty() {
            let mut names = reference
                .iter()
                .filter(|(index, _, _)| selected_indices.contains(index))
                .map(|(_, name, _)| name.clone())
                .collect::<Vec<_>>();
            names.sort();
            return names;
        }
    }
    let Some(value) = nested_bytes(&bitset, BITSET_VALUE) else {
        return Vec::new();
    };
    let mut names = reference
        .iter()
        .filter(|(index, _, _)| {
            value
                .get(*index as usize / 8)
                .is_some_and(|byte| byte & (1 << (*index % 8)) != 0)
        })
        .map(|(_, name, _)| name.clone())
        .collect::<Vec<_>>();
    names.sort();
    names
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

fn u8_attribute(message: &Message, kind: u16) -> Option<u8> {
    bytes_attribute(message, kind)?.first().copied()
}

fn u32_attribute(message: &Message, kind: u16) -> Option<u32> {
    generic_netlink::native_u32(bytes_attribute(message, kind)?)
}

fn port_name(port: u8) -> String {
    match port {
        0 => "twisted-pair".into(),
        1 => "aui".into(),
        2 => "mii".into(),
        3 => "fibre".into(),
        4 => "bnc".into(),
        5 => "direct-attach".into(),
        0xef => "none".into(),
        0xff => "other".into(),
        value => format!("port-{value}"),
    }
}

fn mdix_name(mdix: u8) -> String {
    match mdix {
        0 => "invalid".into(),
        1 => "mdi".into(),
        2 => "mdi-x".into(),
        3 => "automatic".into(),
        value => format!("mdix-{value}"),
    }
}

fn transceiver_name(transceiver: u8) -> String {
    match transceiver {
        0 => "internal".into(),
        1 => "external".into(),
        value => format!("transceiver-{value}"),
    }
}

fn duplex_name(duplex: u8) -> String {
    match duplex {
        0 => "half".into(),
        1 => "full".into(),
        0xff => "unknown".into(),
        value => format!("duplex-{value}"),
    }
}

fn symlink_name(path: impl AsRef<Path>) -> Option<String> {
    fs::read_link(path)
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_owned)
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_common_link_values() {
        assert_eq!(port_name(0), "twisted-pair");
        assert_eq!(duplex_name(1), "full");
        assert_eq!(mdix_name(2), "mdi-x");
    }

    #[test]
    fn parses_standard_statistics_and_histograms() {
        let statistic = Attribute::nested(
            STATS_GROUP_STAT,
            &[Attribute {
                kind: 3,
                value: 42_u64.to_ne_bytes().to_vec(),
            }],
        );
        let histogram = Attribute::nested(
            STATS_GROUP_HIST_RX,
            &[
                Attribute::u32(STATS_HIST_LOW, 64),
                Attribute::u32(STATS_HIST_HIGH, 127),
                Attribute {
                    kind: STATS_HIST_VALUE,
                    value: 9_u64.to_ne_bytes().to_vec(),
                },
            ],
        );
        let nested = Attribute::nested(
            STATS_GROUP,
            &[Attribute::u32(STATS_GROUP_ID, 1), statistic, histogram],
        );
        let message = Message {
            command: CMD_STATS_GET,
            attributes: vec![Attribute {
                kind: STATS_GROUP,
                value: nested.value,
            }],
        };
        assert_eq!(
            parse_statistics(&message),
            vec![
                Statistic {
                    group: "ethernet-mac",
                    name: "receive-packets-64-127-bytes".into(),
                    value: 9,
                },
                Statistic {
                    group: "ethernet-mac",
                    name: "received-packets".into(),
                    value: 42,
                },
            ]
        );
    }
}
