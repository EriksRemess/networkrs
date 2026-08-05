//! Typed route-netlink access for links and IP network configuration.
//!
//! Wire layouts and constants follow Linux headers including `netlink.h`,
//! `rtnetlink.h`, `if_link.h`, `if_addr.h`, `neighbour.h`, and `fib_rules.h`.
//! Fixed fields are native endian; IP addresses are network-order byte
//! sequences; messages and attributes are aligned to four bytes. Parsers
//! validate declared lengths before reading unaligned C-layout values.
//!
//! Dump functions return point-in-time snapshots. An interrupted dump is
//! surfaced as an I/O error instead of a silently partial result.

use std::ffi::{c_int, c_void};
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::OnceLock;

// Socket and framing constants from linux/socket.h and linux/netlink.h.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_NETLINK: c_int = 16;
const SOCK_RAW: c_int = 3;
const NETLINK_ROUTE: c_int = 0;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x100 | 0x200;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_ERROR: u16 = 0x02;
const NLMSG_DONE: u16 = 0x03;
const NLMSG_OVERRUN: u16 = 0x04;
// Route-netlink message types from linux/rtnetlink.h.
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;
const RTM_NEWRULE: u16 = 32;
const RTM_GETRULE: u16 = 34;

// Legacy route-netlink multicast group masks from linux/rtnetlink.h.
const RTMGRP_LINK: u32 = 0x01;
const RTMGRP_NEIGH: u32 = 0x04;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

// Attribute identifiers retain their UAPI prefixes so the parser can be
// compared directly with neighbour.h, if_addr.h, if_link.h, rtnetlink.h, and
// fib_rules.h.
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_CACHEINFO: u16 = 3;
const NDA_PROBES: u16 = 4;
const NDA_MASTER: u16 = 9;
const NDA_PROTOCOL: u16 = 12;
const NDA_FLAGS_EXT: u16 = 15;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_QDISC: u16 = 6;
const IFLA_MASTER: u16 = 10;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKINFO: u16 = 18;
const IFLA_IFALIAS: u16 = 20;
const IFLA_GROUP: u16 = 27;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_CARRIER: u16 = 33;
const IFLA_CARRIER_CHANGES: u16 = 35;
const IFLA_PHYS_PORT_NAME: u16 = 38;
const IFLA_CARRIER_UP_COUNT: u16 = 47;
const IFLA_CARRIER_DOWN_COUNT: u16 = 48;
const IFLA_MIN_MTU: u16 = 50;
const IFLA_MAX_MTU: u16 = 51;
const IFLA_PROP_LIST: u16 = 52;
const IFLA_ALT_IFNAME: u16 = 53;
const IFLA_PARENT_DEV_NAME: u16 = 56;
const IFLA_PARENT_DEV_BUS_NAME: u16 = 57;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_VLAN_ID: u16 = 1;
const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;
const FRA_DST: u16 = 1;
const FRA_SRC: u16 = 2;
const FRA_IIFNAME: u16 = 3;
const FRA_GOTO: u16 = 4;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_OIFNAME: u16 = 17;
const NLA_TYPE_MASK: u16 = 0x3fff;

const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;

const REQUEST_SEQUENCE: u32 = 1;
const ADDRESS_SEQUENCE: u32 = 3;
const ROUTE_DUMP_SEQUENCE: u32 = 4;
const RULE_DUMP_SEQUENCE: u32 = 5;
const LINK_DUMP_SEQUENCE: u32 = 6;

const IFA_F_SECONDARY: u32 = 0x01;
const IFA_F_NODAD: u32 = 0x02;
const IFA_F_OPTIMISTIC: u32 = 0x04;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_HOMEADDRESS: u32 = 0x10;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_F_MANAGETEMPADDR: u32 = 0x100;
const IFA_F_NOPREFIXROUTE: u32 = 0x200;
const IFA_F_MCAUTOJOIN: u32 = 0x400;
const IFA_F_STABLE_PRIVACY: u32 = 0x800;

/// One IPv4 or IPv6 neighbor-table entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Neighbor {
    /// Neighbor IPv4 or IPv6 address.
    pub address: IpAddr,
    /// Link-layer address in colon-delimited form, when resolved.
    pub link_address: Option<String>,
    /// Interface index on which the neighbor exists.
    pub interface_index: i32,
    /// Human-readable neighbor unreachability detection state.
    pub state: String,
    /// Pipe-delimited neighbor flags, or `none`.
    pub flags: String,
    /// Origin protocol when the kernel supplies `NDA_PROTOCOL`.
    pub protocol: Option<String>,
    /// Route type associated with the entry, normally `unicast`.
    pub kind: String,
    /// Number of probes recorded by the neighbor cache.
    pub probes: Option<u32>,
    /// Milliseconds since reachability was last confirmed.
    pub confirmed_ms_ago: Option<u64>,
    /// Milliseconds since the entry was last used.
    pub used_ms_ago: Option<u64>,
    /// Milliseconds since the entry was last updated.
    pub updated_ms_ago: Option<u64>,
    /// Kernel neighbor-cache reference count.
    pub reference_count: Option<u32>,
    /// Master-interface index for stacked devices.
    pub master_index: Option<i32>,
}

/// One IPv4 or IPv6 route returned by a dump or destination lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    /// Destination address; unspecified with prefix zero means the default route.
    pub destination: IpAddr,
    /// Destination prefix length in bits.
    pub prefix: u8,
    /// Optional source selector and prefix length.
    pub source_prefix: Option<(IpAddr, u8)>,
    /// Next-hop gateway, or `None` for a directly connected route.
    pub gateway: Option<IpAddr>,
    /// Output interface index.
    pub interface_index: Option<i32>,
    /// Route priority/metric.
    pub metric: Option<u32>,
    /// Preferred source address selected by the kernel.
    pub source: Option<IpAddr>,
    /// Numeric routing-table identifier.
    pub table: u32,
    /// Human-readable route protocol.
    pub protocol: String,
    /// Human-readable route scope.
    pub scope: String,
    /// Human-readable route type, such as `unicast` or `local`.
    pub kind: String,
    /// Multipath next hops; empty for an ordinary route.
    pub next_hops: Vec<NextHop>,
}

/// One next hop nested in a multipath route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NextHop {
    /// Next-hop gateway, or `None` for a directly connected hop.
    pub gateway: Option<IpAddr>,
    /// Output interface index.
    pub interface_index: i32,
    /// Relative weight, normalized from Linux's zero-based hops field.
    pub weight: u16,
    /// Pipe-delimited next-hop flags, or `none`.
    pub flags: String,
}

/// Internet protocol address family used by a kernel record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpFamily {
    /// Internet Protocol version 4.
    Ipv4,
    /// Internet Protocol version 6.
    Ipv6,
}

impl std::fmt::Display for IpFamily {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        })
    }
}

/// One IPv4 or IPv6 policy-routing rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    /// Address family to which this rule applies.
    pub family: IpFamily,
    /// Priority; lower values are evaluated first.
    pub priority: u32,
    /// Optional source selector and prefix.
    pub source: Option<(IpAddr, u8)>,
    /// Optional destination selector and prefix.
    pub destination: Option<(IpAddr, u8)>,
    /// Optional input-interface selector.
    pub input_interface: Option<String>,
    /// Optional output-interface selector.
    pub output_interface: Option<String>,
    /// Optional firewall-mark value.
    pub fwmark: Option<u32>,
    /// Mask applied to [`Rule::fwmark`].
    pub fwmask: Option<u32>,
    /// Numeric table used by a lookup action.
    pub table: u32,
    /// Human-readable action, such as `lookup` or `unreachable`.
    pub action: String,
    /// Target priority for a `goto` action.
    pub goto: Option<u32>,
    /// Pipe-delimited rule flags, or `none`.
    pub flags: String,
}

/// Kernel link topology and metadata for one interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    /// Kernel interface index.
    pub interface_index: i32,
    /// Kernel interface name.
    pub name: String,
    /// Link-info kind, such as `vlan`, when present.
    pub kind: Option<String>,
    /// ARPHRD hardware type number.
    pub hardware_type: u16,
    /// Pipe-delimited interface flags.
    pub flags: String,
    /// Effective state; loopback is normalized from `IFF_UP`.
    pub operational_state: String,
    /// Carrier state when supplied by the kernel.
    pub carrier: Option<bool>,
    /// Current MTU in bytes.
    pub mtu: Option<u32>,
    /// Minimum supported MTU in bytes.
    pub minimum_mtu: Option<u32>,
    /// Maximum supported MTU in bytes.
    pub maximum_mtu: Option<u32>,
    /// Parent link index for stacked links.
    pub parent_index: Option<i32>,
    /// Master link index for bridge, bond, or similar membership.
    pub master_index: Option<i32>,
    /// Queuing-discipline name.
    pub qdisc: Option<String>,
    /// Configured transmit queue length.
    pub transmit_queue_length: Option<u32>,
    /// User-defined interface alias.
    pub alias: Option<String>,
    /// Alternative interface names.
    pub alternative_names: Vec<String>,
    /// VLAN identifier for VLAN links.
    pub vlan_id: Option<u16>,
    /// Numeric link group.
    pub group: Option<u32>,
    /// Number of promiscuous-mode references.
    pub promiscuity: Option<u32>,
    /// Number of transmit queues.
    pub transmit_queues: Option<u32>,
    /// Number of receive queues.
    pub receive_queues: Option<u32>,
    /// Total carrier transitions.
    pub carrier_changes: Option<u32>,
    /// Number of carrier-up transitions.
    pub carrier_up_count: Option<u32>,
    /// Number of carrier-down transitions.
    pub carrier_down_count: Option<u32>,
    /// Driver-supplied physical port name.
    pub physical_port_name: Option<String>,
    /// Parent device name, commonly a PCI address.
    pub parent_device_name: Option<String>,
    /// Parent bus name, such as `pci`.
    pub parent_device_bus_name: Option<String>,
}

/// One configured IPv4 or IPv6 interface address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    /// Local interface address.
    pub local: IpAddr,
    /// Prefix length in bits.
    pub prefix: u8,
    /// Point-to-point peer when different from the local address.
    pub peer: Option<IpAddr>,
    /// Broadcast address when supplied.
    pub broadcast: Option<IpAddr>,
    /// Owning interface index.
    pub interface_index: i32,
    /// Kernel address label, commonly the interface name.
    pub label: Option<String>,
    /// Human-readable address scope.
    pub scope: &'static str,
    /// Pipe-delimited address flags, or `none`.
    pub flags: String,
    /// Preferred lifetime in seconds, or `None` for forever/unspecified.
    pub preferred_lifetime: Option<u32>,
    /// Valid lifetime in seconds, or `None` for forever/unspecified.
    pub valid_lifetime: Option<u32>,
}

/// A route-netlink multicast notification.
#[derive(Debug, Eq, PartialEq)]
pub enum NetworkEvent {
    /// A link was added, changed, or removed.
    Link {
        /// Whether the link was removed.
        removed: bool,
        /// Kernel interface index.
        interface_index: i32,
        /// Interface name when included in the notification.
        name: Option<String>,
        /// Whether `IFF_UP` is set.
        up: bool,
    },
    /// An IPv4 or IPv6 address was added or removed.
    Address {
        /// Whether the address was removed.
        removed: bool,
        /// Owning interface index.
        interface_index: i32,
        /// Local IPv4 or IPv6 address.
        address: IpAddr,
        /// Prefix length in bits.
        prefix: u8,
    },
    /// An IPv4 or IPv6 route changed or was removed.
    Route {
        /// Whether the route was removed.
        removed: bool,
        /// Parsed route carried by the notification.
        route: Route,
    },
    /// An IPv4 or IPv6 neighbor changed or was removed.
    Neighbor {
        /// Whether the neighbor was removed.
        removed: bool,
        /// Parsed neighbor carried by the notification.
        neighbor: Neighbor,
    },
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketAddress {
    family: u16,
    padding: u16,
    port_id: u32,
    groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MessageHeader {
    length: u32,
    message_type: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NeighborMessage {
    family: u8,
    padding_1: u8,
    padding_2: u16,
    interface_index: i32,
    state: u16,
    flags: u8,
    message_type: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NeighborRequest {
    header: MessageHeader,
    message: NeighborMessage,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NeighborCacheInfo {
    confirmed: u32,
    used: u32,
    updated: u32,
    reference_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AddressRequest {
    header: MessageHeader,
    message: AddressMessage,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteRequest {
    header: MessageHeader,
    message: RouteMessage,
    destination_attribute: RouteAttribute,
    destination: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteRequest6 {
    header: MessageHeader,
    message: RouteMessage,
    destination_attribute: RouteAttribute,
    destination: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteDumpRequest {
    header: MessageHeader,
    message: RouteMessage,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RuleRequest {
    header: MessageHeader,
    message: RuleMessage,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinkRequest {
    header: MessageHeader,
    message: LinkMessage,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinkMessage {
    family: u8,
    padding: u8,
    link_type: u16,
    interface_index: i32,
    flags: u32,
    change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AddressMessage {
    family: u8,
    prefix: u8,
    flags: u8,
    scope: u8,
    interface_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AddressCacheInfo {
    preferred: u32,
    valid: u32,
    _created: u32,
    _updated: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteMessage {
    family: u8,
    destination_prefix: u8,
    source_prefix: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    route_type: u8,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RuleMessage {
    family: u8,
    destination_prefix: u8,
    source_prefix: u8,
    tos: u8,
    table: u8,
    reserved_1: u8,
    reserved_2: u8,
    action: u8,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteNextHop {
    length: u16,
    flags: u8,
    hops: u8,
    interface_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RouteAttribute {
    length: u16,
    attribute_type: u16,
}

unsafe extern "C" {
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn bind(socket: c_int, address: *const c_void, address_length: u32) -> c_int;
    fn sendto(
        socket: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const c_void,
        address_length: u32,
    ) -> isize;
    fn recv(socket: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
    fn sysconf(name: c_int) -> isize;
}

/// Dumps the current IPv4 neighbor table with `RTM_GETNEIGH`.
///
/// Entries are sorted by interface and address. Kernel `NOARP` pseudo-entries
/// and unresolved entries without useful state are omitted; real removal
/// notifications remain available through [`watch_events`].
pub fn ipv4_neighbors() -> io::Result<Vec<Neighbor>> {
    neighbors(AF_INET)
}

/// Dumps the current IPv6 neighbor table with `RTM_GETNEIGH`.
///
/// Entries are sorted by interface and address. Calling this function is
/// passive; it does not send neighbor solicitations.
pub fn ipv6_neighbors() -> io::Result<Vec<Neighbor>> {
    neighbors(AF_INET6)
}

/// Dumps both IPv4 and IPv6 neighbor tables.
pub fn ip_neighbors() -> io::Result<Vec<Neighbor>> {
    let mut entries = ipv4_neighbors()?;
    match ipv6_neighbors() {
        Ok(ipv6) => entries.extend(ipv6),
        Err(error) if ipv6_unavailable(&error) => {}
        Err(error) => return Err(error),
    }
    entries.sort_by_key(|neighbor| (neighbor.interface_index, neighbor.address));
    Ok(entries)
}

fn neighbors(family: u8) -> io::Result<Vec<Neighbor>> {
    let socket = open_route_socket(0)?;
    send_neighbor_request(&socket, family)?;

    let mut neighbors = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        // SAFETY: buffer is writable for buffer.len() bytes and socket is a live fd.
        let received = unsafe {
            recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "netlink socket closed before the dump completed",
            ));
        }

        if parse_response(
            &buffer[..received as usize],
            REQUEST_SEQUENCE,
            &mut neighbors,
        )? {
            break;
        }
    }

    neighbors.retain(|neighbor| ip_address_matches_family(neighbor.address, family));
    neighbors.sort_by_key(|neighbor| (neighbor.interface_index, neighbor.address));
    Ok(neighbors)
}

/// Dumps configured IPv4 addresses with `RTM_GETADDR`.
///
/// Results are sorted by interface index and local address.
pub fn ipv4_addresses() -> io::Result<Vec<Address>> {
    addresses_for_family(AF_INET)
}

/// Dumps configured IPv6 addresses with `RTM_GETADDR`.
///
/// Results are sorted by interface index and local address.
pub fn ipv6_addresses() -> io::Result<Vec<Address>> {
    addresses_for_family(AF_INET6)
}

/// Dumps configured IPv4 and IPv6 interface addresses.
pub fn ip_addresses() -> io::Result<Vec<Address>> {
    let mut addresses = ipv4_addresses()?;
    match ipv6_addresses() {
        Ok(ipv6) => addresses.extend(ipv6),
        Err(error) if ipv6_unavailable(&error) => {}
        Err(error) => return Err(error),
    }
    addresses.sort_by_key(|address| (address.interface_index, address.local, address.prefix));
    Ok(addresses)
}

fn addresses_for_family(family: u8) -> io::Result<Vec<Address>> {
    let socket = open_route_socket(0)?;
    send_address_request(&socket, family)?;

    let mut addresses = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let received = receive(&socket, &mut buffer)?;
        if parse_address_response(&buffer[..received], ADDRESS_SEQUENCE, &mut addresses)? {
            break;
        }
    }

    addresses.retain(|address| ip_address_matches_family(address.local, family));
    addresses.sort_by_key(|address| (address.interface_index, address.local));
    Ok(addresses)
}

/// Dumps IPv4 routes from every routing table with `RTM_GETROUTE`.
///
/// This includes local, main, custom, and policy-selected tables rather than
/// only the conventional main table. Results are sorted by table and target.
pub fn ipv4_routes() -> io::Result<Vec<Route>> {
    routes_for_family(AF_INET)
}

/// Dumps IPv6 routes from every routing table with `RTM_GETROUTE`.
pub fn ipv6_routes() -> io::Result<Vec<Route>> {
    routes_for_family(AF_INET6)
}

/// Dumps IPv4 and IPv6 routes from every routing table.
pub fn ip_routes() -> io::Result<Vec<Route>> {
    let mut routes = ipv4_routes()?;
    match ipv6_routes() {
        Ok(ipv6) => routes.extend(ipv6),
        Err(error) if ipv6_unavailable(&error) => {}
        Err(error) => return Err(error),
    }
    routes.sort_by_key(|route| (route.table, route.destination, route.prefix, route.metric));
    Ok(routes)
}

fn routes_for_family(family: u8) -> io::Result<Vec<Route>> {
    let socket = open_route_socket(0)?;
    let request = RouteDumpRequest {
        header: MessageHeader {
            length: size_of::<RouteDumpRequest>() as u32,
            message_type: RTM_GETROUTE,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            sequence: ROUTE_DUMP_SEQUENCE,
            port_id: 0,
        },
        message: RouteMessage {
            family,
            destination_prefix: 0,
            source_prefix: 0,
            tos: 0,
            table: 0,
            protocol: 0,
            scope: 0,
            route_type: 0,
            flags: 0,
        },
    };
    send_request(&socket, &request)?;
    let mut routes = receive_dump(
        &socket,
        ROUTE_DUMP_SEQUENCE,
        RTM_NEWROUTE,
        "route",
        parse_route,
    )?;
    routes.retain(|route| ip_address_matches_family(route.destination, family));
    routes.sort_by_key(|route| (route.table, route.destination, route.prefix, route.metric));
    Ok(routes)
}

/// Dumps IPv4 policy-routing rules with `RTM_GETRULE`.
///
/// Results are ordered by ascending rule priority.
pub fn ipv4_rules() -> io::Result<Vec<Rule>> {
    rules_for_family(AF_INET)
}

/// Dumps IPv6 policy-routing rules with `RTM_GETRULE`.
pub fn ipv6_rules() -> io::Result<Vec<Rule>> {
    rules_for_family(AF_INET6)
}

/// Dumps IPv4 and IPv6 policy-routing rules.
pub fn ip_rules() -> io::Result<Vec<Rule>> {
    let mut rules = ipv4_rules()?;
    match ipv6_rules() {
        Ok(ipv6) => rules.extend(ipv6),
        Err(error) if ipv6_unavailable(&error) => {}
        Err(error) => return Err(error),
    }
    rules.sort_by_key(|rule| rule.priority);
    Ok(rules)
}

fn rules_for_family(family: u8) -> io::Result<Vec<Rule>> {
    let socket = open_route_socket(0)?;
    let request = RuleRequest {
        header: MessageHeader {
            length: size_of::<RuleRequest>() as u32,
            message_type: RTM_GETRULE,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            sequence: RULE_DUMP_SEQUENCE,
            port_id: 0,
        },
        message: RuleMessage {
            family,
            destination_prefix: 0,
            source_prefix: 0,
            tos: 0,
            table: 0,
            reserved_1: 0,
            reserved_2: 0,
            action: 0,
            flags: 0,
        },
    };
    send_request(&socket, &request)?;
    let mut rules = receive_dump(&socket, RULE_DUMP_SEQUENCE, RTM_NEWRULE, "rule", parse_rule)?;
    rules.retain(|rule| ip_family_matches_family(rule.family, family));
    rules.sort_by_key(|rule| rule.priority);
    Ok(rules)
}

/// Dumps kernel link records and nested topology metadata with `RTM_GETLINK`.
///
/// Results are ordered by interface index. The effective loopback state is
/// derived from `IFF_UP`, because Linux reports no meaningful lower-layer
/// operational state for loopback.
pub fn links() -> io::Result<Vec<Link>> {
    let socket = open_route_socket(0)?;
    let request = LinkRequest {
        header: MessageHeader {
            length: size_of::<LinkRequest>() as u32,
            message_type: RTM_GETLINK,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            sequence: LINK_DUMP_SEQUENCE,
            port_id: 0,
        },
        message: LinkMessage {
            family: 0,
            padding: 0,
            link_type: 0,
            interface_index: 0,
            flags: 0,
            change: 0,
        },
    };
    send_request(&socket, &request)?;
    let mut links = receive_dump(&socket, LINK_DUMP_SEQUENCE, RTM_NEWLINK, "link", parse_link)?;
    links.sort_by_key(|link| link.interface_index);
    Ok(links)
}

/// Asks the kernel for the selected route to one IPv4 destination.
///
/// Unlike [`ipv4_routes`], this is a lookup that applies the kernel's routing
/// policy and can include a chosen source address. It does not send a packet to
/// `destination`.
pub fn ipv4_route(destination: Ipv4Addr) -> io::Result<Route> {
    const ROUTE_SEQUENCE: u32 = 2;

    let socket = open_route_socket(0)?;
    let request = RouteRequest {
        header: MessageHeader {
            length: size_of::<RouteRequest>() as u32,
            message_type: RTM_GETROUTE,
            flags: NLM_F_REQUEST,
            sequence: ROUTE_SEQUENCE,
            port_id: 0,
        },
        message: RouteMessage {
            family: AF_INET,
            destination_prefix: 32,
            source_prefix: 0,
            tos: 0,
            table: 0,
            protocol: 0,
            scope: 0,
            route_type: 0,
            flags: 0,
        },
        destination_attribute: RouteAttribute {
            length: (size_of::<RouteAttribute>() + 4) as u16,
            attribute_type: RTA_DST,
        },
        destination: destination.octets(),
    };
    send_request(&socket, &request)?;

    receive_route_lookup(&socket, ROUTE_SEQUENCE)
}

/// Asks the kernel for the selected route to one IPv6 destination.
///
/// This applies IPv6 routing policy and does not send a packet to the
/// destination.
pub fn ipv6_route(destination: Ipv6Addr) -> io::Result<Route> {
    const ROUTE_SEQUENCE: u32 = 2;

    let socket = open_route_socket(0)?;
    let request = RouteRequest6 {
        header: MessageHeader {
            length: size_of::<RouteRequest6>() as u32,
            message_type: RTM_GETROUTE,
            flags: NLM_F_REQUEST,
            sequence: ROUTE_SEQUENCE,
            port_id: 0,
        },
        message: RouteMessage {
            family: AF_INET6,
            destination_prefix: 128,
            source_prefix: 0,
            tos: 0,
            table: 0,
            protocol: 0,
            scope: 0,
            route_type: 0,
            flags: 0,
        },
        destination_attribute: RouteAttribute {
            length: (size_of::<RouteAttribute>() + 16) as u16,
            attribute_type: RTA_DST,
        },
        destination: destination.octets(),
    };
    send_request(&socket, &request)?;

    receive_route_lookup(&socket, ROUTE_SEQUENCE)
}

/// Asks the kernel for the selected route to an IPv4 or IPv6 destination.
///
/// This performs a routing-policy lookup and does not send any traffic.
pub fn ip_route(destination: IpAddr) -> io::Result<Route> {
    match destination {
        IpAddr::V4(destination) => ipv4_route(destination),
        IpAddr::V6(destination) => ipv6_route(destination),
    }
}

fn receive_route_lookup(socket: &OwnedFd, sequence: u32) -> io::Result<Route> {
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let received = receive(socket, &mut buffer)?;
        let mut offset = 0;
        while received.saturating_sub(offset) >= size_of::<MessageHeader>() {
            let header =
                read_unaligned::<MessageHeader>(&buffer[offset..received]).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated route reply header")
                })?;
            let length = header.length as usize;
            if length < size_of::<MessageHeader>() || length > received - offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid route reply length",
                ));
            }
            let message = &buffer[offset..offset + length];
            if header.sequence == sequence {
                match header.message_type {
                    RTM_NEWROUTE => {
                        let mut route = parse_route(message).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid IP route reply")
                        })?;
                        // inet6_rtm_getroute passes its zero-initialized lookup
                        // source to rt6_fill_node, which serializes `RTA_SRC=::`
                        // with a /128 length. It describes the lookup input, not
                        // a source-specific route selector.
                        normalize_route_lookup(&mut route);
                        return Ok(route);
                    }
                    NLMSG_ERROR => parse_netlink_error(message)?,
                    NLMSG_DONE => {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "kernel returned no IP route",
                        ));
                    }
                    _ => {}
                }
            }
            offset += align_to_4(length);
        }
    }
}

fn normalize_route_lookup(route: &mut Route) {
    if route
        .source_prefix
        .is_some_and(|(source, _)| source.is_unspecified())
    {
        route.source_prefix = None;
    }
}

/// Subscribes to link, IPv4/IPv6 address, route, and neighbor multicast events.
///
/// The function blocks indefinitely and invokes `handler` synchronously for
/// each recognized event. Returning from the handler continues watching; stop
/// the operation by interrupting/closing the process or running it in a thread
/// whose lifetime the application controls. Slow handlers delay reception and
/// can eventually cause a kernel receive-buffer overrun.
pub fn watch_events(mut handler: impl FnMut(NetworkEvent)) -> io::Result<()> {
    let groups = RTMGRP_LINK
        | RTMGRP_NEIGH
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV4_ROUTE
        | RTMGRP_IPV6_IFADDR
        | RTMGRP_IPV6_ROUTE;
    let socket = open_route_socket(groups)?;
    let mut buffer = vec![0_u8; 64 * 1024];

    loop {
        // SAFETY: buffer is writable for buffer.len() bytes and socket is a live fd.
        let received = unsafe {
            recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "netlink event socket closed",
            ));
        }

        for event in parse_events(&buffer[..received as usize])? {
            handler(event);
        }
    }
}

fn open_route_socket(groups: u32) -> io::Result<OwnedFd> {
    // SAFETY: arguments are constants from the Linux socket and netlink UAPI.
    let raw_fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: socket returned a new owned descriptor on success.
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let local = SocketAddress {
        family: AF_NETLINK as u16,
        padding: 0,
        port_id: 0,
        groups,
    };
    // SAFETY: local has the Linux sockaddr_nl layout and remains valid for the call.
    if unsafe {
        bind(
            socket.as_raw_fd(),
            (&raw const local).cast(),
            size_of::<SocketAddress>() as u32,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(socket)
}

fn parse_events(response: &[u8]) -> io::Result<Vec<NetworkEvent>> {
    let mut events = Vec::new();
    let mut offset = 0;
    while response.len().saturating_sub(offset) >= size_of::<MessageHeader>() {
        let header = read_unaligned::<MessageHeader>(&response[offset..]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated netlink event header")
        })?;
        let length = header.length as usize;
        if length < size_of::<MessageHeader>() || length > response.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netlink event length",
            ));
        }
        let message = &response[offset..offset + length];
        let event = match header.message_type {
            NLMSG_ERROR => {
                parse_netlink_error(message)?;
                None
            }
            NLMSG_OVERRUN => {
                return Err(io::Error::other("netlink event receive buffer overrun"));
            }
            RTM_NEWLINK => parse_link_event(message, false),
            RTM_DELLINK => parse_link_event(message, true),
            RTM_NEWADDR => parse_address_event(message, false),
            RTM_DELADDR => parse_address_event(message, true),
            RTM_NEWROUTE => parse_route_event(message, false),
            RTM_DELROUTE => parse_route_event(message, true),
            RTM_NEWNEIGH => parse_neighbor(message, false).map(|neighbor| NetworkEvent::Neighbor {
                removed: false,
                neighbor,
            }),
            RTM_DELNEIGH => parse_neighbor(message, true).map(|neighbor| NetworkEvent::Neighbor {
                removed: true,
                neighbor,
            }),
            _ => None,
        };
        if let Some(event) = event {
            events.push(event);
        }
        offset += align_to_4(length);
    }

    Ok(events)
}

fn parse_link_event(message: &[u8], removed: bool) -> Option<NetworkEvent> {
    let link = parse_link(message)?;
    Some(NetworkEvent::Link {
        removed,
        interface_index: link.interface_index,
        name: Some(link.name),
        up: link.flags.split('|').any(|flag| flag == "up"),
    })
}

fn parse_link(message: &[u8]) -> Option<Link> {
    let link = read_unaligned::<LinkMessage>(message.get(size_of::<MessageHeader>()..)?)?;
    let attributes = attributes(message, size_of::<LinkMessage>())?;
    let name = find_string(&attributes, IFLA_IFNAME)?;
    let (kind, vlan_id) = attributes
        .iter()
        .find_map(|(attribute_type, value)| {
            (*attribute_type == IFLA_LINKINFO).then(|| parse_link_info(value))
        })
        .flatten()
        .unwrap_or((None, None));
    let mut alternative_names = attributes
        .iter()
        .filter_map(|(attribute_type, value)| {
            (*attribute_type == IFLA_ALT_IFNAME).then(|| nul_terminated_string(value))?
        })
        .collect::<Vec<_>>();
    if let Some(property_list) = attributes
        .iter()
        .find_map(|(attribute_type, value)| (*attribute_type == IFLA_PROP_LIST).then_some(*value))
        && let Some(properties) = attributes_from_offset(property_list, 0)
    {
        alternative_names.extend(
            properties
                .into_iter()
                .filter_map(|(attribute_type, value)| {
                    (attribute_type == IFLA_ALT_IFNAME).then(|| nul_terminated_string(value))?
                }),
        );
    }
    alternative_names.sort();
    alternative_names.dedup();

    let mut operational_state = attributes
        .iter()
        .find_map(|(attribute_type, value)| {
            (*attribute_type == IFLA_OPERSTATE)
                .then(|| value.first().map(|state| operational_state(*state)))?
        })
        .unwrap_or_else(|| "unknown".into());
    if operational_state == "unknown" && link.flags & 0x09 == 0x09 {
        operational_state = "up".into();
    }

    Some(Link {
        interface_index: link.interface_index,
        name,
        kind,
        hardware_type: link.link_type,
        flags: link_flags(link.flags),
        operational_state,
        carrier: find_u8(&attributes, IFLA_CARRIER).map(|carrier| carrier != 0),
        mtu: find_native_u32(&attributes, IFLA_MTU),
        minimum_mtu: find_native_u32(&attributes, IFLA_MIN_MTU),
        maximum_mtu: find_native_u32(&attributes, IFLA_MAX_MTU),
        parent_index: find_native_u32(&attributes, IFLA_LINK).map(|index| index as i32),
        master_index: find_native_u32(&attributes, IFLA_MASTER).map(|index| index as i32),
        qdisc: find_string(&attributes, IFLA_QDISC),
        transmit_queue_length: find_native_u32(&attributes, IFLA_TXQLEN),
        alias: find_string(&attributes, IFLA_IFALIAS).filter(|alias| !alias.is_empty()),
        alternative_names,
        vlan_id,
        group: find_native_u32(&attributes, IFLA_GROUP),
        promiscuity: find_native_u32(&attributes, IFLA_PROMISCUITY),
        transmit_queues: find_native_u32(&attributes, IFLA_NUM_TX_QUEUES),
        receive_queues: find_native_u32(&attributes, IFLA_NUM_RX_QUEUES),
        carrier_changes: find_native_u32(&attributes, IFLA_CARRIER_CHANGES),
        carrier_up_count: find_native_u32(&attributes, IFLA_CARRIER_UP_COUNT),
        carrier_down_count: find_native_u32(&attributes, IFLA_CARRIER_DOWN_COUNT),
        physical_port_name: find_string(&attributes, IFLA_PHYS_PORT_NAME),
        parent_device_name: find_string(&attributes, IFLA_PARENT_DEV_NAME),
        parent_device_bus_name: find_string(&attributes, IFLA_PARENT_DEV_BUS_NAME),
    })
}

fn parse_link_info(value: &[u8]) -> Option<(Option<String>, Option<u16>)> {
    let attributes = attributes_from_offset(value, 0)?;
    let kind = find_string(&attributes, IFLA_INFO_KIND);
    let vlan_id = attributes
        .iter()
        .find_map(|(attribute_type, value)| (*attribute_type == IFLA_INFO_DATA).then_some(*value))
        .and_then(|data| attributes_from_offset(data, 0))
        .and_then(|attributes| {
            attributes.into_iter().find_map(|(attribute_type, value)| {
                (attribute_type == IFLA_VLAN_ID).then(|| native_u16(value))?
            })
        });
    Some((kind, vlan_id))
}

fn parse_address_event(message: &[u8], removed: bool) -> Option<NetworkEvent> {
    let address = parse_address(message)?;
    Some(NetworkEvent::Address {
        removed,
        interface_index: address.interface_index,
        address: address.local,
        prefix: address.prefix,
    })
}

fn parse_address(message: &[u8]) -> Option<Address> {
    let address_message =
        read_unaligned::<AddressMessage>(message.get(size_of::<MessageHeader>()..)?)?;
    if !matches!(address_message.family, AF_INET | AF_INET6) {
        return None;
    }

    let attributes = attributes(message, size_of::<AddressMessage>())?;
    let prefix_address = attributes.iter().find_map(|(kind, value)| {
        (*kind == IFA_ADDRESS).then(|| ip_from_bytes(address_message.family, value))?
    });
    let local = attributes
        .iter()
        .find_map(|(kind, value)| {
            (*kind == IFA_LOCAL).then(|| ip_from_bytes(address_message.family, value))?
        })
        .or(prefix_address)?;
    let peer = prefix_address.filter(|address| *address != local);
    let broadcast = attributes.iter().find_map(|(kind, value)| {
        (*kind == IFA_BROADCAST).then(|| ip_from_bytes(address_message.family, value))?
    });
    let label = attributes
        .iter()
        .find_map(|(kind, value)| (*kind == IFA_LABEL).then(|| nul_terminated_string(value))?);
    let flags = attributes
        .iter()
        .find_map(|(kind, value)| (*kind == IFA_FLAGS).then(|| native_u32(value))?)
        .unwrap_or(u32::from(address_message.flags));
    let cache = attributes.iter().find_map(|(kind, value)| {
        (*kind == IFA_CACHEINFO).then(|| read_unaligned::<AddressCacheInfo>(value))?
    });

    Some(Address {
        local,
        prefix: address_message.prefix,
        peer,
        broadcast,
        interface_index: address_message.interface_index as i32,
        label,
        scope: address_scope(address_message.scope),
        flags: address_flags(flags),
        preferred_lifetime: cache.and_then(|cache| finite_lifetime(cache.preferred)),
        valid_lifetime: cache.and_then(|cache| finite_lifetime(cache.valid)),
    })
}

fn parse_route_event(message: &[u8], removed: bool) -> Option<NetworkEvent> {
    Some(NetworkEvent::Route {
        removed,
        route: parse_route(message)?,
    })
}

fn parse_route(message: &[u8]) -> Option<Route> {
    let route = read_unaligned::<RouteMessage>(message.get(size_of::<MessageHeader>()..)?)?;
    if !matches!(route.family, AF_INET | AF_INET6) {
        return None;
    }

    let attributes = attributes(message, size_of::<RouteMessage>())?;
    let destination = attributes
        .iter()
        .find_map(|(kind, value)| (*kind == RTA_DST).then(|| ip_from_bytes(route.family, value))?)
        .unwrap_or_else(|| unspecified_address(route.family));
    let route_source = attributes.iter().find_map(|(kind, value)| {
        (*kind == RTA_SRC).then(|| ip_from_bytes(route.family, value))?
    });
    let gateway = attributes.iter().find_map(|(kind, value)| {
        (*kind == RTA_GATEWAY).then(|| ip_from_bytes(route.family, value))?
    });
    let interface_index = attributes.iter().find_map(|(kind, value)| {
        (*kind == RTA_OIF).then(|| native_u32(value).map(|index| index as i32))?
    });
    let metric = attributes
        .iter()
        .find_map(|(kind, value)| (*kind == RTA_PRIORITY).then(|| native_u32(value))?);
    let source = attributes.iter().find_map(|(kind, value)| {
        (*kind == RTA_PREFSRC).then(|| ip_from_bytes(route.family, value))?
    });
    let table = attributes
        .iter()
        .find_map(|(kind, value)| (*kind == RTA_TABLE).then(|| native_u32(value))?)
        .unwrap_or(u32::from(route.table));
    let next_hops = attributes
        .iter()
        .find_map(|(kind, value)| {
            (*kind == RTA_MULTIPATH).then(|| parse_next_hops(value, route.family))
        })
        .unwrap_or_default();
    Some(Route {
        destination,
        prefix: route.destination_prefix,
        source_prefix: route_source
            .map(|source| (source, route.source_prefix))
            .filter(|(_, prefix)| *prefix != 0),
        gateway,
        interface_index,
        metric,
        source,
        table,
        protocol: route_protocol(route.protocol),
        scope: route_scope(route.scope),
        kind: route_kind(route.route_type),
        next_hops,
    })
}

fn parse_next_hops(value: &[u8], family: u8) -> Vec<NextHop> {
    let mut next_hops = Vec::new();
    let mut offset = 0;
    while value.len().saturating_sub(offset) >= size_of::<RouteNextHop>() {
        let Some(next_hop) = read_unaligned::<RouteNextHop>(&value[offset..]) else {
            break;
        };
        let length = usize::from(next_hop.length);
        if length < size_of::<RouteNextHop>() || length > value.len() - offset {
            break;
        }
        let payload = &value[offset..offset + length];
        let gateway =
            attributes_from_offset(payload, size_of::<RouteNextHop>()).and_then(|attributes| {
                attributes.into_iter().find_map(|(kind, value)| {
                    (kind == RTA_GATEWAY).then(|| ip_from_bytes(family, value))?
                })
            });
        next_hops.push(NextHop {
            gateway,
            interface_index: next_hop.interface_index,
            weight: u16::from(next_hop.hops) + 1,
            flags: next_hop_flags(next_hop.flags),
        });
        offset += align_to_4(length);
    }
    next_hops
}

fn parse_rule(message: &[u8]) -> Option<Rule> {
    let rule = read_unaligned::<RuleMessage>(message.get(size_of::<MessageHeader>()..)?)?;
    if !matches!(rule.family, AF_INET | AF_INET6) {
        return None;
    }
    let attributes = attributes(message, size_of::<RuleMessage>())?;
    let source = attributes
        .iter()
        .find_map(|(kind, value)| (*kind == FRA_SRC).then(|| ip_from_bytes(rule.family, value))?)
        .map(|address| (address, rule.source_prefix));
    let destination = attributes
        .iter()
        .find_map(|(kind, value)| (*kind == FRA_DST).then(|| ip_from_bytes(rule.family, value))?)
        .map(|address| (address, rule.destination_prefix));
    Some(Rule {
        family: if rule.family == AF_INET {
            IpFamily::Ipv4
        } else {
            IpFamily::Ipv6
        },
        priority: find_native_u32(&attributes, FRA_PRIORITY).unwrap_or(0),
        source,
        destination,
        input_interface: find_string(&attributes, FRA_IIFNAME),
        output_interface: find_string(&attributes, FRA_OIFNAME),
        fwmark: find_native_u32(&attributes, FRA_FWMARK),
        fwmask: find_native_u32(&attributes, FRA_FWMASK),
        table: find_native_u32(&attributes, FRA_TABLE).unwrap_or(u32::from(rule.table)),
        action: rule_action(rule.action),
        goto: find_native_u32(&attributes, FRA_GOTO),
        flags: rule_flags(rule.flags),
    })
}

fn find_native_u32(attributes: &[(u16, &[u8])], expected: u16) -> Option<u32> {
    attributes
        .iter()
        .find_map(|(kind, value)| (*kind == expected).then(|| native_u32(value))?)
}

fn find_u8(attributes: &[(u16, &[u8])], expected: u16) -> Option<u8> {
    attributes
        .iter()
        .find_map(|(kind, value)| (*kind == expected).then(|| value.first().copied())?)
}

fn find_string(attributes: &[(u16, &[u8])], expected: u16) -> Option<String> {
    attributes
        .iter()
        .find_map(|(kind, value)| (*kind == expected).then(|| nul_terminated_string(value))?)
}

fn attributes(message: &[u8], payload_size: usize) -> Option<Vec<(u16, &[u8])>> {
    attributes_from_offset(
        message,
        align_to_4(size_of::<MessageHeader>() + payload_size),
    )
}

fn attributes_from_offset(message: &[u8], mut offset: usize) -> Option<Vec<(u16, &[u8])>> {
    let mut attributes = Vec::new();
    while message.len().saturating_sub(offset) >= size_of::<RouteAttribute>() {
        let attribute = read_unaligned::<RouteAttribute>(&message[offset..])?;
        let length = attribute.length as usize;
        if length < size_of::<RouteAttribute>() || length > message.len() - offset {
            return None;
        }
        attributes.push((
            attribute.attribute_type & NLA_TYPE_MASK,
            &message[offset + size_of::<RouteAttribute>()..offset + length],
        ));
        offset += align_to_4(length);
    }
    Some(attributes)
}

fn nul_terminated_string(value: &[u8]) -> Option<String> {
    let length = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    std::str::from_utf8(&value[..length])
        .ok()
        .map(str::to_owned)
}

fn ipv4_from_bytes(value: &[u8]) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::new(
        *value.first()?,
        *value.get(1)?,
        *value.get(2)?,
        *value.get(3)?,
    ))
}

fn ipv6_from_bytes(value: &[u8]) -> Option<Ipv6Addr> {
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(value.get(..16)?).ok()?))
}

fn ip_from_bytes(family: u8, value: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET => ipv4_from_bytes(value).map(IpAddr::V4),
        AF_INET6 => ipv6_from_bytes(value).map(IpAddr::V6),
        _ => None,
    }
}

fn ip_address_matches_family(address: IpAddr, family: u8) -> bool {
    // If a requested protocol family has no registered handler, rtnetlink can
    // fall back to an all-family dump instead of returning an error.
    matches!(
        (address, family),
        (IpAddr::V4(_), AF_INET) | (IpAddr::V6(_), AF_INET6)
    )
}

fn ip_family_matches_family(record_family: IpFamily, family: u8) -> bool {
    matches!(
        (record_family, family),
        (IpFamily::Ipv4, AF_INET) | (IpFamily::Ipv6, AF_INET6)
    )
}

fn ipv6_unavailable(error: &io::Error) -> bool {
    // EPROTONOSUPPORT or EAFNOSUPPORT on kernels built without IPv6.
    matches!(error.raw_os_error(), Some(93 | 97))
}

fn unspecified_address(family: u8) -> IpAddr {
    match family {
        AF_INET6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

fn native_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(value.get(..4)?.try_into().ok()?))
}

fn native_u16(value: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(value.get(..2)?.try_into().ok()?))
}

fn finite_lifetime(seconds: u32) -> Option<u32> {
    (seconds != u32::MAX).then_some(seconds)
}

fn address_scope(scope: u8) -> &'static str {
    match scope {
        0 => "global",
        200 => "site",
        253 => "link",
        254 => "host",
        255 => "nowhere",
        _ => "custom",
    }
}

fn address_flags(flags: u32) -> String {
    let known = [
        (IFA_F_SECONDARY, "secondary"),
        (IFA_F_NODAD, "nodad"),
        (IFA_F_OPTIMISTIC, "optimistic"),
        (IFA_F_DADFAILED, "dadfailed"),
        (IFA_F_HOMEADDRESS, "home"),
        (IFA_F_DEPRECATED, "deprecated"),
        (IFA_F_TENTATIVE, "tentative"),
        (IFA_F_PERMANENT, "permanent"),
        (IFA_F_MANAGETEMPADDR, "manage-temp"),
        (IFA_F_NOPREFIXROUTE, "no-prefix-route"),
        (IFA_F_MCAUTOJOIN, "multicast-autojoin"),
        (IFA_F_STABLE_PRIVACY, "stable-privacy"),
    ];
    let mut names = known
        .into_iter()
        .filter(|(flag, _)| flags & flag != 0)
        .map(|(_, name)| name.to_owned())
        .collect::<Vec<_>>();
    let known_bits = known.into_iter().fold(0, |bits, (flag, _)| bits | flag);
    let unknown = flags & !known_bits;
    if unknown != 0 {
        names.push(format!("0x{unknown:x}"));
    }
    if names.is_empty() {
        "none".into()
    } else {
        names.join("|")
    }
}

fn route_protocol(protocol: u8) -> String {
    match protocol {
        0 => "unspecified".into(),
        1 => "redirect".into(),
        2 => "kernel".into(),
        3 => "boot".into(),
        4 => "static".into(),
        8 => "gated".into(),
        9 => "router-advertisement".into(),
        11 => "zebra".into(),
        12 => "bird".into(),
        16 => "dhcp".into(),
        17 => "mrouted".into(),
        18 => "keepalived".into(),
        186 => "bgp".into(),
        187 => "isis".into(),
        188 => "ospf".into(),
        189 => "rip".into(),
        value => format!("protocol-{value}"),
    }
}

fn route_scope(scope: u8) -> String {
    match scope {
        0 => "global".into(),
        200 => "site".into(),
        253 => "link".into(),
        254 => "host".into(),
        255 => "nowhere".into(),
        value => format!("scope-{value}"),
    }
}

fn route_kind(kind: u8) -> String {
    match kind {
        0 => "unspecified".into(),
        1 => "unicast".into(),
        2 => "local".into(),
        3 => "broadcast".into(),
        4 => "anycast".into(),
        5 => "multicast".into(),
        6 => "blackhole".into(),
        7 => "unreachable".into(),
        8 => "prohibit".into(),
        9 => "throw".into(),
        10 => "nat".into(),
        11 => "xresolve".into(),
        value => format!("type-{value}"),
    }
}

fn operational_state(state: u8) -> String {
    match state {
        0 => "unknown".into(),
        1 => "not-present".into(),
        2 => "down".into(),
        3 => "lower-layer-down".into(),
        4 => "testing".into(),
        5 => "dormant".into(),
        6 => "up".into(),
        value => format!("state-{value}"),
    }
}

fn link_flags(flags: u32) -> String {
    format_flags(
        flags,
        &[
            (0x0000_0001, "up"),
            (0x0000_0002, "broadcast"),
            (0x0000_0004, "debug"),
            (0x0000_0008, "loopback"),
            (0x0000_0010, "point-to-point"),
            (0x0000_0020, "no-trailers"),
            (0x0000_0040, "running"),
            (0x0000_0080, "noarp"),
            (0x0000_0100, "promiscuous"),
            (0x0000_0200, "all-multicast"),
            (0x0000_0400, "master"),
            (0x0000_0800, "slave"),
            (0x0000_1000, "multicast"),
            (0x0000_2000, "port-selection"),
            (0x0000_4000, "automedia"),
            (0x0000_8000, "dynamic"),
            (0x0001_0000, "lower-up"),
            (0x0002_0000, "dormant"),
            (0x0004_0000, "echo"),
        ],
    )
}

fn next_hop_flags(flags: u8) -> String {
    format_flags(
        u32::from(flags),
        &[
            (0x01, "dead"),
            (0x02, "pervasive"),
            (0x04, "onlink"),
            (0x08, "offload"),
            (0x10, "linkdown"),
            (0x20, "unresolved"),
            (0x40, "trap"),
        ],
    )
}

fn rule_action(action: u8) -> String {
    match action {
        0 => "unspecified".into(),
        1 => "lookup".into(),
        2 => "goto".into(),
        3 => "nop".into(),
        6 => "blackhole".into(),
        7 => "unreachable".into(),
        8 => "prohibit".into(),
        value => format!("action-{value}"),
    }
}

fn rule_flags(flags: u32) -> String {
    format_flags(
        flags,
        &[
            (0x0000_0001, "permanent"),
            (0x0000_0002, "invert"),
            (0x0000_0004, "unresolved"),
            (0x0000_0008, "input-detached"),
            (0x0000_0010, "output-detached"),
            (0x0001_0000, "find-source"),
        ],
    )
}

fn format_flags(flags: u32, known: &[(u32, &str)]) -> String {
    let mut names = known
        .iter()
        .filter(|(flag, _)| flags & flag != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect::<Vec<_>>();
    let known_bits = known.iter().fold(0, |bits, (flag, _)| bits | flag);
    let unknown = flags & !known_bits;
    if unknown != 0 {
        names.push(format!("0x{unknown:x}"));
    }
    if names.is_empty() {
        "none".into()
    } else {
        names.join("|")
    }
}

fn send_neighbor_request(socket: &OwnedFd, family: u8) -> io::Result<()> {
    let request = NeighborRequest {
        header: MessageHeader {
            length: size_of::<NeighborRequest>() as u32,
            message_type: RTM_GETNEIGH,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            sequence: REQUEST_SEQUENCE,
            port_id: 0,
        },
        message: NeighborMessage {
            family,
            padding_1: 0,
            padding_2: 0,
            interface_index: 0,
            state: 0,
            flags: 0,
            message_type: 0,
        },
    };
    send_request(socket, &request)
}

fn send_address_request(socket: &OwnedFd, family: u8) -> io::Result<()> {
    let request = AddressRequest {
        header: MessageHeader {
            length: size_of::<AddressRequest>() as u32,
            message_type: RTM_GETADDR,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            sequence: ADDRESS_SEQUENCE,
            port_id: 0,
        },
        message: AddressMessage {
            family,
            prefix: 0,
            flags: 0,
            scope: 0,
            interface_index: 0,
        },
    };
    send_request(socket, &request)
}

fn send_request<T>(socket: &OwnedFd, request: &T) -> io::Result<()> {
    let kernel = SocketAddress {
        family: AF_NETLINK as u16,
        padding: 0,
        port_id: 0,
        groups: 0,
    };

    // SAFETY: request points to a C-layout netlink request created by this module,
    // and both pointers remain valid for the duration of sendto.
    let sent = unsafe {
        sendto(
            socket.as_raw_fd(),
            (request as *const T).cast(),
            size_of::<T>(),
            0,
            (&raw const kernel).cast(),
            size_of::<SocketAddress>() as u32,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != size_of::<T>() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete netlink request",
        ));
    }
    Ok(())
}

fn receive(socket: &OwnedFd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: buffer is writable for buffer.len() bytes and socket is a live fd.
        let received = unsafe {
            recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "netlink socket closed",
            ));
        }
        return Ok(received as usize);
    }
}

fn receive_dump<T>(
    socket: &OwnedFd,
    expected_sequence: u32,
    expected_type: u16,
    name: &str,
    mut parse: impl FnMut(&[u8]) -> Option<T>,
) -> io::Result<Vec<T>> {
    let mut values = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let received = receive(socket, &mut buffer)?;
        let mut offset = 0;
        while received.saturating_sub(offset) >= size_of::<MessageHeader>() {
            let header =
                read_unaligned::<MessageHeader>(&buffer[offset..received]).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("truncated {name} header"),
                    )
                })?;
            let length = header.length as usize;
            if length < size_of::<MessageHeader>() || length > received - offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid {name} message length"),
                ));
            }
            if header.sequence == expected_sequence {
                let message = &buffer[offset..offset + length];
                match header.message_type {
                    NLMSG_DONE => {
                        if header.flags & NLM_F_DUMP_INTR != 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                format!("{name} table changed during the netlink dump"),
                            ));
                        }
                        if let Some(error) = read_i32(message, size_of::<MessageHeader>())
                            && error != 0
                        {
                            return Err(io::Error::from_raw_os_error(-error));
                        }
                        return Ok(values);
                    }
                    NLMSG_ERROR => parse_netlink_error(message)?,
                    NLMSG_OVERRUN => {
                        return Err(io::Error::other(format!(
                            "netlink {name} dump overran the receive buffer"
                        )));
                    }
                    message_type if message_type == expected_type => {
                        if let Some(value) = parse(message) {
                            values.push(value);
                        }
                    }
                    _ => {}
                }
            }
            offset += align_to_4(length);
        }
    }
}

fn parse_response(
    response: &[u8],
    expected_sequence: u32,
    neighbors: &mut Vec<Neighbor>,
) -> io::Result<bool> {
    let mut offset = 0;
    while response.len().saturating_sub(offset) >= size_of::<MessageHeader>() {
        let header = read_unaligned::<MessageHeader>(&response[offset..]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated netlink header")
        })?;
        let length = header.length as usize;
        if length < size_of::<MessageHeader>() || length > response.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netlink message length",
            ));
        }

        if header.sequence == expected_sequence {
            let message = &response[offset..offset + length];
            match header.message_type {
                NLMSG_DONE => {
                    if header.flags & NLM_F_DUMP_INTR != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "neighbor table changed during the netlink dump",
                        ));
                    }
                    if let Some(error) = read_i32(message, size_of::<MessageHeader>())
                        && error != 0
                    {
                        return Err(io::Error::from_raw_os_error(-error));
                    }
                    return Ok(true);
                }
                NLMSG_ERROR => return parse_netlink_error(message).map(|()| false),
                NLMSG_OVERRUN => {
                    return Err(io::Error::other(
                        "netlink neighbor dump overran the receive buffer",
                    ));
                }
                RTM_NEWNEIGH => {
                    if let Some(neighbor) = parse_neighbor(message, false) {
                        neighbors.push(neighbor);
                    }
                }
                _ => {}
            }
        }

        offset += align_to_4(length);
    }

    Ok(false)
}

fn parse_address_response(
    response: &[u8],
    expected_sequence: u32,
    addresses: &mut Vec<Address>,
) -> io::Result<bool> {
    let mut offset = 0;
    while response.len().saturating_sub(offset) >= size_of::<MessageHeader>() {
        let header = read_unaligned::<MessageHeader>(&response[offset..]).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated address dump header")
        })?;
        let length = header.length as usize;
        if length < size_of::<MessageHeader>() || length > response.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid address dump message length",
            ));
        }

        if header.sequence == expected_sequence {
            let message = &response[offset..offset + length];
            match header.message_type {
                NLMSG_DONE => {
                    if header.flags & NLM_F_DUMP_INTR != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "address table changed during the netlink dump",
                        ));
                    }
                    if let Some(error) = read_i32(message, size_of::<MessageHeader>())
                        && error != 0
                    {
                        return Err(io::Error::from_raw_os_error(-error));
                    }
                    return Ok(true);
                }
                NLMSG_ERROR => return parse_netlink_error(message).map(|()| false),
                NLMSG_OVERRUN => {
                    return Err(io::Error::other(
                        "netlink address dump overran the receive buffer",
                    ));
                }
                RTM_NEWADDR => {
                    if let Some(address) = parse_address(message) {
                        addresses.push(address);
                    }
                }
                _ => {}
            }
        }

        offset += align_to_4(length);
    }

    Ok(false)
}

fn parse_netlink_error(message: &[u8]) -> io::Result<()> {
    let error = read_i32(message, size_of::<MessageHeader>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated netlink error"))?;
    if error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-error))
    }
}

fn parse_neighbor(message: &[u8], removed: bool) -> Option<Neighbor> {
    let header_length = size_of::<MessageHeader>();
    let neighbor_message = read_unaligned::<NeighborMessage>(message.get(header_length..)?)?;
    if !matches!(neighbor_message.family, AF_INET | AF_INET6) {
        return None;
    }

    let mut address = None;
    let mut link_address = None;
    let mut cache = None;
    let mut probes = None;
    let mut master_index = None;
    let mut protocol = None;
    let mut extended_flags = 0;
    let mut offset = align_to_4(header_length + size_of::<NeighborMessage>());
    while message.len().saturating_sub(offset) >= size_of::<RouteAttribute>() {
        let attribute = read_unaligned::<RouteAttribute>(&message[offset..])?;
        let length = attribute.length as usize;
        if length < size_of::<RouteAttribute>() || length > message.len() - offset {
            return None;
        }
        let value = &message[offset + size_of::<RouteAttribute>()..offset + length];
        match attribute.attribute_type & NLA_TYPE_MASK {
            NDA_DST => address = ip_from_bytes(neighbor_message.family, value),
            NDA_LLADDR if !value.is_empty() => link_address = Some(format_link_address(value)),
            NDA_CACHEINFO => cache = read_unaligned::<NeighborCacheInfo>(value),
            NDA_PROBES => probes = native_u32(value),
            NDA_MASTER => master_index = native_u32(value).map(|index| index as i32),
            NDA_PROTOCOL => protocol = value.first().map(|value| route_protocol(*value)),
            NDA_FLAGS_EXT => extended_flags = native_u32(value).unwrap_or_default(),
            _ => {}
        }
        offset += align_to_4(length);
    }

    if !is_reportable_neighbor(
        neighbor_message.family,
        neighbor_message.state,
        removed,
        link_address.is_some(),
    ) {
        return None;
    }

    Some(Neighbor {
        address: address?,
        link_address,
        interface_index: neighbor_message.interface_index,
        state: neighbor_state(neighbor_message.state),
        flags: neighbor_flags(neighbor_message.flags, extended_flags),
        protocol,
        kind: route_kind(neighbor_message.message_type),
        probes,
        confirmed_ms_ago: cache.map(|cache| clock_ticks_to_ms(cache.confirmed)),
        used_ms_ago: cache.map(|cache| clock_ticks_to_ms(cache.used)),
        updated_ms_ago: cache.map(|cache| clock_ticks_to_ms(cache.updated)),
        reference_count: cache.map(|cache| cache.reference_count),
        master_index,
    })
}

fn neighbor_flags(flags: u8, extended_flags: u32) -> String {
    let base = format_flags(
        u32::from(flags),
        &[
            (0x01, "use"),
            (0x02, "self"),
            (0x04, "master"),
            (0x08, "proxy"),
            (0x10, "externally-learned"),
            (0x20, "offloaded"),
            (0x40, "sticky"),
            (0x80, "router"),
        ],
    );
    let extended = format_flags(
        extended_flags,
        &[
            (0x01, "managed"),
            (0x02, "locked"),
            (0x04, "externally-validated"),
        ],
    );
    match (base.as_str(), extended.as_str()) {
        ("none", "none") => "none".into(),
        ("none", _) => extended,
        (_, "none") => base,
        _ => format!("{base}|{extended}"),
    }
}

fn clock_ticks_to_ms(ticks: u32) -> u64 {
    // `nda_cacheinfo` ages are USER_HZ ticks, not milliseconds. Querying
    // _SC_CLK_TCK avoids assuming the common-but-not-guaranteed value 100.
    static CLOCK_TICKS: OnceLock<u64> = OnceLock::new();
    let ticks_per_second = *CLOCK_TICKS.get_or_init(|| {
        // SAFETY: _SC_CLK_TCK is a side-effect-free sysconf query.
        let value = unsafe { sysconf(2) };
        u64::try_from(value)
            .ok()
            .filter(|value| *value != 0)
            .unwrap_or(100)
    });
    u64::from(ticks).saturating_mul(1000) / ticks_per_second
}

fn is_reportable_neighbor(family: u8, state: u16, removed: bool, has_link: bool) -> bool {
    matches!(family, AF_INET | AF_INET6)
        && state & NUD_NOARP == 0
        && (state & (NUD_INCOMPLETE | NUD_FAILED) == 0 || (removed && has_link))
}

fn neighbor_state(state: u16) -> String {
    let states = [
        (NUD_INCOMPLETE, "incomplete"),
        (NUD_REACHABLE, "reachable"),
        (NUD_STALE, "stale"),
        (NUD_DELAY, "delay"),
        (NUD_PROBE, "probe"),
        (NUD_FAILED, "failed"),
        (NUD_NOARP, "noarp"),
        (NUD_PERMANENT, "permanent"),
    ];
    let names = states
        .into_iter()
        .filter_map(|(flag, name)| (state & flag != 0).then_some(name))
        .collect::<Vec<_>>();
    if names.is_empty() {
        "none".into()
    } else {
        names.join("|")
    }
}

fn format_link_address(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn read_unaligned<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: the length check guarantees a complete T is readable. read_unaligned
    // handles the byte slice's alignment, and all callers use plain C-layout types.
    Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    read_unaligned(bytes.get(offset..)?)
}

// Route-netlink message and attribute records use four-byte alignment.
const fn align_to_4(length: usize) -> usize {
    (length + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_records_to_the_requested_address_family() {
        assert!(ip_address_matches_family(
            Ipv4Addr::LOCALHOST.into(),
            AF_INET
        ));
        assert!(!ip_address_matches_family(
            Ipv4Addr::LOCALHOST.into(),
            AF_INET6
        ));
        assert!(ip_family_matches_family(IpFamily::Ipv6, AF_INET6));
        assert!(!ip_family_matches_family(IpFamily::Ipv4, AF_INET6));
    }

    #[test]
    fn formats_neighbor_states() {
        assert_eq!(neighbor_state(NUD_REACHABLE), "reachable");
        assert_eq!(neighbor_state(NUD_STALE | NUD_PROBE), "stale|probe");
        assert_eq!(neighbor_state(0), "none");
    }

    #[test]
    fn formats_link_layer_addresses() {
        assert_eq!(
            format_link_address(&[0x00, 0x1a, 0x2b, 0x03, 0xfe, 0xff]),
            "00:1a:2b:03:fe:ff"
        );
    }

    #[test]
    fn linux_uapi_layouts_match() {
        assert_eq!(size_of::<SocketAddress>(), 12);
        assert_eq!(size_of::<MessageHeader>(), 16);
        assert_eq!(size_of::<NeighborMessage>(), 12);
        assert_eq!(size_of::<NeighborRequest>(), 28);
        assert_eq!(size_of::<NeighborCacheInfo>(), 16);
        assert_eq!(size_of::<LinkMessage>(), 16);
        assert_eq!(size_of::<LinkRequest>(), 32);
        assert_eq!(size_of::<AddressMessage>(), 8);
        assert_eq!(size_of::<AddressRequest>(), 24);
        assert_eq!(size_of::<AddressCacheInfo>(), 16);
        assert_eq!(size_of::<RouteDumpRequest>(), 28);
        assert_eq!(size_of::<RouteRequest>(), 36);
        assert_eq!(size_of::<RouteRequest6>(), 48);
        assert_eq!(size_of::<RuleMessage>(), 12);
        assert_eq!(size_of::<RuleRequest>(), 28);
        assert_eq!(size_of::<RouteNextHop>(), 8);
        assert_eq!(size_of::<RouteAttribute>(), 4);
    }

    #[test]
    fn omits_kernel_noarp_pseudo_neighbors() {
        assert!(is_reportable_neighbor(AF_INET, NUD_REACHABLE, false, true));
        assert!(!is_reportable_neighbor(AF_INET, NUD_NOARP, false, true));
        assert!(is_reportable_neighbor(AF_INET6, NUD_REACHABLE, false, true));
        assert!(!is_reportable_neighbor(99, NUD_REACHABLE, false, true));
    }

    #[test]
    fn omits_unresolved_probes_but_keeps_real_removals() {
        assert!(!is_reportable_neighbor(AF_INET, NUD_FAILED, false, false));
        assert!(!is_reportable_neighbor(AF_INET, NUD_FAILED, true, false));
        assert!(is_reportable_neighbor(AF_INET, NUD_FAILED, true, true));
    }

    #[test]
    fn parses_neighbor_cache_metadata() {
        let payload = NeighborMessage {
            family: AF_INET,
            padding_1: 0,
            padding_2: 0,
            interface_index: 2,
            state: NUD_REACHABLE,
            flags: 0x80,
            message_type: 1,
        };
        let cache = NeighborCacheInfo {
            confirmed: 0,
            used: 0,
            updated: 0,
            reference_count: 3,
        };
        let probes = 2_u32.to_ne_bytes();
        let extended_flags = 1_u32.to_ne_bytes();
        let message = event_message(
            RTM_NEWNEIGH,
            &payload,
            &[
                (NDA_DST, &[192, 168, 1, 1]),
                (NDA_LLADDR, &[0, 1, 2, 3, 4, 5]),
                (NDA_CACHEINFO, value_bytes(&cache)),
                (NDA_PROBES, &probes),
                (NDA_PROTOCOL, &[16]),
                (NDA_FLAGS_EXT, &extended_flags),
            ],
        );
        assert_eq!(
            parse_neighbor(&message, false),
            Some(Neighbor {
                address: Ipv4Addr::new(192, 168, 1, 1).into(),
                link_address: Some("00:01:02:03:04:05".into()),
                interface_index: 2,
                state: "reachable".into(),
                flags: "router|managed".into(),
                protocol: Some("dhcp".into()),
                kind: "unicast".into(),
                probes: Some(2),
                confirmed_ms_ago: Some(0),
                used_ms_ago: Some(0),
                updated_ms_ago: Some(0),
                reference_count: Some(3),
                master_index: None,
            })
        );
    }

    #[test]
    fn parses_ipv4_address_events() {
        let payload = AddressMessage {
            family: AF_INET,
            prefix: 24,
            flags: 0,
            scope: 0,
            interface_index: 2,
        };
        let message = event_message(RTM_NEWADDR, &payload, &[(IFA_LOCAL, &[192, 168, 1, 42])]);
        assert_eq!(
            parse_events(&message).unwrap(),
            vec![NetworkEvent::Address {
                removed: false,
                interface_index: 2,
                address: Ipv4Addr::new(192, 168, 1, 42).into(),
                prefix: 24,
            }]
        );
    }

    #[test]
    fn parses_ipv4_address_details() {
        let payload = AddressMessage {
            family: AF_INET,
            prefix: 24,
            flags: 0,
            scope: 0,
            interface_index: 2,
        };
        let flags = (IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE).to_ne_bytes();
        let cache = AddressCacheInfo {
            preferred: u32::MAX,
            valid: 3600,
            _created: 100,
            _updated: 200,
        };
        let message = event_message(
            RTM_NEWADDR,
            &payload,
            &[
                (IFA_ADDRESS, &[192, 168, 1, 42]),
                (IFA_LOCAL, &[192, 168, 1, 42]),
                (IFA_BROADCAST, &[192, 168, 1, 255]),
                (IFA_LABEL, b"eth0\0"),
                (IFA_FLAGS, &flags),
                (IFA_CACHEINFO, value_bytes(&cache)),
            ],
        );
        assert_eq!(
            parse_address(&message),
            Some(Address {
                local: Ipv4Addr::new(192, 168, 1, 42).into(),
                prefix: 24,
                peer: None,
                broadcast: Some(Ipv4Addr::new(192, 168, 1, 255).into()),
                interface_index: 2,
                label: Some("eth0".into()),
                scope: "global",
                flags: "permanent|no-prefix-route".into(),
                preferred_lifetime: None,
                valid_lifetime: Some(3600),
            })
        );
    }

    #[test]
    fn parses_ipv6_address_details_and_events() {
        let payload = AddressMessage {
            family: AF_INET6,
            prefix: 64,
            flags: 0,
            scope: 0,
            interface_index: 3,
        };
        let local = "2001:db8::42".parse::<Ipv6Addr>().unwrap();
        let local_octets = local.octets();
        let message = event_message(RTM_NEWADDR, &payload, &[(IFA_ADDRESS, &local_octets)]);
        assert_eq!(
            parse_address(&message),
            Some(Address {
                local: local.into(),
                prefix: 64,
                peer: None,
                broadcast: None,
                interface_index: 3,
                label: None,
                scope: "global",
                flags: "none".into(),
                preferred_lifetime: None,
                valid_lifetime: None,
            })
        );
        assert_eq!(
            parse_events(&message).unwrap(),
            vec![NetworkEvent::Address {
                removed: false,
                interface_index: 3,
                address: local.into(),
                prefix: 64,
            }]
        );
    }

    #[test]
    fn parses_ipv4_route_events() {
        let payload = RouteMessage {
            family: AF_INET,
            destination_prefix: 0,
            source_prefix: 0,
            tos: 0,
            table: 254,
            protocol: 3,
            scope: 0,
            route_type: 1,
            flags: 0,
        };
        let interface_index = 2_u32.to_ne_bytes();
        let metric = 100_u32.to_ne_bytes();
        let message = event_message(
            RTM_NEWROUTE,
            &payload,
            &[
                (RTA_GATEWAY, &[192, 168, 1, 1]),
                (RTA_OIF, &interface_index),
                (RTA_PRIORITY, &metric),
                (RTA_PREFSRC, &[192, 168, 1, 42]),
            ],
        );
        assert_eq!(
            parse_events(&message).unwrap(),
            vec![NetworkEvent::Route {
                removed: false,
                route: Route {
                    destination: Ipv4Addr::UNSPECIFIED.into(),
                    prefix: 0,
                    source_prefix: None,
                    gateway: Some(Ipv4Addr::new(192, 168, 1, 1).into()),
                    interface_index: Some(2),
                    metric: Some(100),
                    source: Some(Ipv4Addr::new(192, 168, 1, 42).into()),
                    table: 254,
                    protocol: "boot".into(),
                    scope: "global".into(),
                    kind: "unicast".into(),
                    next_hops: Vec::new(),
                },
            }]
        );
    }

    #[test]
    fn parses_ipv6_route_and_neighbor_events() {
        let route_payload = RouteMessage {
            family: AF_INET6,
            destination_prefix: 0,
            source_prefix: 0,
            tos: 0,
            table: 254,
            protocol: 3,
            scope: 0,
            route_type: 1,
            flags: 0,
        };
        let gateway = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let source = "2001:db8::42".parse::<Ipv6Addr>().unwrap();
        let gateway_octets = gateway.octets();
        let source_octets = source.octets();
        let interface_index = 3_u32.to_ne_bytes();
        let route_message = event_message(
            RTM_NEWROUTE,
            &route_payload,
            &[
                (RTA_GATEWAY, &gateway_octets),
                (RTA_OIF, &interface_index),
                (RTA_PREFSRC, &source_octets),
            ],
        );
        let events = parse_events(&route_message).unwrap();
        let NetworkEvent::Route { route, .. } = &events[0] else {
            panic!("expected route event");
        };
        assert_eq!(route.destination, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(route.gateway, Some(gateway.into()));
        assert_eq!(route.source, Some(source.into()));

        let neighbor_payload = NeighborMessage {
            family: AF_INET6,
            padding_1: 0,
            padding_2: 0,
            interface_index: 3,
            state: NUD_STALE,
            flags: 0,
            message_type: 1,
        };
        let neighbor = "fe80::1234".parse::<Ipv6Addr>().unwrap();
        let neighbor_octets = neighbor.octets();
        let neighbor_message = event_message(
            RTM_NEWNEIGH,
            &neighbor_payload,
            &[
                (NDA_DST, &neighbor_octets),
                (NDA_LLADDR, &[0, 1, 2, 3, 4, 5]),
            ],
        );
        let events = parse_events(&neighbor_message).unwrap();
        let NetworkEvent::Neighbor {
            neighbor: entry, ..
        } = &events[0]
        else {
            panic!("expected neighbor event");
        };
        assert_eq!(entry.address, IpAddr::V6(neighbor));
        assert_eq!(entry.state, "stale");
    }

    #[test]
    fn removes_kernel_ipv6_lookup_source_placeholder() {
        let mut route = Route {
            destination: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix: 128,
            source_prefix: Some((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128)),
            gateway: None,
            interface_index: Some(1),
            metric: None,
            source: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            table: 255,
            protocol: "kernel".into(),
            scope: "global".into(),
            kind: "local".into(),
            next_hops: Vec::new(),
        };
        normalize_route_lookup(&mut route);
        assert_eq!(route.source_prefix, None);
    }

    #[test]
    fn parses_multipath_route_nexthops() {
        let mut value = Vec::new();
        append_bytes(
            &mut value,
            &RouteNextHop {
                length: 16,
                flags: 0x04,
                hops: 1,
                interface_index: 2,
            },
        );
        append_bytes(
            &mut value,
            &RouteAttribute {
                length: 8,
                attribute_type: RTA_GATEWAY,
            },
        );
        value.extend_from_slice(&[192, 168, 1, 1]);

        assert_eq!(
            parse_next_hops(&value, AF_INET),
            vec![NextHop {
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1).into()),
                interface_index: 2,
                weight: 2,
                flags: "onlink".into(),
            }]
        );
    }

    #[test]
    fn parses_ipv4_policy_rules() {
        let payload = RuleMessage {
            family: AF_INET,
            destination_prefix: 0,
            source_prefix: 24,
            tos: 0,
            table: 0,
            reserved_1: 0,
            reserved_2: 0,
            action: 1,
            flags: 1,
        };
        let priority = 1000_u32.to_ne_bytes();
        let table = 100_u32.to_ne_bytes();
        let message = event_message(
            RTM_NEWRULE,
            &payload,
            &[
                (FRA_SRC, &[10, 0, 0, 0]),
                (FRA_IIFNAME, b"eth0\0"),
                (FRA_PRIORITY, &priority),
                (FRA_TABLE, &table),
            ],
        );
        assert_eq!(
            parse_rule(&message),
            Some(Rule {
                family: IpFamily::Ipv4,
                priority: 1000,
                source: Some((Ipv4Addr::new(10, 0, 0, 0).into(), 24)),
                destination: None,
                input_interface: Some("eth0".into()),
                output_interface: None,
                fwmark: None,
                fwmask: None,
                table: 100,
                action: "lookup".into(),
                goto: None,
                flags: "permanent".into(),
            })
        );
    }

    #[test]
    fn parses_ipv6_policy_rules() {
        let payload = RuleMessage {
            family: AF_INET6,
            destination_prefix: 64,
            source_prefix: 0,
            tos: 0,
            table: 254,
            reserved_1: 0,
            reserved_2: 0,
            action: 1,
            flags: 0,
        };
        let destination = "2001:db8:1::".parse::<Ipv6Addr>().unwrap();
        let destination_octets = destination.octets();
        let message = event_message(RTM_NEWRULE, &payload, &[(FRA_DST, &destination_octets)]);
        let rule = parse_rule(&message).unwrap();
        assert_eq!(rule.family, IpFamily::Ipv6);
        assert_eq!(rule.destination, Some((destination.into(), 64)));
    }

    #[test]
    fn parses_link_events() {
        let payload = LinkMessage {
            family: 0,
            padding: 0,
            link_type: 1,
            interface_index: 2,
            flags: 1,
            change: u32::MAX,
        };
        let message = event_message(RTM_NEWLINK, &payload, &[(IFLA_IFNAME, b"eth0\0")]);
        assert_eq!(
            parse_events(&message).unwrap(),
            vec![NetworkEvent::Link {
                removed: false,
                interface_index: 2,
                name: Some("eth0".into()),
                up: true,
            }]
        );
    }

    fn event_message<T>(message_type: u16, payload: &T, attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut message = vec![0; size_of::<MessageHeader>()];
        append_bytes(&mut message, payload);
        while !message.len().is_multiple_of(4) {
            message.push(0);
        }
        for (attribute_type, value) in attributes {
            append_bytes(
                &mut message,
                &RouteAttribute {
                    length: (size_of::<RouteAttribute>() + value.len()) as u16,
                    attribute_type: *attribute_type,
                },
            );
            message.extend_from_slice(value);
            while !message.len().is_multiple_of(4) {
                message.push(0);
            }
        }
        let header = MessageHeader {
            length: message.len() as u32,
            message_type,
            flags: 0,
            sequence: 0,
            port_id: 0,
        };
        let header_bytes = value_bytes(&header);
        message[..header_bytes.len()].copy_from_slice(header_bytes);
        message
    }

    fn append_bytes<T>(target: &mut Vec<u8>, value: &T) {
        target.extend_from_slice(value_bytes(value));
    }

    fn value_bytes<T>(value: &T) -> &[u8] {
        // SAFETY: tests pass only initialized C-layout netlink structs, and the
        // returned slice cannot outlive value.
        unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
    }
}
