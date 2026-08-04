//! Explicit IPv4 neighbor discovery on directly connected networks.
//!
//! The scanner sends a one-byte UDP datagram to each target so Linux performs
//! ARP resolution, then reads the kernel neighbor table. It does not craft ARP
//! packets itself. Calls are bounded to 4096 target addresses and generate
//! network traffic.

use crate::netlink::{self, Neighbor};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

const MAX_TARGETS: u64 = 4096;

/// Timing and target controls for one active scan.
pub struct Options {
    /// Delay after each complete pass over all targets.
    pub wait: Duration,
    /// Number of complete probing passes; callers should use at least one.
    pub retries: u32,
    /// Addresses that must not receive a probe.
    pub excluded: HashSet<Ipv4Addr>,
}

/// A directly connected IPv4 network to scan.
///
/// Prefer [`Network::new`] for an interface's configured subnet and
/// [`Network::for_cidr`] for an explicitly selected CIDR after confirming it is
/// directly connected.
#[derive(Debug, Clone)]
pub struct Network {
    /// Kernel interface name used for display and result attribution.
    pub interface: String,
    /// Kernel interface index used to scope neighbor results.
    pub interface_index: i32,
    /// Local source address; this address is excluded from the target set.
    pub address: Ipv4Addr,
    /// CIDR prefix length in bits.
    pub prefix: u32,
    /// Network address stored as a host-order integer.
    pub network: u32,
    /// Broadcast/end address stored as a host-order integer.
    pub broadcast: u32,
}

impl Network {
    /// Constructs the subnet containing an interface address.
    ///
    /// `prefix` must be in `0..=32`; callers are expected to validate external
    /// input before constructing the value.
    pub fn new(interface: String, interface_index: i32, address: Ipv4Addr, prefix: u32) -> Self {
        Self::for_cidr(interface, interface_index, address, address, prefix)
    }

    /// Constructs an explicitly selected CIDR reached through an interface.
    ///
    /// `address` is the interface's local source address, while `cidr_address`
    /// may be any address inside the selected CIDR. This function does not
    /// verify routing; applications should reject CIDRs reached via a gateway.
    pub fn for_cidr(
        interface: String,
        interface_index: i32,
        address: Ipv4Addr,
        cidr_address: Ipv4Addr,
        prefix: u32,
    ) -> Self {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = u32::from(cidr_address) & mask;
        Self {
            interface,
            interface_index,
            address,
            prefix,
            network,
            broadcast: network | !mask,
        }
    }

    /// Returns the inclusive first and last addresses considered for probing.
    ///
    /// Network and broadcast addresses are excluded for prefixes through `/30`;
    /// both addresses remain usable for `/31`, and `/32` contains one address.
    pub fn host_bounds(&self) -> (u32, u32) {
        if self.prefix <= 30 {
            (self.network + 1, self.broadcast - 1)
        } else {
            (self.network, self.broadcast)
        }
    }

    /// Returns the number of potential targets, excluding the local address.
    pub fn target_count(&self) -> u64 {
        let (first, last) = self.host_bounds();
        let addresses = u64::from(last) - u64::from(first) + 1;
        addresses - u64::from(u32::from(self.address) >= first && u32::from(self.address) <= last)
    }

    /// Reports whether `address` lies between this network's inclusive bounds.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let address = u32::from(address);
        address >= self.network && address <= self.broadcast
    }
}

/// Neighbor-table snapshot produced after an active scan.
pub struct ScanResult {
    /// Resolved neighbors on the selected interface and network.
    pub neighbors: Vec<Neighbor>,
    /// Addresses whose link address was new or changed since the initial snapshot.
    pub changed: HashSet<Ipv4Addr>,
    /// Time spent probing and taking the final snapshot.
    pub elapsed: Duration,
}

/// Actively probes `networks` and returns their resolved IPv4 neighbors.
///
/// The function sends one UDP datagram per non-excluded target per retry, waits
/// [`Options::wait`] after each pass, and then performs `RTM_GETNEIGH`. It
/// refuses an empty target set and more than 4096 combined targets. Results are
/// restricted by both interface index and subnet to prevent cross-interface
/// entries from leaking into the scan.
pub fn scan(networks: &[Network], options: &Options) -> io::Result<ScanResult> {
    let target_count = networks.iter().map(Network::target_count).sum::<u64>();
    if target_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no other addresses exist on the connected IPv4 network",
        ));
    }
    if target_count > MAX_TARGETS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to probe {target_count} addresses; the current limit is {MAX_TARGETS}"
            ),
        ));
    }

    let before = netlink::ipv4_neighbors()?
        .into_iter()
        .filter(|neighbor| is_neighbor_on_networks(neighbor, networks))
        .filter_map(|neighbor| match neighbor.address {
            IpAddr::V4(address) => Some((address, neighbor.link_address)),
            IpAddr::V6(_) => None,
        })
        .collect::<HashMap<_, _>>();
    let started = Instant::now();

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    for _ in 0..options.retries {
        for network in networks {
            let own_address = u32::from(network.address);
            let (first, last) = network.host_bounds();
            for address in first..=last {
                let address = Ipv4Addr::from(address);
                if u32::from(address) != own_address && !options.excluded.contains(&address) {
                    let _ = socket.send_to(&[0], (address, 9));
                }
            }
        }
        thread::sleep(options.wait);
    }

    let mut neighbors = netlink::ipv4_neighbors()?;
    neighbors.retain(|neighbor| is_neighbor_on_networks(neighbor, networks));
    let changed = neighbors
        .iter()
        .filter_map(|neighbor| {
            let IpAddr::V4(address) = neighbor.address else {
                return None;
            };
            (before.get(&address) != Some(&neighbor.link_address)).then_some(address)
        })
        .collect();
    Ok(ScanResult {
        neighbors,
        changed,
        elapsed: started.elapsed(),
    })
}

fn is_neighbor_on_networks(neighbor: &Neighbor, networks: &[Network]) -> bool {
    let IpAddr::V4(address) = neighbor.address else {
        return false;
    };
    neighbor.link_address.is_some()
        && networks.iter().any(|network| {
            network.interface_index == neighbor.interface_index && network.contains(address)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_scan_bounds() {
        let network = Network::new("eth0".into(), 2, Ipv4Addr::new(192, 168, 1, 42), 24);
        assert_eq!(network.network, u32::from(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(
            network.host_bounds(),
            (
                u32::from(Ipv4Addr::new(192, 168, 1, 1)),
                u32::from(Ipv4Addr::new(192, 168, 1, 254))
            )
        );
        assert_eq!(network.target_count(), 253);
        assert!(network.contains(Ipv4Addr::new(192, 168, 1, 200)));
        assert!(!network.contains(Ipv4Addr::new(192, 168, 2, 1)));
    }

    #[test]
    fn handles_point_to_point_and_single_host_networks() {
        let point_to_point = Network::new("ppp0".into(), 2, Ipv4Addr::new(10, 0, 0, 0), 31);
        assert_eq!(point_to_point.target_count(), 1);

        let single = Network::new("tun0".into(), 2, Ipv4Addr::new(10, 0, 0, 1), 32);
        assert_eq!(single.target_count(), 0);
    }
}
