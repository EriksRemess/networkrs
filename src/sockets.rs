//! Compatible IPv4 and IPv6 socket snapshots from Linux procfs.
//!
//! This module parses `/proc/net/tcp` and `/proc/net/udp`. For richer transport
//! metrics, use [`crate::sock_diag`]. Process attribution walks
//! `/proc/<pid>/fd` and is inherently best effort because processes and file
//! descriptors can change during the walk or be hidden by permissions.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

const PROC_NET_TCP: &str = "/proc/net/tcp";
const PROC_NET_UDP: &str = "/proc/net/udp";
const PROC_NET_TCP6: &str = "/proc/net/tcp6";
const PROC_NET_UDP6: &str = "/proc/net/udp6";

/// One IPv4 or IPv6 TCP or UDP entry from procfs.
#[derive(Debug, Eq, PartialEq)]
pub struct NetworkSocket {
    /// Transport protocol.
    pub protocol: Protocol,
    /// Local IP endpoint.
    pub local: SocketAddr,
    /// Remote endpoint, or a family-appropriate wildcard when unconnected.
    pub remote: SocketAddr,
    /// Human-readable Linux socket state.
    pub state: &'static str,
    /// Numeric owner UID reported by the kernel.
    pub uid: u32,
    /// Socket inode used for best-effort process attribution.
    pub inode: u64,
}

/// Supported transport protocols.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// Predicate used by the CLI to select a subset of sockets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum View {
    /// Include every parsed socket.
    All,
    /// Include only TCP sockets.
    Tcp,
    /// Include only UDP sockets.
    Udp,
    /// Include TCP listeners and unconnected UDP sockets.
    Listening,
    /// Include sockets with a non-wildcard remote endpoint.
    Connected,
}

/// Process observed holding a file descriptor for a socket inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketProcess {
    /// Process identifier.
    pub pid: u32,
    /// Name read from `/proc/<pid>/comm`.
    pub name: String,
}

impl Protocol {
    /// Returns the uppercase display name used by the CLI.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

impl View {
    /// Parses a lowercase CLI view name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "all" => Some(Self::All),
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "listening" => Some(Self::Listening),
            "connected" => Some(Self::Connected),
            _ => None,
        }
    }

    /// Reports whether a socket belongs in this view.
    pub fn matches(self, socket: &NetworkSocket) -> bool {
        match self {
            Self::All => true,
            Self::Tcp => socket.protocol == Protocol::Tcp,
            Self::Udp => socket.protocol == Protocol::Udp,
            Self::Listening => {
                socket.state == "listen"
                    || (socket.protocol == Protocol::Udp && remote_is_unspecified(socket))
            }
            Self::Connected => !remote_is_unspecified(socket),
        }
    }
}

fn remote_is_unspecified(socket: &NetworkSocket) -> bool {
    socket.remote.ip().is_unspecified() && socket.remote.port() == 0
}

/// Reads and parses the current IPv4 TCP and UDP procfs tables.
///
/// Entries are sorted by protocol, local port/address, and remote port. A
/// procfs read failure is returned as an I/O error; malformed individual rows
/// are skipped because tables can change while being read.
pub fn ipv4_sockets() -> io::Result<Vec<NetworkSocket>> {
    let mut sockets = parse_table(&fs::read_to_string(PROC_NET_TCP)?, Protocol::Tcp);
    sockets.extend(parse_table(
        &fs::read_to_string(PROC_NET_UDP)?,
        Protocol::Udp,
    ));
    sort_sockets(&mut sockets);
    Ok(sockets)
}

/// Reads and parses the current IPv6 TCP and UDP procfs tables.
pub fn ipv6_sockets() -> io::Result<Vec<NetworkSocket>> {
    let mut sockets = parse_table(&fs::read_to_string(PROC_NET_TCP6)?, Protocol::Tcp);
    sockets.extend(parse_table(
        &fs::read_to_string(PROC_NET_UDP6)?,
        Protocol::Udp,
    ));
    sort_sockets(&mut sockets);
    Ok(sockets)
}

/// Reads both IPv4 and IPv6 TCP and UDP procfs tables.
pub fn ip_sockets() -> io::Result<Vec<NetworkSocket>> {
    let mut sockets = ipv4_sockets()?;
    match ipv6_sockets() {
        Ok(ipv6) => sockets.extend(ipv6),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    sort_sockets(&mut sockets);
    Ok(sockets)
}

fn sort_sockets(sockets: &mut [NetworkSocket]) {
    sockets.sort_by_key(|socket| {
        (
            socket.protocol,
            socket.local.port(),
            socket.local.ip(),
            socket.remote.port(),
        )
    });
}

/// Finds processes currently referencing any inode in `inodes`.
///
/// Missing processes, inaccessible descriptor directories, and racing file
/// descriptors are skipped. The map can therefore be incomplete even when the
/// socket itself is visible.
pub fn socket_processes(inodes: &HashSet<u64>) -> HashMap<u64, Vec<SocketProcess>> {
    let Ok(processes) = fs::read_dir("/proc") else {
        return HashMap::new();
    };
    let mut result = HashMap::<u64, Vec<SocketProcess>>::new();

    for process in processes.filter_map(Result::ok) {
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(descriptors) = fs::read_dir(process.path().join("fd")) else {
            continue;
        };
        let name = fs::read_to_string(process.path().join("comm"))
            .map(|name| name.trim().to_owned())
            .unwrap_or_else(|_| "unknown".into());

        for descriptor in descriptors.filter_map(Result::ok) {
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            let Some(inode) = target.to_str().and_then(parse_socket_inode) else {
                continue;
            };
            if !inodes.contains(&inode) {
                continue;
            }
            let processes = result.entry(inode).or_default();
            if !processes.iter().any(|process| process.pid == pid) {
                processes.push(SocketProcess {
                    pid,
                    name: name.clone(),
                });
            }
        }
    }
    for processes in result.values_mut() {
        processes.sort_by_key(|process| process.pid);
    }
    result
}

fn parse_socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn parse_table(contents: &str, protocol: Protocol) -> Vec<NetworkSocket> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| parse_line(line, protocol))
        .collect()
}

fn parse_line(line: &str, protocol: Protocol) -> Option<NetworkSocket> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 10 {
        return None;
    }
    let state = u8::from_str_radix(fields[3], 16).ok()?;
    Some(NetworkSocket {
        protocol,
        local: parse_endpoint(fields[1])?,
        remote: parse_endpoint(fields[2])?,
        state: socket_state(protocol, state),
        uid: fields[7].parse().ok()?,
        inode: fields[9].parse().ok()?,
    })
}

fn parse_endpoint(value: &str) -> Option<SocketAddr> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match address.len() {
        8 => {
            let address = u32::from_str_radix(address, 16).ok()?;
            Some(SocketAddrV4::new(Ipv4Addr::from(address.to_le_bytes()), port).into())
        }
        32 => {
            let mut octets = [0_u8; 16];
            for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                octets[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            Some(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0).into())
        }
        _ => None,
    }
}

fn socket_state(protocol: Protocol, state: u8) -> &'static str {
    match (protocol, state) {
        (Protocol::Tcp, 0x01) => "established",
        (Protocol::Tcp, 0x02) => "syn-sent",
        (Protocol::Tcp, 0x03) => "syn-received",
        (Protocol::Tcp, 0x04) => "fin-wait-1",
        (Protocol::Tcp, 0x05) => "fin-wait-2",
        (Protocol::Tcp, 0x06) => "time-wait",
        (Protocol::Tcp, 0x07) => "closed",
        (Protocol::Tcp, 0x08) => "close-wait",
        (Protocol::Tcp, 0x09) => "last-ack",
        (Protocol::Tcp, 0x0a) => "listen",
        (Protocol::Tcp, 0x0b) => "closing",
        (Protocol::Tcp, 0x0c) => "new-syn-received",
        (Protocol::Udp, 0x01) => "connected",
        (Protocol::Udp, 0x07) => "unconnected",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_procfs_rows() {
        let socket = parse_line(
            "0: 0100007F:0522 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 26014",
            Protocol::Tcp,
        )
        .unwrap();
        assert_eq!(socket.local, "127.0.0.1:1314".parse().unwrap());
        assert_eq!(socket.remote, "0.0.0.0:0".parse().unwrap());
        assert_eq!(socket.state, "listen");
        assert_eq!(socket.uid, 0);
        assert_eq!(socket.inode, 26014);
    }

    #[test]
    fn parses_udp_procfs_rows() {
        let socket = parse_line(
            "1727: 00000000:BADF 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 69608",
            Protocol::Udp,
        )
        .unwrap();
        assert_eq!(socket.local, "0.0.0.0:47839".parse().unwrap());
        assert_eq!(socket.state, "unconnected");
        assert_eq!(socket.uid, 1000);
    }

    #[test]
    fn parses_ipv6_procfs_rows() {
        let socket = parse_line(
            "0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 42",
            Protocol::Tcp,
        )
        .unwrap();
        assert_eq!(socket.local, "[::1]:443".parse().unwrap());
        assert_eq!(socket.remote, "[::]:0".parse().unwrap());
    }

    #[test]
    fn parses_procfs_socket_links() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("pipe:[12345]"), None);
    }

    #[test]
    fn filters_socket_views() {
        let listening = parse_line(
            "0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1",
            Protocol::Tcp,
        )
        .unwrap();
        let connected = parse_line(
            "1: 0100007F:C000 08080808:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 2",
            Protocol::Tcp,
        )
        .unwrap();
        let udp = parse_line(
            "2: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 3",
            Protocol::Udp,
        )
        .unwrap();

        assert!(View::Listening.matches(&listening));
        assert!(View::Listening.matches(&udp));
        assert!(!View::Listening.matches(&connected));
        assert!(View::Connected.matches(&connected));
        assert!(!View::Connected.matches(&udp));
        assert!(View::Tcp.matches(&listening));
        assert!(View::Udp.matches(&udp));
    }
}
