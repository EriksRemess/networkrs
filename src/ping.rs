//! Explicit IPv4 ICMP echo measurements through a Linux ping socket.
//!
//! Linux controls unprivileged access with `/proc/sys/net/ipv4/ping_group_range`.
//! [`echo`] can therefore return a permission error without raw-socket
//! privileges. Calling this module generates network traffic.

use std::ffi::{c_int, c_short, c_void};
use std::io;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const AF_INET: c_int = 2;
const SOCK_DGRAM: c_int = 2;
const IPPROTO_ICMP: c_int = 1;
const POLLIN: c_short = 0x0001;

/// Aggregate result of a bounded ICMP echo run.
#[derive(Debug, PartialEq)]
pub struct Result {
    /// Number of echo requests attempted.
    pub transmitted: u32,
    /// Number of matching echo replies received.
    pub received: u32,
    /// Lowest round-trip time, or `None` when no reply arrived.
    pub minimum: Option<Duration>,
    /// Arithmetic mean round-trip time, or `None` when no reply arrived.
    pub average: Option<Duration>,
    /// Highest round-trip time, or `None` when no reply arrived.
    pub maximum: Option<Duration>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketAddressIpv4 {
    family: u16,
    port: u16,
    address: u32,
    zero: [u8; 8],
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    returned_events: c_short,
}

unsafe extern "C" {
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn sendto(
        socket: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const c_void,
        address_length: u32,
    ) -> isize;
    fn recv(socket: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
    fn poll(descriptors: *mut PollFd, count: usize, timeout_ms: c_int) -> c_int;
}

/// Sends `count` IPv4 ICMP echo requests and measures matching replies.
///
/// Each request waits up to `timeout`; total blocking time can therefore reach
/// approximately `count * timeout`. Timeouts are represented as missing replies
/// in the returned result. Socket, send, receive, and polling failures are
/// returned as I/O errors.
pub fn echo(address: Ipv4Addr, count: u32, timeout: Duration) -> io::Result<Result> {
    // Linux ping sockets allow unprivileged ICMP according to ping_group_range.
    // SAFETY: arguments are Linux socket-domain, type, and protocol constants.
    let raw_fd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let destination = SocketAddressIpv4 {
        family: AF_INET as u16,
        port: 0,
        address: u32::from_ne_bytes(address.octets()),
        zero: [0; 8],
    };
    let mut elapsed = Vec::new();
    for sequence in 0..count {
        let packet = echo_request(sequence as u16);
        let started = Instant::now();
        // SAFETY: packet and destination are initialized and live for the call.
        let sent = unsafe {
            sendto(
                socket.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&raw const destination).cast(),
                size_of::<SocketAddressIpv4>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut descriptor = PollFd {
            fd: socket.as_raw_fd(),
            events: POLLIN,
            returned_events: 0,
        };
        let timeout_ms = timeout.as_millis().min(c_int::MAX as u128) as c_int;
        // SAFETY: descriptor points to one writable pollfd value.
        let ready = unsafe { poll(&mut descriptor, 1, timeout_ms) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            continue;
        }
        let mut response = [0_u8; 256];
        // SAFETY: response is writable storage and its exact length is supplied.
        let received = unsafe {
            recv(
                socket.as_raw_fd(),
                response.as_mut_ptr().cast(),
                response.len(),
                0,
            )
        };
        if received >= 8
            && response[0] == 0
            && u16::from_be_bytes([response[6], response[7]]) == sequence as u16
        {
            elapsed.push(started.elapsed());
        }
    }
    elapsed.sort();
    let average = if elapsed.is_empty() {
        None
    } else {
        Some(Duration::from_nanos(
            (elapsed.iter().map(Duration::as_nanos).sum::<u128>() / elapsed.len() as u128)
                .try_into()
                .unwrap_or(u64::MAX),
        ))
    };
    Ok(Result {
        transmitted: count,
        received: elapsed.len() as u32,
        minimum: elapsed.first().copied(),
        average,
        maximum: elapsed.last().copied(),
    })
}

fn echo_request(sequence: u16) -> [u8; 16] {
    let mut packet = [0_u8; 16];
    packet[0] = 8;
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..].copy_from_slice(b"networkr");
    let checksum = checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
        sum += u32::from(word);
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_echo_request() {
        let packet = echo_request(7);
        assert_eq!(packet[0], 8);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 7);
        assert_eq!(checksum(&packet), 0);
    }
}
