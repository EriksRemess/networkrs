//! IPv4 and IPv6 transport diagnostics from Linux socket diagnostic netlink.
//!
//! The wire format follows `include/uapi/linux/inet_diag.h` and the stable
//! prefix of `include/uapi/linux/tcp.h::tcp_info`. The kernel must enable
//! `CONFIG_INET_DIAG`; otherwise the diagnostic functions return the kernel error.
//! Use [`crate::sockets`] as a broadly available procfs fallback.

use crate::sockets::Protocol;
use std::ffi::{c_int, c_void};
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// Socket/netlink constants from linux/socket.h, linux/netlink.h, and
// linux/sock_diag.h.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_NETLINK: c_int = 16;
const SOCK_RAW: c_int = 3;
const NETLINK_SOCK_DIAG: c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x100 | 0x200;
const NLMSG_ERROR: u16 = 0x02;
const NLMSG_DONE: u16 = 0x03;
const NLMSG_OVERRUN: u16 = 0x04;
// Requested extension attributes from linux/inet_diag.h.
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_CONG: u16 = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;

/// Kernel diagnostic record for one IPv4 or IPv6 TCP or UDP socket.
#[derive(Debug, Eq, PartialEq)]
pub struct SocketDiagnostic {
    /// Transport protocol requested from the diagnostic family.
    pub protocol: Protocol,
    /// Local IP endpoint.
    pub local: SocketAddr,
    /// Remote endpoint, or a wildcard endpoint for unconnected sockets.
    pub remote: SocketAddr,
    /// Human-readable socket state.
    pub state: &'static str,
    /// Numeric owner UID.
    pub uid: u32,
    /// Socket inode.
    pub inode: u64,
    /// Bound interface index, or zero when not bound to an interface.
    pub interface_index: u32,
    /// Human-readable kernel timer kind, or `off`.
    pub timer: &'static str,
    /// Milliseconds until the current timer expires.
    pub expires_ms: u32,
    /// Retransmit count carried in the base diagnostic record.
    pub retransmits: u8,
    /// Bytes queued for receipt.
    pub receive_queue: u32,
    /// Bytes queued for transmission.
    pub send_queue: u32,
    /// Congestion-control algorithm name when reported by the kernel.
    pub congestion: Option<String>,
    /// TCP-specific metrics; always `None` for UDP.
    pub tcp: Option<TcpDiagnostic>,
}

/// Selected metrics from the stable prefix of Linux `struct tcp_info`.
#[derive(Debug, Eq, PartialEq)]
pub struct TcpDiagnostic {
    /// Retransmission timeout in microseconds.
    pub rto_us: u32,
    /// Current send maximum segment size in bytes.
    pub send_mss: u32,
    /// Current receive maximum segment size in bytes.
    pub receive_mss: u32,
    /// Segments sent but not yet acknowledged.
    pub unacked: u32,
    /// Segments currently considered lost.
    pub lost: u32,
    /// Segments retransmitted in the current accounting window.
    pub retransmitted: u32,
    /// Smoothed round-trip time in microseconds.
    pub rtt_us: u32,
    /// Round-trip-time variation in microseconds.
    pub rtt_variance_us: u32,
    /// Send slow-start threshold in segments.
    pub send_ssthresh: u32,
    /// Send congestion window in segments.
    pub send_cwnd: u32,
    /// Discovered path MTU in bytes.
    pub path_mtu: u32,
    /// Total retransmitted segments for the connection.
    pub total_retransmits: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Local mirror of Linux `struct sockaddr_nl`.
struct SocketAddress {
    family: u16,
    padding: u16,
    port_id: u32,
    groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Local mirror of Linux `struct nlmsghdr`.
struct MessageHeader {
    length: u32,
    message_type: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Local mirror of Linux `struct inet_diag_sockid`.
struct SocketId {
    source_port: u16,
    destination_port: u16,
    source: [u32; 4],
    destination: [u32; 4],
    interface_index: u32,
    cookie: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Local mirror of Linux `struct inet_diag_req_v2`.
struct DiagnosticRequest {
    family: u8,
    protocol: u8,
    extensions: u8,
    padding: u8,
    states: u32,
    id: SocketId,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Netlink header followed immediately by an `inet_diag_req_v2` payload.
struct Request {
    header: MessageHeader,
    message: DiagnosticRequest,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Local mirror of Linux `struct inet_diag_msg`.
struct DiagnosticMessage {
    family: u8,
    state: u8,
    timer: u8,
    retransmits: u8,
    id: SocketId,
    expires_ms: u32,
    receive_queue: u32,
    send_queue: u32,
    uid: u32,
    inode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Local mirror of Linux `struct rtattr` used by diagnostic extensions.
struct Attribute {
    length: u16,
    kind: u16,
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
}

/// Dumps diagnostic records for all visible IPv4 TCP and UDP sockets.
///
/// The operation performs separate netlink dumps for TCP and UDP and sorts the
/// combined result. It can fail when socket diagnostics are disabled, access is
/// denied, a dump is interrupted, or the kernel returns malformed data.
pub fn ipv4_diagnostics() -> io::Result<Vec<SocketDiagnostic>> {
    let mut diagnostics = diagnostic_dump(AF_INET, Protocol::Tcp, 6, 1)?;
    diagnostics.extend(diagnostic_dump(AF_INET, Protocol::Udp, 17, 2)?);
    sort_diagnostics(&mut diagnostics);
    Ok(diagnostics)
}

/// Dumps diagnostic records for all visible IPv6 TCP and UDP sockets.
pub fn ipv6_diagnostics() -> io::Result<Vec<SocketDiagnostic>> {
    let mut diagnostics = diagnostic_dump(AF_INET6, Protocol::Tcp, 6, 3)?;
    diagnostics.extend(diagnostic_dump(AF_INET6, Protocol::Udp, 17, 4)?);
    sort_diagnostics(&mut diagnostics);
    Ok(diagnostics)
}

/// Dumps diagnostic records for all visible IPv4 and IPv6 TCP and UDP sockets.
pub fn ip_diagnostics() -> io::Result<Vec<SocketDiagnostic>> {
    let mut diagnostics = ipv4_diagnostics()?;
    match ipv6_diagnostics() {
        Ok(ipv6) => diagnostics.extend(ipv6),
        // EPROTONOSUPPORT or EAFNOSUPPORT on kernels built without IPv6.
        Err(error) if matches!(error.raw_os_error(), Some(93 | 97)) => {}
        Err(error) => return Err(error),
    }
    sort_diagnostics(&mut diagnostics);
    Ok(diagnostics)
}

fn sort_diagnostics(diagnostics: &mut [SocketDiagnostic]) {
    diagnostics.sort_by_key(|diagnostic| {
        (
            diagnostic.protocol,
            diagnostic.local.port(),
            diagnostic.local.ip(),
            diagnostic.remote.port(),
        )
    });
}

fn diagnostic_dump(
    family: u8,
    protocol: Protocol,
    protocol_number: u8,
    sequence: u32,
) -> io::Result<Vec<SocketDiagnostic>> {
    let socket = open_socket()?;
    let request = Request {
        header: MessageHeader {
            length: size_of::<Request>() as u32,
            message_type: SOCK_DIAG_BY_FAMILY,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            sequence,
            port_id: 0,
        },
        message: DiagnosticRequest {
            family,
            protocol: protocol_number,
            extensions: if protocol == Protocol::Tcp {
                (1 << (INET_DIAG_INFO - 1)) | (1 << (INET_DIAG_CONG - 1))
            } else {
                0
            },
            padding: 0,
            states: u32::MAX,
            id: SocketId {
                source_port: 0,
                destination_port: 0,
                source: [0; 4],
                destination: [0; 4],
                interface_index: 0,
                cookie: [u32::MAX; 2],
            },
        },
    };
    send_request(&socket, &request)?;
    receive_dump(&socket, protocol, sequence)
}

fn open_socket() -> io::Result<OwnedFd> {
    // SAFETY: arguments are Linux socket and netlink UAPI constants.
    let raw_fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let local = SocketAddress {
        family: AF_NETLINK as u16,
        padding: 0,
        port_id: 0,
        groups: 0,
    };
    // SAFETY: local has the sockaddr_nl layout and is valid for the call.
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

fn send_request(socket: &OwnedFd, request: &Request) -> io::Result<()> {
    let kernel = SocketAddress {
        family: AF_NETLINK as u16,
        padding: 0,
        port_id: 0,
        groups: 0,
    };
    // SAFETY: request and kernel are initialized C-layout values valid for sendto.
    let sent = unsafe {
        sendto(
            socket.as_raw_fd(),
            (request as *const Request).cast(),
            size_of::<Request>(),
            0,
            (&raw const kernel).cast(),
            size_of::<SocketAddress>() as u32,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != size_of::<Request>() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete socket diagnostic request",
        ));
    }
    Ok(())
}

fn receive_dump(
    socket: &OwnedFd,
    protocol: Protocol,
    sequence: u32,
) -> io::Result<Vec<SocketDiagnostic>> {
    let mut diagnostics = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let received = receive(socket, &mut buffer)?;
        let mut offset = 0;
        while received.saturating_sub(offset) >= size_of::<MessageHeader>() {
            let header =
                read_unaligned::<MessageHeader>(&buffer[offset..received]).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated socket diagnostic header",
                    )
                })?;
            let length = header.length as usize;
            if length < size_of::<MessageHeader>() || length > received - offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid socket diagnostic message length",
                ));
            }
            if header.sequence == sequence {
                let message = &buffer[offset..offset + length];
                match header.message_type {
                    NLMSG_DONE => return Ok(diagnostics),
                    NLMSG_ERROR => parse_error(message)?,
                    NLMSG_OVERRUN => {
                        return Err(io::Error::other("socket diagnostic dump overran"));
                    }
                    SOCK_DIAG_BY_FAMILY => {
                        if let Some(diagnostic) = parse_diagnostic(message, protocol) {
                            diagnostics.push(diagnostic);
                        }
                    }
                    _ => {}
                }
            }
            offset += align_to_4(length);
        }
    }
}

fn receive(socket: &OwnedFd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: buffer is writable and socket is a live descriptor.
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
                "socket diagnostic netlink socket closed",
            ));
        }
        return Ok(received as usize);
    }
}

fn parse_diagnostic(message: &[u8], protocol: Protocol) -> Option<SocketDiagnostic> {
    let diagnostic =
        read_unaligned::<DiagnosticMessage>(message.get(size_of::<MessageHeader>()..)?)?;
    if !matches!(diagnostic.family, AF_INET | AF_INET6) {
        return None;
    }
    let attributes = attributes(message, size_of::<DiagnosticMessage>())?;
    let tcp = attributes
        .iter()
        .find_map(|(kind, value)| (*kind == INET_DIAG_INFO).then(|| parse_tcp_info(value))?)
        .filter(|_| protocol == Protocol::Tcp);
    let congestion = attributes.iter().find_map(|(kind, value)| {
        (*kind == INET_DIAG_CONG).then(|| nul_terminated_string(value))?
    });
    Some(SocketDiagnostic {
        protocol,
        local: endpoint(
            diagnostic.family,
            diagnostic.id.source,
            diagnostic.id.source_port,
        )?,
        remote: endpoint(
            diagnostic.family,
            diagnostic.id.destination,
            diagnostic.id.destination_port,
        )?,
        state: socket_state(protocol, diagnostic.state),
        uid: diagnostic.uid,
        inode: u64::from(diagnostic.inode),
        interface_index: diagnostic.id.interface_index,
        timer: timer_name(diagnostic.timer),
        expires_ms: diagnostic.expires_ms,
        retransmits: diagnostic.retransmits,
        receive_queue: diagnostic.receive_queue,
        send_queue: diagnostic.send_queue,
        congestion,
        tcp,
    })
}

fn parse_tcp_info(value: &[u8]) -> Option<TcpDiagnostic> {
    Some(TcpDiagnostic {
        rto_us: native_u32(value, 8)?,
        send_mss: native_u32(value, 16)?,
        receive_mss: native_u32(value, 20)?,
        unacked: native_u32(value, 24)?,
        lost: native_u32(value, 32)?,
        retransmitted: native_u32(value, 36)?,
        path_mtu: native_u32(value, 60)?,
        rtt_us: native_u32(value, 68)?,
        rtt_variance_us: native_u32(value, 72)?,
        send_ssthresh: native_u32(value, 76)?,
        send_cwnd: native_u32(value, 80)?,
        total_retransmits: native_u32(value, 100)?,
    })
}

fn endpoint(family: u8, address: [u32; 4], port: u16) -> Option<SocketAddr> {
    let port = u16::from_be(port);
    match family {
        AF_INET => Some(SocketAddrV4::new(Ipv4Addr::from(address[0].to_ne_bytes()), port).into()),
        AF_INET6 => {
            let mut octets = [0_u8; 16];
            for (index, word) in address.into_iter().enumerate() {
                octets[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
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

fn timer_name(timer: u8) -> &'static str {
    match timer {
        0 => "off",
        1 => "retransmit",
        2 => "keepalive",
        3 => "time-wait",
        4 => "zero-window-probe",
        5 => "delayed-ack",
        _ => "unknown",
    }
}

fn attributes(message: &[u8], payload_size: usize) -> Option<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    let mut offset = align_to_4(size_of::<MessageHeader>() + payload_size);
    while message.len().saturating_sub(offset) >= size_of::<Attribute>() {
        let attribute = read_unaligned::<Attribute>(&message[offset..])?;
        let length = usize::from(attribute.length);
        if length < size_of::<Attribute>() || length > message.len() - offset {
            return None;
        }
        result.push((
            attribute.kind & NLA_TYPE_MASK,
            &message[offset + size_of::<Attribute>()..offset + length],
        ));
        offset += align_to_4(length);
    }
    Some(result)
}

fn parse_error(message: &[u8]) -> io::Result<()> {
    let payload = message
        .get(size_of::<MessageHeader>()..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated netlink error"))?;
    let error = read_unaligned::<i32>(payload)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated netlink error"))?;
    if error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-error))
    }
}

fn native_u32(value: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        value.get(offset..offset + 4)?.try_into().ok()?,
    ))
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

fn read_unaligned<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: the length was checked and all callers use initialized C-layout values.
    Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

// Diagnostic netlink messages and attributes use four-byte alignment.
const fn align_to_4(length: usize) -> usize {
    (length + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_uapi_layouts_match() {
        assert_eq!(size_of::<SocketAddress>(), 12);
        assert_eq!(size_of::<MessageHeader>(), 16);
        assert_eq!(size_of::<SocketId>(), 48);
        assert_eq!(size_of::<DiagnosticRequest>(), 56);
        assert_eq!(size_of::<Request>(), 72);
        assert_eq!(size_of::<DiagnosticMessage>(), 72);
    }

    #[test]
    fn parses_tcp_info_prefix() {
        let mut value = vec![0_u8; 104];
        value[8..12].copy_from_slice(&250_000_u32.to_ne_bytes());
        value[68..72].copy_from_slice(&12_500_u32.to_ne_bytes());
        value[72..76].copy_from_slice(&2_000_u32.to_ne_bytes());
        value[80..84].copy_from_slice(&10_u32.to_ne_bytes());
        value[100..104].copy_from_slice(&3_u32.to_ne_bytes());
        let info = parse_tcp_info(&value).unwrap();
        assert_eq!(info.rto_us, 250_000);
        assert_eq!(info.rtt_us, 12_500);
        assert_eq!(info.rtt_variance_us, 2_000);
        assert_eq!(info.send_cwnd, 10);
        assert_eq!(info.total_retransmits, 3);
    }

    #[test]
    fn parses_network_order_endpoints() {
        assert_eq!(
            endpoint(
                AF_INET,
                [u32::from_ne_bytes([192, 168, 1, 5]), 0, 0, 0],
                443_u16.to_be()
            ),
            Some("192.168.1.5:443".parse().unwrap())
        );
    }

    #[test]
    fn parses_ipv6_network_order_endpoints() {
        let address = Ipv6Addr::LOCALHOST.octets();
        let mut words = [0_u32; 4];
        for (index, chunk) in address.chunks_exact(4).enumerate() {
            words[index] = u32::from_ne_bytes(chunk.try_into().unwrap());
        }
        assert_eq!(
            endpoint(AF_INET6, words, 53_u16.to_be()),
            Some("[::1]:53".parse().unwrap())
        );
    }
}
