//! Internal generic-netlink transport shared by ethtool and nl80211.
//!
//! Family identifiers are runtime values, so [`Client::connect`] first asks the
//! control family (`GENL_ID_CTRL`) to resolve a family name. Subsequent requests
//! use the resolved identifier and monotonically increasing sequence numbers.
//!
//! The framing follows `include/uapi/linux/netlink.h` and
//! `include/uapi/linux/genetlink.h`: a netlink header contains a generic-netlink
//! header followed by four-byte-aligned attributes. Nested attributes set
//! `NLA_F_NESTED`; parsers mask flag bits with `NLA_TYPE_MASK` before exposing
//! the attribute kind.

use std::ffi::{c_int, c_void};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// Socket and netlink constants from linux/socket.h and linux/netlink.h.
const AF_NETLINK: c_int = 16;
const SOCK_RAW: c_int = 3;
const NETLINK_GENERIC: c_int = 16;
// Generic-netlink controller constants from linux/genetlink.h.
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x100 | 0x200;
const NLMSG_ERROR: u16 = 0x02;
const NLMSG_DONE: u16 = 0x03;
const NLMSG_OVERRUN: u16 = 0x04;
const NLA_TYPE_MASK: u16 = 0x3fff;
const NLA_F_NESTED: u16 = 1 << 15;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    // `kind` is stored without NLA flag bits after parsing. Builders may set
    // NLA_F_NESTED before serialization.
    pub kind: u16,
    pub value: Vec<u8>,
}

impl Attribute {
    pub fn u32(kind: u16, value: u32) -> Self {
        Self {
            kind,
            value: value.to_ne_bytes().to_vec(),
        }
    }

    pub fn nested(kind: u16, attributes: &[Self]) -> Self {
        let mut value = Vec::new();
        for attribute in attributes {
            append_value(
                &mut value,
                &AttributeHeader {
                    length: (size_of::<AttributeHeader>() + attribute.value.len()) as u16,
                    kind: attribute.kind,
                },
            );
            value.extend_from_slice(&attribute.value);
            while !value.len().is_multiple_of(4) {
                value.push(0);
            }
        }
        Self {
            kind: kind | NLA_F_NESTED,
            value,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Message {
    pub command: u8,
    pub attributes: Vec<Attribute>,
}

pub struct Client {
    socket: OwnedFd,
    family_id: u16,
    sequence: u32,
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
/// Local mirror of Linux `struct genlmsghdr`.
struct GenericHeader {
    command: u8,
    version: u8,
    reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Local mirror of Linux `struct nlattr`.
struct AttributeHeader {
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

impl Client {
    pub fn connect(family_name: &str) -> io::Result<Self> {
        let socket = open_socket()?;
        let mut name = family_name.as_bytes().to_vec();
        name.push(0);
        let request = build_message(
            GENL_ID_CTRL,
            1,
            CTRL_CMD_GETFAMILY,
            1,
            NLM_F_REQUEST,
            &[Attribute {
                kind: CTRL_ATTR_FAMILY_NAME,
                value: name,
            }],
        );
        send_message(&socket, &request)?;
        let response = receive_once(&socket)?;
        let messages = parse_messages(&response, GENL_ID_CTRL, 1)?;
        let family_id = messages
            .iter()
            .flat_map(|message| &message.attributes)
            .find_map(|attribute| {
                (attribute.kind == CTRL_ATTR_FAMILY_ID).then(|| native_u16(&attribute.value))?
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("generic netlink family {family_name} is unavailable"),
                )
            })?;
        Ok(Self {
            socket,
            family_id,
            sequence: 1,
        })
    }

    pub fn request(
        &mut self,
        command: u8,
        version: u8,
        dump: bool,
        attributes: &[Attribute],
    ) -> io::Result<Vec<Message>> {
        self.sequence = self.sequence.wrapping_add(1);
        let flags = NLM_F_REQUEST | if dump { NLM_F_DUMP } else { 0 };
        let request = build_message(
            self.family_id,
            self.sequence,
            command,
            version,
            flags,
            attributes,
        );
        send_message(&self.socket, &request)?;

        let mut messages = Vec::new();
        loop {
            let response = receive_once(&self.socket)?;
            let parsed = parse_messages(&response, self.family_id, self.sequence)?;
            let done = response_has_done(&response, self.sequence)?;
            messages.extend(parsed);
            if done || !dump {
                return Ok(messages);
            }
        }
    }
}

pub fn nested_attributes(value: &[u8]) -> Option<Vec<Attribute>> {
    parse_attributes(value, 0)
}

pub fn native_u16(value: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(value.get(..2)?.try_into().ok()?))
}

pub fn native_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(value.get(..4)?.try_into().ok()?))
}

pub fn native_u64(value: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(value.get(..8)?.try_into().ok()?))
}

pub fn string(value: &[u8]) -> Option<String> {
    let length = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    std::str::from_utf8(&value[..length])
        .ok()
        .map(str::to_owned)
}

fn open_socket() -> io::Result<OwnedFd> {
    // SAFETY: arguments are Linux socket and generic-netlink UAPI constants.
    let raw_fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) };
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
    // SAFETY: local has the sockaddr_nl layout and is valid for bind.
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

fn build_message(
    message_type: u16,
    sequence: u32,
    command: u8,
    version: u8,
    flags: u16,
    attributes: &[Attribute],
) -> Vec<u8> {
    let mut message = vec![0; size_of::<MessageHeader>()];
    append_value(
        &mut message,
        &GenericHeader {
            command,
            version,
            reserved: 0,
        },
    );
    for attribute in attributes {
        append_value(
            &mut message,
            &AttributeHeader {
                length: (size_of::<AttributeHeader>() + attribute.value.len()) as u16,
                kind: attribute.kind,
            },
        );
        message.extend_from_slice(&attribute.value);
        while !message.len().is_multiple_of(4) {
            message.push(0);
        }
    }
    let header = MessageHeader {
        length: message.len() as u32,
        message_type,
        flags,
        sequence,
        port_id: 0,
    };
    let bytes = value_bytes(&header);
    message[..bytes.len()].copy_from_slice(bytes);
    message
}

fn send_message(socket: &OwnedFd, message: &[u8]) -> io::Result<()> {
    let kernel = SocketAddress {
        family: AF_NETLINK as u16,
        padding: 0,
        port_id: 0,
        groups: 0,
    };
    // SAFETY: both byte slice and sockaddr remain valid for sendto.
    let sent = unsafe {
        sendto(
            socket.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            0,
            (&raw const kernel).cast(),
            size_of::<SocketAddress>() as u32,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != message.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete generic netlink request",
        ));
    }
    Ok(())
}

fn receive_once(socket: &OwnedFd) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0_u8; 64 * 1024];
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
                "generic netlink socket closed",
            ));
        }
        buffer.truncate(received as usize);
        return Ok(buffer);
    }
}

fn parse_messages(response: &[u8], message_type: u16, sequence: u32) -> io::Result<Vec<Message>> {
    let mut messages = Vec::new();
    let mut offset = 0;
    while response.len().saturating_sub(offset) >= size_of::<MessageHeader>() {
        let header = read_unaligned::<MessageHeader>(&response[offset..]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated generic netlink header",
            )
        })?;
        let length = header.length as usize;
        if length < size_of::<MessageHeader>() || length > response.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid generic netlink message length",
            ));
        }
        if header.sequence == sequence {
            let message = &response[offset..offset + length];
            match header.message_type {
                NLMSG_ERROR => parse_error(message)?,
                NLMSG_OVERRUN => return Err(io::Error::other("generic netlink dump overran")),
                kind if kind == message_type => {
                    let generic = read_unaligned::<GenericHeader>(
                        message.get(size_of::<MessageHeader>()..).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "missing generic netlink header",
                            )
                        })?,
                    )
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "truncated generic netlink payload",
                        )
                    })?;
                    let attributes = parse_attributes(
                        message,
                        align_to_4(size_of::<MessageHeader>() + size_of::<GenericHeader>()),
                    )
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid generic netlink attributes",
                        )
                    })?;
                    messages.push(Message {
                        command: generic.command,
                        attributes,
                    });
                }
                _ => {}
            }
        }
        offset += align_to_4(length);
    }
    Ok(messages)
}

fn response_has_done(response: &[u8], sequence: u32) -> io::Result<bool> {
    let mut offset = 0;
    while response.len().saturating_sub(offset) >= size_of::<MessageHeader>() {
        let header = read_unaligned::<MessageHeader>(&response[offset..]).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated netlink completion header",
            )
        })?;
        let length = header.length as usize;
        if length < size_of::<MessageHeader>() || length > response.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netlink completion length",
            ));
        }
        if header.sequence == sequence && header.message_type == NLMSG_DONE {
            return Ok(true);
        }
        offset += align_to_4(length);
    }
    Ok(false)
}

fn parse_attributes(message: &[u8], mut offset: usize) -> Option<Vec<Attribute>> {
    // Attribute length excludes trailing alignment padding. Advance by the
    // aligned length, but copy only the declared payload bytes.
    let mut attributes = Vec::new();
    while message.len().saturating_sub(offset) >= size_of::<AttributeHeader>() {
        let header = read_unaligned::<AttributeHeader>(&message[offset..])?;
        let length = usize::from(header.length);
        if length < size_of::<AttributeHeader>() || length > message.len() - offset {
            return None;
        }
        attributes.push(Attribute {
            kind: header.kind & NLA_TYPE_MASK,
            value: message[offset + size_of::<AttributeHeader>()..offset + length].to_vec(),
        });
        offset += align_to_4(length);
    }
    Some(attributes)
}

fn parse_error(message: &[u8]) -> io::Result<()> {
    let payload = message.get(size_of::<MessageHeader>()..).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated generic netlink error",
        )
    })?;
    let error = read_unaligned::<i32>(payload).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated generic netlink error",
        )
    })?;
    if error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-error))
    }
}

fn append_value<T>(target: &mut Vec<u8>, value: &T) {
    target.extend_from_slice(value_bytes(value));
}

fn value_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: callers pass initialized C-layout values and the slice cannot outlive value.
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}

fn read_unaligned<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: length is checked and callers use initialized C-layout types.
    Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

// Both nlmsghdr and nlattr records use NLMSG_ALIGNTO/NLA_ALIGNTO == 4.
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
        assert_eq!(size_of::<GenericHeader>(), 4);
        assert_eq!(size_of::<AttributeHeader>(), 4);
    }

    #[test]
    fn builds_and_parses_attributes() {
        let message = build_message(
            42,
            7,
            5,
            1,
            NLM_F_REQUEST,
            &[
                Attribute::u32(3, 123),
                Attribute {
                    kind: 4,
                    value: b"wlan0\0".to_vec(),
                },
            ],
        );
        let parsed = parse_messages(&message, 42, 7).unwrap();
        assert_eq!(parsed[0].command, 5);
        assert_eq!(native_u32(&parsed[0].attributes[0].value), Some(123));
        assert_eq!(
            string(&parsed[0].attributes[1].value).as_deref(),
            Some("wlan0")
        );
    }
}
