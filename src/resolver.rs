//! Resolver helpers using the host's libc NSS configuration.
//!
//! Reverse lookup can consult DNS, mDNS, `/etc/hosts`, or other NSS backends.
//! It is therefore not a kernel-only operation and may block on external name
//! services. Work is bounded to a small number of worker threads.

use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::fs;
use std::mem::size_of;
use std::net::IpAddr;
use std::thread;

#[repr(C)]
struct SocketAddressV4 {
    family: u16,
    port: u16,
    address: u32,
    padding: [u8; 8],
}

#[repr(C)]
struct SocketAddressV6 {
    family: u16,
    port: u16,
    flow_info: u32,
    address: [u8; 16],
    scope_id: u32,
}

unsafe extern "C" {
    fn getnameinfo(
        address: *const c_void,
        address_length: u32,
        host: *mut c_char,
        host_length: u32,
        service: *mut c_char,
        service_length: u32,
        flags: c_int,
    ) -> c_int;
}

/// Resolves IPv4 and IPv6 addresses to names through libc `getnameinfo`.
///
/// Only successful lookups are returned. At most eight worker threads are
/// created, and each input address appears at most once in the result.
pub fn reverse_names(addresses: &[IpAddr]) -> HashMap<IpAddr, String> {
    const MAX_WORKERS: usize = 8;

    if addresses.is_empty() {
        return HashMap::new();
    }
    let worker_count = addresses.len().min(MAX_WORKERS);
    let chunk_size = addresses.len().div_ceil(worker_count);
    thread::scope(|scope| {
        let handles = addresses
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .filter_map(|address| reverse_name(*address).map(|name| (*address, name)))
                        .collect::<HashMap<_, _>>()
                })
            })
            .collect::<Vec<_>>();

        let mut names = HashMap::new();
        for handle in handles {
            if let Ok(resolved) = handle.join() {
                names.extend(resolved);
            }
        }
        names
    })
}

/// Reads `nameserver` entries from a resolver configuration file.
///
/// Invalid, commented, and empty lines are ignored. An unreadable file produces
/// an empty list rather than an error so callers can treat missing resolver
/// configuration as an ordinary health condition.
pub fn nameservers(path: &str) -> Vec<String> {
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_nameservers(&contents)
}

fn parse_nameservers(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                return None;
            }
            let mut fields = line.split_whitespace();
            (fields.next()? == "nameserver").then(|| fields.next().map(str::to_owned))?
        })
        .collect()
}

fn reverse_name(address: IpAddr) -> Option<String> {
    const NI_MAXHOST: usize = 1025;
    const NI_NAMEREQD: c_int = 8;

    let mut host = [0 as c_char; NI_MAXHOST];
    let result = match address {
        IpAddr::V4(address) => {
            let socket_address = SocketAddressV4 {
                family: 2,
                port: 0,
                address: u32::from_ne_bytes(address.octets()),
                padding: [0; 8],
            };
            // SAFETY: socket_address has the Linux sockaddr_in layout and host
            // is writable for the duration of the call.
            unsafe {
                getnameinfo(
                    (&raw const socket_address).cast(),
                    size_of::<SocketAddressV4>() as u32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(address) => {
            let socket_address = SocketAddressV6 {
                family: 10,
                port: 0,
                flow_info: 0,
                address: address.octets(),
                scope_id: 0,
            };
            // SAFETY: socket_address has the Linux sockaddr_in6 layout and host
            // is writable for the duration of the call.
            unsafe {
                getnameinfo(
                    (&raw const socket_address).cast(),
                    size_of::<SocketAddressV6>() as u32,
                    host.as_mut_ptr(),
                    host.len() as u32,
                    std::ptr::null_mut(),
                    0,
                    NI_NAMEREQD,
                )
            }
        }
    };
    if result != 0 {
        return None;
    }

    // SAFETY: getnameinfo returned success and therefore NUL-terminated host.
    Some(
        unsafe { CStr::from_ptr(host.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolver_nameservers() {
        assert_eq!(
            parse_nameservers("# generated\nnameserver 10.0.0.53\nsearch local\n"),
            vec!["10.0.0.53"]
        );
    }

    #[test]
    fn socket_address_layouts_match_linux() {
        assert_eq!(size_of::<SocketAddressV4>(), 16);
        assert_eq!(size_of::<SocketAddressV6>(), 28);
    }
}
