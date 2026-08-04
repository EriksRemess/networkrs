//! Dependency-free Linux network inspection.
//!
//! `networkrs` exposes typed access to Linux network state through route
//! netlink, generic netlink, socket diagnostic netlink, sysfs, procfs, network
//! ioctls, and Linux ping sockets. It does not invoke external networking
//! utilities and has no external Rust dependencies.
//!
//! Most APIs are passive. [`scanner::scan`] and [`ping::echo`] generate network
//! traffic; callers must opt into those operations explicitly. Configuration,
//! neighbors, sockets, name resolution, route lookup, and event APIs support
//! IPv4 and IPv6. Subnet scanning and ICMP echo are currently IPv4-only.
//!
//! # Example
//!
//! ```no_run
//! use networkrs::netlink;
//! use std::io;
//! use std::net::IpAddr;
//!
//! fn main() -> io::Result<()> {
//!     for link in netlink::links()? {
//!         println!("{}: {}", link.name, link.operational_state);
//!     }
//!
//!     let route = netlink::ip_route("2606:4700:4700::1111".parse::<IpAddr>().unwrap())?;
//!     println!("{route:#?}");
//!     Ok(())
//! }
//! ```

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod ethtool;
mod generic_netlink;
pub mod netlink;
pub mod oui;
pub mod ping;
pub mod resolver;
pub mod scanner;
pub mod sock_diag;
pub mod sockets;
pub mod traffic;
pub mod wifi;
