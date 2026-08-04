use networkrs::{
    ethtool, netlink, oui, ping, resolver, scanner, sock_diag, sockets, traffic, wifi,
};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[test]
fn public_api_is_available_to_external_crates() {
    let _: fn() -> io::Result<Vec<netlink::Link>> = netlink::links;
    let _: fn() -> io::Result<Vec<netlink::Address>> = netlink::ipv4_addresses;
    let _: fn() -> io::Result<Vec<netlink::Route>> = netlink::ipv4_routes;
    let _: fn() -> io::Result<Vec<netlink::Rule>> = netlink::ipv4_rules;
    let _: fn() -> io::Result<Vec<netlink::Neighbor>> = netlink::ipv4_neighbors;
    let _: fn(Ipv4Addr) -> io::Result<netlink::Route> = netlink::ipv4_route;
    let _: fn() -> io::Result<Vec<netlink::Address>> = netlink::ipv6_addresses;
    let _: fn() -> io::Result<Vec<netlink::Route>> = netlink::ipv6_routes;
    let _: fn() -> io::Result<Vec<netlink::Rule>> = netlink::ipv6_rules;
    let _: fn() -> io::Result<Vec<netlink::Neighbor>> = netlink::ipv6_neighbors;
    let _: fn(Ipv6Addr) -> io::Result<netlink::Route> = netlink::ipv6_route;
    let _: fn() -> io::Result<Vec<netlink::Address>> = netlink::ip_addresses;
    let _: fn() -> io::Result<Vec<netlink::Route>> = netlink::ip_routes;
    let _: fn() -> io::Result<Vec<netlink::Rule>> = netlink::ip_rules;
    let _: fn() -> io::Result<Vec<netlink::Neighbor>> = netlink::ip_neighbors;
    let _: fn(IpAddr) -> io::Result<netlink::Route> = netlink::ip_route;
    let _: fn() -> io::Result<Vec<ethtool::Device>> = ethtool::devices;
    let _: fn() -> io::Result<Vec<wifi::WifiInterface>> = wifi::interfaces;
    let _: fn() -> io::Result<Vec<sockets::NetworkSocket>> = sockets::ipv4_sockets;
    let _: fn() -> io::Result<Vec<sockets::NetworkSocket>> = sockets::ipv6_sockets;
    let _: fn() -> io::Result<Vec<sockets::NetworkSocket>> = sockets::ip_sockets;
    let _: fn() -> io::Result<Vec<sock_diag::SocketDiagnostic>> = sock_diag::ipv4_diagnostics;
    let _: fn() -> io::Result<Vec<sock_diag::SocketDiagnostic>> = sock_diag::ipv6_diagnostics;
    let _: fn() -> io::Result<Vec<sock_diag::SocketDiagnostic>> = sock_diag::ip_diagnostics;
    let _: fn(Option<&str>, Duration) -> io::Result<traffic::Sample> = traffic::sample;
    let _: fn(Ipv4Addr, u32, Duration) -> io::Result<ping::Result> = ping::echo;
    let _: fn(&str) -> Vec<String> = resolver::nameservers;
    let _: fn() -> oui::Vendors = oui::load;

    let network = scanner::Network::new("eth0".into(), 2, Ipv4Addr::new(192, 0, 2, 10), 24);
    let options = scanner::Options {
        wait: Duration::ZERO,
        retries: 1,
        excluded: [Ipv4Addr::new(192, 0, 2, 1)].into_iter().collect(),
    };
    let _: fn(&[scanner::Network], &scanner::Options) -> io::Result<scanner::ScanResult> =
        scanner::scan;

    assert_eq!(network.interface, "eth0");
    assert_eq!(options.excluded.len(), 1);
    let _: HashMap<u32, String> = oui::Vendors::new();
}
