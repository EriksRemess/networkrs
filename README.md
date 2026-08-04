# networkrs

`networkrs` is a Linux network-inspection CLI written with only the Rust
standard library. It talks to kernel APIs directly and never invokes utilities
such as `ip`, `ss`, `ethtool`, `iw`, `nmcli`, or `resolvectl`.

The project has no external Rust dependencies. Passive configuration and
socket inspection support IPv4 and IPv6. Active subnet discovery, ICMP echo,
and the `check` command's default-gateway health path remain IPv4-only.

## Install and run

```console
cargo install networkrs
networkrs
networkrs help
```

To build a checkout instead, run `cargo build --release` and use
`target/release/networkrs`.

The default `all` command is passive. Active traffic is generated only by the
explicit `scan`, `probe`, and `check --active` commands.

## Library use

The same kernel-facing code is available as a Rust library crate:

```toml
[dependencies]
networkrs = "0.1.0"
```

Then call the typed APIs directly:

```rust
use std::io;
use std::net::IpAddr;

fn main() -> io::Result<()> {
    for link in networkrs::netlink::links()? {
        println!("{}: {}", link.name, link.operational_state);
    }

    let destination = "2606:4700:4700::1111".parse::<IpAddr>().unwrap();
    let route = networkrs::netlink::ip_route(destination)?;
    println!("route: {route:#?}");
    Ok(())
}
```

Public modules cover route netlink (`netlink`), discovery (`scanner`), socket
tables and diagnostics (`sockets`, `sock_diag`), traffic sampling (`traffic`),
ethtool (`ethtool`), nl80211 (`wifi`), ICMP echo (`ping`), name resolution
(`resolver`), and installed OUI data (`oui`). Scanning and ICMP echo are active;
the remaining snapshot APIs are passive.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the module map, data flow, Linux UAPI
conventions, error policy, extension checklist, and maintainer workflow. See
[JSON.md](JSON.md) for machine-readable output conventions and command shapes.

## Commands

```text
networkrs all
networkrs interfaces
networkrs links
networkrs hardware [INTERFACE]
networkrs addresses
networkrs routes
networkrs rules
networkrs route <ADDRESS>
networkrs neighbors [INTERFACE]
networkrs scan [OPTIONS] [INTERFACE|IPv4/CIDR]
networkrs watch
networkrs check [--active]
networkrs probe HOST [PORT] [--timeout MS]
networkrs sockets [all|tcp|udp|listening|connected]
networkrs traffic [INTERFACE] [--interval MS] [--watch]
networkrs wifi
networkrs dns
```

`--json` can appear anywhere in the argument list. Snapshot commands emit one
JSON value. `watch --json` and `traffic --watch --json` emit one compact JSON
object per line, making the streams suitable for pipes and log collectors.

## What it reports

### Interfaces, addresses, and topology

- Interface kind, index, flags, operational state, carrier, MAC, and MTU
- RX/TX bytes, packets, errors, drops, collisions, and carrier transitions
- Detailed IPv4/IPv6 address flags, scope, label, peer/broadcast, and lifetimes
- Link parent/master relationships, VLAN ID, qdisc, queue counts, aliases,
  alternate names, physical port, and parent bus device
- Loopback state derived from `IFF_UP`; the kernel's invariant, unhelpful
  `operstate=unknown` value is not shown as its effective status

### Routes and policy rules

- Every IPv4 and IPv6 routing table from `RTM_GETROUTE`, not only the main table
- Destination and source selectors, gateway, interface, preferred source,
  metric, protocol, scope, route type, and multipath nexthops
- IPv4 and IPv6 policy routing rules from `RTM_GETRULE`
- A per-destination kernel route lookup with `route <ADDRESS>`

### Neighbors and discovery

`neighbors` passively dumps the kernel IPv4 and IPv6 neighbor tables with link address,
interface, NUD state, flags, protocol, type, probe count, cache ages, reference
count, and master interface.

`scan` sends one-byte UDP datagrams so the kernel performs ARP resolution, then
reads the resulting neighbor table. It accepts:

- `--wait MS` between retries, up to 60000 (default 1200)
- `--retries N` from 1 through 10 (default 1)
- repeatable `--exclude IPv4`
- `--no-resolve` to skip reverse name lookup
- one interface or directly connected IPv4 CIDR

The scanner refuses routed CIDRs and more than 4096 targets. Results are scoped
to the selected interface and subnet. New or MAC-changed entries are marked.
Reverse names use the system NSS configuration with bounded worker threads.

MAC vendors are best effort. The kernel does not ship vendor assignments, so
`networkrs` reads an already-installed IEEE OUI file from common system paths.
It never downloads a database. Locally administered addresses are labeled
`private/randomized`, since attributing those to a hardware vendor is usually
misleading.

### Sockets

- IPv4/IPv6 TCP/UDP endpoints, state, UID/user, inode, and best-effort owning process
- Optional protocol, listening, and connected views
- When `CONFIG_INET_DIAG` is enabled: socket queues and timers plus TCP RTT,
  variance, RTO, congestion algorithm, congestion window, retransmissions,
  PMTU, and MSS from `NETLINK_SOCK_DIAG`
- Graceful `/proc/net/tcp*` and `/proc/net/udp*` fallback when socket diagnostics
  are unavailable

### Link hardware and Wi-Fi

`hardware` uses the ethtool generic-netlink family for negotiated speed,
duplex, autonegotiation, port/PHY metadata, supported and peer link modes,
offload features, Energy Efficient Ethernet state, and standard hardware
statistics when implemented by the driver. Driver/module identity comes from
sysfs.

`wifi` uses `nl80211` for interface/radio identity, interface type, power-save
state, associated SSID/BSSID, channel frequency, signal, station inactivity,
traffic/retry/failure counters, and RX/TX bitrate details including encoding,
MCS, channel width, and spatial streams when supplied by the driver.

### Monitoring and health checks

`watch` subscribes to route-netlink multicast groups and streams link,
IPv4/IPv6 address, route, and neighbor changes without polling.

`traffic` samples sysfs counters over a configurable interval (100 through
60000 ms) and reports RX/TX bytes and packets per second plus error/drop deltas.
`--watch` repeats until interrupted.

`check` is passive by default. It validates the default route, interface/carrier,
gateway neighbor, and resolver configuration, returning status 0 for healthy,
1 for warnings, and 2 for operational errors. `check --active` additionally
asks the kernel to refresh gateway ARP, verifies the route to every configured
IPv4 or IPv6 nameserver, measures gateway ICMP echo loss and min/average/max latency,
and times a TCP connection to port 53. ICMP is skipped if Linux ping-socket
policy denies it. A refused TCP port still proves that the host was reached.

`probe HOST [PORT]` resolves an IPv4 or IPv6 destination through NSS, shows the kernel's
chosen route, and times a TCP connection (default port 443 and three-second
timeout). `--timeout MS` accepts 100 through 60000. Connection refusal counts as
host reachability and other errors return status 1.

### DNS

Resolver directives are read from `/etc/resolv.conf`. This is deliberately
identified separately because resolver policy is userspace configuration, not
kernel network state.

## Kernel and system interfaces

- Route netlink: links, IPv4/IPv6 addresses/routes/rules/neighbors, route lookup,
  and multicast change events
- Generic netlink: family discovery, ethtool, and nl80211
- Socket diagnostic netlink: TCP/UDP transport diagnostics when enabled
- `/sys/class/net`: driver identity, interface attributes, and counters
- `/proc/net`: compatibility IPv4/IPv6 socket tables
- `SIOCGIFADDR`/`SIOCGIFNETMASK`: compact interface IPv4 summary
- libc NSS: forward/reverse hostname lookup
- `/etc/resolv.conf`: resolver configuration

## Constraints

- Linux only
- No external Rust dependencies
- No subprocesses
- No automatic downloads
- Active subnet discovery, ICMP echo, and `check` gateway health are IPv4-only;
  passive neighbor inspection and TCP probes are dual-stack
- Some kernel families, commands, fields, and statistics depend on kernel
  configuration and driver support; unavailable data is reported as null,
  omitted in text output, or accompanied by a diagnostic

## License

`networkrs` is available under the [MIT License](LICENSE).
