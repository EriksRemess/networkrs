//! Command-line interface for the `networkrs` library.
//!
mod json;

use networkrs::{
    ethtool, netlink, oui, ping, resolver, scanner, sock_diag, sockets, traffic, wifi,
};

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{c_char, c_int, c_ulong, c_ushort};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const SYS_CLASS_NET: &str = "/sys/class/net";
const PROC_NET_ROUTE: &str = "/proc/net/route";
const PROC_NET_IF_INET6: &str = "/proc/net/if_inet6";
const RESOLV_CONF: &str = "/etc/resolv.conf";
const MAX_PROBE_PORTS: usize = 4096;
const MAX_CONCURRENT_PROBES: usize = 64;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(exit_code) => exit_code,
        Err(message) => {
            eprintln!("networkrs: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: impl Iterator<Item = String>) -> Result<ExitCode, String> {
    let mut arguments = args.collect::<Vec<_>>();
    let json = arguments
        .iter()
        .position(|argument| argument == "--json")
        .map(|position| arguments.remove(position))
        .is_some();
    let command = if arguments.is_empty() {
        "all".into()
    } else {
        arguments.remove(0)
    };
    if json {
        return run_json(&command, &arguments);
    }
    let argument = arguments.first();
    if command != "scan"
        && command != "probe"
        && command != "traffic"
        && command != "watch"
        && let Some(extra) = arguments.get(1)
    {
        return Err(format!("unexpected argument: {extra}\n\n{}", usage()));
    }
    if command != "route"
        && command != "scan"
        && command != "probe"
        && command != "check"
        && command != "neighbors"
        && command != "hardware"
        && command != "sockets"
        && command != "traffic"
        && command != "watch"
        && let Some(argument) = argument.map(String::as_str)
    {
        return Err(format!("unexpected argument: {argument}\n\n{}", usage()));
    }

    let mut exit_code = ExitCode::SUCCESS;
    match command.as_str() {
        "all" => {
            print_system();
            print_interfaces().map_err(|error| format!("cannot read interfaces: {error}"))?;
            print_routes().map_err(|error| format!("cannot read routes: {error}"))?;
            if let Err(error) = print_neighbors(None) {
                println!("Neighbors\n  Unavailable: {error}\n");
            }
            print_dns();
        }
        "interfaces" => {
            print_interfaces().map_err(|error| format!("cannot read interfaces: {error}"))?
        }
        "links" => print_links().map_err(|error| format!("cannot read links: {error}"))?,
        "hardware" => print_hardware(argument.map(String::as_str))
            .map_err(|error| format!("cannot read link hardware: {error}"))?,
        "addresses" => {
            print_addresses().map_err(|error| format!("cannot read addresses: {error}"))?
        }
        "routes" => print_routes().map_err(|error| format!("cannot read routes: {error}"))?,
        "rules" => print_rules().map_err(|error| format!("cannot read rules: {error}"))?,
        "route" => {
            let destination = argument
                .map(String::as_str)
                .ok_or_else(|| format!("route requires an IP address\n\n{}", usage()))?
                .parse::<IpAddr>()
                .map_err(|_| "route destination must be an IP address".to_owned())?;
            print_route_to(destination)
                .map_err(|error| format!("cannot look up route: {error}"))?;
        }
        "neighbors" => print_neighbors(argument.map(String::as_str))
            .map_err(|error| format!("cannot read neighbors: {error}"))?,
        "scan" => scan(&arguments).map_err(|error| format!("cannot scan network: {error}"))?,
        "watch" => {
            let filter = parse_watch_arguments(&arguments)
                .map_err(|error| format!("cannot watch network: {error}"))?;
            watch(filter).map_err(|error| format!("cannot watch network: {error}"))?
        }
        "check" => {
            let active = match arguments.as_slice() {
                [] => false,
                [option] if option == "--active" => true,
                [option] => return Err(format!("unknown check option: {option}")),
                _ => return Err("check accepts only --active".into()),
            };
            if !check(active).map_err(|error| format!("cannot check network: {error}"))? {
                exit_code = ExitCode::from(1);
            }
        }
        "probe" => {
            if !probe(&arguments).map_err(|error| format!("cannot probe destination: {error}"))? {
                exit_code = ExitCode::from(1);
            }
        }
        "sockets" => {
            let view = match argument.map(String::as_str) {
                None => sockets::View::All,
                Some(name) => sockets::View::from_name(name).ok_or_else(|| {
                    format!(
                        "unknown socket view: {name}; expected all, tcp, udp, listening, or connected"
                    )
                })?,
            };
            print_sockets(view).map_err(|error| format!("cannot read sockets: {error}"))?
        }
        "traffic" => {
            print_traffic(&arguments).map_err(|error| format!("cannot sample traffic: {error}"))?
        }
        "wifi" => print_wifi().map_err(|error| format!("cannot read Wi-Fi state: {error}"))?,
        "dns" => print_dns(),
        "-h" | "--help" | "help" => println!("{}", usage()),
        "-V" | "--version" => println!("networkrs {}", env!("CARGO_PKG_VERSION")),
        _ => return Err(format!("unknown command: {command}\n\n{}", usage())),
    }

    Ok(exit_code)
}

fn run_json(command: &str, arguments: &[String]) -> Result<ExitCode, String> {
    use json::Value;

    if command == "watch" {
        let filter = parse_watch_arguments(arguments)
            .map_err(|error| format!("cannot watch network: {error}"))?;
        watch_json(filter).map_err(|error| format!("cannot watch network: {error}"))?;
        return Ok(ExitCode::SUCCESS);
    }
    if command == "traffic" {
        traffic_json(arguments).map_err(|error| format!("cannot sample traffic: {error}"))?;
        return Ok(ExitCode::SUCCESS);
    }
    if command == "probe" {
        let (value, healthy) =
            probe_json(arguments).map_err(|error| format!("cannot probe destination: {error}"))?;
        println!("{}", value.render());
        return Ok(if healthy {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }
    if command == "check" {
        let active = match arguments {
            [] => false,
            [option] if option == "--active" => true,
            [option] => return Err(format!("unknown check option: {option}")),
            _ => return Err("check accepts only --active".into()),
        };
        let (value, healthy) =
            check_json(active).map_err(|error| format!("cannot check network: {error}"))?;
        println!("{}", value.render());
        return Ok(if healthy {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }

    let value = match command {
        "all" => json_all()?,
        "interfaces" => Value::Array(
            json_interfaces().map_err(|error| format!("cannot read interfaces: {error}"))?,
        ),
        "links" => Value::Array(
            netlink::links()
                .map_err(|error| format!("cannot read links: {error}"))?
                .into_iter()
                .map(json_link)
                .collect(),
        ),
        "addresses" => Value::Array(
            netlink::ip_addresses()
                .map_err(|error| format!("cannot read addresses: {error}"))?
                .into_iter()
                .map(json_address)
                .collect(),
        ),
        "routes" => Value::Array(
            netlink::ip_routes()
                .map_err(|error| format!("cannot read routes: {error}"))?
                .into_iter()
                .map(json_route)
                .collect(),
        ),
        "rules" => Value::Array(
            netlink::ip_rules()
                .map_err(|error| format!("cannot read rules: {error}"))?
                .into_iter()
                .map(json_rule)
                .collect(),
        ),
        "route" => {
            if arguments.len() != 1 {
                return Err("route requires one IP address".into());
            }
            let destination = arguments[0]
                .parse::<IpAddr>()
                .map_err(|_| "route destination must be an IP address".to_owned())?;
            json_route(
                route_to(destination).map_err(|error| format!("cannot look up route: {error}"))?,
            )
        }
        "neighbors" => {
            if arguments.len() > 1 {
                return Err("neighbors accepts at most one interface".into());
            }
            let names = interface_names();
            let selected = arguments
                .first()
                .map(|name| {
                    names
                        .iter()
                        .find_map(|(index, candidate)| (candidate == name).then_some(*index))
                        .ok_or_else(|| format!("interface {name} does not exist"))
                })
                .transpose()?;
            Value::Array(
                netlink::ip_neighbors()
                    .map_err(|error| format!("cannot read neighbors: {error}"))?
                    .into_iter()
                    .filter(|neighbor| {
                        selected.is_none_or(|index| neighbor.interface_index == index)
                    })
                    .map(|neighbor| json_neighbor(neighbor, &names))
                    .collect(),
            )
        }
        "hardware" => {
            if arguments.len() > 1 {
                return Err("hardware accepts at most one interface".into());
            }
            let mut devices = ethtool::devices()
                .map_err(|error| format!("cannot read link hardware: {error}"))?;
            if let Some(selection) = arguments.first() {
                devices.retain(|device| &device.name == selection);
                if devices.is_empty() {
                    return Err(format!("no ethtool device named {selection}"));
                }
            }
            Value::Array(devices.into_iter().map(json_hardware).collect())
        }
        "scan" => scan_json(arguments).map_err(|error| format!("cannot scan network: {error}"))?,
        "sockets" => {
            if arguments.len() > 1 {
                return Err("sockets accepts at most one view".into());
            }
            let view = match arguments.first().map(String::as_str) {
                None => sockets::View::All,
                Some(name) => sockets::View::from_name(name).ok_or_else(|| {
                    format!("unknown socket view: {name}; expected all, tcp, udp, listening, or connected")
                })?,
            };
            sockets_json(view).map_err(|error| format!("cannot read sockets: {error}"))?
        }
        "wifi" => {
            if !arguments.is_empty() {
                return Err("wifi accepts no arguments".into());
            }
            Value::Array(
                wifi::interfaces()
                    .map_err(|error| format!("cannot read Wi-Fi state: {error}"))?
                    .into_iter()
                    .map(json_wifi)
                    .collect(),
            )
        }
        "dns" => {
            if !arguments.is_empty() {
                return Err("dns accepts no arguments".into());
            }
            json_dns()
        }
        "-V" | "--version" => {
            Value::object([("version", Value::string(env!("CARGO_PKG_VERSION")))])
        }
        "-h" | "--help" | "help" => Value::object([("usage", Value::string(usage()))]),
        _ => return Err(format!("unknown command: {command}\n\n{}", usage())),
    };
    println!("{}", value.render());
    Ok(ExitCode::SUCCESS)
}

fn json_link(link: netlink::Link) -> json::Value {
    json::Value::object([
        ("index", json::Value::number(link.interface_index)),
        ("name", json::Value::string(link.name)),
        ("kind", json::optional_string(link.kind)),
        ("hardwareType", json::Value::number(link.hardware_type)),
        ("flags", json::Value::string(link.flags)),
        ("state", json::Value::string(link.operational_state)),
        (
            "carrier",
            link.carrier
                .map(json::Value::Bool)
                .unwrap_or(json::Value::Null),
        ),
        ("mtu", json::optional_number(link.mtu)),
        ("minimumMtu", json::optional_number(link.minimum_mtu)),
        ("maximumMtu", json::optional_number(link.maximum_mtu)),
        ("parentIndex", json::optional_number(link.parent_index)),
        ("masterIndex", json::optional_number(link.master_index)),
        ("qdisc", json::optional_string(link.qdisc)),
        (
            "transmitQueueLength",
            json::optional_number(link.transmit_queue_length),
        ),
        ("alias", json::optional_string(link.alias)),
        ("alternativeNames", json::strings(link.alternative_names)),
        ("vlanId", json::optional_number(link.vlan_id)),
        ("group", json::optional_number(link.group)),
        ("promiscuity", json::optional_number(link.promiscuity)),
        (
            "transmitQueues",
            json::optional_number(link.transmit_queues),
        ),
        ("receiveQueues", json::optional_number(link.receive_queues)),
        (
            "carrierChanges",
            json::optional_number(link.carrier_changes),
        ),
        (
            "carrierUpCount",
            json::optional_number(link.carrier_up_count),
        ),
        (
            "carrierDownCount",
            json::optional_number(link.carrier_down_count),
        ),
        (
            "physicalPort",
            json::optional_string(link.physical_port_name),
        ),
        (
            "parentDevice",
            json::optional_string(link.parent_device_name),
        ),
        (
            "parentBus",
            json::optional_string(link.parent_device_bus_name),
        ),
    ])
}

fn json_address(address: netlink::Address) -> json::Value {
    json::Value::object([
        ("family", json::Value::string(json_ip_family(address.local))),
        ("address", json::Value::string(address.local.to_string())),
        ("prefix", json::Value::number(address.prefix)),
        ("peer", json::optional_string(address.peer)),
        ("broadcast", json::optional_string(address.broadcast)),
        (
            "interfaceIndex",
            json::Value::number(address.interface_index),
        ),
        ("label", json::optional_string(address.label)),
        ("scope", json::Value::string(address.scope)),
        ("flags", json::Value::string(address.flags)),
        (
            "preferredLifetimeSeconds",
            json::optional_number(address.preferred_lifetime),
        ),
        (
            "validLifetimeSeconds",
            json::optional_number(address.valid_lifetime),
        ),
    ])
}

fn json_route(route: netlink::Route) -> json::Value {
    let family = json_ip_family(route.destination);
    let next_hops = route
        .next_hops
        .into_iter()
        .map(|next_hop| {
            json::Value::object([
                ("gateway", json::optional_string(next_hop.gateway)),
                (
                    "interfaceIndex",
                    json::Value::number(next_hop.interface_index),
                ),
                ("weight", json::Value::number(next_hop.weight)),
                ("flags", json::Value::string(next_hop.flags)),
            ])
        })
        .collect();
    json::Value::object([
        ("family", json::Value::string(family)),
        (
            "destination",
            json::Value::string(route.destination.to_string()),
        ),
        ("prefix", json::Value::number(route.prefix)),
        (
            "sourcePrefix",
            route
                .source_prefix
                .map(|(address, prefix)| json::Value::string(format!("{address}/{prefix}")))
                .unwrap_or(json::Value::Null),
        ),
        ("gateway", json::optional_string(route.gateway)),
        (
            "interfaceIndex",
            json::optional_number(route.interface_index),
        ),
        ("metric", json::optional_number(route.metric)),
        ("preferredSource", json::optional_string(route.source)),
        ("table", json::Value::number(route.table)),
        ("protocol", json::Value::string(route.protocol)),
        ("scope", json::Value::string(route.scope)),
        ("type", json::Value::string(route.kind)),
        ("nextHops", json::Value::Array(next_hops)),
    ])
}

fn json_rule(rule: netlink::Rule) -> json::Value {
    json::Value::object([
        (
            "family",
            json::Value::string(match rule.family {
                netlink::IpFamily::Ipv4 => "ipv4",
                netlink::IpFamily::Ipv6 => "ipv6",
            }),
        ),
        ("priority", json::Value::number(rule.priority)),
        (
            "source",
            rule.source
                .map(|(address, prefix)| json::Value::string(format!("{address}/{prefix}")))
                .unwrap_or(json::Value::Null),
        ),
        (
            "destination",
            rule.destination
                .map(|(address, prefix)| json::Value::string(format!("{address}/{prefix}")))
                .unwrap_or(json::Value::Null),
        ),
        (
            "inputInterface",
            json::optional_string(rule.input_interface),
        ),
        (
            "outputInterface",
            json::optional_string(rule.output_interface),
        ),
        ("fwmark", json::optional_number(rule.fwmark)),
        ("fwmask", json::optional_number(rule.fwmask)),
        ("table", json::Value::number(rule.table)),
        ("action", json::Value::string(rule.action)),
        ("goto", json::optional_number(rule.goto)),
        ("flags", json::Value::string(rule.flags)),
    ])
}

fn json_neighbor(neighbor: netlink::Neighbor, names: &HashMap<i32, String>) -> json::Value {
    json::Value::object([
        (
            "family",
            json::Value::string(json_ip_family(neighbor.address)),
        ),
        ("address", json::Value::string(neighbor.address.to_string())),
        ("linkAddress", json::optional_string(neighbor.link_address)),
        (
            "interfaceIndex",
            json::Value::number(neighbor.interface_index),
        ),
        (
            "interface",
            json::Value::string(interface_label(names, neighbor.interface_index)),
        ),
        ("state", json::Value::string(neighbor.state)),
        ("flags", json::Value::string(neighbor.flags)),
        ("protocol", json::optional_string(neighbor.protocol)),
        ("type", json::Value::string(neighbor.kind)),
        ("probes", json::optional_number(neighbor.probes)),
        (
            "confirmedMillisecondsAgo",
            json::optional_number(neighbor.confirmed_ms_ago),
        ),
        (
            "usedMillisecondsAgo",
            json::optional_number(neighbor.used_ms_ago),
        ),
        (
            "updatedMillisecondsAgo",
            json::optional_number(neighbor.updated_ms_ago),
        ),
        (
            "referenceCount",
            json::optional_number(neighbor.reference_count),
        ),
        ("masterIndex", json::optional_number(neighbor.master_index)),
    ])
}

fn json_all() -> Result<json::Value, String> {
    let names = interface_names();
    Ok(json::Value::object([
        (
            "system",
            json::Value::object([(
                "hostname",
                read_trimmed("/etc/hostname")
                    .map(json::Value::string)
                    .unwrap_or(json::Value::Null),
            )]),
        ),
        (
            "interfaces",
            json::Value::Array(
                json_interfaces().map_err(|error| format!("cannot read interfaces: {error}"))?,
            ),
        ),
        (
            "addresses",
            json::Value::Array(
                netlink::ip_addresses()
                    .map_err(|error| format!("cannot read addresses: {error}"))?
                    .into_iter()
                    .map(json_address)
                    .collect(),
            ),
        ),
        (
            "routes",
            json::Value::Array(
                netlink::ip_routes()
                    .map_err(|error| format!("cannot read routes: {error}"))?
                    .into_iter()
                    .map(json_route)
                    .collect(),
            ),
        ),
        (
            "rules",
            json::Value::Array(
                netlink::ip_rules()
                    .map_err(|error| format!("cannot read rules: {error}"))?
                    .into_iter()
                    .map(json_rule)
                    .collect(),
            ),
        ),
        (
            "neighbors",
            json::Value::Array(
                netlink::ip_neighbors()
                    .map_err(|error| format!("cannot read neighbors: {error}"))?
                    .into_iter()
                    .map(|neighbor| json_neighbor(neighbor, &names))
                    .collect(),
            ),
        ),
        ("dns", json_dns()),
    ]))
}

fn json_interfaces() -> io::Result<Vec<json::Value>> {
    Ok(netlink::links()?
        .into_iter()
        .map(|link| {
            let path = Path::new(SYS_CLASS_NET).join(&link.name);
            json::Value::object([
                ("link", json_link(link)),
                (
                    "mac",
                    json::optional_string(read_trimmed(path.join("address"))),
                ),
                (
                    "speedMbps",
                    json::optional_number(read_number(path.join("speed"))),
                ),
                (
                    "duplex",
                    json::optional_string(read_trimmed(path.join("duplex"))),
                ),
                (
                    "rxBytes",
                    json::optional_number(read_number(path.join("statistics/rx_bytes"))),
                ),
                (
                    "txBytes",
                    json::optional_number(read_number(path.join("statistics/tx_bytes"))),
                ),
                (
                    "rxPackets",
                    json::optional_number(read_number(path.join("statistics/rx_packets"))),
                ),
                (
                    "txPackets",
                    json::optional_number(read_number(path.join("statistics/tx_packets"))),
                ),
                (
                    "rxErrors",
                    json::optional_number(read_number(path.join("statistics/rx_errors"))),
                ),
                (
                    "txErrors",
                    json::optional_number(read_number(path.join("statistics/tx_errors"))),
                ),
                (
                    "rxDropped",
                    json::optional_number(read_number(path.join("statistics/rx_dropped"))),
                ),
                (
                    "txDropped",
                    json::optional_number(read_number(path.join("statistics/tx_dropped"))),
                ),
                (
                    "collisions",
                    json::optional_number(read_number(path.join("statistics/collisions"))),
                ),
            ])
        })
        .collect())
}

fn json_hardware(device: ethtool::Device) -> json::Value {
    json::Value::object([
        (
            "interfaceIndex",
            json::Value::number(device.interface_index),
        ),
        ("interface", json::Value::string(device.name)),
        ("driver", json::optional_string(device.driver)),
        ("driverModule", json::optional_string(device.driver_module)),
        (
            "driverVersion",
            json::optional_string(device.driver_version),
        ),
        ("port", json::optional_string(device.port)),
        ("phyAddress", json::optional_number(device.phy_address)),
        ("mdiX", json::optional_string(device.mdix)),
        ("transceiver", json::optional_string(device.transceiver)),
        ("speedMbps", json::optional_number(device.speed_mbps)),
        ("duplex", json::optional_string(device.duplex)),
        (
            "autonegotiation",
            optional_json_bool(device.autonegotiation),
        ),
        ("lanes", json::optional_number(device.lanes)),
        ("supportedModes", json::strings(device.supported_modes)),
        ("peerModes", json::strings(device.peer_modes)),
        ("hardwareFeatures", json::strings(device.hardware_features)),
        ("wantedFeatures", json::strings(device.wanted_features)),
        ("activeFeatures", json::strings(device.active_features)),
        ("eeeEnabled", optional_json_bool(device.eee_enabled)),
        ("eeeActive", optional_json_bool(device.eee_active)),
        (
            "eeeTxLpiEnabled",
            optional_json_bool(device.eee_tx_lpi_enabled),
        ),
        (
            "eeeTxLpiTimerMicroseconds",
            json::optional_number(device.eee_tx_lpi_timer_us),
        ),
        ("eeeModes", json::strings(device.eee_modes)),
        ("eeePeerModes", json::strings(device.eee_peer_modes)),
        (
            "statistics",
            json::Value::Array(
                device
                    .statistics
                    .into_iter()
                    .map(|statistic| {
                        json::Value::object([
                            ("group", json::Value::string(statistic.group)),
                            ("name", json::Value::string(statistic.name)),
                            ("value", json::Value::number(statistic.value)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn optional_json_bool(value: Option<bool>) -> json::Value {
    value.map(json::Value::Bool).unwrap_or(json::Value::Null)
}

fn usage() -> &'static str {
    "Usage: networkrs [--json] [COMMAND]\n\nCommands:\n  all                    Show current network configuration (default)\n  interfaces             Show interfaces, addresses, link state, and counters\n  links                  Show kernel link topology and metadata\n  hardware [INTERFACE]   Show driver, link modes, features, and statistics\n  addresses              Show detailed kernel IP address records\n  routes                 Show all IPv4 and IPv6 routing tables\n  rules                  Show IPv4 and IPv6 policy-routing rules\n  route <ADDRESS>        Show the kernel route to an IP address\n  neighbors [INTERFACE]  Show cached IPv4 and IPv6 neighbors\n  scan [OPTIONS] [TARGET] Actively discover neighbors on a local IPv4 network\n  watch [OPTIONS]        Stream kernel network changes\n  check [--active]       Check IPv4 health; optionally exercise the path\n  probe HOST [PORTS]     Test one or more TCP ports and report route and timing\n  sockets [VIEW]         Show IP sockets (all, tcp, udp, listening, connected)\n  traffic [OPTIONS]      Sample or continuously watch interface traffic rates\n  wifi                   Show nl80211 Wi-Fi connection details\n  dns                    Show resolver configuration\n  help                   Show this help\n\nGlobal options:\n  --json                 Emit JSON; streaming commands emit one object per line"
}

fn print_system() {
    println!("System");
    print_value("Hostname", read_trimmed("/etc/hostname"));
    println!();
}

fn print_interfaces() -> io::Result<()> {
    let mut paths = fs::read_dir(SYS_CLASS_NET)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();

    println!("Interfaces");
    if paths.is_empty() {
        println!("  None");
    }

    let ipv6 = ipv6_addresses();
    for path in paths {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        let kind = interface_kind(&path);
        let state = interface_state(&path, kind.as_deref());
        println!("  {name} ({state})");
        print_indented_value("Kind", kind);
        print_indented_value("Index", read_trimmed(path.join("ifindex")));
        print_indented_value("MAC", read_trimmed(path.join("address")));
        print_indented_value("MTU", read_trimmed(path.join("mtu")));

        if let Some((address, prefix)) = ipv4_address(name) {
            println!("    IPv4: {address}/{prefix}");
        }
        for (address, prefix, scope) in ipv6.iter().filter_map(|entry| {
            (entry.interface == name).then_some((entry.address, entry.prefix, entry.scope))
        }) {
            println!("    IPv6: {address}/{prefix} ({})", ipv6_scope(scope));
        }

        let carrier = read_trimmed(path.join("carrier")).map(|value| match value.as_str() {
            "1" => "yes".into(),
            "0" => "no".into(),
            _ => value,
        });
        print_indented_value("Carrier", carrier);

        let speed = read_trimmed(path.join("speed"))
            .filter(|value| value != "-1")
            .map(|value| format!("{value} Mb/s"));
        print_indented_value("Speed", speed);
        print_indented_value("Duplex", read_trimmed(path.join("duplex")));

        let rx = read_number(path.join("statistics/rx_bytes"));
        let tx = read_number(path.join("statistics/tx_bytes"));
        if let (Some(rx), Some(tx)) = (rx, tx) {
            println!(
                "    Traffic: RX {}  TX {}",
                human_bytes(rx),
                human_bytes(tx)
            );
        }
        print_counter_pair(
            "Packets",
            read_number(path.join("statistics/rx_packets")),
            read_number(path.join("statistics/tx_packets")),
        );
        print_counter_pair(
            "Errors",
            read_number(path.join("statistics/rx_errors")),
            read_number(path.join("statistics/tx_errors")),
        );
        print_counter_pair(
            "Dropped",
            read_number(path.join("statistics/rx_dropped")),
            read_number(path.join("statistics/tx_dropped")),
        );
        print_indented_value(
            "Collisions",
            read_trimmed(path.join("statistics/collisions")),
        );
        print_indented_value(
            "Carrier changes",
            read_trimmed(path.join("carrier_changes")),
        );
    }
    println!();
    Ok(())
}

fn print_links() -> io::Result<()> {
    let links = netlink::links()?;
    let names = links
        .iter()
        .map(|link| (link.interface_index, link.name.clone()))
        .collect::<HashMap<_, _>>();
    println!("Links");
    if links.is_empty() {
        println!("  None visible");
    }
    for link in links {
        let kind = link
            .kind
            .as_deref()
            .map(|kind| format!(" kind {kind}"))
            .unwrap_or_default();
        let carrier = link
            .carrier
            .map(|carrier| if carrier { "yes" } else { "no" })
            .unwrap_or("unknown");
        println!(
            "  {} index {}{kind} type {} state {} carrier {carrier}",
            link.name, link.interface_index, link.hardware_type, link.operational_state
        );
        println!("    Flags: {}", link.flags);
        let parent = link
            .parent_index
            .map(|index| interface_label(&names, index))
            .unwrap_or_else(|| "none".into());
        let master = link
            .master_index
            .map(|index| interface_label(&names, index))
            .unwrap_or_else(|| "none".into());
        println!("    Topology: parent {parent}, master {master}");
        if let Some(vlan_id) = link.vlan_id {
            println!("    VLAN: {vlan_id}");
        }
        println!(
            "    MTU: {} (min {}, max {})",
            optional_number(link.mtu),
            optional_number(link.minimum_mtu),
            optional_number(link.maximum_mtu)
        );
        println!(
            "    Queue: qdisc {}, length {}, RX queues {}, TX queues {}",
            link.qdisc.as_deref().unwrap_or("unknown"),
            optional_number(link.transmit_queue_length),
            optional_number(link.receive_queues),
            optional_number(link.transmit_queues)
        );
        println!(
            "    Carrier changes: {} (up {}, down {})",
            optional_number(link.carrier_changes),
            optional_number(link.carrier_up_count),
            optional_number(link.carrier_down_count)
        );
        if let Some(promiscuity) = link.promiscuity {
            println!("    Promiscuity references: {promiscuity}");
        }
        if let Some(group) = link.group {
            println!("    Group: {group}");
        }
        if let Some(alias) = link.alias {
            println!("    Alias: {alias}");
        }
        if !link.alternative_names.is_empty() {
            println!(
                "    Alternative names: {}",
                link.alternative_names.join(", ")
            );
        }
        if let Some(port) = link.physical_port_name {
            println!("    Physical port: {port}");
        }
        if link.parent_device_name.is_some() || link.parent_device_bus_name.is_some() {
            println!(
                "    Parent device: {} bus {}",
                link.parent_device_name.as_deref().unwrap_or("unknown"),
                link.parent_device_bus_name.as_deref().unwrap_or("unknown")
            );
        }
    }
    println!();
    Ok(())
}

fn optional_number(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn print_hardware(selection: Option<&str>) -> io::Result<()> {
    let mut devices = ethtool::devices()?;
    if let Some(selection) = selection {
        devices.retain(|device| device.name == selection);
        if devices.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no ethtool device named {selection}"),
            ));
        }
    }
    println!("Link hardware");
    if devices.is_empty() {
        println!("  None available");
    }
    for device in devices {
        println!("  {} index {}", device.name, device.interface_index);
        println!(
            "    Driver: {} module {} version {}",
            device.driver.as_deref().unwrap_or("unknown"),
            device.driver_module.as_deref().unwrap_or("unknown"),
            device.driver_version.as_deref().unwrap_or("unknown")
        );
        println!(
            "    Link: speed {} Mbit/s, duplex {}, autonegotiation {}, lanes {}",
            optional_number(device.speed_mbps),
            device.duplex.as_deref().unwrap_or("unknown"),
            optional_bool(device.autonegotiation),
            optional_number(device.lanes)
        );
        println!(
            "    Port: {} PHY address {} MDI-X {} transceiver {}",
            device.port.as_deref().unwrap_or("unknown"),
            device
                .phy_address
                .map(|address| address.to_string())
                .unwrap_or_else(|| "unknown".into()),
            device.mdix.as_deref().unwrap_or("unknown"),
            device.transceiver.as_deref().unwrap_or("unknown")
        );
        print_string_list("Supported modes", &device.supported_modes);
        print_string_list("Peer modes", &device.peer_modes);
        print_string_list("Hardware features", &device.hardware_features);
        print_string_list("Wanted features", &device.wanted_features);
        print_string_list("Active features", &device.active_features);
        if device.eee_enabled.is_some() || device.eee_active.is_some() {
            println!(
                "    EEE: enabled {}, active {}, TX LPI {}, timer {}us",
                optional_bool(device.eee_enabled),
                optional_bool(device.eee_active),
                optional_bool(device.eee_tx_lpi_enabled),
                optional_number(device.eee_tx_lpi_timer_us)
            );
            print_string_list("EEE modes", &device.eee_modes);
            print_string_list("EEE peer modes", &device.eee_peer_modes);
        }
        if !device.statistics.is_empty() {
            println!("    Standard hardware statistics:");
            for statistic in device.statistics {
                println!(
                    "      {}.{}: {}",
                    statistic.group, statistic.name, statistic.value
                );
            }
        }
    }
    Ok(())
}

fn optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn print_string_list(label: &str, values: &[String]) {
    if !values.is_empty() {
        println!("    {label}: {}", values.join(", "));
    }
}

fn print_counter_pair(label: &str, received: Option<u64>, transmitted: Option<u64>) {
    if let (Some(received), Some(transmitted)) = (received, transmitted) {
        println!("    {label}: RX {received}  TX {transmitted}");
    }
}

fn interface_kind(path: &Path) -> Option<String> {
    if path.join("wireless").exists() {
        return Some("wireless".into());
    }

    match read_trimmed(path.join("type")).as_deref() {
        Some("1") => Some("ethernet".into()),
        Some("772") => Some("loopback".into()),
        Some(value) => Some(format!("ARPHRD {value}")),
        None => None,
    }
}

fn interface_state(path: &Path, kind: Option<&str>) -> String {
    if kind == Some("loopback")
        && let Some(state) = read_trimmed(path.join("flags"))
            .as_deref()
            .and_then(administrative_state)
    {
        return state.into();
    }

    read_trimmed(path.join("operstate")).unwrap_or_else(|| "unknown".into())
}

fn administrative_state(flags: &str) -> Option<&'static str> {
    let flags = u32::from_str_radix(flags.strip_prefix("0x").unwrap_or(flags), 16).ok()?;
    Some(if flags & 0x1 == 0 { "down" } else { "up" })
}

fn print_addresses() -> io::Result<()> {
    let addresses = netlink::ip_addresses()?;
    let interface_names = interface_names();
    println!("IP addresses");
    if addresses.is_empty() {
        println!("  None configured");
    }
    for address in addresses {
        let interface = interface_label(&interface_names, address.interface_index);
        let peer = address
            .peer
            .map(|peer| format!(" peer {peer}"))
            .unwrap_or_default();
        let broadcast = address
            .broadcast
            .map(|broadcast| format!(" broadcast {broadcast}"))
            .unwrap_or_default();
        let label = address
            .label
            .filter(|label| label != &interface)
            .map(|label| format!(" label {label}"))
            .unwrap_or_default();
        println!(
            "  {}/{} dev {interface}{peer}{broadcast}{label} scope {} flags {} preferred {} valid {}",
            address.local,
            address.prefix,
            address.scope,
            address.flags,
            format_lifetime(address.preferred_lifetime),
            format_lifetime(address.valid_lifetime)
        );
    }
    Ok(())
}

fn format_lifetime(lifetime: Option<u32>) -> String {
    lifetime
        .map(|seconds| format!("{seconds}s"))
        .unwrap_or_else(|| "forever".into())
}

fn print_routes() -> io::Result<()> {
    println!("Routes");
    let mut found = false;
    let interface_names = interface_names();

    for route in netlink::ip_routes()? {
        let family = ip_family(route.destination);
        let target = route_target(route.destination, route.prefix);
        let from = route
            .source_prefix
            .map(|(source, prefix)| format!(" from {source}/{prefix}"))
            .unwrap_or_default();
        let via = route
            .gateway
            .map(|gateway| format!(" via {gateway}"))
            .unwrap_or_default();
        let interface = route
            .interface_index
            .map(|index| format!(" dev {}", interface_label(&interface_names, index)))
            .unwrap_or_default();
        let metric = route
            .metric
            .map(|metric| format!(" metric {metric}"))
            .unwrap_or_default();
        let source = route
            .source
            .map(|source| format!(" source {source}"))
            .unwrap_or_default();
        println!(
            "  {family} {target}{from}{via}{interface} table {} protocol {} scope {} type {}{metric}{source}",
            route_table(route.table),
            route.protocol,
            route.scope,
            route.kind,
        );
        for next_hop in route.next_hops {
            let gateway = next_hop
                .gateway
                .map(|gateway| format!(" via {gateway}"))
                .unwrap_or_default();
            let flags = if next_hop.flags != "none" {
                format!(" flags {}", next_hop.flags)
            } else {
                String::new()
            };
            println!(
                "    nexthop{gateway} dev {} weight {}{flags}",
                interface_label(&interface_names, next_hop.interface_index),
                next_hop.weight
            );
        }
        found = true;
    }

    if !found {
        println!("  None visible");
    }
    println!();
    Ok(())
}

fn print_rules() -> io::Result<()> {
    let rules = netlink::ip_rules()?;
    println!("IP policy rules");
    if rules.is_empty() {
        println!("  None configured");
    }
    for rule in rules {
        let priority = rule.priority;
        let from = rule
            .source
            .map(|(address, prefix)| format!(" from {address}/{prefix}"))
            .unwrap_or_else(|| " from all".into());
        let to = rule
            .destination
            .map(|(address, prefix)| format!(" to {address}/{prefix}"))
            .unwrap_or_default();
        let input = rule
            .input_interface
            .map(|interface| format!(" iif {interface}"))
            .unwrap_or_default();
        let output = rule
            .output_interface
            .map(|interface| format!(" oif {interface}"))
            .unwrap_or_default();
        let mark = rule
            .fwmark
            .map(|mark| format!(" fwmark 0x{mark:x}/0x{:x}", rule.fwmask.unwrap_or(u32::MAX)))
            .unwrap_or_default();
        let goto = rule
            .goto
            .map(|priority| format!(" goto {priority}"))
            .unwrap_or_default();
        let flags = if rule.flags != "none" {
            format!(" flags {}", rule.flags)
        } else {
            String::new()
        };
        println!(
            "  {} {priority}:{from}{to}{input}{output}{mark} action {} table {}{goto}{flags}",
            rule.family,
            rule.action,
            route_table(rule.table)
        );
    }
    println!();
    Ok(())
}

fn route_target(destination: IpAddr, prefix: u8) -> String {
    if destination.is_unspecified() && prefix == 0 {
        "default".into()
    } else {
        format!("{destination}/{prefix}")
    }
}

fn ip_family(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    }
}

fn json_ip_family(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

fn route_table(table: u32) -> String {
    match table {
        0 => "unspecified".into(),
        253 => "default".into(),
        254 => "main".into(),
        255 => "local".into(),
        table => table.to_string(),
    }
}

fn route_to(destination: IpAddr) -> io::Result<netlink::Route> {
    netlink::ip_route(destination)
}

fn print_route_to(destination: IpAddr) -> io::Result<()> {
    let route = route_to(destination)?;
    let interface_names = interface_names();

    println!("Route to {destination}");
    if let Some(gateway) = route.gateway {
        println!("  Gateway: {gateway}");
    } else {
        println!("  Gateway: directly connected");
    }
    if let Some(index) = route.interface_index {
        println!("  Interface: {}", interface_label(&interface_names, index));
    }
    if let Some(source) = route.source {
        println!("  Source: {source}");
    }
    if let Some(metric) = route.metric {
        println!("  Metric: {metric}");
    }
    println!("  Table: {}", route_table(route.table));
    println!("  Protocol: {}", route.protocol);
    println!("  Scope: {}", route.scope);
    println!("  Type: {}", route.kind);
    Ok(())
}

fn print_neighbors(selection: Option<&str>) -> io::Result<()> {
    let interface_names = interface_names();
    let selected_index = selection
        .map(|selection| {
            interface_names
                .iter()
                .find_map(|(index, name)| (name == selection).then_some(*index))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("interface {selection} does not exist"),
                    )
                })
        })
        .transpose()?;
    let mut neighbors = netlink::ip_neighbors()?;
    if let Some(index) = selected_index {
        neighbors.retain(|neighbor| neighbor.interface_index == index);
    }
    print_neighbor_entries(neighbors, false, None, "None cached");
    Ok(())
}

fn print_neighbor_entries(
    neighbors: Vec<netlink::Neighbor>,
    resolve_names: bool,
    changed: Option<&HashSet<Ipv4Addr>>,
    empty_message: &str,
) {
    let interface_names = interface_names();
    let vendors = oui::load();
    let names = if resolve_names {
        resolver::reverse_names(
            &neighbors
                .iter()
                .map(|neighbor| neighbor.address)
                .collect::<Vec<_>>(),
        )
    } else {
        HashMap::new()
    };

    println!("Neighbors");
    if neighbors.is_empty() {
        println!("  {empty_message}");
    }
    for neighbor in neighbors {
        let interface = interface_names
            .get(&neighbor.interface_index)
            .cloned()
            .unwrap_or_else(|| format!("ifindex {}", neighbor.interface_index));
        let vendor = neighbor
            .link_address
            .as_deref()
            .and_then(|address| oui::vendor(address, &vendors))
            .map(|vendor| format!(" vendor {vendor}"))
            .unwrap_or_default();
        let link_address = neighbor
            .link_address
            .as_deref()
            .map(|address| format!(" lladdr {address}"))
            .unwrap_or_default();
        let ipv4_address = match neighbor.address {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        };
        let name = names
            .get(&neighbor.address)
            .map(|name| format!(" name {name}"))
            .unwrap_or_default();
        let marker = changed
            .map(|changed| {
                if ipv4_address.is_some_and(|address| changed.contains(&address)) {
                    "+ "
                } else {
                    "  "
                }
            })
            .unwrap_or_default();
        println!(
            "  {marker}{}{name} dev {interface}{link_address}{vendor} {}",
            neighbor.address, neighbor.state
        );
        let protocol = neighbor
            .protocol
            .as_deref()
            .map(|protocol| format!(" protocol {protocol}"))
            .unwrap_or_default();
        let flags = if neighbor.flags != "none" {
            format!(" flags {}", neighbor.flags)
        } else {
            String::new()
        };
        let probes = neighbor
            .probes
            .map(|probes| format!(" probes {probes}"))
            .unwrap_or_default();
        let master = neighbor
            .master_index
            .map(|index| format!(" master {}", interface_label(&interface_names, index)))
            .unwrap_or_default();
        let ages = neighbor_ages(&neighbor);
        println!(
            "  {marker}  type {}{protocol}{flags}{probes}{master}{ages}",
            neighbor.kind
        );
    }
    println!();
}

fn neighbor_ages(neighbor: &netlink::Neighbor) -> String {
    let confirmed = neighbor
        .confirmed_ms_ago
        .map(|age| format!(" confirmed {} ago", format_age(age)))
        .unwrap_or_default();
    let used = neighbor
        .used_ms_ago
        .map(|age| format!(" used {} ago", format_age(age)))
        .unwrap_or_default();
    let updated = neighbor
        .updated_ms_ago
        .map(|age| format!(" updated {} ago", format_age(age)))
        .unwrap_or_default();
    let references = neighbor
        .reference_count
        .map(|count| format!(" references {count}"))
        .unwrap_or_default();
    format!("{confirmed}{used}{updated}{references}")
}

fn format_age(milliseconds: u64) -> String {
    if milliseconds < 1000 {
        format!("{milliseconds}ms")
    } else {
        format!("{:.1}s", milliseconds as f64 / 1000.0)
    }
}

fn interface_names() -> HashMap<i32, String> {
    let Ok(entries) = fs::read_dir(SYS_CLASS_NET) else {
        return HashMap::new();
    };

    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let index = read_trimmed(entry.path().join("ifindex"))?.parse().ok()?;
            Some((index, name))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanFilter {
    Changed,
    Unchanged,
}

impl ScanFilter {
    fn matches(self, neighbor: &netlink::Neighbor, changed: &HashSet<Ipv4Addr>) -> bool {
        let is_changed = match neighbor.address {
            IpAddr::V4(address) => changed.contains(&address),
            IpAddr::V6(_) => false,
        };
        match self {
            Self::Changed => is_changed,
            Self::Unchanged => !is_changed,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
        }
    }
}

struct ScanArguments {
    selection: Option<String>,
    wait_ms: u64,
    retries: u32,
    resolve_names: bool,
    excluded: HashSet<Ipv4Addr>,
    filter: Option<ScanFilter>,
}

fn scan(arguments: &[String]) -> io::Result<()> {
    let arguments = parse_scan_arguments(arguments)?;
    let networks = scan_networks(arguments.selection.as_deref())?;
    for network in &networks {
        println!(
            "Scanning {}/{} via {} ({} targets)",
            Ipv4Addr::from(network.network),
            network.prefix,
            network.interface,
            network.target_count()
        );
    }

    let result = scanner::scan(
        &networks,
        &scanner::Options {
            wait: std::time::Duration::from_millis(arguments.wait_ms),
            retries: arguments.retries,
            excluded: arguments.excluded,
        },
    )?;
    let neighbor_count = result.neighbors.len();
    let changed_count = result.changed.len();
    let mut neighbors = result.neighbors;
    if let Some(filter) = arguments.filter {
        neighbors.retain(|neighbor| filter.matches(neighbor, &result.changed));
    }
    let matched_count = neighbors.len();
    print_neighbor_entries(
        neighbors,
        arguments.resolve_names,
        Some(&result.changed),
        if arguments.filter.is_some() {
            "None matched the filter"
        } else {
            "None cached"
        },
    );
    if let Some(filter) = arguments.filter {
        println!(
            "Scan complete: {matched_count} {} of {neighbor_count} neighbors, {changed_count} new or changed, {:.1}s",
            filter.name(),
            result.elapsed.as_secs_f32()
        );
    } else {
        println!(
            "Scan complete: {neighbor_count} neighbors, {changed_count} new or changed, {:.1}s",
            result.elapsed.as_secs_f32()
        );
    }
    Ok(())
}

fn scan_json(arguments: &[String]) -> io::Result<json::Value> {
    let arguments = parse_scan_arguments(arguments)?;
    let networks = scan_networks(arguments.selection.as_deref())?;
    let result = scanner::scan(
        &networks,
        &scanner::Options {
            wait: std::time::Duration::from_millis(arguments.wait_ms),
            retries: arguments.retries,
            excluded: arguments.excluded,
        },
    )?;
    let interface_names = interface_names();
    let vendors = oui::load();
    let mut filtered_neighbors = result.neighbors;
    if let Some(filter) = arguments.filter {
        filtered_neighbors.retain(|neighbor| filter.matches(neighbor, &result.changed));
    }
    let resolved_names = if arguments.resolve_names {
        resolver::reverse_names(
            &filtered_neighbors
                .iter()
                .map(|neighbor| neighbor.address)
                .collect::<Vec<_>>(),
        )
    } else {
        HashMap::new()
    };
    let neighbors = filtered_neighbors
        .into_iter()
        .map(|neighbor| {
            let address = neighbor.address;
            let ipv4_address = match address {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            };
            let vendor = neighbor
                .link_address
                .as_deref()
                .and_then(|address| oui::vendor(address, &vendors));
            let mut value = json_neighbor(neighbor, &interface_names);
            if let json::Value::Object(fields) = &mut value {
                fields.push((
                    "name".into(),
                    json::optional_string(resolved_names.get(&address)),
                ));
                fields.push(("vendor".into(), json::optional_string(vendor)));
                fields.push((
                    "changed".into(),
                    json::Value::Bool(
                        ipv4_address.is_some_and(|address| result.changed.contains(&address)),
                    ),
                ));
            }
            value
        })
        .collect();
    Ok(json::Value::object([
        (
            "networks",
            json::Value::Array(
                networks
                    .into_iter()
                    .map(|network| {
                        let targets = network.target_count();
                        json::Value::object([
                            ("interface", json::Value::string(network.interface)),
                            (
                                "interfaceIndex",
                                json::Value::number(network.interface_index),
                            ),
                            ("source", json::Value::string(network.address.to_string())),
                            (
                                "network",
                                json::Value::string(Ipv4Addr::from(network.network).to_string()),
                            ),
                            ("prefix", json::Value::number(network.prefix)),
                            ("targets", json::Value::number(targets)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("neighbors", json::Value::Array(neighbors)),
        (
            "filter",
            json::optional_string(arguments.filter.map(ScanFilter::name)),
        ),
        ("changed", json::Value::number(result.changed.len())),
        (
            "elapsedMilliseconds",
            json::Value::number(result.elapsed.as_millis()),
        ),
    ]))
}

fn parse_scan_arguments(arguments: &[String]) -> io::Result<ScanArguments> {
    let mut parsed = ScanArguments {
        selection: None,
        wait_ms: 1200,
        retries: 1,
        resolve_names: true,
        excluded: HashSet::new(),
        filter: None,
    };
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--filter" => {
                index += 1;
                let value = arguments.get(index).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--filter requires changed or unchanged",
                    )
                })?;
                let filter = match value.as_str() {
                    "changed" => ScanFilter::Changed,
                    "unchanged" => ScanFilter::Unchanged,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "--filter must be changed or unchanged",
                        ));
                    }
                };
                if parsed.filter.replace(filter).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "scan filter was specified more than once",
                    ));
                }
            }
            "--wait" => {
                index += 1;
                parsed.wait_ms = parse_option_value(arguments, index, "--wait")?;
                if parsed.wait_ms > 60_000 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--wait cannot exceed 60000 milliseconds",
                    ));
                }
            }
            "--retries" => {
                index += 1;
                parsed.retries = parse_option_value(arguments, index, "--retries")?;
                if !(1..=10).contains(&parsed.retries) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--retries must be between 1 and 10",
                    ));
                }
            }
            "--exclude" => {
                index += 1;
                let value = arguments.get(index).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--exclude requires an IPv4 address",
                    )
                })?;
                parsed.excluded.insert(value.parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid excluded IPv4 address: {value}"),
                    )
                })?);
            }
            "--no-resolve" => parsed.resolve_names = false,
            option if option.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown scan option: {option}"),
                ));
            }
            selection => {
                if parsed.selection.replace(selection.to_owned()).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "scan accepts only one interface or CIDR",
                    ));
                }
            }
        }
        index += 1;
    }
    Ok(parsed)
}

fn parse_option_value<T: std::str::FromStr>(
    arguments: &[String],
    index: usize,
    option: &str,
) -> io::Result<T> {
    arguments
        .get(index)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{option} requires a value"),
            )
        })?
        .parse()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid value for {option}"),
            )
        })
}

fn scan_networks(selection: Option<&str>) -> io::Result<Vec<scanner::Network>> {
    if let Some(selection) = selection {
        return if selection.contains('/') {
            Ok(vec![scan_cidr(selection)?])
        } else {
            Ok(vec![scan_interface(selection)?])
        };
    }

    let preferred_interface = default_ipv4_interface();
    let mut entries = fs::read_dir(SYS_CLASS_NET)?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    let networks = entries
        .into_iter()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            if preferred_interface
                .as_deref()
                .is_some_and(|preferred| preferred != name)
                || interface_kind(&entry.path()).as_deref() == Some("loopback")
                || read_trimmed(entry.path().join("carrier")).as_deref() != Some("1")
            {
                return None;
            }
            let (address, prefix) = ipv4_address(&name)?;
            let interface_index = read_trimmed(entry.path().join("ifindex"))?.parse().ok()?;
            Some(scanner::Network::new(
                name,
                interface_index,
                address,
                prefix,
            ))
        })
        .collect::<Vec<_>>();

    if networks.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no active non-loopback IPv4 network found",
        ))
    } else {
        Ok(networks)
    }
}

fn scan_interface(name: &str) -> io::Result<scanner::Network> {
    let path = Path::new(SYS_CLASS_NET).join(name);
    if !path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {name} does not exist"),
        ));
    }
    if interface_kind(&path).as_deref() == Some("loopback") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "loopback is not a scannable network",
        ));
    }
    if read_trimmed(path.join("carrier")).as_deref() != Some("1") {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            format!("interface {name} has no carrier"),
        ));
    }
    let (address, prefix) = ipv4_address(name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("interface {name} has no IPv4 address"),
        )
    })?;
    let interface_index = read_trimmed(path.join("ifindex"))
        .and_then(|index| index.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid interface index"))?;
    Ok(scanner::Network::new(
        name.into(),
        interface_index,
        address,
        prefix,
    ))
}

fn scan_cidr(value: &str) -> io::Result<scanner::Network> {
    let (cidr_address, prefix) = parse_ipv4_cidr(value)?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network_address = Ipv4Addr::from(u32::from(cidr_address) & mask);
    let broadcast = Ipv4Addr::from(u32::from(network_address) | !mask);
    let configured_addresses = netlink::ipv4_addresses()?;
    let local_addresses = configured_addresses
        .iter()
        .filter_map(|address| match address.local {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .collect::<HashSet<_>>();
    // A lookup for one of this host's addresses selects the local table and lo,
    // which does not identify the interface that owns the selected subnet.
    let Some(probe_address) =
        first_non_local_scan_address(network_address, broadcast, prefix, &local_addresses)
    else {
        let address = configured_addresses
            .into_iter()
            .find_map(|address| match address.local {
                IpAddr::V4(local)
                    if u32::from(local) >= u32::from(network_address)
                        && u32::from(local) <= u32::from(broadcast) =>
                {
                    Some((local, address.interface_index))
                }
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "CIDR contains no address that can be used for route selection",
                )
            })?;
        return Ok(scanner::Network::for_cidr(
            interface_label(&interface_names(), address.1),
            address.1,
            address.0,
            network_address,
            prefix,
        ));
    };
    let route = netlink::ipv4_route(probe_address)?;
    if let Some(gateway) = route.gateway {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{value} is reached through gateway {gateway}, not directly connected"),
        ));
    }
    let interface_index = route.interface_index.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "kernel route has no output interface",
        )
    })?;
    let interface = interface_label(&interface_names(), interface_index);
    let source = route.source.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "kernel route has no source address",
        )
    })?;
    let IpAddr::V4(source) = source else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned a non-IPv4 source for an IPv4 route",
        ));
    };
    Ok(scanner::Network::for_cidr(
        interface,
        interface_index,
        source,
        network_address,
        prefix,
    ))
}

fn first_non_local_scan_address(
    network: Ipv4Addr,
    broadcast: Ipv4Addr,
    prefix: u32,
    local_addresses: &HashSet<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    let mut candidate = if prefix <= 30 {
        u32::from(network) + 1
    } else {
        u32::from(network)
    };
    let last = if prefix <= 30 {
        u32::from(broadcast) - 1
    } else {
        u32::from(broadcast)
    };
    while candidate <= last {
        let address = Ipv4Addr::from(candidate);
        if !local_addresses.contains(&address) {
            return Some(address);
        }
        if candidate == last {
            break;
        }
        candidate += 1;
    }
    None
}

fn parse_ipv4_cidr(value: &str) -> io::Result<(Ipv4Addr, u32)> {
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "CIDR must contain a prefix length",
        )
    })?;
    if prefix.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid IPv4 CIDR",
        ));
    }
    let address = address
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CIDR address must be IPv4"))?;
    let prefix = prefix
        .parse::<u32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CIDR prefix must be a number"))?;
    if prefix > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CIDR prefix must be between 0 and 32",
        ));
    }
    Ok((address, prefix))
}

fn default_ipv4_interface() -> Option<String> {
    let contents = fs::read_to_string(PROC_NET_ROUTE).ok()?;
    parse_default_ipv4_route(&contents).map(|route| route.interface)
}

#[derive(Debug, Eq, PartialEq)]
struct DefaultIpv4Route {
    interface: String,
    gateway: Ipv4Addr,
    metric: u32,
}

fn parse_default_ipv4_route(contents: &str) -> Option<DefaultIpv4Route> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
                return None;
            }
            let flags = u32::from_str_radix(fields[3], 16).ok()?;
            if flags & 0x0001 == 0 || flags & 0x0200 != 0 {
                return None;
            }
            Some(DefaultIpv4Route {
                interface: fields[0].to_owned(),
                gateway: parse_ipv4_hex(fields[2])?,
                metric: fields[6].parse().ok()?,
            })
        })
        .min_by_key(|route| route.metric)
}

struct ProbeArguments {
    host: String,
    ports: Vec<u16>,
    filter: Option<TcpProbeStatus>,
    timeout_ms: u64,
}

fn parse_probe_arguments(arguments: &[String]) -> io::Result<ProbeArguments> {
    let mut host = None;
    let mut ports = None;
    let mut filter = None;
    let mut timeout_ms = 3000_u64;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--filter" => {
                index += 1;
                let value = arguments.get(index).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--filter requires open, closed, or failed",
                    )
                })?;
                if filter.replace(parse_probe_filter(value)?).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "probe filter was specified more than once",
                    ));
                }
            }
            "--timeout" => {
                index += 1;
                timeout_ms = parse_option_value(arguments, index, "--timeout")?;
                if !(100..=60_000).contains(&timeout_ms) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--timeout must be between 100 and 60000 milliseconds",
                    ));
                }
            }
            option if option.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown probe option: {option}"),
                ));
            }
            value if host.is_none() => host = Some(value.to_owned()),
            value if ports.is_none() => ports = Some(parse_probe_ports(value)?),
            value => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unexpected probe argument: {value}"),
                ));
            }
        }
        index += 1;
    }
    Ok(ProbeArguments {
        host: host
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "probe requires a host"))?,
        ports: ports.unwrap_or_else(|| vec![443]),
        filter,
        timeout_ms,
    })
}

fn parse_probe_filter(value: &str) -> io::Result<TcpProbeStatus> {
    match value {
        "open" => Ok(TcpProbeStatus::Connected),
        "closed" => Ok(TcpProbeStatus::ConnectionRefused),
        "failed" => Ok(TcpProbeStatus::Failed),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--filter must be open, closed, or failed",
        )),
    }
}

fn parse_probe_ports(value: &str) -> io::Result<Vec<u16>> {
    let mut ports = std::collections::BTreeSet::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "probe port list contains an empty item",
            ));
        }
        if let Some((first, last)) = item.split_once('-') {
            let first = parse_probe_port(first)?;
            let last = parse_probe_port(last)?;
            if first > last {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid descending port range: {item}"),
                ));
            }
            for port in first..=last {
                ports.insert(port);
                if ports.len() > MAX_PROBE_PORTS {
                    return Err(too_many_probe_ports());
                }
            }
        } else {
            ports.insert(parse_probe_port(item)?);
        }
        if ports.len() > MAX_PROBE_PORTS {
            return Err(too_many_probe_ports());
        }
    }
    Ok(ports.into_iter().collect())
}

fn parse_probe_port(value: &str) -> io::Result<u16> {
    let port = value.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid TCP port: {value}"),
        )
    })?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP port must be between 1 and 65535",
        ));
    }
    Ok(port)
}

fn too_many_probe_ports() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("probe accepts at most {MAX_PROBE_PORTS} distinct ports"),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpProbeStatus {
    Connected,
    ConnectionRefused,
    Failed,
}

impl TcpProbeStatus {
    fn filter_name(self) -> &'static str {
        match self {
            Self::Connected => "open",
            Self::ConnectionRefused => "closed",
            Self::Failed => "failed",
        }
    }
}

struct TcpProbeResult {
    port: u16,
    status: TcpProbeStatus,
    error: Option<String>,
    elapsed: std::time::Duration,
}

impl TcpProbeResult {
    fn reachable(&self) -> bool {
        self.status != TcpProbeStatus::Failed
    }

    fn status_name(&self) -> &'static str {
        match self.status {
            TcpProbeStatus::Connected => "connected",
            TcpProbeStatus::ConnectionRefused => "connection-refused",
            TcpProbeStatus::Failed => "failed",
        }
    }
}

fn tcp_probe(address: IpAddr, port: u16, timeout: std::time::Duration) -> TcpProbeResult {
    let started = std::time::Instant::now();
    let result = TcpStream::connect_timeout(&std::net::SocketAddr::new(address, port), timeout);
    let elapsed = started.elapsed();
    match result {
        Ok(_) => TcpProbeResult {
            port,
            status: TcpProbeStatus::Connected,
            error: None,
            elapsed,
        },
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => TcpProbeResult {
            port,
            status: TcpProbeStatus::ConnectionRefused,
            error: Some(error.to_string()),
            elapsed,
        },
        Err(error) => TcpProbeResult {
            port,
            status: TcpProbeStatus::Failed,
            error: Some(error.to_string()),
            elapsed,
        },
    }
}

fn tcp_probe_ports(
    address: IpAddr,
    ports: &[u16],
    timeout: std::time::Duration,
) -> Vec<TcpProbeResult> {
    if let [port] = ports {
        return vec![tcp_probe(address, *port, timeout)];
    }
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(ports.len()));
    std::thread::scope(|scope| {
        for _ in 0..ports.len().min(MAX_CONCURRENT_PROBES) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&port) = ports.get(index) else {
                        break;
                    };
                    let result = tcp_probe(address, port, timeout);
                    results
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(result);
                }
            });
        }
    });
    let mut results = results
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    results.sort_by_key(|result| result.port);
    results
}

fn probe(arguments: &[String]) -> io::Result<bool> {
    let arguments = parse_probe_arguments(arguments)?;
    let (destination, route) = resolve_probe_destination(&arguments.host, arguments.ports[0])?;
    let interface_names = interface_names();
    if arguments.ports.len() == 1 && arguments.filter.is_none() {
        println!(
            "TCP probe {}:{} ({})",
            arguments.host,
            arguments.ports[0],
            destination.ip()
        );
    } else {
        println!("TCP port scan {} ({})", arguments.host, destination.ip());
    }
    println!(
        "  Route: {}{}{} source {}",
        route
            .gateway
            .map(|gateway| format!("via {gateway}"))
            .unwrap_or_else(|| "direct".into()),
        route
            .interface_index
            .map(|index| format!(" dev {}", interface_label(&interface_names, index)))
            .unwrap_or_default(),
        route
            .metric
            .map(|metric| format!(" metric {metric}"))
            .unwrap_or_default(),
        route
            .source
            .map(|source| source.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    let started = std::time::Instant::now();
    let results = tcp_probe_ports(
        destination.ip(),
        &arguments.ports,
        std::time::Duration::from_millis(arguments.timeout_ms),
    );
    if arguments.filter.is_none()
        && let [result] = results.as_slice()
    {
        match result.status {
            TcpProbeStatus::Connected => println!(
                "  Result: connected in {:.1}ms",
                result.elapsed.as_secs_f64() * 1000.0
            ),
            TcpProbeStatus::ConnectionRefused => println!(
                "  Result: host reached in {:.1}ms; connection refused",
                result.elapsed.as_secs_f64() * 1000.0
            ),
            TcpProbeStatus::Failed => println!(
                "  Result: failed after {:.1}ms: {}",
                result.elapsed.as_secs_f64() * 1000.0,
                result.error.as_deref().unwrap_or("unknown error")
            ),
        }
    } else {
        let matching = results
            .iter()
            .filter(|result| {
                arguments
                    .filter
                    .is_none_or(|filter| result.status == filter)
            })
            .collect::<Vec<_>>();
        for result in &matching {
            match result.status {
                TcpProbeStatus::Connected => println!(
                    "  {}/tcp open in {:.1}ms",
                    result.port,
                    result.elapsed.as_secs_f64() * 1000.0
                ),
                TcpProbeStatus::ConnectionRefused => println!(
                    "  {}/tcp closed in {:.1}ms (connection refused)",
                    result.port,
                    result.elapsed.as_secs_f64() * 1000.0
                ),
                TcpProbeStatus::Failed => println!(
                    "  {}/tcp failed after {:.1}ms: {}",
                    result.port,
                    result.elapsed.as_secs_f64() * 1000.0,
                    result.error.as_deref().unwrap_or("unknown error")
                ),
            }
        }
        if matching.is_empty()
            && let Some(filter) = arguments.filter
        {
            println!("  No {} TCP ports", filter.filter_name());
        }
        let open = results
            .iter()
            .filter(|result| result.status == TcpProbeStatus::Connected)
            .count();
        let closed = results
            .iter()
            .filter(|result| result.status == TcpProbeStatus::ConnectionRefused)
            .count();
        let failed = results.len() - open - closed;
        if let Some(filter) = arguments.filter {
            println!(
                "Port scan complete: {} {}, {} scanned, {:.1}ms",
                matching.len(),
                filter.filter_name(),
                results.len(),
                started.elapsed().as_secs_f64() * 1000.0
            );
        } else {
            println!(
                "Port scan complete: {open} open, {closed} closed, {failed} failed, {:.1}ms",
                started.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
    Ok(results.iter().any(TcpProbeResult::reachable))
}

fn probe_json(arguments: &[String]) -> io::Result<(json::Value, bool)> {
    let arguments = parse_probe_arguments(arguments)?;
    let (destination, route) = resolve_probe_destination(&arguments.host, arguments.ports[0])?;
    let route_value = json_route(route);
    let started = std::time::Instant::now();
    let results = tcp_probe_ports(
        destination.ip(),
        &arguments.ports,
        std::time::Duration::from_millis(arguments.timeout_ms),
    );
    let reachable = results.iter().any(TcpProbeResult::reachable);
    if arguments.filter.is_none()
        && let [result] = results.as_slice()
    {
        return Ok((
            json::Value::object([
                ("host", json::Value::string(arguments.host)),
                ("port", json::Value::number(result.port)),
                ("address", json::Value::string(destination.ip().to_string())),
                ("route", route_value),
                ("reachable", json::Value::Bool(reachable)),
                ("status", json::Value::string(result.status_name())),
                ("error", json::optional_string(result.error.as_deref())),
                (
                    "elapsedMilliseconds",
                    json::Value::number(format!("{:.3}", result.elapsed.as_secs_f64() * 1000.0)),
                ),
            ]),
            reachable,
        ));
    }
    let scanned_ports = results.len();
    let port_results = results
        .into_iter()
        .filter(|result| {
            arguments
                .filter
                .is_none_or(|filter| result.status == filter)
        })
        .map(|result| {
            json::Value::object([
                ("port", json::Value::number(result.port)),
                ("status", json::Value::string(result.status_name())),
                (
                    "open",
                    json::Value::Bool(result.status == TcpProbeStatus::Connected),
                ),
                ("reachable", json::Value::Bool(result.reachable())),
                ("error", json::optional_string(result.error)),
                (
                    "elapsedMilliseconds",
                    json::Value::number(format!("{:.3}", result.elapsed.as_secs_f64() * 1000.0)),
                ),
            ])
        })
        .collect();
    Ok((
        json::Value::object([
            ("host", json::Value::string(arguments.host)),
            ("address", json::Value::string(destination.ip().to_string())),
            ("route", route_value),
            ("reachable", json::Value::Bool(reachable)),
            (
                "filter",
                json::optional_string(arguments.filter.map(|filter| filter.filter_name())),
            ),
            ("scannedPorts", json::Value::number(scanned_ports)),
            ("ports", json::Value::Array(port_results)),
            (
                "elapsedMilliseconds",
                json::Value::number(format!("{:.3}", started.elapsed().as_secs_f64() * 1000.0)),
            ),
        ]),
        reachable,
    ))
}

fn resolve_probe_destination(
    host: &str,
    port: u16,
) -> io::Result<(std::net::SocketAddr, netlink::Route)> {
    let destinations = (host, port).to_socket_addrs()?.collect::<Vec<_>>();
    if destinations.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "host resolved to no IP addresses",
        ));
    }
    let mut last_error = None;
    for destination in destinations {
        match route_to(destination.ip()) {
            Ok(route) => return Ok((destination, route)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no routable IP address found",
        )
    }))
}

fn check(active: bool) -> io::Result<bool> {
    let route_contents = fs::read_to_string(PROC_NET_ROUTE)?;
    let route = parse_default_ipv4_route(&route_contents)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no usable default IPv4 route"))?;
    let interface_path = Path::new(SYS_CLASS_NET).join(&route.interface);
    let state = interface_state(&interface_path, interface_kind(&interface_path).as_deref());
    let carrier = read_trimmed(interface_path.join("carrier"));
    if active && !route.gateway.is_unspecified() {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let _ = socket.send_to(&[0], (route.gateway, 9));
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let neighbors = netlink::ipv4_neighbors()?;
    let gateway_neighbor = neighbors
        .iter()
        .find(|neighbor| neighbor.address == route.gateway);
    let nameservers = resolver::nameservers(RESOLV_CONF);

    let mut warnings = 0;
    println!("Network check");
    println!(
        "  Default route: ok via {} dev {} metric {}",
        route.gateway, route.interface, route.metric
    );
    if state == "up" && carrier.as_deref() == Some("1") {
        println!("  Interface: ok {} is up with carrier", route.interface);
    } else {
        println!(
            "  Interface: warning {} state {state}, carrier {}",
            route.interface,
            carrier.as_deref().unwrap_or("unknown")
        );
        warnings += 1;
    }
    if route.gateway.is_unspecified() {
        println!("  Gateway neighbor: not applicable (direct default route)");
    } else if let Some(neighbor) = gateway_neighbor {
        let link_address = neighbor.link_address.as_deref().unwrap_or("unknown");
        println!(
            "  Gateway neighbor: ok {} lladdr {link_address} {}",
            route.gateway, neighbor.state
        );
    } else {
        println!(
            "  Gateway neighbor: warning {} is not in the resolved ARP cache",
            route.gateway
        );
        warnings += 1;
    }
    if nameservers.is_empty() {
        println!("  DNS: warning no nameserver configured in {RESOLV_CONF}");
        warnings += 1;
    } else {
        println!("  DNS: ok nameserver {}", nameservers.join(", "));
    }
    if active {
        println!("  Active checks:");
        if !route.gateway.is_unspecified() {
            match ping::echo(route.gateway, 3, std::time::Duration::from_millis(800)) {
                Ok(result) if result.received > 0 => println!(
                    "    Gateway ICMP {}: {}/{} replies, {:.0}% loss, RTT min/avg/max {}/{}/{}",
                    route.gateway,
                    result.received,
                    result.transmitted,
                    ping_loss(&result),
                    format_duration(result.minimum),
                    format_duration(result.average),
                    format_duration(result.maximum),
                ),
                Ok(result) => {
                    println!(
                        "    Gateway ICMP {}: warning 0/{} replies",
                        route.gateway, result.transmitted
                    );
                    warnings += 1;
                }
                Err(error) if matches!(error.raw_os_error(), Some(1 | 13)) => {
                    println!("    Gateway ICMP: skipped ({error})");
                }
                Err(error) => {
                    println!("    Gateway ICMP: warning {error}");
                    warnings += 1;
                }
            }
        }
        for nameserver in &nameservers {
            let Ok(address) = nameserver.parse::<IpAddr>() else {
                println!("    DNS route {nameserver}: skipped (not an IP address)");
                continue;
            };
            match route_to(address) {
                Ok(dns_route) => {
                    let interface = dns_route
                        .interface_index
                        .map(|index| interface_label(&interface_names(), index))
                        .unwrap_or_else(|| "unknown".into());
                    println!("    DNS route {address}: ok dev {interface}");
                }
                Err(error) => {
                    println!("    DNS route {address}: warning {error}");
                    warnings += 1;
                    continue;
                }
            }
            let started = std::time::Instant::now();
            match TcpStream::connect_timeout(
                &std::net::SocketAddr::new(address, 53),
                std::time::Duration::from_secs(2),
            ) {
                Ok(_) => println!(
                    "    DNS TCP {address}: ok {:.1}ms",
                    started.elapsed().as_secs_f64() * 1000.0
                ),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => println!(
                    "    DNS TCP {address}: host reached in {:.1}ms; connection refused",
                    started.elapsed().as_secs_f64() * 1000.0
                ),
                Err(error) => {
                    println!("    DNS TCP {address}: warning {error}");
                    warnings += 1;
                }
            }
        }
    }
    println!(
        "  Result: {}",
        if warnings == 0 {
            "ok".into()
        } else {
            format!("{warnings} warning(s)")
        }
    );
    Ok(warnings == 0)
}

fn ping_loss(result: &ping::Result) -> f64 {
    if result.transmitted == 0 {
        0.0
    } else {
        f64::from(result.transmitted - result.received) * 100.0 / f64::from(result.transmitted)
    }
}

fn format_duration(duration: Option<std::time::Duration>) -> String {
    duration
        .map(|duration| format!("{:.2}ms", duration.as_secs_f64() * 1000.0))
        .unwrap_or_else(|| "unknown".into())
}

fn check_json(active: bool) -> io::Result<(json::Value, bool)> {
    let route_contents = fs::read_to_string(PROC_NET_ROUTE)?;
    let default = parse_default_ipv4_route(&route_contents)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no usable default IPv4 route"))?;
    let interface_path = Path::new(SYS_CLASS_NET).join(&default.interface);
    let state = interface_state(&interface_path, interface_kind(&interface_path).as_deref());
    let carrier = read_trimmed(interface_path.join("carrier"));
    if active && !default.gateway.is_unspecified() {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let _ = socket.send_to(&[0], (default.gateway, 9));
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let gateway = netlink::ipv4_neighbors()?
        .into_iter()
        .find(|neighbor| neighbor.address == default.gateway);
    let nameservers = resolver::nameservers(RESOLV_CONF);
    let mut warnings = 0_u32;
    let mut checks = vec![json_check_item(
        "default-route",
        "ok",
        format!(
            "via {} dev {} metric {}",
            default.gateway, default.interface, default.metric
        ),
    )];
    if state == "up" && carrier.as_deref() == Some("1") {
        checks.push(json_check_item(
            "interface",
            "ok",
            format!("{} is up with carrier", default.interface),
        ));
    } else {
        warnings += 1;
        checks.push(json_check_item(
            "interface",
            "warning",
            format!(
                "{} state {state}, carrier {}",
                default.interface,
                carrier.as_deref().unwrap_or("unknown")
            ),
        ));
    }
    if default.gateway.is_unspecified() {
        checks.push(json_check_item(
            "gateway-neighbor",
            "not-applicable",
            "direct default route",
        ));
    } else if let Some(neighbor) = gateway {
        checks.push(json_check_item(
            "gateway-neighbor",
            "ok",
            format!(
                "{} lladdr {} {}",
                default.gateway,
                neighbor.link_address.as_deref().unwrap_or("unknown"),
                neighbor.state
            ),
        ));
    } else {
        warnings += 1;
        checks.push(json_check_item(
            "gateway-neighbor",
            "warning",
            format!("{} is not in the resolved ARP cache", default.gateway),
        ));
    }
    if nameservers.is_empty() {
        warnings += 1;
        checks.push(json_check_item(
            "dns",
            "warning",
            format!("no nameserver configured in {RESOLV_CONF}"),
        ));
    } else {
        checks.push(json_check_item(
            "dns",
            "ok",
            format!("nameserver {}", nameservers.join(", ")),
        ));
    }
    if active {
        let interface_names = interface_names();
        if !default.gateway.is_unspecified() {
            match ping::echo(default.gateway, 3, std::time::Duration::from_millis(800)) {
                Ok(result) if result.received > 0 => checks.push(json::Value::object([
                    ("name", json::Value::string("gateway-icmp")),
                    ("status", json::Value::string("ok")),
                    ("address", json::Value::string(default.gateway.to_string())),
                    ("transmitted", json::Value::number(result.transmitted)),
                    ("received", json::Value::number(result.received)),
                    ("lossPercent", json::Value::number(ping_loss(&result))),
                    ("minimumMilliseconds", json_duration(result.minimum)),
                    ("averageMilliseconds", json_duration(result.average)),
                    ("maximumMilliseconds", json_duration(result.maximum)),
                ])),
                Ok(result) => {
                    warnings += 1;
                    checks.push(json::Value::object([
                        ("name", json::Value::string("gateway-icmp")),
                        ("status", json::Value::string("warning")),
                        ("address", json::Value::string(default.gateway.to_string())),
                        ("transmitted", json::Value::number(result.transmitted)),
                        ("received", json::Value::number(result.received)),
                        ("lossPercent", json::Value::number(100)),
                    ]));
                }
                Err(error) if matches!(error.raw_os_error(), Some(1 | 13)) => {
                    checks.push(json_check_item(
                        "gateway-icmp",
                        "skipped",
                        error.to_string(),
                    ));
                }
                Err(error) => {
                    warnings += 1;
                    checks.push(json_check_item(
                        "gateway-icmp",
                        "warning",
                        error.to_string(),
                    ));
                }
            }
        }
        for nameserver in &nameservers {
            let Ok(address) = nameserver.parse::<IpAddr>() else {
                checks.push(json_check_item(
                    "dns-route",
                    "skipped",
                    format!("{nameserver} is not an IP address"),
                ));
                continue;
            };
            match route_to(address) {
                Ok(route) => checks.push(json_check_item(
                    "dns-route",
                    "ok",
                    format!(
                        "{address} dev {}",
                        route
                            .interface_index
                            .map(|index| interface_label(&interface_names, index))
                            .unwrap_or_else(|| "unknown".into())
                    ),
                )),
                Err(error) => {
                    warnings += 1;
                    checks.push(json_check_item(
                        "dns-route",
                        "warning",
                        format!("{address}: {error}"),
                    ));
                    continue;
                }
            }
            let started = std::time::Instant::now();
            match TcpStream::connect_timeout(
                &std::net::SocketAddr::new(address, 53),
                std::time::Duration::from_secs(2),
            ) {
                Ok(_) => checks.push(json_check_item(
                    "dns-tcp",
                    "ok",
                    format!(
                        "{address}:53 connected in {:.1}ms",
                        started.elapsed().as_secs_f64() * 1000.0
                    ),
                )),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    checks.push(json_check_item(
                        "dns-tcp",
                        "reached",
                        format!(
                            "{address}:53 refused in {:.1}ms",
                            started.elapsed().as_secs_f64() * 1000.0
                        ),
                    ));
                }
                Err(error) => {
                    warnings += 1;
                    checks.push(json_check_item(
                        "dns-tcp",
                        "warning",
                        format!("{address}:53 {error}"),
                    ));
                }
            }
        }
    }
    Ok((
        json::Value::object([
            ("active", json::Value::Bool(active)),
            ("healthy", json::Value::Bool(warnings == 0)),
            ("warnings", json::Value::number(warnings)),
            ("checks", json::Value::Array(checks)),
        ]),
        warnings == 0,
    ))
}

fn json_duration(duration: Option<std::time::Duration>) -> json::Value {
    duration
        .map(|duration| json::Value::number(duration.as_secs_f64() * 1000.0))
        .unwrap_or(json::Value::Null)
}

fn json_check_item(name: &str, status: &str, detail: impl Into<String>) -> json::Value {
    json::Value::object([
        ("name", json::Value::string(name)),
        ("status", json::Value::string(status)),
        ("detail", json::Value::string(detail)),
    ])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchFilter {
    Link,
    Address,
    Route,
    Neighbor,
}

impl WatchFilter {
    fn matches(self, event: &netlink::NetworkEvent) -> bool {
        matches!(
            (self, event),
            (Self::Link, netlink::NetworkEvent::Link { .. })
                | (Self::Address, netlink::NetworkEvent::Address { .. })
                | (Self::Route, netlink::NetworkEvent::Route { .. })
                | (Self::Neighbor, netlink::NetworkEvent::Neighbor { .. })
        )
    }
}

fn parse_watch_arguments(arguments: &[String]) -> io::Result<Option<WatchFilter>> {
    match arguments {
        [] => Ok(None),
        [option, value] if option == "--filter" => match value.as_str() {
            "link" => Ok(Some(WatchFilter::Link)),
            "address" => Ok(Some(WatchFilter::Address)),
            "route" => Ok(Some(WatchFilter::Route)),
            "neighbor" => Ok(Some(WatchFilter::Neighbor)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--filter must be link, address, route, or neighbor",
            )),
        },
        [option] if option == "--filter" => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--filter requires link, address, route, or neighbor",
        )),
        [option, ..] if option.starts_with('-') => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown watch option: {option}"),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "watch accepts only --filter link|address|route|neighbor",
        )),
    }
}

fn watch(filter: Option<WatchFilter>) -> io::Result<()> {
    let mut interface_names = interface_names();
    let vendors = oui::load();
    println!("Watching kernel network events (Ctrl-C to stop)");
    io::stdout().flush()?;

    netlink::watch_events(|event| {
        let emit = filter.is_none_or(|filter| filter.matches(&event));
        match event {
            netlink::NetworkEvent::Link {
                removed,
                interface_index,
                name,
                up,
            } => {
                let name = name.or_else(|| interface_names.get(&interface_index).cloned());
                let label = name
                    .clone()
                    .unwrap_or_else(|| format!("ifindex {interface_index}"));
                if removed {
                    if emit {
                        println!("link removed {label}");
                    }
                    interface_names.remove(&interface_index);
                } else {
                    if let Some(name) = name {
                        interface_names.insert(interface_index, name);
                    }
                    if emit {
                        println!("link changed {label} {}", if up { "up" } else { "down" });
                    }
                }
            }
            netlink::NetworkEvent::Address {
                removed,
                interface_index,
                address,
                prefix,
            } => {
                let interface = interface_label(&interface_names, interface_index);
                if emit {
                    println!(
                        "address {} {address}/{prefix} dev {interface}",
                        if removed { "removed" } else { "added" }
                    );
                }
            }
            netlink::NetworkEvent::Route { removed, route } => {
                let target = if route.destination.is_unspecified() && route.prefix == 0 {
                    "default".into()
                } else {
                    format!("{}/{}", route.destination, route.prefix)
                };
                let gateway = route
                    .gateway
                    .map(|gateway| format!(" via {gateway}"))
                    .unwrap_or_default();
                let interface = route
                    .interface_index
                    .map(|index| format!(" dev {}", interface_label(&interface_names, index)))
                    .unwrap_or_default();
                let metric = route
                    .metric
                    .map(|metric| format!(" metric {metric}"))
                    .unwrap_or_default();
                if emit {
                    println!(
                        "route {} {target}{gateway}{interface}{metric}",
                        if removed { "removed" } else { "changed" }
                    );
                }
            }
            netlink::NetworkEvent::Neighbor { removed, neighbor } => {
                let interface = interface_label(&interface_names, neighbor.interface_index);
                let link_address = neighbor
                    .link_address
                    .as_deref()
                    .map(|address| format!(" lladdr {address}"))
                    .unwrap_or_default();
                let vendor = neighbor
                    .link_address
                    .as_deref()
                    .and_then(|address| oui::vendor(address, &vendors))
                    .map(|vendor| format!(" vendor {vendor}"))
                    .unwrap_or_default();
                if emit {
                    println!(
                        "neighbor {} {} dev {interface}{link_address}{vendor} {}",
                        if removed { "removed" } else { "changed" },
                        neighbor.address,
                        neighbor.state
                    );
                }
            }
        }
        let _ = io::stdout().flush();
    })
}

fn watch_json(filter: Option<WatchFilter>) -> io::Result<()> {
    let mut interface_names = interface_names();
    netlink::watch_events(|event| {
        let emit = filter.is_none_or(|filter| filter.matches(&event));
        let value = match event {
            netlink::NetworkEvent::Link {
                removed,
                interface_index,
                name,
                up,
            } => {
                let label = name
                    .clone()
                    .or_else(|| interface_names.get(&interface_index).cloned());
                if removed {
                    interface_names.remove(&interface_index);
                } else if let Some(name) = name {
                    interface_names.insert(interface_index, name);
                }
                json::Value::object([
                    (
                        "event",
                        json::Value::string(if removed { "removed" } else { "changed" }),
                    ),
                    ("object", json::Value::string("link")),
                    ("interfaceIndex", json::Value::number(interface_index)),
                    ("interface", json::optional_string(label)),
                    ("up", json::Value::Bool(up)),
                ])
            }
            netlink::NetworkEvent::Address {
                removed,
                interface_index,
                address,
                prefix,
            } => json::Value::object([
                (
                    "event",
                    json::Value::string(if removed { "removed" } else { "added" }),
                ),
                ("object", json::Value::string("address")),
                ("interfaceIndex", json::Value::number(interface_index)),
                (
                    "interface",
                    json::Value::string(interface_label(&interface_names, interface_index)),
                ),
                ("address", json::Value::string(address.to_string())),
                ("prefix", json::Value::number(prefix)),
            ]),
            netlink::NetworkEvent::Route { removed, route } => json::Value::object([
                (
                    "event",
                    json::Value::string(if removed { "removed" } else { "changed" }),
                ),
                ("object", json::Value::string("route")),
                ("route", json_route(route)),
            ]),
            netlink::NetworkEvent::Neighbor { removed, neighbor } => json::Value::object([
                (
                    "event",
                    json::Value::string(if removed { "removed" } else { "changed" }),
                ),
                ("object", json::Value::string("neighbor")),
                ("neighbor", json_neighbor(neighbor, &interface_names)),
            ]),
        };
        if emit {
            println!("{}", value.render());
            let _ = io::stdout().flush();
        }
    })
}

fn interface_label(interface_names: &HashMap<i32, String>, index: i32) -> String {
    interface_names
        .get(&index)
        .cloned()
        .unwrap_or_else(|| format!("ifindex {index}"))
}

fn print_dns() {
    println!("DNS");
    if let Ok(target) = fs::canonicalize(RESOLV_CONF) {
        println!("  Configuration: {}", target.display());
    } else {
        println!("  Configuration: {RESOLV_CONF}");
    }

    let Ok(contents) = fs::read_to_string(RESOLV_CONF) else {
        println!("  Unavailable");
        return;
    };

    let mut found = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(directive) = fields.next() else {
            continue;
        };
        let value = fields.collect::<Vec<_>>().join(" ");
        match directive {
            "nameserver" => println!("  Nameserver: {value}"),
            "search" => println!("  Search domains: {value}"),
            "domain" => println!("  Domain: {value}"),
            "options" => println!("  Options: {value}"),
            _ => continue,
        }
        found = true;
    }
    if !found {
        println!("  No resolver entries");
    }
}

fn json_dns() -> json::Value {
    let configuration = fs::canonicalize(RESOLV_CONF)
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| RESOLV_CONF.into());
    let mut nameservers = Vec::new();
    let mut search = Vec::new();
    let mut domain = None;
    let mut options = Vec::new();
    if let Ok(contents) = fs::read_to_string(RESOLV_CONF) {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(directive) = fields.next() else {
                continue;
            };
            let values = fields.map(str::to_owned).collect::<Vec<_>>();
            match directive {
                "nameserver" => nameservers.extend(values),
                "search" => search.extend(values),
                "domain" => domain = values.first().cloned(),
                "options" => options.extend(values),
                _ => {}
            }
        }
    }
    json::Value::object([
        ("configuration", json::Value::string(configuration)),
        ("nameservers", json::strings(nameservers)),
        ("searchDomains", json::strings(search)),
        ("domain", json::optional_string(domain)),
        ("options", json::strings(options)),
    ])
}

fn print_sockets(view: sockets::View) -> io::Result<()> {
    let sockets = sockets::ip_sockets()?
        .into_iter()
        .filter(|socket| view.matches(socket))
        .collect::<Vec<_>>();
    let users = user_names();
    let inodes = sockets
        .iter()
        .filter_map(|socket| (socket.inode != 0).then_some(socket.inode))
        .collect::<HashSet<_>>();
    let processes = sockets::socket_processes(&inodes);
    let (diagnostics, diagnostic_error) = match sock_diag::ip_diagnostics() {
        Ok(diagnostics) => (
            diagnostics
                .into_iter()
                .map(|diagnostic| {
                    (
                        (diagnostic.protocol, diagnostic.local, diagnostic.remote),
                        diagnostic,
                    )
                })
                .collect::<HashMap<_, _>>(),
            None,
        ),
        Err(error) => (HashMap::new(), Some(error)),
    };
    let interface_names = interface_names();

    println!("Sockets");
    if let Some(error) = diagnostic_error {
        if error.raw_os_error() == Some(2) {
            println!("  Diagnostics unavailable: kernel CONFIG_INET_DIAG is disabled");
        } else {
            println!("  Diagnostics unavailable: {error}");
        }
    }
    if sockets.is_empty() {
        println!("  None visible");
    }
    for socket in sockets {
        let owner = if socket.inode == 0 {
            "kernel".into()
        } else {
            users
                .get(&socket.uid)
                .map(|name| format!("{name}({})", socket.uid))
                .unwrap_or_else(|| socket.uid.to_string())
        };
        let process = processes
            .get(&socket.inode)
            .map(|processes| {
                let processes = processes
                    .iter()
                    .map(|process| format!("{}({})", process.name, process.pid))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(" process {processes}")
            })
            .unwrap_or_default();
        println!(
            "  {} {} -> {} {} owner {owner}{process} inode {}",
            socket.protocol.name(),
            format_socket_endpoint(socket.local),
            format_socket_endpoint(socket.remote),
            socket.state,
            socket.inode
        );
        if let Some(diagnostic) = diagnostics.get(&(socket.protocol, socket.local, socket.remote)) {
            let interface = if diagnostic.interface_index != 0 {
                format!(
                    " dev {}",
                    interface_label(&interface_names, diagnostic.interface_index as i32)
                )
            } else {
                String::new()
            };
            let timer = if diagnostic.timer == "off" {
                " timer off".into()
            } else {
                format!(
                    " timer {} expires {}ms retransmits {}",
                    diagnostic.timer, diagnostic.expires_ms, diagnostic.retransmits
                )
            };
            println!(
                "    queues RX {} B TX {} B{interface}{timer}",
                diagnostic.receive_queue, diagnostic.send_queue
            );
            if let Some(tcp) = diagnostic.tcp.as_ref() {
                let congestion = diagnostic
                    .congestion
                    .as_deref()
                    .map(|name| format!(" congestion {name}"))
                    .unwrap_or_default();
                println!(
                    "    TCP RTT {} variance {} RTO {} cwnd {} ssthresh {} unacked {} lost {} retransmitted {} total-retransmits {} PMTU {} MSS {}/{}{congestion}",
                    format_microseconds(tcp.rtt_us),
                    format_microseconds(tcp.rtt_variance_us),
                    format_microseconds(tcp.rto_us),
                    tcp.send_cwnd,
                    tcp.send_ssthresh,
                    tcp.unacked,
                    tcp.lost,
                    tcp.retransmitted,
                    tcp.total_retransmits,
                    tcp.path_mtu,
                    tcp.send_mss,
                    tcp.receive_mss,
                );
            }
        }
    }
    Ok(())
}

fn sockets_json(view: sockets::View) -> io::Result<json::Value> {
    let sockets = sockets::ip_sockets()?
        .into_iter()
        .filter(|socket| view.matches(socket))
        .collect::<Vec<_>>();
    let users = user_names();
    let inodes = sockets
        .iter()
        .filter_map(|socket| (socket.inode != 0).then_some(socket.inode))
        .collect::<HashSet<_>>();
    let processes = sockets::socket_processes(&inodes);
    let (diagnostics, diagnostic_error) = match sock_diag::ip_diagnostics() {
        Ok(diagnostics) => (
            diagnostics
                .into_iter()
                .map(|diagnostic| {
                    (
                        (diagnostic.protocol, diagnostic.local, diagnostic.remote),
                        diagnostic,
                    )
                })
                .collect::<HashMap<_, _>>(),
            None,
        ),
        Err(error) => (HashMap::new(), Some(error.to_string())),
    };
    let values = sockets
        .into_iter()
        .map(|socket| {
            let diagnostic = diagnostics.get(&(socket.protocol, socket.local, socket.remote));
            let tcp = diagnostic.and_then(|diagnostic| diagnostic.tcp.as_ref());
            json::Value::object([
                (
                    "family",
                    json::Value::string(json_ip_family(socket.local.ip())),
                ),
                (
                    "protocol",
                    json::Value::string(socket.protocol.name().to_ascii_lowercase()),
                ),
                (
                    "local",
                    json::Value::string(format_socket_endpoint(socket.local)),
                ),
                (
                    "remote",
                    json::Value::string(format_socket_endpoint(socket.remote)),
                ),
                ("state", json::Value::string(socket.state)),
                ("uid", json::Value::number(socket.uid)),
                ("user", json::optional_string(users.get(&socket.uid))),
                ("inode", json::Value::number(socket.inode)),
                (
                    "processes",
                    json::Value::Array(
                        processes
                            .get(&socket.inode)
                            .into_iter()
                            .flatten()
                            .map(|process| {
                                json::Value::object([
                                    ("pid", json::Value::number(process.pid)),
                                    ("name", json::Value::string(&process.name)),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "receiveQueueBytes",
                    json::optional_number(diagnostic.map(|value| value.receive_queue)),
                ),
                (
                    "sendQueueBytes",
                    json::optional_number(diagnostic.map(|value| value.send_queue)),
                ),
                (
                    "interfaceIndex",
                    json::optional_number(
                        diagnostic
                            .map(|value| value.interface_index)
                            .filter(|index| *index != 0),
                    ),
                ),
                (
                    "timer",
                    json::optional_string(diagnostic.map(|value| value.timer)),
                ),
                (
                    "timerExpiresMilliseconds",
                    json::optional_number(diagnostic.map(|value| value.expires_ms)),
                ),
                (
                    "retransmits",
                    json::optional_number(diagnostic.map(|value| value.retransmits)),
                ),
                (
                    "congestion",
                    json::optional_string(diagnostic.and_then(|value| value.congestion.as_deref())),
                ),
                (
                    "tcp",
                    tcp.map(json_tcp_diagnostic).unwrap_or(json::Value::Null),
                ),
            ])
        })
        .collect();
    Ok(json::Value::object([
        (
            "diagnosticsAvailable",
            json::Value::Bool(diagnostic_error.is_none()),
        ),
        ("diagnosticError", json::optional_string(diagnostic_error)),
        ("sockets", json::Value::Array(values)),
    ]))
}

fn json_tcp_diagnostic(tcp: &sock_diag::TcpDiagnostic) -> json::Value {
    json::Value::object([
        ("rtoMicroseconds", json::Value::number(tcp.rto_us)),
        ("rttMicroseconds", json::Value::number(tcp.rtt_us)),
        (
            "rttVarianceMicroseconds",
            json::Value::number(tcp.rtt_variance_us),
        ),
        ("sendMss", json::Value::number(tcp.send_mss)),
        ("receiveMss", json::Value::number(tcp.receive_mss)),
        ("unacked", json::Value::number(tcp.unacked)),
        ("lost", json::Value::number(tcp.lost)),
        ("retransmitted", json::Value::number(tcp.retransmitted)),
        (
            "totalRetransmits",
            json::Value::number(tcp.total_retransmits),
        ),
        (
            "sendSlowStartThreshold",
            json::Value::number(tcp.send_ssthresh),
        ),
        ("sendCongestionWindow", json::Value::number(tcp.send_cwnd)),
        ("pathMtu", json::Value::number(tcp.path_mtu)),
    ])
}

fn format_microseconds(microseconds: u32) -> String {
    if microseconds < 1000 {
        format!("{microseconds}us")
    } else {
        format!("{:.2}ms", f64::from(microseconds) / 1000.0)
    }
}

fn print_traffic(arguments: &[String]) -> io::Result<()> {
    let (selection, interval, watch) = parse_traffic_arguments(arguments)?;
    let refresh = watch && io::stdout().is_terminal();
    let mut rendered_lines = 0;
    loop {
        let sample = traffic::sample(selection.as_deref(), interval)?;
        if refresh && rendered_lines != 0 {
            print!("\x1b[{rendered_lines}A\r\x1b[J");
        }
        rendered_lines = traffic_sample_line_count(sample.interfaces.len());
        print_traffic_sample(sample);
        io::stdout().flush()?;
        if !watch {
            return Ok(());
        }
    }
}

fn traffic_sample_line_count(interface_count: usize) -> usize {
    1 + interface_count * 3
}

fn traffic_json(arguments: &[String]) -> io::Result<()> {
    let (selection, interval, watch) = parse_traffic_arguments(arguments)?;
    loop {
        let sample = traffic::sample(selection.as_deref(), interval)?;
        println!("{}", json_traffic_sample(sample).render());
        io::stdout().flush()?;
        if !watch {
            return Ok(());
        }
    }
}

fn json_traffic_sample(sample: traffic::Sample) -> json::Value {
    json::Value::object([
        (
            "elapsedMilliseconds",
            json::Value::number(sample.elapsed.as_millis()),
        ),
        (
            "interfaces",
            json::Value::Array(
                sample
                    .interfaces
                    .into_iter()
                    .map(|interface| {
                        json::Value::object([
                            ("interface", json::Value::string(interface.interface)),
                            ("received", json_direction_rate(interface.received)),
                            ("transmitted", json_direction_rate(interface.transmitted)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn json_direction_rate(rate: traffic::DirectionRate) -> json::Value {
    json::Value::object([
        ("bytesPerSecond", json::Value::number(rate.bytes_per_second)),
        (
            "packetsPerSecond",
            json::Value::number(rate.packets_per_second),
        ),
        ("errors", json::Value::number(rate.errors)),
        ("dropped", json::Value::number(rate.dropped)),
    ])
}

fn print_traffic_sample(sample: traffic::Sample) {
    println!("Traffic ({:.1}s sample)", sample.elapsed.as_secs_f32());
    for interface in sample.interfaces {
        println!("  {}", interface.interface);
        print_direction_rate("RX", &interface.received);
        print_direction_rate("TX", &interface.transmitted);
    }
}

fn parse_traffic_arguments(
    arguments: &[String],
) -> io::Result<(Option<String>, std::time::Duration, bool)> {
    let mut selection = None;
    let mut interval_ms = 1000_u64;
    let mut watch = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--watch" => watch = true,
            "--interval" => {
                index += 1;
                interval_ms = parse_option_value(arguments, index, "--interval")?;
                if !(100..=60_000).contains(&interval_ms) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--interval must be between 100 and 60000 milliseconds",
                    ));
                }
            }
            option if option.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown traffic option: {option}"),
                ));
            }
            interface => {
                if selection.replace(interface.to_owned()).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "traffic accepts only one interface",
                    ));
                }
            }
        }
        index += 1;
    }
    Ok((
        selection,
        std::time::Duration::from_millis(interval_ms),
        watch,
    ))
}

fn print_direction_rate(label: &str, rate: &traffic::DirectionRate) {
    println!(
        "    {label}: {}/s, {} packets/s, {} errors, {} dropped",
        human_bytes(rate.bytes_per_second),
        rate.packets_per_second,
        rate.errors,
        rate.dropped
    );
}

fn print_wifi() -> io::Result<()> {
    let interfaces = wifi::interfaces()?;
    println!("Wi-Fi");
    if interfaces.is_empty() {
        println!("  No nl80211 interfaces");
    }
    for interface in interfaces {
        println!(
            "  {} index {} type {}",
            interface.name, interface.interface_index, interface.interface_type
        );
        if let Some(mac) = interface.mac {
            println!("    MAC: {mac}");
        }
        if let Some(wiphy) = interface.wiphy {
            println!(
                "    Radio: {} ({wiphy})",
                interface.wiphy_name.as_deref().unwrap_or("unnamed")
            );
        }
        if let Some(ssid) = interface.ssid {
            println!("    SSID: {ssid}");
        }
        if let Some(bssid) = interface.bssid {
            println!("    BSSID: {bssid}");
        }
        if let Some(frequency) = interface.frequency_mhz {
            println!("    Frequency: {frequency} MHz");
        }
        if let Some(signal) = interface.signal_dbm {
            println!("    Signal: {signal:.1} dBm");
        } else if let Some(signal) = interface.signal_unspecified {
            println!("    Signal: {signal}/100");
        }
        if let Some(age) = interface.seen_ms_ago {
            println!("    Last BSS update: {} ago", format_age(u64::from(age)));
        }
        if let Some(power_save) = interface.power_save {
            println!(
                "    Power save: {}",
                if power_save { "enabled" } else { "disabled" }
            );
        }
        if let Some(station) = interface.station {
            if let Some(signal) = station.signal_dbm {
                println!(
                    "    Station signal: {signal} dBm (average {} dBm)",
                    station
                        .average_signal_dbm
                        .map(|signal| signal.to_string())
                        .unwrap_or_else(|| "unknown".into())
                );
            }
            if let Some(inactive) = station.inactive_ms {
                println!("    Inactive: {}", format_age(u64::from(inactive)));
            }
            if let Some(rate) = station.receive_bitrate {
                println!("    Receive bitrate: {}", format_bitrate(&rate));
            }
            if let Some(rate) = station.transmit_bitrate {
                println!("    Transmit bitrate: {}", format_bitrate(&rate));
            }
            println!(
                "    Traffic: RX {} in {} packets, TX {} in {} packets",
                station
                    .receive_bytes
                    .map(human_bytes)
                    .unwrap_or_else(|| "unknown".into()),
                optional_number(station.receive_packets),
                station
                    .transmit_bytes
                    .map(human_bytes)
                    .unwrap_or_else(|| "unknown".into()),
                optional_number(station.transmit_packets),
            );
            println!(
                "    TX retries: {}, failures: {}",
                optional_number(station.transmit_retries),
                optional_number(station.transmit_failures)
            );
        }
    }
    Ok(())
}

fn json_wifi(interface: wifi::WifiInterface) -> json::Value {
    json::Value::object([
        (
            "interfaceIndex",
            json::Value::number(interface.interface_index),
        ),
        ("interface", json::Value::string(interface.name)),
        ("type", json::Value::string(interface.interface_type)),
        ("mac", json::optional_string(interface.mac)),
        ("radioIndex", json::optional_number(interface.wiphy)),
        ("radio", json::optional_string(interface.wiphy_name)),
        (
            "frequencyMHz",
            json::optional_number(interface.frequency_mhz),
        ),
        ("ssid", json::optional_string(interface.ssid)),
        ("bssid", json::optional_string(interface.bssid)),
        ("signalDbm", json::optional_number(interface.signal_dbm)),
        (
            "signalUnspecified",
            json::optional_number(interface.signal_unspecified),
        ),
        (
            "seenMillisecondsAgo",
            json::optional_number(interface.seen_ms_ago),
        ),
        ("powerSave", optional_json_bool(interface.power_save)),
        (
            "station",
            interface
                .station
                .map(json_wifi_station)
                .unwrap_or(json::Value::Null),
        ),
    ])
}

fn json_wifi_station(station: wifi::Station) -> json::Value {
    json::Value::object([
        (
            "inactiveMilliseconds",
            json::optional_number(station.inactive_ms),
        ),
        ("signalDbm", json::optional_number(station.signal_dbm)),
        (
            "averageSignalDbm",
            json::optional_number(station.average_signal_dbm),
        ),
        ("receiveBytes", json::optional_number(station.receive_bytes)),
        (
            "transmitBytes",
            json::optional_number(station.transmit_bytes),
        ),
        (
            "receivePackets",
            json::optional_number(station.receive_packets),
        ),
        (
            "transmitPackets",
            json::optional_number(station.transmit_packets),
        ),
        (
            "transmitRetries",
            json::optional_number(station.transmit_retries),
        ),
        (
            "transmitFailures",
            json::optional_number(station.transmit_failures),
        ),
        (
            "receiveBitrate",
            station
                .receive_bitrate
                .map(json_bitrate)
                .unwrap_or(json::Value::Null),
        ),
        (
            "transmitBitrate",
            station
                .transmit_bitrate
                .map(json_bitrate)
                .unwrap_or(json::Value::Null),
        ),
    ])
}

fn json_bitrate(rate: wifi::Bitrate) -> json::Value {
    json::Value::object([
        ("megabitsPerSecond", json::Value::number(rate.mbps)),
        ("widthMHz", json::optional_number(rate.width_mhz)),
        ("mcs", json::optional_number(rate.mcs)),
        (
            "spatialStreams",
            json::optional_number(rate.spatial_streams),
        ),
        ("encoding", json::optional_string(rate.encoding)),
    ])
}

fn format_bitrate(rate: &wifi::Bitrate) -> String {
    let encoding = rate
        .encoding
        .map(|encoding| format!(" {encoding}"))
        .unwrap_or_default();
    let mcs = rate
        .mcs
        .map(|mcs| format!(" MCS {mcs}"))
        .unwrap_or_default();
    let streams = rate
        .spatial_streams
        .map(|streams| format!(" {streams} stream(s)"))
        .unwrap_or_default();
    let width = rate
        .width_mhz
        .map(|width| format!(" {width} MHz"))
        .unwrap_or_default();
    format!("{:.1} Mbit/s{encoding}{mcs}{streams}{width}", rate.mbps)
}

fn format_socket_endpoint(endpoint: std::net::SocketAddr) -> String {
    if endpoint.ip().is_unspecified() {
        if endpoint.port() == 0 {
            "*".into()
        } else {
            format!("*:{}", endpoint.port())
        }
    } else {
        endpoint.to_string()
    }
}

fn user_names() -> HashMap<u32, String> {
    let Ok(contents) = fs::read_to_string("/etc/passwd") else {
        return HashMap::new();
    };
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.to_owned();
            let _password = fields.next()?;
            let uid = fields.next()?.parse().ok()?;
            Some((uid, name))
        })
        .collect()
}

fn print_value(label: &str, value: Option<String>) {
    if let Some(value) = value {
        println!("  {label}: {value}");
    }
}

fn print_indented_value(label: &str, value: Option<String>) {
    if let Some(value) = value {
        println!("    {label}: {value}");
    }
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn read_number(path: impl AsRef<Path>) -> Option<u64> {
    read_trimmed(path)?.parse().ok()
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn parse_ipv4_hex(value: &str) -> Option<Ipv4Addr> {
    let value = u32::from_str_radix(value, 16).ok()?;
    Some(Ipv4Addr::from(value.to_le_bytes()))
}

fn parse_ipv6_hex(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    Some(Ipv6Addr::from(u128::from_str_radix(value, 16).ok()?))
}

#[derive(Debug)]
struct Ipv6Address {
    interface: String,
    address: Ipv6Addr,
    prefix: u8,
    scope: u8,
}

fn ipv6_addresses() -> Vec<Ipv6Address> {
    let Ok(contents) = fs::read_to_string(PROC_NET_IF_INET6) else {
        return Vec::new();
    };

    contents
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            Some(Ipv6Address {
                address: parse_ipv6_hex(fields.first()?)?,
                prefix: u8::from_str_radix(fields.get(2)?, 16).ok()?,
                scope: u8::from_str_radix(fields.get(3)?, 16).ok()?,
                interface: (*fields.get(5)?).into(),
            })
        })
        .collect()
}

fn ipv6_scope(scope: u8) -> &'static str {
    match scope {
        0x00 => "global",
        0x10 => "host",
        0x20 => "link",
        0x40 => "site",
        _ => "unknown scope",
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddr {
    family: c_ushort,
    data: [c_char; 14],
}

#[repr(C)]
union IfreqData {
    address: SockAddr,
    padding: [u8; 24],
    alignment: u64,
}

#[repr(C)]
struct Ifreq {
    name: [c_char; 16],
    data: IfreqData,
}

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

fn ipv4_address(interface: &str) -> Option<(Ipv4Addr, u32)> {
    const SIOCGIFADDR: c_ulong = 0x8915;
    const SIOCGIFNETMASK: c_ulong = 0x891b;

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    let address = ioctl_ipv4(socket.as_raw_fd(), interface, SIOCGIFADDR)?;
    let mask = ioctl_ipv4(socket.as_raw_fd(), interface, SIOCGIFNETMASK)?;
    Some((address, u32::from(mask).count_ones()))
}

fn ioctl_ipv4(fd: c_int, interface: &str, request: c_ulong) -> Option<Ipv4Addr> {
    let mut ifreq = Ifreq {
        name: [0; 16],
        data: IfreqData { padding: [0; 24] },
    };
    if interface.len() >= ifreq.name.len() {
        return None;
    }
    for (target, source) in ifreq.name.iter_mut().zip(interface.bytes()) {
        *target = source as c_char;
    }

    // SAFETY: ifreq points to writable storage with the Linux ifreq layout. The
    // interface name is NUL-terminated and the UDP socket remains open for the call.
    if unsafe { ioctl(fd, request, &mut ifreq) } < 0 {
        return None;
    }
    // SAFETY: a successful SIOCGIFADDR/SIOCGIFNETMASK call initialized address.
    let address = unsafe { ifreq.data.address };
    let octets = [
        address.data[2] as u8,
        address.data[3] as u8,
        address.data[4] as u8,
        address.data[5] as u8,
    ];
    Some(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_ipv4_byte_order() {
        assert_eq!(
            parse_ipv4_hex("0102A8C0"),
            Some(Ipv4Addr::new(192, 168, 2, 1))
        );
        assert_eq!(parse_ipv4_hex("00000000"), Some(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn parses_proc_ipv6_address() {
        assert_eq!(
            parse_ipv6_hex("fe800000000000000000000000000001"),
            Some("fe80::1".parse().unwrap())
        );
    }

    #[test]
    fn formats_byte_counts() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn derives_administrative_state_from_interface_flags() {
        assert_eq!(administrative_state("0x9"), Some("up"));
        assert_eq!(administrative_state("0x8"), Some("down"));
        assert_eq!(administrative_state("invalid"), None);
    }

    #[test]
    fn parses_ipv4_scan_cidr() {
        assert_eq!(
            parse_ipv4_cidr("192.168.1.42/24").unwrap(),
            (Ipv4Addr::new(192, 168, 1, 42), 24)
        );
        assert!(parse_ipv4_cidr("192.168.1.0/33").is_err());
        assert!(parse_ipv4_cidr("example/24").is_err());
    }

    #[test]
    fn avoids_local_addresses_for_cidr_route_selection() {
        let local_addresses =
            HashSet::from([Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 53)]);
        assert_eq!(
            first_non_local_scan_address(
                Ipv4Addr::new(10, 0, 0, 0),
                Ipv4Addr::new(10, 0, 0, 255),
                24,
                &local_addresses,
            ),
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(
            first_non_local_scan_address(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 1),
                32,
                &local_addresses,
            ),
            None
        );
    }

    #[test]
    fn parses_scan_controls() {
        let arguments = [
            "enp5s0".to_owned(),
            "--wait".to_owned(),
            "500".to_owned(),
            "--retries".to_owned(),
            "2".to_owned(),
            "--exclude".to_owned(),
            "10.0.0.1".to_owned(),
            "--filter".to_owned(),
            "changed".to_owned(),
            "--no-resolve".to_owned(),
        ];
        let parsed = parse_scan_arguments(&arguments).unwrap();
        assert_eq!(parsed.selection.as_deref(), Some("enp5s0"));
        assert_eq!(parsed.wait_ms, 500);
        assert_eq!(parsed.retries, 2);
        assert_eq!(parsed.filter, Some(ScanFilter::Changed));
        assert!(!parsed.resolve_names);
        assert!(parsed.excluded.contains(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(parse_scan_arguments(&["--retries".into(), "0".into()]).is_err());
        assert!(parse_scan_arguments(&["--filter".into()]).is_err());
        assert!(parse_scan_arguments(&["--filter".into(), "unknown".into()]).is_err());
    }

    #[test]
    fn parses_and_matches_watch_filters() {
        assert_eq!(
            parse_watch_arguments(&["--filter".into(), "route".into()]).unwrap(),
            Some(WatchFilter::Route)
        );
        assert_eq!(parse_watch_arguments(&[]).unwrap(), None);
        assert!(parse_watch_arguments(&["--filter".into()]).is_err());
        assert!(parse_watch_arguments(&["--filter".into(), "unknown".into()]).is_err());

        let event = netlink::NetworkEvent::Link {
            removed: false,
            interface_index: 2,
            name: Some("eth0".into()),
            up: true,
        };
        assert!(WatchFilter::Link.matches(&event));
        assert!(!WatchFilter::Route.matches(&event));
    }

    #[test]
    fn parses_probe_controls() {
        let parsed = parse_probe_arguments(&[
            "example.test".into(),
            "22,80,443,8000-8002".into(),
            "--filter".into(),
            "closed".into(),
            "--timeout".into(),
            "750".into(),
        ])
        .unwrap();
        assert_eq!(parsed.host, "example.test");
        assert_eq!(parsed.ports, [22, 80, 443, 8000, 8001, 8002]);
        assert_eq!(parsed.filter, Some(TcpProbeStatus::ConnectionRefused));
        assert_eq!(parsed.timeout_ms, 750);
        assert_eq!(parse_probe_ports("443,22,443").unwrap(), [22, 443]);
        assert_eq!(
            (
                parse_probe_arguments(&["host".into()]).unwrap().ports,
                parse_probe_arguments(&["host".into()]).unwrap().filter,
            ),
            (vec![443], None)
        );
        assert!(parse_probe_arguments(&["host".into(), "--timeout".into(), "20".into()]).is_err());
        assert!(parse_probe_arguments(&["host".into(), "0".into()]).is_err());
        assert!(parse_probe_arguments(&["host".into(), "90-80".into()]).is_err());
        assert!(parse_probe_arguments(&["host".into(), "22,,80".into()]).is_err());
        assert!(parse_probe_arguments(&["host".into(), "1-4097".into()]).is_err());
        assert!(parse_probe_arguments(&["host".into(), "--filter".into()]).is_err());
        assert!(
            parse_probe_arguments(&["host".into(), "--filter".into(), "unknown".into()]).is_err()
        );
    }

    #[test]
    fn parses_traffic_controls() {
        let parsed = parse_traffic_arguments(&[
            "eth0".into(),
            "--interval".into(),
            "250".into(),
            "--watch".into(),
        ])
        .unwrap();
        assert_eq!(parsed.0.as_deref(), Some("eth0"));
        assert_eq!(parsed.1, std::time::Duration::from_millis(250));
        assert!(parsed.2);
        assert_eq!(traffic_sample_line_count(0), 1);
        assert_eq!(traffic_sample_line_count(2), 7);
        assert!(parse_traffic_arguments(&["--interval".into(), "50".into()]).is_err());
    }

    #[test]
    fn selects_lowest_metric_default_route() {
        let routes = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                      eth1\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n\
                      eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(
            parse_default_ipv4_route(routes),
            Some(DefaultIpv4Route {
                interface: "eth0".into(),
                gateway: Ipv4Addr::new(192, 168, 0, 1),
                metric: 100,
            })
        );
    }

    #[test]
    fn formats_wildcard_socket_endpoints() {
        assert_eq!(
            format_socket_endpoint("0.0.0.0:53".parse().unwrap()),
            "*:53"
        );
        assert_eq!(format_socket_endpoint("0.0.0.0:0".parse().unwrap()), "*");
        assert_eq!(format_socket_endpoint("[::]:53".parse().unwrap()), "*:53");
        assert_eq!(format_socket_endpoint("[::]:0".parse().unwrap()), "*");
        assert_eq!(
            format_socket_endpoint("127.0.0.1:8080".parse().unwrap()),
            "127.0.0.1:8080"
        );
    }
}
