# Architecture and maintenance guide

This document explains how `networkrs` is organized, why its low-level code is
written the way it is, and how to extend it without accidentally changing the
CLI or library contracts.

## Design constraints

The project has three deliberate constraints:

1. It uses only the Rust standard library.
2. It obtains network information from Linux kernel and system interfaces
   directly, without invoking command-line utilities.
3. Passive inspection is the default. Code that sends packets must remain
   behind an explicitly active API or CLI command.

These constraints explain the small C-ABI declarations and hand-written Linux
UAPI structures. Adding a dependency or subprocess may be easier, but would be
a design change rather than an implementation detail.

## Data flow

```text
Linux kernel or system file
        |
        v
transport module (netlink, generic netlink, procfs, sysfs, ioctl)
        |
        v
validated parser (length, type, alignment, byte order)
        |
        v
public typed record in the networkrs library
        |
        +--------------------+
        |                    |
        v                    v
CLI text renderer       CLI JSON renderer
```

Kernel-facing modules return data and `io::Error`; they do not print. The binary
owns argument parsing, presentation, and exit-status policy. Keep this boundary
when adding library functionality.

## Module map

| Module | Responsibility | Main source |
| --- | --- | --- |
| `netlink` | Links, IPv4/IPv6 addresses, routes, rules, neighbors, route lookup, and change events | route netlink |
| `generic_netlink` | Internal generic-netlink family discovery and message framing | `NETLINK_GENERIC` |
| `ethtool` | Driver, modes, features, EEE, and standard statistics | ethtool generic-netlink family and sysfs |
| `wifi` | Wi-Fi interface, association, and station information | nl80211 generic-netlink family |
| `sock_diag` | Transport queues, timers, and TCP metrics | `NETLINK_SOCK_DIAG` |
| `sockets` | Compatible socket table and process ownership view | `/proc/net` and `/proc/<pid>/fd` |
| `scanner` | Explicit IPv4 neighbor discovery | UDP sends followed by `RTM_GETNEIGH` |
| `ping` | Explicit ICMP echo measurements | Linux IPv4 ping socket |
| `traffic` | Counter-delta rate sampling | `/sys/class/net/*/statistics` |
| `resolver` | Forward/reverse names and resolver configuration | libc NSS and `/etc/resolv.conf` |
| `oui` | Best-effort installed MAC vendor database | local IEEE OUI files |

`src/main.rs` is the CLI adapter. `src/json.rs` is intentionally binary-private:
the library returns typed Rust values and does not prescribe a serialization
format or pull in a serialization dependency.

## Linux UAPI conventions

The checked-out kernel source is the reference used while implementing the
wire formats. Relevant headers include:

- `include/uapi/linux/netlink.h`
- `include/uapi/linux/rtnetlink.h`
- `include/uapi/linux/if_link.h`
- `include/uapi/linux/if_addr.h`
- `include/uapi/linux/neighbour.h`
- `include/uapi/linux/fib_rules.h`
- `include/uapi/linux/genetlink.h`
- `include/uapi/linux/ethtool_netlink.h`
- `include/uapi/linux/nl80211.h`
- `include/uapi/linux/inet_diag.h`
- `include/uapi/linux/tcp.h`

Constants are copied by name rather than generated at build time so builds do
not require kernel headers. When adding or changing one, preserve the UAPI name
and verify its numeric value against the kernel source.

Netlink messages use native-endian fixed-width fields unless a protocol field
explicitly specifies network byte order. Attributes and messages are aligned to
four-byte boundaries. A parser must validate the declared length before reading
a header or payload and must mask attribute flag bits before comparing its type.
Never cast an arbitrary byte pointer to a Rust reference: validated payloads are
read with `read_unaligned` into owned values.

The C-layout structures are protected by layout tests. If a structure changes,
compare it to the matching UAPI definition before updating a test expectation.

## Error and availability policy

Public APIs return `io::Result`. The original OS error is retained where useful
so callers can distinguish permission, unsupported-kernel, and malformed-data
conditions.

An absent optional attribute becomes `None`; it is not automatically an error.
Drivers and kernel configurations legitimately omit fields. For example,
socket diagnostics require `CONFIG_INET_DIAG`; the CLI falls back to procfs,
while the library exposes the diagnostic error to its caller.

Procfs process ownership is best effort. Processes can exit, descriptors can
change, and permission boundaries can hide entries while a scan is in progress.
The result is a snapshot, not an atomic system-wide transaction.

## Active operations

The following library calls generate traffic:

- `scanner::scan` sends UDP datagrams to trigger kernel ARP resolution.
- `ping::echo` sends ICMP echo requests.

The CLI also performs TCP connection attempts in `probe` and `check --active`.
Do not add active behavior to passive snapshot functions. New active APIs must
say what they send, how many targets they can reach, and how they bound time and
resource use.

## Adding a kernel attribute

1. Find the named constant and payload type in the current Linux UAPI header.
2. Add the constant near the related constants, retaining the kernel name.
3. Parse it only after the containing message and attribute lengths are valid.
4. Decide whether absence means `None`, a default, or an unsupported operation.
5. Add the field to the public record with units and absence semantics in its
   Rustdoc.
6. Add a byte-level fixture test, including truncated input where relevant.
7. Add text and JSON rendering in the CLI if the field should be user-visible.
8. Test on the host kernel, remembering that one driver is not proof of support
   across all drivers.

## Tests

Tests fall into three groups:

- Layout tests pin C structures to the Linux ABI sizes expected by the code.
- Parser fixtures describe representative netlink/procfs messages without
  requiring privileges or a particular host configuration.
- `tests/library_api.rs` compiles from an external-crate perspective and guards
  the intended reusable surface.

Host-kernel smoke tests are still valuable for generic-netlink families and
driver-specific behavior, but they should not become unit tests: availability
depends on kernel configuration, hardware, and permissions.

Before handing off a change, run:

```console
cargo fmt -- --check
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps --document-private-items
cargo build --release
```

## Current structural debt

The library/CLI boundary is clean, but `src/main.rs` still combines command
execution with text and JSON rendering. Some operations therefore have parallel
text and JSON code paths. When changing one, update both and add a regression
test. A future refactor should introduce CLI-facing result records and render
the same record to either format; that can be done without changing the public
kernel-facing modules.
