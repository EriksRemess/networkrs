# JSON output contract

`--json` may appear anywhere in the CLI argument list. Snapshot commands write
exactly one compact JSON value followed by a newline. Streaming commands write
newline-delimited JSON (NDJSON): every line is independently valid JSON.

The project is currently version 0.1, so consumers should select fields by name
and tolerate new fields. Removing or changing the meaning/type of an existing
field should be treated as an API change.

## Conventions

- Field names use `camelCase`.
- Addresses and link-layer addresses are strings.
- IP address, route, rule, neighbor, and socket records identify their address
  family as `ipv4` or `ipv6` where applicable.
- Interface references include a numeric `interfaceIndex`; some records also
  include the current interface name for convenience.
- Durations name their unit, normally `Milliseconds` or `Microseconds`.
- Rates use `bytesPerSecond` and `packetsPerSecond`.
- Counters are JSON integers. They can exceed JavaScript's exact integer range;
  consumers that require exact 64-bit values must use a capable JSON decoder.
- `null` means the kernel, driver, procfs, or sysfs source did not provide the
  field. It is different from zero, `false`, and an empty string.
- Empty arrays mean the query succeeded but produced no matching values, or an
  optional driver operation supplied no values. A top-level command error is
  written to stderr and returns status 2 rather than producing an error object.

## Snapshot shapes

| Command | Top-level shape | Contents |
| --- | --- | --- |
| `all` | object | `system`, `interfaces`, `addresses`, `routes`, `rules`, `neighbors`, `dns` |
| `interfaces` | array | sysfs counters plus a nested `link` object |
| `links` | array | route-netlink link records |
| `hardware` | array | ethtool device records |
| `addresses` | array | IPv4 and IPv6 address records |
| `routes` | array | IPv4 and IPv6 routes from all tables |
| `rules` | array | IPv4 and IPv6 policy rules |
| `route` | object | kernel-selected route to one destination |
| `neighbors` | array | IPv4 and IPv6 neighbor records |
| `scan` | object | `networks`, `neighbors`, changed count, elapsed time |
| `check` | object | active flag, health result, warning count, check records |
| `probe` | object | resolved destination, route, per-port reachability, result and timing |
| `sockets` | object | diagnostic availability/error and socket array |
| `traffic` | object | elapsed time and per-interface direction rates |
| `wifi` | array | nl80211 interface and station records |
| `dns` | object | resolver path and parsed directives |
| `--version` | object | `version` string |
| `help` | object | `usage` string |

The `all` snapshot intentionally contains passive configuration only. Detailed
hardware, Wi-Fi, socket, and sampled-rate queries remain explicit commands.

## Neighbor records

Neighbor objects contain the address, link address, interface identity, NUD
state, flags, protocol, type, probe/cache metadata, reference count, and master
index. Scan results append:

- `name`: best-effort NSS reverse name
- `vendor`: installed-OUI lookup or `private/randomized`
- `changed`: whether the address/link-address pair changed during this scan

## Socket diagnostics

The `sockets` object always contains `diagnosticsAvailable` and
`diagnosticError`. When `CONFIG_INET_DIAG` is unavailable, the socket list still
comes from procfs and diagnostic-only fields are `null`. A non-null `tcp` object
contains RTT/RTO values in microseconds, MSS and PMTU in bytes, and congestion
window/retransmission counters.

## Health and probe statuses

`check` exits with status 0 when `healthy` is true, 1 when warnings exist, and 2
when the operation cannot be performed. Individual check records use statuses
such as `ok`, `warning`, `reached`, `skipped`, and `not-applicable`.

For a single selected port, `probe` retains the scalar `port`, `status`, `error`,
and `elapsedMilliseconds` fields. A multi-port probe replaces those scalar
result fields with a `ports` array; each entry contains `port`, `status`, `open`,
`reachable`, `error`, and `elapsedMilliseconds`. The top-level elapsed value is
the wall-clock duration of the bounded concurrent scan.

`probe` exits with status 0 when any selected port connects or explicitly
refuses the connection. Refusal demonstrates that the destination host was
reached. It returns status 1 when every port fails for another reason. Argument,
resolution, and route lookup errors return status 2.

## Streaming records

`traffic --watch --json` repeats the same object emitted by a one-shot traffic
sample. Each interval produces one line.

`watch --json` emits objects with:

- `event`: `added`, `changed`, or `removed`
- `object`: `link`, `address`, `route`, or `neighbor`
- object-specific identity and data

Consumers must not assume that the first event is an initial snapshot. Run a
snapshot command first when initial state is required, then consume the event
stream to track later changes. Netlink multicast delivery can overrun if a
consumer blocks for too long; the command exits with an error rather than
silently pretending the stream remained complete.
