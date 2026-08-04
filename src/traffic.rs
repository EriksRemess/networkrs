//! Passive interface-rate sampling from sysfs counters.
//!
//! A sample reads counters, sleeps for the requested interval, reads them again,
//! and reports saturating deltas. Counter resets therefore produce zero rather
//! than underflow. The call blocks for approximately the requested interval.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const SYS_CLASS_NET: &str = "/sys/class/net";

#[derive(Debug, Eq, PartialEq)]
struct Counters {
    bytes: u64,
    packets: u64,
    errors: u64,
    dropped: u64,
}

/// Receive or transmit rates and counter deltas over one sample interval.
#[derive(Debug, Eq, PartialEq)]
pub struct DirectionRate {
    /// Payload bytes per second, rounded down to an integer.
    pub bytes_per_second: u64,
    /// Packets per second, rounded down to an integer.
    pub packets_per_second: u64,
    /// Error-counter increase during the interval.
    pub errors: u64,
    /// Dropped-packet-counter increase during the interval.
    pub dropped: u64,
}

/// Rates for both directions of one interface.
#[derive(Debug, Eq, PartialEq)]
pub struct InterfaceRate {
    /// Kernel interface name.
    pub interface: String,
    /// Receive-side rate and deltas.
    pub received: DirectionRate,
    /// Transmit-side rate and deltas.
    pub transmitted: DirectionRate,
}

/// Complete result from one sampling interval.
pub struct Sample {
    /// Actual elapsed time between the two counter snapshots.
    pub elapsed: Duration,
    /// Rates for the selected interfaces, ordered by interface name.
    pub interfaces: Vec<InterfaceRate>,
}

/// Samples all interfaces, or one selected interface, over `interval`.
///
/// This is passive but blocking. It returns [`io::ErrorKind::NotFound`] when a
/// selected interface does not exist or no interfaces are visible.
pub fn sample(selection: Option<&str>, interval: Duration) -> io::Result<Sample> {
    let paths = interface_paths(selection)?;
    let before = read_all(&paths)?;
    let started = Instant::now();
    thread::sleep(interval);
    let elapsed = started.elapsed();
    let after = read_all(&paths)?;

    let interfaces = paths
        .iter()
        .zip(before.iter().zip(after.iter()))
        .filter_map(|(path, (before, after))| {
            let interface = path.file_name()?.to_str()?.to_owned();
            Some(InterfaceRate {
                interface,
                received: rate(&before.0, &after.0, elapsed),
                transmitted: rate(&before.1, &after.1, elapsed),
            })
        })
        .collect();

    Ok(Sample {
        elapsed,
        interfaces,
    })
}

fn interface_paths(selection: Option<&str>) -> io::Result<Vec<PathBuf>> {
    if let Some(interface) = selection {
        let path = Path::new(SYS_CLASS_NET).join(interface);
        if !path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {interface} does not exist"),
            ));
        }
        return Ok(vec![path]);
    }

    let mut paths = fs::read_dir(SYS_CLASS_NET)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no network interfaces found",
        ));
    }
    Ok(paths)
}

fn read_all(paths: &[PathBuf]) -> io::Result<Vec<(Counters, Counters)>> {
    paths
        .iter()
        .map(|path| Ok((read_direction(path, "rx")?, read_direction(path, "tx")?)))
        .collect()
}

fn read_direction(path: &Path, direction: &str) -> io::Result<Counters> {
    let statistics = path.join("statistics");
    Ok(Counters {
        bytes: read_counter(&statistics.join(format!("{direction}_bytes")))?,
        packets: read_counter(&statistics.join(format!("{direction}_packets")))?,
        errors: read_counter(&statistics.join(format!("{direction}_errors")))?,
        dropped: read_counter(&statistics.join(format!("{direction}_dropped")))?,
    })
}

fn read_counter(path: &Path) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn rate(before: &Counters, after: &Counters, elapsed: Duration) -> DirectionRate {
    DirectionRate {
        bytes_per_second: per_second(after.bytes.saturating_sub(before.bytes), elapsed),
        packets_per_second: per_second(after.packets.saturating_sub(before.packets), elapsed),
        errors: after.errors.saturating_sub(before.errors),
        dropped: after.dropped.saturating_sub(before.dropped),
    }
}

fn per_second(delta: u64, elapsed: Duration) -> u64 {
    let nanos = elapsed.as_nanos();
    if nanos == 0 {
        return 0;
    }
    (u128::from(delta) * 1_000_000_000 / nanos)
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_rates_and_counter_deltas() {
        let before = Counters {
            bytes: 100,
            packets: 20,
            errors: 2,
            dropped: 4,
        };
        let after = Counters {
            bytes: 2_100,
            packets: 120,
            errors: 3,
            dropped: 6,
        };
        assert_eq!(
            rate(&before, &after, Duration::from_millis(500)),
            DirectionRate {
                bytes_per_second: 4_000,
                packets_per_second: 200,
                errors: 1,
                dropped: 2,
            }
        );
    }

    #[test]
    fn tolerates_counter_resets() {
        let before = Counters {
            bytes: 10,
            packets: 10,
            errors: 10,
            dropped: 10,
        };
        let after = Counters {
            bytes: 1,
            packets: 1,
            errors: 1,
            dropped: 1,
        };
        assert_eq!(
            rate(&before, &after, Duration::from_secs(1)),
            DirectionRate {
                bytes_per_second: 0,
                packets_per_second: 0,
                errors: 0,
                dropped: 0,
            }
        );
    }
}
