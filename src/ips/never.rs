//! Stage 12: destinations the IPS never drops. `docs/design.md`
//! "段階12 IDS/IPS の業務水準化" (never-block).
//!
//! A policy that says `drop` cannot take the loopback, the gateway or the
//! resolver away from the host, whatever an alert claims. The protection is
//! built from pure pieces (`resolvers_of`, `gateways_of`) so tests need no
//! network; `Protected::detect` reads the live files once.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use crate::iplist::{parse_line, Cidr};

/// Why a destination is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    Special,
    Private,
    Host,
    Gateway,
    Resolver,
    Listed,
}

/// The set of destinations that are never dropped.
#[derive(Debug, Default)]
pub struct Protected {
    allow_private: bool,
    host: Vec<IpAddr>,
    gateways: Vec<IpAddr>,
    resolvers: Vec<IpAddr>,
    listed: Vec<Cidr>,
}

/// Addresses written in a `resolv.conf`: the `nameserver` lines.
pub fn resolvers_of(text: &str) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        if let Some(ip) = words.next().and_then(|w| w.parse::<IpAddr>().ok()) {
            found.push(ip);
        }
    }
    found
}

/// Default gateways in `/proc/net/route`: rows whose destination is 0.
pub fn gateways_of(text: &str) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for row in text.lines().skip(1) {
        let cols: Vec<&str> = row.split_whitespace().collect();
        let (Some(dest), Some(gate)) = (cols.get(1), cols.get(2)) else {
            continue;
        };
        if *dest != "00000000" {
            continue;
        }
        if let Ok(raw) = u32::from_str_radix(gate, 16) {
            // /proc/net/route prints the address as a little-endian hex word.
            found.push(IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())));
        }
    }
    found
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.to_bits() >> 121 == 0x7e,
    }
}

fn is_special(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || v6.to_bits() >> 118 == 0x3fa
        }
    }
}

impl Protected {
    pub fn new(allow_private: bool, host: Vec<IpAddr>) -> Self {
        Self {
            allow_private,
            host,
            ..Self::default()
        }
    }

    /// Read the resolvers and gateways from the files of this machine.
    pub fn detect(allow_private: bool, host: Vec<IpAddr>) -> Result<Self, String> {
        let resolv = std::fs::read_to_string(Path::new("/etc/resolv.conf"));
        let routes = std::fs::read_to_string(Path::new("/proc/net/route"));
        let resolv = resolv.map_err(|e| format!("/etc/resolv.conf: {e}"))?;
        let routes = routes.map_err(|e| format!("/proc/net/route: {e}"))?;
        Ok(Self::new(allow_private, host)
            .with_resolvers(resolvers_of(&resolv))
            .with_gateways(gateways_of(&routes)))
    }

    pub fn with_resolvers(mut self, resolvers: Vec<IpAddr>) -> Self {
        self.resolvers = resolvers;
        self
    }

    pub fn with_gateways(mut self, gateways: Vec<IpAddr>) -> Self {
        self.gateways = gateways;
        self
    }

    /// Replace the `--ips-never` list (one address or CIDR per line).
    pub fn with_listed(mut self, text: &str) -> Self {
        self.listed = text.lines().filter_map(parse_line).collect();
        self
    }

    /// The reason `ip` must not be dropped, or `None` when it may be.
    pub fn why(&self, ip: &IpAddr) -> Option<Why> {
        if is_special(ip) {
            return Some(Why::Special);
        }
        if self.host.contains(ip) {
            return Some(Why::Host);
        }
        if self.gateways.contains(ip) {
            return Some(Why::Gateway);
        }
        if self.resolvers.contains(ip) {
            return Some(Why::Resolver);
        }
        if self.listed.iter().any(|c| c.contains(ip)) {
            return Some(Why::Listed);
        }
        if !self.allow_private && is_private(ip) {
            return Some(Why::Private);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn special_addresses_are_always_protected() {
        let p = Protected::new(true, Vec::new());
        for ip in [v4(127, 0, 0, 1), v4(169, 254, 1, 1), v4(224, 0, 0, 1), v4(0, 0, 0, 0)] {
            assert_eq!(p.why(&ip), Some(Why::Special), "{ip}");
        }
        assert_eq!(p.why(&IpAddr::V6(Ipv6Addr::LOCALHOST)), Some(Why::Special));
    }

    #[test]
    fn private_is_protected_until_allowed_and_public_never() {
        let strict = Protected::new(false, Vec::new());
        assert_eq!(strict.why(&v4(192, 168, 1, 5)), Some(Why::Private));
        assert_eq!(strict.why(&v4(203, 0, 113, 9)), None);
        let open = Protected::new(true, Vec::new());
        assert_eq!(open.why(&v4(192, 168, 1, 5)), None);
    }

    #[test]
    fn allowing_private_keeps_host_gateway_resolver_and_list() {
        let p = Protected::new(true, vec![v4(192, 168, 1, 2)])
            .with_gateways(vec![v4(192, 168, 1, 1)])
            .with_resolvers(vec![v4(8, 8, 8, 8)])
            .with_listed("# keep\n203.0.113.0/24\n");
        assert_eq!(p.why(&v4(192, 168, 1, 2)), Some(Why::Host));
        assert_eq!(p.why(&v4(192, 168, 1, 1)), Some(Why::Gateway));
        assert_eq!(p.why(&v4(8, 8, 8, 8)), Some(Why::Resolver));
        assert_eq!(p.why(&v4(203, 0, 113, 77)), Some(Why::Listed));
        assert_eq!(p.why(&v4(192, 168, 1, 50)), None);
    }

    #[test]
    fn resolvers_and_gateways_are_read_from_their_files() {
        let resolv = "# c\nnameserver 10.0.0.2\nsearch x\nnameserver bad\nnameserver 1.1.1.1\n";
        assert_eq!(resolvers_of(resolv), vec![v4(10, 0, 0, 2), v4(1, 1, 1, 1)]);
        let route = "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\neth0\t0001A8C0\t00000000\t0001\n";
        assert_eq!(gateways_of(route), vec![v4(192, 168, 1, 1)]);
        assert!(gateways_of("").is_empty() && resolvers_of("").is_empty());
    }
}
