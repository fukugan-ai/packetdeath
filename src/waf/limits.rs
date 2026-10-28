//! Stage 11: who is asking, how often, and who has earned a ban.
//!
//! `docs/design.md` "段階11 WAF". Everything here takes the time as an argument
//! (milliseconds on any monotone clock), so the tests need no sleep.
//!
//! Every table is bounded by `cap`. When one is full, the oldest eighth is
//! dropped before a new entry goes in, so an attacker who rotates source
//! addresses cannot make the process grow.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::iplist::IpList;

/// Why a limit setting could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum LimitError {
    /// `--rate` is not `<count>/<seconds>` with both positive.
    Rate(String),
}

impl std::fmt::Display for LimitError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitError::Rate(text) => write!(out, "--rate {text:?} is not <count>/<seconds>"),
        }
    }
}

impl std::error::Error for LimitError {}

/// `count` requests per `per_ms` milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateSpec {
    pub count: u32,
    pub per_ms: u64,
}

/// Read `5/1` (five per second) or `100/60`.
pub fn parse_rate(text: &str) -> Result<RateSpec, LimitError> {
    let bad = || LimitError::Rate(text.to_owned());
    let Some((count, seconds)) = text.split_once('/') else {
        return Err(bad());
    };
    let (Ok(count), Ok(seconds)) = (count.trim().parse::<u32>(), seconds.trim().parse::<u64>())
    else {
        return Err(bad());
    };
    let Some(per_ms) = seconds.checked_mul(1000) else {
        return Err(bad());
    };
    if count == 0 || per_ms == 0 {
        return Err(bad());
    }
    Ok(RateSpec { count, per_ms })
}

/// What the limiter decided about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Take {
    Allowed,
    /// Over the rate; try again after this many seconds.
    Limited { retry_after_secs: u64 },
}

/// Limits and bans, per source address.
#[derive(Debug, Clone, Copy)]
pub struct LimitConfig {
    pub rate: Option<RateSpec>,
    /// Blocks inside `ban_window_ms` that earn a ban. Zero means no bans.
    pub ban_after: u32,
    pub ban_window_ms: u64,
    pub ban_ttl_ms: u64,
    /// Entries kept in each table.
    pub cap: usize,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    seen_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct Strikes {
    count: u32,
    first_ms: u64,
}

/// The state behind `--rate`, `--ban-after` and `--ban-ttl`.
#[derive(Debug)]
pub struct Limiter {
    cfg: LimitConfig,
    buckets: HashMap<IpAddr, Bucket>,
    strikes: HashMap<IpAddr, Strikes>,
    /// Address to the time its ban ends.
    bans: HashMap<IpAddr, u64>,
}

/// Drop the oldest eighth of a table whose entries carry a time.
fn make_room<V: Copy>(table: &mut HashMap<IpAddr, V>, cap: usize, time_of: impl Fn(&V) -> u64) {
    if table.len() < cap {
        return;
    }
    let mut ages: Vec<(u64, IpAddr)> = table.iter().map(|(ip, v)| (time_of(v), *ip)).collect();
    ages.sort_unstable();
    let drop = (cap / 8).max(1);
    for (_, ip) in ages.into_iter().take(drop) {
        table.remove(&ip);
    }
}

impl Limiter {
    pub fn new(cfg: LimitConfig) -> Limiter {
        Limiter {
            cfg,
            buckets: HashMap::new(),
            strikes: HashMap::new(),
            bans: HashMap::new(),
        }
    }

    /// Whether `ip` is banned at `now_ms`. An ended ban is removed.
    pub fn is_banned(&mut self, ip: IpAddr, now_ms: u64) -> bool {
        let banned = self.bans.get(&ip).is_some_and(|&until| now_ms < until);
        if !banned {
            self.bans.remove(&ip);
        }
        banned
    }

    /// Spend one token for `ip`.
    pub fn take(&mut self, ip: IpAddr, now_ms: u64) -> Take {
        let Some(rate) = self.cfg.rate else {
            return Take::Allowed;
        };
        let capacity = f64::from(rate.count);
        let per_ms = capacity / rate.per_ms as f64;
        if !self.buckets.contains_key(&ip) {
            make_room(&mut self.buckets, self.cfg.cap, |b| b.seen_ms);
        }
        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            tokens: capacity,
            seen_ms: now_ms,
        });
        let idle = now_ms.saturating_sub(bucket.seen_ms) as f64;
        bucket.tokens = (bucket.tokens + idle * per_ms).min(capacity);
        bucket.seen_ms = now_ms;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Take::Allowed;
        }
        let wait_ms = ((1.0 - bucket.tokens) / per_ms).ceil() as u64;
        Take::Limited {
            retry_after_secs: wait_ms.div_ceil(1000).max(1),
        }
    }

    /// Count one block against `ip`. Returns true when this block earned a ban.
    pub fn record_block(&mut self, ip: IpAddr, now_ms: u64) -> bool {
        if self.cfg.ban_after == 0 {
            return false;
        }
        if !self.strikes.contains_key(&ip) {
            make_room(&mut self.strikes, self.cfg.cap, |s| s.first_ms);
        }
        let window = self.cfg.ban_window_ms;
        let strikes = self.strikes.entry(ip).or_insert(Strikes {
            count: 0,
            first_ms: now_ms,
        });
        if now_ms.saturating_sub(strikes.first_ms) > window {
            *strikes = Strikes {
                count: 0,
                first_ms: now_ms,
            };
        }
        strikes.count += 1;
        if strikes.count < self.cfg.ban_after {
            return false;
        }
        self.strikes.remove(&ip);
        make_room(&mut self.bans, self.cfg.cap, |until| *until);
        self.bans
            .insert(ip, now_ms.saturating_add(self.cfg.ban_ttl_ms));
        true
    }

    pub fn tracked(&self) -> usize {
        self.buckets.len() + self.strikes.len() + self.bans.len()
    }
}

/// The address a request is counted against.
///
/// With no trusted front, or a peer that is not one, it is the peer. With a
/// trusted peer, it is the first address from the right of `X-Forwarded-For`
/// that is not itself trusted. A header that is not a list of addresses is not
/// believed, and the peer is used.
pub fn client_ip(peer: IpAddr, forwarded: Option<&str>, trusted: &IpList) -> IpAddr {
    if trusted.is_empty() || !trusted.contains(&peer) {
        return peer;
    }
    let Some(header) = forwarded else {
        return peer;
    };
    let mut leftmost = peer;
    for part in header.rsplit(',') {
        let Ok(ip) = part.trim().parse::<IpAddr>() else {
            return peer;
        };
        if !trusted.contains(&ip) {
            return ip;
        }
        leftmost = ip;
    }
    leftmost
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ip(text: &str) -> Result<IpAddr, std::net::AddrParseError> {
        text.parse()
    }

    fn cfg() -> LimitConfig {
        LimitConfig {
            rate: Some(RateSpec {
                count: 5,
                per_ms: 1000,
            }),
            ban_after: 3,
            ban_window_ms: 60_000,
            ban_ttl_ms: 10_000,
            cap: 16,
        }
    }

    #[test]
    fn a_rate_is_read() {
        assert_eq!(
            parse_rate("5/1"),
            Ok(RateSpec {
                count: 5,
                per_ms: 1000
            })
        );
        assert_eq!(
            parse_rate(" 100 / 60 "),
            Ok(RateSpec {
                count: 100,
                per_ms: 60_000
            })
        );
    }

    #[test]
    fn a_bad_rate_is_refused() {
        for text in ["", "5", "5/", "/1", "0/1", "5/0", "a/b", "5/-1", "-5/1"] {
            assert!(parse_rate(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn the_sixth_request_in_a_second_is_limited_and_one_second_later_it_recovers() -> TestResult {
        let mut limiter = Limiter::new(cfg());
        let a = ip("203.0.113.5")?;
        for _ in 0..5 {
            assert_eq!(limiter.take(a, 0), Take::Allowed);
        }
        assert_eq!(
            limiter.take(a, 0),
            Take::Limited {
                retry_after_secs: 1
            }
        );
        assert_eq!(limiter.take(a, 1000), Take::Allowed);
        Ok(())
    }

    #[test]
    fn one_source_does_not_spend_anothers_tokens() -> TestResult {
        let mut limiter = Limiter::new(cfg());
        let (a, b) = (ip("203.0.113.5")?, ip("203.0.113.6")?);
        for _ in 0..5 {
            limiter.take(a, 0);
        }
        assert!(matches!(limiter.take(a, 0), Take::Limited { .. }));
        assert_eq!(limiter.take(b, 0), Take::Allowed);
        Ok(())
    }

    #[test]
    fn without_a_rate_everything_is_allowed() -> TestResult {
        let mut limiter = Limiter::new(LimitConfig {
            rate: None,
            ..cfg()
        });
        for _ in 0..100 {
            assert_eq!(limiter.take(ip("203.0.113.5")?, 0), Take::Allowed);
        }
        Ok(())
    }

    #[test]
    fn a_slow_rate_asks_for_a_longer_wait() -> TestResult {
        let slow = LimitConfig {
            rate: Some(RateSpec {
                count: 1,
                per_ms: 60_000,
            }),
            ..cfg()
        };
        let mut limiter = Limiter::new(slow);
        let a = ip("203.0.113.5")?;
        assert_eq!(limiter.take(a, 0), Take::Allowed);
        assert_eq!(
            limiter.take(a, 0),
            Take::Limited {
                retry_after_secs: 60
            }
        );
        Ok(())
    }

    #[test]
    fn three_blocks_in_the_window_ban_and_the_ban_ends() -> TestResult {
        let mut limiter = Limiter::new(cfg());
        let a = ip("203.0.113.5")?;
        assert!(!limiter.record_block(a, 0));
        assert!(!limiter.record_block(a, 1000));
        assert!(limiter.record_block(a, 2000));
        assert!(limiter.is_banned(a, 2001));
        assert!(limiter.is_banned(a, 11_999));
        assert!(!limiter.is_banned(a, 12_000));
        assert!(!limiter.is_banned(a, 12_001));
        Ok(())
    }

    #[test]
    fn blocks_spread_past_the_window_do_not_ban() -> TestResult {
        let mut limiter = Limiter::new(cfg());
        let a = ip("203.0.113.5")?;
        assert!(!limiter.record_block(a, 0));
        assert!(!limiter.record_block(a, 61_000));
        assert!(!limiter.record_block(a, 122_000));
        assert!(!limiter.is_banned(a, 122_001));
        Ok(())
    }

    #[test]
    fn zero_means_no_bans() -> TestResult {
        let mut limiter = Limiter::new(LimitConfig {
            ban_after: 0,
            ..cfg()
        });
        let a = ip("203.0.113.5")?;
        for t in 0..10 {
            assert!(!limiter.record_block(a, t));
        }
        assert!(!limiter.is_banned(a, 11));
        Ok(())
    }

    #[test]
    fn the_tables_stay_inside_the_cap() {
        let mut limiter = Limiter::new(cfg());
        for n in 0..200u32 {
            let a = IpAddr::from([10, 0, (n / 256) as u8, (n % 256) as u8]);
            limiter.take(a, u64::from(n));
            limiter.record_block(a, u64::from(n));
        }
        assert!(limiter.buckets.len() <= 16, "{}", limiter.buckets.len());
        assert!(limiter.strikes.len() <= 16, "{}", limiter.strikes.len());
        assert!(limiter.tracked() <= 48);
    }

    #[test]
    fn the_oldest_entries_are_the_ones_dropped() {
        let mut limiter = Limiter::new(LimitConfig { cap: 8, ..cfg() });
        for n in 0..8u32 {
            limiter.take(IpAddr::from([10, 0, 0, n as u8]), u64::from(n));
        }
        limiter.take(IpAddr::from([10, 0, 1, 1]), 100);
        assert!(!limiter.buckets.contains_key(&IpAddr::from([10, 0, 0, 0])));
        assert!(limiter.buckets.contains_key(&IpAddr::from([10, 0, 0, 7])));
    }

    fn trusted(text: &str) -> IpList {
        IpList::parse(text)
    }

    #[test]
    fn the_peer_is_used_when_no_front_is_trusted() -> TestResult {
        let peer = ip("198.51.100.9")?;
        assert_eq!(client_ip(peer, Some("203.0.113.5"), &IpList::empty()), peer);
        Ok(())
    }

    #[test]
    fn a_header_from_an_untrusted_peer_is_ignored() -> TestResult {
        let peer = ip("198.51.100.9")?;
        let list = trusted("10.0.0.0/8\n");
        assert_eq!(client_ip(peer, Some("203.0.113.5"), &list), peer);
        Ok(())
    }

    #[test]
    fn a_trusted_front_gives_the_first_untrusted_address_from_the_right() -> TestResult {
        let list = trusted("10.0.0.0/8\n");
        let front = ip("10.0.0.2")?;
        let got = client_ip(front, Some("1.2.3.4, 203.0.113.5, 10.0.0.9"), &list);
        assert_eq!(got, ip("203.0.113.5")?);
        Ok(())
    }

    #[test]
    fn a_forged_leftmost_entry_does_not_count() -> TestResult {
        let list = trusted("10.0.0.0/8\n");
        let got = client_ip(ip("10.0.0.2")?, Some("6.6.6.6, 203.0.113.5"), &list);
        assert_eq!(got, ip("203.0.113.5")?);
        Ok(())
    }

    #[test]
    fn an_all_trusted_chain_gives_the_leftmost() -> TestResult {
        let list = trusted("10.0.0.0/8\n");
        let got = client_ip(ip("10.0.0.2")?, Some("10.1.1.1, 10.2.2.2"), &list);
        assert_eq!(got, ip("10.1.1.1")?);
        Ok(())
    }

    #[test]
    fn a_missing_or_garbled_header_gives_the_peer() -> TestResult {
        let list = trusted("10.0.0.0/8\n");
        let front = ip("10.0.0.2")?;
        assert_eq!(client_ip(front, None, &list), front);
        assert_eq!(client_ip(front, Some("not-an-address"), &list), front);
        assert_eq!(client_ip(front, Some("203.0.113.5, junk"), &list), front);
        assert_eq!(client_ip(front, Some(""), &list), front);
        Ok(())
    }
}
