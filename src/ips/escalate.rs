//! Stage 12: staged escalation. `docs/design.md` "段階12 IDS/IPS の業務水準化".
//!
//! A rule `{"action":"escalate","count":5,"window":60,"ttl":900}` drops a
//! destination only when the same (source, destination, sid) alerts `count`
//! times inside `window` seconds. Until then the alert is only observed.
//! Time is passed in, so a test never sleeps. The table is bounded: when it is
//! full, the key whose latest alert is oldest makes room.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// One counted thing: who sent it, where it went, which signature.
pub type Key = (Option<IpAddr>, IpAddr, u64);

/// Alert times per key, newest last.
#[derive(Debug)]
pub struct Escalator {
    cap: usize,
    seen: HashMap<Key, VecDeque<u64>>,
}

impl Escalator {
    /// A table that holds at most `cap` keys (at least one).
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            seen: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Count an alert at `now` (seconds). Returns true when this alert is the
    /// `count`-th inside `window`; the key is then cleared, so the next
    /// escalation needs a fresh `count` alerts.
    pub fn record(&mut self, key: Key, now: u64, count: u32, window: u64) -> bool {
        if !self.seen.contains_key(&key) && self.seen.len() >= self.cap {
            self.make_room();
        }
        let times = self.seen.entry(key).or_default();
        while times.front().is_some_and(|t| now.saturating_sub(*t) >= window) {
            times.pop_front();
        }
        times.push_back(now);
        let reached = times.len() as u64 >= u64::from(count);
        if reached {
            self.seen.remove(&key);
        }
        reached
    }

    /// Forget keys whose latest alert left every window of `window` seconds.
    pub fn expire(&mut self, now: u64, window: u64) {
        self.seen
            .retain(|_, times| times.back().is_some_and(|t| now.saturating_sub(*t) < window));
    }

    fn make_room(&mut self) {
        let oldest = self
            .seen
            .iter()
            .min_by_key(|(_, times)| times.back().copied())
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.seen.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(sid: u64) -> Key {
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        (Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))), dst, sid)
    }

    #[test]
    fn the_count_th_alert_inside_the_window_escalates() {
        let mut e = Escalator::new(8);
        let hits: Vec<bool> = (0..5).map(|i| e.record(key(1), 100 + i, 5, 60)).collect();
        assert_eq!(hits, vec![false, false, false, false, true]);
        assert!(e.is_empty());
    }

    #[test]
    fn alerts_spread_past_the_window_never_escalate() {
        let mut e = Escalator::new(8);
        let hits: Vec<bool> = (0..6).map(|i| e.record(key(1), i * 60, 3, 60)).collect();
        assert_eq!(hits, vec![false; 6]);
    }

    #[test]
    fn the_window_edge_is_exclusive_and_the_next_round_needs_a_fresh_count() {
        let mut e = Escalator::new(8);
        assert!(!e.record(key(1), 0, 2, 10));
        assert!(!e.record(key(1), 10, 2, 10));
        assert!(e.record(key(1), 15, 2, 10));
        assert!(!e.record(key(1), 16, 2, 10));
    }

    #[test]
    fn different_keys_count_separately() {
        let mut e = Escalator::new(8);
        assert!(!e.record(key(1), 0, 2, 60));
        assert!(!e.record(key(2), 1, 2, 60));
        assert!(e.record(key(1), 2, 2, 60));
    }

    #[test]
    fn the_table_stays_at_its_cap_and_drops_the_stalest_key() {
        let mut e = Escalator::new(4);
        for sid in 0..100 {
            e.record(key(sid), sid, 5, 1000);
        }
        assert_eq!(e.len(), 4);
        assert!(!e.record(key(99), 100, 2, 1000) || e.len() <= 4);
        e.expire(5000, 1000);
        assert!(e.is_empty());
    }
}
