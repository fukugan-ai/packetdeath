//! Stage 12: is Suricata still writing? `docs/design.md`
//! "段階12 IDS/IPS の業務水準化" (健全性).
//!
//! The IPS cannot tell a quiet network from a dead sensor by itself. This
//! watches the size and modification time of `eve.json`: when neither moves for
//! `stale_after` seconds, or the file cannot be read, it reports `Stale` once;
//! when the file moves again it reports `Recovered` once. Time is passed in.

/// What the file looked like at one poll. `None` means it could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    pub len: u64,
    pub mtime_secs: u64,
}

/// A change in health, reported once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Stale,
    Recovered,
}

/// The watcher's memory between polls.
#[derive(Debug)]
pub struct Health {
    stale_after: u64,
    last_seen: Option<Seen>,
    last_move: u64,
    stale: bool,
}

impl Health {
    /// Start watching at `now`. The file is treated as having moved at `now`,
    /// so a fresh start is not stale until `stale_after` has passed.
    pub fn new(stale_after: u64, now: u64) -> Self {
        Self {
            stale_after,
            last_seen: None,
            last_move: now,
            stale: false,
        }
    }

    pub fn is_stale(&self) -> bool {
        self.stale
    }

    /// Feed one poll. Returns a change when health flips.
    pub fn poll(&mut self, seen: Option<Seen>, now: u64) -> Option<Change> {
        if seen.is_some() && seen != self.last_seen {
            self.last_move = now;
        }
        self.last_seen = seen;
        let quiet = now.saturating_sub(self.last_move) >= self.stale_after;
        if quiet && !self.stale {
            self.stale = true;
            return Some(Change::Stale);
        }
        if !quiet && self.stale {
            self.stale = false;
            return Some(Change::Recovered);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(len: u64) -> Option<Seen> {
        Some(Seen { len, mtime_secs: len })
    }

    #[test]
    fn a_file_that_keeps_growing_is_never_stale() {
        let mut h = Health::new(900, 0);
        let changes: Vec<Option<Change>> = (1..=20).map(|i| h.poll(seen(i), i * 100)).collect();
        assert!(changes.iter().all(Option::is_none));
    }

    #[test]
    fn a_still_file_goes_stale_once_after_the_limit_and_recovers_once() {
        let mut h = Health::new(900, 0);
        assert_eq!(h.poll(seen(5), 0), None);
        assert_eq!(h.poll(seen(5), 899), None);
        assert_eq!(h.poll(seen(5), 900), Some(Change::Stale));
        assert_eq!(h.poll(seen(5), 1500), None);
        assert!(h.is_stale());
        assert_eq!(h.poll(seen(6), 1600), Some(Change::Recovered));
        assert_eq!(h.poll(seen(6), 1700), None);
    }

    #[test]
    fn a_missing_file_goes_stale_after_the_limit_too() {
        let mut h = Health::new(60, 0);
        assert_eq!(h.poll(None, 30), None);
        assert_eq!(h.poll(None, 60), Some(Change::Stale));
        assert_eq!(h.poll(seen(1), 70), Some(Change::Recovered));
    }

    #[test]
    fn a_new_mtime_alone_counts_as_movement() {
        let mut h = Health::new(100, 0);
        let a = Some(Seen { len: 10, mtime_secs: 1 });
        let b = Some(Seen { len: 10, mtime_secs: 2 });
        assert_eq!(h.poll(a, 50), None);
        assert_eq!(h.poll(b, 140), None);
        assert_eq!(h.poll(b, 239), None);
        assert_eq!(h.poll(b, 240), Some(Change::Stale));
    }
}
