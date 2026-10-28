//! Stage 12: the bounded, persistent drop set. `docs/design.md`
//! "段階12 IDS/IPS の業務水準化".
//!
//! Entries hold an absolute expiry (seconds since the Unix epoch), so a restart
//! restores what is still in force and nothing is extended. At the cap, the
//! entry that expires first makes room. The state file is written beside
//! itself and renamed, so a reader sees the old file or the new one.

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Line {
    ip: IpAddr,
    port: u16,
    expires: u64,
}

/// What `insert` did to make room.
#[derive(Debug, PartialEq, Eq)]
pub struct Inserted {
    /// Entries removed because their time had passed.
    pub expired: usize,
    /// Entries removed while still in force, to stay under the cap.
    pub evicted: usize,
}

/// Destinations being dropped, with their expiry.
#[derive(Debug)]
pub struct DropSet {
    cap: usize,
    entries: HashMap<(IpAddr, u16), u64>,
}

impl DropSet {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            entries: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop `ip:port` until `now + ttl`.
    pub fn insert(&mut self, ip: IpAddr, port: u16, now: u64, ttl: u64) -> Inserted {
        let before = self.entries.len();
        self.entries.retain(|_, expires| *expires > now);
        let expired = before - self.entries.len();
        let mut evicted = 0;
        let key = (ip, port);
        while !self.entries.contains_key(&key) && self.entries.len() >= self.cap {
            let soonest = self.entries.iter().min_by_key(|(_, e)| **e).map(|(k, _)| *k);
            let Some(gone) = soonest else { break };
            self.entries.remove(&gone);
            evicted += 1;
        }
        self.entries.insert(key, now.saturating_add(ttl));
        Inserted { expired, evicted }
    }

    /// Entries in force at `now`, as `(ip, port, seconds left)`.
    pub fn in_force(&self, now: u64) -> Vec<(IpAddr, u16, u64)> {
        self.entries
            .iter()
            .filter(|(_, e)| **e > now)
            .map(|((ip, port), e)| (*ip, *port, *e - now))
            .collect()
    }

    pub fn contains(&self, ip: &IpAddr, port: u16, now: u64) -> bool {
        self.entries.get(&(*ip, port)).is_some_and(|e| *e > now)
    }

    /// Write the entries still in force to `path`, atomically.
    pub fn save(&self, path: &Path, now: u64) -> Result<(), String> {
        let mut body = String::new();
        for ((ip, port), expires) in self.entries.iter().filter(|(_, e)| **e > now) {
            let line = Line { ip: *ip, port: *port, expires: *expires };
            body.push_str(&serde_json::to_string(&line).map_err(|e| e.to_string())?);
            body.push('\n');
        }
        let mut tmp: PathBuf = path.to_path_buf();
        tmp.set_extension("tmp");
        let mut file = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        file.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Read a state file. Returns the set, how many entries were restored, and
    /// how many were already expired. A file that cannot be read or has a
    /// broken line is an error; the caller starts empty and says so.
    pub fn load(path: &Path, cap: usize, now: u64) -> Result<(Self, usize, usize), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut set = Self::new(cap);
        let mut gone = 0;
        for (index, text) in text.lines().enumerate() {
            let line: Line = serde_json::from_str(text).map_err(|e| format!("line {}: {e}", index + 1))?;
            if line.expires <= now {
                gone += 1;
                continue;
            }
            let ttl = line.expires - now;
            set.insert(line.ip, line.port, now, ttl);
        }
        let restored = set.len();
        Ok((set, restored, gone))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("ips-test")
            .join(format!("dropset-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join(name))
    }

    #[test]
    fn an_entry_is_in_force_until_its_time() {
        let mut set = DropSet::new(8);
        set.insert(ip(1), 443, 100, 60);
        assert!(set.contains(&ip(1), 443, 159));
        assert!(!set.contains(&ip(1), 443, 160));
        assert!(!set.contains(&ip(1), 80, 100));
    }

    #[test]
    fn a_hundred_inserts_into_a_cap_of_eight_evict_ninety_two() {
        let mut set = DropSet::new(8);
        let mut evicted = 0;
        for n in 0..100_u8 {
            evicted += set.insert(ip(n), 443, 100, 1000 + u64::from(n)).evicted;
        }
        assert_eq!((set.len(), evicted), (8, 92));
        assert!(set.contains(&ip(99), 443, 101));
        assert!(!set.contains(&ip(0), 443, 101));
    }

    #[test]
    fn expired_entries_leave_before_live_ones_are_evicted() {
        let mut set = DropSet::new(2);
        set.insert(ip(1), 1, 0, 10);
        set.insert(ip(2), 1, 0, 1000);
        let done = set.insert(ip(3), 1, 50, 1000);
        assert_eq!(done, Inserted { expired: 1, evicted: 0 });
        assert!(set.contains(&ip(2), 1, 51));
    }

    #[test]
    fn a_saved_set_comes_back_and_expired_entries_are_not_extended() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("state.jsonl")?;
        let mut set = DropSet::new(8);
        set.insert(ip(1), 443, 100, 500);
        set.insert(ip(2), 443, 100, 50);
        set.save(&path, 100)?;
        let (back, restored, gone) = DropSet::load(&path, 8, 200)?;
        assert_eq!((restored, gone), (1, 1));
        assert!(back.contains(&ip(1), 443, 599));
        assert!(!back.contains(&ip(1), 443, 600));
        Ok(())
    }

    #[test]
    fn a_broken_or_missing_state_file_is_an_error() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("broken.jsonl")?;
        std::fs::write(&path, "{\"ip\":\"203.0.113.1\",\"port\":1,\"expires\":9999}\nnot json\n")?;
        assert!(DropSet::load(&path, 8, 0).is_err());
        assert!(DropSet::load(&scratch("absent.jsonl")?, 8, 0).is_err());
        Ok(())
    }
}
