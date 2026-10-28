//! Sessions, CSRF tokens and the sign-in limiter. `docs/design.md`
//! "段階13 WebApp" 認証と権限.
//!
//! A session id and its CSRF token are 256 random bits each, kept only in
//! memory. A session ends 8 hours after sign-in or after 1 hour without use.
//! Time is passed in so a test never sleeps. Both tables are bounded.

use std::collections::HashMap;

use crate::users::Role;

/// A session lives this long in total.
pub const LIFETIME: u64 = 8 * 3600;
/// ...and this long without a request.
pub const IDLE: u64 = 3600;
/// Sessions held at once.
pub const MAX_SESSIONS: usize = 1024;
/// Failures of one account before it waits.
pub const ACCOUNT_FAILS: u32 = 5;
/// Failures of one source before it waits.
pub const SOURCE_FAILS: u32 = 20;
/// How long a wait lasts, and how long a failure is remembered.
pub const WAIT: u64 = 15 * 60;
/// Failure records held at once.
pub const MAX_RECORDS: usize = 4096;

/// A fresh random token, as 64 hex characters.
pub fn token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Who a session belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Who {
    pub name: String,
    pub role: Role,
    pub csrf: String,
}

struct Entry {
    who: Who,
    started: u64,
    last: u64,
}

/// The table of live sessions.
#[derive(Default)]
pub struct Sessions {
    live: HashMap<String, Entry>,
}

impl Sessions {
    /// Start a session. Returns its id. When the table is full the session
    /// used longest ago makes room.
    pub fn start(&mut self, name: &str, role: Role, now: u64) -> Result<(String, String), String> {
        self.live.retain(|_, e| alive(e, now));
        while self.live.len() >= MAX_SESSIONS {
            let oldest = self.live.iter().min_by_key(|(_, e)| e.last).map(|(id, _)| id.clone());
            let Some(id) = oldest else { break };
            self.live.remove(&id);
        }
        let (id, csrf) = (token()?, token()?);
        let who = Who { name: name.to_owned(), role, csrf: csrf.clone() };
        self.live.insert(id.clone(), Entry { who, started: now, last: now });
        Ok((id, csrf))
    }

    /// The owner of `id`, if it is live. A use counts as activity.
    pub fn touch(&mut self, id: &str, now: u64) -> Option<Who> {
        let entry = self.live.get_mut(id)?;
        if !alive(entry, now) {
            self.live.remove(id);
            return None;
        }
        entry.last = now;
        Some(entry.who.clone())
    }

    pub fn end(&mut self, id: &str) {
        self.live.remove(id);
    }

    /// End every session of `name` (the account was changed or removed).
    pub fn end_all_of(&mut self, name: &str) {
        self.live.retain(|_, e| e.who.name != name);
    }

    /// Change the role the live sessions of `name` carry.
    pub fn set_role_of(&mut self, name: &str, role: Role) {
        for entry in self.live.values_mut().filter(|e| e.who.name == name) {
            entry.who.role = role;
        }
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

/// A ticket for the second step lives this long.
pub const TICKET_LIFETIME: u64 = 300;
/// Wrong second-step answers a ticket takes before it is dropped.
pub const TICKET_FAILS: u32 = 5;
/// Tickets held at once.
pub const MAX_TICKETS: usize = 256;

struct Ticket {
    name: String,
    role: Role,
    born: u64,
    fails: u32,
}

/// Passwords that were right and wait for a second factor: ticket id to account. Memory only.
#[derive(Default)]
pub struct Tickets {
    waiting: HashMap<String, Ticket>,
}

impl Tickets {
    /// A new ticket for `name`. When the table is full the oldest makes room.
    pub fn issue(&mut self, name: &str, role: Role, now: u64) -> Result<String, String> {
        self.waiting.retain(|_, t| now.saturating_sub(t.born) < TICKET_LIFETIME);
        while self.waiting.len() >= MAX_TICKETS {
            let oldest = self.waiting.iter().min_by_key(|(_, t)| t.born).map(|(id, _)| id.clone());
            let Some(id) = oldest else { break };
            self.waiting.remove(&id);
        }
        let id = token()?;
        self.waiting.insert(id.clone(), Ticket { name: name.to_owned(), role, born: now, fails: 0 });
        Ok(id)
    }

    /// The account a live ticket belongs to, with its role.
    pub fn owner(&self, id: &str, now: u64) -> Option<(String, Role)> {
        let t = self.waiting.get(id)?;
        (now.saturating_sub(t.born) < TICKET_LIFETIME).then(|| (t.name.clone(), t.role))
    }

    /// A wrong answer: the ticket is dropped at the fifth.
    pub fn missed(&mut self, id: &str) {
        let spent = self.waiting.get_mut(id).is_some_and(|t| {
            t.fails += 1;
            t.fails >= TICKET_FAILS
        });
        if spent {
            self.waiting.remove(id);
        }
    }

    /// The ticket is used up.
    pub fn spend(&mut self, id: &str) {
        self.waiting.remove(id);
    }

    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }
}

fn alive(entry: &Entry, now: u64) -> bool {
    now.saturating_sub(entry.started) < LIFETIME && now.saturating_sub(entry.last) < IDLE
}

/// Failures of one key: how many, and when the latest was.
#[derive(Default)]
struct Record {
    fails: u32,
    last: u64,
}

/// The sign-in limiter: one table for accounts, one for sources.
#[derive(Default)]
pub struct Limiter {
    accounts: HashMap<String, Record>,
    sources: HashMap<String, Record>,
}

fn waiting(table: &HashMap<String, Record>, key: &str, limit: u32, now: u64) -> bool {
    table.get(key).is_some_and(|r| r.fails >= limit && now.saturating_sub(r.last) < WAIT)
}

fn note(table: &mut HashMap<String, Record>, key: &str, now: u64) {
    table.retain(|_, r| now.saturating_sub(r.last) < WAIT);
    if !table.contains_key(key) && table.len() >= MAX_RECORDS {
        let stalest = table.iter().min_by_key(|(_, r)| r.last).map(|(k, _)| k.clone());
        if let Some(k) = stalest {
            table.remove(&k);
        }
    }
    let record = table.entry(key.to_owned()).or_default();
    record.fails += 1;
    record.last = now;
}

impl Limiter {
    /// Whether this account or this source must wait.
    pub fn must_wait(&self, account: &str, source: &str, now: u64) -> bool {
        waiting(&self.accounts, account, ACCOUNT_FAILS, now) || waiting(&self.sources, source, SOURCE_FAILS, now)
    }

    pub fn failed(&mut self, account: &str, source: &str, now: u64) {
        note(&mut self.accounts, account, now);
        note(&mut self.sources, source, now);
    }

    /// A good sign-in clears the account's failures (not the source's).
    pub fn succeeded(&mut self, account: &str) {
        self.accounts.remove(account);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_64_hex_characters_and_differ() -> Result<(), String> {
        let (a, b) = (token()?, token()?);
        assert!(a.len() == 64 && a.chars().all(|c| c.is_ascii_hexdigit()) && a != b);
        Ok(())
    }

    #[test]
    fn a_session_ends_after_its_lifetime_and_after_idleness() -> Result<(), String> {
        let mut s = Sessions::default();
        let (id, csrf) = s.start("alice", Role::Admin, 0)?;
        assert_eq!(s.touch(&id, 10).map(|w| w.csrf), Some(csrf));
        assert!(s.touch(&id, 10 + IDLE - 1).is_some());
        assert!(s.touch(&id, 10 + IDLE - 1 + IDLE).is_none());
        let (long, _) = s.start("bob", Role::Viewer, 0)?;
        for step in 1..8 {
            assert!(s.touch(&long, step * 3000).is_some());
        }
        assert!(s.touch(&long, LIFETIME).is_none());
        Ok(())
    }

    #[test]
    fn logging_out_and_ending_all_of_a_name_close_sessions() -> Result<(), String> {
        let mut s = Sessions::default();
        let (a, _) = s.start("alice", Role::Admin, 0)?;
        let (b, _) = s.start("alice", Role::Admin, 0)?;
        let (c, _) = s.start("bob", Role::Viewer, 0)?;
        s.end(&a);
        assert!(s.touch(&a, 1).is_none() && s.touch(&b, 1).is_some());
        s.end_all_of("alice");
        assert!(s.touch(&b, 1).is_none() && s.touch(&c, 1).is_some());
        s.set_role_of("bob", Role::Operator);
        assert_eq!(s.touch(&c, 2).map(|w| w.role), Some(Role::Operator));
        Ok(())
    }

    #[test]
    fn the_table_stays_at_its_cap() -> Result<(), String> {
        let mut s = Sessions::default();
        for n in 0..(MAX_SESSIONS + 50) {
            s.start("alice", Role::Viewer, n as u64)?;
        }
        assert_eq!(s.len(), MAX_SESSIONS);
        Ok(())
    }

    #[test]
    fn five_failures_make_an_account_wait_and_the_wait_ends() {
        let mut l = Limiter::default();
        for t in 0..4 {
            l.failed("alice", "10.0.0.1", t);
            assert!(!l.must_wait("alice", "10.0.0.1", t));
        }
        l.failed("alice", "10.0.0.1", 4);
        assert!(l.must_wait("alice", "10.0.0.2", 5));
        assert!(!l.must_wait("bob", "10.0.0.2", 5));
        assert!(!l.must_wait("alice", "10.0.0.2", 4 + WAIT));
    }

    #[test]
    fn twenty_failures_from_one_source_make_it_wait_for_any_account() {
        let mut l = Limiter::default();
        for n in 0..20 {
            l.failed(&format!("user{n}"), "10.0.0.9", 0);
        }
        assert!(l.must_wait("fresh", "10.0.0.9", 1));
        assert!(!l.must_wait("fresh", "10.0.0.8", 1));
    }

    #[test]
    fn a_good_sign_in_clears_the_account_and_the_tables_are_bounded() {
        let mut l = Limiter::default();
        for t in 0..5 {
            l.failed("alice", "s", t);
        }
        l.succeeded("alice");
        assert!(!l.must_wait("alice", "t", 6));
        for n in 0..(MAX_RECORDS + 10) {
            l.failed(&format!("u{n}"), &format!("s{n}"), 0);
        }
        assert!(l.accounts.len() <= MAX_RECORDS && l.sources.len() <= MAX_RECORDS);
    }
}
