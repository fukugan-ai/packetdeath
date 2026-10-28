//! Stage 12: the running IPS. `docs/design.md` "段階12 IDS/IPS の業務水準化".
//!
//! `Runtime::tick` is one poll: reload the policy and the never-block list,
//! read the next bounded piece of `eve.json`, decide each alert, write the
//! audit line, mirror drops into the `IdsDropSet` the packet judge reads, keep
//! the state file, and watch whether Suricata is still writing. `run` repeats
//! `tick` until the stop channel closes.

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ids::IdsDropSet;
use crate::reload::{ReloadOutcome, ReloadWatcher};

use super::audit::{Event, IpsLog, Record};
use super::dropset::DropSet;
use super::engine::{Engine, Outcome};
use super::escalate::Escalator;
use super::eve::EveReader;
use super::health::{Change, Health, Seen};
use super::never::Protected;
use super::parse::alert_of;
use super::policy::{Action, AlertInfo, Policy};

/// Longest `eve.json` line read.
pub const MAX_LINE: usize = 1024 * 1024;

/// Everything `Runtime` needs, fixed at start.
pub struct Config {
    pub eve: PathBuf,
    pub policy: PathBuf,
    pub never: Option<PathBuf>,
    pub allow_private: bool,
    pub default_action: Action,
    pub default_ttl: u64,
    pub log_dir: Option<PathBuf>,
    pub state: Option<PathBuf>,
    pub max_entries: usize,
    pub max_read: usize,
    pub stale_after: u64,
}

/// One running IPS.
pub struct Runtime {
    cfg: Config,
    engine: Engine,
    reader: EveReader,
    health: Health,
    log: Option<IpsLog>,
    policy_watch: ReloadWatcher,
    never_watch: Option<ReloadWatcher>,
    sink: Arc<IdsDropSet>,
}

fn epoch_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        // DEFAULT: a clock before 1970 is treated as the epoch itself, so entries expire at once instead of never.
        Err(_) => 0,
    }
}

fn warn(text: &str) {
    eprintln!("packetdeath: [warn] ips: {text}");
}

impl Runtime {
    /// Build the IPS and restore the state file, if there is one.
    pub fn start(cfg: Config, sink: Arc<IdsDropSet>) -> Result<Self, String> {
        let text = std::fs::read_to_string(&cfg.policy).map_err(|e| format!("{}: {e}", cfg.policy.display()))?;
        let (policy, skipped) = Policy::parse(&text);
        if policy.is_empty() {
            return Err(format!("{}: no rule could be read ({skipped} line(s) dropped)", cfg.policy.display()));
        }
        let now = epoch_secs();
        let host = Vec::new();
        let mut never = Protected::detect(cfg.allow_private, host).map_err(|e| e.to_string())?;
        if let Some(path) = &cfg.never {
            let listed = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            never = never.with_listed(&listed);
        }
        let log = match &cfg.log_dir {
            Some(dir) => Some(IpsLog::open(dir).map_err(|e| e.to_string())?),
            None => None,
        };
        let mut drops = DropSet::new(cfg.max_entries);
        if let Some(path) = cfg.state.as_ref().filter(|p| p.exists()) {
            match DropSet::load(path, cfg.max_entries, now) {
                Ok((restored, kept, _gone)) => {
                    drops = restored;
                    if let Some(log) = &log {
                        write(log, Record::new(Event::Restored).map(|r| r.counted(kept as u64)));
                    }
                }
                Err(why) => warn(&format!("state file not restored, starting empty: {why}")),
            }
        }
        let engine = Engine {
            policy,
            never,
            escalator: Escalator::new(cfg.max_entries),
            drops,
            default_action: cfg.default_action,
            default_ttl: cfg.default_ttl,
        };
        let runtime = Self {
            policy_watch: ReloadWatcher::new(cfg.policy.clone()),
            never_watch: cfg.never.clone().map(ReloadWatcher::new),
            health: Health::new(cfg.stale_after, now),
            reader: EveReader::new(),
            cfg,
            engine,
            log,
            sink,
        };
        runtime.mirror(now);
        Ok(runtime)
    }

    /// Make the packet judge's set equal to the engine's.
    fn mirror(&self, now: u64) {
        let at = Instant::now();
        let entries = self
            .engine
            .drops
            .in_force(now)
            .into_iter()
            .map(|(ip, port, left)| ((ip, port), at + Duration::from_secs(left)))
            .collect();
        self.sink.replace(entries);
    }

    fn reload(&mut self) {
        match self.policy_watch.poll() {
            ReloadOutcome::Loaded(text) => {
                let (policy, skipped) = Policy::parse(&text);
                if policy.is_empty() {
                    warn("policy has no readable rule, keeping the previous one");
                } else {
                    self.engine.policy = policy;
                    if skipped > 0 {
                        warn(&format!("{skipped} policy line(s) could not be read"));
                    }
                }
            }
            ReloadOutcome::Failed(why) => warn(&why),
            ReloadOutcome::Unchanged => {}
        }
        let Some(watch) = self.never_watch.as_mut() else {
            return;
        };
        match watch.poll() {
            ReloadOutcome::Loaded(text) => {
                let host = Vec::new();
                if let Ok(base) = Protected::detect(self.cfg.allow_private, host) {
                    self.engine.never = base.with_listed(&text);
                }
            }
            ReloadOutcome::Failed(why) => warn(&why),
            ReloadOutcome::Unchanged => {}
        }
    }

    fn audit(&self, outcome: &Outcome, alert: &AlertInfo) {
        let Some(log) = &self.log else {
            return;
        };
        if outcome.event == Event::Ignored {
            return;
        }
        let made = Record::new(outcome.event).map(|r| {
            r.alert(alert.sid, alert.severity, alert.classtype.as_deref())
                .flow(alert.src_ip, alert.dst_ip, alert.dst_port)
                .deciding(outcome.rule, outcome.ttl)
        });
        write(log, made);
        if outcome.evicted > 0 {
            write(log, Record::new(Event::Evicted).map(|r| r.counted(outcome.evicted as u64)));
        }
    }

    fn read_eve(&mut self, now: u64) {
        let batch = match self.reader.read(&self.cfg.eve, self.cfg.max_read, MAX_LINE) {
            Ok(batch) => batch,
            Err(_) => return,
        };
        let mut changed = false;
        for line in &batch.lines {
            let Some(alert) = alert_of(line) else {
                continue;
            };
            let outcome = self.engine.handle(&alert, now);
            self.audit(&outcome, &alert);
            changed |= outcome.ttl.is_some();
        }
        let skipped = batch.oversized + batch.bad_utf8;
        if let (Some(log), true) = (&self.log, skipped > 0) {
            write(log, Record::new(Event::Skipped).map(|r| r.counted(skipped as u64)));
        }
        if changed {
            self.mirror(now);
            self.save(now);
        }
    }

    fn save(&self, now: u64) {
        if let Some(path) = &self.cfg.state {
            if let Err(why) = self.engine.drops.save(path, now) {
                warn(&format!("state file not written: {why}"));
            }
        }
    }

    fn watch_health(&mut self, now: u64) {
        let seen = std::fs::metadata(&self.cfg.eve).ok().and_then(|m| {
            let since_epoch = m.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
            Some(Seen {
                len: m.len(),
                mtime_secs: since_epoch.as_secs(),
            })
        });
        let event = match self.health.poll(seen, now) {
            Some(Change::Stale) => Event::Stale,
            Some(Change::Recovered) => Event::Recovered,
            None => return,
        };
        warn(&format!("eve.json is {}", event.as_str()));
        if let Some(log) = &self.log {
            write(log, Record::new(event));
        }
    }

    /// One poll at `now` (seconds since the epoch).
    pub fn tick(&mut self, now: u64) {
        self.reload();
        self.read_eve(now);
        self.watch_health(now);
    }
}

fn write(log: &IpsLog, record: Result<Record, super::audit::AuditError>) {
    match record {
        Ok(record) => {
            if let Err(why) = log.write(&record) {
                warn(&why.to_string());
            }
        }
        Err(why) => warn(&why.to_string()),
    }
}

/// Poll until `stop` closes or receives.
pub fn run(mut runtime: Runtime, poll: Duration, stop: &mpsc::Receiver<()>) {
    loop {
        match stop.recv_timeout(poll) {
            Err(mpsc::RecvTimeoutError::Timeout) => runtime.tick(epoch_secs()),
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}
