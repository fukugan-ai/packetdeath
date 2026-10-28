//! Stage 11: the inputs that can be rewritten while the WAF runs.
//!
//! `docs/design.md` "段階11 WAF" 読み直し. Rules, exclusions and the three IP
//! lists are read at start (a file that cannot be read stops the start) and
//! read again whenever `ReloadWatcher` sees the file change. A file that cannot
//! be read later leaves the previous content in use and says so once.
//!
//! A request takes one [`Inputs`] snapshot at its start and uses it to the end,
//! so a reload never changes the rules under a request that is being judged.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use crate::flow::service_log;
use crate::iplist::IpList;
use crate::reload::{ReloadOutcome, ReloadWatcher};

use super::config::{load_exclusions, Settings};
use super::engine::Exclusion;
use super::rules::{load_jsonl, RuleSet};

/// One consistent set of inputs.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub rules: Arc<RuleSet>,
    pub exclusions: Arc<Vec<Exclusion>>,
    pub allow: Arc<IpList>,
    pub deny: Arc<IpList>,
    pub trust: Arc<IpList>,
}

/// Which input a watcher feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Rules,
    Exclusions,
    Allow,
    Deny,
    Trust,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Rules => "rules",
            Kind::Exclusions => "exclusions",
            Kind::Allow => "allow-ip",
            Kind::Deny => "deny-ip",
            Kind::Trust => "trust-forwarded-from",
        }
    }
}

/// Parse rule-file text into a rule set. Lines that are not rules are said
/// once each and dropped.
fn rules_from(text: &str) -> Result<RuleSet, String> {
    let loaded = load_jsonl(text);
    for (line, why) in &loaded.bad {
        service_log(&format!("packetdeath: [warn] waf rules line {line}: {why}"));
    }
    RuleSet::with_extra(loaded.rules).map_err(|e| e.to_string())
}

/// Parse exclusion-file text.
fn exclusions_from(text: &str) -> Vec<Exclusion> {
    let loaded = load_exclusions(text);
    for (line, why) in &loaded.bad {
        service_log(&format!(
            "packetdeath: [warn] waf exclusions line {line}: {why}"
        ));
    }
    loaded.exclusions
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// An IP list file, or the empty list when no file is configured.
fn list_from(path: &Option<PathBuf>) -> Result<IpList, String> {
    match path {
        Some(p) => IpList::load(p).map_err(|e| format!("{}: {e}", p.display())),
        None => Ok(IpList::empty()),
    }
}

/// Read every configured input once, at start.
fn initial(settings: &Settings) -> Result<Inputs, String> {
    let mut rules = RuleSet::builtin_only().map_err(|e| e.to_string())?;
    if let Some(path) = &settings.rules {
        rules = rules_from(&read_text(path)?)?;
    }
    let mut exclusions = Vec::new();
    if let Some(path) = &settings.exclusions {
        exclusions = exclusions_from(&read_text(path)?);
    }
    Ok(Inputs {
        rules: Arc::new(rules),
        exclusions: Arc::new(exclusions),
        allow: Arc::new(list_from(&settings.allow_ip)?),
        deny: Arc::new(list_from(&settings.deny_ip)?),
        trust: Arc::new(list_from(&settings.trust_forwarded_from)?),
    })
}

/// The shared, reloadable inputs.
pub struct Live {
    current: RwLock<Arc<Inputs>>,
    watchers: Mutex<Vec<(Kind, ReloadWatcher)>>,
}

impl Live {
    /// Read everything. An unreadable configured file is an error.
    pub fn start(settings: &Settings) -> Result<Live, String> {
        let inputs = initial(settings)?;
        let mut watchers = Vec::new();
        let wanted = [
            (Kind::Rules, &settings.rules),
            (Kind::Exclusions, &settings.exclusions),
            (Kind::Allow, &settings.allow_ip),
            (Kind::Deny, &settings.deny_ip),
            (Kind::Trust, &settings.trust_forwarded_from),
        ];
        for (kind, path) in wanted {
            if let Some(path) = path {
                watchers.push((kind, ReloadWatcher::new(path.clone())));
            }
        }
        Ok(Live {
            current: RwLock::new(Arc::new(inputs)),
            watchers: Mutex::new(watchers),
        })
    }

    /// The inputs a request should use.
    pub fn snapshot(&self) -> Arc<Inputs> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Poll every watched file once; swap in whatever changed. Returns how
    /// many inputs were replaced.
    pub fn poll_once(&self) -> usize {
        let mut watchers = match self.watchers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut next = (*self.snapshot()).clone();
        let mut replaced = 0;
        for (kind, watcher) in watchers.iter_mut() {
            match watcher.poll() {
                ReloadOutcome::Unchanged => {}
                ReloadOutcome::Loaded(text) => {
                    if apply(*kind, &text, &mut next) {
                        replaced += 1;
                    }
                }
                ReloadOutcome::Failed(why) => service_log(&format!(
                    "packetdeath: [warn] waf {}: {why}; the previous content stays",
                    kind.label()
                )),
            }
        }
        if replaced > 0 {
            match self.current.write() {
                Ok(mut guard) => *guard = Arc::new(next),
                Err(poisoned) => *poisoned.into_inner() = Arc::new(next),
            }
        }
        replaced
    }
}

/// Put freshly read text into `next`. False when the text could not be used.
fn apply(kind: Kind, text: &str, next: &mut Inputs) -> bool {
    match kind {
        Kind::Rules => match rules_from(text) {
            Ok(set) => {
                next.rules = Arc::new(set);
                true
            }
            Err(why) => {
                service_log(&format!("packetdeath: [warn] waf rules: {why}"));
                false
            }
        },
        Kind::Exclusions => {
            next.exclusions = Arc::new(exclusions_from(text));
            true
        }
        Kind::Allow => {
            next.allow = Arc::new(IpList::parse(text));
            true
        }
        Kind::Deny => {
            next.deny = Arc::new(IpList::parse(text));
            true
        }
        Kind::Trust => {
            next.trust = Arc::new(IpList::parse(text));
            true
        }
    }
}

/// Poll every 300 ms for as long as the process lives.
pub fn spawn_watcher(live: Arc<Live>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(300));
        live.poll_once();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::config::{parse_waf_args, Settings};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("waf-live-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn settings(extra: &[String]) -> Result<Settings, Box<dyn std::error::Error>> {
        let mut args: Vec<String> = "--listen 127.0.0.1:1 --upstream 127.0.0.1:2 --log-dir x"
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        args.extend_from_slice(extra);
        Ok(parse_waf_args(&args)?)
    }

    const RULE: &str = r#"{"id":990001,"target":"query","pattern":"forbidden-word","severity":"critical","paranoia":1,"message":"mine"}"#;

    #[test]
    fn with_no_files_the_builtin_rules_alone_are_used() -> TestResult {
        let live = Live::start(&settings(&[])?)?;
        let inputs = live.snapshot();
        assert!(inputs.exclusions.is_empty());
        assert!(inputs.rules.get(942_100).is_some());
        assert!(inputs.rules.get(990_001).is_none());
        assert_eq!(live.poll_once(), 0);
        Ok(())
    }

    #[test]
    fn a_configured_file_that_cannot_be_read_stops_the_start() -> TestResult {
        let missing = "/nonexistent-waf-rules-4f9a.jsonl".to_owned();
        let result = Live::start(&settings(&["--rules".into(), missing])?);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn a_rewritten_rules_file_changes_the_snapshot_and_a_taken_snapshot_does_not_move() -> TestResult {
        let dir = scratch("rules")?;
        let file = dir.join("rules.jsonl");
        std::fs::write(&file, "")?;
        let live = Live::start(&settings(&["--rules".into(), file.display().to_string()])?)?;
        let before = live.snapshot();
        assert!(before.rules.get(990_001).is_none());
        std::fs::write(&file, format!("{RULE}\n"))?;
        assert_eq!(live.poll_once(), 1);
        assert!(live.snapshot().rules.get(990_001).is_some());
        assert!(before.rules.get(990_001).is_none());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn a_vanished_file_keeps_the_previous_content() -> TestResult {
        let dir = scratch("gone")?;
        let file = dir.join("deny.txt");
        std::fs::write(&file, "203.0.113.0/24\n")?;
        let live = Live::start(&settings(&["--deny-ip".into(), file.display().to_string()])?)?;
        let ip: std::net::IpAddr = "203.0.113.9".parse()?;
        assert!(live.snapshot().deny.contains(&ip));
        std::fs::remove_file(&file)?;
        assert_eq!(live.poll_once(), 0);
        assert!(live.snapshot().deny.contains(&ip));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn bad_rule_lines_are_dropped_and_good_ones_kept_on_reload() -> TestResult {
        let dir = scratch("badline")?;
        let file = dir.join("rules.jsonl");
        std::fs::write(&file, "")?;
        let live = Live::start(&settings(&["--rules".into(), file.display().to_string()])?)?;
        std::fs::write(&file, format!("garbage\n{RULE}\n"))?;
        assert_eq!(live.poll_once(), 1);
        assert!(live.snapshot().rules.get(990_001).is_some());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn the_exclusion_and_ip_files_are_reloaded() -> TestResult {
        let dir = scratch("others")?;
        let ex = dir.join("ex.jsonl");
        let allow = dir.join("allow.txt");
        std::fs::write(&ex, "")?;
        std::fs::write(&allow, "")?;
        let live = Live::start(&settings(&[
            "--exclusions".into(),
            ex.display().to_string(),
            "--allow-ip".into(),
            allow.display().to_string(),
        ])?)?;
        std::fs::write(&ex, "{\"rule\":942100,\"path_prefix\":\"/\"}\n")?;
        std::fs::write(&allow, "198.51.100.0/24\n")?;
        assert_eq!(live.poll_once(), 2);
        let now = live.snapshot();
        assert_eq!(now.exclusions.len(), 1);
        assert!(now.allow.contains(&"198.51.100.7".parse()?));
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
