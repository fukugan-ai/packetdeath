//! Stage 12: the command-line options of the IPS, read by `block`.
//! `docs/design.md` "段階12 IDS/IPS の業務水準化".
//!
//! `Options::accept` is called for each flag the caller does not know. It
//! consumes the flags below and says whether it took one, so `block` gains the
//! options without this module knowing the rest of its command line.

use std::path::PathBuf;

use super::policy::Action;
use super::runtime::Config;
use super::testcmd::default_of;

/// Default size of the drop set and the escalation table.
pub const DEFAULT_MAX_ENTRIES: usize = 16384;
/// Default bytes read from `eve.json` in one poll.
pub const DEFAULT_MAX_READ: usize = 8 * 1024 * 1024;
/// Default seconds without a change before `eve.json` is called stale.
pub const DEFAULT_STALE_SECS: u64 = 900;

/// The IPS options given to `block`.
#[derive(Debug)]
pub struct Options {
    pub policy: Option<PathBuf>,
    pub never: Option<PathBuf>,
    pub allow_private: bool,
    pub default_action: Action,
    pub max_entries: usize,
    pub state: Option<PathBuf>,
    pub max_read: usize,
    pub stale_after: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            policy: None,
            never: None,
            allow_private: false,
            default_action: Action::Alert,
            max_entries: DEFAULT_MAX_ENTRIES,
            state: None,
            max_read: DEFAULT_MAX_READ,
            stale_after: DEFAULT_STALE_SECS,
        }
    }
}

fn number<T: std::str::FromStr>(flag: &str, text: &str) -> Result<T, String> {
    text.parse().map_err(|_| format!("{flag} {text:?} is not a number"))
}

impl Options {
    /// Take `flag` (and its value from `rest`) if it is an IPS option.
    pub fn accept<'a>(&mut self, flag: &str, rest: &mut impl Iterator<Item = &'a String>) -> Result<bool, String> {
        if flag == "--ips-allow-private" {
            self.allow_private = true;
            return Ok(true);
        }
        if !matches!(
            flag,
            "--ips-policy" | "--ips-never" | "--ips-default" | "--ips-max-entries" | "--ips-state" | "--eve-max-read" | "--eve-stale"
        ) {
            return Ok(false);
        }
        let Some(value) = rest.next() else {
            return Err(format!("{flag} needs a value"));
        };
        match flag {
            "--ips-policy" => self.policy = Some(PathBuf::from(value)),
            "--ips-never" => self.never = Some(PathBuf::from(value)),
            "--ips-state" => self.state = Some(PathBuf::from(value)),
            "--ips-default" => self.default_action = default_of(value)?,
            "--ips-max-entries" => self.max_entries = number(flag, value)?,
            "--eve-max-read" => self.max_read = number(flag, value)?,
            _ => self.stale_after = number(flag, value)?,
        }
        Ok(true)
    }

    /// Refuse a combination that has no single meaning.
    ///
    /// The policy decides every alert, so `--ips-sids` and `--ips-severity`
    /// would be a second, unordered decision; the IPS options without a policy
    /// would silently do nothing.
    pub fn check(&self, legacy_rule_given: bool, eve_given: bool) -> Result<(), String> {
        if self.policy.is_none() {
            let others = self.never.is_some() || self.state.is_some() || self.allow_private;
            return if others { Err(String::from("--ips-never, --ips-state and --ips-allow-private need --ips-policy")) } else { Ok(()) };
        }
        if legacy_rule_given {
            return Err(String::from("--ips-policy replaces --ips-sids and --ips-severity; give one or the other"));
        }
        if !eve_given {
            return Err(String::from("--ips-policy needs --eve"));
        }
        Ok(())
    }

    /// The runtime configuration, or `None` when there is no policy.
    pub fn runtime(&self, eve: PathBuf, ttl: u64, log_dir: Option<PathBuf>) -> Option<Config> {
        Some(Config {
            eve,
            policy: self.policy.clone()?,
            never: self.never.clone(),
            allow_private: self.allow_private,
            default_action: self.default_action,
            default_ttl: ttl,
            log_dir,
            state: self.state.clone(),
            max_entries: self.max_entries,
            max_read: self.max_read,
            stale_after: self.stale_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(args: &[&str]) -> Result<Options, String> {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut options = Options::default();
        let mut iter = owned.iter();
        while let Some(flag) = iter.next() {
            if !options.accept(flag, &mut iter)? {
                return Err(format!("unknown {flag}"));
            }
        }
        Ok(options)
    }

    #[test]
    fn every_option_is_read_and_unknown_ones_are_left_to_the_caller() -> Result<(), String> {
        let o = feed(&["--ips-policy", "p", "--ips-never", "n", "--ips-default", "drop", "--ips-max-entries", "5", "--ips-state", "s", "--eve-max-read", "99", "--eve-stale", "7", "--ips-allow-private"])?;
        assert_eq!((o.max_entries, o.max_read, o.stale_after, o.allow_private), (5, 99, 7, true));
        assert_eq!(o.default_action, Action::Drop { ttl: None });
        assert!(feed(&["--queue", "1"]).is_err_and(|why| why == "unknown --queue"));
        Ok(())
    }

    #[test]
    fn a_missing_or_bad_value_is_an_error() {
        assert!(feed(&["--ips-policy"]).is_err());
        assert!(feed(&["--eve-stale", "soon"]).is_err());
        assert!(feed(&["--ips-default", "explode"]).is_err());
    }

    #[test]
    fn check_refuses_the_combinations_that_mean_nothing() -> Result<(), String> {
        let none = Options::default();
        assert!(none.check(true, false).is_ok());
        let orphan = feed(&["--ips-state", "s"])?;
        assert!(orphan.check(false, true).is_err());
        let policy = feed(&["--ips-policy", "p"])?;
        assert!(policy.check(true, true).is_err());
        assert!(policy.check(false, false).is_err());
        assert!(policy.check(false, true).is_ok());
        Ok(())
    }

    #[test]
    fn the_runtime_exists_only_with_a_policy() -> Result<(), String> {
        assert!(Options::default().runtime(PathBuf::from("e"), 600, None).is_none());
        let cfg = feed(&["--ips-policy", "p"])?.runtime(PathBuf::from("e"), 600, None);
        assert!(cfg.is_some_and(|c| c.default_ttl == 600 && c.max_entries == DEFAULT_MAX_ENTRIES));
        Ok(())
    }
}
