//! Stage 11: `packetdeath waf` options and the exclusion file.
//!
//! `docs/design.md` "段階11 WAF". Nothing here reads the environment: every
//! setting is an argument, and a missing required one is an error before the
//! socket is opened.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::engine::Exclusion;
use super::limits::{parse_rate, LimitError, RateSpec};
use super::rules::Target;

/// What the WAF does with a request that scores over the threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No inspection; requests are forwarded and logged.
    Off,
    /// Inspect and log, forward everything.
    Detect,
    /// Inspect, log, and answer 403.
    Block,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Detect => "detect",
            Mode::Block => "block",
        }
    }

    pub fn parse(text: &str) -> Option<Mode> {
        match text {
            "off" => Some(Mode::Off),
            "detect" => Some(Mode::Detect),
            "block" => Some(Mode::Block),
            _ => None,
        }
    }
}

/// Time limits (design "資源の上限" and "上流").
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const UPSTREAM_IDLE: Duration = Duration::from_secs(60);
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
pub const BODY_IDLE: Duration = Duration::from_secs(30);

/// Everything `packetdeath waf` is told.
#[derive(Debug, Clone)]
pub struct Settings {
    pub listen: SocketAddr,
    /// `host:port` of the server behind the WAF.
    pub upstream: String,
    pub log_dir: PathBuf,
    pub mode: Mode,
    pub paranoia: u8,
    pub threshold: u32,
    pub max_body: u64,
    pub max_body_inspect: usize,
    pub max_conns: usize,
    pub max_tracked_ips: usize,
    pub rate: Option<RateSpec>,
    pub ban_after: u32,
    pub ban_ttl_secs: u64,
    pub rules: Option<PathBuf>,
    pub exclusions: Option<PathBuf>,
    pub allow_ip: Option<PathBuf>,
    pub deny_ip: Option<PathBuf>,
    pub trust_forwarded_from: Option<PathBuf>,
}

/// Why the options could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum WafCliError {
    Missing(&'static str),
    MissingValue(String),
    Unknown(String),
    Invalid { flag: &'static str, value: String },
    Rate(LimitError),
}

impl std::fmt::Display for WafCliError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WafCliError::Missing(flag) => write!(out, "{flag} is required"),
            WafCliError::MissingValue(flag) => write!(out, "{flag} needs a value"),
            WafCliError::Unknown(flag) => write!(out, "unknown option {flag:?}"),
            WafCliError::Invalid { flag, value } => write!(out, "{flag} {value:?} is not valid"),
            WafCliError::Rate(e) => write!(out, "{e}"),
        }
    }
}

impl std::error::Error for WafCliError {}

fn value<'a>(
    iter: &mut std::slice::Iter<'a, String>,
    flag: &str,
) -> Result<&'a String, WafCliError> {
    iter.next()
        .ok_or_else(|| WafCliError::MissingValue(flag.to_owned()))
}

fn number<T: std::str::FromStr>(
    iter: &mut std::slice::Iter<'_, String>,
    flag: &'static str,
) -> Result<T, WafCliError> {
    let text = value(iter, flag)?;
    text.parse::<T>().map_err(|_| WafCliError::Invalid {
        flag,
        value: text.clone(),
    })
}

/// A `host:port` with a port, and a host that is not empty.
fn check_upstream(text: &str) -> Result<(), WafCliError> {
    let bad = || WafCliError::Invalid {
        flag: "--upstream",
        value: text.to_owned(),
    };
    let Some((host, port)) = text.rsplit_once(':') else {
        return Err(bad());
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(bad());
    }
    Ok(())
}

/// What is read so far, before the required options are checked.
#[derive(Default)]
struct Partial {
    listen: Option<SocketAddr>,
    upstream: Option<String>,
    log_dir: Option<PathBuf>,
    mode: Option<Mode>,
    paranoia: Option<u8>,
    threshold: Option<u32>,
    max_body: Option<u64>,
    max_body_inspect: Option<usize>,
    max_conns: Option<usize>,
    max_tracked_ips: Option<usize>,
    rate: Option<RateSpec>,
    ban_after: Option<u32>,
    ban_ttl_secs: Option<u64>,
    rules: Option<PathBuf>,
    exclusions: Option<PathBuf>,
    allow_ip: Option<PathBuf>,
    deny_ip: Option<PathBuf>,
    trust: Option<PathBuf>,
}

fn read_one(
    p: &mut Partial,
    flag: &str,
    iter: &mut std::slice::Iter<'_, String>,
) -> Result<(), WafCliError> {
    match flag {
        "--listen" => p.listen = Some(number(iter, "--listen")?),
        "--upstream" => {
            let text = value(iter, flag)?;
            check_upstream(text)?;
            p.upstream = Some(text.clone());
        }
        "--log-dir" => p.log_dir = Some(PathBuf::from(value(iter, flag)?)),
        "--mode" => {
            let text = value(iter, flag)?;
            p.mode = Some(Mode::parse(text).ok_or_else(|| WafCliError::Invalid {
                flag: "--mode",
                value: text.clone(),
            })?);
        }
        "--paranoia" => {
            let level: u8 = number(iter, "--paranoia")?;
            if !(1..=4).contains(&level) {
                return Err(WafCliError::Invalid {
                    flag: "--paranoia",
                    value: level.to_string(),
                });
            }
            p.paranoia = Some(level);
        }
        "--threshold" => p.threshold = Some(number(iter, "--threshold")?),
        "--max-body" => p.max_body = Some(number(iter, "--max-body")?),
        "--max-body-inspect" => p.max_body_inspect = Some(number(iter, "--max-body-inspect")?),
        "--max-conns" => p.max_conns = Some(number(iter, "--max-conns")?),
        "--max-tracked-ips" => p.max_tracked_ips = Some(number(iter, "--max-tracked-ips")?),
        "--rate" => {
            p.rate = Some(parse_rate(value(iter, flag)?).map_err(WafCliError::Rate)?);
        }
        "--ban-after" => p.ban_after = Some(number(iter, "--ban-after")?),
        "--ban-ttl" => p.ban_ttl_secs = Some(number(iter, "--ban-ttl")?),
        "--rules" => p.rules = Some(PathBuf::from(value(iter, flag)?)),
        "--exclusions" => p.exclusions = Some(PathBuf::from(value(iter, flag)?)),
        "--allow-ip" => p.allow_ip = Some(PathBuf::from(value(iter, flag)?)),
        "--deny-ip" => p.deny_ip = Some(PathBuf::from(value(iter, flag)?)),
        "--trust-forwarded-from" => p.trust = Some(PathBuf::from(value(iter, flag)?)),
        other => return Err(WafCliError::Unknown(other.to_owned())),
    }
    Ok(())
}

/// Read `packetdeath waf ...`.
pub fn parse_waf_args(args: &[String]) -> Result<Settings, WafCliError> {
    let mut p = Partial::default();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        read_one(&mut p, flag, &mut iter)?;
    }
    let listen = p.listen.ok_or(WafCliError::Missing("--listen"))?;
    let upstream = p.upstream.ok_or(WafCliError::Missing("--upstream"))?;
    let log_dir = p.log_dir.ok_or(WafCliError::Missing("--log-dir"))?;
    Ok(Settings {
        listen,
        upstream,
        log_dir,
        // DEFAULT: design 段階11 "mode": detect is the mode when --mode is not given.
        mode: p.mode.unwrap_or(Mode::Detect),
        // DEFAULT: design 段階11 "判定": paranoia level 1 when --paranoia is not given.
        paranoia: p.paranoia.unwrap_or(1),
        // DEFAULT: design 段階11 "判定": threshold 5 when --threshold is not given.
        threshold: p.threshold.unwrap_or(5),
        // DEFAULT: design 段階11 "資源の上限": 10 MiB when --max-body is not given.
        max_body: p.max_body.unwrap_or(10 * 1024 * 1024),
        // DEFAULT: design 段階11 "検査の対象": 131072 bytes when --max-body-inspect is not given.
        max_body_inspect: p.max_body_inspect.unwrap_or(131_072),
        // DEFAULT: design 段階11 "資源の上限": 512 connections when --max-conns is not given.
        max_conns: p.max_conns.unwrap_or(512),
        // DEFAULT: design 段階11 "壊れ方": 65536 tracked addresses when --max-tracked-ips is not given.
        max_tracked_ips: p.max_tracked_ips.unwrap_or(65_536),
        rate: p.rate,
        // DEFAULT: bans are off unless --ban-after is given (design "source IP の制御").
        ban_after: p.ban_after.unwrap_or(0),
        // DEFAULT: a ban lasts 600 seconds when --ban-ttl is not given.
        ban_ttl_secs: p.ban_ttl_secs.unwrap_or(600),
        rules: p.rules,
        exclusions: p.exclusions,
        allow_ip: p.allow_ip,
        deny_ip: p.deny_ip,
        trust_forwarded_from: p.trust,
    })
}

/// One line of the exclusion file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExclusionLine {
    rule: u32,
    path_prefix: String,
    target: Option<String>,
    method: Option<String>,
}

/// Why an exclusion line was not used.
#[derive(Debug)]
pub enum ExclusionError {
    Json(serde_json::Error),
    Target(String),
}

impl std::fmt::Display for ExclusionError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExclusionError::Json(e) => write!(out, "not an exclusion: {e}"),
            ExclusionError::Target(t) => write!(out, "unknown target {t:?}"),
        }
    }
}

fn exclusion_from_line(line: &str) -> Result<Exclusion, ExclusionError> {
    let parsed: ExclusionLine = serde_json::from_str(line).map_err(ExclusionError::Json)?;
    let at = match parsed.target {
        None => None,
        Some(name) => match Target::parse(&name) {
            Some(Target::One(location)) => Some(location),
            _ => return Err(ExclusionError::Target(name)),
        },
    };
    Ok(Exclusion {
        rule: parsed.rule,
        path_prefix: parsed.path_prefix,
        at,
        method: parsed.method,
    })
}

/// The exclusions read, and the lines that were not (1-based line, why).
#[derive(Debug, Default)]
pub struct LoadedExclusions {
    pub exclusions: Vec<Exclusion>,
    pub bad: Vec<(usize, ExclusionError)>,
}

/// Read a JSON Lines exclusion file. Blank lines and `#` lines are skipped.
pub fn load_exclusions(text: &str) -> LoadedExclusions {
    let mut loaded = LoadedExclusions::default();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match exclusion_from_line(trimmed) {
            Ok(found) => loaded.exclusions.push(found),
            Err(error) => loaded.bad.push((index + 1, error)),
        }
    }
    loaded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::rules::Location;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    const BASE: &str = "--listen 127.0.0.1:8080 --upstream 127.0.0.1:9000 --log-dir /var/log/pd";

    #[test]
    fn the_required_options_alone_give_the_design_defaults() -> TestResult {
        let s = parse_waf_args(&args(BASE))?;
        assert_eq!(s.mode, Mode::Detect);
        assert_eq!((s.paranoia, s.threshold), (1, 5));
        assert_eq!(s.max_body, 10 * 1024 * 1024);
        assert_eq!(s.max_body_inspect, 131_072);
        assert_eq!((s.max_conns, s.max_tracked_ips), (512, 65_536));
        assert!(s.rate.is_none() && s.rules.is_none());
        assert_eq!((s.ban_after, s.ban_ttl_secs), (0, 600));
        Ok(())
    }

    #[test]
    fn every_option_is_read() -> TestResult {
        let line = format!(
            "{BASE} --mode block --paranoia 3 --threshold 7 --max-body 1000 \
             --max-body-inspect 500 --max-conns 4 --max-tracked-ips 99 --rate 5/1 \
             --ban-after 3 --ban-ttl 30 --rules r.jsonl --exclusions e.jsonl \
             --allow-ip a.txt --deny-ip d.txt --trust-forwarded-from t.txt"
        );
        let s = parse_waf_args(&args(&line))?;
        assert_eq!(s.mode, Mode::Block);
        assert_eq!((s.paranoia, s.threshold), (3, 7));
        assert_eq!((s.max_body, s.max_body_inspect), (1000, 500));
        assert_eq!((s.max_conns, s.max_tracked_ips), (4, 99));
        assert_eq!(s.rate, Some(RateSpec { count: 5, per_ms: 1000 }));
        assert_eq!((s.ban_after, s.ban_ttl_secs), (3, 30));
        assert_eq!(s.rules, Some(PathBuf::from("r.jsonl")));
        assert_eq!(s.exclusions, Some(PathBuf::from("e.jsonl")));
        assert_eq!(s.allow_ip, Some(PathBuf::from("a.txt")));
        assert_eq!(s.deny_ip, Some(PathBuf::from("d.txt")));
        assert_eq!(s.trust_forwarded_from, Some(PathBuf::from("t.txt")));
        Ok(())
    }

    #[test]
    fn each_required_option_is_named_when_missing() {
        let cases = [
            ("--upstream 127.0.0.1:9000 --log-dir x", "--listen"),
            ("--listen 127.0.0.1:1 --log-dir x", "--upstream"),
            ("--listen 127.0.0.1:1 --upstream h:1", "--log-dir"),
        ];
        for (line, flag) in cases {
            assert_eq!(parse_waf_args(&args(line)).err(), Some(WafCliError::Missing(flag)));
        }
    }

    #[test]
    fn bad_values_are_refused_with_the_flag_named() {
        let bad = [
            "--mode loud",
            "--paranoia 0",
            "--paranoia 5",
            "--paranoia x",
            "--threshold -1",
            "--rate 0/1",
            "--upstream nohost",
            "--upstream :80",
            "--upstream h:99999",
            "--listen nowhere",
        ];
        for tail in bad {
            let line = format!("{BASE} {tail}");
            assert!(parse_waf_args(&args(&line)).is_err(), "{tail}");
        }
    }

    #[test]
    fn an_unknown_option_and_a_dangling_one_are_errors() {
        let unknown = format!("{BASE} --frobnicate");
        assert_eq!(
            parse_waf_args(&args(&unknown)).err(),
            Some(WafCliError::Unknown("--frobnicate".into()))
        );
        let dangling = format!("{BASE} --mode");
        assert_eq!(
            parse_waf_args(&args(&dangling)).err(),
            Some(WafCliError::MissingValue("--mode".into()))
        );
    }

    #[test]
    fn modes_round_trip() {
        for mode in [Mode::Off, Mode::Detect, Mode::Block] {
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(Mode::parse(""), None);
    }

    #[test]
    fn an_exclusion_line_is_read() -> TestResult {
        let text = concat!(
            "# comment\n",
            "{\"rule\":942100,\"path_prefix\":\"/api/search\",\"target\":\"query\",\"method\":\"GET\"}\n",
            "{\"rule\":941100,\"path_prefix\":\"/\"}\n",
        );
        let loaded = load_exclusions(text);
        assert!(loaded.bad.is_empty());
        assert_eq!(loaded.exclusions.len(), 2);
        assert_eq!(loaded.exclusions[0].at, Some(Location::Query));
        assert_eq!(loaded.exclusions[0].method.as_deref(), Some("GET"));
        assert_eq!(loaded.exclusions[1].at, None);
        Ok(())
    }

    #[test]
    fn bad_exclusion_lines_are_reported_and_the_rest_kept() {
        let text = concat!(
            "{\"rule\":1,\"path_prefix\":\"/\"}\n",
            "not json\n",
            "{\"rule\":2,\"path_prefix\":\"/\",\"target\":\"args\"}\n",
            "{\"rule\":3,\"path_prefix\":\"/\",\"extra\":1}\n",
        );
        let loaded = load_exclusions(text);
        assert_eq!(loaded.exclusions.len(), 1);
        let lines: Vec<usize> = loaded.bad.iter().map(|b| b.0).collect();
        assert_eq!(lines, vec![2, 3, 4]);
        assert!(load_exclusions("").exclusions.is_empty());
    }
}
