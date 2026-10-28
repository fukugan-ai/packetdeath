//! Stage 12: `packetdeath ips-test`. `docs/design.md`
//! "段階12 IDS/IPS の業務水準化".
//!
//! Runs a file of `eve.json` alert lines through a policy and prints the
//! decision for each, with no socket and no Suricata. The alerts arrive one
//! second apart, so escalation windows can be tested. Gateway and resolver
//! protection is not read from this machine, so the answer does not depend on
//! where the test runs.

use std::path::PathBuf;

use super::dropset::DropSet;
use super::engine::Engine;
use super::escalate::Escalator;
use super::never::Protected;
use super::parse::alert_of;
use super::policy::{Action, Policy};

/// Options of `ips-test`.
#[derive(Debug)]
pub struct TestArgs {
    pub policy: PathBuf,
    pub alerts: PathBuf,
    pub expect: Option<PathBuf>,
    pub never: Option<PathBuf>,
    pub allow_private: bool,
    pub default_action: Action,
    pub ttl: u64,
}

/// Read `ips-test` options.
pub fn parse_test_args(args: &[String]) -> Result<TestArgs, String> {
    let (mut policy, mut alerts, mut expect, mut never) = (None, None, None, None);
    let (mut allow_private, mut default_action, mut ttl) = (false, Action::Alert, 600_u64);
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        if flag == "--allow-private" {
            allow_private = true;
            continue;
        }
        let Some(value) = iter.next() else {
            return Err(format!("{flag} needs a value"));
        };
        match flag.as_str() {
            "--policy" => policy = Some(PathBuf::from(value)),
            "--alerts" => alerts = Some(PathBuf::from(value)),
            "--expect" => expect = Some(PathBuf::from(value)),
            "--never" => never = Some(PathBuf::from(value)),
            "--ttl" => ttl = value.parse().map_err(|_| format!("--ttl {value:?}"))?,
            "--default" => default_action = default_of(value)?,
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    Ok(TestArgs {
        policy: policy.ok_or_else(|| String::from("--policy is required"))?,
        alerts: alerts.ok_or_else(|| String::from("--alerts is required"))?,
        expect,
        never,
        allow_private,
        default_action,
        ttl,
    })
}

/// The action named by `--ips-default` / `--default`.
pub fn default_of(text: &str) -> Result<Action, String> {
    match text {
        "drop" => Ok(Action::Drop { ttl: None }),
        "alert" => Ok(Action::Alert),
        "ignore" => Ok(Action::Ignore),
        other => Err(format!("--default {other:?} is not drop, alert or ignore")),
    }
}

fn read(path: &PathBuf) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn expected_events(text: &str) -> Result<Vec<String>, String> {
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("expect line {}: {e}", index + 1))?;
        let Some(event) = value.get("event").and_then(|e| e.as_str()) else {
            return Err(format!("expect line {} has no \"event\"", index + 1));
        };
        events.push(event.to_owned());
    }
    Ok(events)
}

/// Run `ips-test`. Prints one line per alert; returns the exit code.
pub fn run(args: &TestArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(why) => {
            eprintln!("packetdeath: [error] ips-test: {why}");
            2
        }
    }
}

fn run_inner(args: &TestArgs) -> Result<i32, String> {
    let (policy, dropped) = Policy::parse(&read(&args.policy)?);
    if dropped > 0 {
        eprintln!("packetdeath: [warn] ips-test: {dropped} policy line(s) could not be read");
    }
    let mut never = Protected::new(args.allow_private, Vec::new());
    if let Some(path) = &args.never {
        never = never.with_listed(&read(path)?);
    }
    let mut engine = Engine {
        policy,
        never,
        escalator: Escalator::new(4096),
        drops: DropSet::new(4096),
        default_action: args.default_action,
        default_ttl: args.ttl,
    };
    let wanted = match &args.expect {
        Some(path) => Some(expected_events(&read(path)?)?),
        None => None,
    };
    let name = args.alerts.display().to_string();
    let mut seen = 0_usize;
    let mut wrong = 0_usize;
    for (index, line) in read(&args.alerts)?.lines().enumerate() {
        let Some(alert) = alert_of(line) else {
            continue;
        };
        let outcome = engine.handle(&alert, seen as u64);
        let got = outcome.event.as_str();
        println!("{name}:{}: {got} sid={} rule={:?} ttl={:?}", index + 1, alert.sid, outcome.rule, outcome.ttl);
        if let Some(events) = &wanted {
            if events.get(seen).map(String::as_str) != Some(got) {
                wrong += 1;
                eprintln!("{name}:{}: expected {:?}, got {got}", index + 1, events.get(seen));
            }
        }
        seen += 1;
    }
    if let Some(events) = &wanted {
        if events.len() != seen {
            eprintln!("packetdeath: [error] ips-test: {} expected result(s) for {seen} alert(s)", events.len());
            return Ok(1);
        }
    }
    Ok(i32::from(wrong > 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_read_and_the_required_ones_are_enforced() {
        let args: Vec<String> = ["--policy", "p", "--alerts", "a", "--default", "drop", "--ttl", "30", "--allow-private"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let parsed = parse_test_args(&args);
        assert!(parsed.as_ref().is_ok_and(|t| t.allow_private && t.ttl == 30));
        assert!(parse_test_args(&[]).is_err());
        assert!(parse_test_args(&["--policy".to_owned()]).is_err());
        assert!(parse_test_args(&["--bogus".to_owned(), "x".to_owned()]).is_err());
        assert!(default_of("explode").is_err());
    }

    #[test]
    fn expected_events_are_read_one_per_line() {
        assert_eq!(expected_events("{\"event\":\"drop\"}\n\n{\"event\":\"observed\"}\n"), Ok(vec![String::from("drop"), String::from("observed")]));
        assert!(expected_events("{\"nope\":1}").is_err());
        assert!(expected_events("garbage").is_err());
    }
}
