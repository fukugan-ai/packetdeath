//! Stage 12 acceptance PK-171 through the built binary. `docs/design.md`
//! "段階12 IDS/IPS の業務水準化" 受入 ID.

use std::path::Path;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run(args: &[&str]) -> Result<Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_packetdeath")).args(args).output()
}

fn text(out: &[u8]) -> String {
    String::from_utf8_lossy(out).into_owned()
}

fn repo(relative: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative).display().to_string()
}

#[test]
fn pk171_the_policy_gives_the_expected_action_for_every_alert() -> TestResult {
    let (p, a, e) = (repo("tests/ids/policy.jsonl"), repo("tests/ids/alerts.jsonl"), repo("tests/ids/expect.jsonl"));
    let out = run(&["ips-test", "--policy", &p, "--alerts", &a, "--expect", &e])?;
    let said = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{said}{}", text(&out.stderr));
    for want in ["ignored sid=100 rule=Some(2)", "drop sid=250 rule=Some(3) ttl=Some(60)", "escalated sid=500", "protected sid=250"] {
        assert!(said.contains(want), "{want}\n{said}");
    }
    assert_eq!(said.lines().count(), 8, "{said}");
    Ok(())
}

#[test]
fn pk171_negative_control_a_wrong_expectation_is_named_by_line_and_exits_1() -> TestResult {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("ips-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let wrong = dir.join("wrong.jsonl");
    let good = std::fs::read_to_string(repo("tests/ids/expect.jsonl"))?;
    std::fs::write(&wrong, good.replacen("\"drop\"", "\"observed\"", 1))?;
    let (p, a) = (repo("tests/ids/policy.jsonl"), repo("tests/ids/alerts.jsonl"));
    let out = run(&["ips-test", "--policy", &p, "--alerts", &a, "--expect", &wrong.display().to_string()])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("alerts.jsonl:2: expected"), "{}", text(&out.stderr));
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn allow_private_releases_a_private_destination_but_not_loopback() -> TestResult {
    let (p, a) = (repo("tests/ids/policy.jsonl"), repo("tests/ids/alerts.jsonl"));
    let kept = text(&run(&["ips-test", "--policy", &p, "--alerts", &a])?.stdout);
    assert!(kept.contains("protected sid=250"), "{kept}");
    let freed = text(&run(&["ips-test", "--policy", &p, "--alerts", &a, "--allow-private"])?.stdout);
    assert!(!freed.contains("protected"), "{freed}");
    Ok(())
}

#[test]
fn pk180_the_report_counts_events_names_observed_only_signatures_and_protected_destinations() -> TestResult {
    let dir = repo("tests/ids/fixture-log");
    let out = run(&["ips-report", "--log-dir", &dir])?;
    assert_eq!(out.status.code(), Some(0));
    let said = text(&out.stdout);
    assert!(said.contains("lines 6  unreadable 0"), "{said}");
    assert!(said.contains("drop       2") && said.contains("observed   2") && said.contains("protected  1"), "{said}");
    assert!(said.contains("sid 2001219  2"), "{said}");
    assert!(said.contains("sid 2013504  2"), "{said}");
    assert!(said.contains("192.168.1.1  1"), "{said}");
    assert!(said.contains("2026-10-28  2"), "{said}");
    let since = text(&run(&["ips-report", "--log-dir", &dir, "--since", "2026-10-28"])?.stdout);
    assert!(since.contains("lines 5"), "{since}");
    let missing = run(&["ips-report", "--log-dir", "/nonexistent-ips-log-7b2e"])?;
    assert_eq!(missing.status.code(), Some(2));
    Ok(())
}

#[test]
fn a_missing_policy_file_is_an_error_not_a_pass() -> TestResult {
    let a = repo("tests/ids/alerts.jsonl");
    let out = run(&["ips-test", "--policy", "/nonexistent-ips-policy-3c1d", "--alerts", &a])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("ips-test"));
    let none = run(&["ips-test", "--alerts", &a])?;
    assert_eq!(none.status.code(), Some(1));
    Ok(())
}
