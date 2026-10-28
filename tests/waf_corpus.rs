//! Stage 11 acceptance PK-152, 153 and the judge half of 154: the corpora run
//! through the same judge the server uses, without a socket.
//! `docs/design.md` "段階11 WAF" 受入 ID.

use packetdeath::waf::engine::Policy;
use packetdeath::waf::rules::RuleSet;
use packetdeath::waf::testcmd::{run_corpus, Report};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const POLICY: Policy = Policy {
    paranoia: 1,
    threshold: 5,
};

fn run(name: &str) -> Result<Report, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("waf")
        .join(name);
    let text = std::fs::read_to_string(path)?;
    Ok(run_corpus(&text, &RuleSet::builtin_only()?, POLICY, &[]))
}

fn assert_clean(name: &str, report: &Report) {
    assert!(
        report.passed(),
        "{name}: mismatches {:?}, unreadable {:?}",
        report.mismatches,
        report.bad_lines
    );
}

#[test]
fn pk152_the_attack_corpus_blocks_every_line_and_is_big_enough() -> TestResult {
    let report = run("attacks.jsonl")?;
    assert_clean("attacks", &report);
    assert!(report.total >= 60, "{} lines", report.total);
    Ok(())
}

#[test]
fn pk152_the_benign_corpus_passes_every_line_and_is_big_enough() -> TestResult {
    let report = run("benign.jsonl")?;
    assert_clean("benign", &report);
    assert!(report.total >= 100, "{} lines", report.total);
    Ok(())
}

#[test]
fn pk153_the_evasion_corpus_blocks_every_line() -> TestResult {
    let report = run("evasions.jsonl")?;
    assert_clean("evasions", &report);
    assert!(report.total >= 25, "{} lines", report.total);
    Ok(())
}

#[test]
fn pk154_the_body_corpus_matches() -> TestResult {
    let report = run("bodies.jsonl")?;
    assert_clean("bodies", &report);
    Ok(())
}

/// The negative control: a corpus line that expects the wrong thing is found.
#[test]
fn the_runner_does_find_a_wrong_expectation() -> TestResult {
    let wrong = "{\"method\":\"GET\",\"path\":\"/\",\"query\":\"q=1+union+select+2\",\"expect\":\"pass\"}\n";
    let report = run_corpus(wrong, &RuleSet::builtin_only()?, POLICY, &[]);
    assert_eq!(report.mismatches.len(), 1);
    Ok(())
}
