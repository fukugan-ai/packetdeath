//! Stage 11 acceptance PK-163 and the command line of `waf-test` / `waf-report`,
//! through the built binary. `docs/design.md` "段階11 WAF" 受入 ID.

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
fn pk163_the_report_counts_actions_rules_sources_and_names_a_false_positive() -> TestResult {
    let dir = repo("tests/waf/fixture-log");
    let out = run(&["waf-report", "--log-dir", &dir])?;
    assert_eq!(out.status.code(), Some(0));
    let said = text(&out.stdout);
    assert!(said.contains("requests 10"), "{said}");
    assert!(said.contains("blocked 20.0%"), "{said}");
    assert!(said.contains("detect     6"), "{said}");
    assert!(said.contains("block      2"), "{said}");
    assert!(said.contains("942170"), "{said}");
    assert!(said.contains("198.51.100.7"), "{said}");
    assert!(
        said.contains("rule 942170 on /api/search  6 hits from 6 sources"),
        "{said}"
    );
    Ok(())
}

#[test]
fn pk163_since_leaves_out_the_older_line() -> TestResult {
    let dir = repo("tests/waf/fixture-log");
    let out = run(&["waf-report", "--log-dir", &dir, "--since", "2026-10-28"])?;
    assert!(text(&out.stdout).contains("requests 9"), "{}", text(&out.stdout));
    Ok(())
}

#[test]
fn pk163_negative_control_a_missing_log_is_an_error() -> TestResult {
    let out = run(&["waf-report", "--log-dir", "/nonexistent-waf-log-4f9a"])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("waf-report"));
    Ok(())
}

#[test]
fn waf_test_exits_0_on_the_project_corpora_and_1_on_a_wrong_expectation() -> TestResult {
    for name in ["attacks", "benign", "evasions", "bodies"] {
        let corpus = repo(&format!("tests/waf/{name}.jsonl"));
        let out = run(&["waf-test", "--corpus", &corpus])?;
        assert_eq!(out.status.code(), Some(0), "{name}: {}", text(&out.stdout));
    }
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("waf-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let wrong = dir.join("wrong.jsonl");
    std::fs::write(
        &wrong,
        "{\"method\":\"GET\",\"path\":\"/\",\"query\":\"q=1+union+select+2\",\"expect\":\"pass\"}\n",
    )?;
    let out = run(&["waf-test", "--corpus", &wrong.display().to_string()])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stdout).contains("wrong.jsonl:1:"), "{}", text(&out.stdout));
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[test]
fn the_waf_command_refuses_to_start_without_its_required_options() -> TestResult {
    let out = run(&["waf", "--listen", "127.0.0.1:0"])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("--upstream"), "{}", text(&out.stderr));
    Ok(())
}
