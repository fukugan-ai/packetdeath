//! The baseline rules in `webapp/deploy/baseline/` pass the console's own validators.

use std::path::{Path, PathBuf};

use packetdeath_webapp::settings::{Store, KINDS};

type Fault = Box<dyn std::error::Error>;

const BASELINE: &[&str] = &["ips-policy", "ips-never", "ids-sids", "waf-rules", "waf-exclusions", "waf-allow-ip", "waf-deny-ip", "waf-trusted"];

fn baseline_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy").join("baseline")
}

fn scratch(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("baseline-test").join(format!("{}-{name}", std::process::id()))
}

#[test]
fn every_baseline_file_is_saved_by_the_console_store_without_a_complaint() -> Result<(), Fault> {
    let dir = scratch("all");
    std::fs::create_dir_all(&dir)?;
    let store = Store::open(&dir)?;
    for id in BASELINE {
        let Some(kind) = KINDS.iter().find(|k| k.id == *id) else {
            return Err(format!("no setting kind called {id}").into());
        };
        let text = std::fs::read_to_string(baseline_dir().join(kind.file))?;
        store.save(id, &text, 1).map_err(|e| format!("{id}: {e:?}"))?;
        assert_eq!(store.read(id).map_err(|e| format!("{id}: {e:?}"))?, text, "{id} did not round-trip");
    }
    Ok(())
}

#[test]
fn the_baseline_policy_drops_severity_one_and_never_drops_a_public_resolver() -> Result<(), Fault> {
    let policy = std::fs::read_to_string(baseline_dir().join("ips-policy.jsonl"))?;
    assert!(policy.lines().next().is_some_and(|first| first.contains("\"severity_max\":1") && first.contains("\"drop\"")), "{policy}");
    assert!(policy.lines().last().is_some_and(|last| last.contains("\"alert\"")), "the last rule must only observe");
    let never = std::fs::read_to_string(baseline_dir().join("ips-never.txt"))?;
    assert!(never.lines().any(|line| line == "8.8.8.8/32") && never.lines().any(|line| line == "1.1.1.1/32"), "{never}");
    Ok(())
}

#[test]
fn a_file_the_baseline_does_not_ship_is_a_missing_file_not_a_pass() {
    assert!(std::fs::read_to_string(baseline_dir().join("no-such-rule.txt")).is_err());
}
