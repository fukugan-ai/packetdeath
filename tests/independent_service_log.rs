//! Measures the process-wide `service.log` redirect (`flow::redirect_service_log`)
//! in its own process, and that opening a sink in a missing directory fails
//! without creating it.
//! No panicking unwraps: each test returns `Result<(), Box<dyn Error>>` and uses `?`.
//! Scratch files live under `tests/tmp-independent-service-log/`, one name per test.

use packetdeath::flow::{redirect_service_log, service_log, ServiceLog};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

/// A scratch path for `name`, with the directory created and any older file removed.
fn scratch_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/tmp-independent-service-log");
    fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(path)
}

/// The only test that touches the process-wide sink.
#[test]
fn service_log_lines_reach_the_redirected_file() -> TestResult {
    let path = scratch_path("redirected.log")?;
    let log = ServiceLog::open(&path, None)?;
    assert!(redirect_service_log(log));

    service_log("packetdeath: [info] via global one");
    service_log("packetdeath: [debug] via global dropped");
    service_log("packetdeath: [warn] via global two");

    let content = fs::read_to_string(&path)?;
    assert_eq!(content.lines().count(), 2, "{content:?}");
    assert!(!content.contains("dropped"), "{content:?}");
    let expected = [
        "packetdeath: [info] via global one",
        "packetdeath: [warn] via global two",
    ];
    for (line, want) in content.lines().zip(expected) {
        let (_, body) = line
            .split_once(' ')
            .ok_or_else(|| format!("no space in {line:?}"))?;
        assert_eq!(body, want);
    }

    let second_path = scratch_path("redirected-second.log")?;
    let second = ServiceLog::open(&second_path, None)?;
    assert!(!redirect_service_log(second));
    Ok(())
}

#[test]
fn service_log_open_on_a_missing_dir_fails_without_panic() -> TestResult {
    // The parent exists; only the leaf directory is missing.
    let dir = scratch_path("missing-dir-probe.log")?.with_file_name("does-not-exist");
    let path = dir.join("service.log");
    assert!(ServiceLog::open(&path, None).is_err());
    assert!(!dir.exists());
    Ok(())
}
