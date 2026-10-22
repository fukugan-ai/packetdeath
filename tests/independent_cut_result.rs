//! Measures, in its own process, that a `SetTcpEntry` return other than zero reaches
//! the process-wide `service.log` as one `[warn]` line (`flow::redirect_service_log`),
//! and that a zero return writes none.
//! No panicking unwraps: the test returns `Result<(), Box<dyn Error>>` and uses `?`.
//! Scratch files live under `tests/tmp-independent-cut-result/`.

#[cfg(unix)]
use packetdeath::block_loop::{RespawningPsBridge, TcpBlocker};
#[cfg(unix)]
use packetdeath::flow::{redirect_service_log, ServiceLog};
#[cfg(unix)]
use packetdeath::ps_bridge::PsBridge;
#[cfg(unix)]
use packetdeath::windows::TcpRowSpec;
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
type TestResult = Result<(), Box<dyn Error>>;

/// Words that only the cut-rejected line carries, in Japanese and in English.
#[cfg(unix)]
const REJECTED_WORDS: [&str; 2] = ["切らなかった", "did not cut"];

/// A scratch path for `name`, with the directory created and any older file removed.
#[cfg(unix)]
fn scratch_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/tmp-independent-cut-result");
    fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(path)
}

/// Warm-up answers `rc=317`, the first row `rc=0`, every later row `rc=317`.
#[cfg(unix)]
fn child(_: &Path) -> std::io::Result<PsBridge> {
    PsBridge::spawn(
        "sh",
        &[
            "-c",
            "read l; echo 'rc=317 us=1.0'; read l; echo 'rc=0 us=1.0'; while read l; do echo 'rc=317 us=1.0'; done",
        ],
    )
}

/// The lines of `path` that carry one of [`REJECTED_WORDS`].
#[cfg(unix)]
fn rejected_lines(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter(|line| REJECTED_WORDS.iter().any(|word| line.contains(word)))
        .map(str::to_owned)
        .collect())
}

/// The only test that touches the process-wide sink.
#[cfg(unix)]
#[test]
fn cut_result_reaches_the_service_log() -> TestResult {
    let path = scratch_path("service.log")?;
    assert!(redirect_service_log(ServiceLog::open(&path, None)?));

    let mut blocker = RespawningPsBridge::with_spawner(
        PathBuf::from("unused"),
        child,
        Duration::from_secs(5),
        Duration::from_secs(60),
    );
    let row = TcpRowSpec {
        local_addr: 1,
        local_port: 2,
        remote_addr: 3,
        remote_port: 4,
    };

    assert!(blocker.try_block(&row));
    assert_eq!(rejected_lines(&path)?.len(), 0);

    assert!(!blocker.try_block(&row));
    let rejected = rejected_lines(&path)?;
    assert_eq!(rejected.len(), 1, "{rejected:?}");
    assert!(rejected[0].contains("[warn]"), "{rejected:?}");
    assert!(rejected[0].contains("rc=317"), "{rejected:?}");
    Ok(())
}
