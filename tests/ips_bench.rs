//! Stage 12 acceptance PK-181: a flood of alerts neither grows memory nor slows
//! the judge's lookup. `docs/design.md` "段階12 IDS/IPS の業務水準化" 受入 ID.
//!
//! It is `#[ignore]` because a debug build says nothing about speed:
//!
//! ```text
//! cargo test --release --test ips_bench -- --ignored --nocapture
//! ```
//!
//! 100000 alert lines, one of them over 1 MiB, are written to `eve.json` at
//! once. While the runtime works through them (8 MiB per poll), another thread
//! asks the packet judge's set whether a destination is dropped, and the
//! resident memory is compared before and after.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use packetdeath::ids::IdsDropSet;
use packetdeath::ips::policy::Action;
use packetdeath::ips::runtime::{Config, Runtime};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ALERTS: usize = 100_000;

fn scratch() -> Result<PathBuf, std::io::Error> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("ips-bench-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn resident_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).ok_or("no VmRSS line")?;
    let kib = line.split_whitespace().nth(1).ok_or("no VmRSS value")?;
    Ok(kib.parse()?)
}

fn alert(n: usize) -> String {
    let (a, b) = (n / 250 % 250, n % 250);
    format!("{{\"event_type\":\"alert\",\"src_ip\":\"192.168.1.20\",\"dest_ip\":\"198.51.{a}.{b}\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{{\"signature_id\":{},\"severity\":1,\"category\":\"Trojan\"}}}}\n", 1 + n % 7)
}

#[test]
#[ignore = "a speed and memory measurement; run with --release --ignored"]
fn pk181_a_flood_stays_inside_the_memory_bound_and_the_lookup_stays_fast() -> TestResult {
    let dir = scratch()?;
    std::fs::write(dir.join("policy.jsonl"), "{\"action\":\"drop\",\"ttl\":3000}\n")?;
    let mut eve = std::fs::File::create(dir.join("eve.json"))?;
    for n in 0..ALERTS {
        eve.write_all(alert(n).as_bytes())?;
        if n == ALERTS / 2 {
            eve.write_all(format!("{}\n", "x".repeat(1_200_000)).as_bytes())?;
        }
    }
    eve.sync_all()?;
    let sink = Arc::new(IdsDropSet::new());
    let cfg = Config {
        eve: dir.join("eve.json"),
        policy: dir.join("policy.jsonl"),
        never: None,
        allow_private: false,
        default_action: Action::Alert,
        default_ttl: 600,
        log_dir: Some(dir.clone()),
        state: None,
        max_entries: 16384,
        max_read: 8 * 1024 * 1024,
        stale_after: 900,
    };
    let mut rt = Runtime::start(cfg, Arc::clone(&sink))?;
    let before = resident_kib()?;

    let done = Arc::new(AtomicBool::new(false));
    let (look_sink, look_done) = (Arc::clone(&sink), Arc::clone(&done));
    let looker = std::thread::spawn(move || -> Result<Vec<Duration>, String> {
        let ip: IpAddr = "198.51.0.1".parse().map_err(|_| String::from("ip"))?;
        // One sample per 1024 lookups, the slowest of them: the figure below is
        // then harsher than a p99 of every lookup, and the sample list stays small.
        let mut took = Vec::new();
        while !look_done.load(Ordering::Relaxed) {
            let mut slowest = Duration::ZERO;
            for _ in 0..1024 {
                let started = Instant::now();
                look_sink.contains(&ip, 443, Instant::now());
                slowest = slowest.max(started.elapsed());
            }
            took.push(slowest);
        }
        Ok(took)
    });

    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    for poll in 0..40 {
        rt.tick(started + poll);
    }
    let after = resident_kib()?;
    done.store(true, Ordering::Relaxed);
    let mut took = looker.join().map_err(|_| "the lookup thread panicked")??;
    took.sort();
    let p99 = took[(took.len() * 99 / 100).min(took.len() - 1)];
    let grew = after.saturating_sub(before);
    println!("lookups {}  p99 {p99:?}  VmRSS before {before} KiB, after {after} KiB, grew {grew} KiB", took.len());

    let log = std::fs::read_to_string(dir.join("ips.jsonl"))?;
    assert!(log.contains("\"event\":\"skipped\""), "the oversized line was not counted");
    assert!(grew < 64 * 1024, "grew {grew} KiB");
    assert!(p99 < Duration::from_millis(1), "p99 {p99:?}");
    Ok(())
}
