//! Stage 11 acceptance PK-161: what the WAF adds to a request, and whether it
//! grows. `docs/design.md` "段階11 WAF" 受入 ID.
//!
//! It is `#[ignore]` because a debug build says nothing about speed. Run it
//! the way the design says:
//!
//! ```text
//! cargo test --release --test waf_bench -- --ignored --nocapture
//! ```
//!
//! The same client sends the same 1 KiB request straight to the upstream and
//! through the WAF, 10000 each, 16 at a time. The result is the difference of
//! the two p99 values, and the difference of the process's resident memory.

mod waf_support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use waf_support::{exchange, scratch, serial, upstream, waf, TestResult};

const REQUESTS: usize = 10_000;
const THREADS: usize = 16;

fn request() -> String {
    format!(
        "GET /search?q={} HTTP/1.1\r\nHost: bench.test\r\nUser-Agent: bench\r\nConnection: close\r\n\r\n",
        "a".repeat(900)
    )
}

fn phase(addr: SocketAddr) -> Result<Vec<Duration>, Box<dyn std::error::Error>> {
    let raw = Arc::new(request());
    let samples = Arc::new(Mutex::new(Vec::with_capacity(REQUESTS)));
    let mut workers = Vec::new();
    for _ in 0..THREADS {
        let (raw, samples) = (Arc::clone(&raw), Arc::clone(&samples));
        workers.push(std::thread::spawn(move || -> Result<(), String> {
            for _ in 0..REQUESTS / THREADS {
                let started = Instant::now();
                let reply = exchange(addr, raw.as_bytes()).map_err(|e| e.to_string())?;
                if reply.status != 200 {
                    return Err(format!("status {}", reply.status));
                }
                let took = started.elapsed();
                samples.lock().map_err(|_| String::from("lock"))?.push(took);
            }
            Ok(())
        }));
    }
    for worker in workers {
        worker.join().map_err(|_| "a worker panicked")??;
    }
    let mut taken = samples.lock().map_err(|_| "lock")?.clone();
    taken.sort();
    Ok(taken)
}

fn percentile(sorted: &[Duration], per_mille: usize) -> Duration {
    let last = sorted.len().saturating_sub(1);
    sorted[(sorted.len() * per_mille / 1000).min(last)]
}

fn resident_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .ok_or("no VmRSS line")?;
    let kib = line.split_whitespace().nth(1).ok_or("no VmRSS value")?;
    Ok(kib.parse()?)
}

#[test]
#[ignore = "a speed measurement; run with --release --ignored"]
fn pk161_the_waf_adds_less_than_5_ms_at_p99_and_does_not_grow() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk161")?);
    let up_addr: SocketAddr = format!("127.0.0.1:{}", up.port).parse()?;
    let running = waf(up.port, &dir, "--mode block")?;

    // Warm both paths, then measure.
    phase(up_addr)?;
    phase(running.addr)?;
    let direct = phase(up_addr)?;
    let before = resident_kib()?;
    let through = phase(running.addr)?;
    let after = resident_kib()?;

    let (d99, w99) = (percentile(&direct, 990), percentile(&through, 990));
    let (d50, w50) = (percentile(&direct, 500), percentile(&through, 500));
    let grew_kib = after.saturating_sub(before);
    println!("direct  p50 {d50:?} p99 {d99:?}");
    println!("via waf p50 {w50:?} p99 {w99:?}");
    println!("added   p50 {:?} p99 {:?}", w50.saturating_sub(d50), w99.saturating_sub(d99));
    println!("VmRSS before {before} KiB, after {after} KiB, grew {grew_kib} KiB");

    assert!(w99.saturating_sub(d99) < Duration::from_millis(5), "added p99 {:?}", w99.saturating_sub(d99));
    assert!(grew_kib < 8 * 1024, "grew {grew_kib} KiB");
    running.stop();
    Ok(())
}
