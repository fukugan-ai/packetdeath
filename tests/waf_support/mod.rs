//! Shared pieces for the WAF socket tests: a small upstream, a way to start the
//! WAF on a free port, and a raw HTTP round trip.
//!
//! Each test crate that includes this module uses a part of it.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use packetdeath::waf::config::parse_waf_args;
use packetdeath::waf::server::{start, Running};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

static SERIAL: Mutex<()> = Mutex::new(());

/// Every socket test holds this: the panic injection is process-wide.
pub fn serial() -> MutexGuard<'static, ()> {
    match SERIAL.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// A scratch directory that is empty.
pub fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("waf-{name}-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// An upstream that answers `ok` to everything and counts what reached it.
pub struct Upstream {
    pub port: u16,
    pub seen: Arc<AtomicUsize>,
    pub last_head: Arc<Mutex<String>>,
}

fn read_request(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&chunk[..n]);
    }
    Some(String::from_utf8_lossy(&data).into_owned())
}

pub fn upstream() -> Result<Upstream, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let seen = Arc::new(AtomicUsize::new(0));
    let last_head = Arc::new(Mutex::new(String::new()));
    let (count, last) = (Arc::clone(&seen), Arc::clone(&last_head));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (count, last) = (Arc::clone(&count), Arc::clone(&last));
            std::thread::spawn(move || {
                let Some(head) = read_request(&mut stream) else { return };
                count.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut slot) = last.lock() {
                    *slot = head;
                }
                let reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                // The WAF may have given up on this connection already.
                let _ = stream.write_all(reply.as_bytes());
            });
        }
    });
    Ok(Upstream { port, seen, last_head })
}

/// Start the WAF in front of `upstream_port` with extra options.
pub fn waf(upstream_port: u16, log_dir: &Path, extra: &str) -> Result<Running, Box<dyn std::error::Error>> {
    let line = format!(
        "--listen 127.0.0.1:0 --upstream 127.0.0.1:{upstream_port} --log-dir {} {extra}",
        log_dir.display()
    );
    let args: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
    let settings = parse_waf_args(&args)?;
    Ok(start(settings)?)
}

/// What came back from one raw exchange.
pub struct Reply {
    pub status: u16,
    pub text: String,
}

/// Send `raw`, read until the server closes, and return the status and text.
pub fn exchange(addr: SocketAddr, raw: &[u8]) -> Result<Reply, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.write_all(raw)?;
    let mut data = Vec::new();
    // The WAF closes after an answer it will not follow with another.
    let _ = stream.read_to_end(&mut data);
    let text = String::from_utf8_lossy(&data).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .ok_or("no status line in the reply")?
        .parse::<u16>()?;
    Ok(Reply { status, text })
}

/// A GET with `Connection: close`.
pub fn get(addr: SocketAddr, target: &str) -> Result<Reply, Box<dyn std::error::Error>> {
    let raw = format!("GET {target} HTTP/1.1\r\nHost: t.test\r\nConnection: close\r\n\r\n");
    exchange(addr, raw.as_bytes())
}

/// The parsed lines of `waf.jsonl`, waiting until there are at least `n`.
pub fn audit_lines(dir: &Path, n: usize) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let text = std::fs::read_to_string(dir.join("waf.jsonl"))?;
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        if lines.len() >= n || Instant::now() > deadline {
            return Ok(lines);
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}
