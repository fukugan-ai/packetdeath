//! Stage 11: the reverse proxy. `packetdeath waf`.
//!
//! `docs/design.md` "段階11 WAF". One thread per client connection, many
//! requests per connection. This file owns the socket, the connection table and
//! the head of each request; `carry.rs` owns what happens to a request whose
//! head has been read.
//!
//! A panic while judging lets the request through and says so
//! (`engine_error`); anything else the WAF cannot do ends the request with an
//! error status or closes the connection. The process does not stop for a
//! request.

use std::io::{self, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::flow::service_log;

use super::audit::AuditLog;
use super::carry::{carry_request, refuse_head, Parsed};
use super::config::{Settings, BODY_IDLE, HEAD_TIMEOUT};
use super::forward::{respond, DeadlineReader};
use super::http::{parse_request_line, read_head, request_framing};
use super::limits::{LimitConfig, Limiter};
use super::live::{spawn_watcher, Live};
use super::request::head_failure;

/// Blocks inside this window count toward `--ban-after`.
const BAN_WINDOW_MS: u64 = 60_000;

/// Set by a test to make the next judgment panic (fail-open is then observable).
/// Nothing a client sends can set it.
#[doc(hidden)]
pub static PANIC_NEXT: AtomicBool = AtomicBool::new(false);

/// Everything the connection threads share.
pub struct Shared {
    pub(super) settings: Settings,
    pub(super) live: Arc<Live>,
    pub(super) audit: AuditLog,
    pub(super) limiter: Mutex<Limiter>,
    pub(super) conns: AtomicUsize,
    pub(super) started_secs: u64,
    pub(super) clock: Instant,
}

/// What a connection does after a request.
pub enum Next {
    KeepAlive,
    Close,
}

/// The client side of a connection.
pub type Reader = BufReader<DeadlineReader<TcpStream>>;

/// A running server.
pub struct Running {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Running {
    /// Stop accepting and wait for the accept loop to end. Requests in flight
    /// finish on their own threads.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // The accept loop blocks in accept; a connection to ourselves wakes it.
        let mut wake = self.addr;
        if wake.ip().is_unspecified() {
            wake.set_ip(match wake.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            });
        }
        // A refused connection means the loop is already gone.
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(1));
        if let Some(thread) = self.thread.take() {
            // A join error means the accept thread panicked; there is nothing left to stop.
            let _ = thread.join();
        }
    }

    /// Wait for the server to end (it ends only if the accept loop does).
    pub fn wait(mut self) {
        if let Some(thread) = self.thread.take() {
            // A join error means the accept thread panicked; the process then exits.
            let _ = thread.join();
        }
    }
}

fn set_read_timeout(stream: &TcpStream, limit: Option<Duration>) -> io::Result<()> {
    stream.set_read_timeout(limit)
}

fn limit_config(settings: &Settings) -> LimitConfig {
    LimitConfig {
        rate: settings.rate,
        ban_after: settings.ban_after,
        ban_window_ms: BAN_WINDOW_MS,
        ban_ttl_ms: settings.ban_ttl_secs.saturating_mul(1000),
        cap: settings.max_tracked_ips,
    }
}

fn now_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| e.to_string())
}

/// Open the socket, read the inputs and start accepting.
pub fn start(settings: Settings) -> Result<Running, String> {
    let live = Arc::new(Live::start(&settings)?);
    let audit = AuditLog::open(&settings.log_dir).map_err(|e| e.to_string())?;
    let listener = TcpListener::bind(settings.listen).map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    spawn_watcher(Arc::clone(&live));
    let shared = Arc::new(Shared {
        limiter: Mutex::new(Limiter::new(limit_config(&settings))),
        settings,
        live,
        audit,
        conns: AtomicUsize::new(0),
        started_secs: now_secs()?,
        clock: Instant::now(),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let thread = std::thread::spawn(move || accept_loop(&listener, &shared, &flag));
    Ok(Running {
        addr,
        stop,
        thread: Some(thread),
    })
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                // The wake-up connection from `stop` arrives with the flag set.
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                admit(shared, stream, peer);
            }
            Err(e) => {
                service_log(&format!("packetdeath: [warn] waf accept: {e}"));
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Counts a connection while it lives.
struct ConnGuard(Arc<Shared>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Take a connection, or turn it away with 503 when the table is full.
fn admit(shared: &Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    let before = shared.conns.fetch_add(1, Ordering::SeqCst);
    let guard = ConnGuard(Arc::clone(shared));
    if before >= shared.settings.max_conns {
        turn_away(stream);
        return;
    }
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let shared = Arc::clone(shared);
    let spawned = std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(move || {
            let _guard = guard;
            serve(&shared, stream, peer);
        });
    if let Err(e) = spawned {
        service_log(&format!("packetdeath: [warn] waf thread: {e}"));
    }
}

fn turn_away(mut stream: TcpStream) {
    if stream.set_write_timeout(Some(Duration::from_secs(2))).is_ok() {
        // The peer may already be gone; the answer is a courtesy.
        let _ = respond(&mut stream, 503, "-", &[], false);
    }
}

fn serve(shared: &Shared, stream: TcpStream, peer: SocketAddr) {
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    if writer
        .set_write_timeout(Some(Duration::from_secs(30)))
        .is_err()
    {
        return;
    }
    let mut reader = BufReader::new(DeadlineReader::new(stream, set_read_timeout));
    let mut first = true;
    while let Next::KeepAlive = serve_one(shared, &mut reader, &mut writer, peer, first) {
        first = false;
    }
}

fn begin_head(reader: &mut Reader) {
    reader
        .get_mut()
        .set_deadline(Some(Instant::now() + HEAD_TIMEOUT));
}

fn begin_body(reader: &mut Reader) -> io::Result<()> {
    reader.get_mut().set_deadline(None);
    reader.get_ref().get_ref().set_read_timeout(Some(BODY_IDLE))
}

/// Read one request head and hand the request on.
fn serve_one(
    shared: &Shared,
    reader: &mut Reader,
    writer: &mut TcpStream,
    peer: SocketAddr,
    first: bool,
) -> Next {
    begin_head(reader);
    let head = match read_head(reader) {
        Ok(head) => head,
        Err(error) => {
            if let Some((status, flag)) = head_failure(&error, first) {
                refuse_head(shared, writer, peer, status, flag);
            }
            return Next::Close;
        }
    };
    if begin_body(reader).is_err() {
        return Next::Close;
    }
    let line = match parse_request_line(&head.first) {
        Ok(line) => line,
        Err(error) => {
            if let Some((status, flag)) = head_failure(&error, true) {
                refuse_head(shared, writer, peer, status, flag);
            }
            return Next::Close;
        }
    };
    let framing = match request_framing(&head, shared.settings.max_body) {
        Ok(framing) => framing,
        Err(refused) => {
            refuse_head(shared, writer, peer, refused.status, refused.flag);
            return Next::Close;
        }
    };
    let parsed = Parsed {
        head: &head,
        line: &line,
        framing,
    };
    carry_request(shared, reader, writer, peer, &parsed)
}

/// Start the server and run until the process ends.
pub fn run(settings: Settings) -> Result<(), String> {
    let running = start(settings)?;
    service_log(&format!(
        "packetdeath: [info] waf listening on {}",
        running.addr
    ));
    running.wait();
    Ok(())
}
