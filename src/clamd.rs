//! Stage 8: the clamd client. `docs/design.md` "段階8 MITM", subsection
//! "clamd との会話", is the source of truth.
//!
//! One scan opens one connection: `zINSTREAM\0`, then the body in chunks of at
//! most 64 KiB, each prefixed with its length as a big-endian `u32`, then a
//! zero-length chunk. The reply is read up to its NUL and sorted into three
//! shapes: `stream: OK`, `stream: <signature> FOUND` (the signature may hold
//! spaces), and everything else (including `INSTREAM size limit exceeded.
//! ERROR`), which is an error and lets the body through (fail-open).
//!
//! Connecting, sending and waiting for the reply are all bounded by a timeout,
//! so a stuck clamd delays only the one connection being scanned.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Largest chunk sent in one INSTREAM frame.
pub const MAX_CHUNK: usize = 64 * 1024;

/// Default bound on connecting, sending and waiting for the reply of one
/// scan. It is longer than clamd's `MaxScanTime` (1134 s), so a time-out is
/// answered by clamd first (as `Heuristics.Limits.Exceeded.*`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1260);

/// clamd (with `AlertExceedsMax yes`) reports a limit it hit as a `FOUND`
/// whose signature starts with this prefix. It means "not fully scanned", not
/// "malware".
pub const UNFINISHED_PREFIX: &str = "Heuristics.Limits.Exceeded.";

/// Bound on the startup PING. It is short because `Mitm::start` runs before
/// the proxy serves, so a stuck clamd would hold up every connection.
pub const PING_TIMEOUT: Duration = Duration::from_secs(10);

/// A reply longer than this is not a clamd reply; reading stops there.
const MAX_REPLY: usize = 4096;

/// Where clamd listens: a Unix socket path or a TCP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamdAddr {
    Unix(PathBuf),
    Tcp(SocketAddr),
}

impl ClamdAddr {
    /// Reads the `--clamd` value: TCP when it contains `:` and parses as a
    /// socket address, a socket path otherwise.
    pub fn parse(value: &str) -> Self {
        if value.contains(':') {
            if let Ok(addr) = value.parse::<SocketAddr>() {
                return Self::Tcp(addr);
            }
        }
        Self::Unix(PathBuf::from(value))
    }

    /// A TCP address off this host: file bodies would cross the network in
    /// the clear, which deserves a warning at startup.
    pub fn is_remote_tcp(&self) -> bool {
        matches!(self, Self::Tcp(addr) if !addr.ip().is_loopback())
    }
}

impl fmt::Display for ClamdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "{}", path.display()),
            Self::Tcp(addr) => write!(f, "{addr}"),
        }
    }
}

/// The three shapes a clamd reply can take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Clean,
    Found(String),
    Error,
}

/// Why a scan produced no verdict. Each one lets the body through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Unreachable,
    Timeout,
    Error,
}

impl Failure {
    /// The reason word written to the log.
    pub fn as_log_str(self) -> &'static str {
        match self {
            Self::Unreachable => "clamd_unreachable",
            Self::Timeout => "clamd_timeout",
            Self::Error => "clamd_error",
        }
    }
}

/// The outcome of one scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Found(String),
    /// clamd hit one of its own limits (`UNFINISHED_PREFIX`): the body was not
    /// fully scanned. Carries the signature name. The body is let through.
    Unfinished(String),
    Failed(Failure),
}

/// Sorts the bytes clamd sent back. Anything that is not exactly
/// `stream: OK` or `stream: <signature> FOUND` up to a NUL is an error.
pub fn parse_reply(raw: &[u8]) -> Reply {
    let Some(end) = raw.iter().position(|&b| b == 0) else {
        return Reply::Error;
    };
    let Ok(text) = std::str::from_utf8(&raw[..end]) else {
        return Reply::Error;
    };
    let Some(rest) = text.strip_prefix("stream: ") else {
        return Reply::Error;
    };
    if rest == "OK" {
        return Reply::Clean;
    }
    match rest.strip_suffix(" FOUND") {
        Some(signature) if !signature.trim().is_empty() => Reply::Found(signature.to_owned()),
        _ => Reply::Error,
    }
}

/// Writes one complete INSTREAM exchange for `body`.
pub fn write_instream<W: Write>(out: &mut W, body: &[u8]) -> io::Result<()> {
    out.write_all(b"zINSTREAM\0")?;
    for chunk in body.chunks(MAX_CHUNK) {
        // A chunk is at most MAX_CHUNK (64 KiB) long, so the cast is lossless.
        out.write_all(&(chunk.len() as u32).to_be_bytes())?;
        out.write_all(chunk)?;
    }
    out.write_all(&[0, 0, 0, 0])?;
    out.flush()
}

/// Reads up to and including the first NUL, or to EOF, at most `MAX_REPLY`.
/// An interrupted read is retried because EINTR carries no data and no verdict.
fn read_reply<R: Read>(input: &mut R) -> io::Result<Vec<u8>> {
    let mut reply = Vec::with_capacity(64);
    let mut buf = [0u8; 256];
    while reply.len() < MAX_REPLY {
        let n = match input.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        reply.extend_from_slice(&buf[..n]);
        if buf[..n].contains(&0) {
            break;
        }
    }
    Ok(reply)
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The INSTREAM exchange over an already connected stream.
fn exchange<S: Read + Write>(stream: &mut S, body: &[u8]) -> Verdict {
    if let Err(e) = write_instream(stream, body) {
        if is_timeout(&e) {
            return Verdict::Failed(Failure::Timeout);
        }
        // clamd answers and hangs up when the stream breaks one of its
        // limits. Whatever it said, the scan has no verdict.
        return Verdict::Failed(Failure::Error);
    }
    match read_reply(stream) {
        Ok(raw) => match parse_reply(&raw) {
            Reply::Clean => Verdict::Clean,
            Reply::Found(signature) if signature.starts_with(UNFINISHED_PREFIX) => {
                Verdict::Unfinished(signature)
            }
            Reply::Found(signature) => Verdict::Found(signature),
            Reply::Error => Verdict::Failed(Failure::Error),
        },
        Err(e) if is_timeout(&e) => Verdict::Failed(Failure::Timeout),
        Err(_) => Verdict::Failed(Failure::Error),
    }
}

/// Opens one connection to clamd with every wait bounded by `timeout`.
fn connect(addr: &ClamdAddr, timeout: Duration) -> Result<Conn, Failure> {
    let classify = |e: io::Error| {
        if is_timeout(&e) {
            Failure::Timeout
        } else {
            Failure::Unreachable
        }
    };
    let conn = match addr {
        ClamdAddr::Unix(path) => Conn::Unix(UnixStream::connect(path).map_err(classify)?),
        ClamdAddr::Tcp(addr) => {
            Conn::Tcp(TcpStream::connect_timeout(addr, timeout).map_err(classify)?)
        }
    };
    conn.set_timeouts(timeout)
        .map_err(|_| Failure::Unreachable)?;
    Ok(conn)
}

/// A connection to clamd over either transport.
enum Conn {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Conn {
    fn set_timeouts(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Unix(s) => {
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))
            }
            Self::Tcp(s) => {
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))
            }
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Unix(s) => s.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

/// Scans `body` with clamd. Never blocks longer than about `timeout` per
/// step; every failure comes back as `Verdict::Failed`.
pub fn scan(addr: &ClamdAddr, body: &[u8], timeout: Duration) -> Verdict {
    match connect(addr, timeout) {
        Ok(mut conn) => exchange(&mut conn, body),
        Err(failure) => Verdict::Failed(failure),
    }
}

/// `zPING\0` answered by `PONG\0`. Used once at startup and waited for at most
/// `PING_TIMEOUT`; a `false` only warns.
pub fn ping(addr: &ClamdAddr, timeout: Duration) -> bool {
    let Ok(mut conn) = connect(addr, timeout) else {
        return false;
    };
    if conn.write_all(b"zPING\0").is_err() {
        return false;
    }
    matches!(read_reply(&mut conn), Ok(raw) if raw.starts_with(b"PONG\0"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    #[test]
    fn ok_is_clean() {
        assert_eq!(parse_reply(b"stream: OK\0"), Reply::Clean);
    }

    #[test]
    fn found_carries_the_signature() {
        assert_eq!(
            parse_reply(b"stream: Eicar-Test-Signature FOUND\0"),
            Reply::Found("Eicar-Test-Signature".to_owned())
        );
    }

    #[test]
    fn a_signature_may_contain_spaces() {
        assert_eq!(
            parse_reply(b"stream: Some Odd Name.UNOFFICIAL FOUND\0"),
            Reply::Found("Some Odd Name.UNOFFICIAL".to_owned())
        );
    }

    #[test]
    fn size_limit_is_an_error() {
        assert_eq!(
            parse_reply(b"INSTREAM size limit exceeded. ERROR\0"),
            Reply::Error
        );
    }

    #[test]
    fn empty_reply_is_an_error() {
        assert_eq!(parse_reply(b""), Reply::Error);
    }

    #[test]
    fn reply_without_nul_is_an_error() {
        assert_eq!(parse_reply(b"stream: OK"), Reply::Error);
    }

    #[test]
    fn malformed_replies_are_errors() {
        assert_eq!(parse_reply(b"garbage\0"), Reply::Error);
        assert_eq!(parse_reply(b"stream: \0"), Reply::Error);
        assert_eq!(parse_reply(b"stream:  FOUND\0"), Reply::Error);
        assert_eq!(parse_reply(b"stream: OK ERROR\0"), Reply::Error);
        assert_eq!(parse_reply(b"stream: \xff FOUND\0"), Reply::Error);
    }

    #[test]
    fn instream_of_an_empty_body_is_command_and_terminator() -> Result<(), io::Error> {
        let mut out = Vec::new();
        write_instream(&mut out, b"")?;
        assert_eq!(out, b"zINSTREAM\0\0\0\0\0");
        Ok(())
    }

    #[test]
    fn instream_lengths_are_big_endian() -> Result<(), io::Error> {
        let mut out = Vec::new();
        write_instream(&mut out, b"hello")?;
        assert_eq!(out, b"zINSTREAM\0\0\0\0\x05hello\0\0\0\0");
        Ok(())
    }

    #[test]
    fn instream_splits_at_64_kib() -> Result<(), io::Error> {
        let body = vec![7u8; MAX_CHUNK + 1];
        let mut out = Vec::new();
        write_instream(&mut out, &body)?;
        let first_len = &out[10..14];
        assert_eq!(first_len, &65536u32.to_be_bytes());
        let second_at = 14 + MAX_CHUNK;
        assert_eq!(&out[second_at..second_at + 4], &1u32.to_be_bytes());
        assert_eq!(&out[out.len() - 4..], &[0, 0, 0, 0]);
        assert_eq!(out.len(), 10 + 4 + MAX_CHUNK + 4 + 1 + 4);
        Ok(())
    }

    #[test]
    fn a_socket_path_is_unix_and_an_address_is_tcp() -> Result<(), String> {
        assert_eq!(
            ClamdAddr::parse("/var/run/clamav/clamd.ctl"),
            ClamdAddr::Unix(PathBuf::from("/var/run/clamav/clamd.ctl"))
        );
        let tcp: SocketAddr = "127.0.0.1:3310".parse().map_err(|e| format!("{e}"))?;
        assert_eq!(ClamdAddr::parse("127.0.0.1:3310"), ClamdAddr::Tcp(tcp));
        // A name is not a socket address; it stays a path, as the design says.
        assert_eq!(
            ClamdAddr::parse("clamd.example:3310"),
            ClamdAddr::Unix(PathBuf::from("clamd.example:3310"))
        );
        Ok(())
    }

    #[test]
    fn only_tcp_off_this_host_is_remote() {
        assert!(!ClamdAddr::parse("/run/clamd.ctl").is_remote_tcp());
        assert!(!ClamdAddr::parse("127.0.0.1:3310").is_remote_tcp());
        assert!(!ClamdAddr::parse("[::1]:3310").is_remote_tcp());
        assert!(ClamdAddr::parse("192.168.1.5:3310").is_remote_tcp());
    }

    #[test]
    fn failure_words_are_stable() {
        assert_eq!(Failure::Unreachable.as_log_str(), "clamd_unreachable");
        assert_eq!(Failure::Timeout.as_log_str(), "clamd_timeout");
        assert_eq!(Failure::Error.as_log_str(), "clamd_error");
    }

    /// A per-process directory inside the repository, so two test processes
    /// never share a path. Stale directories of dead processes are swept first.
    fn unit_dir() -> Result<PathBuf, io::Error> {
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let own = std::process::id();
        for entry in std::fs::read_dir(&tests)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(pid) = name
                .to_str()
                .and_then(|n| n.strip_prefix("tmp-unit-"))
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if pid != own && !Path::new(&format!("/proc/{pid}")).exists() {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        Ok(tests.join(format!("tmp-unit-{own}")))
    }

    fn socket_path(name: &str) -> Result<PathBuf, io::Error> {
        let dir = unit_dir()?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(path)
    }

    /// Answers one connection with `reply` after reading what the client sent.
    fn answer_once(path: &Path, reply: &'static [u8]) -> Result<(), io::Error> {
        let listener = UnixListener::bind(path)?;
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                // Read until the zero-length terminator or the PING command.
                let mut seen = Vec::new();
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..n]);
                    if seen.ends_with(&[0, 0, 0, 0]) || seen == b"zPING\0" {
                        break;
                    }
                }
                let _ = stream.write_all(reply);
            }
        });
        Ok(())
    }

    #[test]
    fn scan_reports_clean_and_found() -> Result<(), io::Error> {
        let clean = socket_path("clean.sock")?;
        answer_once(&clean, b"stream: OK\0")?;
        let verdict = scan(&ClamdAddr::Unix(clean), b"hello", DEFAULT_TIMEOUT);
        assert_eq!(verdict, Verdict::Clean);

        let found = socket_path("found.sock")?;
        answer_once(&found, b"stream: Test.Sig FOUND\0")?;
        let verdict = scan(&ClamdAddr::Unix(found), b"x", DEFAULT_TIMEOUT);
        assert_eq!(verdict, Verdict::Found("Test.Sig".to_owned()));
        Ok(())
    }

    #[test]
    fn a_limit_signature_is_unfinished_not_found() -> Result<(), io::Error> {
        let limit = socket_path("limit.sock")?;
        answer_once(
            &limit,
            b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0",
        )?;
        let verdict = scan(&ClamdAddr::Unix(limit), b"x", DEFAULT_TIMEOUT);
        assert_eq!(
            verdict,
            Verdict::Unfinished("Heuristics.Limits.Exceeded.MaxFileSize".to_owned())
        );
        Ok(())
    }

    #[test]
    fn scan_of_a_missing_socket_is_unreachable() {
        let addr = ClamdAddr::Unix(PathBuf::from("/nonexistent/packetdeath-clamd.sock"));
        assert_eq!(
            scan(&addr, b"x", DEFAULT_TIMEOUT),
            Verdict::Failed(Failure::Unreachable)
        );
    }

    #[test]
    fn a_silent_clamd_times_out() -> Result<(), io::Error> {
        let path = socket_path("silent.sock")?;
        let listener = UnixListener::bind(&path)?;
        // The fake clamd holds the connection silently until the test drops
        // `release`. The 30 s bound only keeps the test from hanging if `scan`
        // ever loses its timeout; it is not a window the test relies on.
        let (release, held) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = held.recv_timeout(Duration::from_secs(30));
                drop(stream);
            }
        });
        let verdict = scan(&ClamdAddr::Unix(path), b"x", Duration::from_millis(200));
        assert_eq!(verdict, Verdict::Failed(Failure::Timeout));
        drop(release);
        Ok(())
    }

    /// Fails the first read with EINTR, answers on the second, then hits EOF.
    struct InterruptedOnce {
        reads: u8,
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            match self.reads {
                1 => Err(io::Error::from(io::ErrorKind::Interrupted)),
                2 => {
                    let reply = b"stream: OK\0";
                    buf[..reply.len()].copy_from_slice(reply);
                    Ok(reply.len())
                }
                _ => Ok(0),
            }
        }
    }

    #[test]
    fn an_interrupted_read_is_retried() -> Result<(), io::Error> {
        let mut reader = InterruptedOnce { reads: 0 };
        assert_eq!(read_reply(&mut reader)?, b"stream: OK\0");
        Ok(())
    }

    #[test]
    fn ping_wants_pong() -> Result<(), io::Error> {
        let path = socket_path("ping.sock")?;
        answer_once(&path, b"PONG\0")?;
        assert!(ping(&ClamdAddr::Unix(path), PING_TIMEOUT));
        let missing = ClamdAddr::Unix(PathBuf::from("/nonexistent/packetdeath-ping.sock"));
        assert!(!ping(&missing, Duration::from_millis(200)));
        Ok(())
    }
}
