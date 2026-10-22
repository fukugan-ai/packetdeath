//! Independent check of stage 8 (MITM): `docs/design.md` "段階8 MITM",
//! integration test table, acceptance IDs PK-103 to PK-109.
//!
//! Every test runs the real `proxy::serve` with a real `Mitm` against a fake
//! HTTPS upstream (a rustls server whose `localhost` certificate is signed by
//! a test CA) and, except PK-108/PK-109, a fake clamd on a Unix socket under
//! `tests/tmp-independent-mitm/` (git-ignored). The proxy is told to trust
//! the test CA instead of the web PKI, and to decrypt the fake upstream's
//! ephemeral port instead of 443 (`MitmLimits::decrypt_port`).
//!
//! PK-108 and PK-109 use the real clamd at `/var/run/clamav/clamd.ctl` and
//! `curl`, as the design says; without that socket they fail rather than pass.
//!
//! The EICAR test string is assembled at run time from fragments; it never
//! appears as one literal (an on-access scanner would quarantine the repo).
#![cfg(target_os = "linux")]

use packetdeath::allowlist::Allowlist;
use packetdeath::av::AvList;
use packetdeath::block_loop::{MitmList, WatchInputs};
use packetdeath::blocklist::Blocklist;
use packetdeath::clamd::ClamdAddr;
use packetdeath::flow::FlowLogSink;
use packetdeath::iplist::IpList;
use packetdeath::mitm::{Mitm, MitmLimits, MitmSettings};
use packetdeath::proxy::{self, AllowFrom, DenyMode, ProxyLimits};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::StreamOwned;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::error::Error;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn Error>>;

const MIB: usize = 1024 * 1024;
const REAL_CLAMD: &str = "/var/run/clamav/clamd.ctl";

// ------------------------------------------------------------------
// Scratch space
// ------------------------------------------------------------------

/// A fresh directory for one test under `tests/tmp-independent-mitm/`.
fn fresh_dir(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/tmp-independent-mitm")
        .join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The EICAR test file, built from fragments at run time.
fn eicar() -> Vec<u8> {
    [
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-",
        "ANTIVIRUS-TEST-",
        "FILE!$H+H*",
    ]
    .concat()
    .into_bytes()
}

/// Bytes that differ on every call (clamd caches results by content).
fn random_bytes(len: usize) -> Vec<u8> {
    static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let mut state = nanos ^ COUNTER.fetch_add(0x2545_f491_4f6c_dd1d, Ordering::Relaxed);
    if state == 0 {
        state = 1;
    }
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

// ------------------------------------------------------------------
// Test PKI for the fake upstream
// ------------------------------------------------------------------

struct Pki {
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    leaf: CertificateDer<'static>,
    leaf_key: Vec<u8>,
}

/// A test CA called `name` and a leaf for `localhost` and `127.0.0.1`.
fn test_pki(name: &str) -> Result<Pki, Box<dyn Error>> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    ca_params.distinguished_name = dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate()?;
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &issuer)?;
    Ok(Pki {
        ca_der: ca_cert.der().clone(),
        ca_pem: ca_cert.pem(),
        leaf: leaf.der().clone(),
        leaf_key: leaf_key.serialize_der(),
    })
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

// ------------------------------------------------------------------
// Fake HTTPS upstream
// ------------------------------------------------------------------

/// Builds the whole response for a method and path.
type Responder = Arc<dyn Fn(&str, &str) -> Vec<u8> + Send + Sync>;

struct FakeUpstream {
    port: u16,
    accepted: Arc<AtomicUsize>,
    requests: mpsc::Receiver<Vec<u8>>,
}

fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for header in headers {
        out.push_str(header);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A `200` carrying `body` with the given content type and its length.
fn file_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    let length = format!("Content-Length: {}", body.len());
    let content_type = format!("Content-Type: {content_type}");
    response("200 OK", &[&content_type, &length], body)
}

fn spawn_upstream(pki: &Pki, respond: Responder) -> Result<FakeUpstream, Box<dyn Error>> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.leaf_key.clone()));
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![pki.leaf.clone()], key)?;
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let (tx, requests) = mpsc::channel();
    let counter = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            let config = Arc::clone(&config);
            let respond = Arc::clone(&respond);
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = serve_upstream(stream, config, respond.as_ref(), &tx);
            });
        }
    });
    Ok(FakeUpstream {
        port,
        accepted,
        requests,
    })
}

fn serve_upstream(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    respond: &(dyn Fn(&str, &str) -> Vec<u8> + Send + Sync),
    seen: &mpsc::Sender<Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let conn = ServerConnection::new(config)?;
    let mut tls = StreamOwned::new(conn, stream);
    let mut raw = Vec::new();
    let mut length = 0usize;
    let mut request_line = String::new();
    loop {
        let mut line = Vec::new();
        if tls.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&line);
        let text = String::from_utf8_lossy(&line).into_owned();
        if request_line.is_empty() {
            request_line = text.trim_end().to_owned();
        }
        if let Some((name, value)) = text.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                length = value.trim().parse()?;
            }
        }
        if line == b"\r\n" {
            break;
        }
    }
    let mut body = vec![0u8; length];
    tls.read_exact(&mut body)?;
    raw.extend_from_slice(&body);
    let _ = seen.send(raw);
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or("no method")?.to_owned();
    let path = parts.next().ok_or("no path")?.to_owned();
    tls.write_all(&respond(&method, &path))?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

// ------------------------------------------------------------------
// Fake clamd
// ------------------------------------------------------------------

struct FakeClamd {
    addr: ClamdAddr,
    scans: Arc<AtomicUsize>,
    received: mpsc::Receiver<Vec<u8>>,
    socket: PathBuf,
}

impl Drop for FakeClamd {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Where the fake clamd socket for `dir` lives. A Unix socket path is limited
/// to 107 bytes, which a deep worktree path exceeds, so the socket goes to a
/// short per-user tmpfs directory; the name is a hash of `dir`, so the parent
/// and the child process of a test agree on it.
fn short_socket_path(dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let uid = std::fs::metadata("/proc/self")?.uid();
    let mut hasher = DefaultHasher::new();
    dir.hash(&mut hasher);
    let name = format!("{:016x}.sock", hasher.finish());
    for base in [format!("/run/user/{uid}"), String::from("/dev/shm")] {
        if Path::new(&base).is_dir() {
            let parent = Path::new(&base).join(format!("pd-mitm-test-{uid}"));
            std::fs::create_dir_all(&parent)?;
            return Ok(parent.join(name));
        }
    }
    Err("no short runtime directory (/run/user/<uid> or /dev/shm)".into())
}

/// A body holding this makes the fake clamd answer as the real one does when
/// a limit is hit (`AlertExceedsMax yes`).
const LIMIT_MARKER: &[u8] = b"packetdeath-test-limit-exceeded-marker";

/// A body small enough for any test limit that holds `LIMIT_MARKER`.
fn limit_marker_body() -> Vec<u8> {
    let mut body = random_bytes(4096);
    body.extend_from_slice(LIMIT_MARKER);
    body
}

/// Answers `zPING` with `PONG`, and `zINSTREAM` with `OK` or, when the body
/// holds the EICAR string, `Eicar-Test-Signature FOUND`, after `delay`. A body
/// holding `LIMIT_MARKER` gets `Heuristics.Limits.Exceeded.MaxFileSize FOUND`.
fn spawn_clamd(dir: &Path, delay: Duration) -> Result<FakeClamd, Box<dyn Error>> {
    let path = short_socket_path(dir)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(&path)?;
    let scans = Arc::new(AtomicUsize::new(0));
    let (tx, received) = mpsc::channel();
    let counter = Arc::clone(&scans);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let counter = Arc::clone(&counter);
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = serve_clamd(stream, &counter, &tx, delay);
            });
        }
    });
    Ok(FakeClamd {
        addr: ClamdAddr::Unix(path.clone()),
        scans,
        received,
        socket: path,
    })
}

fn serve_clamd(
    stream: std::os::unix::net::UnixStream,
    scans: &AtomicUsize,
    seen: &mpsc::Sender<Vec<u8>>,
    delay: Duration,
) -> Result<(), Box<dyn Error>> {
    let mut reader = BufReader::new(stream);
    let mut command = Vec::new();
    reader.read_until(0, &mut command)?;
    if command == b"zPING\0" {
        reader.get_mut().write_all(b"PONG\0")?;
        return Ok(());
    }
    if command != b"zINSTREAM\0" {
        return Ok(());
    }
    scans.fetch_add(1, Ordering::SeqCst);
    let mut body = Vec::new();
    loop {
        let mut len = [0u8; 4];
        reader.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 {
            break;
        }
        let start = body.len();
        body.resize(start + len, 0);
        reader.read_exact(&mut body[start..])?;
    }
    std::thread::sleep(delay);
    let reply: &[u8] = if contains(&body, &eicar()) {
        b"stream: Eicar-Test-Signature FOUND\0"
    } else if contains(&body, LIMIT_MARKER) {
        b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0"
    } else {
        b"stream: OK\0"
    };
    reader.get_mut().write_all(reply)?;
    let _ = seen.send(body);
    Ok(())
}

// ------------------------------------------------------------------
// The proxy under test
// ------------------------------------------------------------------

#[derive(Clone)]
struct Setup {
    blocklist: String,
    allowlist: String,
    mitm_list: String,
    /// `None` runs stage 7 only (no `Mitm`).
    clamd: Option<ClamdAddr>,
    /// Roots the proxy trusts upstream.
    upstream_roots: Vec<CertificateDer<'static>>,
    mitm_limits: MitmLimits,
    deny: DenyMode,
}

struct RunningProxy {
    addr: SocketAddr,
    flows: PathBuf,
    av: PathBuf,
    mitm_list: PathBuf,
    /// The proxy CA, once generated.
    ca: Option<CertificateDer<'static>>,
    ca_file: PathBuf,
}

fn start_proxy(dir: &Path, setup: Setup) -> Result<RunningProxy, Box<dyn Error>> {
    let listener = proxy::bind("127.0.0.1:0".parse()?)?;
    let addr = listener.local_addr()?;
    let flows = dir.join("flows.jsonl");
    let av = dir.join("av.jsonl");
    let ca_dir = dir.join("ca");
    let mitm_list = dir.join("mitm.txt");
    std::fs::write(&mitm_list, &setup.mitm_list)?;
    let log = FlowLogSink::open(&flows)?;

    let mitm = match setup.clamd {
        Some(clamd) => {
            let mut roots = RootCertStore::empty();
            for root in setup.upstream_roots {
                roots.add(root)?;
            }
            Some(Mitm::start(MitmSettings {
                ca_dir: ca_dir.clone(),
                clamd,
                av_log: av.clone(),
                upstream_roots: roots,
                limits: setup.mitm_limits,
            })?)
        }
        None => None,
    };
    let ca_file = ca_dir.join("ca.crt");
    let ca = match &mitm {
        Some(_) => Some(CertificateDer::from_pem_file(&ca_file)?),
        None => None,
    };

    let limits = ProxyLimits {
        deny: setup.deny,
        ..ProxyLimits::default()
    };
    let blocklist = Blocklist::parse(&setup.blocklist);
    let allowlist = Allowlist::parse(&setup.allowlist);
    let list_path = mitm_list.clone();
    std::thread::spawn(move || {
        let av_list = AvList::empty();
        let inputs = WatchInputs::new(blocklist, allowlist, None, IpList::empty(), &av_list);
        let inputs = match mitm {
            Some(_) => {
                let list = MitmList::load(&list_path);
                inputs.with_mitm_list(list_path, list)
            }
            None => inputs,
        };
        let allow_from = AllowFrom::from_args(&[]);
        proxy::serve(listener, &allow_from, &log, inputs, limits, mitm.as_ref());
    });
    Ok(RunningProxy {
        addr,
        flows,
        av,
        mitm_list,
        ca,
        ca_file,
    })
}

/// Everything a usual test needs: an upstream, a fake clamd and the proxy.
struct Harness {
    pki: Pki,
    upstream: FakeUpstream,
    clamd: FakeClamd,
    proxy: RunningProxy,
}

fn default_setup(pki: &Pki, upstream: &FakeUpstream, clamd: &FakeClamd) -> Setup {
    Setup {
        blocklist: String::new(),
        allowlist: String::new(),
        mitm_list: String::from("localhost\n"),
        clamd: Some(clamd.addr.clone()),
        upstream_roots: vec![pki.ca_der.clone()],
        mitm_limits: MitmLimits {
            decrypt_port: upstream.port,
            ..MitmLimits::default()
        },
        deny: DenyMode::Forbid,
    }
}

fn harness(
    name: &str,
    respond: Responder,
    clamd_delay: Duration,
    adjust: impl FnOnce(&mut Setup),
) -> Result<Harness, Box<dyn Error>> {
    let dir = fresh_dir(name)?;
    let pki = test_pki("packetdeath test upstream CA")?;
    let upstream = spawn_upstream(&pki, respond)?;
    let clamd = spawn_clamd(&dir, clamd_delay)?;
    let mut setup = default_setup(&pki, &upstream, &clamd);
    adjust(&mut setup);
    let proxy = start_proxy(&dir, setup)?;
    Ok(Harness {
        pki,
        upstream,
        clamd,
        proxy,
    })
}

// ------------------------------------------------------------------
// A client that goes through the proxy
// ------------------------------------------------------------------

struct Fetched {
    status: u16,
    head: String,
    body: Vec<u8>,
    /// The server certificate was issued by the packetdeath CA (decrypted).
    decrypted: bool,
}

/// Sends `CONNECT host:port` and returns the stream after the proxy's head.
fn connect_through(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> Result<(TcpStream, String), Box<dyn Error>> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    write!(
        stream,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    )?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok((stream, String::from_utf8_lossy(&head).into_owned()))
}

fn read_until_close<R: Read>(input: &mut R) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match input.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(out),
            Err(e) => return Err(e),
        }
    }
}

/// One HTTPS request through the proxy to `host:port`, trusting `roots`.
fn fetch(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    roots: &[CertificateDer<'static>],
    request: &[u8],
) -> Result<Fetched, Box<dyn Error>> {
    let (stream, connect_head) = connect_through(proxy, host, port)?;
    if !connect_head.starts_with("HTTP/1.1 200") {
        return Err(format!("CONNECT was not accepted: {connect_head:?}").into());
    }
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(root.clone())?;
    }
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(store)
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned())?;
    let conn = ClientConnection::new(Arc::new(config), name)?;
    let mut tls = StreamOwned::new(conn, stream);
    tls.write_all(request)?;
    tls.flush()?;
    let raw = read_until_close(&mut tls)?;
    let decrypted = match tls.conn.peer_certificates() {
        Some([leaf, ..]) => contains(leaf, b"packetdeath CA"),
        _ => false,
    };
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no end of head in the response")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head.split(' ').nth(1).ok_or("no status")?.parse::<u16>()?;
    Ok(Fetched {
        status,
        head,
        body: raw[split + 4..].to_vec(),
        decrypted,
    })
}

fn get_request(method: &str, path: &str) -> Vec<u8> {
    format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\n\r\n")
        .into_bytes()
}

impl Harness {
    /// Trusts both the proxy CA and the upstream CA, so a fetch succeeds
    /// either way and `decrypted` says which way it went.
    fn roots(&self) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
        let proxy_ca = self.proxy.ca.clone().ok_or("the proxy has no CA")?;
        Ok(vec![proxy_ca, self.pki.ca_der.clone()])
    }

    fn get(&self, path: &str) -> Result<Fetched, Box<dyn Error>> {
        self.request(&get_request("GET", path))
    }

    fn request(&self, request: &[u8]) -> Result<Fetched, Box<dyn Error>> {
        fetch(
            self.proxy.addr,
            "localhost",
            self.upstream.port,
            &self.roots()?,
            request,
        )
    }

    /// A client that only trusts the upstream CA, like a pinned app.
    fn get_pinned(&self, path: &str) -> Result<Fetched, Box<dyn Error>> {
        fetch(
            self.proxy.addr,
            "localhost",
            self.upstream.port,
            std::slice::from_ref(&self.pki.ca_der),
            &get_request("GET", path),
        )
    }

    fn scans(&self) -> usize {
        self.clamd.scans.load(Ordering::SeqCst)
    }

    /// See [`handshake_then_close`].
    fn handshake_then_close(&self, clean: bool) -> Result<(), Box<dyn Error>> {
        handshake_then_close(self.proxy.addr, self.upstream.port, &self.roots()?, clean)
    }
}

/// Finishes a handshake that trusts `roots` and sends no request, like curl
/// after its own certificate check fails or a browser dropping a spare
/// socket. `clean` sends `close_notify` and waits for the proxy to close;
/// otherwise the socket is simply dropped.
fn handshake_then_close(
    proxy: SocketAddr,
    port: u16,
    roots: &[CertificateDer<'static>],
    clean: bool,
) -> Result<(), Box<dyn Error>> {
    let (stream, connect_head) = connect_through(proxy, "localhost", port)?;
    if !connect_head.starts_with("HTTP/1.1 200") {
        return Err(format!("CONNECT was not accepted: {connect_head:?}").into());
    }
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(root.clone())?;
    }
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(store)
        .with_no_client_auth();
    let conn = ClientConnection::new(Arc::new(config), ServerName::try_from("localhost")?)?;
    let mut tls = StreamOwned::new(conn, stream);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    if clean {
        tls.conn.send_close_notify();
        tls.flush()?;
        read_until_close(&mut tls)?;
    }
    Ok(())
}

fn read_or_empty(path: &Path) -> Result<String, Box<dyn Error>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

fn last_line(text: &str) -> Result<&str, Box<dyn Error>> {
    Ok(text.lines().last().ok_or("the log is empty")?)
}

fn is_sha256(value: &serde_json::Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn fixed(body: Vec<u8>, content_type: &'static str) -> Responder {
    Arc::new(move |_, _| file_response(content_type, &body))
}

// ------------------------------------------------------------------
// PK-103
// ------------------------------------------------------------------

#[test]
fn eicar_is_replaced_with_403_and_logged_as_av() -> TestResult {
    let h = harness(
        "eicar",
        fixed(eicar(), "application/octet-stream"),
        Duration::ZERO,
        |_| {},
    )?;
    let fetched = h.get("/eicar.com")?;
    assert_eq!(fetched.status, 403, "{}", fetched.head);
    assert!(fetched.decrypted, "the connection was not decrypted");
    assert!(fetched
        .head
        .contains("Content-Type: text/plain; charset=utf-8"));
    assert!(
        !contains(&fetched.body, &eicar()),
        "the upstream body leaked"
    );
    assert!(contains(&fetched.body, b"packetdeath"));

    let flows = std::fs::read_to_string(&h.proxy.flows)?;
    let block = last_line(&flows)?;
    assert!(block.contains("\"decision\":\"block\"") && block.contains("\"reason\":\"av\""));
    let av: serde_json::Value = serde_json::from_str(last_line(&read_or_empty(&h.proxy.av)?)?)?;
    assert_eq!(av.get("verdict"), Some(&serde_json::json!("malicious")));
    assert_eq!(
        av.get("engine"),
        Some(&serde_json::json!("clamav:Eicar-Test-Signature"))
    );
    assert!(av.get("sha256").is_some_and(is_sha256));
    assert_eq!(
        av.get("sha256"),
        Some(&serde_json::json!(packetdeath::scan::sha256_hex(&eicar())))
    );
    Ok(())
}

#[test]
fn clean_file_passes_and_is_recorded_in_av_jsonl() -> TestResult {
    let body = random_bytes(256 * 1024);
    let h = harness(
        "clean",
        fixed(body.clone(), "application/zip"),
        Duration::ZERO,
        |_| {},
    )?;
    let fetched = h.get("/file.zip")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(fetched.decrypted);
    assert!(fetched.body == body, "the body changed on the way");
    assert_eq!(h.scans(), 1);
    let av: serde_json::Value = serde_json::from_str(last_line(&read_or_empty(&h.proxy.av)?)?)?;
    assert_eq!(av.get("verdict"), Some(&serde_json::json!("clean")));
    assert_eq!(av.get("engine"), Some(&serde_json::json!("clamav")));
    let flows = std::fs::read_to_string(&h.proxy.flows)?;
    assert!(!flows.contains("\"decision\":\"block\""));
    Ok(())
}

#[test]
fn chunked_response_is_scanned_decoded() -> TestResult {
    let parts: Vec<Vec<u8>> = vec![random_bytes(1000), random_bytes(70_000), random_bytes(5)];
    let whole = parts.concat();
    let mut chunked = Vec::new();
    for part in &parts {
        chunked.extend_from_slice(format!("{:X}\r\n", part.len()).as_bytes());
        chunked.extend_from_slice(part);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let responder: Responder = Arc::new(move |_, _| {
        response(
            "200 OK",
            &[
                "Content-Type: application/octet-stream",
                "Transfer-Encoding: chunked",
            ],
            &chunked,
        )
    });
    let h = harness("chunked", responder, Duration::ZERO, |_| {})?;
    let fetched = h.get("/stream.bin")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(
        fetched.body == whole,
        "the client did not get the decoded body"
    );
    let scanned = h.clamd.received.recv_timeout(Duration::from_secs(5))?;
    assert!(scanned == whole, "clamd did not see the decoded body");
    Ok(())
}

// ------------------------------------------------------------------
// PK-104
// ------------------------------------------------------------------

#[test]
fn clamd_down_passes_the_same_file() -> TestResult {
    let body = random_bytes(64 * 1024);
    let h = harness(
        "clamd-down",
        fixed(body.clone(), "application/octet-stream"),
        Duration::ZERO,
        |setup| {
            setup.clamd = Some(ClamdAddr::Unix(PathBuf::from(
                "/nonexistent/packetdeath-test-clamd.sock",
            )));
        },
    )?;
    let fetched = h.get("/file.bin")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(fetched.decrypted);
    assert!(fetched.body == body);
    let flows = std::fs::read_to_string(&h.proxy.flows)?;
    assert!(!flows.contains("\"decision\":\"block\""));
    assert!(read_or_empty(&h.proxy.av)?.is_empty(), "av.jsonl grew");
    Ok(())
}

// ------------------------------------------------------------------
// PK-105
// ------------------------------------------------------------------

/// A small `MitmLimits::max_scan_bytes`, so the limit can be crossed without
/// holding the default (8191 MiB) in memory.
const SMALL_LIMIT: usize = 256 * 1024;

#[test]
fn oversize_body_is_streamed_without_scan() -> TestResult {
    let body = random_bytes(SMALL_LIMIT + 1);
    let h = harness(
        "oversize",
        fixed(body.clone(), "application/octet-stream"),
        Duration::ZERO,
        |s| s.mitm_limits.max_scan_bytes = SMALL_LIMIT,
    )?;
    let fetched = h.get("/big.bin")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(fetched.decrypted);
    assert!(
        fetched.body == body,
        "the limit + 1 byte body did not arrive byte for byte"
    );
    assert_eq!(h.scans(), 0);
    Ok(())
}

#[test]
fn exactly_the_limit_is_scanned() -> TestResult {
    let at_limit = random_bytes(SMALL_LIMIT);
    let over_limit = random_bytes(SMALL_LIMIT + 1);
    let (a, b) = (at_limit.clone(), over_limit.clone());
    let responder: Responder = Arc::new(move |_, path| {
        let body = if path == "/limit.bin" { &a } else { &b };
        file_response("application/octet-stream", body)
    });
    let h = harness("exactly-the-limit", responder, Duration::ZERO, |s| {
        s.mitm_limits.max_scan_bytes = SMALL_LIMIT
    })?;
    let fetched = h.get("/limit.bin")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(fetched.body == at_limit);
    assert_eq!(h.scans(), 1, "exactly the limit was not scanned");
    let fetched = h.get("/over.bin")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(fetched.body == over_limit);
    assert_eq!(h.scans(), 1, "limit + 1 byte was scanned");
    Ok(())
}

// ------------------------------------------------------------------
// PK-113
// ------------------------------------------------------------------

#[test]
fn limits_exceeded_is_passed_through_as_unscanned() -> TestResult {
    let unfinished = limit_marker_body();
    let served = unfinished.clone();
    let responder: Responder = Arc::new(move |_, path| {
        if path == "/eicar.com" {
            file_response("application/octet-stream", &eicar())
        } else {
            file_response("application/octet-stream", &served)
        }
    });
    let h = harness("limits-exceeded", responder, Duration::ZERO, |_| {})?;

    let fetched = h.get("/limit.bin")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(fetched.decrypted);
    assert!(fetched.body == unfinished, "the body changed on the way");
    assert_eq!(h.scans(), 1);
    assert!(
        read_or_empty(&h.proxy.av)?.is_empty(),
        "av.jsonl grew for an unfinished scan"
    );
    let flows = read_or_empty(&h.proxy.flows)?;
    assert!(
        !flows.contains("\"reason\":\"av\""),
        "an unfinished scan was logged as av: {flows}"
    );

    // Positive control: a real signature is still a 403 and a malicious line.
    let found = h.get("/eicar.com")?;
    assert_eq!(found.status, 403, "{}", found.head);
    assert_eq!(h.scans(), 2);
    let av = read_or_empty(&h.proxy.av)?;
    assert_eq!(av.lines().count(), 1, "{av}");
    let line: serde_json::Value = serde_json::from_str(last_line(&av)?)?;
    assert_eq!(line.get("verdict"), Some(&serde_json::json!("malicious")));
    Ok(())
}

#[test]
fn head_range_and_page_parts_are_not_scanned() -> TestResult {
    let responder: Responder = Arc::new(|method, path| match (method, path) {
        ("HEAD", _) => response(
            "200 OK",
            &["Content-Type: application/zip", "Content-Length: 1234"],
            b"",
        ),
        (_, "/partial") => response(
            "206 Partial Content",
            &[
                "Content-Type: application/zip",
                "Content-Length: 5",
                "Content-Range: bytes 0-4/100",
            ],
            b"abcde",
        ),
        _ => file_response(
            "text/html; charset=utf-8",
            b"<html><body>page</body></html>",
        ),
    });
    let h = harness("not-scanned", responder, Duration::ZERO, |_| {})?;
    let head = h.request(&get_request("HEAD", "/file.zip"))?;
    assert_eq!(head.status, 200, "{}", head.head);
    assert!(head.body.is_empty());
    let partial = h.get("/partial")?;
    assert_eq!(partial.status, 206, "{}", partial.head);
    assert_eq!(partial.body, b"abcde");
    let page = h.get("/index.html")?;
    assert_eq!(page.status, 200, "{}", page.head);
    assert!(page.decrypted);
    assert_eq!(h.scans(), 0);
    Ok(())
}

// ------------------------------------------------------------------
// PK-107
// ------------------------------------------------------------------

#[test]
fn pinned_client_falls_back_to_tunnel_on_the_next_connection() -> TestResult {
    let h = harness(
        "pinned",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    assert!(
        h.get_pinned("/").is_err(),
        "a client that does not trust the proxy CA got through decrypted"
    );
    std::thread::sleep(Duration::from_millis(300));
    let second = h.get_pinned("/")?;
    assert_eq!(second.status, 200, "{}", second.head);
    assert!(!second.decrypted, "the second connection was not tunnelled");
    let flows = std::fs::read_to_string(&h.proxy.flows)?;
    assert_eq!(flows.lines().count(), 2);
    assert!(flows.lines().all(|l| l.contains("\"decision\":\"pass\"")));
    Ok(())
}

/// curl (OpenSSL) and post-handshake pinning finish the handshake, check the
/// certificate, and drop the socket without a request.
#[test]
fn client_dropping_after_the_handshake_falls_back_to_tunnel() -> TestResult {
    let h = harness(
        "dropped",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    h.handshake_then_close(false)?;
    std::thread::sleep(Duration::from_millis(300));
    let second = h.get("/")?;
    assert_eq!(second.status, 200, "{}", second.head);
    assert!(
        !second.decrypted,
        "an unclean drop after the handshake did not bypass the pair"
    );
    Ok(())
}

/// Negative control: a clean `close_notify` with no request is not a refusal.
#[test]
fn clean_close_after_the_handshake_keeps_decrypting() -> TestResult {
    let h = harness(
        "clean-close",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    h.handshake_then_close(true)?;
    std::thread::sleep(Duration::from_millis(300));
    let second = h.get("/")?;
    assert_eq!(second.status, 200, "{}", second.head);
    assert!(second.decrypted, "a clean close bypassed the pair");
    Ok(())
}

/// A browser drops its spare sockets without `close_notify` right after a
/// page. A sibling socket closing silently while a request of the same
/// (client, host) is still being scanned must not bypass the pair.
#[test]
fn silent_close_after_a_recent_request_is_not_bypassed() -> TestResult {
    let h = harness(
        "recent-request",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::from_millis(800),
        |_| {},
    )?;
    let (proxy, port, roots) = (h.proxy.addr, h.upstream.port, h.roots()?);
    let sibling = std::thread::spawn(move || {
        // Lands while the first request's body is held for the slow clamd.
        std::thread::sleep(Duration::from_millis(300));
        handshake_then_close(proxy, port, &roots, false).map_err(|e| e.to_string())
    });
    let first = h.get("/")?;
    let Ok(dropped) = sibling.join() else {
        return Err("the sibling socket thread panicked".into());
    };
    dropped?;
    assert_eq!(first.status, 200, "{}", first.head);
    assert!(first.decrypted, "the first request was not decrypted");
    std::thread::sleep(Duration::from_millis(300));
    let next = h.get("/")?;
    assert_eq!(next.status, 200, "{}", next.head);
    assert!(
        next.decrypted,
        "a silent close after a recent request bypassed the pair"
    );
    Ok(())
}

/// Chrome aborts pending connects (its certificate settings reloading at
/// start-up) after `CONNECT` but before its ClientHello. A client that sent
/// no TLS byte never saw the leaf and must not bypass the pair.
#[test]
fn close_before_tls_is_not_bypassed() -> TestResult {
    let h = harness(
        "before-tls",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    let (stream, connect_head) = connect_through(h.proxy.addr, "localhost", h.upstream.port)?;
    assert!(connect_head.starts_with("HTTP/1.1 200"), "{connect_head:?}");
    drop(stream);
    std::thread::sleep(Duration::from_millis(300));
    let next = h.get("/")?;
    assert_eq!(next.status, 200, "{}", next.head);
    assert!(
        next.decrypted,
        "a close before any TLS byte bypassed the pair"
    );
    Ok(())
}

/// Chrome cancels in-flight handshakes without an alert when its
/// certificate settings reload. A client that sent its ClientHello and then
/// closed before its Finished, without an alert, is not refusing the leaf,
/// even with no recent request from the pair.
#[test]
fn silent_close_during_the_handshake_is_not_bypassed() -> TestResult {
    let h = harness(
        "mid-handshake",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    let (mut stream, connect_head) = connect_through(h.proxy.addr, "localhost", h.upstream.port)?;
    assert!(connect_head.starts_with("HTTP/1.1 200"), "{connect_head:?}");
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let mut conn = ClientConnection::new(Arc::new(config), ServerName::try_from("localhost")?)?;
    while conn.wants_write() {
        conn.write_tls(&mut stream)?;
    }
    // The server's first flight has started, so the ClientHello was taken.
    let mut first = [0u8; 1];
    stream.read_exact(&mut first)?;
    drop(stream);
    std::thread::sleep(Duration::from_millis(300));
    let next = h.get("/")?;
    assert_eq!(next.status, 200, "{}", next.head);
    assert!(
        next.decrypted,
        "a silent close during the handshake bypassed the pair"
    );
    Ok(())
}

/// Negative control: a recent request does not excuse an alert.
#[test]
fn alert_is_bypassed_even_after_a_recent_request() -> TestResult {
    let h = harness(
        "alert-after-request",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    let first = h.get("/")?;
    assert!(first.decrypted, "the first request was not decrypted");
    assert!(
        h.get_pinned("/").is_err(),
        "a client that does not trust the proxy CA got through decrypted"
    );
    std::thread::sleep(Duration::from_millis(300));
    let next = h.get("/")?;
    assert_eq!(next.status, 200, "{}", next.head);
    assert!(
        !next.decrypted,
        "an alert after a recent request was not bypassed"
    );
    Ok(())
}

#[test]
fn bypass_expires_after_its_ttl() -> TestResult {
    let h = harness(
        "bypass-ttl",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |setup| setup.mitm_limits.bypass_ttl = Duration::from_secs(1),
    )?;
    assert!(h.get_pinned("/").is_err());
    std::thread::sleep(Duration::from_millis(300));
    let second = h.get("/")?;
    assert!(!second.decrypted, "the bypass was not in effect");
    std::thread::sleep(Duration::from_millis(1200));
    let third = h.get("/")?;
    assert_eq!(third.status, 200, "{}", third.head);
    assert!(
        third.decrypted,
        "decryption did not come back after the TTL"
    );
    Ok(())
}

#[test]
fn upstream_tls_failure_falls_back_to_tunnel() -> TestResult {
    let other = test_pki("some other CA")?;
    let h = harness(
        "upstream-tls",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |setup| setup.upstream_roots = vec![other.ca_der.clone()],
    )?;
    let fetched = h.get("/")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(!fetched.decrypted, "an untrusted upstream was decrypted");
    assert_eq!(h.scans(), 0);
    Ok(())
}

// ------------------------------------------------------------------
// Decrypted exchange handling
// ------------------------------------------------------------------

#[test]
fn request_body_is_forwarded_exactly() -> TestResult {
    let h = harness(
        "request-body",
        fixed(b"ok".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    let body = random_bytes(100 * 1024);
    let mut request = format!(
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    let fetched = h.request(&request)?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    let seen = h.upstream.requests.recv_timeout(Duration::from_secs(5))?;
    let split = seen
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no end of head upstream")?;
    let head = String::from_utf8_lossy(&seen[..split]).into_owned();
    assert!(seen[split + 4..] == body[..], "the request body changed");
    assert!(head.contains("Accept-Encoding: identity"), "{head}");
    assert!(head.contains("Connection: close"), "{head}");
    assert!(
        !head.contains("Expect:") && !head.contains("keep-alive"),
        "{head}"
    );
    Ok(())
}

#[test]
fn upgrade_gets_501_and_is_bypassed_next_time() -> TestResult {
    let h = harness(
        "upgrade",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    let upgrade =
        b"GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    let first = h.request(upgrade)?;
    assert_eq!(first.status, 501, "{}", first.head);
    assert!(first.decrypted);
    let second = h.get("/")?;
    assert_eq!(second.status, 200, "{}", second.head);
    assert!(!second.decrypted, "the next connection was decrypted again");
    Ok(())
}

#[test]
fn scan_slot_exhaustion_passes_unscanned() -> TestResult {
    let h = harness(
        "slots",
        Arc::new(|_, _| file_response("application/octet-stream", &random_bytes(MIB))),
        Duration::from_millis(1500),
        |setup| setup.mitm_limits.scan_budget_bytes = MIB,
    )?;
    let proxy = h.proxy.addr;
    let port = h.upstream.port;
    let roots = h.roots()?;
    let first = std::thread::spawn(move || {
        fetch(proxy, "localhost", port, &roots, &get_request("GET", "/a"))
            .map(|f| f.status)
            .map_err(|e| e.to_string())
    });
    std::thread::sleep(Duration::from_millis(400));
    let started = Instant::now();
    let second = h.get("/b")?;
    let second_took = started.elapsed();
    assert_eq!(second.status, 200, "{}", second.head);
    assert_eq!(second.body.len(), MIB);
    assert!(
        second_took < Duration::from_millis(1000),
        "the second download waited for the first scan: {second_took:?}"
    );
    let first_status = first.join().map_err(|_| "the first download panicked")??;
    assert_eq!(first_status, 200);
    assert_eq!(h.scans(), 1, "the second body was scanned");
    Ok(())
}

/// Starts `GET path` through the proxy on its own thread; the thread yields
/// the status.
fn spawn_get(
    h: &Harness,
    path: &'static str,
) -> Result<std::thread::JoinHandle<Result<u16, String>>, Box<dyn Error>> {
    let proxy = h.proxy.addr;
    let port = h.upstream.port;
    let roots = h.roots()?;
    Ok(std::thread::spawn(move || {
        fetch(proxy, "localhost", port, &roots, &get_request("GET", path))
            .map(|f| f.status)
            .map_err(|e| e.to_string())
    }))
}

#[test]
fn scan_budget_counts_bytes_not_connections() -> TestResult {
    let h = harness(
        "budget-bytes",
        Arc::new(|_, _| file_response("application/octet-stream", &random_bytes(MIB))),
        Duration::from_millis(1500),
        |setup| setup.mitm_limits.scan_budget_bytes = 2 * MIB,
    )?;
    let first = spawn_get(&h, "/a")?;
    let second = spawn_get(&h, "/b")?;
    std::thread::sleep(Duration::from_millis(400));
    let started = Instant::now();
    let third = h.get("/c")?;
    let third_took = started.elapsed();
    assert_eq!(third.status, 200, "{}", third.head);
    assert_eq!(third.body.len(), MIB);
    assert!(
        third_took < Duration::from_millis(1000),
        "the third download waited for a scan: {third_took:?}"
    );
    for held in [first, second] {
        let status = held.join().map_err(|_| "a held download panicked")??;
        assert_eq!(status, 200);
    }
    assert_eq!(h.scans(), 2, "two bodies fit the budget; the third did not");

    // Both leases are back: the next body is scanned again.
    let fourth = h.get("/d")?;
    assert_eq!(fourth.status, 200, "{}", fourth.head);
    assert_eq!(h.scans(), 3, "the budget did not come back");
    Ok(())
}

#[test]
fn unknown_length_takes_the_whole_limit_from_the_budget() -> TestResult {
    let data = random_bytes(4096);
    let served = data.clone();
    let responder: Responder = Arc::new(move |_, path| {
        if path == "/chunked" {
            let mut body = format!("{:x}\r\n", served.len()).into_bytes();
            body.extend_from_slice(&served);
            body.extend_from_slice(b"\r\n0\r\n\r\n");
            response(
                "200 OK",
                &[
                    "Content-Type: application/octet-stream",
                    "Transfer-Encoding: chunked",
                ],
                &body,
            )
        } else {
            file_response("application/octet-stream", &random_bytes(1024))
        }
    });
    let h = harness(
        "budget-unknown-length",
        responder,
        Duration::from_millis(1500),
        |setup| {
            setup.mitm_limits.max_scan_bytes = SMALL_LIMIT;
            setup.mitm_limits.scan_budget_bytes = SMALL_LIMIT;
        },
    )?;
    let chunked = spawn_get(&h, "/chunked")?;
    std::thread::sleep(Duration::from_millis(400));
    let started = Instant::now();
    let small = h.get("/small")?;
    let small_took = started.elapsed();
    assert_eq!(small.status, 200, "{}", small.head);
    assert_eq!(small.body.len(), 1024);
    assert!(
        small_took < Duration::from_millis(1000),
        "the small download waited for the chunked scan: {small_took:?}"
    );
    let status = chunked
        .join()
        .map_err(|_| "the chunked download panicked")??;
    assert_eq!(status, 200);
    assert_eq!(h.scans(), 1, "the small body was scanned");
    Ok(())
}

// ------------------------------------------------------------------
// Which CONNECTs are decrypted
// ------------------------------------------------------------------

#[test]
fn blocked_host_in_mitm_list_is_not_decrypted() -> TestResult {
    let h = harness(
        "blocked",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |setup| setup.blocklist = String::from("localhost\n"),
    )?;
    let (_stream, head) = connect_through(h.proxy.addr, "localhost", h.upstream.port)?;
    assert!(head.starts_with("HTTP/1.1 403"), "{head:?}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(h.upstream.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(h.scans(), 0);
    Ok(())
}

#[test]
fn allowlisted_host_in_mitm_list_is_tunneled() -> TestResult {
    let h = harness(
        "allowlisted",
        fixed(b"plain".to_vec(), "application/octet-stream"),
        Duration::ZERO,
        |setup| setup.allowlist = String::from("localhost\n"),
    )?;
    let fetched = h.get("/")?;
    assert_eq!(fetched.status, 200, "{}", fetched.head);
    assert!(!fetched.decrypted, "an allowlisted host was decrypted");
    assert_eq!(h.scans(), 0);
    Ok(())
}

// ------------------------------------------------------------------
// PK-106
// ------------------------------------------------------------------

#[test]
fn mitm_list_reload_takes_effect() -> TestResult {
    let h = harness(
        "reload",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |setup| setup.mitm_list = String::new(),
    )?;
    let before = h.get("/")?;
    assert!(!before.decrypted, "decrypted before the host was listed");
    std::fs::write(&h.proxy.mitm_list, "localhost\n")?;
    std::thread::sleep(Duration::from_millis(400));
    let after = h.get("/")?;
    assert_eq!(after.status, 200, "{}", after.head);
    assert!(after.decrypted, "the reloaded list did not take effect");
    Ok(())
}

// ------------------------------------------------------------------
// PK-111
// ------------------------------------------------------------------

/// One plain (not CONNECT) request to the proxy; the head and the body of
/// what it answers before it closes.
fn plain_exchange(proxy: SocketAddr, request: &str) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(request.as_bytes())?;
    let raw = read_until_close(&mut stream)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no end of head in the response")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    Ok((head, raw[split + 4..].to_vec()))
}

#[test]
fn ca_certificate_is_served_and_the_key_never() -> TestResult {
    let h = harness(
        "ca-serve",
        fixed(b"plain".to_vec(), "text/plain"),
        Duration::ZERO,
        |_| {},
    )?;
    let ca_crt = "GET /ca.crt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let (head, body) = plain_exchange(h.proxy.addr, ca_crt)?;
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head:?}");
    assert!(
        head.contains("Content-Type: application/x-x509-ca-cert"),
        "{head:?}"
    );
    assert!(
        head.contains(&format!("Content-Length: {}", body.len())),
        "{head:?}"
    );
    assert!(head.contains("Connection: close"), "{head:?}");
    assert!(!head.contains("Content-Disposition"), "{head:?}");
    assert_eq!(body, std::fs::read(&h.proxy.ca_file)?);
    let key = std::fs::read(h.proxy.ca_file.with_file_name("ca.key"))?;
    assert!(
        !contains(&body, &key),
        "the key was served as the certificate"
    );

    let ca_key = "GET /ca.key HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let (head, body) = plain_exchange(h.proxy.addr, ca_key)?;
    assert!(head.starts_with("HTTP/1.1 400"), "{head:?}");
    assert!(!contains(&body, b"PRIVATE KEY"), "{body:?}");

    // Neither request is a flow; a CONNECT afterwards is, so the log works.
    assert_eq!(read_or_empty(&h.proxy.flows)?, "");
    h.get("/")?;
    let flows = read_or_empty(&h.proxy.flows)?;
    assert!(!flows.is_empty(), "the control CONNECT was not logged");
    assert!(!flows.contains("ca.crt"), "{flows:?}");

    // Decryption off: the same request is the usual `400`.
    let off = start_proxy(
        &fresh_dir("ca-serve-off")?,
        Setup {
            blocklist: String::new(),
            allowlist: String::new(),
            mitm_list: String::new(),
            clamd: None,
            upstream_roots: Vec::new(),
            mitm_limits: MitmLimits::default(),
            deny: DenyMode::Forbid,
        },
    )?;
    let (head, body) = plain_exchange(off.addr, ca_crt)?;
    assert!(head.starts_with("HTTP/1.1 400"), "{head:?}");
    assert!(body.is_empty(), "{body:?}");
    Ok(())
}

// ------------------------------------------------------------------
// PK-108 / PK-109: timing against the real clamd, with curl
// ------------------------------------------------------------------

/// `%{time_total}` of one curl through `proxy`, trusting `cacert`.
fn curl_time(proxy: SocketAddr, cacert: &Path, url: &str) -> Result<f64, Box<dyn Error>> {
    let output = Command::new("curl")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .args(["-sS", "-o", "/dev/null", "-w", "%{time_total}"])
        .arg("-x")
        .arg(format!("http://{proxy}"))
        .arg("--cacert")
        .arg(cacert)
        .arg(url)
        .output()?;
    if !output.status.success() {
        return Err(format!("curl failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}

fn median(mut values: Vec<f64>) -> Result<f64, Box<dyn Error>> {
    values.sort_by(f64::total_cmp);
    Ok(*values.get(values.len() / 2).ok_or("no values")?)
}

/// The real clamd, or a failure: these two IDs must not pass without it.
fn real_clamd() -> Result<ClamdAddr, Box<dyn Error>> {
    let addr = ClamdAddr::Unix(PathBuf::from(REAL_CLAMD));
    if !packetdeath::clamd::ping(&addr, Duration::from_secs(5)) {
        return Err(format!("no clamd answering PING at {REAL_CLAMD}").into());
    }
    Ok(addr)
}

struct TimingRig {
    pki_file: PathBuf,
    upstream_port: u16,
    with_scan: RunningProxy,
    without_scan: RunningProxy,
}

fn timing_rig(name: &str) -> Result<TimingRig, Box<dyn Error>> {
    let clamd = real_clamd()?;
    let dir = fresh_dir(name)?;
    let pki = test_pki("packetdeath test upstream CA")?;
    let pki_file = dir.join("upstream-ca.pem");
    std::fs::write(&pki_file, &pki.ca_pem)?;
    let upstream = spawn_upstream(
        &pki,
        Arc::new(|_, path| {
            if path == "/small" {
                file_response("text/plain", b"small")
            } else {
                file_response("application/octet-stream", &random_bytes(10 * MIB))
            }
        }),
    )?;
    let base = Setup {
        blocklist: String::new(),
        allowlist: String::new(),
        mitm_list: String::from("localhost\n"),
        clamd: Some(clamd),
        upstream_roots: vec![pki.ca_der.clone()],
        mitm_limits: MitmLimits {
            decrypt_port: upstream.port,
            ..MitmLimits::default()
        },
        deny: DenyMode::Forbid,
    };
    let with_dir = dir.join("with");
    std::fs::create_dir_all(&with_dir)?;
    let without_dir = dir.join("without");
    std::fs::create_dir_all(&without_dir)?;
    let without_scan = start_proxy(
        &without_dir,
        Setup {
            clamd: None,
            mitm_list: String::new(),
            ..base.clone()
        },
    )?;
    let with_scan = start_proxy(&with_dir, base)?;
    Ok(TimingRig {
        pki_file,
        upstream_port: upstream.port,
        with_scan,
        without_scan,
    })
}

#[test]
fn ten_mib_clean_download_overhead_is_within_two_seconds() -> TestResult {
    let rig = timing_rig("pk108")?;
    let url = format!("https://localhost:{}/big", rig.upstream_port);
    let mut without = Vec::new();
    let mut with = Vec::new();
    for _ in 0..3 {
        without.push(curl_time(rig.without_scan.addr, &rig.pki_file, &url)?);
        with.push(curl_time(rig.with_scan.addr, &rig.with_scan.ca_file, &url)?);
    }
    let (without, with) = (median(without)?, median(with)?);
    println!("PK-108 median time_total without_scan={without:.3}s with_scan={with:.3}s");
    let av = read_or_empty(&rig.with_scan.av)?;
    assert_eq!(
        av.lines()
            .filter(|l| l.contains("\"verdict\":\"clean\""))
            .count(),
        3,
        "the scanned run did not scan three files: {av}"
    );
    assert!(
        with - without <= 2.0,
        "scan overhead {:.3}s is over 2 seconds",
        with - without
    );
    Ok(())
}

#[test]
fn connect_to_unlisted_host_is_not_slowed_by_a_running_scan() -> TestResult {
    let rig = timing_rig("pk109")?;
    let small = format!("https://127.0.0.1:{}/small", rig.upstream_port);
    let proxy = rig.with_scan.addr;
    let mut quiet = Vec::new();
    for _ in 0..3 {
        quiet.push(curl_time(proxy, &rig.pki_file, &small)?);
    }

    let big = format!("https://localhost:{}/big", rig.upstream_port);
    let ca_file = rig.with_scan.ca_file.clone();
    let background = std::thread::spawn(move || -> Result<usize, String> {
        let mut done = 0;
        for _ in 0..3 {
            curl_time(proxy, &ca_file, &big).map_err(|e| e.to_string())?;
            done += 1;
        }
        Ok(done)
    });
    std::thread::sleep(Duration::from_millis(300));
    let mut busy = Vec::new();
    for _ in 0..3 {
        busy.push(curl_time(proxy, &rig.pki_file, &small)?);
        std::thread::sleep(Duration::from_millis(150));
    }
    let downloads = background
        .join()
        .map_err(|_| "background curl panicked")??;
    let (quiet, busy) = (median(quiet)?, median(busy)?);
    println!("PK-109 median time_total no_scan={quiet:.3}s during_scan={busy:.3}s");
    assert_eq!(downloads, 3);
    let av = read_or_empty(&rig.with_scan.av)?;
    assert!(
        av.lines().count() >= 3,
        "the background downloads were not scanned: {av}"
    );
    assert!(
        busy - quiet <= 0.5,
        "a CONNECT during a scan was slower by {:.3}s",
        busy - quiet
    );
    Ok(())
}

// ------------------------------------------------------------------
// PK-112
// ------------------------------------------------------------------

/// The scratch directory shared by `clean_and_found_lines_carry_the_scan_time`
/// and the proxy child it starts. Unlike `fresh_dir` it does not clear it.
fn pk112_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/tmp-independent-mitm/pk112")
}

/// The proxy of PK-112, run as a child of this test binary so that its stderr
/// is a pipe the parent can read (the other tests run the proxy in-process).
/// It is not a test of its own: it needs the files the parent writes and
/// serves until the parent kills it.
#[test]
#[ignore = "started as a child process by clean_and_found_lines_carry_the_scan_time"]
fn pk112_proxy_child() -> TestResult {
    let dir = pk112_dir();
    let port: u16 = std::fs::read_to_string(dir.join("upstream-port.txt"))?
        .trim()
        .parse()?;
    let setup = Setup {
        blocklist: String::new(),
        allowlist: String::new(),
        mitm_list: String::from("localhost\n"),
        clamd: Some(ClamdAddr::Unix(short_socket_path(&dir)?)),
        upstream_roots: vec![CertificateDer::from_pem_file(dir.join("upstream-ca.pem"))?],
        mitm_limits: MitmLimits {
            decrypt_port: port,
            ..MitmLimits::default()
        },
        deny: DenyMode::Forbid,
    };
    let proxy = start_proxy(&fresh_dir("pk112/child")?, setup)?;
    std::fs::write(dir.join("proxy-addr.txt"), proxy.addr.to_string())?;
    loop {
        std::thread::park();
    }
}

/// Kills and reaps the proxy child however the test ends.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits until the child has written its address, or it exits, or 20 s pass.
fn wait_for_proxy_addr(guard: &mut ChildGuard, dir: &Path) -> Result<SocketAddr, Box<dyn Error>> {
    let file = dir.join("proxy-addr.txt");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(status) = guard.0.try_wait()? {
            return Err(format!("the proxy child exited early: {status}").into());
        }
        if let Ok(text) = std::fs::read_to_string(&file) {
            return Ok(text.trim().parse()?);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("the proxy child did not start in 20 s".into())
}

/// Reads lines from `lines` until one passes `wanted`, keeping every line seen.
fn wait_for_line(
    lines: &mpsc::Receiver<String>,
    seen: &mut Vec<String>,
    wanted: impl Fn(&str) -> bool,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let line = lines.recv_timeout(deadline.saturating_duration_since(Instant::now()))?;
        let done = wanted(&line);
        seen.push(line);
        if done {
            return Ok(());
        }
    }
}

fn is_clean_line(line: &str) -> bool {
    line.contains("[info]") && (line.contains("clean だった") || line.contains("scanned clean"))
}

fn is_found_line(line: &str) -> bool {
    line.contains("[info]") && (line.contains("検知した") || line.contains("detected;"))
}

/// The `ms=` value of a line, which must be a whole number followed by
/// `sha256=`.
fn scan_ms(line: &str) -> Result<u64, Box<dyn Error>> {
    let (_, rest) = line.split_once(" ms=").ok_or("no ms= in the line")?;
    let (digits, tail) = rest.split_once(' ').ok_or("nothing after ms=")?;
    if !tail.starts_with("sha256=") {
        return Err(format!("sha256= does not follow ms=: {line}").into());
    }
    Ok(digits.parse()?)
}

#[test]
fn clean_and_found_lines_carry_the_scan_time() -> TestResult {
    // The production timeouts: a scan may take 1260 s, the startup PING 10 s.
    assert_eq!(
        MitmLimits::default().clamd_timeout,
        Duration::from_secs(1260)
    );
    assert_eq!(packetdeath::clamd::PING_TIMEOUT, Duration::from_secs(10));
    let dir = fresh_dir("pk112")?;
    let pki = test_pki("packetdeath test upstream CA")?;
    let upstream = spawn_upstream(
        &pki,
        Arc::new(|_, path| {
            if path == "/eicar.com" {
                file_response("application/octet-stream", &eicar())
            } else {
                file_response("application/zip", &random_bytes(64 * 1024))
            }
        }),
    )?;
    // The fake clamd answers after 30 ms, so a timed scan cannot read 0.
    let _clamd = spawn_clamd(&dir, Duration::from_millis(30))?;
    std::fs::write(dir.join("upstream-ca.pem"), &pki.ca_pem)?;
    std::fs::write(dir.join("upstream-port.txt"), upstream.port.to_string())?;

    let mut child = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "pk112_proxy_child", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("the proxy child has no stderr")?;
    let mut guard = ChildGuard(child);
    let (tx, lines) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let proxy = wait_for_proxy_addr(&mut guard, &dir)?;
    let roots = vec![
        CertificateDer::from_pem_file(dir.join("child/ca/ca.crt"))?,
        pki.ca_der.clone(),
    ];
    let mut seen = Vec::new();

    let clean = fetch(
        proxy,
        "localhost",
        upstream.port,
        &roots,
        &get_request("GET", "/file.zip"),
    )?;
    assert_eq!(clean.status, 200, "{}", clean.head);
    wait_for_line(&lines, &mut seen, is_clean_line)?;

    let found = fetch(
        proxy,
        "localhost",
        upstream.port,
        &roots,
        &get_request("GET", "/eicar.com"),
    )?;
    assert_eq!(found.status, 403, "{}", found.head);
    wait_for_line(&lines, &mut seen, is_found_line)?;

    drop(guard);
    reader.join().map_err(|_| "the stderr reader panicked")?;
    seen.extend(lines.try_iter());

    let clean_lines: Vec<&String> = seen.iter().filter(|l| is_clean_line(l)).collect();
    let found_lines: Vec<&String> = seen.iter().filter(|l| is_found_line(l)).collect();
    assert_eq!(clean_lines.len(), 1, "{seen:?}");
    assert_eq!(found_lines.len(), 1, "{seen:?}");
    for line in clean_lines.into_iter().chain(found_lines) {
        let ms = scan_ms(line)?;
        assert!((30..10_000).contains(&ms), "ms={ms} in {line}");
    }
    Ok(())
}
