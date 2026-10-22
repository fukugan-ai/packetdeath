//! Acceptance tests of stage 10 (active defense): `docs/design.md` "段階10
//! 能動防御（PC を守る見張りと遮断）", acceptance IDs PK-130, PK-133 to PK-140.
//!
//! Every test but PK-130 and PK-138 runs the real `proxy::serve` against a
//! fake HTTPS upstream (a rustls server) whose chain is
//! `leaf -> intermediate -> root`, all made here by `rcgen`. The "distrusted"
//! lists are written by the tests from the hashes of those certificates, so no
//! host outside this machine decides a result. PK-130 starts the real
//! `packetdeath` binary; PK-138 drives `Defense` directly, because it needs
//! more distinct hosts than a loopback upstream can be called.
//!
//! Scratch files live under `CARGO_TARGET_TMPDIR`; nothing is written into the
//! source tree.
#![cfg(target_os = "linux")]

use aws_lc_rs::digest;
use packetdeath::allowlist::Allowlist;
use packetdeath::av::AvList;
use packetdeath::block_loop::{MitmList, WatchInputs};
use packetdeath::blocklist::Blocklist;
use packetdeath::clamd::ClamdAddr;
use packetdeath::defense::{Defense, DefenseConfig, FlowFacts};
use packetdeath::flow::{redirect_service_log, FlowKey, FlowLogSink, Proto, ServiceLog};
use packetdeath::iplist::IpList;
use packetdeath::mitm::{Mitm, MitmLimits, MitmSettings};
use packetdeath::prober::ProbeSettings;
use packetdeath::proxy::{self, AllowFrom, DenyMode, ProxyLimits};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, TrustAnchor,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::error::Error;
use std::io::{BufRead, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn Error>>;

// ------------------------------------------------------------------
// Scratch space and the service log
// ------------------------------------------------------------------

fn fresh_dir(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("stage10")
        .join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Every `[info]` / `[warn]` / `[error]` line of this test binary goes to one
/// file, so a test can count the lines the proxy printed.
fn service_log_path() -> Result<&'static PathBuf, Box<dyn Error>> {
    static LOG: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    let made = LOG.get_or_init(|| {
        let made = fresh_dir("service-log").map_err(|e| e.to_string())?;
        let path = made.join("service.log");
        let log = ServiceLog::open(&path, None).map_err(|e| e.to_string())?;
        redirect_service_log(log);
        Ok(path)
    });
    made.as_ref().map_err(|e| e.clone().into())
}

fn count_in_service_log(needle: &str) -> Result<usize, Box<dyn Error>> {
    let text = std::fs::read_to_string(service_log_path()?)?;
    Ok(text.lines().filter(|line| line.contains(needle)).count())
}

fn read_lines(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .map(str::to_owned)
        .collect())
}

// ------------------------------------------------------------------
// Test PKI: leaf -> intermediate -> root
// ------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();
        let n = u32::from(chunk[0]) << 16
            | second.map_or(0, |byte| u32::from(byte) << 8)
            | third.map_or(0, u32::from);
        for (at, shift) in [18_u32, 12, 6, 0].into_iter().enumerate() {
            if at <= chunk.len() {
                out.push(char::from(TABLE[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

struct Chain {
    root: CertificateDer<'static>,
    intermediate: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    leaf_key: Vec<u8>,
    intermediate_sha1: String,
    leaf_sha1: String,
    /// `spki-sha256` value of the root, computed from the key pair.
    root_spki_b64: String,
}

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

fn sha1_hex(der: &[u8]) -> String {
    hex(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, der).as_ref())
}

fn test_chain() -> Result<Chain, Box<dyn Error>> {
    let root_key = KeyPair::generate()?;
    let root_params = ca_params("packetdeath stage10 test root");
    let root_cert = root_params.self_signed(&root_key)?;
    let root_spki = digest::digest(&digest::SHA256, &root_key.subject_public_key_info());
    let root_issuer = Issuer::new(root_params, root_key);

    let int_key = KeyPair::generate()?;
    let int_params = ca_params("packetdeath stage10 test intermediate");
    let int_cert = int_params.signed_by(&int_key, &root_issuer)?;
    let int_issuer = Issuer::new(int_params, int_key);

    let leaf_key = KeyPair::generate()?;
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &int_issuer)?;
    Ok(Chain {
        root: root_cert.der().clone(),
        intermediate_sha1: sha1_hex(int_cert.der()),
        intermediate: int_cert.der().clone(),
        leaf_sha1: sha1_hex(leaf.der()),
        leaf: leaf.der().clone(),
        leaf_key: leaf_key.serialize_der(),
        root_spki_b64: base64(root_spki.as_ref()),
    })
}

fn anchors_of(root: &CertificateDer<'static>) -> Result<Vec<TrustAnchor<'static>>, Box<dyn Error>> {
    let mut store = RootCertStore::empty();
    store.add(root.clone())?;
    Ok(store.roots)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

// ------------------------------------------------------------------
// Fake upstreams
// ------------------------------------------------------------------

struct Upstream {
    port: u16,
    accepted: Arc<AtomicUsize>,
}

/// An HTTPS server that sends `leaf, intermediate` and answers every request
/// with a tiny `image/png` (a type stage 8 does not scan).
fn spawn_upstream(chain: &Chain) -> Result<Upstream, Box<dyn Error>> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.leaf_key.clone()));
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![chain.leaf.clone(), chain.intermediate.clone()], key)?;
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let _ = serve_one(stream, config);
            });
        }
    });
    Ok(Upstream { port, accepted })
}

fn serve_one(stream: TcpStream, config: Arc<ServerConfig>) -> Result<(), Box<dyn Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut tls = StreamOwned::new(ServerConnection::new(config)?, stream);
    loop {
        let mut line = Vec::new();
        if tls.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        if line == b"\r\n" {
            break;
        }
    }
    tls.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    )?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

/// A server that accepts and never answers: a probe stalls on it.
fn spawn_silent() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    Ok(port)
}

// ------------------------------------------------------------------
// The proxy under test
// ------------------------------------------------------------------

#[derive(Default)]
struct Options {
    /// Run stage 10 at all. `false` is the baseline proxy.
    defense: bool,
    /// Decrypt `localhost` (stage 8).
    mitm: bool,
    /// Stage 7 `--blocklist` content.
    blocklist: String,
    /// `Some` writes `allowlist.txt` and watches it.
    allowlist: Option<String>,
    stop: Vec<(&'static str, String)>,
    watch_distrust: Vec<(&'static str, String)>,
    watch_blocklists: Vec<(&'static str, String)>,
    watch_iplists: Vec<(&'static str, String)>,
    probe: Option<ProbeSettings>,
    off_file: bool,
}

struct Env {
    dir: PathBuf,
    proxy: SocketAddr,
    flows: PathBuf,
    watch: PathBuf,
    ca_file: PathBuf,
    defense: Option<Arc<Defense>>,
}

fn write_lists(dir: &Path, lists: &[(&str, String)]) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut paths = Vec::new();
    for (name, content) in lists {
        let path = dir.join(name);
        std::fs::write(&path, content)?;
        paths.push(path);
    }
    Ok(paths)
}

fn defense_config(dir: &Path, chain: &Chain, o: &Options) -> Result<DefenseConfig, Box<dyn Error>> {
    let mut config = DefenseConfig::new(dir.join("watch.jsonl"), anchors_of(&chain.root)?);
    config.stop_distrust = write_lists(dir, &o.stop)?;
    config.watch_distrust = write_lists(dir, &o.watch_distrust)?;
    config.watch_blocklists = write_lists(dir, &o.watch_blocklists)?;
    config.watch_iplists = write_lists(dir, &o.watch_iplists)?;
    config.probe = o.probe.clone();
    config.off_file = o.off_file.then(|| dir.join("defense-off"));
    Ok(config)
}

fn start_mitm(dir: &Path, chain: &Chain, port: u16) -> Result<Mitm, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(chain.root.clone())?;
    Ok(Mitm::start(MitmSettings {
        ca_dir: dir.join("ca"),
        clamd: ClamdAddr::Unix(dir.join("no-clamd.sock")),
        av_log: dir.join("av.jsonl"),
        upstream_roots: roots,
        limits: MitmLimits {
            decrypt_port: port,
            ..MitmLimits::default()
        },
    })?)
}

fn start_env(
    name: &str,
    upstream_port: u16,
    chain: &Chain,
    o: Options,
) -> Result<Env, Box<dyn Error>> {
    service_log_path()?;
    let dir = fresh_dir(name)?;
    let listener = proxy::bind("127.0.0.1:0".parse()?)?;
    let proxy = listener.local_addr()?;
    let flows = dir.join("flows.jsonl");
    let log = FlowLogSink::open(&flows)?;
    let defense = if o.defense {
        Some(Arc::new(Defense::start(defense_config(&dir, chain, &o)?)?))
    } else {
        None
    };
    let mitm = if o.mitm {
        Some(start_mitm(&dir, chain, upstream_port)?)
    } else {
        None
    };
    let mitm_list = dir.join("mitm.txt");
    std::fs::write(&mitm_list, "localhost\n")?;
    let allowlist_file = dir.join("allowlist.txt");
    let allowlist = match &o.allowlist {
        Some(text) => {
            std::fs::write(&allowlist_file, text)?;
            Allowlist::parse(text)
        }
        None => Allowlist::empty(),
    };
    let allowlist_path = o.allowlist.as_ref().map(|_| allowlist_file);
    let blocklist = Blocklist::parse(&o.blocklist);
    let limits = ProxyLimits {
        deny: DenyMode::Forbid,
        ..ProxyLimits::default()
    };
    let for_thread = defense.clone();
    std::thread::spawn(move || {
        let av = AvList::empty();
        let inputs = WatchInputs::new(blocklist, allowlist, allowlist_path, IpList::empty(), &av);
        let inputs = if mitm.is_some() {
            let list = MitmList::load(&mitm_list);
            inputs.with_mitm_list(mitm_list, list)
        } else {
            inputs
        };
        let inputs = match for_thread {
            Some(defense) => inputs.with_defense(defense),
            None => inputs,
        };
        let allow_from = AllowFrom::from_args(&[]);
        proxy::serve(listener, &allow_from, &log, inputs, limits, mitm.as_ref());
    });
    Ok(Env {
        watch: dir.join("watch.jsonl"),
        ca_file: dir.join("ca").join("ca.crt"),
        dir,
        proxy,
        flows,
        defense,
    })
}

// ------------------------------------------------------------------
// Clients
// ------------------------------------------------------------------

/// Sends `CONNECT host:port` and returns the stream after the proxy's head.
fn connect_through(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> Result<(TcpStream, String), Box<dyn Error>> {
    let mut stream = TcpStream::connect(proxy)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    write!(
        stream,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    )?;
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok((stream, String::from_utf8_lossy(&head).into_owned()))
}

fn status_of(head: &str) -> Result<u16, Box<dyn Error>> {
    Ok(head
        .split(' ')
        .nth(1)
        .ok_or("no status in the head")?
        .parse()?)
}

/// The status the proxy answers to a CONNECT.
fn connect_status(proxy: SocketAddr, host: &str, port: u16) -> Result<u16, Box<dyn Error>> {
    let (_stream, head) = connect_through(proxy, host, port)?;
    status_of(&head)
}

/// What an HTTPS request through the proxy ended in.
enum Got {
    /// The proxy refused the CONNECT with this head.
    Refused(String),
    /// The upstream's answer, and whether packetdeath's CA signed the leaf.
    Served { status: u16, decrypted: bool },
}

fn https_get(
    proxy: SocketAddr,
    port: u16,
    roots: &[CertificateDer<'static>],
) -> Result<Got, Box<dyn Error>> {
    let (stream, head) = connect_through(proxy, "localhost", port)?;
    if !head.starts_with("HTTP/1.1 200") {
        return Ok(Got::Refused(head));
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
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    tls.flush()?;
    let mut raw = Vec::new();
    let _ = tls.read_to_end(&mut raw);
    let decrypted = match tls.conn.peer_certificates() {
        Some([leaf, ..]) => leaf.windows(14).any(|window| window == b"packetdeath CA"),
        _ => false,
    };
    let text = String::from_utf8_lossy(&raw).into_owned();
    Ok(Got::Served {
        status: status_of(&text)?,
        decrypted,
    })
}

impl Env {
    fn connect(&self, host: &str, port: u16) -> Result<u16, Box<dyn Error>> {
        connect_status(self.proxy, host, port)
    }

    fn flow_lines(&self) -> Result<Vec<String>, Box<dyn Error>> {
        read_lines(&self.flows)
    }

    fn watch_lines(&self) -> Result<Vec<String>, Box<dyn Error>> {
        read_lines(&self.watch)
    }

    /// Waits until the prober has stored a chain for `host`.
    fn wait_for_verdict(&self, host: &str) -> Result<(), Box<dyn Error>> {
        let defense = self.defense.as_ref().ok_or("no defense in this env")?;
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if defense.verdicts().is_fresh(host, Instant::now()) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err("the prober stored no chain in time".into())
    }

    /// The proxy CA plus the test root, so a fetch works either way and
    /// `decrypted` says which way it went.
    fn client_roots(&self, chain: &Chain) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
        Ok(vec![
            CertificateDer::from_pem_file(&self.ca_file)?,
            chain.root.clone(),
        ])
    }
}

fn probe_settings(port: u16) -> ProbeSettings {
    ProbeSettings {
        port,
        min_interval: Duration::from_millis(20),
        timeout: Duration::from_secs(2),
        public_only: false,
        ..ProbeSettings::default()
    }
}

fn lines_containing(lines: &[String], needle: &str) -> usize {
    lines.iter().filter(|line| line.contains(needle)).count()
}

// ------------------------------------------------------------------
// PK-130: nothing given, nothing changes
// ------------------------------------------------------------------

struct Binary {
    child: Child,
    dir: PathBuf,
    addr: SocketAddr,
}

impl Drop for Binary {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the real `packetdeath proxy` on a free port.
fn run_binary(name: &str, extra: &[&str]) -> Result<Binary, Box<dyn Error>> {
    let dir = fresh_dir(name)?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let child = Command::new(env!("CARGO_BIN_EXE_packetdeath"))
        .args([
            "proxy",
            "--deny",
            "403",
            "--listen",
            &addr.to_string(),
            "--log-dir",
        ])
        .arg(&dir)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let binary = Binary { child, dir, addr };
    let until = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(addr).is_err() {
        if Instant::now() > until {
            return Err("the binary did not listen in time".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(binary)
}

#[test]
fn without_stage10_options_no_watch_log_is_written() -> TestResult {
    let silent = spawn_silent()?;
    let plain = run_binary("p130-plain", &[])?;
    assert_eq!(connect_status(plain.addr, "localhost", silent)?, 200);
    assert!(plain.dir.join("flows.jsonl").exists());
    assert!(
        !plain.dir.join("watch.jsonl").exists(),
        "a proxy without stage 10 options made watch.jsonl"
    );

    // Negative control: one stage 10 option makes the file.
    let list = fresh_dir("p130-list")?.join("w.txt");
    std::fs::write(&list, "example.invalid\n")?;
    let list = list.to_string_lossy().into_owned();
    let watching = run_binary("p130-watch", &["--watch-blocklist", &list])?;
    assert_eq!(connect_status(watching.addr, "localhost", silent)?, 200);
    assert!(watching.dir.join("watch.jsonl").exists());

    // The Cargo.lock holds the same number of packages as before stage 10.
    let lock = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))?;
    assert_eq!(
        lock.lines().filter(|l| l.starts_with("name = ")).count(),
        88
    );
    Ok(())
}

// ------------------------------------------------------------------
// PK-133: a watch list hit is logged and the flow passes
// ------------------------------------------------------------------

#[test]
fn a_watch_list_hit_is_logged_and_the_flow_passes() -> TestResult {
    let chain = test_chain()?;
    let upstream = spawn_upstream(&chain)?;
    let env = start_env(
        "p133-watch",
        upstream.port,
        &chain,
        Options {
            defense: true,
            watch_blocklists: vec![("w.txt", "localhost\n".to_owned())],
            ..Options::default()
        },
    )?;
    assert_eq!(env.connect("localhost", upstream.port)?, 200);
    let watch = env.watch_lines()?;
    assert_eq!(watch.len(), 1, "{watch:?}");
    for field in [
        "\"sni\":\"localhost\"",
        "\"source\":\"w.txt\"",
        "\"kind\":\"blocklist\"",
        "\"mode\":\"watch\"",
        "\"allowlisted\":false",
    ] {
        assert!(watch[0].contains(field), "{field} missing in {}", watch[0]);
    }
    let flows = env.flow_lines()?;
    let last = flows.last().ok_or("no flow row")?;
    assert!(last.contains("\"decision\":\"pass\"") && last.contains("\"reason\":null"));

    // The allowlist does not hide the hit from the watch.
    let allowed = start_env(
        "p133-allowlisted",
        upstream.port,
        &chain,
        Options {
            defense: true,
            allowlist: Some("localhost\n".to_owned()),
            watch_blocklists: vec![("w.txt", "localhost\n".to_owned())],
            ..Options::default()
        },
    )?;
    assert_eq!(allowed.connect("localhost", upstream.port)?, 200);
    let watch = allowed.watch_lines()?;
    assert_eq!(watch.len(), 1, "{watch:?}");
    assert!(watch[0].contains("\"allowlisted\":true"), "{}", watch[0]);

    // Negative control: the same list given as a stop list denies the CONNECT.
    let stopped = start_env(
        "p133-stop",
        upstream.port,
        &chain,
        Options {
            blocklist: "localhost\n".to_owned(),
            ..Options::default()
        },
    )?;
    assert_eq!(stopped.connect("localhost", upstream.port)?, 403);
    Ok(())
}

// ------------------------------------------------------------------
// PK-134 and PK-135: the upstream chain of a decrypted CONNECT
// ------------------------------------------------------------------

#[test]
fn a_distrusted_upstream_chain_is_logged_in_watch_mode() -> TestResult {
    let chain = test_chain()?;
    let upstream = spawn_upstream(&chain)?;
    let line = format!("cert-sha1 {}\n", chain.intermediate_sha1);
    let env = start_env(
        "p134-watch",
        upstream.port,
        &chain,
        Options {
            defense: true,
            mitm: true,
            watch_distrust: vec![("manual.txt", line)],
            ..Options::default()
        },
    )?;
    let roots = env.client_roots(&chain)?;
    let Got::Served { status, decrypted } = https_get(env.proxy, upstream.port, &roots)? else {
        return Err("the CONNECT was refused in watch mode".into());
    };
    assert_eq!(status, 200);
    assert!(decrypted, "the connection was not decrypted");
    let watch = env.watch_lines()?;
    assert_eq!(watch.len(), 1, "{watch:?}");
    for field in [
        "\"kind\":\"distrust\"",
        "\"source\":\"manual.txt\"",
        "\"mode\":\"watch\"",
    ] {
        assert!(watch[0].contains(field), "{field} missing in {}", watch[0]);
    }
    assert_eq!(
        lines_containing(&env.flow_lines()?, "\"decision\":\"block\""),
        0
    );

    // Negative control: a list that holds nothing of the chain writes nothing.
    let quiet = start_env(
        "p134-quiet",
        upstream.port,
        &chain,
        Options {
            defense: true,
            mitm: true,
            watch_distrust: vec![("manual.txt", "# empty\n".to_owned())],
            ..Options::default()
        },
    )?;
    let roots = quiet.client_roots(&chain)?;
    let Got::Served { status, .. } = https_get(quiet.proxy, upstream.port, &roots)? else {
        return Err("the CONNECT was refused with an empty list".into());
    };
    assert_eq!(status, 200);
    assert!(quiet.watch_lines()?.is_empty());
    Ok(())
}

#[test]
fn a_distrusted_upstream_chain_is_denied_and_not_tunneled() -> TestResult {
    let chain = test_chain()?;
    let lines = [
        (
            "intermediate",
            format!("cert-sha1 {}\n", chain.intermediate_sha1),
        ),
        ("root", format!("spki-sha256 {}\n", chain.root_spki_b64)),
    ];
    for (which, line) in lines {
        let upstream = spawn_upstream(&chain)?;
        let env = start_env(
            &format!("p135-{which}"),
            upstream.port,
            &chain,
            Options {
                defense: true,
                mitm: true,
                stop: vec![("canary.txt", line)],
                ..Options::default()
            },
        )?;
        let roots = env.client_roots(&chain)?;
        let Got::Refused(head) = https_get(env.proxy, upstream.port, &roots)? else {
            return Err(format!("{which}: the distrusted chain was served").into());
        };
        assert!(head.starts_with("HTTP/1.1 403"), "{which}: {head:?}");
        let flows = env.flow_lines()?;
        let last = flows.last().ok_or("no flow row")?;
        assert!(
            last.contains("\"decision\":\"block\"") && last.contains("\"reason\":\"chain\""),
            "{which}: {last}"
        );
        // The proxy opened one connection (to read the chain) and no other.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(upstream.accepted.load(Ordering::SeqCst), 1, "{which}");
    }

    // Negative control: a chain no list names is decrypted and served.
    let upstream = spawn_upstream(&chain)?;
    let env = start_env(
        "p135-clean",
        upstream.port,
        &chain,
        Options {
            defense: true,
            mitm: true,
            stop: vec![(
                "canary.txt",
                "cert-sha1 0000000000000000000000000000000000000000\n".to_owned(),
            )],
            ..Options::default()
        },
    )?;
    let roots = env.client_roots(&chain)?;
    let Got::Served { status, decrypted } = https_get(env.proxy, upstream.port, &roots)? else {
        return Err("a clean chain was refused".into());
    };
    assert_eq!(status, 200);
    assert!(decrypted);
    assert_eq!(
        lines_containing(&env.flow_lines()?, "\"reason\":\"chain\""),
        0
    );
    Ok(())
}

// ------------------------------------------------------------------
// PK-136 and PK-137: the prober
// ------------------------------------------------------------------

#[test]
fn the_prober_records_a_distrusted_chain_without_blocking_in_watch_mode() -> TestResult {
    let chain = test_chain()?;
    let upstream = spawn_upstream(&chain)?;
    let env = start_env(
        "p136-watch",
        upstream.port,
        &chain,
        Options {
            defense: true,
            probe: Some(probe_settings(upstream.port)),
            watch_distrust: vec![(
                "manual.txt",
                format!("cert-sha1 {}\n", chain.intermediate_sha1),
            )],
            ..Options::default()
        },
    )?;
    assert_eq!(env.connect("localhost", upstream.port)?, 200);
    env.wait_for_verdict("localhost")?;
    assert_eq!(env.connect("localhost", upstream.port)?, 200);
    let watch = env.watch_lines()?;
    assert_eq!(
        lines_containing(&watch, "\"source\":\"probe\""),
        1,
        "{watch:?}"
    );
    assert_eq!(
        lines_containing(&watch, "\"kind\":\"chain\""),
        1,
        "{watch:?}"
    );

    // Negative control: a server that never answers stores nothing, and the
    // flow still passes.
    let silent = spawn_silent()?;
    let stalled = start_env(
        "p136-silent",
        upstream.port,
        &chain,
        Options {
            defense: true,
            probe: Some(ProbeSettings {
                timeout: Duration::from_millis(300),
                ..probe_settings(silent)
            }),
            watch_distrust: vec![(
                "manual.txt",
                format!("cert-sha1 {}\n", chain.intermediate_sha1),
            )],
            ..Options::default()
        },
    )?;
    assert_eq!(stalled.connect("localhost", silent)?, 200);
    std::thread::sleep(Duration::from_millis(900));
    let defense = stalled.defense.as_ref().ok_or("no defense")?;
    assert!(!defense.verdicts().is_fresh("localhost", Instant::now()));
    assert_eq!(stalled.connect("localhost", silent)?, 200);
    assert!(stalled.watch_lines()?.is_empty());
    Ok(())
}

#[test]
fn a_host_marked_by_the_prober_is_denied_on_the_next_connect() -> TestResult {
    let chain = test_chain()?;
    let upstream = spawn_upstream(&chain)?;
    let env = start_env(
        "p137-marked",
        upstream.port,
        &chain,
        Options {
            defense: true,
            probe: Some(probe_settings(upstream.port)),
            stop: vec![(
                "canary.txt",
                format!("cert-sha1 {}\n", chain.intermediate_sha1),
            )],
            allowlist: Some(String::new()),
            ..Options::default()
        },
    )?;
    // The first connect passes (the prober reacts, it does not hold flows).
    assert_eq!(env.connect("localhost", upstream.port)?, 200);
    env.wait_for_verdict("localhost")?;
    assert_eq!(env.connect("localhost", upstream.port)?, 403);
    let flows = env.flow_lines()?;
    let last = flows.last().ok_or("no flow row")?;
    assert!(last.contains("\"reason\":\"chain\""), "{last}");

    // The allowlist beats stage 10, and says so once.
    let warning =
        packetdeath::i18n::chain_marked_allowlisted(packetdeath::i18n::locale(), "localhost");
    let before = count_in_service_log(&warning)?;
    std::fs::write(env.dir.join("allowlist.txt"), "localhost\n")?;
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(env.connect("localhost", upstream.port)?, 200);
    assert_eq!(env.connect("localhost", upstream.port)?, 200);
    assert_eq!(count_in_service_log(&warning)? - before, 1);

    // Negative control: a chain the list does not name stays open and quiet.
    let quiet = start_env(
        "p137-quiet",
        upstream.port,
        &chain,
        Options {
            defense: true,
            probe: Some(probe_settings(upstream.port)),
            stop: vec![(
                "canary.txt",
                "cert-sha1 0000000000000000000000000000000000000000\n".to_owned(),
            )],
            allowlist: Some(String::new()),
            ..Options::default()
        },
    )?;
    assert_eq!(quiet.connect("localhost", upstream.port)?, 200);
    quiet.wait_for_verdict("localhost")?;
    assert_eq!(quiet.connect("localhost", upstream.port)?, 200);
    std::fs::write(quiet.dir.join("allowlist.txt"), "localhost\n")?;
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(quiet.connect("localhost", upstream.port)?, 200);
    assert_eq!(
        count_in_service_log(&warning)? - before,
        1,
        "the quiet env warned"
    );
    Ok(())
}

// ------------------------------------------------------------------
// PK-138: the breaker
// ------------------------------------------------------------------

fn facts(host: &str) -> FlowFacts<'_> {
    FlowFacts {
        key: FlowKey {
            proto: Proto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            src_port: 40000,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            dst_port: 443,
        },
        host,
        allowlisted: false,
    }
}

#[test]
fn a_distrust_source_over_the_breaker_threshold_falls_back_to_watch() -> TestResult {
    service_log_path()?;
    let chain = test_chain()?;
    let dir = fresh_dir("p138-breaker")?;
    let options = Options {
        stop: vec![
            ("a.txt", format!("cert-sha1 {}\n", chain.intermediate_sha1)),
            ("b.txt", format!("cert-sha1 {}\n", chain.leaf_sha1)),
        ],
        ..Options::default()
    };
    let mut config = defense_config(&dir, &chain, &options)?;
    config.breaker_hosts = 3;
    let defense = Defense::start(config)?;
    let full = [chain.leaf.clone(), chain.intermediate.clone()];
    let leaf_only = [chain.leaf.clone()];
    let tripped = packetdeath::i18n::breaker_tripped(packetdeath::i18n::locale(), "a.txt", 3);
    let watch = dir.join("watch.jsonl");

    // Exactly the threshold: every host is stopped and the breaker stays quiet.
    for host in ["h1.test", "h2.test", "h3.test"] {
        assert!(defense.check_upstream_chain(&facts(host), &full), "{host}");
    }
    assert_eq!(count_in_service_log(&tripped)?, 0);
    assert!(read_lines(&watch)?.is_empty());

    // One host over: it falls to watch, with one [error].
    assert!(!defense.check_upstream_chain(&facts("h4.test"), &full));
    assert_eq!(count_in_service_log(&tripped)?, 1);
    assert!(!defense.check_upstream_chain(&facts("h5.test"), &full));
    assert_eq!(count_in_service_log(&tripped)?, 1, "one [error] only");
    let rows = read_lines(&watch)?;
    assert_eq!(
        lines_containing(&rows, "\"mode\":\"breaker\""),
        2,
        "{rows:?}"
    );
    assert_eq!(
        lines_containing(&rows, "\"source\":\"a.txt\""),
        2,
        "{rows:?}"
    );

    // Another source keeps stopping.
    assert!(defense.check_upstream_chain(&facts("h6.test"), &leaf_only));

    // A changed file brings the source back.
    std::fs::write(
        dir.join("a.txt"),
        format!("# reviewed\ncert-sha1 {}\n", chain.intermediate_sha1),
    )?;
    defense.poll();
    assert!(defense.check_upstream_chain(&facts("h7.test"), &full));
    Ok(())
}

// ------------------------------------------------------------------
// PK-139: --defense-off
// ------------------------------------------------------------------

#[test]
fn the_defense_off_file_turns_stage10_blocking_into_watch_within_one_poll() -> TestResult {
    let chain = test_chain()?;
    let upstream = spawn_upstream(&chain)?;
    let env = start_env(
        "p139-off",
        upstream.port,
        &chain,
        Options {
            defense: true,
            off_file: true,
            probe: Some(probe_settings(upstream.port)),
            blocklist: "blocked.test\n".to_owned(),
            stop: vec![(
                "canary.txt",
                format!("cert-sha1 {}\n", chain.intermediate_sha1),
            )],
            ..Options::default()
        },
    )?;
    let off = env.dir.join("defense-off");
    assert_eq!(env.connect("localhost", upstream.port)?, 200);
    env.wait_for_verdict("localhost")?;
    // Negative control: without the file the mark stops the host.
    assert_eq!(env.connect("localhost", upstream.port)?, 403);

    std::fs::write(&off, "")?;
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(env.connect("localhost", upstream.port)?, 200);
    let watch = env.watch_lines()?;
    let last = watch.last().ok_or("no watch row")?;
    assert!(last.contains("\"mode\":\"off\""), "{last}");
    // The stage 7 blocklist is not stage 10: it keeps denying.
    assert_eq!(env.connect("blocked.test", 443)?, 403);

    std::fs::remove_file(&off)?;
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(env.connect("localhost", upstream.port)?, 403);
    Ok(())
}

// ------------------------------------------------------------------
// PK-140: speed
// ------------------------------------------------------------------

fn connect_latency(proxy: SocketAddr, port: u16) -> Result<Duration, Box<dyn Error>> {
    let started = Instant::now();
    let (_stream, head) = connect_through(proxy, "localhost", port)?;
    let elapsed = started.elapsed();
    if status_of(&head)? != 200 {
        return Err(format!("CONNECT was refused: {head:?}").into());
    }
    Ok(elapsed)
}

fn p95(mut samples: Vec<Duration>) -> Result<Duration, Box<dyn Error>> {
    samples.sort();
    let at = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    samples.get(at).copied().ok_or_else(|| "no samples".into())
}

#[test]
fn stage10_judging_adds_at_most_five_ms_to_connect_p95() -> TestResult {
    let chain = test_chain()?;
    let upstream = spawn_upstream(&chain)?;
    let plain = start_env("p140-plain", upstream.port, &chain, Options::default())?;
    let full = start_env(
        "p140-full",
        upstream.port,
        &chain,
        Options {
            defense: true,
            off_file: true,
            probe: Some(probe_settings(upstream.port)),
            stop: vec![(
                "canary.txt",
                "cert-sha1 0000000000000000000000000000000000000001\n".to_owned(),
            )],
            watch_distrust: vec![(
                "manual.txt",
                "cert-sha1 0000000000000000000000000000000000000000\n".to_owned(),
            )],
            watch_blocklists: vec![("w.txt", "tracker.invalid\n".to_owned())],
            watch_iplists: vec![("ips.txt", "203.0.113.7\n".to_owned())],
            ..Options::default()
        },
    )?;
    for _ in 0..5 {
        connect_latency(plain.proxy, upstream.port)?;
        connect_latency(full.proxy, upstream.port)?;
    }
    let (mut base, mut with_defense) = (Vec::new(), Vec::new());
    for _ in 0..50 {
        base.push(connect_latency(plain.proxy, upstream.port)?);
        with_defense.push(connect_latency(full.proxy, upstream.port)?);
    }
    let (base, with_defense) = (p95(base)?, p95(with_defense)?);
    let diff_ms = with_defense.as_secs_f64() * 1000.0 - base.as_secs_f64() * 1000.0;
    println!(
        "p95_base_ms={:.3} p95_stage10_ms={:.3} p95_diff_ms={diff_ms:.3}",
        base.as_secs_f64() * 1000.0,
        with_defense.as_secs_f64() * 1000.0
    );
    assert!(diff_ms <= 5.0, "stage 10 added {diff_ms:.3} ms at p95");

    // A probe stuck on a silent server does not slow other connects.
    let silent = spawn_silent()?;
    let stuck = start_env(
        "p140-stuck",
        upstream.port,
        &chain,
        Options {
            defense: true,
            probe: Some(ProbeSettings {
                timeout: Duration::from_secs(5),
                ..probe_settings(silent)
            }),
            ..Options::default()
        },
    )?;
    assert_eq!(stuck.connect("localhost", silent)?, 200);
    std::thread::sleep(Duration::from_millis(300));
    let mut worst = Duration::ZERO;
    for _ in 0..20 {
        worst = worst.max(connect_latency(stuck.proxy, upstream.port)?);
    }
    println!(
        "worst_connect_while_probe_stalled_s={:.3}",
        worst.as_secs_f64()
    );
    assert!(worst <= Duration::from_millis(500), "{worst:?}");
    Ok(())
}
