//! Stage 10: the chain prober and the table of chains it reads.
//! `docs/design.md` "段階10 能動防御（PC を守る見張りと遮断）", policy 3, is the
//! source of truth.
//!
//! TLS 1.3 encrypts the server certificate, so nothing on the path can read a
//! chain. The prober opens its own TLS connection to a host a client already
//! reached, reads the chain the server sends and keeps its fingerprints in
//! [`ChainVerdicts`]. It sends no HTTP request: the handshake is stopped as
//! soon as the chain has been read.
//!
//! Rules that keep it harmless:
//! - It never judges. The judge path only reads the table ([`ChainJudge`]), so
//!   no I/O happens in `Judge::judge`, and the first flow to a host is never
//!   held back (reactive, like an IDS).
//! - The destination is the flow's own `dst_ip`. The host name is only used as
//!   the SNI, so whoever controls DNS cannot choose where the prober connects.
//! - One thread, at most one probe a second, 5 seconds per probe, 256 queued
//!   hosts (the oldest is dropped when full).
//! - A failed probe writes nothing to the table (fail-open).

use crate::distrust::{chain_prints, CertPrints};
use crate::judge::{Judge, JudgeInput, Reason};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub const DEFAULT_PROBE_PORT: u16 = 443;
/// At most one probe starts in this time: the hard ceiling on outgoing probes.
pub const DEFAULT_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// TCP connect and handshake together.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_REPORT_EVERY: Duration = Duration::from_secs(60 * 60);
pub const QUEUE_CAPACITY: usize = 256;
pub const VERDICT_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const VERDICT_CAPACITY: usize = 4096;

/// Whether a chain matches the stop-side lists; used for the log line only.
pub type ChainHit = Arc<dyn Fn(&[CertPrints]) -> bool + Send + Sync>;

/// Takes the lock; a poisoned mutex is used as it stands (the tables hold
/// plain data, so a panicked holder cannot leave them half-built).
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Opens the TCP connection of a probe. A test replaces it to see where the
/// prober dials, without a network.
pub trait Dialer: Send + Sync {
    fn dial(&self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream>;
}

pub struct TcpDialer;

impl Dialer for TcpDialer {
    fn dial(&self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&addr, timeout)
    }
}

/// Everything the prober is told. Production uses [`Default`]; a test passes a
/// short interval, the port of its fake upstream and `public_only: false`.
#[derive(Clone)]
pub struct ProbeSettings {
    /// The only destination port probed.
    pub port: u16,
    pub min_interval: Duration,
    pub timeout: Duration,
    pub report_every: Duration,
    /// Skip private, loopback, link-local, CGNAT, multicast and `0.0.0.0/8`
    /// destinations, so the LAN never receives a handshake from this host.
    pub public_only: bool,
    pub dialer: Arc<dyn Dialer>,
}

impl Default for ProbeSettings {
    fn default() -> Self {
        Self {
            port: DEFAULT_PROBE_PORT,
            min_interval: DEFAULT_MIN_INTERVAL,
            timeout: DEFAULT_PROBE_TIMEOUT,
            report_every: DEFAULT_REPORT_EVERY,
            public_only: true,
            dialer: Arc::new(TcpDialer),
        }
    }
}

/// Whether `ip` can be a probe destination: not private, loopback, link-local,
/// CGNAT, multicast, reserved or `0.0.0.0/8`.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                !(v6.is_unspecified()
                    || v6.is_loopback()
                    || first & 0xfe00 == 0xfc00
                    || first & 0xffc0 == 0xfe80
                    || first & 0xff00 == 0xff00)
            }
        },
    }
}

/// The address to probe for a flow, or `None` when the flow is not probed:
/// another port, an IP-literal host, or a destination that is not public.
pub fn probe_target(
    host: &str,
    dst_ip: IpAddr,
    dst_port: u16,
    settings: &ProbeSettings,
) -> Option<SocketAddr> {
    if host.is_empty() || dst_port != settings.port || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    if settings.public_only && !is_public(dst_ip) {
        return None;
    }
    Some(SocketAddr::new(dst_ip, dst_port))
}

struct Verdict {
    stored_at: Instant,
    prints: Vec<CertPrints>,
}

/// Host -> fingerprints of the chain the prober read. The distrust lists are
/// applied at judge time, so a changed list takes effect without a new probe.
pub struct ChainVerdicts {
    table: Mutex<HashMap<String, Verdict>>,
    ttl: Duration,
    capacity: usize,
}

impl ChainVerdicts {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            table: Mutex::new(HashMap::new()),
            ttl,
            capacity,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(VERDICT_TTL, VERDICT_CAPACITY)
    }

    /// Stores a chain. When the table is full the oldest host goes.
    pub fn insert(&self, host: &str, prints: Vec<CertPrints>, now: Instant) {
        let host = host.to_ascii_lowercase();
        let mut table = lock(&self.table);
        if table.len() >= self.capacity && !table.contains_key(&host) {
            let oldest = table
                .iter()
                .min_by_key(|(_, verdict)| verdict.stored_at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                table.remove(&oldest);
            }
        }
        table.insert(
            host,
            Verdict {
                stored_at: now,
                prints,
            },
        );
    }

    /// Runs `f` over the stored chain of `host` while it is younger than the
    /// lifetime; `None` when there is none.
    pub fn with<R>(
        &self,
        host: &str,
        now: Instant,
        f: impl FnOnce(&[CertPrints]) -> R,
    ) -> Option<R> {
        let table = lock(&self.table);
        let verdict = table.get(&host.to_ascii_lowercase())?;
        (now.saturating_duration_since(verdict.stored_at) <= self.ttl).then(|| f(&verdict.prints))
    }

    pub fn is_fresh(&self, host: &str, now: Instant) -> bool {
        self.with(host, now, |_| ()).is_some()
    }

    pub fn len(&self) -> usize {
        lock(&self.table).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The judge of stage 10: a host whose stored chain matches the stop-side
/// lists gets [`Reason::Chain`]. It only reads the table.
pub struct ChainJudge<'a> {
    pub verdicts: &'a ChainVerdicts,
    /// Whether a chain matches the stop-side lists.
    pub hit: &'a dyn Fn(&[CertPrints]) -> bool,
}

impl Judge for ChainJudge<'_> {
    fn judge(&self, input: &JudgeInput) -> Option<Reason> {
        let host = input.sni_state.sni()?;
        let matched = self
            .verdicts
            .with(host, Instant::now(), |chain| (self.hit)(chain))?;
        matched.then_some(Reason::Chain)
    }
}

struct ProbeJob {
    host: String,
    addr: SocketAddr,
}

/// Bounded queue; when full the oldest job goes.
struct ProbeQueue {
    jobs: Mutex<VecDeque<ProbeJob>>,
    ready: Condvar,
    closed: AtomicBool,
    capacity: usize,
    dropped: AtomicU64,
}

impl ProbeQueue {
    fn new(capacity: usize) -> Self {
        Self {
            jobs: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
            capacity,
            dropped: AtomicU64::new(0),
        }
    }

    /// Adds a job unless the host is already waiting.
    fn push(&self, job: ProbeJob) {
        let mut jobs = lock(&self.jobs);
        if jobs.iter().any(|queued| queued.host == job.host) {
            return;
        }
        if jobs.len() >= self.capacity {
            jobs.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        jobs.push_back(job);
        self.ready.notify_one();
    }

    /// Waits up to `wait` for a job.
    fn pop(&self, wait: Duration) -> Option<ProbeJob> {
        let mut jobs = lock(&self.jobs);
        if jobs.is_empty() && !self.closed.load(Ordering::Acquire) {
            jobs = match self.ready.wait_timeout(jobs, wait) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        jobs.pop_front()
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// Counts for the hourly `[info]` line.
#[derive(Default)]
struct ProbeStats {
    probes: AtomicU64,
    hits: AtomicU64,
    timeouts: AtomicU64,
}

#[derive(Debug)]
pub enum ProbeError {
    Setup(String),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Reads the chain out of the handshake and refuses to go on. Whether the
/// chain would have verified is kept for the log only.
#[derive(Debug)]
struct Capture {
    inner: Arc<WebPkiServerVerifier>,
    slot: Mutex<Option<(Vec<CertificateDer<'static>>, bool)>>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .is_ok();
        let mut chain = vec![end_entity.clone().into_owned()];
        chain.extend(intermediates.iter().map(|der| der.clone().into_owned()));
        *lock(&self.slot) = Some((chain, verified));
        Err(rustls::Error::General(
            "chain read; the handshake is not continued".to_owned(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Why a probe wrote nothing.
enum ReadError {
    Timeout,
    Failed,
}

/// Drives the handshake of `conn` by hand so the whole probe stays inside
/// `deadline`, and returns once the verifier has seen the chain.
fn drive_handshake(
    conn: &mut ClientConnection,
    sock: &mut TcpStream,
    deadline: Instant,
) -> Result<(), ReadError> {
    loop {
        while conn.wants_write() {
            conn.write_tls(sock).map_err(|_| ReadError::Failed)?;
        }
        if !conn.is_handshaking() {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ReadError::Timeout);
        }
        sock.set_read_timeout(Some(remaining))
            .map_err(|_| ReadError::Failed)?;
        match conn.read_tls(sock) {
            Ok(0) => return Err(ReadError::Failed),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ReadError::Timeout)
            }
            Err(_) => return Err(ReadError::Failed),
        }
        if conn.process_new_packets().is_err() {
            // The verifier refused on purpose; the chain is in its slot.
            return Ok(());
        }
    }
}

struct Worker {
    queue: Arc<ProbeQueue>,
    verdicts: Arc<ChainVerdicts>,
    anchors: Arc<Vec<TrustAnchor<'static>>>,
    hit: ChainHit,
    config: Arc<ClientConfig>,
    capture: Arc<Capture>,
    settings: ProbeSettings,
    stats: Arc<ProbeStats>,
    /// When the last connection was opened. Only the prober thread uses it.
    last_dial: Cell<Option<Instant>>,
}

impl Worker {
    /// One probe: dial, handshake, keep the chain. Nothing is written on failure.
    fn probe(&self, job: &ProbeJob) {
        self.stats.probes.fetch_add(1, Ordering::Relaxed);
        match self.read_chain(job) {
            Ok((chain, verified)) => self.keep(job, &chain, verified),
            Err(ReadError::Timeout) => {
                self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
            }
            Err(ReadError::Failed) => {}
        }
    }

    /// Sleeps until `min_interval` has passed since the last connection was
    /// opened, so the rate bounds the connections themselves.
    fn wait_for_turn(&self) {
        if let Some(previous) = self.last_dial.get() {
            std::thread::sleep(
                self.settings
                    .min_interval
                    .saturating_sub(previous.elapsed()),
            );
        }
        self.last_dial.set(Some(Instant::now()));
    }

    fn read_chain(
        &self,
        job: &ProbeJob,
    ) -> Result<(Vec<CertificateDer<'static>>, bool), ReadError> {
        let name = ServerName::try_from(job.host.clone()).map_err(|_| ReadError::Failed)?;
        let mut conn =
            ClientConnection::new(Arc::clone(&self.config), name).map_err(|_| ReadError::Failed)?;
        self.wait_for_turn();
        let deadline = Instant::now() + self.settings.timeout;
        let mut sock = self
            .settings
            .dialer
            .dial(job.addr, self.settings.timeout)
            .map_err(|e| match e.kind() {
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ReadError::Timeout,
                _ => ReadError::Failed,
            })?;
        sock.set_write_timeout(Some(self.settings.timeout))
            .map_err(|_| ReadError::Failed)?;
        *lock(&self.capture.slot) = None;
        drive_handshake(&mut conn, &mut sock, deadline)?;
        // The alert, if any, is a courtesy; the socket closes when dropped.
        let _ = conn.write_tls(&mut sock);
        lock(&self.capture.slot).take().ok_or(ReadError::Failed)
    }

    fn keep(&self, job: &ProbeJob, chain: &[CertificateDer<'static>], verified: bool) {
        let prints = chain_prints(chain, &self.anchors);
        let hit = (self.hit)(&prints);
        self.verdicts.insert(&job.host, prints, Instant::now());
        crate::flow::service_log(&format!(
            "packetdeath: [debug] {}",
            crate::i18n::probe_chain_read(crate::i18n::locale(), &job.host, chain.len(), verified)
        ));
        if hit {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            crate::flow::service_log(&format!(
                "packetdeath: [warn] {}",
                crate::i18n::probe_chain_distrusted(crate::i18n::locale(), &job.host)
            ));
        }
    }

    fn report(&self) {
        let take = |counter: &AtomicU64| counter.swap(0, Ordering::Relaxed);
        crate::flow::service_log(&format!(
            "packetdeath: [info] {}",
            crate::i18n::probe_summary(
                crate::i18n::locale(),
                take(&self.stats.probes),
                take(&self.stats.hits),
                take(&self.stats.timeouts),
                take(&self.queue.dropped),
            )
        ));
    }

    /// The thread body: pace the probes, report once per `report_every`.
    fn run(&self) {
        let mut last_report = Instant::now();
        while !self.queue.is_closed() {
            if last_report.elapsed() >= self.settings.report_every {
                self.report();
                last_report = Instant::now();
            }
            let Some(job) = self.queue.pop(Duration::from_millis(250)) else {
                continue;
            };
            if self.verdicts.is_fresh(&job.host, Instant::now()) {
                continue;
            }
            self.probe(&job);
        }
    }
}

/// The running prober. Dropping it stops the thread after its current probe.
pub struct Prober {
    queue: Arc<ProbeQueue>,
    verdicts: Arc<ChainVerdicts>,
    settings: ProbeSettings,
}

impl Prober {
    /// Starts the thread. `anchors` are the roots the chain is judged against
    /// (for the log) and the roots a chain's top is completed with; `hit` says
    /// whether a chain matches the stop-side lists (for the log).
    pub fn start(
        settings: ProbeSettings,
        verdicts: Arc<ChainVerdicts>,
        anchors: Arc<Vec<TrustAnchor<'static>>>,
        hit: ChainHit,
    ) -> Result<Self, ProbeError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let roots = Arc::new(RootCertStore {
            roots: anchors.as_ref().clone(),
        });
        let inner = WebPkiServerVerifier::builder_with_provider(roots, Arc::clone(&provider))
            .build()
            .map_err(|e| ProbeError::Setup(e.to_string()))?;
        let capture = Arc::new(Capture {
            inner,
            slot: Mutex::new(None),
        });
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ProbeError::Setup(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::clone(&capture) as Arc<dyn ServerCertVerifier>)
            .with_no_client_auth();
        let queue = Arc::new(ProbeQueue::new(QUEUE_CAPACITY));
        let worker = Worker {
            queue: Arc::clone(&queue),
            verdicts: Arc::clone(&verdicts),
            anchors,
            hit,
            config: Arc::new(config),
            capture,
            settings: settings.clone(),
            stats: Arc::new(ProbeStats::default()),
            last_dial: Cell::new(None),
        };
        std::thread::Builder::new()
            .name("pd-prober".to_owned())
            .spawn(move || worker.run())
            .map_err(|e| ProbeError::Setup(e.to_string()))?;
        Ok(Self {
            queue,
            verdicts,
            settings,
        })
    }

    /// Queues a probe for a passed flow when it is eligible and the host has
    /// no fresh chain. Never blocks and never does I/O. Returns whether the
    /// flow was queued.
    pub fn offer(&self, host: &str, dst_ip: IpAddr, dst_port: u16) -> bool {
        let Some(addr) = probe_target(host, dst_ip, dst_port, &self.settings) else {
            return false;
        };
        if self.verdicts.is_fresh(host, Instant::now()) {
            return false;
        }
        self.queue.push(ProbeJob {
            host: host.to_ascii_lowercase(),
            addr,
        });
        true
    }
}

impl Drop for Prober {
    fn drop(&mut self) {
        self.queue.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Records every dial and refuses it, so no connection is ever made.
    struct Recording {
        seen: Mutex<Vec<(SocketAddr, Instant)>>,
    }

    impl Dialer for Recording {
        fn dial(&self, addr: SocketAddr, _timeout: Duration) -> io::Result<TcpStream> {
            lock(&self.seen).push((addr, Instant::now()));
            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
        }
    }

    fn recording_settings(interval: Duration) -> (ProbeSettings, Arc<Recording>) {
        let dialer = Arc::new(Recording {
            seen: Mutex::new(Vec::new()),
        });
        let settings = ProbeSettings {
            min_interval: interval,
            dialer: Arc::clone(&dialer) as Arc<dyn Dialer>,
            ..ProbeSettings::default()
        };
        (settings, dialer)
    }

    fn start(settings: ProbeSettings) -> Result<Prober, ProbeError> {
        Prober::start(
            settings,
            Arc::new(ChainVerdicts::with_defaults()),
            Arc::new(webpki_roots::TLS_SERVER_ROOTS.to_vec()),
            Arc::new(|_| false),
        )
    }

    fn wait_for(dialer: &Recording, count: usize) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if lock(&dialer.seen).len() >= count {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn the_prober_dials_the_flows_destination_and_skips_private_addresses() -> TestResult {
        let (settings, dialer) = recording_settings(Duration::from_millis(10));
        let prober = start(settings)?;
        let public = v4(198, 51, 100, 1);
        assert!(prober.offer("example.test", public, 443));
        assert!(wait_for(&dialer, 1));
        assert_eq!(
            lock(&dialer.seen).first().map(|(addr, _)| *addr),
            Some(SocketAddr::new(public, 443))
        );
        // The control above: a public destination is dialled. None of these is.
        for private in [
            v4(10, 0, 0, 1),
            v4(127, 0, 0, 1),
            v4(169, 254, 1, 1),
            v4(100, 64, 0, 1),
            v4(224, 0, 0, 1),
            v4(0, 0, 0, 0),
        ] {
            assert!(!prober.offer("private.test", private, 443), "{private}");
        }
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(lock(&dialer.seen).len(), 1);
        Ok(())
    }

    #[test]
    fn probes_start_at_most_once_per_interval() -> TestResult {
        assert_eq!(
            ProbeSettings::default().min_interval,
            Duration::from_secs(1)
        );
        let interval = Duration::from_millis(150);
        let (settings, dialer) = recording_settings(interval);
        let prober = start(settings)?;
        for n in 1..=3 {
            assert!(prober.offer(&format!("h{n}.test"), v4(198, 51, 100, n), 443));
        }
        assert!(wait_for(&dialer, 3));
        let seen = lock(&dialer.seen);
        for pair in seen.windows(2) {
            let gap = pair[1].1.duration_since(pair[0].1);
            assert!(gap >= interval - Duration::from_millis(10), "{gap:?}");
        }
        Ok(())
    }

    #[test]
    fn a_host_is_queued_once_and_a_full_queue_drops_its_oldest() {
        let queue = ProbeQueue::new(2);
        let job = |name: &str| ProbeJob {
            host: name.to_owned(),
            addr: SocketAddr::new(v4(198, 51, 100, 1), 443),
        };
        queue.push(job("a"));
        queue.push(job("a"));
        queue.push(job("b"));
        queue.push(job("c"));
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 1);
        let first = queue.pop(Duration::from_millis(1)).map(|job| job.host);
        assert_eq!(first.as_deref(), Some("b"));
        assert!(queue.pop(Duration::from_millis(1)).is_some());
        assert!(queue.pop(Duration::from_millis(1)).is_none());
    }

    #[test]
    fn the_table_forgets_after_its_lifetime_and_drops_the_oldest_when_full() {
        let table = ChainVerdicts::new(Duration::from_secs(10), 2);
        let start = Instant::now();
        table.insert("a.test", Vec::new(), start);
        table.insert("b.test", Vec::new(), start + Duration::from_secs(1));
        table.insert("C.test", Vec::new(), start + Duration::from_secs(2));
        assert_eq!(table.len(), 2);
        assert!(!table.is_fresh("a.test", start + Duration::from_secs(3)));
        assert!(table.is_fresh("c.test", start + Duration::from_secs(3)));
        assert!(table.is_fresh("b.test", start + Duration::from_secs(11)));
        assert!(!table.is_fresh("b.test", start + Duration::from_secs(12)));
    }

    #[test]
    fn only_a_public_unicast_destination_with_a_name_on_the_probe_port_is_probed() -> TestResult {
        let settings = ProbeSettings::default();
        let public = v4(198, 51, 100, 1);
        assert!(probe_target("example.test", public, 443, &settings).is_some());
        assert!(probe_target("example.test", public, 8443, &settings).is_none());
        assert!(probe_target("198.51.100.1", public, 443, &settings).is_none());
        assert!(probe_target("", public, 443, &settings).is_none());
        for private in [
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(private.parse::<IpAddr>()?), "{private}");
        }
        assert!(is_public("2001:db8::1".parse::<IpAddr>()?));
        Ok(())
    }
}
