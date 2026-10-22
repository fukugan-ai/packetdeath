//! Stage 8: decrypting one CONNECT and scanning the file it downloads.
//! `docs/design.md` "段階8 MITM" is the source of truth.
//!
//! A decrypted connection carries exactly one HTTP/1.1 request and is closed
//! after its response (`Connection: close`). Only `http/1.1` is offered by
//! ALPN on both sides. Request bodies are streamed upstream, never held.
//! What cannot be handled decrypted (`Upgrade`, two different
//! `Content-Length`s, `Transfer-Encoding` beside `Content-Length`, a head over
//! the stage 7 limits) is answered `501` (`502` when the response is at fault)
//! and the (client IP, host) pair goes into the bypass table: the next
//! connection is tunnelled without decryption.
//!
//! **Every failure falls back to the stage 7 tunnel or to an unscanned
//! response.** The upstream handshake runs before `200` is sent, so its
//! failure hands the client back for a plain tunnel. A client that refuses
//! the leaf (pinning, or the CA not installed) cannot be answered once `200`
//! went out, so the pair is bypassed for the next connection. A refusal is
//! a failed handshake, or a session dropped uncleanly before the first
//! request byte (clients that check the certificate after the handshake).
//!
//! Decrypted URLs, headers, bodies and cookies are never logged: only the
//! host, the sha256, the verdict and the signature.

use crate::ca::{utc_text, LEAF_CACHE_CAPACITY, LEAF_REFRESH};
use crate::ca::{Ca, CaError, CaOrigin, LeafCache, LeafError, EXPIRY_WARNING_DAYS};
use crate::clamd::{self, ClamdAddr, Verdict};
use crate::defense::{Defense, FlowFacts};
use crate::flow::{FlowKey, FlowLogSink};
use crate::judge::Reason;
use crate::proxy::{log_flow, read_capped_line, LineOutcome, ProxyLimits, MAX_HEADER_LINES};
use crate::scan::{self, AvLog, AvVerdict, Eligibility, ResponseFacts, ScanBudget, SkipReason};
use crate::sni::SniState;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// Bound on each TLS handshake (upstream and client).
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The only application protocol offered on either side.
const ALPN_HTTP11: &[u8] = b"http/1.1";
/// Buffer for relaying bodies.
const COPY_BUF: usize = 64 * 1024;

pub const DEFAULT_BYPASS_TTL: Duration = Duration::from_secs(60 * 60);
pub const DEFAULT_BYPASS_CAPACITY: usize = 4096;
/// A silent close from a pair that sent a request within this window is a
/// browser dropping a spare socket, not a refusal.
pub const DEFAULT_RECENT_REQUEST_WINDOW: Duration = Duration::from_secs(60);
pub const HTTPS_PORT: u16 = 443;

/// Times and limits of stage 8, gathered like `ProxyLimits` so tests can pass
/// short values.
#[derive(Debug, Clone, Copy)]
pub struct MitmLimits {
    /// How long a (client IP, host) pair stays tunnelled after a failure.
    pub bypass_ttl: Duration,
    /// Pairs kept in the bypass table (and in the table of recent requests);
    /// the oldest goes first.
    pub bypass_capacity: usize,
    /// How long a request keeps silent closes from the same pair out of the
    /// bypass table. Alerts are bypassed regardless.
    pub recent_request_window: Duration,
    /// Largest body held and scanned.
    pub max_scan_bytes: usize,
    /// Body bytes all scans may hold at once; beyond this, bodies pass
    /// unscanned.
    pub scan_budget_bytes: usize,
    /// Bound on each step of talking to clamd.
    pub clamd_timeout: Duration,
    /// The only port decrypted: 443 in production. Tests run their fake
    /// upstream on an ephemeral port and put that port here.
    pub decrypt_port: u16,
}

impl Default for MitmLimits {
    fn default() -> Self {
        Self {
            bypass_ttl: DEFAULT_BYPASS_TTL,
            bypass_capacity: DEFAULT_BYPASS_CAPACITY,
            recent_request_window: DEFAULT_RECENT_REQUEST_WINDOW,
            max_scan_bytes: scan::DEFAULT_MAX_SCAN_BYTES,
            scan_budget_bytes: scan::DEFAULT_SCAN_BUDGET_BYTES,
            clamd_timeout: clamd::DEFAULT_TIMEOUT,
            decrypt_port: HTTPS_PORT,
        }
    }
}

/// Everything `Mitm::start` needs.
pub struct MitmSettings {
    pub ca_dir: PathBuf,
    pub clamd: ClamdAddr,
    /// `<log dir>/av.jsonl`.
    pub av_log: PathBuf,
    /// Roots that upstream certificates must chain to. Production passes
    /// [`production_roots`]; tests pass their own CA.
    pub upstream_roots: RootCertStore,
    pub limits: MitmLimits,
}

/// The public web PKI (webpki-roots), used to verify upstream servers.
pub fn production_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

#[derive(Debug)]
pub enum MitmError {
    Ca(CaError),
    AvLog(PathBuf, io::Error),
    Tls(rustls::Error),
}

impl fmt::Display for MitmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ca(e) => write!(f, "{e}"),
            Self::AvLog(path, e) => write!(
                f,
                "{}",
                crate::i18n::av_log_open_failed(crate::i18n::locale(), path.display(), e)
            ),
            Self::Tls(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MitmError {}

/// The running state of stage 8, shared by every connection thread.
pub struct Mitm {
    ca: Ca,
    leaves: Mutex<LeafCache>,
    bypass: Mutex<BypassTable>,
    /// When each pair last got its first request byte read, held as a
    /// [`BypassTable`] whose TTL is `recent_request_window`.
    requests: Mutex<BypassTable>,
    clamd: ClamdAddr,
    budget: ScanBudget,
    av_log: AvLog,
    upstream_config: Arc<ClientConfig>,
    provider: Arc<CryptoProvider>,
    limits: MitmLimits,
}

impl Mitm {
    /// Loads or generates the CA, checks clamd once and opens `av.jsonl`.
    /// Any `Err` means decryption stays off; the proxy still runs as stage 7.
    pub fn start(settings: MitmSettings) -> Result<Self, MitmError> {
        let locale = crate::i18n::locale();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let now = OffsetDateTime::now_utc();
        let (ca, origin) = Ca::load_or_create(&settings.ca_dir, Arc::clone(&provider), now)
            .map_err(MitmError::Ca)?;
        let dir = settings.ca_dir.display();
        let made = match origin {
            CaOrigin::Generated => crate::i18n::ca_generated(locale, dir),
            CaOrigin::Loaded => crate::i18n::ca_loaded(locale, dir),
        };
        eprintln!("packetdeath: [info] {made}");
        eprintln!(
            "packetdeath: [info] {}",
            crate::i18n::ca_fingerprint(
                locale,
                &ca.sha256_fingerprint(),
                &ca.sha1_fingerprint(),
                utc_text(ca.not_after())
            )
        );
        let days_left = ca.days_left(now);
        if days_left < EXPIRY_WARNING_DAYS {
            eprintln!(
                "packetdeath: [warn] {}",
                crate::i18n::ca_expiring_soon(locale, days_left, utc_text(ca.not_after()))
            );
        }

        if settings.clamd.is_remote_tcp() {
            eprintln!(
                "packetdeath: [warn] {}",
                crate::i18n::clamd_not_loopback(locale, &settings.clamd)
            );
        }
        if !clamd::ping(&settings.clamd, clamd::PING_TIMEOUT) {
            eprintln!(
                "packetdeath: [warn] {}",
                crate::i18n::clamd_ping_failed(locale, &settings.clamd)
            );
        }

        let av_log = AvLog::open(&settings.av_log)
            .map_err(|e| MitmError::AvLog(settings.av_log.clone(), e))?;

        let mut upstream = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(MitmError::Tls)?
            .with_root_certificates(settings.upstream_roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![ALPN_HTTP11.to_vec()];

        let limits = settings.limits;
        Ok(Self {
            ca,
            leaves: Mutex::new(LeafCache::new(LEAF_CACHE_CAPACITY, LEAF_REFRESH)),
            bypass: Mutex::new(BypassTable::new(limits.bypass_ttl, limits.bypass_capacity)),
            requests: Mutex::new(BypassTable::new(
                limits.recent_request_window,
                limits.bypass_capacity,
            )),
            clamd: settings.clamd,
            budget: ScanBudget::new(limits.scan_budget_bytes),
            av_log,
            upstream_config: Arc::new(upstream),
            provider,
            limits,
        })
    }

    pub fn ca(&self) -> &Ca {
        &self.ca
    }

    /// The port a CONNECT must name to be decrypted.
    pub fn decrypt_port(&self) -> u16 {
        self.limits.decrypt_port
    }

    /// Condition 6 of "復号する範囲": the pair is not in the bypass table.
    pub(crate) fn is_bypassed(&self, client_ip: IpAddr, host: &str, now: Instant) -> bool {
        let host = host.to_ascii_lowercase();
        match self.bypass.lock() {
            Ok(mut table) => table.contains(client_ip, &host, now),
            Err(poisoned) => poisoned.into_inner().contains(client_ip, &host, now),
        }
    }

    fn add_bypass(&self, client_ip: IpAddr, host: &str) {
        let host = host.to_ascii_lowercase();
        let now = Instant::now();
        match self.bypass.lock() {
            Ok(mut table) => table.insert(client_ip, host.clone(), now),
            Err(poisoned) => poisoned.into_inner().insert(client_ip, host.clone(), now),
        }
        eprintln!(
            "packetdeath: [info] {}",
            crate::i18n::mitm_bypassed(
                crate::i18n::locale(),
                client_ip,
                &host,
                self.limits.bypass_ttl.as_secs()
            )
        );
    }

    fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>, LeafError> {
        let host = host.to_ascii_lowercase();
        let now = Instant::now();
        let wall = OffsetDateTime::now_utc();
        match self.leaves.lock() {
            Ok(mut cache) => cache.get_or_issue(&self.ca, &host, now, wall),
            Err(poisoned) => poisoned
                .into_inner()
                .get_or_issue(&self.ca, &host, now, wall),
        }
    }

    /// Takes over a CONNECT that passed every condition of "復号する範囲".
    /// `upstream` is the TCP connection already open to the host.
    pub(crate) fn intercept(
        &self,
        reader: BufReader<TcpStream>,
        upstream: TcpStream,
        flow: &FlowContext<'_>,
    ) -> Outcome {
        let locale = crate::i18n::locale();
        let leaf = match self.leaf_for(flow.host) {
            Ok(leaf) => leaf,
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    crate::i18n::mitm_leaf_failed(locale, flow.host, e)
                );
                return Outcome::Fallback {
                    reader,
                    upstream: Some(upstream),
                };
            }
        };
        let mut upstream = match self.connect_upstream(flow.host, upstream) {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!(
                    "packetdeath: [warn] {}",
                    crate::i18n::mitm_upstream_tls_failed(locale, flow.host, e)
                );
                return Outcome::Fallback {
                    reader,
                    upstream: None,
                };
            }
        };
        // A distrusted upstream chain is denied here, not tunnelled: a plain
        // tunnel would hand the chain to a client whose own store may still
        // trust it.
        if upstream_chain_denied(&upstream, flow) {
            return Outcome::Denied { reader };
        }

        // Bytes the client sent right after CONNECT belong to its handshake.
        let leftover = reader.buffer().to_vec();
        let mut client = reader.into_inner();
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return Outcome::Done;
        }
        let mut client = match self.accept_client(client, leaf, &leftover) {
            Ok(client) => client,
            Err(refusal) => {
                self.client_refused(flow, refusal, Stage::Handshake);
                return Outcome::Done;
            }
        };

        if set_timeouts(
            &client.sock,
            flow.limits.request_read_timeout,
            flow.limits.pipe_idle_timeout,
        )
        .is_ok()
            && set_timeouts(
                &upstream.sock,
                flow.limits.pipe_idle_timeout,
                flow.limits.pipe_idle_timeout,
            )
            .is_ok()
        {
            match first_read(&mut client) {
                FirstRead::Request => {
                    // Recorded before the exchange: while a body is held for
                    // scanning, a sibling socket of the same client may close.
                    self.remember_request(flow.key.src_ip, flow.host);
                    self.exchange(&mut client, &mut upstream, flow);
                }
                FirstRead::Quiet => {}
                FirstRead::Refused(refusal) => {
                    self.client_refused(flow, refusal, Stage::AfterHandshake);
                    return Outcome::Done;
                }
            }
        }
        // close_notify on both sides; the sockets close when dropped.
        client.conn.send_close_notify();
        let _ = client.flush();
        upstream.conn.send_close_notify();
        let _ = upstream.flush();
        Outcome::Done
    }

    /// The client seems not to accept the leaf: tunnel this pair from the
    /// next connection on, unless it was only a spare socket dropped by a
    /// client that is otherwise talking to us.
    fn client_refused(&self, flow: &FlowContext<'_>, refusal: Refusal, stage: Stage) {
        let locale = crate::i18n::locale();
        let (ip, host) = (flow.key.src_ip, flow.host);
        if refusal == Refusal::Unstarted {
            eprintln!(
                "packetdeath: [debug] {}",
                crate::i18n::mitm_closed_before_tls(locale, ip, host)
            );
            return;
        }
        if !bypasses(refusal, stage, self.requested_recently(ip, host)) {
            let why = match stage {
                Stage::Handshake => "handshake",
                Stage::AfterHandshake => "recent_request",
            };
            eprintln!(
                "packetdeath: [debug] {}",
                crate::i18n::mitm_silent_close_kept(locale, why, stage.as_log_str(), ip, host)
            );
            return;
        }
        eprintln!(
            "packetdeath: [warn] {}",
            crate::i18n::mitm_client_refused(
                locale,
                refusal.as_log_str(),
                stage.as_log_str(),
                ip,
                host
            )
        );
        self.add_bypass(ip, host);
    }

    fn remember_request(&self, client_ip: IpAddr, host: &str) {
        let host = host.to_ascii_lowercase();
        lock_table(&self.requests).insert(client_ip, host, Instant::now());
    }

    fn requested_recently(&self, client_ip: IpAddr, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        lock_table(&self.requests).contains(client_ip, &host, Instant::now())
    }

    fn connect_upstream(
        &self,
        host: &str,
        mut sock: TcpStream,
    ) -> Result<UpstreamSide, UpstreamTlsError> {
        let name =
            ServerName::try_from(host.to_owned()).map_err(|_| UpstreamTlsError::ServerName)?;
        let mut conn = ClientConnection::new(Arc::clone(&self.upstream_config), name)
            .map_err(UpstreamTlsError::Tls)?;
        set_timeouts(&sock, TLS_HANDSHAKE_TIMEOUT, TLS_HANDSHAKE_TIMEOUT)
            .map_err(UpstreamTlsError::Io)?;
        conn.complete_io(&mut sock).map_err(UpstreamTlsError::Io)?;
        if conn.is_handshaking() {
            return Err(UpstreamTlsError::Io(io::Error::from(
                io::ErrorKind::UnexpectedEof,
            )));
        }
        Ok(StreamOwned::new(conn, sock))
    }

    fn accept_client(
        &self,
        mut sock: TcpStream,
        leaf: Arc<CertifiedKey>,
        leftover: &[u8],
    ) -> Result<ClientSide, Refusal> {
        let mut config = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| refusal_of_tls(&e))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneLeaf(leaf)));
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        let mut conn = ServerConnection::new(Arc::new(config)).map_err(|e| refusal_of_tls(&e))?;
        set_timeouts(&sock, TLS_HANDSHAKE_TIMEOUT, TLS_HANDSHAKE_TIMEOUT)
            .map_err(|e| refusal_of(&e))?;
        if !leftover.is_empty() {
            let mut pending = leftover;
            while !pending.is_empty() {
                conn.read_tls(&mut pending).map_err(|e| refusal_of(&e))?;
            }
            conn.process_new_packets().map_err(|e| refusal_of_tls(&e))?;
        }
        let mut io = CountingIo {
            sock: &mut sock,
            read: leftover.len(),
        };
        let finished = conn.complete_io(&mut io).map(|_| !conn.is_handshaking());
        let started = io.read > 0;
        match finished {
            Ok(true) => Ok(StreamOwned::new(conn, sock)),
            _ if !started => Err(Refusal::Unstarted),
            Ok(false) => Err(Refusal::SilentClose),
            Err(e) => Err(refusal_of(&e)),
        }
    }

    /// One request, one response.
    fn exchange(
        &self,
        client: &mut ClientSide,
        upstream: &mut UpstreamSide,
        flow: &FlowContext<'_>,
    ) {
        let request = match read_head(client) {
            Ok(head) => head,
            Err(HeadError::Eof) => return,
            Err(HeadError::TooLarge) => return self.refuse(client, 501, flow, "head_too_large"),
        };
        let Some(method) = request_method(&request.start) else {
            return self.refuse(client, 501, flow, "bad_request_line");
        };
        let request_body = match request_framing(&request.headers) {
            Ok(framing) => framing,
            Err(kind) => return self.refuse(client, 501, flow, kind),
        };
        if client
            .sock
            .set_read_timeout(Some(flow.limits.pipe_idle_timeout))
            .is_err()
        {
            return;
        }
        if let Err(e) = send_request(upstream, client, &request, request_body) {
            return log_aborted(flow.host, &e);
        }

        let (response, status) = loop {
            match read_head(upstream) {
                Ok(head) => match status_code(&head.start) {
                    Some(101) => return self.refuse(client, 502, flow, "upgrade"),
                    Some(100..=199) => {
                        if client.write_all(&interim_head(&head)).is_err() {
                            return;
                        }
                    }
                    Some(code) => break (head, code),
                    None => return self.refuse(client, 502, flow, "bad_status_line"),
                },
                Err(HeadError::Eof) => {
                    eprintln!(
                        "packetdeath: [warn] {}",
                        crate::i18n::mitm_upstream_closed(crate::i18n::locale(), flow.host)
                    );
                    return respond_plain(client, 502, "Bad Gateway", "");
                }
                Err(HeadError::TooLarge) => {
                    return self.refuse(client, 502, flow, "head_too_large")
                }
            }
        };
        let body = match response_framing(method, status, &response.headers) {
            Ok(framing) => framing,
            Err(kind) => return self.refuse(client, 502, flow, kind),
        };
        let facts = ResponseFacts {
            method,
            status,
            content_type: first_header(&response.headers, "content-type"),
            content_disposition: first_header(&response.headers, "content-disposition"),
            content_encoding: first_header(&response.headers, "content-encoding"),
            content_length: match body {
                Framing::Length(n) => Some(n),
                _ => None,
            },
        };
        let skipped = match scan::eligibility(&facts, self.limits.max_scan_bytes) {
            Eligibility::Skip(reason) => reason,
            Eligibility::Scan => match self.scan_bytes(body) {
                None => SkipReason::TooLarge,
                Some(bytes) => match self.budget.try_acquire(bytes) {
                    Some(_lease) => {
                        return self.scan_and_answer(client, upstream, &response, body, flow);
                    }
                    None => SkipReason::SlotFull,
                },
            },
        };
        log_skip(flow.host, skipped);
        if let Err(e) = relay(client, upstream, &response, body) {
            log_aborted(flow.host, &e);
        }
    }

    /// Bytes a scan of this body takes from the budget: the declared length,
    /// or the whole limit when the length is unknown. `None` when the declared
    /// length does not fit in `usize`.
    fn scan_bytes(&self, body: Framing) -> Option<usize> {
        match body {
            Framing::Length(n) => usize::try_from(n).ok(),
            _ => Some(self.limits.max_scan_bytes),
        }
    }

    /// Holds the body (up to the limit), scans it, and answers with either the
    /// body or a `403`.
    fn scan_and_answer(
        &self,
        client: &mut ClientSide,
        upstream: &mut UpstreamSide,
        head: &Head,
        body: Framing,
        flow: &FlowContext<'_>,
    ) {
        let max = self.limits.max_scan_bytes;
        let mut held = Vec::new();
        let outcome = match body {
            Framing::Length(n) => hold_exact(upstream, &mut held, n),
            Framing::Chunked => {
                held.reserve_exact(max);
                hold_chunked(upstream, client, head, &mut held, max)
            }
            Framing::UntilClose => {
                held.reserve_exact(max);
                hold_until_close(upstream, client, head, &mut held, max)
            }
            Framing::None => Held::Complete,
        };
        match outcome {
            Held::Complete => {}
            Held::Overflowed => return log_skip(flow.host, SkipReason::TooLarge),
            Held::Broken => {
                eprintln!(
                    "packetdeath: [warn] {}",
                    crate::i18n::mitm_upstream_closed(crate::i18n::locale(), flow.host)
                );
                return respond_plain(client, 502, "Bad Gateway", "");
            }
        }

        let sha256 = scan::sha256_hex(&held);
        let locale = crate::i18n::locale();
        // Only the clamd exchange is timed, not the time spent holding the body.
        let scan_started = Instant::now();
        let verdict = clamd::scan(&self.clamd, &held, self.limits.clamd_timeout);
        let elapsed = scan_started.elapsed();
        match verdict {
            Verdict::Found(signature) => {
                let body = crate::i18n::av_blocked_body(locale);
                respond_plain(client, 403, "Forbidden", &body);
                log_flow(flow.log, flow.key, flow.sni_state, Some(Reason::Av));
                self.record(
                    flow,
                    &sha256,
                    AvVerdict::Malicious {
                        signature: &signature,
                    },
                );
                eprintln!(
                    "packetdeath: [info] {}",
                    crate::i18n::av_found(locale, flow.host, &signature, &sha256, elapsed)
                );
            }
            Verdict::Unfinished(signature) => {
                // A clamd limit, not malware: no 403, no av.jsonl line.
                eprintln!(
                    "packetdeath: [warn] {}",
                    crate::i18n::av_scan_unfinished(locale, flow.host, &signature)
                );
                let _ = send_held(client, head, &held);
            }
            Verdict::Clean => {
                let _ = send_held(client, head, &held);
                self.record(flow, &sha256, AvVerdict::Clean);
                eprintln!(
                    "packetdeath: [info] {}",
                    crate::i18n::av_clean(locale, flow.host, &sha256, elapsed)
                );
            }
            Verdict::Failed(failure) => {
                eprintln!(
                    "packetdeath: [warn] {}",
                    crate::i18n::av_scan_failed(locale, flow.host, failure.as_log_str())
                );
                let _ = send_held(client, head, &held);
            }
        }
    }

    fn record(&self, flow: &FlowContext<'_>, sha256: &str, verdict: AvVerdict<'_>) {
        if let Err(e) = self
            .av_log
            .write(flow.key.dst_ip, flow.key.dst_port, sha256, verdict)
        {
            eprintln!(
                "packetdeath: [error] {}",
                crate::i18n::av_log_write_failed(crate::i18n::locale(), e)
            );
        }
    }

    /// Answers what cannot be handled decrypted and tunnels the pair next time.
    fn refuse(&self, client: &mut ClientSide, code: u16, flow: &FlowContext<'_>, kind: &str) {
        eprintln!(
            "packetdeath: [warn] {}",
            crate::i18n::mitm_unsupported(crate::i18n::locale(), flow.host, kind)
        );
        let reason = if code == 501 {
            "Not Implemented"
        } else {
            "Bad Gateway"
        };
        respond_plain(client, code, reason, "");
        self.add_bypass(flow.key.src_ip, flow.host);
    }
}

/// What `proxy::handle_connection` hands to [`Mitm::intercept`].
pub(crate) struct FlowContext<'a> {
    pub key: FlowKey,
    pub host: &'a str,
    pub sni_state: &'a SniState,
    pub log: &'a FlowLogSink,
    pub limits: ProxyLimits,
    /// Stage 10, when it is on.
    pub defense: Option<&'a Defense>,
}

/// Whether stage 10 denies the chain the upstream server sent. Stage 8 only
/// decrypts hosts that are not allowlisted, so the flow is never allowlisted.
fn upstream_chain_denied(upstream: &UpstreamSide, flow: &FlowContext<'_>) -> bool {
    flow.defense.is_some_and(|defense| {
        let facts = FlowFacts {
            key: flow.key,
            host: flow.host,
            allowlisted: false,
        };
        upstream
            .conn
            .peer_certificates()
            .is_some_and(|chain| defense.check_upstream_chain(&facts, chain))
    })
}

/// How [`Mitm::intercept`] ended.
pub(crate) enum Outcome {
    /// The connection was handled (or closed) here.
    Done,
    /// Stage 10 denied the upstream chain. Nothing was sent to the client; the
    /// caller answers it like any other denied flow.
    Denied { reader: BufReader<TcpStream> },
    /// Nothing was sent to the client yet: tunnel it as stage 7. `upstream`
    /// is `None` when the TCP connection was spent on a failed handshake.
    Fallback {
        reader: BufReader<TcpStream>,
        upstream: Option<TcpStream>,
    },
}

type ClientSide = StreamOwned<ServerConnection, TcpStream>;
type UpstreamSide = StreamOwned<ClientConnection, TcpStream>;

/// How a client ended a session it did not use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The client sent a TLS alert.
    Alert,
    /// The socket closed or reset without `close_notify`.
    SilentClose,
    /// Nothing arrived in time during the handshake.
    Timeout,
    /// Any other TLS or socket failure.
    TlsError,
    /// The client closed or went quiet before sending a single TLS byte, so
    /// it never saw the leaf. Not a refusal: Chrome aborts every pending
    /// connect this way when it reloads its certificate settings.
    Unstarted,
}

impl Refusal {
    fn as_log_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::SilentClose => "silent_close",
            Self::Timeout => "timeout",
            Self::TlsError => "tls_error",
            Self::Unstarted => "unstarted",
        }
    }
}

/// The client socket during the handshake, counting the bytes it sent.
struct CountingIo<'a> {
    sock: &'a mut TcpStream,
    read: usize,
}

impl Read for CountingIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.sock.read(buf)?;
        self.read += n;
        Ok(n)
    }
}

impl Write for CountingIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

/// Where in the session the refusal was seen.
#[derive(Clone, Copy)]
enum Stage {
    Handshake,
    AfterHandshake,
}

impl Stage {
    fn as_log_str(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::AfterHandshake => "after_handshake",
        }
    }
}

/// rustls hands a received alert back as `Error::AlertReceived`, wrapped in
/// an `InvalidData` I/O error by `complete_io` and the stream reader.
fn refusal_of(e: &io::Error) -> Refusal {
    match e.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => Refusal::SilentClose,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Refusal::Timeout,
        _ => match e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(tls) => refusal_of_tls(tls),
            None => Refusal::TlsError,
        },
    }
}

fn refusal_of_tls(e: &rustls::Error) -> Refusal {
    match e {
        rustls::Error::AlertReceived(_) => Refusal::Alert,
        _ => Refusal::TlsError,
    }
}

/// Whether a refusal puts the pair into the bypass table.
///
/// An alert is an explicit "no" whatever came before (a pinned app on a
/// device whose browser uses the same host must still be bypassed). A silent
/// close during the handshake is a cancelled connect, not a verdict on the
/// leaf: TLS stacks that reject a certificate mid-handshake send an alert,
/// and Chrome drops in-flight handshakes silently whenever its certificate
/// settings reload. A silent close after the handshake with no request is
/// how post-handshake checkers (curl with OpenSSL) refuse, unless the same
/// pair sent a request recently (a browser dropping a spare socket).
fn bypasses(refusal: Refusal, stage: Stage, requested_recently: bool) -> bool {
    match (refusal, stage) {
        (Refusal::Unstarted, _) => false,
        (Refusal::SilentClose, Stage::Handshake) => false,
        (Refusal::SilentClose, Stage::AfterHandshake) => !requested_recently,
        (Refusal::Alert | Refusal::Timeout | Refusal::TlsError, _) => true,
    }
}

/// Takes a table whether or not another thread panicked holding it; the
/// table holds no invariant a half-done update could break.
fn lock_table(table: &Mutex<BypassTable>) -> MutexGuard<'_, BypassTable> {
    match table.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// What the client did first on a session that finished its handshake.
enum FirstRead {
    /// Request bytes arrived.
    Request,
    /// `close_notify`, or nothing before the timeout (an unused preconnect).
    Quiet,
    /// The session was dropped uncleanly or with an alert.
    Refused(Refusal),
}

/// Waits for the first request byte.
///
/// Some clients finish the handshake and only then check the certificate
/// (curl with OpenSSL, post-handshake pinning in app libraries); on refusal
/// they close the socket without `close_notify`. Seen from here the handshake
/// succeeded, so this is the same refusal one step later.
fn first_read(client: &mut ClientSide) -> FirstRead {
    match client.fill_buf() {
        Ok([]) => FirstRead::Quiet,
        Ok(_) => FirstRead::Request,
        Err(e) => match refusal_of(&e) {
            Refusal::Timeout => FirstRead::Quiet,
            refusal => FirstRead::Refused(refusal),
        },
    }
}

/// Serves the one leaf issued for the CONNECT host, whatever SNI says.
#[derive(Debug)]
struct OneLeaf(Arc<CertifiedKey>);

impl ResolvesServerCert for OneLeaf {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn set_timeouts(sock: &TcpStream, read: Duration, write: Duration) -> io::Result<()> {
    sock.set_read_timeout(Some(read))?;
    sock.set_write_timeout(Some(write))
}

/// Why the TLS connection to the upstream server could not be made. The
/// texts are the libraries' own; the log line around them is translated.
#[derive(Debug)]
enum UpstreamTlsError {
    ServerName,
    Tls(rustls::Error),
    Io(io::Error),
}

impl fmt::Display for UpstreamTlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerName => write!(f, "server_name"),
            Self::Tls(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

// ------------------------------------------------------------------
// Bypass table
// ------------------------------------------------------------------

/// (client IP, host) pairs tunnelled without decryption for a while. Memory
/// only; the clock is passed in so tests can step it.
struct BypassTable {
    entries: HashMap<(IpAddr, String), Instant>,
    ttl: Duration,
    capacity: usize,
}

impl BypassTable {
    fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            capacity,
        }
    }

    fn contains(&mut self, client_ip: IpAddr, host: &str, now: Instant) -> bool {
        let key = (client_ip, host.to_owned());
        match self.entries.get(&key) {
            Some(&added) if now.saturating_duration_since(added) < self.ttl => true,
            Some(_) => {
                self.entries.remove(&key);
                false
            }
            None => false,
        }
    }

    fn insert(&mut self, client_ip: IpAddr, host: String, now: Instant) {
        let key = (client_ip, host);
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            let ttl = self.ttl;
            self.entries
                .retain(|_, added| now.saturating_duration_since(*added) < ttl);
            if self.entries.len() >= self.capacity {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, added)| **added)
                    .map(|(key, _)| key.clone());
                if let Some(oldest) = oldest {
                    self.entries.remove(&oldest);
                }
            }
        }
        if self.capacity > 0 {
            self.entries.insert(key, now);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ------------------------------------------------------------------
// HTTP/1.1 heads
// ------------------------------------------------------------------

/// A start line and its header lines, CRLF removed.
struct Head {
    start: String,
    headers: Vec<String>,
}

enum HeadError {
    /// Closed (or timed out) before a full head arrived.
    Eof,
    /// A line over 8 KiB or more than 100 header lines (stage 7 limits).
    TooLarge,
}

fn read_head<R: BufRead>(input: &mut R) -> Result<Head, HeadError> {
    let start = match read_capped_line(input) {
        LineOutcome::Line(line) => line,
        LineOutcome::Eof => return Err(HeadError::Eof),
        LineOutcome::TooLong => return Err(HeadError::TooLarge),
    };
    let mut headers = Vec::new();
    loop {
        match read_capped_line(input) {
            LineOutcome::Line(line) if line.is_empty() => return Ok(Head { start, headers }),
            LineOutcome::Line(line) => {
                if headers.len() >= MAX_HEADER_LINES {
                    return Err(HeadError::TooLarge);
                }
                headers.push(line);
            }
            LineOutcome::Eof => return Err(HeadError::Eof),
            LineOutcome::TooLong => return Err(HeadError::TooLarge),
        }
    }
}

fn header_name(line: &str) -> &str {
    match line.split_once(':') {
        Some((name, _)) => name.trim(),
        None => line.trim(),
    }
}

fn header_values<'a>(headers: &'a [String], name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers.iter().filter_map(move |line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn first_header<'a>(headers: &'a [String], name: &'a str) -> Option<&'a str> {
    header_values(headers, name).next()
}

fn is_named(line: &str, names: &[&str]) -> bool {
    let name = header_name(line);
    names.iter().any(|n| name.eq_ignore_ascii_case(n))
}

/// `METHOD target HTTP/1.x`, returning the method.
fn request_method(start: &str) -> Option<&str> {
    let mut parts = start.split(' ');
    let method = parts.next().filter(|m| !m.is_empty())?;
    parts.next().filter(|t| !t.is_empty())?;
    let version = parts.next()?;
    (version.starts_with("HTTP/1.") && parts.next().is_none()).then_some(method)
}

/// `HTTP/1.x NNN reason`, returning the status code.
fn status_code(start: &str) -> Option<u16> {
    let mut parts = start.splitn(3, ' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse().ok()
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

/// The single `Content-Length` value, `Ok(None)` when absent. Repeated equal
/// values are one value; different or unreadable values are refused.
fn content_length(headers: &[String]) -> Result<Option<u64>, &'static str> {
    let mut found: Option<u64> = None;
    for value in header_values(headers, "content-length").flat_map(|v| v.split(',')) {
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("bad_content_length");
        }
        let Ok(n) = value.parse::<u64>() else {
            return Err("bad_content_length");
        };
        match found {
            Some(previous) if previous != n => return Err("conflicting_content_length"),
            _ => found = Some(n),
        }
    }
    Ok(found)
}

/// `Transfer-Encoding`: `Ok(false)` when absent, `Ok(true)` for exactly
/// `chunked`, `Err` for any other coding.
fn is_chunked(headers: &[String]) -> Result<bool, &'static str> {
    let codings: Vec<&str> = header_values(headers, "transfer-encoding")
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect();
    match codings.as_slice() {
        [] => Ok(false),
        [only] if only.eq_ignore_ascii_case("chunked") => Ok(true),
        _ => Err("unsupported_transfer_encoding"),
    }
}

/// The framing both kinds of message share; `without_length` is what a
/// message with neither header means (no body for a request, read-to-close
/// for a response).
fn body_framing(headers: &[String], without_length: Framing) -> Result<Framing, &'static str> {
    let length = content_length(headers)?;
    match (is_chunked(headers)?, length) {
        (true, Some(_)) => Err("transfer_encoding_with_content_length"),
        (true, None) => Ok(Framing::Chunked),
        (false, Some(n)) => Ok(Framing::Length(n)),
        (false, None) => Ok(without_length),
    }
}

fn request_framing(headers: &[String]) -> Result<Framing, &'static str> {
    if first_header(headers, "upgrade").is_some() {
        return Err("upgrade");
    }
    body_framing(headers, Framing::None)
}

fn response_framing(
    method: &str,
    status: u16,
    headers: &[String],
) -> Result<Framing, &'static str> {
    if method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 {
        return Ok(Framing::None);
    }
    body_framing(headers, Framing::UntilClose)
}

/// Hop-by-hop headers never passed on.
const HOP_BY_HOP: [&str; 3] = ["connection", "keep-alive", "proxy-connection"];

/// The request as sent upstream: hop-by-hop headers, `Expect` and
/// `Accept-Encoding` dropped; `Accept-Encoding: identity` so the stored bytes
/// are what gets scanned; `Connection: close`.
fn request_head(head: &Head) -> Vec<u8> {
    let mut out = String::with_capacity(512);
    out.push_str(&head.start);
    out.push_str("\r\n");
    for line in &head.headers {
        if is_named(line, &HOP_BY_HOP) || is_named(line, &["expect", "accept-encoding"]) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Accept-Encoding: identity\r\nConnection: close\r\n\r\n");
    out.into_bytes()
}

/// How the response body is delimited towards the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reframe {
    /// As upstream sent it.
    Keep,
    /// The held body, with its exact length.
    Length(usize),
    /// Decoded bytes until the connection closes.
    Close,
}

fn response_head(head: &Head, reframe: Reframe) -> Vec<u8> {
    let mut out = String::with_capacity(512);
    out.push_str(&head.start);
    out.push_str("\r\n");
    for line in &head.headers {
        if is_named(line, &HOP_BY_HOP) {
            continue;
        }
        if reframe != Reframe::Keep && is_named(line, &["transfer-encoding", "content-length"]) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if let Reframe::Length(n) = reframe {
        out.push_str(&format!("Content-Length: {n}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

/// A `1xx` interim response, passed on as received.
fn interim_head(head: &Head) -> Vec<u8> {
    let mut out = String::with_capacity(128);
    out.push_str(&head.start);
    out.push_str("\r\n");
    for line in &head.headers {
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// A short self-made response inside the decrypted connection.
fn respond_plain<W: Write>(out: &mut W, code: u16, reason: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = out.write_all(response.as_bytes());
    let _ = out.flush();
}

fn log_skip(host: &str, reason: SkipReason) {
    let message = crate::i18n::av_scan_skipped(crate::i18n::locale(), host, reason.as_log_str());
    let level = match reason {
        SkipReason::NotEligible => "debug",
        SkipReason::Encoded | SkipReason::TooLarge => "info",
        SkipReason::SlotFull => "warn",
    };
    eprintln!("packetdeath: [{level}] {message}");
}

// ------------------------------------------------------------------
// Bodies
// ------------------------------------------------------------------

fn send_request<R: BufRead, W: Write>(
    upstream: &mut W,
    client: &mut R,
    head: &Head,
    body: Framing,
) -> Result<(), ChunkError> {
    upstream.write_all(&request_head(head))?;
    match body {
        Framing::Length(n) => copy_exact(client, upstream, n)?,
        Framing::Chunked => copy_chunked(client, upstream)?,
        Framing::None | Framing::UntilClose => {}
    }
    upstream.flush()?;
    Ok(())
}

/// Passes the response on without holding it.
fn relay<R: BufRead, W: Write>(
    client: &mut W,
    upstream: &mut R,
    head: &Head,
    body: Framing,
) -> Result<(), ChunkError> {
    client.write_all(&response_head(head, Reframe::Keep))?;
    match body {
        Framing::None => {}
        Framing::Length(n) => copy_exact(upstream, client, n)?,
        Framing::Chunked => copy_chunked(upstream, client)?,
        Framing::UntilClose => copy_until_close(upstream, client)?,
    }
    client.flush()?;
    Ok(())
}

fn send_held<W: Write>(client: &mut W, head: &Head, held: &[u8]) -> io::Result<()> {
    client.write_all(&response_head(head, Reframe::Length(held.len())))?;
    client.write_all(held)?;
    client.flush()
}

fn copy_exact<R: Read, W: Write>(input: &mut R, output: &mut W, n: u64) -> io::Result<()> {
    let copied = io::copy(&mut input.take(n), output)?;
    if copied != n {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

/// TLS peers often close without `close_notify`; for a body that runs to the
/// close, that is the end.
fn is_end_of_body(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::UnexpectedEof
}

fn copy_until_close<R: Read, W: Write>(input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if is_end_of_body(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        output.write_all(&buf[..n])?;
    }
}

/// How holding a body for the scan ended.
enum Held {
    /// The whole body is in memory.
    Complete,
    /// It outgrew the limit; head and body were streamed to the client.
    Overflowed,
    /// Upstream failed before anything was sent to the client.
    Broken,
}

fn hold_exact<R: Read>(upstream: &mut R, held: &mut Vec<u8>, n: u64) -> Held {
    let Ok(capacity) = usize::try_from(n) else {
        return Held::Broken;
    };
    held.reserve_exact(capacity);
    match upstream.take(n).read_to_end(held) {
        Ok(_) if held.len() == capacity => Held::Complete,
        _ => Held::Broken,
    }
}

fn hold_chunked<R: BufRead, W: Write>(
    upstream: &mut R,
    client: &mut W,
    head: &Head,
    held: &mut Vec<u8>,
    max: usize,
) -> Held {
    let mut overflowed = false;
    let result = transfer_chunked(upstream, |piece| {
        let Piece::Data(data) = piece else {
            return Ok(());
        };
        if overflowed {
            return client.write_all(data);
        }
        if held.len() + data.len() > max {
            overflowed = true;
            client.write_all(&response_head(head, Reframe::Close))?;
            client.write_all(held)?;
            held.clear();
            return client.write_all(data);
        }
        held.extend_from_slice(data);
        Ok(())
    });
    match (result, overflowed) {
        (_, true) => Held::Overflowed,
        (Ok(()), false) => Held::Complete,
        (Err(_), false) => Held::Broken,
    }
}

fn hold_until_close<R: Read, W: Write>(
    upstream: &mut R,
    client: &mut W,
    head: &Head,
    held: &mut Vec<u8>,
    max: usize,
) -> Held {
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = match upstream.read(&mut buf) {
            Ok(0) => return Held::Complete,
            Ok(n) => n,
            Err(e) if is_end_of_body(&e) => return Held::Complete,
            Err(_) => return Held::Broken,
        };
        if held.len() + n > max {
            // A failure here only ends the response early; the head is out.
            let _ = client
                .write_all(&response_head(head, Reframe::Keep))
                .and_then(|()| client.write_all(held))
                .and_then(|()| client.write_all(&buf[..n]))
                .and_then(|()| copy_until_close(upstream, client));
            held.clear();
            return Held::Overflowed;
        }
        held.extend_from_slice(&buf[..n]);
    }
}

// ------------------------------------------------------------------
// Chunked transfer coding
// ------------------------------------------------------------------

/// A piece of a chunked body: framing bytes or decoded data.
enum Piece<'a> {
    Framing(&'a [u8]),
    Data(&'a [u8]),
}

#[derive(Debug)]
enum ChunkError {
    Io(io::Error),
    Malformed(&'static str),
}

impl From<io::Error> for ChunkError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Malformed(kind) => write!(f, "{kind}"),
        }
    }
}

/// A relay that ended early: the connection just closes, but the reason is
/// worth a debug line.
fn log_aborted(host: &str, e: &ChunkError) {
    eprintln!(
        "packetdeath: [debug] {}",
        crate::i18n::mitm_relay_aborted(crate::i18n::locale(), host, e)
    );
}

/// The size of a chunk-size line: hex digits, optionally followed by
/// `;extension`.
fn chunk_size(line: &str) -> Result<usize, ChunkError> {
    let digits = match line.split_once(';') {
        Some((digits, _)) => digits,
        None => line,
    }
    .trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ChunkError::Malformed("bad_chunk_size"));
    }
    usize::from_str_radix(digits, 16).map_err(|_| ChunkError::Malformed("chunk_size_overflow"))
}

/// Reads one chunked body to its end, handing every byte to `sink` in order:
/// framing (size lines, CRLFs, trailers) as `Framing`, chunk contents as
/// `Data`. Copying both reproduces the input; keeping `Data` decodes it.
fn transfer_chunked<R: BufRead>(
    input: &mut R,
    mut sink: impl FnMut(Piece<'_>) -> io::Result<()>,
) -> Result<(), ChunkError> {
    const TRUNCATED: ChunkError = ChunkError::Malformed("truncated");
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let line = match read_capped_line(input) {
            LineOutcome::Line(line) => line,
            LineOutcome::Eof => return Err(TRUNCATED),
            LineOutcome::TooLong => return Err(ChunkError::Malformed("chunk_size_line_too_long")),
        };
        let size = chunk_size(&line)?;
        sink(Piece::Framing(line.as_bytes()))?;
        sink(Piece::Framing(b"\r\n"))?;
        if size == 0 {
            break;
        }
        let mut left = size;
        while left > 0 {
            let want = left.min(buf.len());
            let n = input.read(&mut buf[..want])?;
            if n == 0 {
                return Err(TRUNCATED);
            }
            sink(Piece::Data(&buf[..n]))?;
            left -= n;
        }
        match read_capped_line(input) {
            LineOutcome::Line(line) if line.is_empty() => sink(Piece::Framing(b"\r\n"))?,
            LineOutcome::Eof => return Err(TRUNCATED),
            _ => return Err(ChunkError::Malformed("missing_chunk_crlf")),
        }
    }
    let mut trailers = 0usize;
    loop {
        match read_capped_line(input) {
            LineOutcome::Line(line) if line.is_empty() => {
                sink(Piece::Framing(b"\r\n"))?;
                return Ok(());
            }
            LineOutcome::Line(line) => {
                trailers += 1;
                if trailers > MAX_HEADER_LINES {
                    return Err(ChunkError::Malformed("too_many_trailers"));
                }
                sink(Piece::Framing(line.as_bytes()))?;
                sink(Piece::Framing(b"\r\n"))?;
            }
            LineOutcome::Eof => return Err(TRUNCATED),
            LineOutcome::TooLong => return Err(ChunkError::Malformed("trailer_too_long")),
        }
    }
}

fn copy_chunked<R: BufRead, W: Write>(input: &mut R, output: &mut W) -> Result<(), ChunkError> {
    transfer_chunked(input, |piece| match piece {
        Piece::Framing(bytes) | Piece::Data(bytes) => output.write_all(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    // -- bypass table ------------------------------------------------

    #[test]
    fn bypass_is_kept_per_client_and_host() {
        let mut table = BypassTable::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        table.insert(ip(1), "a.example".to_owned(), t0);
        assert!(table.contains(ip(1), "a.example", t0));
        assert!(
            !table.contains(ip(2), "a.example", t0),
            "another client was affected"
        );
        assert!(!table.contains(ip(1), "b.example", t0));
    }

    #[test]
    fn bypass_expires_after_its_ttl() {
        let mut table = BypassTable::new(Duration::from_secs(60), 16);
        let t0 = Instant::now();
        table.insert(ip(1), "a.example".to_owned(), t0);
        assert!(table.contains(ip(1), "a.example", t0 + Duration::from_secs(59)));
        assert!(!table.contains(ip(1), "a.example", t0 + Duration::from_secs(60)));
        assert_eq!(table.len(), 0, "an expired pair was not dropped");
    }

    #[test]
    fn a_full_bypass_table_drops_its_oldest_pair() {
        let mut table = BypassTable::new(Duration::from_secs(600), 2);
        let t0 = Instant::now();
        table.insert(ip(1), "a.example".to_owned(), t0);
        table.insert(ip(1), "b.example".to_owned(), t0 + Duration::from_secs(1));
        table.insert(ip(1), "c.example".to_owned(), t0 + Duration::from_secs(2));
        let now = t0 + Duration::from_secs(3);
        assert_eq!(table.len(), 2);
        assert!(!table.contains(ip(1), "a.example", now));
        assert!(table.contains(ip(1), "b.example", now));
        assert!(table.contains(ip(1), "c.example", now));
    }

    #[test]
    fn default_limits_match_the_design() {
        let limits = MitmLimits::default();
        assert_eq!(limits.bypass_ttl, Duration::from_secs(3600));
        assert_eq!(limits.bypass_capacity, 4096);
        assert_eq!(limits.max_scan_bytes, 8_588_886_016);
        assert_eq!(limits.scan_budget_bytes, 8_589_934_592);
        assert_eq!(limits.clamd_timeout, Duration::from_secs(1260));
        assert_eq!(limits.decrypt_port, 443);
    }

    // -- chunked -----------------------------------------------------

    fn decode(input: &[u8]) -> Result<Vec<u8>, ChunkError> {
        let mut data = Vec::new();
        transfer_chunked(&mut Cursor::new(input), |piece| {
            if let Piece::Data(bytes) = piece {
                data.extend_from_slice(bytes);
            }
            Ok(())
        })?;
        Ok(data)
    }

    fn malformed(result: Result<Vec<u8>, ChunkError>) -> Option<&'static str> {
        match result {
            Err(ChunkError::Malformed(kind)) => Some(kind),
            _ => None,
        }
    }

    #[test]
    fn chunked_decodes_a_plain_body() -> Result<(), String> {
        let data =
            decode(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").map_err(|e| format!("{e:?}"))?;
        assert_eq!(data, b"hello world");
        Ok(())
    }

    #[test]
    fn chunked_reads_hex_in_either_case() -> Result<(), String> {
        let body = vec![b'x'; 26];
        let mut upper = b"1A\r\n".to_vec();
        upper.extend_from_slice(&body);
        upper.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(decode(&upper).map_err(|e| format!("{e:?}"))?, body);
        let mut lower = b"1a\r\n".to_vec();
        lower.extend_from_slice(&body);
        lower.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(decode(&lower).map_err(|e| format!("{e:?}"))?, body);
        Ok(())
    }

    #[test]
    fn chunked_ignores_extensions() -> Result<(), String> {
        let data =
            decode(b"3;name=value\r\nabc\r\n0;last\r\n\r\n").map_err(|e| format!("{e:?}"))?;
        assert_eq!(data, b"abc");
        Ok(())
    }

    #[test]
    fn chunked_accepts_trailers() -> Result<(), String> {
        let data = decode(b"2\r\nok\r\n0\r\nX-Check: 1\r\n\r\n").map_err(|e| format!("{e:?}"))?;
        assert_eq!(data, b"ok");
        Ok(())
    }

    #[test]
    fn chunked_refuses_an_overlong_size_line() {
        let mut input = vec![b'0'; 9000];
        input.extend_from_slice(b"\r\n\r\n");
        assert_eq!(malformed(decode(&input)), Some("chunk_size_line_too_long"));
    }

    #[test]
    fn chunked_refuses_a_size_that_is_not_hex() {
        assert_eq!(
            malformed(decode(b"zz\r\nab\r\n0\r\n\r\n")),
            Some("bad_chunk_size")
        );
        assert_eq!(
            malformed(decode(b"+5\r\nhello\r\n0\r\n\r\n")),
            Some("bad_chunk_size")
        );
        assert_eq!(malformed(decode(b"\r\n")), Some("bad_chunk_size"));
    }

    #[test]
    fn chunked_refuses_a_size_beyond_usize() {
        assert_eq!(
            malformed(decode(b"1ffffffffffffffff\r\n")),
            Some("chunk_size_overflow")
        );
    }

    #[test]
    fn chunked_refuses_a_missing_end() {
        assert_eq!(malformed(decode(b"5\r\nhello\r\n")), Some("truncated"));
        assert_eq!(malformed(decode(b"5\r\nhel")), Some("truncated"));
        assert_eq!(malformed(decode(b"5\r\nhello\r\n0\r\n")), Some("truncated"));
        assert_eq!(
            malformed(decode(b"5\r\nhelloXX0\r\n\r\n")),
            Some("missing_chunk_crlf")
        );
    }

    #[test]
    fn chunked_copy_reproduces_the_input() -> Result<(), String> {
        let input =
            b"5;ext=1\r\nhello\r\n1A\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nX-Trailer: v\r\n\r\n";
        let mut out = Vec::new();
        copy_chunked(&mut Cursor::new(&input[..]), &mut out).map_err(|e| format!("{e:?}"))?;
        assert_eq!(out, input.to_vec());
        Ok(())
    }

    // -- heads and framing -------------------------------------------

    fn head(start: &str, headers: &[&str]) -> Head {
        Head {
            start: start.to_owned(),
            headers: headers.iter().map(|h| (*h).to_owned()).collect(),
        }
    }

    #[test]
    fn the_request_upstream_drops_hop_headers_and_asks_for_identity() -> TestResult {
        let request = head(
            "GET /f.zip HTTP/1.1",
            &[
                "Host: dl.example",
                "Connection: keep-alive",
                "Proxy-Connection: keep-alive",
                "Keep-Alive: timeout=5",
                "Expect: 100-continue",
                "Accept-Encoding: gzip, br",
                "User-Agent: t",
            ],
        );
        let sent = String::from_utf8(request_head(&request))?;
        assert_eq!(
            sent,
            "GET /f.zip HTTP/1.1\r\nHost: dl.example\r\nUser-Agent: t\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        );
        Ok(())
    }

    #[test]
    fn conflicting_lengths_and_mixed_framing_are_refused() {
        let two = [
            "Content-Length: 5".to_owned(),
            "Content-Length: 6".to_owned(),
        ];
        assert_eq!(request_framing(&two), Err("conflicting_content_length"));
        let listed = ["Content-Length: 5, 6".to_owned()];
        assert_eq!(request_framing(&listed), Err("conflicting_content_length"));
        let mixed = [
            "Transfer-Encoding: chunked".to_owned(),
            "Content-Length: 5".to_owned(),
        ];
        assert_eq!(
            request_framing(&mixed),
            Err("transfer_encoding_with_content_length")
        );
        assert_eq!(
            response_framing("GET", 200, &mixed),
            Err("transfer_encoding_with_content_length")
        );
        assert_eq!(
            response_framing("GET", 200, &two),
            Err("conflicting_content_length")
        );
    }

    #[test]
    fn repeated_equal_lengths_are_one_length() {
        let same = [
            "Content-Length: 5".to_owned(),
            "content-length: 5".to_owned(),
        ];
        assert_eq!(request_framing(&same), Ok(Framing::Length(5)));
    }

    #[test]
    fn upgrade_and_odd_codings_are_refused() {
        let upgrade = [
            "Connection: Upgrade".to_owned(),
            "Upgrade: websocket".to_owned(),
        ];
        assert_eq!(request_framing(&upgrade), Err("upgrade"));
        let gzip = ["Transfer-Encoding: gzip, chunked".to_owned()];
        assert_eq!(request_framing(&gzip), Err("unsupported_transfer_encoding"));
        let bad = ["Content-Length: -1".to_owned()];
        assert_eq!(request_framing(&bad), Err("bad_content_length"));
    }

    #[test]
    fn request_framing_reads_each_shape() {
        assert_eq!(request_framing(&[]), Ok(Framing::None));
        let chunked = ["Transfer-Encoding: Chunked".to_owned()];
        assert_eq!(request_framing(&chunked), Ok(Framing::Chunked));
        let length = ["Content-Length: 12".to_owned()];
        assert_eq!(request_framing(&length), Ok(Framing::Length(12)));
    }

    #[test]
    fn response_framing_reads_each_shape() {
        let length = ["Content-Length: 12".to_owned()];
        assert_eq!(response_framing("HEAD", 200, &length), Ok(Framing::None));
        assert_eq!(response_framing("GET", 204, &[]), Ok(Framing::None));
        assert_eq!(response_framing("GET", 304, &length), Ok(Framing::None));
        assert_eq!(
            response_framing("GET", 200, &length),
            Ok(Framing::Length(12))
        );
        assert_eq!(response_framing("GET", 200, &[]), Ok(Framing::UntilClose));
        let chunked = ["Transfer-Encoding: chunked".to_owned()];
        assert_eq!(response_framing("GET", 200, &chunked), Ok(Framing::Chunked));
    }

    #[test]
    fn the_response_head_is_reframed_as_asked() -> TestResult {
        let response = head(
            "HTTP/1.1 200 OK",
            &[
                "Content-Type: application/zip",
                "Transfer-Encoding: chunked",
                "Connection: keep-alive",
                "Keep-Alive: timeout=5",
            ],
        );
        let kept = String::from_utf8(response_head(&response, Reframe::Keep))?;
        assert_eq!(
            kept,
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        );
        let held = String::from_utf8(response_head(&response, Reframe::Length(7)))?;
        assert_eq!(
            held,
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 7\r\nConnection: close\r\n\r\n"
        );
        let closed = String::from_utf8(response_head(&response, Reframe::Close))?;
        assert_eq!(
            closed,
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nConnection: close\r\n\r\n"
        );
        Ok(())
    }

    #[test]
    fn start_lines_are_read_strictly() {
        assert_eq!(request_method("GET /x HTTP/1.1"), Some("GET"));
        assert_eq!(request_method("GET /x HTTP/2"), None);
        assert_eq!(request_method("GET /x"), None);
        assert_eq!(request_method(""), None);
        assert_eq!(status_code("HTTP/1.1 206 Partial Content"), Some(206));
        assert_eq!(status_code("HTTP/1.1 200"), Some(200));
        assert_eq!(status_code("HTTP/1.1 2000 OK"), None);
        assert_eq!(status_code("ICY 200 OK"), None);
    }

    #[test]
    fn a_head_over_the_limits_is_too_large() {
        let mut many = String::from("HTTP/1.1 200 OK\r\n");
        for i in 0..=MAX_HEADER_LINES {
            many.push_str(&format!("X-{i}: v\r\n"));
        }
        many.push_str("\r\n");
        assert!(matches!(
            read_head(&mut Cursor::new(many.into_bytes())),
            Err(HeadError::TooLarge)
        ));
        let long = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "v".repeat(9000));
        assert!(matches!(
            read_head(&mut Cursor::new(long.into_bytes())),
            Err(HeadError::TooLarge)
        ));
        assert!(matches!(
            read_head(&mut Cursor::new(b"HTTP/1.1 200 OK\r\n".to_vec())),
            Err(HeadError::Eof)
        ));
    }

    // -- holding bodies ----------------------------------------------

    #[test]
    fn an_oversized_chunked_body_is_streamed_decoded() -> TestResult {
        let response = head("HTTP/1.1 200 OK", &["Transfer-Encoding: chunked"]);
        let mut upstream = Cursor::new(b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n".to_vec());
        let mut client = Vec::new();
        let mut held = Vec::new();
        let outcome = hold_chunked(&mut upstream, &mut client, &response, &mut held, 4);
        assert!(matches!(outcome, Held::Overflowed));
        let text = String::from_utf8(client)?;
        assert!(
            text.ends_with("Connection: close\r\n\r\nabcdef"),
            "{text:?}"
        );
        assert!(!text.contains("Transfer-Encoding"));
        Ok(())
    }

    #[test]
    fn a_chunked_body_within_the_limit_is_held_decoded() {
        let response = head("HTTP/1.1 200 OK", &["Transfer-Encoding: chunked"]);
        let mut upstream = Cursor::new(b"3\r\nabc\r\n0\r\n\r\n".to_vec());
        let mut client = Vec::new();
        let mut held = Vec::new();
        let outcome = hold_chunked(&mut upstream, &mut client, &response, &mut held, 3);
        assert!(matches!(outcome, Held::Complete));
        assert_eq!(held, b"abc");
        assert!(
            client.is_empty(),
            "nothing goes to the client before the scan"
        );
    }

    #[test]
    fn a_short_body_is_broken() {
        let mut held = Vec::new();
        let outcome = hold_exact(&mut Cursor::new(b"abc".to_vec()), &mut held, 5);
        assert!(matches!(outcome, Held::Broken));
    }

    // -- refusals ----------------------------------------------------

    #[test]
    fn a_recent_request_cancels_only_a_silent_close() {
        let after = Stage::AfterHandshake;
        assert!(!bypasses(Refusal::SilentClose, after, true));
        assert!(bypasses(Refusal::SilentClose, after, false));
        assert!(bypasses(Refusal::Alert, after, true));
        assert!(bypasses(Refusal::Timeout, after, true));
        assert!(bypasses(Refusal::TlsError, after, true));
    }

    #[test]
    fn a_client_that_never_started_tls_is_never_bypassed() {
        for stage in [Stage::Handshake, Stage::AfterHandshake] {
            assert!(!bypasses(Refusal::Unstarted, stage, false));
            assert!(!bypasses(Refusal::Unstarted, stage, true));
        }
    }

    /// The whole table: Refusal x Stage x recent request.
    #[test]
    fn bypass_table_of_refusal_stage_and_recent_request() {
        use Refusal::{Alert, SilentClose, Timeout, TlsError, Unstarted};
        use Stage::{AfterHandshake, Handshake};
        let expected = [
            (Alert, Handshake, false, true),
            (Alert, Handshake, true, true),
            (Alert, AfterHandshake, false, true),
            (Alert, AfterHandshake, true, true),
            (SilentClose, Handshake, false, false),
            (SilentClose, Handshake, true, false),
            (SilentClose, AfterHandshake, false, true),
            (SilentClose, AfterHandshake, true, false),
            (Timeout, Handshake, false, true),
            (Timeout, Handshake, true, true),
            (Timeout, AfterHandshake, false, true),
            (Timeout, AfterHandshake, true, true),
            (TlsError, Handshake, false, true),
            (TlsError, Handshake, true, true),
            (TlsError, AfterHandshake, false, true),
            (TlsError, AfterHandshake, true, true),
            (Unstarted, Handshake, false, false),
            (Unstarted, Handshake, true, false),
            (Unstarted, AfterHandshake, false, false),
            (Unstarted, AfterHandshake, true, false),
        ];
        for (refusal, stage, recent, bypassed) in expected {
            assert_eq!(
                bypasses(refusal, stage, recent),
                bypassed,
                "{refusal:?} {} recent={recent}",
                stage.as_log_str()
            );
        }
    }

    #[test]
    fn eof_and_reset_are_silent_closes() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
        ] {
            assert_eq!(refusal_of(&io::Error::from(kind)), Refusal::SilentClose);
        }
    }

    #[test]
    fn a_wrapped_alert_is_an_alert() {
        let alert = rustls::Error::AlertReceived(rustls::AlertDescription::UnknownCA);
        let wrapped = io::Error::new(io::ErrorKind::InvalidData, alert);
        assert_eq!(refusal_of(&wrapped), Refusal::Alert);
    }

    #[test]
    fn another_tls_error_is_not_an_alert() {
        let wrapped = io::Error::new(io::ErrorKind::InvalidData, rustls::Error::DecryptError);
        assert_eq!(refusal_of(&wrapped), Refusal::TlsError);
        let plain = io::Error::from(io::ErrorKind::InvalidData);
        assert_eq!(refusal_of(&plain), Refusal::TlsError);
    }

    #[test]
    fn a_timeout_is_its_own_reason() {
        assert_eq!(
            refusal_of(&io::Error::from(io::ErrorKind::TimedOut)),
            Refusal::Timeout
        );
        assert_eq!(
            refusal_of(&io::Error::from(io::ErrorKind::WouldBlock)),
            Refusal::Timeout
        );
    }
}
