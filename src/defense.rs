//! Stage 10: the watch side, the breaker, `--defense-off` and `defense-report`.
//! `docs/design.md` "段階10 能動防御（PC を守る見張りと遮断）", policies 4 and
//! 6, is the source of truth.
//!
//! [`Defense`] sits beside the stage 7 judges and adds three things:
//!
//! - **Watch lists** (`--watch-blocklist`, `--watch-iplist`,
//!   `--watch-distrust`). A hit is written to `<log dir>/watch.jsonl` and the
//!   flow is decided exactly as without the list. They run for every flow,
//!   allowlisted ones included (`"allowlisted":true`), because the promotion
//!   rule counts allowlisted hits and a short-circuit would hide them. A flow a
//!   stop-side judge already hit is not written again.
//! - **Stop lists** (`--distrust`, and the prober's table). A hit stops the
//!   flow (`Reason::Chain`) unless the safety devices say otherwise: the
//!   `--defense-off` file turns every stop-side hit into a watch row
//!   (`mode:"off"`), and a breaker per source does the same (`mode:"breaker"`)
//!   once the source stopped more than `--breaker-hosts` distinct hosts in ten
//!   minutes. The allowlist always wins over this stage.
//! - **`defense-report`**, the read-only subcommand that counts the rows per
//!   source and says whether a watched source may be promoted to the stop side.
//!
//! The file `watch.jsonl` is created only when a stage 10 option is given, so a
//! proxy started without them behaves and logs exactly as before.
//!
//! Nothing here performs network I/O on the judging path: the table of chains
//! is read, the probe is only queued, and rows are appended to a local file.

use crate::allowlist::Allowlist;
use crate::blocklist::Blocklist;
use crate::distrust::{chain_prints, CertPrints, DistrustList};
use crate::flow::FlowKey;
use crate::iplist::IpList;
use crate::judge::Reason;
use crate::prober::{lock, ChainHit, ChainVerdicts, ProbeError, ProbeSettings, Prober};
use crate::reload::{self, ReloadWatcher};
use rustls::pki_types::{CertificateDer, TrustAnchor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Distinct hosts one stop source may stop inside [`BREAKER_WINDOW`].
pub const DEFAULT_BREAKER_HOSTS: usize = 5;
/// The window the breaker counts newly stopped hosts in.
pub const BREAKER_WINDOW: Duration = Duration::from_secs(10 * 60);
/// A host marked by the prober that sits on the allowlist is warned about at
/// most this often.
const MARK_WARN_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// The `source` of rows that come from the prober's table.
pub const PROBE_SOURCE: &str = "probe";
/// Days of log a source needs before `defense-report` says `promote=yes`.
pub const PROMOTE_MIN_DAYS: usize = 7;

fn say(level: &str, message: impl fmt::Display) {
    crate::flow::service_log(&format!("packetdeath: [{level}] {message}"));
}

/// The kind of list a row comes from: the `kind` field of `watch.jsonl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Blocklist,
    Iplist,
    Distrust,
    Chain,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blocklist => "blocklist",
            Self::Iplist => "iplist",
            Self::Distrust => "distrust",
            Self::Chain => "chain",
        }
    }
}

/// Why a row was written instead of a stop: the `mode` field of `watch.jsonl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A watch list, which never stops.
    Watch,
    /// A stop source whose breaker has tripped.
    Breaker,
    /// The `--defense-off` file exists.
    Off,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Breaker => "breaker",
            Self::Off => "off",
        }
    }
}

/// What the defense needs to know about one flow.
#[derive(Clone, Copy)]
pub struct FlowFacts<'a> {
    pub key: FlowKey,
    pub host: &'a str,
    /// The stage 7 judges did not run because the allowlist matched.
    pub allowlisted: bool,
}

#[derive(Debug)]
pub enum DefenseError {
    WatchLog(PathBuf, std::io::Error),
    Probe(ProbeError),
}

impl fmt::Display for DefenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WatchLog(path, e) => write!(
                f,
                "{}",
                crate::i18n::watch_log_open_failed(crate::i18n::locale(), path.display(), e)
            ),
            Self::Probe(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DefenseError {}

// ------------------------------------------------------------
// The breaker
// ------------------------------------------------------------

/// The verdict of [`Breakers::admit`].
#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// The hit may stop the flow.
    Stop,
    /// This hit is the one over the threshold: the source falls to watch now.
    Tripped,
    /// The source already fell to watch.
    Fallen,
}

#[derive(Default)]
struct SourceState {
    stopped: HashMap<String, Instant>,
    tripped: bool,
}

/// Counts, per stop source, the distinct hosts newly stopped inside a window.
/// The threshold is the number of hosts a source may stop; the next new host
/// trips it, and that host is itself let through.
pub struct Breakers {
    threshold: usize,
    window: Duration,
    sources: HashMap<String, SourceState>,
}

impl Breakers {
    pub fn new(threshold: usize, window: Duration) -> Self {
        Self {
            threshold,
            window,
            sources: HashMap::new(),
        }
    }

    pub fn admit(&mut self, source: &str, host: &str, now: Instant) -> Admit {
        let window = self.window;
        let state = self.sources.entry(source.to_owned()).or_default();
        if state.tripped {
            return Admit::Fallen;
        }
        state
            .stopped
            .retain(|_, at| now.saturating_duration_since(*at) < window);
        let host = host.to_ascii_lowercase();
        if state.stopped.contains_key(&host) {
            return Admit::Stop;
        }
        if state.stopped.len() >= self.threshold {
            state.tripped = true;
            return Admit::Tripped;
        }
        state.stopped.insert(host, now);
        Admit::Stop
    }

    /// Forgets a source: its list file changed, so it stops again.
    pub fn reset(&mut self, source: &str) {
        self.sources.remove(source);
    }
}

// ------------------------------------------------------------
// The lists
// ------------------------------------------------------------

/// One list file and what was read from it. `name` is the file name: it is the
/// `source` of the rows and the key of the breaker.
struct Source<T> {
    name: String,
    watcher: ReloadWatcher,
    list: T,
}

/// The `source` of rows that come from the list file at `path`.
pub fn source_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

fn load_distrust(path: &Path) -> Source<DistrustList> {
    let watcher = ReloadWatcher::new(path.to_path_buf());
    let list = match std::fs::read_to_string(path) {
        Ok(content) => {
            let list = DistrustList::parse(&content);
            say(
                "info",
                crate::i18n::distrust_loaded(
                    crate::i18n::locale(),
                    path.display(),
                    list.len(),
                    list.skipped(),
                ),
            );
            warn_skipped(path, &list);
            list
        }
        Err(e) => {
            say(
                "warn",
                crate::i18n::distrust_load_failed_empty(crate::i18n::locale(), path.display(), e),
            );
            DistrustList::empty()
        }
    };
    Source {
        name: source_name(path),
        watcher,
        list,
    }
}

fn warn_skipped(path: &Path, list: &DistrustList) {
    if list.skipped() > 0 {
        say(
            "warn",
            crate::i18n::distrust_lines_skipped(
                crate::i18n::locale(),
                path.display(),
                list.skipped(),
            ),
        );
    }
}

/// Re-reads a distrust file when it changed; `true` when it was replaced.
fn reload_distrust(source: &mut Source<DistrustList>) -> bool {
    let replaced = reload::apply(
        &mut source.watcher,
        &mut source.list,
        "distrust",
        DistrustList::parse,
        DistrustList::len,
    );
    if replaced {
        warn_skipped(source.watcher.path(), &source.list);
    }
    replaced
}

fn named<T>(files: Vec<(PathBuf, T)>) -> Vec<Source<T>> {
    files
        .into_iter()
        .map(|(path, list)| Source {
            name: source_name(&path),
            watcher: ReloadWatcher::new(path),
            list,
        })
        .collect()
}

/// Every list the defense reads, with the files they came from.
struct Lists {
    stop: Vec<Source<DistrustList>>,
    watch_distrust: Vec<Source<DistrustList>>,
    blocklists: Vec<Source<Blocklist>>,
    iplists: Vec<Source<IpList>>,
}

impl Lists {
    fn load(config: &DefenseConfig) -> Self {
        Self {
            stop: config
                .stop_distrust
                .iter()
                .map(|p| load_distrust(p))
                .collect(),
            watch_distrust: config
                .watch_distrust
                .iter()
                .map(|p| load_distrust(p))
                .collect(),
            blocklists: named(Blocklist::load_all(&config.watch_blocklists)),
            iplists: named(IpList::load_all(&config.watch_iplists)),
        }
    }

    fn stop_matches(&self, chain: &[CertPrints]) -> bool {
        self.stop.iter().any(|s| s.list.matches_chain(chain))
    }

    fn first_stop_match(&self, chain: &[CertPrints]) -> Option<String> {
        self.stop
            .iter()
            .find(|s| s.list.matches_chain(chain))
            .map(|s| s.name.clone())
    }

    fn watch_distrust_matches(&self, chain: &[CertPrints]) -> bool {
        self.watch_distrust
            .iter()
            .any(|s| s.list.matches_chain(chain))
    }

    fn watch_distrust_names(&self, chain: &[CertPrints]) -> Vec<String> {
        self.watch_distrust
            .iter()
            .filter(|s| s.list.matches_chain(chain))
            .map(|s| s.name.clone())
            .collect()
    }

    fn any_distrust_matches(&self, chain: &[CertPrints]) -> bool {
        self.stop_matches(chain) || self.watch_distrust_matches(chain)
    }

    /// The watch blocklists and iplists a flow hits, as `(source, kind)`.
    fn list_hits(&self, host: &str, dst_ip: IpAddr, out: &mut Vec<(String, Kind)>) {
        out.extend(
            self.blocklists
                .iter()
                .filter(|s| s.list.matches(host))
                .map(|s| (s.name.clone(), Kind::Blocklist)),
        );
        out.extend(
            self.iplists
                .iter()
                .filter(|s| s.list.contains(&dst_ip))
                .map(|s| (s.name.clone(), Kind::Iplist)),
        );
    }

    /// Re-reads the changed files. Returns the names of the stop sources that
    /// were replaced: their breakers are reset.
    fn reload(&mut self) -> Vec<String> {
        let replaced_stop = self
            .stop
            .iter_mut()
            .filter_map(|s| reload_distrust(s).then(|| s.name.clone()))
            .collect();
        for source in &mut self.watch_distrust {
            reload_distrust(source);
        }
        for s in &mut self.blocklists {
            reload::apply(
                &mut s.watcher,
                &mut s.list,
                "watch-blocklist",
                Blocklist::parse,
                Blocklist::len,
            );
        }
        for s in &mut self.iplists {
            reload::apply(
                &mut s.watcher,
                &mut s.list,
                "watch-iplist",
                IpList::parse,
                IpList::len,
            );
        }
        replaced_stop
    }
}

// ------------------------------------------------------------
// watch.jsonl
// ------------------------------------------------------------

#[derive(Serialize)]
struct WatchRow<'a> {
    ts: String,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    sni: &'a str,
    source: &'a str,
    kind: &'static str,
    mode: &'static str,
    allowlisted: bool,
}

/// `<log dir>/watch.jsonl`. Unlike `flows.jsonl` it is not echoed to stdout.
struct WatchSink {
    file: Mutex<File>,
}

impl WatchSink {
    fn open(path: &Path) -> Result<Self, DefenseError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| DefenseError::WatchLog(path.to_path_buf(), e))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// A failed write is reported and dropped: the flow is decided regardless.
    fn write(&self, facts: &FlowFacts<'_>, source: &str, kind: Kind, mode: Mode) {
        let locale = crate::i18n::locale();
        let ts = match OffsetDateTime::now_utc().format(&Rfc3339) {
            Ok(ts) => ts,
            Err(e) => return say("error", crate::i18n::timestamp_format_failed(locale, e)),
        };
        let row = WatchRow {
            ts,
            src_ip: facts.key.src_ip,
            src_port: facts.key.src_port,
            dst_ip: facts.key.dst_ip,
            dst_port: facts.key.dst_port,
            sni: facts.host,
            source,
            kind: kind.as_str(),
            mode: mode.as_str(),
            allowlisted: facts.allowlisted,
        };
        let mut line = match serde_json::to_string(&row) {
            Ok(line) => line,
            Err(e) => return say("error", crate::i18n::watch_log_write_failed(locale, e)),
        };
        line.push('\n');
        if let Err(e) = lock(&self.file).write_all(line.as_bytes()) {
            say("error", crate::i18n::watch_log_write_failed(locale, e));
        }
    }
}

// ------------------------------------------------------------
// The defense
// ------------------------------------------------------------

/// Everything [`Defense::start`] needs. A list that is not given is not read.
pub struct DefenseConfig {
    /// `--distrust`: a hit stops the flow.
    pub stop_distrust: Vec<PathBuf>,
    /// `--watch-distrust`: a hit is written to `watch.jsonl`.
    pub watch_distrust: Vec<PathBuf>,
    pub watch_blocklists: Vec<PathBuf>,
    pub watch_iplists: Vec<PathBuf>,
    /// `--probe-chains`.
    pub probe: Option<ProbeSettings>,
    /// `--defense-off`.
    pub off_file: Option<PathBuf>,
    /// `--breaker-hosts`.
    pub breaker_hosts: usize,
    /// `<log dir>/watch.jsonl`.
    pub watch_log: PathBuf,
    /// The roots a chain is completed with: the public web PKI in production.
    pub anchors: Vec<TrustAnchor<'static>>,
}

impl DefenseConfig {
    /// No list, no probe, no off file.
    pub fn new(watch_log: PathBuf, anchors: Vec<TrustAnchor<'static>>) -> Self {
        Self {
            stop_distrust: Vec::new(),
            watch_distrust: Vec::new(),
            watch_blocklists: Vec::new(),
            watch_iplists: Vec::new(),
            probe: None,
            off_file: None,
            breaker_hosts: DEFAULT_BREAKER_HOSTS,
            watch_log,
            anchors,
        }
    }
}

/// The running state of stage 10, shared by every connection thread.
pub struct Defense {
    lists: Arc<Mutex<Lists>>,
    verdicts: Arc<ChainVerdicts>,
    prober: Option<Prober>,
    sink: WatchSink,
    breakers: Mutex<Breakers>,
    off_file: Option<PathBuf>,
    off: AtomicBool,
    anchors: Arc<Vec<TrustAnchor<'static>>>,
    marked_warned: Mutex<HashMap<String, Instant>>,
}

impl Defense {
    /// Opens `watch.jsonl`, reads the lists and starts the prober when asked.
    /// Any `Err` means stage 10 stays off; the proxy still runs without it.
    pub fn start(config: DefenseConfig) -> Result<Self, DefenseError> {
        let sink = WatchSink::open(&config.watch_log)?;
        let lists = Arc::new(Mutex::new(Lists::load(&config)));
        let verdicts = Arc::new(ChainVerdicts::with_defaults());
        let anchors = Arc::new(config.anchors.clone());
        let prober = Self::start_prober(&config, &lists, &verdicts, &anchors)?;
        let off = config
            .off_file
            .as_deref()
            .is_some_and(|path| std::fs::metadata(path).is_ok());
        say(
            "info",
            crate::i18n::defense_started(
                crate::i18n::locale(),
                config.stop_distrust.len(),
                config.watch_distrust.len()
                    + config.watch_blocklists.len()
                    + config.watch_iplists.len(),
                prober.is_some(),
                config.breaker_hosts,
            ),
        );
        Ok(Self {
            lists,
            verdicts,
            prober,
            sink,
            breakers: Mutex::new(Breakers::new(config.breaker_hosts, BREAKER_WINDOW)),
            off_file: config.off_file,
            off: AtomicBool::new(off),
            anchors,
            marked_warned: Mutex::new(HashMap::new()),
        })
    }

    fn start_prober(
        config: &DefenseConfig,
        lists: &Arc<Mutex<Lists>>,
        verdicts: &Arc<ChainVerdicts>,
        anchors: &Arc<Vec<TrustAnchor<'static>>>,
    ) -> Result<Option<Prober>, DefenseError> {
        let Some(settings) = config.probe.clone() else {
            return Ok(None);
        };
        let for_log = Arc::clone(lists);
        let hit: ChainHit = Arc::new(move |chain| lock(&for_log).any_distrust_matches(chain));
        Prober::start(settings, Arc::clone(verdicts), Arc::clone(anchors), hit)
            .map(Some)
            .map_err(DefenseError::Probe)
    }

    /// The table the [`crate::prober::ChainJudge`] reads.
    pub fn verdicts(&self) -> &ChainVerdicts {
        &self.verdicts
    }

    /// Whether a chain matches a stop-side list.
    pub fn stop_hit(&self, chain: &[CertPrints]) -> bool {
        lock(&self.lists).stop_matches(chain)
    }

    /// Called at every poll of the proxy (300 ms): the off file and the lists.
    pub fn poll(&self) {
        self.poll_off();
        let replaced = lock(&self.lists).reload();
        if !replaced.is_empty() {
            let mut breakers = lock(&self.breakers);
            for name in &replaced {
                breakers.reset(name);
            }
        }
    }

    fn poll_off(&self) {
        let Some(path) = self.off_file.as_deref() else {
            return;
        };
        let on = std::fs::metadata(path).is_ok();
        if self.off.swap(on, Ordering::AcqRel) != on {
            let message = crate::i18n::defense_off_changed(crate::i18n::locale(), on);
            say(if on { "warn" } else { "info" }, message);
        }
    }

    /// Decides the stage 10 part of one flow. `stop` is what the stage 7
    /// judges (and the chain judge) said: a stop-side verdict other than
    /// `Reason::Chain` is returned untouched and writes no row. A
    /// `Reason::Chain` goes through the safety devices and may turn into a
    /// watch row. A passed flow is checked against the watch lists and, when
    /// not allowlisted, offered to the prober.
    pub fn assess(&self, facts: &FlowFacts<'_>, stop: Option<Reason>) -> Option<Reason> {
        let stop = match stop {
            Some(Reason::Chain) => self
                .gate(PROBE_SOURCE, Kind::Chain, facts)
                .then_some(Reason::Chain),
            other => other,
        };
        if stop.is_some() {
            return stop;
        }
        self.write_watch_hits(facts);
        if facts.allowlisted {
            self.warn_if_marked(facts.host);
        } else if let Some(prober) = &self.prober {
            prober.offer(facts.host, facts.key.dst_ip, facts.key.dst_port);
        }
        None
    }

    /// Checks the chain stage 8 saw at its upstream handshake. `true` when the
    /// flow must be denied. Watch lists are written either way.
    pub fn check_upstream_chain(
        &self,
        facts: &FlowFacts<'_>,
        chain: &[CertificateDer<'_>],
    ) -> bool {
        let prints = chain_prints(chain, &self.anchors);
        let (stop, watching) = {
            let lists = lock(&self.lists);
            (
                lists.first_stop_match(&prints),
                lists.watch_distrust_names(&prints),
            )
        };
        for source in &watching {
            self.sink.write(facts, source, Kind::Distrust, Mode::Watch);
        }
        stop.is_some_and(|source| self.stop_upstream(&source, facts))
    }

    fn stop_upstream(&self, source: &str, facts: &FlowFacts<'_>) -> bool {
        let stop = self.gate(source, Kind::Distrust, facts);
        if stop {
            say(
                "warn",
                crate::i18n::upstream_chain_distrusted(crate::i18n::locale(), facts.host, source),
            );
        }
        stop
    }

    /// Whether a stop-side hit of `source` may stop the flow. When it may not
    /// a watch row says why.
    fn gate(&self, source: &str, kind: Kind, facts: &FlowFacts<'_>) -> bool {
        if self.off.load(Ordering::Acquire) {
            self.sink.write(facts, source, kind, Mode::Off);
            return false;
        }
        let admit = lock(&self.breakers).admit(source, facts.host, Instant::now());
        match admit {
            Admit::Stop => true,
            Admit::Tripped => {
                say(
                    "error",
                    crate::i18n::breaker_tripped(
                        crate::i18n::locale(),
                        source,
                        lock(&self.breakers).threshold,
                    ),
                );
                self.sink.write(facts, source, kind, Mode::Breaker);
                false
            }
            Admit::Fallen => {
                self.sink.write(facts, source, kind, Mode::Breaker);
                false
            }
        }
    }

    /// Writes a row for every watch list the flow hits.
    ///
    /// Lock order: the table of chains, then the lists, never the reverse
    /// (the chain judge and `warn_if_marked` take them in this order). Here
    /// they are taken one after the other.
    fn write_watch_hits(&self, facts: &FlowFacts<'_>) {
        let mut hits: Vec<(String, Kind)> = Vec::new();
        lock(&self.lists).list_hits(facts.host, facts.key.dst_ip, &mut hits);
        let probed = self.verdicts.with(facts.host, Instant::now(), |chain| {
            lock(&self.lists).watch_distrust_matches(chain)
        });
        if matches!(probed, Some(true)) {
            hits.push((PROBE_SOURCE.to_owned(), Kind::Chain));
        }
        for (source, kind) in &hits {
            self.sink.write(facts, source, *kind, Mode::Watch);
        }
    }

    /// An allowlisted host the prober marked is let through; say so, at most
    /// once an hour per host.
    fn warn_if_marked(&self, host: &str) {
        let now = Instant::now();
        let marked = self.verdicts.with(host, now, |chain| self.stop_hit(chain));
        if !matches!(marked, Some(true)) {
            return;
        }
        let key = host.to_ascii_lowercase();
        let mut warned = lock(&self.marked_warned);
        let recent = warned
            .get(&key)
            .is_some_and(|at| now.saturating_duration_since(*at) < MARK_WARN_INTERVAL);
        if recent {
            return;
        }
        warned.insert(key, now);
        drop(warned);
        say(
            "warn",
            crate::i18n::chain_marked_allowlisted(crate::i18n::locale(), host),
        );
    }
}

// ------------------------------------------------------------
// defense-report
// ------------------------------------------------------------

/// One line of the report.
#[derive(Debug, PartialEq, Eq)]
pub struct ReportRow {
    pub source: String,
    pub hits: usize,
    /// Distinct hosts.
    pub hosts: usize,
    /// Distinct hosts that are also on an allowlist.
    pub allowlisted: usize,
    /// Distinct dates of the log that was read.
    pub days: usize,
    /// The distrust file holds a line that matches a public trust anchor.
    pub root: bool,
    pub promote: bool,
}

impl fmt::Display for ReportRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "source={} hits={} hosts={} allowlisted={} days={}",
            self.source, self.hits, self.hosts, self.allowlisted, self.days
        )?;
        if self.root {
            write!(f, " root=yes")?;
        }
        write!(f, " promote={}", if self.promote { "yes" } else { "no" })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub rows: Vec<ReportRow>,
    /// Lines that could not be read (a torn last line, a row without a date).
    pub skipped: usize,
}

/// A row of `flows.jsonl` or `watch.jsonl`, reduced to what the report reads.
#[derive(Deserialize)]
struct LogRow {
    ts: String,
    sni: Option<String>,
    dst_ip: Option<String>,
    source: Option<String>,
    #[serde(default)]
    allowlisted: bool,
}

impl LogRow {
    fn date(&self) -> Option<&str> {
        self.ts.get(..10)
    }

    /// The host a row is counted under: the SNI, else the destination.
    fn host(&self) -> Option<&str> {
        self.sni.as_deref().or(self.dst_ip.as_deref())
    }
}

/// Parses the lines of a log; the second value counts the lines dropped.
fn read_rows(content: &str) -> (Vec<LogRow>, usize) {
    let mut skipped = 0;
    let mut rows = Vec::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        match serde_json::from_str::<LogRow>(line) {
            Ok(row) if row.date().is_some() && row.host().is_some() => rows.push(row),
            _ => skipped += 1,
        }
    }
    (rows, skipped)
}

fn log_days(rows: &[LogRow]) -> usize {
    rows.iter()
        .filter_map(LogRow::date)
        .collect::<HashSet<_>>()
        .len()
}

#[derive(Default)]
struct Tally {
    hits: usize,
    hosts: HashSet<String>,
    allowlisted: HashSet<String>,
    per_day: HashMap<String, HashSet<String>>,
}

impl Tally {
    fn add(&mut self, date: &str, host: &str, allowlisted: bool) {
        self.hits += 1;
        self.hosts.insert(host.to_owned());
        if allowlisted {
            self.allowlisted.insert(host.to_owned());
        }
        self.per_day
            .entry(date.to_owned())
            .or_default()
            .insert(host.to_owned());
    }

    fn max_day_hosts(&self) -> Option<usize> {
        self.per_day.values().map(HashSet::len).max()
    }
}

/// What a source must show before it may be promoted.
struct Criteria {
    log_days: usize,
    min_days: usize,
    breaker_hosts: usize,
}

impl Criteria {
    /// The three conditions of the design, and never for a root line.
    fn allows(&self, tally: &Tally, root: bool) -> bool {
        self.log_days >= PROMOTE_MIN_DAYS.max(self.min_days)
            && tally.allowlisted.is_empty()
            && tally
                .max_day_hosts()
                .is_none_or(|most| most < self.breaker_hosts)
            && !root
    }

    fn row(&self, source: String, tally: &Tally, root: bool) -> ReportRow {
        ReportRow {
            promote: self.allows(tally, root),
            hits: tally.hits,
            hosts: tally.hosts.len(),
            allowlisted: tally.allowlisted.len(),
            days: self.log_days,
            root,
            source,
        }
    }
}

fn on_allowlists(allowlists: &[Allowlist], host: &str) -> bool {
    allowlists.iter().any(|list| list.matches(host))
}

/// Counts `watch.jsonl` per source. `root_sources` names the sources whose
/// distrust file holds a line for a public trust anchor.
pub fn report_watch(
    watch_jsonl: &str,
    allowlists: &[Allowlist],
    root_sources: &HashSet<String>,
    min_days: usize,
) -> Report {
    let (rows, skipped) = read_rows(watch_jsonl);
    let criteria = Criteria {
        log_days: log_days(&rows),
        min_days,
        breaker_hosts: DEFAULT_BREAKER_HOSTS,
    };
    let mut tallies: BTreeMap<&str, Tally> = BTreeMap::new();
    for row in &rows {
        let (Some(source), Some(date), Some(host)) =
            (row.source.as_deref(), row.date(), row.host())
        else {
            continue;
        };
        let allowlisted = row.allowlisted || on_allowlists(allowlists, host);
        tallies
            .entry(source)
            .or_default()
            .add(date, host, allowlisted);
    }
    let rows = tallies
        .into_iter()
        .map(|(source, tally)| {
            criteria.row(source.to_owned(), &tally, root_sources.contains(source))
        })
        .collect();
    Report { rows, skipped }
}

/// Re-applies candidate lists to a past `flows.jsonl`: how many flows each list
/// would have hit.
pub fn report_flows(
    flows_jsonl: &str,
    blocklists: &[(String, Blocklist)],
    iplists: &[(String, IpList)],
    allowlists: &[Allowlist],
    min_days: usize,
) -> Report {
    let (rows, skipped) = read_rows(flows_jsonl);
    let criteria = Criteria {
        log_days: log_days(&rows),
        min_days,
        breaker_hosts: DEFAULT_BREAKER_HOSTS,
    };
    let mut report = Report {
        rows: Vec::new(),
        skipped,
    };
    for (name, list) in blocklists {
        let tally = tally_flows(&rows, allowlists, |row| {
            row.sni.as_deref().is_some_and(|sni| list.matches(sni))
        });
        report.rows.push(criteria.row(name.clone(), &tally, false));
    }
    for (name, list) in iplists {
        let tally = tally_flows(&rows, allowlists, |row| {
            row.dst_ip
                .as_deref()
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                .is_some_and(|ip| list.contains(&ip))
        });
        report.rows.push(criteria.row(name.clone(), &tally, false));
    }
    report
}

fn tally_flows(rows: &[LogRow], allowlists: &[Allowlist], hit: impl Fn(&LogRow) -> bool) -> Tally {
    let mut tally = Tally::default();
    for row in rows.iter().filter(|row| hit(row)) {
        let (Some(date), Some(host)) = (row.date(), row.host()) else {
            continue;
        };
        let allowlisted = row
            .sni
            .as_deref()
            .is_some_and(|sni| on_allowlists(allowlists, sni));
        tally.add(date, host, allowlisted);
    }
    tally
}

/// The names of the distrust files that hold a line for a public trust
/// anchor, for the `root=yes` mark.
pub fn root_sources(
    files: &[(PathBuf, DistrustList)],
    anchors: &[TrustAnchor<'_>],
) -> HashSet<String> {
    files
        .iter()
        .filter(|(_, list)| list.root_entries(anchors) > 0)
        .map(|(path, _)| source_name(path))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64, base: Instant) -> Instant {
        base + Duration::from_secs(seconds)
    }

    #[test]
    fn the_breaker_trips_on_the_host_after_the_threshold_and_not_before() {
        let base = Instant::now();
        let mut breakers = Breakers::new(3, BREAKER_WINDOW);
        for (n, host) in ["a.test", "b.test", "c.test"].into_iter().enumerate() {
            assert_eq!(
                breakers.admit("list", host, at(n as u64, base)),
                Admit::Stop
            );
        }
        // A host already stopped is not a new one.
        assert_eq!(breakers.admit("list", "A.test", at(5, base)), Admit::Stop);
        assert_eq!(
            breakers.admit("list", "d.test", at(6, base)),
            Admit::Tripped
        );
        // Fallen for good, whichever host comes.
        assert_eq!(breakers.admit("list", "a.test", at(7, base)), Admit::Fallen);
        // Another source is untouched.
        assert_eq!(breakers.admit("other", "d.test", at(7, base)), Admit::Stop);
    }

    #[test]
    fn the_breaker_forgets_hosts_after_the_window_and_after_a_reset() {
        let base = Instant::now();
        let mut breakers = Breakers::new(1, Duration::from_secs(60));
        assert_eq!(breakers.admit("list", "a.test", base), Admit::Stop);
        assert_eq!(
            breakers.admit("list", "b.test", at(30, base)),
            Admit::Tripped
        );
        breakers.reset("list");
        assert_eq!(breakers.admit("list", "b.test", at(31, base)), Admit::Stop);
        // The first host left the window; the second takes its place.
        assert_eq!(breakers.admit("list", "c.test", at(100, base)), Admit::Stop);
    }

    #[test]
    fn a_source_is_named_by_its_file_name() {
        assert_eq!(source_name(Path::new("/home/x/pd/w.txt")), "w.txt");
        assert_eq!(source_name(Path::new("w.txt")), "w.txt");
    }

    #[test]
    fn kinds_and_modes_have_the_logged_names() {
        let kinds = [Kind::Blocklist, Kind::Iplist, Kind::Distrust, Kind::Chain];
        let names: Vec<&str> = kinds.into_iter().map(Kind::as_str).collect();
        assert_eq!(names, ["blocklist", "iplist", "distrust", "chain"]);
        let modes = [Mode::Watch, Mode::Breaker, Mode::Off];
        let names: Vec<&str> = modes.into_iter().map(Mode::as_str).collect();
        assert_eq!(names, ["watch", "breaker", "off"]);
    }

    fn flow_line(ts: &str, sni: &str, dst_ip: &str) -> String {
        format!(
            "{{\"ts\":\"{ts}\",\"proto\":\"tcp\",\"src_ip\":\"192.168.0.2\",\"src_port\":5000,\
             \"dst_ip\":\"{dst_ip}\",\"dst_port\":443,\"sni\":\"{sni}\",\"sni_state\":\"ok\",\
             \"decision\":\"pass\",\"reason\":null}}\n"
        )
    }

    #[test]
    fn defense_report_counts_hits_per_source_and_allowlisted_hosts() {
        let mut log = String::new();
        log.push_str(&flow_line(
            "2026-10-20T01:00:00Z",
            "known.test",
            "198.51.100.1",
        ));
        log.push_str(&flow_line(
            "2026-10-20T01:00:05Z",
            "known.test",
            "198.51.100.1",
        ));
        log.push_str(&flow_line(
            "2026-10-21T01:00:00Z",
            "www.known.test",
            "198.51.100.1",
        ));
        log.push_str(&flow_line(
            "2026-10-21T02:00:00Z",
            "kept.test",
            "203.0.113.9",
        ));
        log.push_str("{\"ts\":\"2026-10-21T0");
        let known = Blocklist::parse("known.test\n");
        let none = Blocklist::parse("nonexistent.invalid\n");
        let ips = IpList::parse("203.0.113.9\n");
        let allow = Allowlist::parse("www.known.test\n");
        let report = report_flows(
            &log,
            &[
                ("known.txt".to_owned(), known),
                ("none.txt".to_owned(), none),
            ],
            &[("ips.txt".to_owned(), ips)],
            &[allow],
            0,
        );
        assert_eq!(report.skipped, 1);
        let lines: Vec<String> = report.rows.iter().map(ToString::to_string).collect();
        assert_eq!(
            lines,
            [
                "source=known.txt hits=3 hosts=2 allowlisted=1 days=2 promote=no",
                "source=none.txt hits=0 hosts=0 allowlisted=0 days=2 promote=no",
                "source=ips.txt hits=1 hosts=1 allowlisted=0 days=2 promote=no",
            ]
        );
    }

    fn watch_line(date: &str, host: &str, source: &str, allowlisted: bool) -> String {
        format!(
            "{{\"ts\":\"{date}T01:00:00Z\",\"src_ip\":\"192.168.0.2\",\"src_port\":5000,\
             \"dst_ip\":\"198.51.100.1\",\"dst_port\":443,\"sni\":\"{host}\",\"source\":\"{source}\",\
             \"kind\":\"blocklist\",\"mode\":\"watch\",\"allowlisted\":{allowlisted}}}\n"
        )
    }

    /// One host a day for `days` days from the 10th.
    fn quiet_week(source: &str, days: usize) -> String {
        (10..10 + days)
            .map(|day| watch_line(&format!("2026-10-{day:02}"), "a.test", source, false))
            .collect()
    }

    fn lines_of(report: &Report) -> Vec<String> {
        report.rows.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn promotion_is_refused_when_an_allowlisted_host_was_hit() {
        let mut log = quiet_week("clean.txt", 7);
        log.push_str(&quiet_week("dirty.txt", 7));
        log.push_str(&watch_line("2026-10-12", "ok.test", "dirty.txt", true));
        let none = HashSet::new();
        let report = report_watch(&log, &[], &none, 0);
        assert_eq!(
            lines_of(&report),
            [
                "source=clean.txt hits=7 hosts=1 allowlisted=0 days=7 promote=yes",
                "source=dirty.txt hits=8 hosts=2 allowlisted=1 days=7 promote=no",
            ]
        );
        // The same log, with the allowlist given on the command line instead.
        let mut plain = quiet_week("dirty.txt", 7);
        plain.push_str(&watch_line("2026-10-12", "ok.test", "dirty.txt", false));
        let allow = [Allowlist::parse("ok.test\n")];
        let report = report_watch(&plain, &allow, &none, 0);
        assert!(lines_of(&report)[0].ends_with("allowlisted=1 days=7 promote=no"));
    }

    #[test]
    fn promotion_needs_seven_real_days_and_a_quiet_day() {
        let none = HashSet::new();
        let short = report_watch(&quiet_week("a.txt", 6), &[], &none, 0);
        assert!(lines_of(&short)[0].ends_with("days=6 promote=no"));
        // `--days` raises the bar but cannot stand in for real days.
        let asked = report_watch(&quiet_week("a.txt", 7), &[], &none, 10);
        assert!(lines_of(&asked)[0].ends_with("days=7 promote=no"));
        // Five distinct hosts in one day reach the breaker threshold.
        let mut busy = quiet_week("a.txt", 7);
        for host in ["b.test", "c.test", "d.test", "e.test"] {
            busy.push_str(&watch_line("2026-10-10", host, "a.txt", false));
        }
        let busy = report_watch(&busy, &[], &none, 0);
        assert!(lines_of(&busy)[0].ends_with("hosts=5 allowlisted=0 days=7 promote=no"));
    }

    #[test]
    fn a_root_line_is_marked_and_never_promoted() {
        let roots: HashSet<String> = ["manual.txt".to_owned()].into_iter().collect();
        let report = report_watch(&quiet_week("manual.txt", 7), &[], &roots, 0);
        assert_eq!(
            lines_of(&report),
            ["source=manual.txt hits=7 hosts=1 allowlisted=0 days=7 root=yes promote=no"]
        );
    }

    #[test]
    fn an_empty_log_gives_no_rows_and_a_broken_line_is_counted() {
        let none = HashSet::new();
        assert_eq!(report_watch("", &[], &none, 0), Report::default());
        let broken = report_watch("not json\n\n", &[], &none, 0);
        assert_eq!(broken.rows.len(), 0);
        assert_eq!(broken.skipped, 1);
    }

    #[test]
    fn root_sources_skips_a_file_without_a_trust_anchor_line() {
        let plain = DistrustList::parse("cert-sha1 0000000000000000000000000000000000000000\n");
        let files = [(PathBuf::from("/x/plain.txt"), plain)];
        assert!(root_sources(&files, webpki_roots::TLS_SERVER_ROOTS).is_empty());
    }
}
