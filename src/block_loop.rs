//! pcapng file を監視し、SNI が blocklist に当たった flow を
//! [`TcpBlocker`] へ渡して切る、OS に依存しない loop core。
//!
//! `windows.rs`（pcapng の parse・SNI 判定への橋渡し・`TcpRowSpec` の構築）と
//! `ps_bridge.rs`（常駐 PowerShell との通信）の両方を呼ぶ「配線」の層であり、
//! 判定そのもの（`sni.rs` / `blocklist.rs` / `judge.rs`）は書き直さない。
//!
//! # pcapng file をどう監視するか（判断）
//!
//! **polling で file 全体を読み直す。**利用者は `pktmon stop` →
//! `pktmon etl2pcap` を随時 実行して pcapng を作り直す運用であり
//! （`windows.rs` 冒頭コメント）、その file が「末尾へ追記される」の
//! か「毎回 丸ごと作り直される」のかは `未確認`。file 末尾の byte 位置を覚えて
//! そこから読み継ぐ設計は、file が丸ごと作り直された場合に「古い offset から
//! 新しい file の途中を読む」事故になり、block 境界がずれて壊れた byte 列を
//! 読む形になる。file 全体を毎回 読み直せば、どちらの運用でも
//! `extract_pcapng_packets` の fail-open 性質（壊れた block で読み取りを打ち
//! 切るだけ）に守られたまま安全に扱える。file サイズ（`len()`）が前回と同じ
//! ときは読み直しを省略し、無駄な I/O を避ける。
//!
//! # 同じパケットを二度 処理しない仕組み（判断）
//!
//! **flow 単位（[`FlowKey`]）で重複排除する。**file 全体を毎回 読み直す設計
//! では byte 位置による重複排除ができない。`linux.rs`（`run_block`）が
//! 「一度 判定した flow は `seen`/`blocked` に載せ、後続 packet を無視する」
//! のと同じ形を踏襲し、`processed: HashSet<FlowKey>` に一度でも判定した
//! flow を積んで、以降は同じ flow の packet を skip する。
//!
//! `sni_state` が `Fragmented`（[`crate::reassemble::Reassembler`] が
//! まだ判定できていない）の間は `processed` へ入れない。同じ flow の
//! 後続 segment を積み続けられるようにするためで、判定が確定した
//! （`Ok` / `None`、または `Reassembler` が上限で諦めた `Fragmented`）
//! 瞬間にだけ `processed` へ入れて1行 log を書く（`docs/design.md`
//! 「ClientHello の組み立て直し」節）。
//!
//! # `send_tcp_row` の呼び出しを test から観測できる形（判断）
//!
//! **trait（[`TcpBlocker`]）にする。**`judge.rs` の `Judge` trait と同じ形で、
//! test は呼び出し回数と引数を記録するだけの実装を注入できるようにする。
//! `PsBridge` を直接 呼ぶ設計だと、test は実際に `powershell.exe`
//! （この box には存在しない）を起動しない限り検証できない。
//!
//! # 走行中の blocklist / allowlist / iplist 読み直し（判断）
//!
//! **`JudgeConfig<'a>` の借用（`&'a Blocklist` / `&'a Allowlist` /
//! `&'a IpList`）はそのまま変えない。**所有権は新しく足す [`WatchInputs`]
//! が持ち、`run_watch_loop` が poll のたびに [`WatchInputs::poll_reloads`]
//! を呼んで中身を差し替えた上で、その場で `JudgeConfig` を組み立てて既存の
//! 判定関数へ渡す。blocklist と iplist は複数 file の和集合で、file ごとに
//! 読み直す（`docs/design.md`「段階9 malware feed」）。`av` は走行中に
//! 読み直さない（段階6は Windows 向け受入が無い。`win_service.rs` と同じ判断）
//! ので `&'a` の借用のまま。読み直しの実体（file の変化検知・fail-open）は
//! `reload.rs` に切り出し、ここでは呼び出すだけにする。

use crate::allowlist::Allowlist;
use crate::av::AvList;
use crate::blocklist::Blocklist;
use crate::flow::{FlowKey, FlowLogEntry, FlowLogSink, LogError, DECISION_BLOCK, DECISION_PASS};
use crate::iplist::IpList;
use crate::judge::Reason;
use crate::ps_bridge::{BridgeError, PsBridge, STARTUP_TIMEOUT};
use crate::reassemble::{FrameOutcome, Reassembler};
use crate::reload::{self, ReloadWatcher};
use crate::sni::SniState;
use crate::windows::{
    build_tcp_row_spec, extract_pcapng_packets, inspect_captured_frame, judge_sni, TcpRowSpec,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// `send_tcp_row` 相当の口。実体は [`RespawningPsBridge`]、test は記録するだけの
/// 実装を注入する。
pub trait TcpBlocker {
    /// `row` の接続切断を試みる。成功したら `true`。
    /// 失敗（`PsBridge` が `Err` を返した等）したら `false` を返し、
    /// **呼び出し側はこれを遮断の失敗として扱い、素通しに倒す**。
    fn try_block(&mut self, row: &TcpRowSpec) -> bool;
}

/// 常に遮断を諦める実装。常駐 PowerShell の起動（`spawn_powershell`）自体が
/// 失敗したときのフォールバックに使う（fail-open。通信は止めない）。
pub struct NoopBlocker;

impl TcpBlocker for NoopBlocker {
    fn try_block(&mut self, _row: &TcpRowSpec) -> bool {
        false
    }
}

/// [`PsBridge`] を遅延 spawn し、`Poisoned` になったら次回 呼び出しで
/// spawn し直す薄い wrapper。`ps_bridge.rs` の doc comment（「呼び出し側は
/// 次の要求で新しい `PsBridge` を spawn し直す設計」）に従う。
pub struct RespawningPsBridge {
    script_path: PathBuf,
    spawner: fn(&Path) -> std::io::Result<PsBridge>,
    startup_timeout: Duration,
    backoff: Duration,
    /// No spawn before this instant. Set by a failed warm-up, cleared by a
    /// successful one.
    next_spawn_at: Option<Instant>,
    bridge: Option<PsBridge>,
}

/// How long [`RespawningPsBridge`] refuses to spawn after a failed warm-up.
///
/// Without it, a machine whose warm-up always fails would pay a spawn and up
/// to [`STARTUP_TIMEOUT`] for every flow, and `process_pcapng_snapshot`
/// handles one snapshot synchronously, so even a service stop would wait.
pub const WARM_UP_BACKOFF: Duration = Duration::from_secs(60);

impl RespawningPsBridge {
    pub fn new(script_path: PathBuf) -> Self {
        Self::with_spawner(
            script_path,
            PsBridge::spawn_powershell,
            STARTUP_TIMEOUT,
            WARM_UP_BACKOFF,
        )
    }

    /// `new` with the spawn function, the warm-up limit and the backoff given,
    /// so a test can drive the warm-up and backoff with a stand-in child.
    pub fn with_spawner(
        script_path: PathBuf,
        spawner: fn(&Path) -> std::io::Result<PsBridge>,
        startup_timeout: Duration,
        backoff: Duration,
    ) -> Self {
        Self {
            script_path,
            spawner,
            startup_timeout,
            backoff,
            next_spawn_at: None,
            bridge: None,
        }
    }

    /// Warms the resident PowerShell once when the loop starts, so the first
    /// connection does not pay the start-up time. A failed warm-up does not
    /// stop the loop.
    pub fn prepare(&mut self) {
        self.ensure_bridge();
    }

    /// Returns the live bridge, or spawns and warms one. A failed spawn or
    /// warm-up yields `None` (the caller fails open for this packet). After a
    /// failed warm-up, nothing is spawned or logged for `backoff`; `None` is
    /// returned.
    fn ensure_bridge(&mut self) -> Option<&mut PsBridge> {
        if self.bridge.is_none() {
            if self.next_spawn_at.is_some_and(|at| Instant::now() < at) {
                return None;
            }
            self.bridge = self.spawn_warmed();
        }
        self.bridge.as_mut()
    }

    /// Spawns a child and waits for its first response. A child that does not
    /// answer is dropped (which kills and reaps it) and the backoff starts.
    fn spawn_warmed(&mut self) -> Option<PsBridge> {
        let locale = crate::i18n::locale();
        let mut bridge = match (self.spawner)(&self.script_path) {
            Ok(bridge) => bridge,
            Err(e) => {
                crate::flow::service_log(&format!(
                    "packetdeath: [error] {}",
                    crate::i18n::ps_bridge_spawn_failed(locale, e)
                ));
                return None;
            }
        };
        let started = Instant::now();
        match bridge.warm_up(self.startup_timeout) {
            Ok(resp) => {
                self.next_spawn_at = None;
                crate::flow::service_log(&format!(
                    "packetdeath: [info] {}",
                    crate::i18n::ps_bridge_warmed(locale, started.elapsed().as_millis(), resp.rc)
                ));
                Some(bridge)
            }
            Err(e) => {
                // `BridgeError::Timeout` prints the row limit; name the limit
                // this wait actually used.
                let reason = match e {
                    BridgeError::Timeout => {
                        crate::i18n::ps_bridge_timeout(locale, self.startup_timeout)
                    }
                    other => other.to_string(),
                };
                crate::flow::service_log(&format!(
                    "packetdeath: [error] {}",
                    crate::i18n::ps_bridge_warm_up_failed(locale, self.startup_timeout, reason)
                ));
                self.next_spawn_at = Some(Instant::now() + self.backoff);
                None
            }
        }
    }
}

impl TcpBlocker for RespawningPsBridge {
    fn try_block(&mut self, row: &TcpRowSpec) -> bool {
        let Some(bridge) = self.ensure_bridge() else {
            return false;
        };
        match bridge.send_tcp_row(row) {
            // Only a zero return from `SetTcpEntry` means the connection was cut.
            Ok(resp) if resp.rc == 0 => {
                crate::flow::service_log(&format!(
                    "packetdeath: [debug] {}",
                    crate::i18n::tcp_connection_cut(crate::i18n::locale(), resp.rc, resp.micros)
                ));
                true
            }
            Ok(resp) => {
                crate::flow::service_log(&format!(
                    "packetdeath: [warn] {}",
                    crate::i18n::tcp_cut_rejected(crate::i18n::locale(), resp.rc, resp.micros)
                ));
                false
            }
            Err(BridgeError::Poisoned) => {
                // 二度と使えない bridge を捨てる。次回 呼び出しの ensure_bridge が
                // spawn し直す。今回の packet の遮断は諦める（loop は止めない）。
                self.bridge = None;
                false
            }
            Err(e) => {
                crate::flow::service_log(&format!(
                    "packetdeath: [error] {}",
                    crate::i18n::tcp_block_failed(crate::i18n::locale(), e)
                ));
                false
            }
        }
    }
}

/// `judge_sni`（`windows.rs`）に渡す判定材料をまとめた設定。
/// `process_pcapng_snapshot` / `run_watch_loop` の引数を clippy
/// `too_many_arguments`（上限7）以内に保つためにまとめる
/// （`linux.rs::BlockConfig` と同じ判断）。
pub struct JudgeConfig<'a> {
    pub blocklist: &'a Blocklist,
    pub iplist: &'a IpList,
    pub av: &'a AvList,
    /// 「当たっても通す」allowlist。未指定なら `Allowlist::empty()`
    /// （何も救わない＝従来どおりの挙動）。`docs/design.md`「判定を差し込む口」：
    /// SNI が当たれば `blocklist` / `iplist` / `av` のどれに当たっていても
    /// 通す（`judge_and_log` が先頭でチェックする）。
    pub allowlist: &'a Allowlist,
}

/// [`run_watch_loop`] が所有する、poll ごとに読み直す対象一式。
///
/// `blocklist` / `iplist` は、起動時から持つ固定の中身（`*_base`。file を
/// 持たない）と、file ごとに読み直す部分（`*_files`）の和集合を判定に使う
/// （`--blocklist` / `--iplist` の複数指定。`docs/design.md`「段階9」）。
/// どれか1本の file が変わると、その部分だけを読み直して和集合を組み直す。
/// 読み直しに失敗した file は前の部分を使い続ける。`allowlist` は path が
/// `Some` なら [`ReloadWatcher`] で監視する。`av` は借用のまま読み直さない。
pub struct WatchInputs<'a> {
    blocklist_base: Blocklist,
    blocklist_files: Vec<Watched<Blocklist>>,
    blocklist: Blocklist,
    allowlist: Allowlist,
    allowlist_watcher: Option<ReloadWatcher>,
    iplist_base: IpList,
    iplist_files: Vec<Watched<IpList>>,
    iplist: IpList,
    av: &'a AvList,
    /// Stage 8 `--mitm-list`, reloaded like the iplist files. `None` while
    /// decryption is off.
    mitm: Option<Watched<MitmList>>,
    /// Stage 10 (`docs/design.md` "段階10 能動防御"): polled with the other
    /// files. `None` while no stage 10 option is given.
    #[cfg(target_os = "linux")]
    defense: Option<std::sync::Arc<crate::defense::Defense>>,
}

/// Stage 8 `--mitm-list`: the hosts whose HTTPS is decrypted and scanned
/// (`docs/design.md` "段階8 MITM", CLI table). One domain per line, `#` lines
/// and blank lines ignored, case-insensitive, a trailing `.` dropped, suffix
/// match like the blocklist. An IP literal never matches.
#[derive(Debug, Default, Clone)]
pub struct MitmList {
    /// Normalized entries, kept to name each one in the allowlist warning.
    entries: Vec<String>,
    matcher: Blocklist,
}

impl MitmList {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn parse(content: &str) -> Self {
        let entries: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.trim_end_matches('.').to_ascii_lowercase())
            .filter(|line| !line.is_empty())
            .collect();
        let matcher = Blocklist::parse(&entries.join("\n"));
        Self { entries, matcher }
    }

    /// Reads `path`. An unreadable file gives an empty list and a `[warn]`
    /// (fail-open: decrypting nothing is the safe side); the path is still
    /// watched, so the list takes effect once the file appears.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let list = Self::parse(&content);
                crate::flow::service_log(&format!(
                    "packetdeath: [info] {}",
                    crate::i18n::mitm_list_loaded(
                        crate::i18n::locale(),
                        path.display(),
                        list.len()
                    )
                ));
                list
            }
            Err(e) => {
                crate::flow::service_log(&format!(
                    "packetdeath: [warn] {}",
                    crate::i18n::mitm_list_load_failed_empty(
                        crate::i18n::locale(),
                        path.display(),
                        e
                    )
                ));
                Self::empty()
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `host` (as named in the CONNECT line) is to be decrypted.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        if host.parse::<std::net::IpAddr>().is_ok() {
            return false;
        }
        self.matcher.matches(host)
    }
}

/// The `--mitm-list` entries the allowlist covers. Those hosts are never
/// decrypted, which must not happen silently (`docs/design.md` "復号する範囲"
/// item 3, the council's fix C).
pub fn mitm_allowlist_overlap<'a>(list: &'a MitmList, allowlist: &Allowlist) -> Vec<&'a str> {
    list.entries
        .iter()
        .map(String::as_str)
        .filter(|entry| allowlist.matches(entry))
        .collect()
}

/// One `[warn]` per overlapping entry, at startup and after each reload.
fn warn_mitm_allowlist_overlap(list: &MitmList, allowlist: &Allowlist) {
    for host in mitm_allowlist_overlap(list, allowlist) {
        crate::flow::service_log(&format!(
            "packetdeath: [warn] {}",
            crate::i18n::mitm_list_entry_allowlisted(crate::i18n::locale(), host)
        ));
    }
}

/// 1 file と、その file から読んだ部分。
struct Watched<T> {
    watcher: ReloadWatcher,
    list: T,
}

fn watch_files<T>(files: Vec<(PathBuf, T)>) -> Vec<Watched<T>> {
    files
        .into_iter()
        .map(|(path, list)| Watched {
            watcher: ReloadWatcher::new(path),
            list,
        })
        .collect()
}

/// 各 file の変化を確かめ、1つでも差し替えたら `true`。全 file を必ず
/// 確かめる（`|=` は短絡しない）。
fn reload_files<T>(
    files: &mut [Watched<T>],
    kind: &str,
    parse: impl Fn(&str) -> T,
    len_of: impl Fn(&T) -> usize,
) -> bool {
    let mut replaced = false;
    for file in files {
        replaced |= reload::apply(&mut file.watcher, &mut file.list, kind, &parse, &len_of);
    }
    replaced
}

impl<'a> WatchInputs<'a> {
    /// `blocklist` / `iplist` は file を持たない固定の中身（無ければ `empty()`）。
    /// file から読む list は [`with_blocklist_files`](Self::with_blocklist_files) /
    /// [`with_iplist_files`](Self::with_iplist_files) で足す。`allowlist_path`
    /// が `Some` のときだけ、その file を poll ごとに監視して読み直す
    /// （`--allowlist` を渡さなかった従来の挙動と同じ）。
    pub fn new(
        blocklist: Blocklist,
        allowlist: Allowlist,
        allowlist_path: Option<PathBuf>,
        iplist: IpList,
        av: &'a AvList,
    ) -> Self {
        Self {
            blocklist: blocklist.clone(),
            blocklist_base: blocklist,
            blocklist_files: Vec::new(),
            allowlist_watcher: allowlist_path.map(ReloadWatcher::new),
            allowlist,
            iplist: iplist.clone(),
            iplist_base: iplist,
            iplist_files: Vec::new(),
            av,
            mitm: None,
            #[cfg(target_os = "linux")]
            defense: None,
        }
    }

    /// Adds stage 10; its files and the off file are polled from now on.
    #[cfg(target_os = "linux")]
    pub fn with_defense(mut self, defense: std::sync::Arc<crate::defense::Defense>) -> Self {
        self.defense = Some(defense);
        self
    }

    /// The running stage 10, if any.
    #[cfg(target_os = "linux")]
    pub(crate) fn defense(&self) -> Option<std::sync::Arc<crate::defense::Defense>> {
        self.defense.clone()
    }

    /// Adds the stage 8 `--mitm-list` read from `path` (watched from now on)
    /// and warns once per entry the allowlist covers.
    pub fn with_mitm_list(mut self, path: PathBuf, list: MitmList) -> Self {
        warn_mitm_allowlist_overlap(&list, &self.allowlist);
        self.mitm = Some(Watched {
            watcher: ReloadWatcher::new(path),
            list,
        });
        self
    }

    /// Stage 8: `host` is on the `--mitm-list` and not on the allowlist
    /// (`docs/design.md` "復号する範囲", items 3 and 4). Linux only, like
    /// decryption itself.
    #[cfg(target_os = "linux")]
    pub(crate) fn mitm_target(&self, host: &str) -> bool {
        self.mitm
            .as_ref()
            .is_some_and(|mitm| mitm.list.matches(host))
            && !self.allowlist.matches(host)
    }

    /// 読み込み済みの blocklist を、その path とともに足す（以後 poll ごとに
    /// path を監視する）。`Blocklist::load_all` の戻り値をそのまま渡せる。
    pub fn with_blocklist_files(mut self, files: Vec<(PathBuf, Blocklist)>) -> Self {
        self.blocklist_files = watch_files(files);
        self.rebuild_blocklist();
        self
    }

    /// [`with_blocklist_files`](Self::with_blocklist_files) の iplist 版。
    pub fn with_iplist_files(mut self, files: Vec<(PathBuf, IpList)>) -> Self {
        self.iplist_files = watch_files(files);
        self.rebuild_iplist();
        self
    }

    fn rebuild_blocklist(&mut self) {
        let parts = self.blocklist_files.iter().map(|file| &file.list);
        self.blocklist = Blocklist::union(std::iter::once(&self.blocklist_base).chain(parts));
    }

    fn rebuild_iplist(&mut self) {
        let parts = self.iplist_files.iter().map(|file| &file.list);
        self.iplist = IpList::union(std::iter::once(&self.iplist_base).chain(parts));
    }

    /// poll ごとに呼ぶ。変化が在れば読み直して `[info]`／`[warn]` を1行 出す。
    /// 変化が無ければ何もしない（`reload::apply` の契約。log が溢れない）。
    /// `pub(crate)`：`linux.rs::run_block` が nfqueue 本経路でも同じ読み直しを
    /// 使う（`docs/design.md`「走行中の読み直し」節）。
    pub(crate) fn poll_reloads(&mut self) {
        if reload_files(
            &mut self.blocklist_files,
            "blocklist",
            Blocklist::parse,
            Blocklist::len,
        ) {
            self.rebuild_blocklist();
        }
        let allowlist_replaced = match self.allowlist_watcher.as_mut() {
            Some(watcher) => reload::apply(
                watcher,
                &mut self.allowlist,
                "allowlist",
                Allowlist::parse,
                Allowlist::len,
            ),
            None => false,
        };
        if reload_files(&mut self.iplist_files, "iplist", IpList::parse, IpList::len) {
            self.rebuild_iplist();
        }
        if let Some(mitm) = self.mitm.as_mut() {
            let mitm_replaced = reload::apply(
                &mut mitm.watcher,
                &mut mitm.list,
                "mitm-list",
                MitmList::parse,
                MitmList::len,
            );
            if mitm_replaced || allowlist_replaced {
                warn_mitm_allowlist_overlap(&mitm.list, &self.allowlist);
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(defense) = &self.defense {
            defense.poll();
        }
    }

    /// 現在の値を指す [`JudgeConfig`] を組み立てる。`poll_reloads` の
    /// 呼び出し後に使うことで、直近の読み直し結果を反映した判定になる。
    /// `pub(crate)`：`linux.rs::run_block` が nfqueue 本経路でも使う。
    pub(crate) fn judge_config(&self) -> JudgeConfig<'_> {
        JudgeConfig {
            blocklist: &self.blocklist,
            iplist: &self.iplist,
            av: self.av,
            allowlist: &self.allowlist,
        }
    }
}

/// blocklist に当たった flow を [`TcpBlocker`] へ渡して切ろうとし、
/// 結果を `log` へ1 flow 1行で書く。呼び出し元（[`process_pcapng_snapshot`]
/// と [`flush_expired_flows`]）の両方が使う共通の判定・ログ処理。
///
/// **`decision` は実際に何が起きたかを書く。**SNI が blocklist に当たっても
/// 遮断（`try_block`）に失敗したら通信は続く（fail-open）ので `decision` は
/// `pass`、`reason` は `null` にする。`with_verdict`（`flow.rs`）の契約
/// （`decision` が `pass` のとき `reason` は常に `None`）と一致させる。
fn judge_and_log(
    key: FlowKey,
    sni_state: &SniState,
    config: &JudgeConfig,
    blocker: &mut dyn TcpBlocker,
    log: &FlowLogSink,
) -> Result<(), LogError> {
    // allowlist が blocklist / iplist / av のどれよりも先に効く
    // （`docs/design.md`「判定を差し込む口」。`judge::run_judges_with_allowlist`
    // と同じ判断だが、`judge_sni`（`windows.rs`）は Allowlist を知らないため、
    // ここで先頭に差し込む）。当たったことは `[debug]` の log に出す。
    let reason = match sni_state.sni() {
        Some(sni) if config.allowlist.matches(sni) => {
            crate::flow::service_log(&format!(
                "packetdeath: [debug] {}",
                crate::i18n::allowlist_passed(crate::i18n::locale(), sni)
            ));
            None
        }
        _ => judge_sni(
            config.blocklist,
            config.iplist,
            config.av,
            sni_state,
            key.dst_ip,
            key.dst_port,
        ),
    };
    if reason == Some(Reason::Av) {
        crate::av::log_match(config.av, &key.dst_ip, key.dst_port);
    }
    let (decision, reason_str) = match reason {
        Some(reason) => {
            let blocked = build_tcp_row_spec(&key)
                .map(|row| blocker.try_block(&row))
                .unwrap_or(false);
            if blocked {
                (DECISION_BLOCK, Some(reason.as_log_str()))
            } else {
                (DECISION_PASS, None)
            }
        }
        None => (DECISION_PASS, None),
    };

    let entry = FlowLogEntry::with_verdict(key, sni_state, decision, reason_str)?;
    log.write(&entry)
}

/// pcapng の1回分の snapshot（`data`）を処理する。`reassembler` へ TCP
/// payload を積み、SNI 判定が確定した（`Ok` / `None`、または `Reassembler`
/// が上限で諦めた `Fragmented`）flow だけを [`judge_and_log`] へ渡す。
/// `FrameOutcome::Pending`（まだ判定できない）flow は `processed` へ入れず、
/// log にも書かない。次の snapshot で同じ flow の後続 segment を処理できる
/// ようにするためである（`docs/design.md`「ClientHello の組み立て直し」節）。
///
/// タイムアウトで諦めた flow は、この関数ではなく [`flush_expired_flows`]
/// が扱う（file 更新が無い間も `poll_interval` ごとに払い出す必要があるため、
/// `run_watch_loop` が両方を呼ぶ）。
pub fn process_pcapng_snapshot(
    data: &[u8],
    config: &JudgeConfig,
    processed: &mut HashSet<FlowKey>,
    reassembler: &mut Reassembler,
    blocker: &mut dyn TcpBlocker,
    log: &FlowLogSink,
) -> Result<(), LogError> {
    let now = Instant::now();
    for frame in extract_pcapng_packets(data) {
        let Some((key, outcome)) = inspect_captured_frame(frame, reassembler, now) else {
            continue;
        };
        if processed.contains(&key) {
            continue;
        }
        let sni_state = match outcome {
            FrameOutcome::Pending => continue,
            FrameOutcome::Final(state) => state,
        };
        processed.insert(key);
        judge_and_log(key, &sni_state, config, blocker, log)?;
    }
    Ok(())
}

/// `reassembler` から寿命（`FLOW_TTL`）を超えた flow を払い出し、
/// `SniState::Fragmented` として1行 log に書く。ClientHello は接続の最初に
/// 来るので、これ以上 待つ意味が無い（`docs/design.md`「ClientHello の
/// 組み立て直し」節）。file 更新が無い poll でも呼ぶ必要があるため、
/// `process_pcapng_snapshot` とは独立に `run_watch_loop` から毎回 呼ぶ。
fn flush_expired_flows(
    reassembler: &mut Reassembler,
    processed: &mut HashSet<FlowKey>,
    config: &JudgeConfig,
    blocker: &mut dyn TcpBlocker,
    log: &FlowLogSink,
) {
    for key in reassembler.expire_stale(Instant::now()) {
        if !processed.insert(key) {
            continue;
        }
        if let Err(e) = judge_and_log(key, &SniState::Fragmented, config, blocker, log) {
            crate::flow::service_log(&format!(
                "packetdeath: [warn] {}",
                crate::i18n::flow_log_write_failed(crate::i18n::locale(), e)
            ));
        }
    }
}

/// `pcapng_path` を `poll_interval` ごとに監視し、変化があれば読み直して
/// [`process_pcapng_snapshot`] へ渡す。同じ poll の中で `inputs` の
/// blocklist / allowlist の変化も確かめ、変わっていれば読み直してから
/// 判定に使う。`stop_rx` に何か届くか、送信側が drop されたら
/// （`Disconnected`）戻る。
///
/// 🔴 **file が無い・壊れている・途中で消えても落ちない。**`metadata` /
/// `read` が `Err` を返した回は、その poll を skip して次回へ進む
/// （fail-open）。
pub fn run_watch_loop(
    pcapng_path: &Path,
    poll_interval: Duration,
    inputs: &mut WatchInputs,
    blocker: &mut dyn TcpBlocker,
    log: &FlowLogSink,
    stop_rx: &mpsc::Receiver<()>,
) {
    let mut processed: HashSet<FlowKey> = HashSet::new();
    let mut reassembler = Reassembler::new();
    let mut last_len: Option<u64> = None;

    loop {
        match stop_rx.recv_timeout(poll_interval) {
            Ok(()) => return,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }

        inputs.poll_reloads();
        let config = inputs.judge_config();

        // file が更新されない poll でも、寿命切れの flow は払い出す。
        flush_expired_flows(&mut reassembler, &mut processed, &config, blocker, log);

        let Ok(metadata) = std::fs::metadata(pcapng_path) else {
            continue;
        };
        let len = metadata.len();
        if last_len == Some(len) {
            continue;
        }
        last_len = Some(len);

        let Ok(data) = std::fs::read(pcapng_path) else {
            continue;
        };

        if let Err(e) = process_pcapng_snapshot(
            &data,
            &config,
            &mut processed,
            &mut reassembler,
            blocker,
            log,
        ) {
            crate::flow::service_log(&format!(
                "packetdeath: [warn] {}",
                crate::i18n::flow_log_write_failed(crate::i18n::locale(), e)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// `TcpBlocker::try_block` の呼び出しを記録するだけの test 用実装。
    #[derive(Default, Clone)]
    struct RecordingBlocker {
        calls: Arc<Mutex<Vec<TcpRowSpec>>>,
        /// `true` にすると常に遮断に失敗したことにする（PI-2 用）。
        always_fail: bool,
    }

    impl RecordingBlocker {
        fn call_count(&self) -> usize {
            // INVARIANT: 同じ thread からしか触らない test 用 mock なので
            // mutex が poison することはない。
            self.calls.lock().map(|v| v.len()).unwrap_or(0)
        }
    }

    impl TcpBlocker for RecordingBlocker {
        fn try_block(&mut self, row: &TcpRowSpec) -> bool {
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(*row);
            }
            !self.always_fail
        }
    }

    /// SNI を1つ持つ最小の TLS ClientHello を組み立てる。
    /// （`windows.rs` の test fixture と同じ形だが、window.rs の private
    /// helper は再利用せず、この module 内で完結させる。）
    fn build_client_hello(host: &[u8]) -> Vec<u8> {
        let mut sni_ext_data = Vec::new();
        let entry_len = 1 + 2 + host.len();
        sni_ext_data.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_ext_data.push(0x00);
        sni_ext_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_data);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let body_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// TCP payload を積んだ生 IPv4 frame（Ethernet header 無し）を組み立てる。
    /// `src`/`dst` を呼び出し側で変えられるようにし、複数 flow の test を
    /// 書けるようにする。
    fn build_ip_tcp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
        use etherparse::PacketBuilder;
        let builder = PacketBuilder::ipv4([192, 168, 1, 10], [172, 66, 147, 243], 64)
            .tcp(src_port, dst_port, 1, 64240);
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut frame, payload)
            .map_err(|e| e.to_string())?;
        Ok(frame)
    }

    /// Enhanced Packet Block を1つ組み立てる。
    fn build_enhanced_packet_block(packet: &[u8]) -> Vec<u8> {
        const BLOCK_TYPE_EPB: u32 = 0x0000_0006;
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        body.extend_from_slice(packet);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let total_len = (4 + 4 + body.len() + 4) as u32;
        let mut block = Vec::new();
        block.extend_from_slice(&BLOCK_TYPE_EPB.to_le_bytes());
        block.extend_from_slice(&total_len.to_le_bytes());
        block.extend_from_slice(&body);
        block.extend_from_slice(&total_len.to_le_bytes());
        block
    }

    /// `host` への ClientHello を1つ含む pcapng byte 列を組み立てる。
    fn build_pcapng_with_sni(src_port: u16, dst_port: u16, host: &[u8]) -> Result<Vec<u8>, String> {
        let client_hello = build_client_hello(host);
        let frame = build_ip_tcp_frame(src_port, dst_port, &client_hello)?;
        Ok(build_enhanced_packet_block(&frame))
    }

    fn temp_log_path(name: &str) -> Result<std::path::PathBuf, String> {
        let dir = std::env::temp_dir().join(format!(
            "packetdeath-block-loop-test-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(dir.join("flows.jsonl"))
    }

    #[test]
    fn pi0_negative_control_empty_blocklist_never_calls_try_block() -> Result<(), String> {
        let data = build_pcapng_with_sni(59012, 443, b"example.com")?;
        let blocklist = Blocklist::empty();
        let mut processed = HashSet::new();
        let mut reassembler = Reassembler::new();
        let mut blocker = RecordingBlocker::default();
        let log_path = temp_log_path("pi0")?;
        let log = FlowLogSink::open(&log_path).map_err(|e| e.to_string())?;

        process_pcapng_snapshot(
            &data,
            &JudgeConfig {
                blocklist: &blocklist,
                iplist: &IpList::empty(),
                av: &AvList::empty(),
                allowlist: &Allowlist::empty(),
            },
            &mut processed,
            &mut reassembler,
            &mut blocker,
            &log,
        )
        .map_err(|e| e.to_string())?;

        assert_eq!(blocker.call_count(), 0);
        Ok(())
    }

    #[test]
    fn pi1_blocklisted_sni_calls_try_block_once_and_logs_block() -> Result<(), String> {
        let data = build_pcapng_with_sni(59012, 443, b"ads.example")?;
        let blocklist = Blocklist::parse("ads.example\n");
        let mut processed = HashSet::new();
        let mut reassembler = Reassembler::new();
        let mut blocker = RecordingBlocker::default();
        let log_path = temp_log_path("pi1")?;
        let log = FlowLogSink::open(&log_path).map_err(|e| e.to_string())?;

        process_pcapng_snapshot(
            &data,
            &JudgeConfig {
                blocklist: &blocklist,
                iplist: &IpList::empty(),
                av: &AvList::empty(),
                allowlist: &Allowlist::empty(),
            },
            &mut processed,
            &mut reassembler,
            &mut blocker,
            &log,
        )
        .map_err(|e| e.to_string())?;

        assert_eq!(blocker.call_count(), 1);
        let content = std::fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
        assert!(content.contains("\"decision\":\"block\""));
        assert!(content.contains("\"reason\":\"sni\""));
        Ok(())
    }

    #[test]
    fn pi2_bridge_err_does_not_stop_processing_of_next_packet() -> Result<(), String> {
        // PsBridge が常に Err（ここでは try_block が常に false）を返す模擬でも、
        // 2つ目の flow（別 src_port）が processed へ積まれ、判定が続くこと。
        let blocklist = Blocklist::parse("ads.example\n");
        let mut processed = HashSet::new();
        let mut reassembler = Reassembler::new();
        let mut blocker = RecordingBlocker {
            always_fail: true,
            ..Default::default()
        };
        let log_path = temp_log_path("pi2")?;
        let log = FlowLogSink::open(&log_path).map_err(|e| e.to_string())?;

        let mut data = build_pcapng_with_sni(1111, 443, b"ads.example")?;
        data.extend(build_pcapng_with_sni(2222, 443, b"ads.example")?);

        process_pcapng_snapshot(
            &data,
            &JudgeConfig {
                blocklist: &blocklist,
                iplist: &IpList::empty(),
                av: &AvList::empty(),
                allowlist: &Allowlist::empty(),
            },
            &mut processed,
            &mut reassembler,
            &mut blocker,
            &log,
        )
        .map_err(|e| e.to_string())?;

        // 遮断は毎回 失敗するが、2 flow とも try_block まで到達している
        // （= loop が1つ目で止まっていない）。
        assert_eq!(blocker.call_count(), 2);
        let content = std::fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
        assert_eq!(content.lines().count(), 2);
        // 遮断に失敗したので decision は pass のまま（fail-open）。
        assert!(!content.contains("\"decision\":\"block\""));
        Ok(())
    }

    #[test]
    fn pi3_empty_bytes_does_not_panic_and_calls_nothing() -> Result<(), String> {
        let blocklist = Blocklist::parse("ads.example\n");
        let mut processed = HashSet::new();
        let mut reassembler = Reassembler::new();
        let mut blocker = RecordingBlocker::default();
        let log_path = temp_log_path("pi3-empty")?;
        let log = FlowLogSink::open(&log_path).map_err(|e| e.to_string())?;

        process_pcapng_snapshot(
            &[],
            &JudgeConfig {
                blocklist: &blocklist,
                iplist: &IpList::empty(),
                av: &AvList::empty(),
                allowlist: &Allowlist::empty(),
            },
            &mut processed,
            &mut reassembler,
            &mut blocker,
            &log,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(blocker.call_count(), 0);
        Ok(())
    }

    #[test]
    fn pi3_garbage_bytes_do_not_panic() -> Result<(), String> {
        let blocklist = Blocklist::parse("ads.example\n");
        let mut processed = HashSet::new();
        let mut reassembler = Reassembler::new();
        let mut blocker = RecordingBlocker::default();
        let log_path = temp_log_path("pi3-garbage")?;
        let log = FlowLogSink::open(&log_path).map_err(|e| e.to_string())?;

        let garbage = vec![0x41u8; 4096];
        process_pcapng_snapshot(
            &garbage,
            &JudgeConfig {
                blocklist: &blocklist,
                iplist: &IpList::empty(),
                av: &AvList::empty(),
                allowlist: &Allowlist::empty(),
            },
            &mut processed,
            &mut reassembler,
            &mut blocker,
            &log,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(blocker.call_count(), 0);
        Ok(())
    }

    #[test]
    fn pi3_missing_pcapng_file_falls_open_and_watch_loop_returns_on_stop() -> Result<(), String> {
        // file が最初から存在しない path を渡し、run_watch_loop が panic せず、
        // stop 通知で確実に戻ることを確かめる。
        let blocklist = Blocklist::empty();
        let av = AvList::empty();
        let allowlist = Allowlist::empty();
        let mut blocker = NoopBlocker;
        let log_path = temp_log_path("pi3-missing-file")?;
        let log = FlowLogSink::open(&log_path).map_err(|e| e.to_string())?;
        let missing_path = std::env::temp_dir().join("packetdeath-does-not-exist.pcapng");

        let (stop_tx, stop_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut inputs = WatchInputs::new(blocklist, allowlist, None, IpList::empty(), &av);
            run_watch_loop(
                &missing_path,
                Duration::from_millis(10),
                &mut inputs,
                &mut blocker,
                &log,
                &stop_rx,
            );
        });
        std::thread::sleep(Duration::from_millis(50));
        stop_tx.send(()).map_err(|e| e.to_string())?;
        handle
            .join()
            .map_err(|e| format!("run_watch_loop の thread が panic した: {e:?}"))?;
        Ok(())
    }

    #[test]
    fn pi4_same_bytes_processed_twice_calls_try_block_only_once() -> Result<(), String> {
        let data = build_pcapng_with_sni(59012, 443, b"ads.example")?;
        let blocklist = Blocklist::parse("ads.example\n");
        let mut processed = HashSet::new();
        let mut reassembler = Reassembler::new();
        let mut blocker = RecordingBlocker::default();
        let log_path = temp_log_path("pi4")?;
        let log = FlowLogSink::open(&log_path).map_err(|e| e.to_string())?;

        process_pcapng_snapshot(
            &data,
            &JudgeConfig {
                blocklist: &blocklist,
                iplist: &IpList::empty(),
                av: &AvList::empty(),
                allowlist: &Allowlist::empty(),
            },
            &mut processed,
            &mut reassembler,
            &mut blocker,
            &log,
        )
        .map_err(|e| e.to_string())?;
        // 同じ byte 列をもう一度 処理する（file を再読した想定）。
        process_pcapng_snapshot(
            &data,
            &JudgeConfig {
                blocklist: &blocklist,
                iplist: &IpList::empty(),
                av: &AvList::empty(),
                allowlist: &Allowlist::empty(),
            },
            &mut processed,
            &mut reassembler,
            &mut blocker,
            &log,
        )
        .map_err(|e| e.to_string())?;

        assert_eq!(blocker.call_count(), 1);
        let content = std::fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
        assert_eq!(content.lines().count(), 1);
        Ok(())
    }

    #[test]
    fn noop_blocker_always_returns_false() {
        let mut blocker = NoopBlocker;
        let row = TcpRowSpec {
            local_addr: 1,
            local_port: 2,
            remote_addr: 3,
            remote_port: 4,
        };
        assert!(!blocker.try_block(&row));
    }

    #[test]
    fn watch_inputs_without_path_never_reloads() {
        let av = AvList::empty();
        let mut inputs = WatchInputs::new(
            Blocklist::parse("ads.example\n"),
            Allowlist::empty(),
            None,
            IpList::empty(),
            &av,
        );
        inputs.poll_reloads();
        assert!(inputs.judge_config().blocklist.matches("ads.example"));
    }

    /// `dir` 配下の `name` に `content` を書き、その path を返す。
    fn write_list(dir: &Path, name: &str, content: &str) -> Result<PathBuf, String> {
        let path = dir.join(name);
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(path)
    }

    fn list_dir(name: &str) -> Result<PathBuf, String> {
        let flows_path = temp_log_path(name)?;
        Ok(flows_path
            .parent()
            .ok_or("親 directory が無い")?
            .to_path_buf())
    }

    #[test]
    fn watch_inputs_reloads_blocklist_when_file_changes() -> Result<(), String> {
        let dir = list_dir("watch-inputs-reload")?;
        let bl_path = write_list(&dir, "bl.txt", "old.example\n")?;
        let av = AvList::empty();
        let mut inputs = WatchInputs::new(
            Blocklist::empty(),
            Allowlist::empty(),
            None,
            IpList::empty(),
            &av,
        )
        .with_blocklist_files(Blocklist::load_all(std::slice::from_ref(&bl_path)));
        assert!(inputs.judge_config().blocklist.matches("old.example"));

        std::thread::sleep(Duration::from_millis(20));
        write_list(&dir, "bl.txt", "new.example\n")?;
        inputs.poll_reloads();

        assert!(inputs.judge_config().blocklist.matches("new.example"));
        assert!(!inputs.judge_config().blocklist.matches("old.example"));
        Ok(())
    }

    #[test]
    fn watch_inputs_unions_blocklists_and_a_change_keeps_the_other_file() -> Result<(), String> {
        let dir = list_dir("watch-inputs-union")?;
        let a = write_list(&dir, "union-a.txt", "a.example\n")?;
        let b = write_list(&dir, "union-b.txt", "b.example\n")?;
        let av = AvList::empty();
        let mut inputs = WatchInputs::new(
            Blocklist::parse("base.example\n"),
            Allowlist::empty(),
            None,
            IpList::empty(),
            &av,
        )
        .with_blocklist_files(Blocklist::load_all(&[a, b.clone()]));
        let jc = inputs.judge_config();
        assert!(jc.blocklist.matches("a.example") && jc.blocklist.matches("b.example"));
        assert!(jc.blocklist.matches("base.example"));

        std::thread::sleep(Duration::from_millis(20));
        write_list(&dir, "union-b.txt", "cc.example\n")?;
        inputs.poll_reloads();

        let jc = inputs.judge_config();
        assert!(jc.blocklist.matches("cc.example"));
        assert!(!jc.blocklist.matches("b.example"));
        assert!(
            jc.blocklist.matches("a.example"),
            "変えていない file が消えた"
        );
        assert!(jc.blocklist.matches("base.example"), "固定の中身が消えた");
        Ok(())
    }

    #[test]
    fn watch_inputs_reloads_iplist_and_keeps_previous_when_a_file_vanishes() -> Result<(), String> {
        let dir = list_dir("watch-inputs-iplist")?;
        let x = write_list(&dir, "ip-x.txt", "192.0.2.1\n")?;
        let y = write_list(&dir, "ip-y.txt", "192.0.2.2\n")?;
        let av = AvList::empty();
        let mut inputs = WatchInputs::new(
            Blocklist::empty(),
            Allowlist::empty(),
            None,
            IpList::empty(),
            &av,
        )
        .with_iplist_files(IpList::load_all(&[x.clone(), y.clone()]));
        let ip = |last: u8| std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last));
        assert!(inputs.judge_config().iplist.contains(&ip(2)));
        assert!(!inputs.judge_config().iplist.contains(&ip(3)));

        std::thread::sleep(Duration::from_millis(20));
        write_list(&dir, "ip-x.txt", "192.0.2.3\n# changed\n")?;
        std::fs::remove_file(&y).map_err(|e| e.to_string())?;
        inputs.poll_reloads();

        let jc = inputs.judge_config();
        assert!(jc.iplist.contains(&ip(3)), "書き換えが反映されていない");
        assert!(!jc.iplist.contains(&ip(1)));
        assert!(
            jc.iplist.contains(&ip(2)),
            "消えた file の前の内容が残っていない"
        );
        Ok(())
    }

    // ------------------------------------------------------------
    // Stage 8 `--mitm-list` (docs/design.md "段階8 MITM", test items).
    // ------------------------------------------------------------

    #[test]
    fn mitm_list_matches_exact_and_subdomains_case_insensitively() {
        let list = MitmList::parse("Example.ORG\n");
        assert!(list.matches("example.org"));
        assert!(list.matches("dl.EXAMPLE.org"));
        assert!(!list.matches("notexample.org"));
        assert!(!list.matches("example.com"));
    }

    #[test]
    fn mitm_list_drops_trailing_dots_on_both_sides() {
        let list = MitmList::parse("example.org.\n");
        assert!(list.matches("example.org"));
        assert!(list.matches("a.example.org."));
    }

    #[test]
    fn mitm_list_ignores_comments_and_blank_lines() {
        let list = MitmList::parse("# comment\n\n  # indented\nexample.org\n.\n");
        assert_eq!(list.len(), 1);
        assert!(!list.matches("# comment"));
    }

    #[test]
    fn mitm_list_never_matches_an_ip_literal() {
        let list = MitmList::parse("127.0.0.1\n1\n::1\n");
        assert!(!list.matches("127.0.0.1"));
        assert!(!list.matches("::1"));
    }

    #[test]
    fn empty_mitm_list_matches_nothing() {
        assert!(MitmList::empty().is_empty());
        assert!(!MitmList::empty().matches("example.org"));
    }

    #[test]
    fn overlap_names_each_allowlisted_entry() {
        let list = MitmList::parse("github.com\ndl.dropbox.com\ndownload.example\n");
        let allowlist = Allowlist::parse("github.com\ndropbox.com\n");
        assert_eq!(
            mitm_allowlist_overlap(&list, &allowlist),
            vec!["github.com", "dl.dropbox.com"]
        );
    }

    #[test]
    fn no_overlap_names_nothing() {
        let list = MitmList::parse("download.example\n");
        let allowlist = Allowlist::parse("github.com\n");
        assert!(mitm_allowlist_overlap(&list, &allowlist).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mitm_target_needs_the_list_and_not_the_allowlist() {
        let av = AvList::empty();
        let without = WatchInputs::new(
            Blocklist::empty(),
            Allowlist::empty(),
            None,
            IpList::empty(),
            &av,
        );
        assert!(!without.mitm_target("download.example"));

        let inputs = WatchInputs::new(
            Blocklist::empty(),
            Allowlist::parse("safe.example\n"),
            None,
            IpList::empty(),
            &av,
        )
        .with_mitm_list(
            PathBuf::from("/nonexistent/packetdeath-mitm.txt"),
            MitmList::parse("download.example\nsafe.example\n"),
        );
        assert!(inputs.mitm_target("download.example"));
        assert!(!inputs.mitm_target("safe.example"));
        assert!(!inputs.mitm_target("other.example"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn watch_inputs_reloads_the_mitm_list() -> Result<(), String> {
        let dir = list_dir("watch-inputs-mitm")?;
        let path = write_list(&dir, "mitm.txt", "")?;
        let av = AvList::empty();
        let mut inputs = WatchInputs::new(
            Blocklist::empty(),
            Allowlist::empty(),
            None,
            IpList::empty(),
            &av,
        )
        .with_mitm_list(path.clone(), MitmList::load(&path));
        assert!(!inputs.mitm_target("download.example"));

        std::thread::sleep(Duration::from_millis(20));
        write_list(&dir, "mitm.txt", "download.example\n")?;
        inputs.poll_reloads();
        assert!(inputs.mitm_target("download.example"));

        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        inputs.poll_reloads();
        assert!(
            inputs.mitm_target("download.example"),
            "a vanished file must keep the previous list"
        );
        Ok(())
    }

    #[test]
    fn respawning_bridge_falls_open_when_powershell_missing() {
        // この Linux 環境には powershell.exe が無いため、spawn_powershell は
        // 必ず失敗する。ensure_bridge が None を返し、try_block は false に
        // なることを確かめる（起動失敗時も panic せず fail-open）。
        let mut blocker = RespawningPsBridge::new(PathBuf::from("/nonexistent/kill_tcp.ps1"));
        let row = TcpRowSpec {
            local_addr: 1,
            local_port: 2,
            remote_addr: 3,
            remote_port: 4,
        };
        assert!(!blocker.try_block(&row));
    }

    /// Answers the first line after 700 ms (longer than the row limit), then
    /// every line at once with `rc=0`.
    #[cfg(unix)]
    fn slow_first_line_child(_: &Path) -> std::io::Result<PsBridge> {
        PsBridge::spawn(
            "sh",
            &[
                "-c",
                "read l; sleep 0.7; echo 'rc=317 us=1.0'; while read l; do echo 'rc=0 us=1.0'; done",
            ],
        )
    }

    /// Warms up and answers every row with a non-zero `rc`.
    #[cfg(unix)]
    fn rejecting_child(_: &Path) -> std::io::Result<PsBridge> {
        PsBridge::spawn(
            "sh",
            &[
                "-c",
                "read l; echo 'rc=317 us=1.0'; while read l; do echo 'rc=317 us=1.0'; done",
            ],
        )
    }

    /// Warms up with a non-zero `rc`, then answers every row with `rc=0`.
    #[cfg(unix)]
    fn cutting_child(_: &Path) -> std::io::Result<PsBridge> {
        PsBridge::spawn(
            "sh",
            &[
                "-c",
                "read l; echo 'rc=317 us=1.0'; while read l; do echo 'rc=0 us=1.0'; done",
            ],
        )
    }

    /// Never answers.
    #[cfg(unix)]
    fn hanging_child(_: &Path) -> std::io::Result<PsBridge> {
        PsBridge::spawn("sleep", &["30"])
    }

    #[cfg(unix)]
    fn any_row() -> TcpRowSpec {
        TcpRowSpec {
            local_addr: 1,
            local_port: 2,
            remote_addr: 3,
            remote_port: 4,
        }
    }

    #[cfg(unix)]
    #[test]
    fn respawning_bridge_warms_a_slow_child_before_the_first_row() {
        let mut blocker = RespawningPsBridge::with_spawner(
            PathBuf::from("unused"),
            slow_first_line_child,
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        assert!(blocker.try_block(&any_row()));
    }

    #[cfg(unix)]
    #[test]
    fn a_nonzero_rc_is_not_a_cut() -> Result<(), String> {
        let mut blocker = RespawningPsBridge::with_spawner(
            PathBuf::from("unused"),
            rejecting_child,
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        assert!(!blocker.try_block(&any_row()));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_zero_rc_is_a_cut() -> Result<(), String> {
        let mut blocker = RespawningPsBridge::with_spawner(
            PathBuf::from("unused"),
            cutting_child,
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        assert!(blocker.try_block(&any_row()));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn respawning_bridge_waits_before_respawning_after_a_failed_warm_up() {
        let mut blocker = RespawningPsBridge::with_spawner(
            PathBuf::from("unused"),
            hanging_child,
            Duration::from_millis(200),
            Duration::from_secs(2),
        );
        let row = any_row();

        let started = Instant::now();
        assert!(!blocker.try_block(&row));
        let first = started.elapsed();
        assert!(first >= Duration::from_millis(150), "first took {first:?}");

        let started = Instant::now();
        assert!(!blocker.try_block(&row));
        let second = started.elapsed();
        assert!(
            second < Duration::from_millis(50),
            "second took {second:?}; it spawned inside the backoff"
        );

        std::thread::sleep(Duration::from_millis(2100));

        let started = Instant::now();
        assert!(!blocker.try_block(&row));
        let third = started.elapsed();
        assert!(
            third >= Duration::from_millis(150),
            "third took {third:?}; it did not spawn after the backoff"
        );
    }
}
