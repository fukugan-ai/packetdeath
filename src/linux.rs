//! Linux（nfqueue）から生 IP packet を受け取り、TLS ClientHello の SNI を観測・
//! 判定する。
//!
//! 🔴 **`--queue-bypass` 相当を必ず有効にする。**付けないと packetdeath が死んだとき
//! 通信が全部 止まる（`docs/design.md`「fail-open」節）。`nfq::Queue::set_fail_open`
//! がそれに当たる。iptables の rule 自体は利用者が打つ（packetdeath は rule を
//! 足さない。`docs/design.md`「名前と置き場」）。
//!
//! `run`（段階1・観測のみ）は受け取った packet を必ず `Verdict::Accept` で通す。
//! `run_block`（段階2・3）は `Judge` の判定結果に従って `Accept` / `Drop` する。
//!
//! # 複数 TCP segment に割れた ClientHello の組み立て直し
//!
//! `crate::reassemble::Reassembler` を `run` と `run_block` の両方へ配線する。
//! TCP payload は seq 番号ごと `Reassembler::feed` に積み、
//! `FrameOutcome::Pending`（まだ判定できない）の間は `Verdict::Accept`
//! （fail-open）で通し続け、`Final` になった時点で1 flow 1行 log に書く。
//! 寿命（`Reassembler` 内部の `FLOW_TTL`）を超えた flow は `expire_stale` が
//! `Fragmented` として払い出す。`recv` はブロックする呼び出しなので、
//! `EXPIRE_CHECK_INTERVAL` ごとの確認は「次の packet を受けたとき」にしか
//! 起きないが、判定できていない間は `Accept` のままなので実害は無い
//! （`docs/design.md`「ClientHello の組み立て直し」節）。UDP（QUIC 等）は
//! 中身を見ず `SniState::None` のまま確定する。
//!
//! # allowlist と走行中の読み直し（`run_block` のみ）
//!
//! `run_block` は `block_loop::WatchInputs` を `&mut` で受け取り、
//! `RELOAD_POLL_INTERVAL` ごとに `poll_reloads` を呼んで blocklist /
//! allowlist を読み直す。判定は `judge::run_judges_with_allowlist` を使い、
//! allowlist が blocklist・CNAME・IDS・IP・av のどれよりも先に効く
//! （`docs/design.md`「判定を差し込む口」）。`SniJudge` は poll の直後に、
//! 読み直した最新の blocklist から組み直す。

use crate::allowlist::Allowlist;
use crate::av::AvList;
use crate::block_loop::WatchInputs;
use crate::blocklist::Blocklist;
use crate::dns::{parse_dns_response, DnsAnswer, DnsLogEntry, DnsLogSink};
use crate::flow::{FlowKey, FlowLogEntry, FlowLogSink, Proto, DECISION_BLOCK, DECISION_PASS};
use crate::ids::IdsDropSet;
use crate::judge::{
    run_judges_with_allowlist, AvJudge, CnameJudge, IdsJudge, IpJudge, JudgeInput, Reason, SniJudge,
};
use crate::reassemble::{FrameOutcome, Reassembler};
use crate::sni::SniState;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use nfq::{Queue, Verdict};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const DNS_SOURCE_PORT: u16 = 53;

/// blocklist / allowlist の走行中 読み直しを確かめる間隔。
/// `win_service::PCAPNG_POLL_INTERVAL`（300 ms）と同じ値を、Linux の
/// nfqueue 本経路でも踏襲する（`docs/design.md`「走行中の読み直し」節）。
const RELOAD_POLL_INTERVAL: Duration = Duration::from_millis(300);

/// `Reassembler::expire_stale` を確かめる間隔。ClientHello は接続の最初に
/// 来るので、これより高頻度で確かめる意味は無い
/// （`docs/design.md`「ClientHello の組み立て直し」節）。
const EXPIRE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// How long a flow may stay silent (no packet with a payload) before
/// `FlowSet::sweep` forgets it. Longer than the reassembler's `FLOW_TTL`
/// and than the Linux data retransmission interval cap (RTO, 120 s), shorter
/// than the default TCP keepalive (7200 s).
const FLOW_SET_IDLE_TTL: Duration = Duration::from_secs(600);

/// A set of flows that forgets a flow once it has been idle for a TTL.
/// The only lookup is `touch`, which refreshes the last-seen time, so a
/// caller cannot test membership without also keeping the flow alive.
struct FlowSet {
    last_seen: HashMap<FlowKey, Instant>,
}

impl FlowSet {
    fn new() -> Self {
        Self {
            last_seen: HashMap::new(),
        }
    }

    /// Records `key` as seen at `now`. Returns true only if it was absent.
    fn insert(&mut self, key: FlowKey, now: Instant) -> bool {
        self.last_seen.insert(key, now).is_none()
    }

    /// Refreshes `key`'s last-seen time. Returns false if it is absent.
    fn touch(&mut self, key: &FlowKey, now: Instant) -> bool {
        match self.last_seen.get_mut(key) {
            Some(last) => {
                *last = now;
                true
            }
            None => false,
        }
    }

    /// Drops flows idle for more than `ttl`. Returns how many were dropped.
    fn sweep(&mut self, now: Instant, ttl: Duration) -> usize {
        let before = self.last_seen.len();
        self.last_seen
            .retain(|_, last| now.saturating_duration_since(*last) <= ttl);
        before - self.last_seen.len()
    }
}

/// Emits one `[debug]` line when a sweep dropped at least one flow.
fn log_idle_flows_dropped(removed: usize) {
    if removed > 0 {
        eprintln!(
            "packetdeath: [debug] {}",
            crate::i18n::flow_set_swept(crate::i18n::locale(), removed)
        );
    }
}

#[derive(Debug)]
pub enum LinuxQueueError {
    Open(std::io::Error),
    Bind(std::io::Error),
    FailOpen(std::io::Error),
    Recv(std::io::Error),
    Verdict(std::io::Error),
    Log(crate::flow::LogError),
}

impl fmt::Display for LinuxQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let locale = crate::i18n::locale();
        let s = match self {
            Self::Open(e) => crate::i18n::nfqueue_open_failed(locale, e),
            Self::Bind(e) => crate::i18n::nfqueue_bind_failed(locale, e),
            Self::FailOpen(e) => crate::i18n::nfqueue_fail_open_setting_failed(locale, e),
            Self::Recv(e) => crate::i18n::nfqueue_recv_failed(locale, e),
            Self::Verdict(e) => crate::i18n::nfqueue_verdict_send_failed(locale, e),
            Self::Log(e) => crate::i18n::flow_log_write_failed(locale, e),
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for LinuxQueueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(e)
            | Self::Bind(e)
            | Self::FailOpen(e)
            | Self::Recv(e)
            | Self::Verdict(e) => Some(e),
            Self::Log(e) => Some(e),
        }
    }
}

/// 1 packet を覗いた結果。`inspect_ip_packet` が返す。
enum PacketKind<'a> {
    /// TCP payload（DNS 応答を除く）。`seq` は TCP の sequence number で、
    /// 呼び出し側がそのまま `Reassembler::feed` へ渡し、複数 segment に
    /// 割れた ClientHello を組み立て直す。
    Tcp {
        key: FlowKey,
        seq: u32,
        payload: &'a [u8],
    },
    /// UDP flow（QUIC 等）。中身を見ず `SniState::None` で確定する
    /// （`docs/design.md`「QUIC」節）。
    Udp { key: FlowKey },
    /// UDP src_port 53 の応答 payload（段階3の DNS 解析対象）。
    DnsResponse { payload: &'a [u8] },
}

/// 生 IP packet（Ethernet header 無し）を覗き、`PacketKind` に分類する。
///
/// - IP/TCP/UDP header が壊れている packet → `None`（＝ log すべき flow ではない）
/// - payload を持たない packet（SYN/ACK のみ等）→ `None`
/// - UDP src_port 53 → `DnsResponse`（中身の応答かどうかは呼び出し側が
///   `parse_dns_response` で確かめる。ここでは port だけで振り分ける）
/// - TCP → `Tcp`（seq と生 payload をそのまま返す。組み立て直しは呼び出し側の
///   `Reassembler` が行う）
/// - UDP（DNS 応答を除く）→ `Udp`
fn inspect_ip_packet(data: &[u8]) -> Option<PacketKind<'_>> {
    let sliced = SlicedPacket::from_ip(data).ok()?;

    let (src_ip, dst_ip): (IpAddr, IpAddr) = match sliced.net? {
        NetSlice::Ipv4(v4) => (
            v4.header().source_addr().into(),
            v4.header().destination_addr().into(),
        ),
        NetSlice::Ipv6(v6) => (
            v6.header().source_addr().into(),
            v6.header().destination_addr().into(),
        ),
        // nfqueue の L3 queue には ARP は載らない。念のため flow 対象外として扱う。
        NetSlice::Arp(_) => return None,
    };

    match sliced.transport? {
        TransportSlice::Tcp(tcp) => {
            let payload = tcp.payload();
            if payload.is_empty() {
                return None;
            }
            let key = FlowKey {
                proto: Proto::Tcp,
                src_ip,
                src_port: tcp.source_port(),
                dst_ip,
                dst_port: tcp.destination_port(),
            };
            Some(PacketKind::Tcp {
                key,
                seq: tcp.sequence_number(),
                payload,
            })
        }
        TransportSlice::Udp(udp) => {
            let payload = udp.payload();
            if payload.is_empty() {
                return None;
            }
            if udp.source_port() == DNS_SOURCE_PORT {
                return Some(PacketKind::DnsResponse { payload });
            }
            let key = FlowKey {
                proto: Proto::Udp,
                src_ip,
                src_port: udp.source_port(),
                dst_ip,
                dst_port: udp.destination_port(),
            };
            Some(PacketKind::Udp { key })
        }
        _ => None,
    }
}

/// `key` を1 flow 1行 の観測 log（`decision` は常に `observe`）として書く。
fn log_observed_flow(
    key: FlowKey,
    sni_state: &SniState,
    log: &FlowLogSink,
) -> Result<(), LinuxQueueError> {
    let entry = FlowLogEntry::new(key, sni_state)
        .map_err(|e| LinuxQueueError::Log(crate::flow::LogError::from(e)))?;
    log.write(&entry).map_err(LinuxQueueError::Log)
}

/// `key` の寿命切れを `[debug]` へ出す（`docs/design.md`「ClientHello の
/// 組み立て直し」節。`Reassembler::expire_stale` が払い出した flow だけが通る）。
fn log_reassembly_expired(key: FlowKey) {
    eprintln!(
        "packetdeath: [debug] {}",
        crate::i18n::reassemble_flow_expired(crate::i18n::locale(), key.dst_ip, key.dst_port)
    );
}

/// nfqueue の `queue_num` を bind し、受信した packet を素通しで転送しながら
/// 未 log の flow だけ1行 log へ出す。**遮断は0件。** 呼び出し元が止めるまで戻らない。
pub fn run(queue_num: u16, log: &FlowLogSink) -> Result<(), LinuxQueueError> {
    let mut queue = Queue::open().map_err(LinuxQueueError::Open)?;
    queue.bind(queue_num).map_err(LinuxQueueError::Bind)?;
    // INVARIANT: ここで必ず fail-open を有効にする。失敗したまま起動を続けると
    // packetdeath が落ちたときに通信が全部 止まる事故になるため、bind 直後に確定させる。
    queue
        .set_fail_open(queue_num, true)
        .map_err(LinuxQueueError::FailOpen)?;
    eprintln!(
        "packetdeath: [info] {}",
        crate::i18n::nfqueue_bound_observe(crate::i18n::locale(), queue_num)
    );

    let mut seen = FlowSet::new();
    let mut reassembler = Reassembler::new();
    let mut last_expire_check = Instant::now();

    loop {
        let mut msg = queue.recv().map_err(LinuxQueueError::Recv)?;
        let now = Instant::now();

        if now.duration_since(last_expire_check) >= EXPIRE_CHECK_INTERVAL {
            last_expire_check = now;
            for key in reassembler.expire_stale(now) {
                if seen.insert(key, now) {
                    log_reassembly_expired(key);
                    log_observed_flow(key, &SniState::Fragmented, log)?;
                }
            }
            log_idle_flows_dropped(seen.sweep(now, FLOW_SET_IDLE_TTL));
        }

        match inspect_ip_packet(msg.get_payload()) {
            Some(PacketKind::Tcp { key, seq, payload }) => {
                if !seen.touch(&key, now) {
                    if let FrameOutcome::Final(sni_state) = reassembler.feed(key, seq, payload, now)
                    {
                        seen.insert(key, now);
                        log_observed_flow(key, &sni_state, log)?;
                    }
                }
            }
            Some(PacketKind::Udp { key }) => {
                if seen.insert(key, now) {
                    log_observed_flow(key, &SniState::None, log)?;
                }
            }
            Some(PacketKind::DnsResponse { .. }) | None => {}
        }

        // 段階1は観測のみ。全部 素通しする（DNS 応答も含む）。
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg).map_err(LinuxQueueError::Verdict)?;
    }
}

/// `packetdeath block` の設定のうち、走行中に読み直さない
/// 判定材料だけを持つ。blocklist / allowlist / iplist は `WatchInputs` が
/// 所有し、`run_block` が poll のたびに読み直した最新値を使う
/// （`docs/design.md`「走行中の読み直し」節）。
pub struct BlockConfig<'a> {
    /// `--dns` が指定されたときだけ `Some`。`None` のときは DNS 応答を一切
    /// 解析・記録しない（PK-20 の陰性対照）。
    pub dns_log: Option<&'a DnsLogSink>,
    /// 段階4：`--eve` の alert が `--ips-sids` に当たった drop 集合。
    /// `--eve` 未指定なら呼び出し側が空の `IdsDropSet::new()` を渡す
    /// （PK-30 の陰性対照。「この file に無い sid では落とさない」）。
    pub ids_drop_set: &'a IdsDropSet,
    /// 段階6：`--av` 未指定なら `AvList::empty()`（PK-60 の陰性対照）。
    pub av: &'a AvList,
}

/// allowlist を先頭に判定し、1 flow 1行 log に書く。`Some(Reason)` が返れば
/// 呼び出し側は `blocked` へ積んで以後 Drop する
/// （`docs/design.md`「判定を差し込む口」。nfqueue の `Verdict::Drop` で
/// 直接 落とすので、`block_loop::judge_and_log` と違い遮断の成否は問わない）。
fn judge_and_log(
    key: FlowKey,
    sni_state: &SniState,
    judges: &[&dyn crate::judge::Judge],
    allowlist: &Allowlist,
    av: &AvList,
    cname_matched_qnames: &HashSet<String>,
    log: &FlowLogSink,
) -> Result<Option<Reason>, LinuxQueueError> {
    let input = JudgeInput {
        sni_state,
        cname_matched_qnames,
        dst_ip: key.dst_ip,
        dst_port: key.dst_port,
    };
    let reason = run_judges_with_allowlist(allowlist, judges, &input);
    if reason == Some(Reason::Av) {
        crate::av::log_match(av, &key.dst_ip, key.dst_port);
    }
    let (decision, reason_str) = match reason {
        Some(r) => (DECISION_BLOCK, Some(r.as_log_str())),
        None => (DECISION_PASS, None),
    };
    let entry = FlowLogEntry::with_verdict(key, sni_state, decision, reason_str)
        .map_err(|e| LinuxQueueError::Log(crate::flow::LogError::from(e)))?;
    log.write(&entry).map_err(LinuxQueueError::Log)?;
    Ok(reason)
}

/// nfqueue の `queue_num` を bind し、`config` / `inputs` の判定に従って
/// packet を Accept / Drop する。段階2「遮断」・段階3「CNAME チェーン解決」の
/// 実行 loop。呼び出し元が止めるまで戻らない。
///
/// `inputs` は `RELOAD_POLL_INTERVAL` ごとに読み直す（`poll_reloads`）。
/// `SniJudge` は読み直しの直後に、最新の blocklist から組み直す。
pub fn run_block(
    queue_num: u16,
    log: &FlowLogSink,
    config: &BlockConfig,
    inputs: &mut WatchInputs,
) -> Result<(), LinuxQueueError> {
    let mut queue = Queue::open().map_err(LinuxQueueError::Open)?;
    queue.bind(queue_num).map_err(LinuxQueueError::Bind)?;
    // INVARIANT: ここで必ず fail-open を有効にする（段階1 と同じ理由）。
    queue
        .set_fail_open(queue_num, true)
        .map_err(LinuxQueueError::FailOpen)?;
    eprintln!(
        "packetdeath: [info] {}",
        crate::i18n::nfqueue_bound_block(crate::i18n::locale(), queue_num)
    );

    // 1 flow 1行の重複排除（段階1と同じ）。
    let mut seen = FlowSet::new();
    // 一度 block と判定した flow は、後続 packet も無条件で Drop する。
    let mut blocked = FlowSet::new();
    // 段階3：CNAME チェーンが blocklist に当たった qname（小文字化）の集合。
    let mut cname_matched_qnames: HashSet<String> = HashSet::new();
    let mut reassembler = Reassembler::new();
    let mut last_reload_poll = Instant::now();
    let mut last_expire_check = Instant::now();

    // blocklist を除く判定器は poll で変わらないので loop の外で1回だけ作る
    // （`docs/design.md`「判定を差し込む口」節。段階の番号順 sni=2, cname=3,
    // ids=4, iplist=5, av=6 に並べる。`SniJudge` だけが poll のたびに
    // 組み直る対象）。
    let cname_judge = CnameJudge;
    let ids_judge = IdsJudge {
        drop_set: config.ids_drop_set,
    };
    let av_judge = AvJudge { av: config.av };

    loop {
        let mut msg = queue.recv().map_err(LinuxQueueError::Recv)?;
        let now = Instant::now();

        if now.duration_since(last_reload_poll) >= RELOAD_POLL_INTERVAL {
            last_reload_poll = now;
            inputs.poll_reloads();
        }

        // `judge_config` は借用を組み立てるだけで I/O をしないので、recv
        // ごとに呼んでも安い。allowlist / blocklist は poll_reloads が
        // 読み直した最新値になっている。
        let jc = inputs.judge_config();
        let sni_judge = SniJudge {
            blocklist: jc.blocklist,
        };
        // iplist も blocklist と同じく poll_reloads が差し替えるので、
        // 判定器は recv ごとに最新の値から組む。
        let ip_judge = IpJudge { iplist: jc.iplist };
        let judges: [&dyn crate::judge::Judge; 5] =
            [&sni_judge, &cname_judge, &ids_judge, &ip_judge, &av_judge];

        if now.duration_since(last_expire_check) >= EXPIRE_CHECK_INTERVAL {
            last_expire_check = now;
            for key in reassembler.expire_stale(now) {
                if !seen.insert(key, now) {
                    continue;
                }
                log_reassembly_expired(key);
                let reason = judge_and_log(
                    key,
                    &SniState::Fragmented,
                    &judges,
                    jc.allowlist,
                    config.av,
                    &cname_matched_qnames,
                    log,
                )?;
                if reason.is_some() {
                    blocked.insert(key, now);
                }
            }
            let mut dropped = seen.sweep(now, FLOW_SET_IDLE_TTL);
            dropped += blocked.sweep(now, FLOW_SET_IDLE_TTL);
            log_idle_flows_dropped(dropped);
        }

        let verdict = match inspect_ip_packet(msg.get_payload()) {
            Some(PacketKind::DnsResponse { payload }) => {
                if let Some(dns_log) = config.dns_log {
                    handle_dns_response(payload, jc.blocklist, dns_log, &mut cname_matched_qnames)
                        .map_err(LinuxQueueError::Log)?;
                }
                // DNS 応答自体は判定対象ではない。常に通す。
                Verdict::Accept
            }
            Some(PacketKind::Udp { key }) => {
                if blocked.touch(&key, now) {
                    Verdict::Drop
                } else if seen.insert(key, now) {
                    let reason = judge_and_log(
                        key,
                        &SniState::None,
                        &judges,
                        jc.allowlist,
                        config.av,
                        &cname_matched_qnames,
                        log,
                    )?;
                    if reason.is_some() {
                        blocked.insert(key, now);
                        Verdict::Drop
                    } else {
                        Verdict::Accept
                    }
                } else {
                    // 既に pass と log 済みの flow の後続 packet。素通しのまま。
                    Verdict::Accept
                }
            }
            Some(PacketKind::Tcp { key, seq, payload }) => {
                if blocked.touch(&key, now) {
                    Verdict::Drop
                } else if seen.touch(&key, now) {
                    // 既に判定済みの flow の後続 segment。組み立て直しは
                    // 不要（`Reassembler` は Final になった時点で自分の
                    // bookkeeping を消している）。
                    Verdict::Accept
                } else {
                    match reassembler.feed(key, seq, payload, now) {
                        // まだ判定できない。fail-open で通す。
                        FrameOutcome::Pending => Verdict::Accept,
                        FrameOutcome::Final(sni_state) => {
                            seen.insert(key, now);
                            let reason = judge_and_log(
                                key,
                                &sni_state,
                                &judges,
                                jc.allowlist,
                                config.av,
                                &cname_matched_qnames,
                                log,
                            )?;
                            if reason.is_some() {
                                blocked.insert(key, now);
                                Verdict::Drop
                            } else {
                                Verdict::Accept
                            }
                        }
                    }
                }
            }
            None => Verdict::Accept,
        };

        msg.set_verdict(verdict);
        queue.verdict(msg).map_err(LinuxQueueError::Verdict)?;
    }
}

/// DNS 応答 payload を parse し、`dns.jsonl` へ1行 書く。parse に失敗した
/// payload（DNS 応答以外・壊れた byte 列）は記録せずに無視する
/// （fail-open。攻撃者が作れる byte 列で panic も停止もしない）。
fn handle_dns_response(
    payload: &[u8],
    blocklist: &Blocklist,
    dns_log: &DnsLogSink,
    cname_matched_qnames: &mut HashSet<String>,
) -> Result<(), crate::flow::LogError> {
    let Ok(answer) = parse_dns_response(payload) else {
        return Ok(());
    };
    let matched = find_blocklist_match(&answer, blocklist);
    if matched.is_some() {
        cname_matched_qnames.insert(answer.qname.to_ascii_lowercase());
    }
    let entry = DnsLogEntry::new(answer, matched).map_err(crate::flow::LogError::from)?;
    dns_log.write(&entry)
}

/// CNAME チェーンのうち、blocklist に最初に当たった要素を返す。
fn find_blocklist_match(answer: &DnsAnswer, blocklist: &Blocklist) -> Option<String> {
    answer
        .chain
        .iter()
        .find(|host| blocklist.matches(host))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ip_tcp_frame(seq: u32, payload: &[u8]) -> Result<Vec<u8>, String> {
        use etherparse::PacketBuilder;
        let builder = PacketBuilder::ipv4([192, 168, 1, 10], [172, 66, 147, 243], 64)
            .tcp(59012, 443, seq, 64240);
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut frame, payload)
            .map_err(|e| e.to_string())?;
        Ok(frame)
    }

    /// SNI を1つ持つ最小の TLS ClientHello を組み立てる
    /// （`reassemble.rs` の test fixture と同じ形）。
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

    fn loopback_flow_key() -> FlowKey {
        FlowKey {
            proto: Proto::Tcp,
            src_ip: IpAddr::from([127, 0, 0, 1]),
            src_port: 40000,
            dst_ip: IpAddr::from([127, 0, 0, 1]),
            dst_port: 443,
        }
    }

    #[test]
    fn idle_flows_leave_the_set_after_the_ttl() {
        let ttl = FLOW_SET_IDLE_TTL;
        let one_second = Duration::from_secs(1);
        let key = loopback_flow_key();
        let t0 = Instant::now();
        let mut set = FlowSet::new();
        assert!(set.insert(key, t0));
        assert!(!set.insert(key, t0));
        assert_eq!(set.sweep(t0 + ttl - one_second, ttl), 0);
        assert!(set.touch(&key, t0 + ttl - one_second));
        assert_eq!(set.sweep(t0 + 2 * ttl, ttl), 1);
        assert!(!set.touch(&key, t0 + 2 * ttl));
    }

    #[test]
    fn a_touched_flow_survives_the_sweep() {
        let ttl = FLOW_SET_IDLE_TTL;
        let one_second = Duration::from_secs(1);
        let key = loopback_flow_key();
        let t0 = Instant::now();
        let mut set = FlowSet::new();
        assert!(set.insert(key, t0));
        assert!(set.touch(&key, t0 + ttl / 2));
        assert_eq!(set.sweep(t0 + ttl + one_second, ttl), 0);
        assert!(set.touch(&key, t0 + ttl + one_second));
        assert_eq!(set.sweep(t0 + 2 * ttl + 2 * one_second, ttl), 1);
    }

    #[test]
    fn inspect_ip_packet_returns_tcp_sequence_number_and_payload() -> Result<(), String> {
        let frame = build_ip_tcp_frame(123456, b"hello")?;
        let Some(PacketKind::Tcp { seq, payload, .. }) = inspect_ip_packet(&frame) else {
            return Err("PacketKind::Tcp を期待した".to_string());
        };
        assert_eq!(seq, 123456);
        assert_eq!(payload, b"hello");
        Ok(())
    }

    #[test]
    fn inspect_ip_packet_classifies_udp_as_flow_and_dns_as_response() -> Result<(), String> {
        use etherparse::PacketBuilder;

        let udp_builder =
            PacketBuilder::ipv4([192, 168, 1, 10], [172, 66, 147, 243], 64).udp(51000, 443);
        let mut udp_frame = Vec::with_capacity(udp_builder.size(4));
        udp_builder
            .write(&mut udp_frame, &[1, 2, 3, 4])
            .map_err(|e| e.to_string())?;
        let Some(PacketKind::Udp { key }) = inspect_ip_packet(&udp_frame) else {
            return Err("PacketKind::Udp を期待した".to_string());
        };
        assert_eq!(key.dst_port, 443);

        let dns_builder =
            PacketBuilder::ipv4([172, 66, 147, 243], [192, 168, 1, 10], 64).udp(53, 51000);
        let mut dns_frame = Vec::with_capacity(dns_builder.size(4));
        dns_builder
            .write(&mut dns_frame, &[1, 2, 3, 4])
            .map_err(|e| e.to_string())?;
        let Some(PacketKind::DnsResponse { payload }) = inspect_ip_packet(&dns_frame) else {
            return Err("PacketKind::DnsResponse を期待した".to_string());
        };
        assert_eq!(payload, &[1, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn two_segments_inspected_from_raw_frames_reassemble_into_sni() -> Result<(), String> {
        // `inspect_ip_packet` が返した (key, seq, payload) を、そのまま
        // `Reassembler::feed` へ渡す実際の配線を確かめる。
        let hello = build_client_hello(b"example.com");
        let mid = hello.len() / 2;
        let (first, second) = hello.split_at(mid);

        let frame1 = build_ip_tcp_frame(1000, first)?;
        let Some(PacketKind::Tcp {
            key: key1,
            seq: seq1,
            payload: payload1,
        }) = inspect_ip_packet(&frame1)
        else {
            return Err("1つ目の frame が Tcp と判定されなかった".to_string());
        };

        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        assert_eq!(
            reassembler.feed(key1, seq1, payload1, now),
            FrameOutcome::Pending
        );

        let frame2 = build_ip_tcp_frame(1000 + first.len() as u32, second)?;
        let Some(PacketKind::Tcp {
            key: key2,
            seq: seq2,
            payload: payload2,
        }) = inspect_ip_packet(&frame2)
        else {
            return Err("2つ目の frame が Tcp と判定されなかった".to_string());
        };
        assert_eq!(key1, key2);
        assert_eq!(
            reassembler.feed(key2, seq2, payload2, now),
            FrameOutcome::Final(SniState::Ok("example.com".to_string()))
        );
        Ok(())
    }
}
