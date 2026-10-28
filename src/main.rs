#![forbid(unsafe_code)]

use packetdeath::allowlist::Allowlist;
use packetdeath::av::AvList;
#[cfg(not(target_os = "linux"))]
use packetdeath::block_loop::RespawningPsBridge;
use packetdeath::block_loop::{NoopBlocker, TcpBlocker, WatchInputs};
use packetdeath::blocklist::Blocklist;
#[cfg(target_os = "linux")]
use packetdeath::dns::DnsLogSink;
use packetdeath::flow::FlowLogSink;
#[cfg(target_os = "linux")]
use packetdeath::ids::{IdsDropSet, IpsRule};
use packetdeath::iplist::IpList;
use packetdeath::proxy::{AllowFrom, DenyMode};
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// `docs/design.md`「名前と置き場」の既定 NFQUEUE 番号。
const DEFAULT_QUEUE_NUM: u16 = 1808;

/// `docs/design.md`「採る方式」節：`--ips-ttl` の既定値（秒）。
const DEFAULT_IPS_TTL_SECS: u64 = 300;

/// `--pcapng` 使用時の poll 間隔の既定値（ミリ秒）。
const DEFAULT_POLL_MS: u64 = 1000;

/// `eve.json` を tail する poll 間隔。Suricata の追記から drop 集合への反映
/// までの遅延の上限になる。PK-31 の `sleep 2` に対して十分 短い。
#[cfg(target_os = "linux")]
const EVE_POLL_INTERVAL: Duration = Duration::from_millis(200);

struct ObserveArgs {
    queue_num: u16,
    /// `docs/design.md`「名前と置き場」：`--filter` は Windows だけで効く。
    /// Linux 実装は受け取るが使わない。
    filter: Option<String>,
    /// 未指定なら `default_log_dir()` で OS ごとの既定値を決める。
    log_dir: Option<PathBuf>,
}

#[derive(Debug)]
enum CliError {
    UnknownFlag(String),
    MissingValue(&'static str),
    InvalidQueueNum(String),
    /// 値の欠落ではなく、引数そのもの（例：`--labels`）が1つも無かった。
    MissingRequiredArg(&'static str),
    /// 段階4：`--ips-ttl` の値が `u64`（秒）として読めない。
    InvalidIpsTtl(String),
    /// `--ips-severity` の値が 1 から 3 の整数として読めない。
    InvalidIpsSeverity(String),
    /// `--pcapng` の前景経路：`--poll-ms` の値が `u64`（ミリ秒）として読めない。
    InvalidPollMs(String),
    /// 段階7：`proxy` の `--listen` の値が `addr:port` として読めない。
    InvalidListenAddr(String),
    /// 段階7：`proxy` の `--deny` の値が `blackhole`/`403` のどちらでもない。
    InvalidDenyMode(String),
    /// Stage 10: `--breaker-hosts` is not an integer of 1 or more.
    InvalidBreakerHosts(String),
    /// Stage 10: `defense-report --days` is not an integer.
    InvalidDays(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let locale = packetdeath::i18n::locale();
        let s = match self {
            Self::UnknownFlag(flag) => packetdeath::i18n::cli_unknown_flag(locale, flag),
            Self::MissingValue(flag) => packetdeath::i18n::cli_value_required(locale, flag),
            Self::InvalidQueueNum(v) => packetdeath::i18n::cli_invalid_queue_num(locale, v),
            Self::MissingRequiredArg(flag) => {
                packetdeath::i18n::cli_required_arg_missing(locale, flag)
            }
            Self::InvalidIpsTtl(v) => packetdeath::i18n::cli_invalid_ips_ttl(locale, v),
            Self::InvalidIpsSeverity(v) => packetdeath::i18n::cli_invalid_ips_severity(locale, v),
            Self::InvalidPollMs(v) => packetdeath::i18n::cli_invalid_poll_ms(locale, v),
            Self::InvalidListenAddr(v) => packetdeath::i18n::cli_invalid_listen_addr(locale, v),
            Self::InvalidDenyMode(v) => packetdeath::i18n::cli_invalid_deny_mode(locale, v),
            Self::InvalidBreakerHosts(v) => packetdeath::i18n::cli_invalid_breaker_hosts(locale, v),
            Self::InvalidDays(v) => packetdeath::i18n::cli_invalid_days(locale, v),
        };
        write!(f, "{s}")
    }
}

/// `observe` subcommand の引数を解析する。設定は引数だけから読み、
/// 環境変数は読まない（設定は引数だけから読む）。
/// `--log-dir` を渡さなかったときの既定値計算だけは、実行環境が定義する
/// `$HOME` 等を読む。
fn parse_observe_args(args: &[String]) -> Result<ObserveArgs, CliError> {
    let mut queue_num = DEFAULT_QUEUE_NUM;
    let mut filter = None;
    let mut log_dir = None;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--queue" => {
                let value = iter.next().ok_or(CliError::MissingValue("--queue"))?;
                queue_num = value
                    .parse()
                    .map_err(|_| CliError::InvalidQueueNum(value.clone()))?;
            }
            "--filter" => {
                let value = iter.next().ok_or(CliError::MissingValue("--filter"))?;
                filter = Some(value.clone());
            }
            "--log-dir" => {
                let value = iter.next().ok_or(CliError::MissingValue("--log-dir"))?;
                log_dir = Some(PathBuf::from(value));
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(ObserveArgs {
        queue_num,
        filter,
        log_dir,
    })
}

struct BlockArgs {
    queue_num: u16,
    /// `--blocklist` は複数回 渡せる（和集合。`docs/design.md`「段階9」）。
    /// 未指定（空）なら空の blocklist として動く（PK-10 の陰性対照）。
    blocklist_paths: Vec<PathBuf>,
    /// 「当たっても通す」allowlist の path。未指定なら空の allowlist として
    /// 動く（何も救わない＝従来どおりの挙動）。`docs/design.md`「判定を
    /// 差し込む口」：blocklist / iplist / av のどれよりも先に効く。
    allowlist_path: Option<PathBuf>,
    /// `--dns` の有無。段階3「CNAME チェーン解決」を有効にするか。
    dns: bool,
    /// `--iplist` は複数回 渡せる（和集合）。未指定（空）なら空の iplist として
    /// 動く（PK-50 の陰性対照）。
    iplist_paths: Vec<PathBuf>,
    log_dir: Option<PathBuf>,
    /// 段階4：Suricata の `eve.json` の path。未指定なら IDS 由来の遮断は
    /// 0件のまま（PK-30 の陰性対照）。
    eve_path: Option<PathBuf>,
    /// 段階4：落としてよい `signature_id` の一覧 file。未指定なら空集合
    /// （この file に無い sid では落とさない。PK-30 と同じ陰性対照）。
    ips_sids_path: Option<PathBuf>,
    /// 段階4：`alert.severity` がこの値以下の alert を落とす（1 が最も重い）。
    /// 未指定なら severity では落とさない（PK-36a の陰性対照）。
    ips_severity: Option<u8>,
    /// 段階4：drop 集合の寿命（秒）。未指定なら `DEFAULT_IPS_TTL_SECS`
    /// （`docs/design.md`「採る方式」節）。
    ips_ttl_secs: u64,
    /// 段階6：`--av` の path。未指定なら空の av 集合として動く
    /// （PK-60 の陰性対照）。
    av_path: Option<PathBuf>,
    /// 利用者が `pktmon etl2pcap`（Windows）で作った pcapng を前景で監視して
    /// 遮断する経路。未指定なら Linux は既存の nfqueue 経路のまま、Windows は
    /// 従来どおり「未実装」のまま（続きを頼む節：この2つの挙動を変えない）。
    pcapng_path: Option<PathBuf>,
    /// `--pcapng` 使用時の poll 間隔（ミリ秒）。未指定なら `DEFAULT_POLL_MS`。
    poll_ms: u64,
}

/// `--ips-severity` の値を 1〜3 の整数として読む（Suricata の rule の既定の
/// 重さは 1〜3）。
fn parse_ips_severity(value: &str) -> Result<u8, CliError> {
    match value.parse::<u8>() {
        Ok(severity @ 1..=3) => Ok(severity),
        _ => Err(CliError::InvalidIpsSeverity(value.to_string())),
    }
}

/// `block` subcommand の引数を解析する。段階4「IPS 化」の `--eve` /
/// `--ips-sids` / `--ips-severity` / `--ips-ttl` を受け付ける
/// （`docs/design.md`「名前と置き場」）。
fn parse_block_args(args: &[String]) -> Result<BlockArgs, CliError> {
    let mut queue_num = DEFAULT_QUEUE_NUM;
    let mut blocklist_paths = Vec::new();
    let mut allowlist_path = None;
    let mut dns = false;
    let mut iplist_paths = Vec::new();
    let mut log_dir = None;
    let mut eve_path = None;
    let mut ips_sids_path = None;
    let mut ips_severity = None;
    let mut ips_ttl_secs = DEFAULT_IPS_TTL_SECS;
    let mut av_path = None;
    let mut pcapng_path = None;
    let mut poll_ms = DEFAULT_POLL_MS;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--queue" => {
                let value = iter.next().ok_or(CliError::MissingValue("--queue"))?;
                queue_num = value
                    .parse()
                    .map_err(|_| CliError::InvalidQueueNum(value.clone()))?;
            }
            "--blocklist" => {
                let value = iter.next().ok_or(CliError::MissingValue("--blocklist"))?;
                blocklist_paths.push(PathBuf::from(value));
            }
            "--allowlist" => {
                let value = iter.next().ok_or(CliError::MissingValue("--allowlist"))?;
                allowlist_path = Some(PathBuf::from(value));
            }
            "--dns" => {
                dns = true;
            }
            "--iplist" => {
                let value = iter.next().ok_or(CliError::MissingValue("--iplist"))?;
                iplist_paths.push(PathBuf::from(value));
            }
            "--eve" => {
                let value = iter.next().ok_or(CliError::MissingValue("--eve"))?;
                eve_path = Some(PathBuf::from(value));
            }
            "--ips-sids" => {
                let value = iter.next().ok_or(CliError::MissingValue("--ips-sids"))?;
                ips_sids_path = Some(PathBuf::from(value));
            }
            "--ips-severity" => {
                let value = iter
                    .next()
                    .ok_or(CliError::MissingValue("--ips-severity"))?;
                ips_severity = Some(parse_ips_severity(value)?);
            }
            "--ips-ttl" => {
                let value = iter.next().ok_or(CliError::MissingValue("--ips-ttl"))?;
                ips_ttl_secs = value
                    .parse()
                    .map_err(|_| CliError::InvalidIpsTtl(value.clone()))?;
            }
            "--av" => {
                let value = iter.next().ok_or(CliError::MissingValue("--av"))?;
                av_path = Some(PathBuf::from(value));
            }
            "--pcapng" => {
                let value = iter.next().ok_or(CliError::MissingValue("--pcapng"))?;
                pcapng_path = Some(PathBuf::from(value));
            }
            "--poll-ms" => {
                let value = iter.next().ok_or(CliError::MissingValue("--poll-ms"))?;
                poll_ms = value
                    .parse()
                    .map_err(|_| CliError::InvalidPollMs(value.clone()))?;
            }
            "--log-dir" => {
                let value = iter.next().ok_or(CliError::MissingValue("--log-dir"))?;
                log_dir = Some(PathBuf::from(value));
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    Ok(BlockArgs {
        queue_num,
        blocklist_paths,
        allowlist_path,
        dns,
        iplist_paths,
        log_dir,
        eve_path,
        ips_sids_path,
        ips_severity,
        ips_ttl_secs,
        av_path,
        pcapng_path,
        poll_ms,
    })
}

struct EvalArgs {
    /// 必須。`host<TAB>ad` / `host<TAB>ok` 形式の tsv。
    labels_path: PathBuf,
    log_dir: Option<PathBuf>,
}

/// `eval` subcommand の引数を解析する。`--labels` は必須。
fn parse_eval_args(args: &[String]) -> Result<EvalArgs, CliError> {
    let mut labels_path = None;
    let mut log_dir = None;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--labels" => {
                let value = iter.next().ok_or(CliError::MissingValue("--labels"))?;
                labels_path = Some(PathBuf::from(value));
            }
            "--log-dir" => {
                let value = iter.next().ok_or(CliError::MissingValue("--log-dir"))?;
                log_dir = Some(PathBuf::from(value));
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    let labels_path = labels_path.ok_or(CliError::MissingRequiredArg("--labels"))?;
    Ok(EvalArgs {
        labels_path,
        log_dir,
    })
}

struct FilterlistArgs {
    /// 必須。`-` なら stdin から読む。
    in_path: String,
    /// 必須。`-` なら stdout へ書く。
    out_path: String,
}

/// `filterlist` / `allowlist-convert` 共通の引数を解析する。`--in` / `--out`
/// はどちらも必須（`docs/design.md`「EasyList からの変換」）。`--log-dir` は
/// 持たない。この subcommand は file を変換するだけで、`flows.jsonl` 等の
/// 運用 log とは無関係である。
fn parse_filterlist_args(args: &[String]) -> Result<FilterlistArgs, CliError> {
    let mut in_path = None;
    let mut out_path = None;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--in" => {
                let value = iter.next().ok_or(CliError::MissingValue("--in"))?;
                in_path = Some(value.clone());
            }
            "--out" => {
                let value = iter.next().ok_or(CliError::MissingValue("--out"))?;
                out_path = Some(value.clone());
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    let in_path = in_path.ok_or(CliError::MissingRequiredArg("--in"))?;
    let out_path = out_path.ok_or(CliError::MissingRequiredArg("--out"))?;
    Ok(FilterlistArgs { in_path, out_path })
}

struct ServiceArgs {
    log_dir: PathBuf,
    /// `service-run` だけが使う。利用者が `pktmon etl2pcap` で作る pcapng の
    /// path。未指定なら遮断 loop を回さず、SCM の stop/shutdown 待ちだけの
    /// 骨格動作にする（`win_service.rs` の判断）。`service-install` /
    /// `service-uninstall` では読み取るだけで使わない。
    pcapng_path: Option<PathBuf>,
    /// `service-run` だけが使う。未指定なら空の blocklist（何も落とさない）。
    blocklist_path: Option<PathBuf>,
    /// `service-run` だけが使う。未指定なら空の allowlist（何も救わない＝
    /// 従来どおりの挙動）。
    allowlist_path: Option<PathBuf>,
}

/// `service-install` / `service-run` の引数を解析する。`--log-dir` は必須
/// （SYSTEM で走ると `%LOCALAPPDATA%` が既定値として使えないため、
/// 既定値へ倒さない。PS-4）。`--pcapng` / `--blocklist` は任意（`service-run`
/// だけが使う。`block` subcommand の `--blocklist` と同じ名前にして揃える）。
fn parse_service_args(args: &[String]) -> Result<ServiceArgs, CliError> {
    let mut log_dir = None;
    let mut pcapng_path = None;
    let mut blocklist_path = None;
    let mut allowlist_path = None;
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--log-dir" => {
                let value = iter.next().ok_or(CliError::MissingValue("--log-dir"))?;
                log_dir = Some(PathBuf::from(value));
            }
            "--pcapng" => {
                let value = iter.next().ok_or(CliError::MissingValue("--pcapng"))?;
                pcapng_path = Some(PathBuf::from(value));
            }
            "--blocklist" => {
                let value = iter.next().ok_or(CliError::MissingValue("--blocklist"))?;
                blocklist_path = Some(PathBuf::from(value));
            }
            "--allowlist" => {
                let value = iter.next().ok_or(CliError::MissingValue("--allowlist"))?;
                allowlist_path = Some(PathBuf::from(value));
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }

    let log_dir = log_dir.ok_or(CliError::MissingRequiredArg("--log-dir"))?;
    Ok(ServiceArgs {
        log_dir,
        pcapng_path,
        blocklist_path,
        allowlist_path,
    })
}

/// `docs/design.md`「段階7 proxy」節：`packetdeath proxy` の引数一式。
/// `--dns` を持たない（段階3「CNAME チェーン解決」は proxy に無い）。
struct ProxyArgs {
    /// 必須。`0.0.0.0` を黙って開かない（open proxy 対策。既定を置かない）。
    listen: SocketAddr,
    /// 複数回 渡せる（和集合）。未指定（空）なら空の blocklist として動く
    /// （PK-70 の陰性対照）。
    blocklist_paths: Vec<PathBuf>,
    /// 未指定なら空の allowlist として動く（何も救わない＝従来どおりの挙動）。
    allowlist_path: Option<PathBuf>,
    /// 複数回 渡せる（和集合）。未指定（空）なら空の iplist として動く。
    iplist_paths: Vec<PathBuf>,
    /// 未指定なら空の av 集合として動く。
    av_path: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    /// `--allow-from <CIDR>` は複数回 渡せる。未指定（空）なら
    /// `proxy::AllowFrom::from_args` が既定（loopback と RFC1918）へ倒す。
    allow_from: Vec<String>,
    /// block 判定を返す形。既定は `DenyMode::Blackhole`
    /// （相手に気づかれない側。`docs/design.md`
    /// 「段階7 proxy」節「拒否の形」）。
    deny: DenyMode,
    /// Stage 8 (`docs/design.md` "段階8 MITM", CLI). Decryption needs all
    /// three; any subset leaves it off with a `[warn]` naming what is missing.
    mitm_list_path: Option<PathBuf>,
    ca_dir: Option<PathBuf>,
    /// `--clamd`: a Unix socket path or `addr:port` (read in `clamd.rs`).
    clamd: Option<String>,
    /// Stage 10 (`docs/design.md` "段階10 能動防御"). Nothing given leaves the
    /// proxy exactly as before.
    stage10: Stage10Args,
}

/// The stage 10 options of `proxy`.
#[derive(Default)]
struct Stage10Args {
    /// `--distrust`: certificates that stop a flow.
    distrust: Vec<PathBuf>,
    /// `--watch-distrust`: certificates that are only written to `watch.jsonl`.
    watch_distrust: Vec<PathBuf>,
    watch_blocklists: Vec<PathBuf>,
    watch_iplists: Vec<PathBuf>,
    probe_chains: bool,
    defense_off: Option<PathBuf>,
    breaker_hosts: Option<usize>,
}

impl Stage10Args {
    fn requested(&self) -> bool {
        !self.distrust.is_empty()
            || !self.watch_distrust.is_empty()
            || !self.watch_blocklists.is_empty()
            || !self.watch_iplists.is_empty()
            || self.probe_chains
            || self.defense_off.is_some()
            || self.breaker_hosts.is_some()
    }
}

/// Reads one stage 10 flag of `proxy`. `Ok(false)` when `flag` is not one.
fn parse_stage10_flag(
    args: &mut Stage10Args,
    flag: &str,
    values: &mut std::slice::Iter<'_, String>,
) -> Result<bool, CliError> {
    match flag {
        "--distrust" => args.distrust.push(path_value(values, "--distrust")?),
        "--watch-distrust" => args
            .watch_distrust
            .push(path_value(values, "--watch-distrust")?),
        "--watch-blocklist" => args
            .watch_blocklists
            .push(path_value(values, "--watch-blocklist")?),
        "--watch-iplist" => args
            .watch_iplists
            .push(path_value(values, "--watch-iplist")?),
        "--probe-chains" => args.probe_chains = true,
        "--defense-off" => args.defense_off = Some(path_value(values, "--defense-off")?),
        "--breaker-hosts" => {
            let value = values
                .next()
                .ok_or(CliError::MissingValue("--breaker-hosts"))?;
            let hosts = value
                .parse::<usize>()
                .ok()
                .filter(|hosts| *hosts >= 1)
                .ok_or_else(|| CliError::InvalidBreakerHosts(value.clone()))?;
            args.breaker_hosts = Some(hosts);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// The path that follows `flag`.
fn path_value(
    values: &mut std::slice::Iter<'_, String>,
    flag: &'static str,
) -> Result<PathBuf, CliError> {
    values
        .next()
        .map(PathBuf::from)
        .ok_or(CliError::MissingValue(flag))
}

/// What the three stage 8 options ask for.
#[derive(Debug, PartialEq, Eq)]
enum MitmRequest<'a> {
    /// None given: stage 7 as before, nothing said.
    Off,
    /// Some but not all given: stage 7, and these names are missing.
    Partial(Vec<&'static str>),
    /// All three given.
    Full {
        mitm_list: &'a Path,
        ca_dir: &'a Path,
        clamd: &'a str,
    },
}

fn mitm_request<'a>(
    mitm_list: Option<&'a Path>,
    ca_dir: Option<&'a Path>,
    clamd: Option<&'a str>,
) -> MitmRequest<'a> {
    match (mitm_list, ca_dir, clamd) {
        (None, None, None) => MitmRequest::Off,
        (Some(mitm_list), Some(ca_dir), Some(clamd)) => MitmRequest::Full {
            mitm_list,
            ca_dir,
            clamd,
        },
        (list, ca, clamd) => MitmRequest::Partial(
            [
                (list.is_none(), "--mitm-list"),
                (ca.is_none(), "--ca-dir"),
                (clamd.is_none(), "--clamd"),
            ]
            .into_iter()
            .filter_map(|(missing, name)| missing.then_some(name))
            .collect(),
        ),
    }
}

/// `proxy` subcommand の引数を解析する。`--listen` は必須（`docs/design.md`
/// 「段階7 proxy」節：「`--listen` に既定は置かない」）。
fn parse_proxy_args(args: &[String]) -> Result<ProxyArgs, CliError> {
    let mut listen = None;
    let mut blocklist_paths = Vec::new();
    let mut allowlist_path = None;
    let mut iplist_paths = Vec::new();
    let mut av_path = None;
    let mut log_dir = None;
    let mut allow_from = Vec::new();
    let mut deny = DenyMode::Blackhole;
    let mut mitm_list_path = None;
    let mut ca_dir = None;
    let mut clamd = None;
    let mut stage10 = Stage10Args::default();
    let mut iter = args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--mitm-list" => {
                let value = iter.next().ok_or(CliError::MissingValue("--mitm-list"))?;
                mitm_list_path = Some(PathBuf::from(value));
            }
            "--ca-dir" => {
                let value = iter.next().ok_or(CliError::MissingValue("--ca-dir"))?;
                ca_dir = Some(PathBuf::from(value));
            }
            "--clamd" => {
                let value = iter.next().ok_or(CliError::MissingValue("--clamd"))?;
                clamd = Some(value.clone());
            }
            "--listen" => {
                let value = iter.next().ok_or(CliError::MissingValue("--listen"))?;
                listen = Some(
                    value
                        .parse::<SocketAddr>()
                        .map_err(|_| CliError::InvalidListenAddr(value.clone()))?,
                );
            }
            "--blocklist" => {
                let value = iter.next().ok_or(CliError::MissingValue("--blocklist"))?;
                blocklist_paths.push(PathBuf::from(value));
            }
            "--allowlist" => {
                let value = iter.next().ok_or(CliError::MissingValue("--allowlist"))?;
                allowlist_path = Some(PathBuf::from(value));
            }
            "--iplist" => {
                let value = iter.next().ok_or(CliError::MissingValue("--iplist"))?;
                iplist_paths.push(PathBuf::from(value));
            }
            "--av" => {
                let value = iter.next().ok_or(CliError::MissingValue("--av"))?;
                av_path = Some(PathBuf::from(value));
            }
            "--log-dir" => {
                let value = iter.next().ok_or(CliError::MissingValue("--log-dir"))?;
                log_dir = Some(PathBuf::from(value));
            }
            "--allow-from" => {
                let value = iter.next().ok_or(CliError::MissingValue("--allow-from"))?;
                allow_from.push(value.clone());
            }
            "--deny" => {
                let value = iter.next().ok_or(CliError::MissingValue("--deny"))?;
                deny = value
                    .parse()
                    .map_err(|_| CliError::InvalidDenyMode(value.clone()))?;
            }
            other => {
                if !parse_stage10_flag(&mut stage10, other, &mut iter)? {
                    return Err(CliError::UnknownFlag(other.to_string()));
                }
            }
        }
    }

    let listen = listen.ok_or(CliError::MissingRequiredArg("--listen"))?;
    Ok(ProxyArgs {
        listen,
        blocklist_paths,
        allowlist_path,
        iplist_paths,
        av_path,
        log_dir,
        allow_from,
        deny,
        mitm_list_path,
        ca_dir,
        clamd,
        stage10,
    })
}

#[derive(Debug)]
enum LogDirError {
    /// Linux で `XDG_STATE_HOME` も `HOME` も読めなかった。
    #[cfg(target_os = "linux")]
    NoHome,
    /// Windows で `LOCALAPPDATA` が読めなかった。
    #[cfg(not(target_os = "linux"))]
    NoLocalAppData,
}

impl fmt::Display for LogDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let locale = packetdeath::i18n::locale();
        let s = match self {
            #[cfg(target_os = "linux")]
            Self::NoHome => packetdeath::i18n::log_dir_no_home(locale),
            #[cfg(not(target_os = "linux"))]
            Self::NoLocalAppData => packetdeath::i18n::log_dir_no_local_app_data(locale),
        };
        write!(f, "{s}")
    }
}

/// `--log-dir` 未指定時の既定値。`docs/design.md`「名前と置き場」:
/// Linux は `${XDG_STATE_HOME:-$HOME/.local/state}/packetdeath/`。
#[cfg(target_os = "linux")]
fn default_log_dir() -> Result<PathBuf, LogDirError> {
    if let Some(xdg_state_home) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(xdg_state_home).join("packetdeath"));
    }
    let home = std::env::var_os("HOME").ok_or(LogDirError::NoHome)?;
    Ok(PathBuf::from(home).join(".local/state/packetdeath"))
}

/// `docs/design.md`「名前と置き場」: Windows は `%LOCALAPPDATA%\packetdeath\`。
#[cfg(not(target_os = "linux"))]
fn default_log_dir() -> Result<PathBuf, LogDirError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or(LogDirError::NoLocalAppData)?;
    Ok(PathBuf::from(local_app_data).join("packetdeath"))
}

/// `--log-dir` の明示値があればそれを使い、無ければ OS ごとの既定値を計算する。
/// 全 subcommand（`observe` / `block` / `eval`）が共有する
/// （`docs/design.md`「名前と置き場」：全 subcommand に共通の `--log-dir`）。
fn resolve_log_dir(explicit: Option<PathBuf>) -> Result<PathBuf, LogDirError> {
    match explicit {
        Some(dir) => Ok(dir),
        None => default_log_dir(),
    }
}

/// `log_dir` を作り、`flows.jsonl` を append-open する。`observe` と `block` の
/// 両方が使う（`docs/design.md`「名前と置き場」の flow log）。`block` の
/// `--pcapng` 前景経路は Windows でも使うため、OS を絞らない。
fn open_flow_sink(log_dir: &Path) -> Result<(PathBuf, FlowLogSink), String> {
    let locale = packetdeath::i18n::locale();
    std::fs::create_dir_all(log_dir)
        .map_err(|e| packetdeath::i18n::log_dir_create_failed(locale, log_dir.display(), e))?;
    let flows_path = log_dir.join("flows.jsonl");
    let sink = FlowLogSink::open(&flows_path)
        .map_err(|e| packetdeath::i18n::flow_log_open_failed(locale, flows_path.display(), e))?;
    Ok((flows_path, sink))
}

fn main() -> ExitCode {
    packetdeath::i18n::log_detected_locale();
    let locale = packetdeath::i18n::locale();
    let args: Vec<String> = std::env::args().skip(1).collect();

    let Some(command) = args.first() else {
        eprintln!(
            "packetdeath: [error] {}",
            packetdeath::i18n::usage_banner(locale)
        );
        return ExitCode::FAILURE;
    };

    match command.as_str() {
        "observe" => match parse_observe_args(&args[1..]) {
            Ok(parsed) => run_observe(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "block" => match parse_block_args(&args[1..]) {
            Ok(parsed) => run_block(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "eval" => match parse_eval_args(&args[1..]) {
            Ok(parsed) => run_eval(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "filterlist" => match parse_filterlist_args(&args[1..]) {
            Ok(parsed) => run_filterlist(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "allowlist-convert" => match parse_filterlist_args(&args[1..]) {
            Ok(parsed) => run_allowlist_convert(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "service-install" => match parse_service_args(&args[1..]) {
            Ok(parsed) => run_service_install(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "service-uninstall" => run_service_uninstall(),
        "service-run" => match parse_service_args(&args[1..]) {
            Ok(parsed) => run_service_run(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "proxy" => match parse_proxy_args(&args[1..]) {
            Ok(parsed) => run_proxy(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "defense-report" => match parse_defense_report_args(&args[1..]) {
            Ok(parsed) => run_defense_report(parsed),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::arg_parse_failed(locale, e)
                );
                ExitCode::FAILURE
            }
        },
        "waf" => match packetdeath::waf::config::parse_waf_args(&args[1..]) {
            Ok(settings) => run_waf(settings),
            Err(e) => arg_error(locale, e),
        },
        "waf-test" => match packetdeath::waf::testcmd::parse_test_args(&args[1..]) {
            Ok(parsed) => exit_code_of(packetdeath::waf::testcmd::run(&parsed)),
            Err(e) => arg_error(locale, e),
        },
        "waf-report" => match packetdeath::waf::report::parse_report_args(&args[1..]) {
            Ok(parsed) => exit_code_of(packetdeath::waf::report::run(&parsed)),
            Err(e) => arg_error(locale, e),
        },
        other => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::unknown_command(locale, other)
            );
            ExitCode::FAILURE
        }
    }
}

/// Report an option that could not be read and fail.
fn arg_error(locale: packetdeath::i18n::Locale, e: impl std::fmt::Display) -> ExitCode {
    eprintln!(
        "packetdeath: [error] {}",
        packetdeath::i18n::arg_parse_failed(locale, e)
    );
    ExitCode::FAILURE
}

/// A process exit code from the integer a subcommand returned.
fn exit_code_of(code: i32) -> ExitCode {
    match u8::try_from(code) {
        Ok(byte) => ExitCode::from(byte),
        Err(_) => ExitCode::FAILURE,
    }
}

/// `packetdeath waf` (`docs/design.md` "段階11 WAF"): runs until the process ends.
fn run_waf(settings: packetdeath::waf::config::Settings) -> ExitCode {
    match packetdeath::waf::server::run(settings) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("packetdeath: [error] waf: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run_observe(parsed: ObserveArgs) -> ExitCode {
    let locale = packetdeath::i18n::locale();
    if parsed.filter.is_some() {
        eprintln!(
            "packetdeath: [warn] {}",
            packetdeath::i18n::filter_windows_only_ignored(locale)
        );
    }

    let log_dir = match resolve_log_dir(parsed.log_dir) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::log_dir_undecided(locale, e)
            );
            return ExitCode::FAILURE;
        }
    };

    let (flows_path, sink) = match open_flow_sink(&log_dir) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("packetdeath: [error] {msg}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!(
        "packetdeath: [info] {}",
        packetdeath::i18n::observe_started(locale, parsed.queue_num, flows_path.display())
    );

    match packetdeath::linux::run(parsed.queue_num, &sink) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::observe_loop_failed(locale, e)
            );
            ExitCode::FAILURE
        }
    }
}

/// Builds the drop rule from `--ips-sids` and `--ips-severity`. An unreadable
/// sids file leaves the sid set empty and logs a warning; the severity limit
/// still applies.
#[cfg(target_os = "linux")]
fn load_ips_rule(ips_sids_path: Option<&PathBuf>, max_severity: Option<u8>) -> IpsRule {
    let sids = match ips_sids_path {
        None => std::collections::HashSet::new(),
        Some(path) => match packetdeath::ids::load_ips_sids(path) {
            Ok(set) => set,
            Err(e) => {
                eprintln!(
                    "packetdeath: [warn] {}",
                    packetdeath::i18n::ips_sids_load_failed(
                        packetdeath::i18n::locale(),
                        path.display(),
                        e
                    )
                );
                std::collections::HashSet::new()
            }
        },
    };
    IpsRule { sids, max_severity }
}

/// 段階4：`--eve` が指定されていれば、`eve.json` を tail する別 thread を
/// 起動する。`--eve` 未指定なら何も起動せず `None`（IDS 由来の遮断は0件の
/// まま。PK-30 の陰性対照）。
///
/// 🔴 **戻り値の `Sender` を drop すると監視 thread が終了する。**呼び出し元
/// はプロセスが動いている間、戻り値をスコープに残す必要がある
/// （`mpsc::Receiver::recv_timeout` が `Disconnected` を受けて即 戻るため）。
#[cfg(target_os = "linux")]
fn spawn_eve_watcher(
    eve_path: Option<&PathBuf>,
    rule: IpsRule,
    drop_set: Arc<IdsDropSet>,
    ttl: Duration,
) -> Option<mpsc::Sender<()>> {
    let eve_path = eve_path?.clone();

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        packetdeath::ids::watch_eve_file(
            &eve_path,
            &rule,
            &drop_set,
            ttl,
            EVE_POLL_INTERVAL,
            &stop_rx,
        );
    });
    Some(stop_tx)
}

/// `--blocklist`（複数可）/ `--allowlist` / `--iplist`（複数可）/ `--av` を
/// 読む。読めなければ（file 単位で）空集合へ倒し、
/// 理由を `[warn]`／`[error]` で出す（`docs/design.md`「制約」）。Linux の
/// nfqueue 経路、`--pcapng` の前景経路（Linux・Windows 共通）、`proxy`
/// 経路（段階7）の3つが使う共通処理（重複を避けるための切り出し。log の
/// 文言・順序は従来のまま）。引数は `BlockArgs` / `ProxyArgs` のどちらにも
/// 依存しない path だけを受け取る形にしてある。
fn load_judge_inputs(
    blocklist_paths: &[PathBuf],
    allowlist_path: Option<&Path>,
    iplist_paths: &[PathBuf],
    av_path: Option<&Path>,
) -> JudgeInputs {
    let locale = packetdeath::i18n::locale();
    let blocklists = Blocklist::load_all(blocklist_paths);

    let allowlist = match allowlist_path {
        Some(path) => match Allowlist::load(path) {
            Ok(al) => al,
            Err(e) => {
                eprintln!(
                    "packetdeath: [warn] {}",
                    packetdeath::i18n::allowlist_load_failed_empty(locale, path.display(), e)
                );
                Allowlist::empty()
            }
        },
        None => Allowlist::empty(),
    };

    let iplists = IpList::load_all(iplist_paths);

    let av = match av_path {
        Some(path) => match AvList::load(path) {
            Ok(list) => list,
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::av_load_failed_empty(locale, path.display(), e)
                );
                AvList::empty()
            }
        },
        None => AvList::empty(),
    };

    JudgeInputs {
        blocklists,
        allowlist,
        iplists,
        av,
    }
}

/// [`load_judge_inputs`] の結果。blocklist と iplist は file ごとに分けたまま
/// 持つ（`WatchInputs` が file ごとに読み直す）。
struct JudgeInputs {
    blocklists: Vec<(PathBuf, Blocklist)>,
    allowlist: Allowlist,
    iplists: Vec<(PathBuf, IpList)>,
    av: AvList,
}

/// 読み込み済みの list を `WatchInputs` へ束ねる。`block`（`--pcapng` を含む）
/// と `proxy` の4経路が同じ形で使う。
fn build_watch_inputs<'a>(
    blocklists: Vec<(PathBuf, Blocklist)>,
    allowlist: Allowlist,
    allowlist_path: Option<PathBuf>,
    iplists: Vec<(PathBuf, IpList)>,
    av: &'a AvList,
) -> WatchInputs<'a> {
    WatchInputs::new(
        Blocklist::empty(),
        allowlist,
        allowlist_path,
        IpList::empty(),
        av,
    )
    .with_blocklist_files(blocklists)
    .with_iplist_files(iplists)
}

/// `--pcapng` が指定されたときの共通の前景経路。Linux・Windows どちらも
/// 使う（`blocker` の実体だけが呼び出し側で変わる。Linux は
/// [`NoopBlocker`]、Windows は [`RespawningPsBridge`]）。
///
/// **Ctrl-C で止まる。**`run_watch_loop` は `stop_rx` の受信か切断で戻る
/// 契約だが、この経路はどちらも起こさない（`_stop_tx` を関数の終わりまで
/// 保持し続ける）。かわりに、他の loop（`packetdeath::linux::run` 等）と
/// 同じく、SIGINT の既定動作（process 終了）にそのまま乗る。
fn run_pcapng_foreground(
    pcapng_path: &Path,
    poll_ms: u64,
    inputs: &mut WatchInputs,
    log: &FlowLogSink,
    blocker: &mut dyn TcpBlocker,
) -> ExitCode {
    eprintln!(
        "packetdeath: [info] {}",
        packetdeath::i18n::pcapng_foreground_watch(
            packetdeath::i18n::locale(),
            pcapng_path.display(),
            poll_ms
        )
    );

    // `_stop_tx` を drop すると `stop_rx` が Disconnected になり
    // `run_watch_loop` が即 return してしまうため、呼び出しが終わるまで
    // スコープに残す（誰も送らない。停止は Ctrl-C の既定動作に任せる）。
    let (_stop_tx, stop_rx) = mpsc::channel::<()>();
    packetdeath::block_loop::run_watch_loop(
        pcapng_path,
        Duration::from_millis(poll_ms),
        inputs,
        blocker,
        log,
        &stop_rx,
    );
    ExitCode::SUCCESS
}

/// 段階2「遮断」・段階3「CNAME チェーン解決」・段階4「IPS 化」の起動。
///
/// **外部が更新する blocklist / iplist / eve.json / ips-sids を動作の gate に
/// しない。**指定した path が読めなくても起動を止めず、空（＝何も落とさない）
/// へ倒して素通しのまま動き続ける（`docs/design.md`「制約」）。
#[cfg(target_os = "linux")]
fn run_block(parsed: BlockArgs) -> ExitCode {
    let locale = packetdeath::i18n::locale();
    let log_dir = match resolve_log_dir(parsed.log_dir.clone()) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::log_dir_undecided(locale, e)
            );
            return ExitCode::FAILURE;
        }
    };

    let (flows_path, sink) = match open_flow_sink(&log_dir) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("packetdeath: [error] {msg}");
            return ExitCode::FAILURE;
        }
    };

    let JudgeInputs {
        blocklists,
        allowlist,
        iplists,
        av,
    } = load_judge_inputs(
        &parsed.blocklist_paths,
        parsed.allowlist_path.as_deref(),
        &parsed.iplist_paths,
        parsed.av_path.as_deref(),
    );

    // `--pcapng` 前景経路（続きを頼む節）。Linux には `SetTcpEntry` も
    // 常駐 PowerShell も無いので、遮断はできない。SNI 判定と log だけを
    // 行い、`NoopBlocker` で素通しへ倒す（動作確認のためだけに受ける）。
    // `--pcapng` 無しの経路（この if の外）は1文字も変えない。
    if let Some(pcapng_path) = &parsed.pcapng_path {
        eprintln!(
            "packetdeath: [warn] {}",
            packetdeath::i18n::linux_pcapng_no_blocker_passthrough(locale)
        );
        let mut blocker = NoopBlocker;
        // blocklist / allowlist は走行中に読み直す（再起動なしで編集を反映する。
        // `block_loop.rs`「走行中の blocklist / allowlist 読み直し」の判断）。
        let mut inputs = build_watch_inputs(
            blocklists,
            allowlist,
            parsed.allowlist_path.clone(),
            iplists,
            &av,
        );
        return run_pcapng_foreground(
            pcapng_path,
            parsed.poll_ms,
            &mut inputs,
            &sink,
            &mut blocker,
        );
    }

    let dns_sink = if parsed.dns {
        let dns_path = log_dir.join("dns.jsonl");
        match DnsLogSink::open(&dns_path) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::dns_log_open_failed(locale, dns_path.display(), e)
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    eprintln!(
        "packetdeath: [info] {}",
        packetdeath::i18n::block_started(
            locale,
            parsed.queue_num,
            flows_path.display(),
            &parsed.blocklist_paths,
            parsed.dns,
            &parsed.iplist_paths,
            &parsed.eve_path,
            &parsed.ips_sids_path,
            parsed.ips_severity,
            parsed.ips_ttl_secs,
            &parsed.av_path,
        )
    );

    let ids_drop_set = Arc::new(IdsDropSet::new());
    // 監視 thread を止めないため、戻り値をこの関数のスコープに残す
    // （`run_block` 自体が呼び出し元が止めるまで戻らない loop なので、
    // 実質プロセス終了まで生存する）。
    let _eve_stop_tx = spawn_eve_watcher(
        parsed.eve_path.as_ref(),
        load_ips_rule(parsed.ips_sids_path.as_ref(), parsed.ips_severity),
        Arc::clone(&ids_drop_set),
        Duration::from_secs(parsed.ips_ttl_secs),
    );

    let config = packetdeath::linux::BlockConfig {
        dns_log: dns_sink.as_ref(),
        ids_drop_set: &ids_drop_set,
        av: &av,
    };

    // blocklist / allowlist は走行中に読み直す（再起動なしで編集を反映する。
    // `block_loop.rs`「走行中の blocklist / allowlist 読み直し」の判断。`--pcapng` 経路と
    // 同じ `WatchInputs` をそのまま nfqueue 本経路でも使う）。
    let mut inputs = build_watch_inputs(
        blocklists,
        allowlist,
        parsed.allowlist_path.clone(),
        iplists,
        &av,
    );

    match packetdeath::linux::run_block(parsed.queue_num, &sink, &config, &mut inputs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::block_loop_failed(locale, e)
            );
            ExitCode::FAILURE
        }
    }
}

/// **`--pcapng` 無しの経路（段階2w 本体）は未着手のまま、1文字も変えない**
/// （`docs/design.md`「段階」：「Linux の段階は Linux の受入 ID だけで進む」）。
/// **`--pcapng` 有りの経路だけ**（続きを頼む節）、常駐 PowerShell を起動して
/// `TcpBlocker` にし、前景で `run_watch_loop` を回す。
#[cfg(not(target_os = "linux"))]
fn run_block(parsed: BlockArgs) -> ExitCode {
    let locale = packetdeath::i18n::locale();
    let log_dir = match resolve_log_dir(parsed.log_dir.clone()) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::log_dir_undecided(locale, e)
            );
            return ExitCode::FAILURE;
        }
    };

    let Some(pcapng_path) = parsed.pcapng_path.clone() else {
        eprintln!(
            "packetdeath: [error] {}",
            packetdeath::i18n::block_not_implemented_for_os(
                locale,
                parsed.queue_num,
                log_dir.display(),
                &parsed.blocklist_paths,
                parsed.dns,
                &parsed.iplist_paths,
                &parsed.eve_path,
                &parsed.ips_sids_path,
                parsed.ips_severity,
                parsed.ips_ttl_secs,
                &parsed.av_path,
            )
        );
        return ExitCode::FAILURE;
    };

    let (flows_path, sink) = match open_flow_sink(&log_dir) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("packetdeath: [error] {msg}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "packetdeath: [info] {}",
        packetdeath::i18n::flow_log_opened(locale, flows_path.display())
    );

    let JudgeInputs {
        blocklists,
        allowlist,
        iplists,
        av,
    } = load_judge_inputs(
        &parsed.blocklist_paths,
        parsed.allowlist_path.as_deref(),
        &parsed.iplist_paths,
        parsed.av_path.as_deref(),
    );

    let mut noop = NoopBlocker;
    let mut respawning;
    let blocker: &mut dyn TcpBlocker = match packetdeath::ps_bridge::write_script(&log_dir) {
        Ok(script_path) => {
            respawning = RespawningPsBridge::new(script_path);
            respawning.prepare();
            &mut respawning
        }
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::kill_tcp_script_write_failed(locale, e)
            );
            &mut noop
        }
    };

    // blocklist / allowlist / iplist は走行中に読み直す（同上の判断）。
    let mut inputs = build_watch_inputs(
        blocklists,
        allowlist,
        parsed.allowlist_path.clone(),
        iplists,
        &av,
    );
    run_pcapng_foreground(&pcapng_path, parsed.poll_ms, &mut inputs, &sink, blocker)
}

/// `packetdeath eval --labels <tsv>`。`flows.jsonl` を labels.tsv と突き合わせ、
/// 遮断率・誤遮断率を出す（`docs/design.md` PK-13）。OS 非依存。
fn run_eval(parsed: EvalArgs) -> ExitCode {
    let locale = packetdeath::i18n::locale();
    let log_dir = match resolve_log_dir(parsed.log_dir) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::log_dir_undecided(locale, e)
            );
            return ExitCode::FAILURE;
        }
    };

    let labels_content = match std::fs::read_to_string(&parsed.labels_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::labels_file_read_failed(locale, parsed.labels_path.display(), e)
            );
            return ExitCode::FAILURE;
        }
    };
    let labels = packetdeath::eval::parse_labels(&labels_content);

    // flows.jsonl が無い（未起動）なら 0 flow として扱う（PK-13 の陰性対照）。
    let flows_path = log_dir.join("flows.jsonl");
    let flows_content = std::fs::read_to_string(&flows_path).unwrap_or_default();

    let report = packetdeath::eval::evaluate(&labels, &flows_content);
    println!("{}", report.ad_line());
    println!("{}", report.ok_line());
    if let Some(skipped_line) = report.skipped_line() {
        println!("{skipped_line}");
    }
    ExitCode::SUCCESS
}

/// 段階7「proxy」の起動。`docs/design.md`「段階7 proxy」節。root は要らない
/// （nfqueue や `SetTcpEntry` を使わない）ので、`block` と違い OS を絞らない。
fn run_proxy(parsed: ProxyArgs) -> ExitCode {
    let locale = packetdeath::i18n::locale();
    let log_dir = match resolve_log_dir(parsed.log_dir) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::log_dir_undecided(locale, e)
            );
            return ExitCode::FAILURE;
        }
    };

    let (flows_path, sink) = match open_flow_sink(&log_dir) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("packetdeath: [error] {msg}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "packetdeath: [info] {}",
        packetdeath::i18n::flow_log_opened(locale, flows_path.display())
    );

    let JudgeInputs {
        blocklists,
        allowlist,
        iplists,
        av,
    } = load_judge_inputs(
        &parsed.blocklist_paths,
        parsed.allowlist_path.as_deref(),
        &parsed.iplist_paths,
        parsed.av_path.as_deref(),
    );
    let allow_from = AllowFrom::from_args(&parsed.allow_from);

    let listener = match packetdeath::proxy::bind(parsed.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("packetdeath: [error] {e}");
            return ExitCode::FAILURE;
        }
    };

    // blocklist / allowlist / iplist は走行中に読み直す（`block` / `--pcapng`
    // 経路と同じ `WatchInputs`。`docs/design.md`「段階7 proxy」節の reload）。
    let inputs = build_watch_inputs(
        blocklists,
        allowlist,
        parsed.allowlist_path.clone(),
        iplists,
        &av,
    );

    let limits = packetdeath::proxy::ProxyLimits {
        deny: parsed.deny,
        ..packetdeath::proxy::ProxyLimits::default()
    };

    let request = mitm_request(
        parsed.mitm_list_path.as_deref(),
        parsed.ca_dir.as_deref(),
        parsed.clamd.as_deref(),
    );
    #[cfg(target_os = "linux")]
    let (inputs, mitm) = match start_mitm(request, &log_dir) {
        Some((mitm, path, list)) => (inputs.with_mitm_list(path, list), Some(mitm)),
        None => (inputs, None),
    };
    #[cfg(not(target_os = "linux"))]
    let mitm: Option<packetdeath::proxy::Mitm> = {
        if request != MitmRequest::Off {
            eprintln!(
                "packetdeath: [warn] {}",
                packetdeath::i18n::mitm_disabled_os(locale)
            );
        }
        None
    };

    #[cfg(target_os = "linux")]
    let inputs = match start_defense(&parsed.stage10, &log_dir) {
        Some(defense) => inputs.with_defense(defense),
        None => inputs,
    };
    #[cfg(not(target_os = "linux"))]
    if parsed.stage10.requested() {
        eprintln!(
            "packetdeath: [warn] {}",
            packetdeath::i18n::stage10_disabled_os(locale)
        );
    }

    // `serve` は Ctrl-C まで戻らない（他の `run_*` loop と同じ）。
    packetdeath::proxy::serve(listener, &allow_from, &sink, inputs, limits, mitm.as_ref());
    ExitCode::SUCCESS
}

/// `packetdeath defense-report` (`docs/design.md` "段階10 能動防御", policy 4):
/// counts the hits of the watched sources in a log. Read-only; no network.
#[derive(Default)]
struct DefenseReportArgs {
    flows: Option<PathBuf>,
    watch: Option<PathBuf>,
    blocklists: Vec<PathBuf>,
    iplists: Vec<PathBuf>,
    allowlists: Vec<PathBuf>,
    /// `--watch` mode: the distrust files, to mark the lines that name a
    /// public trust anchor (`root=yes`).
    distrust: Vec<PathBuf>,
    days: usize,
}

fn parse_defense_report_args(args: &[String]) -> Result<DefenseReportArgs, CliError> {
    let mut parsed = DefenseReportArgs::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--flows" => parsed.flows = Some(path_value(&mut iter, "--flows")?),
            "--watch" => parsed.watch = Some(path_value(&mut iter, "--watch")?),
            "--blocklist" => parsed
                .blocklists
                .push(path_value(&mut iter, "--blocklist")?),
            "--iplist" => parsed.iplists.push(path_value(&mut iter, "--iplist")?),
            "--allowlist" => parsed
                .allowlists
                .push(path_value(&mut iter, "--allowlist")?),
            "--distrust" => parsed.distrust.push(path_value(&mut iter, "--distrust")?),
            "--days" => {
                let value = iter.next().ok_or(CliError::MissingValue("--days"))?;
                parsed.days = value
                    .parse()
                    .map_err(|_| CliError::InvalidDays(value.clone()))?;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
    }
    if parsed.flows.is_some() == parsed.watch.is_some() {
        return Err(CliError::MissingRequiredArg("--flows | --watch"));
    }
    Ok(parsed)
}

/// Reads every file the report needs. A file that cannot be read stops the
/// report: a list read as empty would show `hits=0` and look clean.
#[cfg(target_os = "linux")]
fn build_report(parsed: &DefenseReportArgs) -> Result<packetdeath::defense::Report, String> {
    use packetdeath::defense::{report_flows, report_watch, root_sources, source_name};
    use packetdeath::distrust::DistrustList;

    let locale = packetdeath::i18n::locale();
    let failed = |path: &Path, e: &dyn fmt::Display| {
        packetdeath::i18n::defense_report_read_failed(locale, path.display(), e)
    };
    let read = |path: &Path| std::fs::read_to_string(path).map_err(|e| failed(path, &e));
    let allowlists = parsed
        .allowlists
        .iter()
        .map(|path| Allowlist::load(path).map_err(|e| failed(path, &e)))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(watch) = &parsed.watch {
        let log = read(watch)?;
        let files = parsed
            .distrust
            .iter()
            .map(|path| read(path).map(|content| (path.clone(), DistrustList::parse(&content))))
            .collect::<Result<Vec<_>, _>>()?;
        let roots = root_sources(&files, webpki_roots::TLS_SERVER_ROOTS);
        return Ok(report_watch(&log, &allowlists, &roots, parsed.days));
    }
    let flows = parsed
        .flows
        .as_deref()
        .ok_or_else(|| packetdeath::i18n::cli_required_arg_missing(locale, "--flows | --watch"))?;
    let blocklists = parsed
        .blocklists
        .iter()
        .map(|path| {
            Blocklist::load(path)
                .map(|list| (source_name(path), list))
                .map_err(|e| failed(path, &e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let iplists = parsed
        .iplists
        .iter()
        .map(|path| {
            IpList::load(path)
                .map(|list| (source_name(path), list))
                .map_err(|e| failed(path, &e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(report_flows(
        &read(flows)?,
        &blocklists,
        &iplists,
        &allowlists,
        parsed.days,
    ))
}

#[cfg(target_os = "linux")]
fn run_defense_report(parsed: DefenseReportArgs) -> ExitCode {
    match build_report(&parsed) {
        Ok(report) => {
            for row in &report.rows {
                println!("{row}");
            }
            if report.skipped > 0 {
                eprintln!(
                    "packetdeath: [warn] {}",
                    packetdeath::i18n::defense_report_lines_skipped(
                        packetdeath::i18n::locale(),
                        report.skipped
                    )
                );
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("packetdeath: [error] {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_defense_report(_parsed: DefenseReportArgs) -> ExitCode {
    eprintln!(
        "packetdeath: [error] {}",
        packetdeath::i18n::stage10_disabled_os(packetdeath::i18n::locale())
    );
    ExitCode::FAILURE
}

/// Stage 10 startup (`docs/design.md` "段階10 能動防御"): no stage 10 option
/// leaves the proxy as it was; a failure leaves it running without stage 10.
#[cfg(target_os = "linux")]
fn start_defense(args: &Stage10Args, log_dir: &Path) -> Option<Arc<packetdeath::defense::Defense>> {
    use packetdeath::defense::{Defense, DefenseConfig};

    if !args.requested() {
        return None;
    }
    let mut config = DefenseConfig::new(
        log_dir.join("watch.jsonl"),
        webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    );
    config.stop_distrust.clone_from(&args.distrust);
    config.watch_distrust.clone_from(&args.watch_distrust);
    config.watch_blocklists.clone_from(&args.watch_blocklists);
    config.watch_iplists.clone_from(&args.watch_iplists);
    config.probe = args
        .probe_chains
        .then(packetdeath::prober::ProbeSettings::default);
    config.off_file.clone_from(&args.defense_off);
    if let Some(hosts) = args.breaker_hosts {
        config.breaker_hosts = hosts;
    }
    match Defense::start(config) {
        Ok(defense) => Some(Arc::new(defense)),
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::defense_disabled_error(packetdeath::i18n::locale(), e)
            );
            None
        }
    }
}

/// Stage 8 startup (`docs/design.md` "段階8 MITM", "fail-open の形"): any
/// missing option or failure leaves decryption off and the proxy running as
/// stage 7. Returns the state, the `--mitm-list` path and its first contents.
#[cfg(target_os = "linux")]
fn start_mitm(
    request: MitmRequest<'_>,
    log_dir: &Path,
) -> Option<(
    packetdeath::mitm::Mitm,
    PathBuf,
    packetdeath::block_loop::MitmList,
)> {
    use packetdeath::block_loop::MitmList;
    use packetdeath::clamd::ClamdAddr;
    use packetdeath::mitm::{production_roots, Mitm, MitmLimits, MitmSettings};

    let locale = packetdeath::i18n::locale();
    let (list_path, ca_dir, clamd) = match request {
        MitmRequest::Off => return None,
        MitmRequest::Partial(missing) => {
            eprintln!(
                "packetdeath: [warn] {}",
                packetdeath::i18n::mitm_disabled_missing(locale, &missing.join(", "))
            );
            return None;
        }
        MitmRequest::Full {
            mitm_list,
            ca_dir,
            clamd,
        } => (mitm_list, ca_dir, clamd),
    };
    let settings = MitmSettings {
        ca_dir: ca_dir.to_path_buf(),
        clamd: ClamdAddr::parse(clamd),
        av_log: log_dir.join("av.jsonl"),
        upstream_roots: production_roots(),
        limits: MitmLimits::default(),
    };
    let mitm = match Mitm::start(settings) {
        Ok(mitm) => mitm,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::mitm_disabled_error(locale, e)
            );
            return None;
        }
    };
    let list = MitmList::load(list_path);
    eprintln!(
        "packetdeath: [info] {}",
        packetdeath::i18n::mitm_enabled(
            locale,
            list.len(),
            packetdeath::ca::utc_text(mitm.ca().not_after()),
            &mitm.ca().sha256_fingerprint()
        )
    );
    Some((mitm, list_path.to_path_buf(), list))
}

/// `--in` の値を読む。`-` なら stdin、それ以外なら file を読む。
/// `filterlist` / `allowlist-convert` の両方が使う共通処理。
fn read_conversion_input(in_path: &str) -> Result<String, String> {
    let locale = packetdeath::i18n::locale();
    if in_path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .map_err(|e| packetdeath::i18n::stdin_read_failed(locale, e))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(in_path)
            .map_err(|e| packetdeath::i18n::input_file_read_failed(locale, in_path, e))
    }
}

/// `--out` の値へ書く。`-` なら stdout。`filterlist` / `allowlist-convert` の
/// 両方が使う共通処理。
fn write_conversion_output(out_path: &str, rendered: &str) -> Result<(), String> {
    if out_path == "-" {
        print!("{rendered}");
        Ok(())
    } else {
        std::fs::write(out_path, rendered).map_err(|e| {
            packetdeath::i18n::output_file_write_failed(packetdeath::i18n::locale(), out_path, e)
        })
    }
}

/// `filterlist` subcommand：EasyList 形式を `--in` から読み、
/// `packetdeath::filterlist` で blocklist 形式へ変換して `--out` へ書く。
/// `--in` / `--out` に `-` を渡すと、それぞれ stdin / stdout を使う
/// （`docs/design.md`「EasyList からの変換」）。network へは出ない
/// （file を読み書きするだけ）。
fn run_filterlist(parsed: FilterlistArgs) -> ExitCode {
    let content = match read_conversion_input(&parsed.in_path) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("packetdeath: [error] {msg}");
            return ExitCode::FAILURE;
        }
    };

    let conversion = packetdeath::filterlist::convert(&content);

    let generated_at = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::cli_timestamp_format_failed(packetdeath::i18n::locale(), e)
            );
            return ExitCode::FAILURE;
        }
    };
    let rendered = packetdeath::filterlist::render(&conversion, &parsed.in_path, &generated_at);

    if let Err(msg) = write_conversion_output(&parsed.out_path, &rendered) {
        eprintln!("packetdeath: [error] {msg}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// `allowlist-convert` subcommand：公開 allowlist（Microsoft の JSON /
/// 平文1行1domain / Adblock Plus の `@@` 形式）を `--in` から読み、
/// `packetdeath::filterlist::convert_allowlist` が形式を自動判定して
/// `src/allowlist.rs` が読む形式へ変換し `--out` へ書く。`--in` / `--out` に
/// `-` を渡すと、それぞれ stdin / stdout を使う。network へは出ない
/// （file を読み書きするだけ。`run_filterlist` と同じ思想）。
fn run_allowlist_convert(parsed: FilterlistArgs) -> ExitCode {
    let content = match read_conversion_input(&parsed.in_path) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("packetdeath: [error] {msg}");
            return ExitCode::FAILURE;
        }
    };

    let conversion = packetdeath::filterlist::convert_allowlist(&content);

    let generated_at = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::cli_timestamp_format_failed(packetdeath::i18n::locale(), e)
            );
            return ExitCode::FAILURE;
        }
    };
    let rendered =
        packetdeath::filterlist::render_allowlist(&conversion, &parsed.in_path, &generated_at);

    if let Err(msg) = write_conversion_output(&parsed.out_path, &rendered) {
        eprintln!("packetdeath: [error] {msg}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn run_observe(parsed: ObserveArgs) -> ExitCode {
    // 段階1w（Windows 観測）は未着手。log_dir の解決だけ先に通し、
    // PK-6 の build 確認と `default_log_dir` の動作を分離しないようにする。
    let locale = packetdeath::i18n::locale();
    let log_dir = match parsed.log_dir {
        Some(dir) => dir,
        None => match default_log_dir() {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!(
                    "packetdeath: [error] {}",
                    packetdeath::i18n::log_dir_undecided(locale, e)
                );
                return ExitCode::FAILURE;
            }
        },
    };
    eprintln!(
        "packetdeath: [error] {}",
        packetdeath::i18n::observe_not_implemented_for_os(
            locale,
            parsed.queue_num,
            log_dir.display(),
            &parsed.filter,
        )
    );
    ExitCode::FAILURE
}

/// `service-install`。設定する内容は `win_service::install_service` のコメントに
/// 列挙する（起動種別・delayed-auto・失敗時の自動再起動）。
///
/// `--pcapng` / `--blocklist` を渡していれば、それを起動引数へ載せる
/// （渡さないと登録したサービスが何も遮断しない穴を塞ぐ）。
#[cfg(windows)]
fn run_service_install(parsed: ServiceArgs) -> ExitCode {
    match packetdeath::win_service::install_service(
        &parsed.log_dir,
        parsed.pcapng_path.as_deref(),
        parsed.blocklist_path.as_deref(),
        parsed.allowlist_path.as_deref(),
    ) {
        Ok(()) => {
            eprintln!(
                "packetdeath: [info] {}",
                packetdeath::i18n::service_installed(
                    packetdeath::i18n::locale(),
                    parsed.log_dir.display(),
                    &parsed.pcapng_path,
                    &parsed.blocklist_path,
                    &parsed.allowlist_path,
                )
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::service_install_failed(packetdeath::i18n::locale(), e)
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn run_service_install(parsed: ServiceArgs) -> ExitCode {
    // `pcapng_path` / `blocklist_path` / `allowlist_path` は Windows 版の
    // `run_service_install` だけが使う。この OS では読まないことを明示する
    // （`dead_code` 抑止）。
    let _ = (
        &parsed.pcapng_path,
        &parsed.blocklist_path,
        &parsed.allowlist_path,
    );
    eprintln!(
        "packetdeath: [error] {}",
        packetdeath::i18n::service_install_windows_only(
            packetdeath::i18n::locale(),
            parsed.log_dir.display()
        )
    );
    ExitCode::FAILURE
}

/// `service-uninstall`。
#[cfg(windows)]
fn run_service_uninstall() -> ExitCode {
    match packetdeath::win_service::uninstall_service() {
        Ok(()) => {
            eprintln!(
                "packetdeath: [info] {}",
                packetdeath::i18n::service_uninstalled(packetdeath::i18n::locale())
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                packetdeath::i18n::service_uninstall_failed(packetdeath::i18n::locale(), e)
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn run_service_uninstall() -> ExitCode {
    eprintln!(
        "packetdeath: [error] {}",
        packetdeath::i18n::service_uninstall_windows_only(packetdeath::i18n::locale())
    );
    ExitCode::FAILURE
}

/// Send the service's `[info]` / `[warn]` / `[error]` lines to `<log dir>/service.log`.
/// A file that cannot be opened leaves them on stderr; the service keeps running.
#[cfg(windows)]
fn redirect_service_log_to_file(log_dir: &Path) {
    let locale = packetdeath::i18n::locale();
    let offset = time::UtcOffset::current_local_offset().ok();
    let path = log_dir.join("service.log");
    match packetdeath::flow::ServiceLog::open(&path, offset) {
        Ok(log) => {
            packetdeath::flow::redirect_service_log(log);
            if offset.is_none() {
                packetdeath::flow::service_log(&format!(
                    "packetdeath: [warn] {}",
                    packetdeath::i18n::service_log_utc_fallback(locale)
                ));
            }
        }
        Err(e) => eprintln!(
            "packetdeath: [warn] {}",
            packetdeath::i18n::service_log_open_failed(locale, path.display(), e)
        ),
    }
}

/// `service-run`。SCM から起動される想定の entry point。`parsed` を
/// `ServiceRuntimeConfig` へ詰めて SCM の dispatcher を起動し、stop/shutdown
/// が来るまでブロックする（`win_service::run_service_dispatcher` の契約）。
///
/// `--pcapng` を渡さなかった場合は、`win_service::run_service` が
/// stop/shutdown を待つだけの骨格動作へフォールバックする
/// （`win_service.rs`「実際の遮断 loop」節）。
#[cfg(windows)]
fn run_service_run(parsed: ServiceArgs) -> ExitCode {
    redirect_service_log_to_file(&parsed.log_dir);
    let config = packetdeath::win_service::ServiceRuntimeConfig {
        log_dir: parsed.log_dir,
        pcapng_path: parsed.pcapng_path,
        blocklist_path: parsed.blocklist_path,
        allowlist_path: parsed.allowlist_path,
    };
    match packetdeath::win_service::run_service_dispatcher(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            packetdeath::flow::service_log(&format!(
                "packetdeath: [error] {}",
                packetdeath::i18n::service_dispatcher_failed(packetdeath::i18n::locale(), e)
            ));
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn run_service_run(parsed: ServiceArgs) -> ExitCode {
    // `pcapng_path` / `blocklist_path` / `allowlist_path` は Windows 版の
    // `run_service_run` だけが使う。この OS では読まないことを明示する
    // （`dead_code` 抑止）。
    let _ = (
        &parsed.pcapng_path,
        &parsed.blocklist_path,
        &parsed.allowlist_path,
    );
    eprintln!(
        "packetdeath: [error] {}",
        packetdeath::i18n::service_run_windows_only(
            packetdeath::i18n::locale(),
            parsed.log_dir.display()
        )
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_args_when_empty() -> Result<(), String> {
        let parsed = parse_observe_args(&[]).map_err(|e| e.to_string())?;
        assert_eq!(parsed.queue_num, DEFAULT_QUEUE_NUM);
        assert_eq!(parsed.filter, None);
        assert_eq!(parsed.log_dir, None);
        Ok(())
    }

    #[test]
    fn load_judge_inputs_returns_empty_sets_when_no_paths_given() -> Result<(), String> {
        // --pcapng 前景経路と nfqueue 経路が両方 使う共通処理。path が1つも
        // 無ければ、何にも当たらない空集合4つを返す（PK-10/PK-50/PK-60 と
        // 同じ陰性対照の形。allowlist は「何も救わない」が陰性対照）。
        let parsed = parse_block_args(&[]).map_err(|e| e.to_string())?;
        let parsed_inputs = load_judge_inputs(
            &parsed.blocklist_paths,
            parsed.allowlist_path.as_deref(),
            &parsed.iplist_paths,
            parsed.av_path.as_deref(),
        );
        assert!(parsed_inputs.blocklists.is_empty());
        assert!(parsed_inputs.iplists.is_empty());
        let ip = "93.184.216.34".parse().map_err(|e| format!("{e}"))?;
        assert!(!parsed_inputs.av.contains(&ip, 443));
        assert!(!parsed_inputs.allowlist.matches("example.com"));
        Ok(())
    }

    #[test]
    fn parses_repeated_blocklist_and_iplist_flags_in_order() -> Result<(), String> {
        // 段階9：--blocklist / --iplist は複数回 渡せて、渡した順に残る。
        let args: Vec<String> = [
            "--blocklist",
            "/tmp/a.txt",
            "--iplist",
            "/tmp/x.txt",
            "--blocklist",
            "/tmp/b.txt",
            "--iplist",
            "/tmp/y.txt",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let expected_bl = vec![PathBuf::from("/tmp/a.txt"), PathBuf::from("/tmp/b.txt")];
        let expected_ip = vec![PathBuf::from("/tmp/x.txt"), PathBuf::from("/tmp/y.txt")];
        let block = parse_block_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(block.blocklist_paths, expected_bl);
        assert_eq!(block.iplist_paths, expected_ip);

        let mut proxy_args = vec!["--listen".to_string(), "127.0.0.1:0".to_string()];
        proxy_args.extend(args);
        let proxy = parse_proxy_args(&proxy_args).map_err(|e| e.to_string())?;
        assert_eq!(proxy.blocklist_paths, expected_bl);
        assert_eq!(proxy.iplist_paths, expected_ip);
        Ok(())
    }

    fn proxy_args(extra: &[&str]) -> Result<ProxyArgs, String> {
        let mut args = vec!["--listen".to_string(), "127.0.0.1:0".to_string()];
        args.extend(extra.iter().map(|s| s.to_string()));
        parse_proxy_args(&args).map_err(|e| e.to_string())
    }

    #[test]
    fn parses_the_three_mitm_options() -> Result<(), String> {
        // PK-100 (CLI side): the stage 8 options are read as given.
        let parsed = proxy_args(&[
            "--mitm-list",
            "/tmp/mitm.txt",
            "--ca-dir",
            "/tmp/ca",
            "--clamd",
            "/var/run/clamav/clamd.ctl",
        ])?;
        assert_eq!(parsed.mitm_list_path, Some(PathBuf::from("/tmp/mitm.txt")));
        assert_eq!(parsed.ca_dir, Some(PathBuf::from("/tmp/ca")));
        assert_eq!(parsed.clamd.as_deref(), Some("/var/run/clamav/clamd.ctl"));
        assert_eq!(
            mitm_request(
                parsed.mitm_list_path.as_deref(),
                parsed.ca_dir.as_deref(),
                parsed.clamd.as_deref()
            ),
            MitmRequest::Full {
                mitm_list: Path::new("/tmp/mitm.txt"),
                ca_dir: Path::new("/tmp/ca"),
                clamd: "/var/run/clamav/clamd.ctl",
            }
        );
        Ok(())
    }

    #[test]
    fn no_mitm_option_means_stage_7_and_says_nothing() -> Result<(), String> {
        let parsed = proxy_args(&[])?;
        assert_eq!(
            mitm_request(
                parsed.mitm_list_path.as_deref(),
                parsed.ca_dir.as_deref(),
                parsed.clamd.as_deref()
            ),
            MitmRequest::Off
        );
        Ok(())
    }

    #[test]
    fn some_mitm_options_name_the_missing_ones() -> Result<(), String> {
        // PK-100: only `--ca-dir` → stage 7, and the two missing names.
        let parsed = proxy_args(&["--ca-dir", "/tmp/ca"])?;
        assert_eq!(
            mitm_request(
                parsed.mitm_list_path.as_deref(),
                parsed.ca_dir.as_deref(),
                parsed.clamd.as_deref()
            ),
            MitmRequest::Partial(vec!["--mitm-list", "--clamd"])
        );
        let parsed = proxy_args(&["--mitm-list", "/tmp/m.txt", "--clamd", "127.0.0.1:3310"])?;
        assert_eq!(
            mitm_request(
                parsed.mitm_list_path.as_deref(),
                parsed.ca_dir.as_deref(),
                parsed.clamd.as_deref()
            ),
            MitmRequest::Partial(vec!["--ca-dir"])
        );
        Ok(())
    }

    #[test]
    fn a_mitm_option_without_its_value_is_an_error() {
        for flag in ["--mitm-list", "--ca-dir", "--clamd"] {
            assert!(proxy_args(&[flag]).is_err(), "{flag}");
        }
    }

    #[test]
    fn parses_block_args_allowlist_flag() -> Result<(), String> {
        // --allowlist が BlockArgs へ渡ることを確かめる。
        let args = vec!["--allowlist".to_string(), "/tmp/al.txt".to_string()];
        let parsed = parse_block_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(parsed.allowlist_path, Some(PathBuf::from("/tmp/al.txt")));
        Ok(())
    }

    #[test]
    fn parses_block_args_without_allowlist_defaults_to_none() -> Result<(), String> {
        // --allowlist 無しでは None のまま（空の allowlist＝従来どおりの挙動）。
        let parsed = parse_block_args(&[]).map_err(|e| e.to_string())?;
        assert_eq!(parsed.allowlist_path, None);
        Ok(())
    }

    #[test]
    fn parses_block_args_iplist_flag() -> Result<(), String> {
        // 段階5：--iplist が BlockArgs へ渡ることを確かめる。
        let args = vec!["--iplist".to_string(), "/tmp/ip.txt".to_string()];
        let parsed = parse_block_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(parsed.iplist_paths, vec![PathBuf::from("/tmp/ip.txt")]);
        assert!(parsed.blocklist_paths.is_empty());
        Ok(())
    }

    #[test]
    fn parses_block_args_without_iplist_defaults_to_none() -> Result<(), String> {
        // PK-50 の陰性対照相当：--iplist 無しでは空のまま。
        let parsed = parse_block_args(&[]).map_err(|e| e.to_string())?;
        assert!(parsed.iplist_paths.is_empty());
        Ok(())
    }

    #[test]
    fn parses_block_args_eve_ips_sids_and_ttl() -> Result<(), String> {
        // 段階4：--eve / --ips-sids / --ips-ttl が BlockArgs へ渡ることを確かめる。
        let args = vec![
            "--eve".to_string(),
            "/tmp/eve.json".to_string(),
            "--ips-sids".to_string(),
            "/tmp/sids.txt".to_string(),
            "--ips-ttl".to_string(),
            "5".to_string(),
        ];
        let parsed = parse_block_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(parsed.eve_path, Some(PathBuf::from("/tmp/eve.json")));
        assert_eq!(parsed.ips_sids_path, Some(PathBuf::from("/tmp/sids.txt")));
        assert_eq!(parsed.ips_ttl_secs, 5);
        Ok(())
    }

    #[test]
    fn parses_block_args_without_eve_defaults_to_none_and_default_ttl() -> Result<(), String> {
        // PK-30 の陰性対照相当：--eve / --ips-sids 無しでは None のまま、
        // --ips-ttl は既定値（300）のまま。
        let parsed = parse_block_args(&[]).map_err(|e| e.to_string())?;
        assert_eq!(parsed.eve_path, None);
        assert_eq!(parsed.ips_sids_path, None);
        assert_eq!(parsed.ips_ttl_secs, DEFAULT_IPS_TTL_SECS);
        Ok(())
    }

    #[test]
    fn parses_block_args_av_flag() -> Result<(), String> {
        // 段階6：--av が BlockArgs へ渡ることを確かめる。
        let args = vec!["--av".to_string(), "/tmp/av.jsonl".to_string()];
        let parsed = parse_block_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(parsed.av_path, Some(PathBuf::from("/tmp/av.jsonl")));
        Ok(())
    }

    #[test]
    fn parses_block_args_without_av_defaults_to_none() -> Result<(), String> {
        // PK-60 の陰性対照相当：--av 無しでは None のまま。
        let parsed = parse_block_args(&[]).map_err(|e| e.to_string())?;
        assert_eq!(parsed.av_path, None);
        Ok(())
    }

    #[test]
    fn parses_block_args_pcapng_and_poll_ms_flags() -> Result<(), String> {
        // 続きを頼む節：--pcapng / --poll-ms が BlockArgs へ渡ることを確かめる。
        let args = vec![
            "--pcapng".to_string(),
            "/tmp/capture.pcapng".to_string(),
            "--poll-ms".to_string(),
            "250".to_string(),
        ];
        let parsed = parse_block_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(
            parsed.pcapng_path,
            Some(PathBuf::from("/tmp/capture.pcapng"))
        );
        assert_eq!(parsed.poll_ms, 250);
        Ok(())
    }

    #[test]
    fn parses_block_args_without_pcapng_defaults_to_none_and_default_poll_ms() -> Result<(), String>
    {
        // --pcapng 無しでは None のまま、--poll-ms は既定値（1000）のまま。
        // `--pcapng` 無しの経路の挙動を変えていないことを確かめる回帰 test。
        let parsed = parse_block_args(&[]).map_err(|e| e.to_string())?;
        assert_eq!(parsed.pcapng_path, None);
        assert_eq!(parsed.poll_ms, DEFAULT_POLL_MS);
        Ok(())
    }

    #[test]
    fn rejects_non_numeric_poll_ms() {
        let args = vec!["--poll-ms".to_string(), "abc".to_string()];
        assert!(matches!(
            parse_block_args(&args),
            Err(CliError::InvalidPollMs(_))
        ));
    }

    #[test]
    fn parses_block_args_ips_severity() -> Result<(), String> {
        let args = vec!["--ips-severity".to_string(), "1".to_string()];
        let parsed = parse_block_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(parsed.ips_severity, Some(1));
        Ok(())
    }

    #[test]
    fn block_args_without_ips_severity_do_not_drop_by_severity() -> Result<(), String> {
        // PK-36a の陰性対照：`--ips-severity` 無しでは None のまま。
        let parsed = parse_block_args(&[]).map_err(|e| e.to_string())?;
        assert_eq!(parsed.ips_severity, None);
        Ok(())
    }

    #[test]
    fn rejects_ips_severity_outside_one_to_three() {
        for value in ["0", "4", "-1", "abc", "", "256"] {
            let args = vec!["--ips-severity".to_string(), value.to_string()];
            assert!(
                matches!(
                    parse_block_args(&args),
                    Err(CliError::InvalidIpsSeverity(_))
                ),
                "value={value:?}"
            );
        }
    }

    #[test]
    fn ips_severity_without_a_value_is_missing_value() {
        let args = vec!["--ips-severity".to_string()];
        assert!(matches!(
            parse_block_args(&args),
            Err(CliError::MissingValue("--ips-severity"))
        ));
    }

    #[test]
    fn rejects_non_numeric_ips_ttl() {
        let args = vec!["--ips-ttl".to_string(), "abc".to_string()];
        assert!(matches!(
            parse_block_args(&args),
            Err(CliError::InvalidIpsTtl(_))
        ));
    }

    #[test]
    fn parses_queue_filter_and_log_dir_flags() -> Result<(), String> {
        let args = vec![
            "--queue".to_string(),
            "7".to_string(),
            "--filter".to_string(),
            "tcp.DstPort == 443".to_string(),
            "--log-dir".to_string(),
            "/tmp/pdlog".to_string(),
        ];
        let parsed = parse_observe_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(parsed.queue_num, 7);
        assert_eq!(parsed.filter.as_deref(), Some("tcp.DstPort == 443"));
        assert_eq!(parsed.log_dir, Some(PathBuf::from("/tmp/pdlog")));
        Ok(())
    }

    #[test]
    fn rejects_unknown_flag() {
        let args = vec!["--bogus".to_string()];
        assert!(matches!(
            parse_observe_args(&args),
            Err(CliError::UnknownFlag(_))
        ));
    }

    #[test]
    fn rejects_missing_value_for_queue() {
        let args = vec!["--queue".to_string()];
        assert!(matches!(
            parse_observe_args(&args),
            Err(CliError::MissingValue("--queue"))
        ));
    }

    #[test]
    fn rejects_non_numeric_queue() {
        let args = vec!["--queue".to_string(), "abc".to_string()];
        assert!(matches!(
            parse_observe_args(&args),
            Err(CliError::InvalidQueueNum(_))
        ));
    }

    #[test]
    fn ps4_service_args_rejects_missing_log_dir() {
        // PS-4：--log-dir 無しでは起動しない。
        assert!(matches!(
            parse_service_args(&[]),
            Err(CliError::MissingRequiredArg("--log-dir"))
        ));
    }

    #[test]
    fn parses_service_args_log_dir() -> Result<(), String> {
        let args = vec!["--log-dir".to_string(), "/tmp/pdsvc".to_string()];
        let parsed = parse_service_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(parsed.log_dir, PathBuf::from("/tmp/pdsvc"));
        assert_eq!(parsed.pcapng_path, None);
        assert_eq!(parsed.blocklist_path, None);
        Ok(())
    }

    #[test]
    fn parses_service_args_pcapng_and_blocklist_are_optional_but_parseable() -> Result<(), String> {
        let args = vec![
            "--log-dir".to_string(),
            "/tmp/pdsvc".to_string(),
            "--pcapng".to_string(),
            "/tmp/capture.pcapng".to_string(),
            "--blocklist".to_string(),
            "/tmp/blocklist.txt".to_string(),
        ];
        let parsed = parse_service_args(&args).map_err(|e| e.to_string())?;
        assert_eq!(
            parsed.pcapng_path,
            Some(PathBuf::from("/tmp/capture.pcapng"))
        );
        assert_eq!(
            parsed.blocklist_path,
            Some(PathBuf::from("/tmp/blocklist.txt"))
        );
        Ok(())
    }

    #[test]
    fn rejects_missing_value_for_pcapng() {
        let args = vec![
            "--log-dir".to_string(),
            "/tmp/pdsvc".to_string(),
            "--pcapng".to_string(),
        ];
        assert!(matches!(
            parse_service_args(&args),
            Err(CliError::MissingValue("--pcapng"))
        ));
    }

    #[test]
    fn rejects_unknown_flag_for_service_args() {
        let args = vec!["--bogus".to_string()];
        assert!(matches!(
            parse_service_args(&args),
            Err(CliError::UnknownFlag(_))
        ));
    }
}
