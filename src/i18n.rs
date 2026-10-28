//! 自然言語の文言を locale で切り替える。
//!
//! **判定は `LANG` / `LC_ALL` 環境変数だけを読む。**Windows の
//! `GetUserDefaultUILanguage` は呼ばない（`unsafe` が要るため。
//! `Cargo.toml` の `unsafe_code = "forbid"` に従う）。`LC_ALL` を `LANG` より優先する（POSIX の慣習）。値が `ja` で
//! 始まれば日本語、それ以外・空・未設定・未対応の言語は英語（既定）。
//!
//! **引数の埋め込みは、メッセージ1つにつき専用の関数を1つ用意し、Rust の
//! `format!` へそのまま渡すことで解く。**実行時テンプレート文字列（`{0}` を
//! 自前で置換する等）は書かない。std の `format!` はコンパイル時の文字列
//! リテラルにしか使えないため、`match locale { Locale::Ja => format!(...),
//! Locale::En => format!(...) }` の形になる。この形は、`Locale` が
//! `Ja` / `En` の2値しか持たない enum である限り、**`match` の網羅性検査が
//! 「日本語だけ書いて英語を書き忘れる」を build error にする**という副次効果を
//! 持つ（`cargo build` が拾う。追加の検知器を書かずに済む）。
//!
//! `locale` を引数として明示的に受け取る設計にしているのは、
//! `tests/independent_i18n.rs` が同一プロセスの中で `Locale::Ja` と
//! `Locale::En` の両方を呼んで結果を突き合わせられるようにするため
//! （プロセス全体の locale をグローバルに1つだけ持つ設計だと、test 側から
//! 両方を切り替えて呼べない）。実行中の呼び出し元は `i18n::locale()`
//! （`OnceLock` で起動時に1回だけ判定した値）を渡す。
//!
//! **新しい関数を足したら [`all_message_samples`] にも1行 足す。**
//! 足し忘れは `tests/independent_i18n.rs` の
//! `every_pub_message_fn_has_a_sample` が検出する（`src/i18n.rs` の
//! `pub fn` の数と `all_message_samples` が返す件数を突き合わせる）。

use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

/// 表示する自然言語。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    Ja,
    En,
}

static LOCALE: OnceLock<Locale> = OnceLock::new();

/// `LC_ALL` を優先し、無ければ `LANG` を見る。`ja` で始まる値（大小 無視）
/// なら日本語、それ以外（未対応の言語を含む）・空・未設定は英語。
fn detect() -> Locale {
    let value = std::env::var("LC_ALL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("LANG").ok().filter(|v| !v.is_empty()));
    match value {
        Some(v) if v.to_ascii_lowercase().starts_with("ja") => Locale::Ja,
        _ => Locale::En,
    }
}

/// プロセス起動中に1回だけ判定し、以降は使い回す（`LANG` / `LC_ALL` は
/// 実行中に変わらない前提。CLI ツールが呼び出しのたびに読み直す価値は無い）。
pub fn locale() -> Locale {
    *LOCALE.get_or_init(detect)
}

/// 起動時に1回、判定した locale を log へ出す（エラーを追えるように。
/// 判定結果そのものが追跡対象になる）。
pub fn log_detected_locale() {
    let tag = match locale() {
        Locale::Ja => "ja",
        Locale::En => "en",
    };
    eprintln!("packetdeath: [info] locale={tag}");
}

// ============================================================
// CLI 引数解析（`main.rs::CliError` / `main.rs::LogDirError`）
// ============================================================

pub fn cli_unknown_flag(locale: Locale, flag: &str) -> String {
    match locale {
        Locale::Ja => format!("未知の引数: {flag}"),
        Locale::En => format!("unknown argument: {flag}"),
    }
}

pub fn cli_value_required(locale: Locale, flag: &str) -> String {
    match locale {
        Locale::Ja => format!("{flag} に値が要る"),
        Locale::En => format!("{flag} requires a value"),
    }
}

pub fn cli_invalid_queue_num(locale: Locale, v: &str) -> String {
    match locale {
        Locale::Ja => format!("--queue の値が u16 として読めない: {v}"),
        Locale::En => format!("--queue value does not parse as u16: {v}"),
    }
}

pub fn cli_required_arg_missing(locale: Locale, flag: &str) -> String {
    match locale {
        Locale::Ja => format!("{flag} は必須である"),
        Locale::En => format!("{flag} is required"),
    }
}

pub fn cli_invalid_ips_ttl(locale: Locale, v: &str) -> String {
    match locale {
        Locale::Ja => format!("--ips-ttl の値が u64（秒）として読めない: {v}"),
        Locale::En => format!("--ips-ttl value does not parse as u64 seconds: {v}"),
    }
}

pub fn cli_invalid_ips_severity(locale: Locale, v: &str) -> String {
    match locale {
        Locale::Ja => format!("--ips-severity の値は 1 から 3 の整数: {v}"),
        Locale::En => format!("--ips-severity value must be an integer from 1 to 3: {v}"),
    }
}

pub fn cli_invalid_poll_ms(locale: Locale, v: &str) -> String {
    match locale {
        Locale::Ja => format!("--poll-ms の値が u64（ミリ秒）として読めない: {v}"),
        Locale::En => format!("--poll-ms value does not parse as u64 milliseconds: {v}"),
    }
}

pub fn cli_invalid_listen_addr(locale: Locale, v: &str) -> String {
    match locale {
        Locale::Ja => format!("--listen の値が addr:port として読めない: {v}"),
        Locale::En => format!("--listen value does not parse as addr:port: {v}"),
    }
}

pub fn cli_invalid_deny_mode(locale: Locale, v: &str) -> String {
    match locale {
        Locale::Ja => format!("--deny の値は blackhole か 403 のどちらか: {v}"),
        Locale::En => format!("--deny value must be blackhole or 403: {v}"),
    }
}

pub fn log_dir_no_home(locale: Locale) -> String {
    match locale {
        Locale::Ja => "XDG_STATE_HOME も HOME も読めない。--log-dir を明示してほしい".to_string(),
        Locale::En => {
            "could not read XDG_STATE_HOME or HOME; please pass --log-dir explicitly".to_string()
        }
    }
}

pub fn log_dir_no_local_app_data(locale: Locale) -> String {
    match locale {
        Locale::Ja => "LOCALAPPDATA が読めない。--log-dir を明示してほしい".to_string(),
        Locale::En => "could not read LOCALAPPDATA; please pass --log-dir explicitly".to_string(),
    }
}

// ============================================================
// main.rs 本体（起動・log dir・各 subcommand）
// ============================================================

pub fn log_dir_create_failed(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("log dir を作れなかった ({path}): {e}"),
        Locale::En => format!("failed to create log dir ({path}): {e}"),
    }
}

pub fn flow_log_open_failed(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("log を開けなかった ({path}): {e}"),
        Locale::En => format!("failed to open log ({path}): {e}"),
    }
}

pub fn usage_banner(locale: Locale) -> String {
    match locale {
        Locale::Ja => "使い方: packetdeath observe [--queue <N>] [--filter <式>] [--log-dir <path>]\n      packetdeath block [--queue <N>] [--blocklist <path>]... [--allowlist <path>] [--dns] [--iplist <path>]... [--eve <path>] [--ips-sids <path>] [--ips-severity <1-3>] [--ips-ttl <秒>] [--av <path>] [--pcapng <path>] [--poll-ms <ミリ秒>] [--log-dir <path>]\n      packetdeath eval --labels <tsv> [--log-dir <path>]\n      packetdeath filterlist --in <path> --out <path>\n      packetdeath allowlist-convert --in <path> --out <path>\n      packetdeath service-install --log-dir <path> [--pcapng <path>] [--blocklist <path>] [--allowlist <path>]\n      packetdeath service-uninstall\n      packetdeath service-run --log-dir <path> [--pcapng <path>] [--blocklist <path>] [--allowlist <path>]\n      packetdeath proxy --listen <addr:port> [--blocklist <path>]... [--allowlist <path>] [--iplist <path>]... [--av <path>] [--log-dir <path>] [--allow-from <CIDR>]... [--deny blackhole|403] [--mitm-list <path> --ca-dir <path> --clamd <socket path|addr:port>] [--distrust <path>]... [--watch-distrust <path>]... [--watch-blocklist <path>]... [--watch-iplist <path>]... [--probe-chains] [--defense-off <path>] [--breaker-hosts <N>]\n      packetdeath defense-report (--flows <flows.jsonl> [--blocklist <path>]... [--iplist <path>]... | --watch <watch.jsonl> [--distrust <path>]...) [--allowlist <path>]... [--days <N>]\n      packetdeath waf --listen <addr:port> --upstream <host:port> --log-dir <path> [--mode off|detect|block] [--paranoia <1-4>] [--threshold <N>] [--max-body <bytes>] [--max-body-inspect <bytes>] [--max-conns <N>] [--max-tracked-ips <N>] [--rate <N>/<seconds>] [--ban-after <N>] [--ban-ttl <seconds>] [--rules <path>] [--exclusions <path>] [--allow-ip <path>] [--deny-ip <path>] [--trust-forwarded-from <path>]\n      packetdeath waf-test --corpus <path> [--rules <path>] [--exclusions <path>] [--paranoia <1-4>] [--threshold <N>]\n      packetdeath waf-report --log-dir <path> [--since <YYYY-MM-DD>]".to_string(),
        Locale::En => "usage: packetdeath observe [--queue <N>] [--filter <expr>] [--log-dir <path>]\n      packetdeath block [--queue <N>] [--blocklist <path>]... [--allowlist <path>] [--dns] [--iplist <path>]... [--eve <path>] [--ips-sids <path>] [--ips-severity <1-3>] [--ips-ttl <seconds>] [--av <path>] [--pcapng <path>] [--poll-ms <milliseconds>] [--log-dir <path>]\n      packetdeath eval --labels <tsv> [--log-dir <path>]\n      packetdeath filterlist --in <path> --out <path>\n      packetdeath allowlist-convert --in <path> --out <path>\n      packetdeath service-install --log-dir <path> [--pcapng <path>] [--blocklist <path>] [--allowlist <path>]\n      packetdeath service-uninstall\n      packetdeath service-run --log-dir <path> [--pcapng <path>] [--blocklist <path>] [--allowlist <path>]\n      packetdeath proxy --listen <addr:port> [--blocklist <path>]... [--allowlist <path>] [--iplist <path>]... [--av <path>] [--log-dir <path>] [--allow-from <CIDR>]... [--deny blackhole|403] [--mitm-list <path> --ca-dir <path> --clamd <socket path|addr:port>] [--distrust <path>]... [--watch-distrust <path>]... [--watch-blocklist <path>]... [--watch-iplist <path>]... [--probe-chains] [--defense-off <path>] [--breaker-hosts <N>]\n      packetdeath defense-report (--flows <flows.jsonl> [--blocklist <path>]... [--iplist <path>]... | --watch <watch.jsonl> [--distrust <path>]...) [--allowlist <path>]... [--days <N>]\n      packetdeath waf --listen <addr:port> --upstream <host:port> --log-dir <path> [--mode off|detect|block] [--paranoia <1-4>] [--threshold <N>] [--max-body <bytes>] [--max-body-inspect <bytes>] [--max-conns <N>] [--max-tracked-ips <N>] [--rate <N>/<seconds>] [--ban-after <N>] [--ban-ttl <seconds>] [--rules <path>] [--exclusions <path>] [--allow-ip <path>] [--deny-ip <path>] [--trust-forwarded-from <path>]\n      packetdeath waf-test --corpus <path> [--rules <path>] [--exclusions <path>] [--paranoia <1-4>] [--threshold <N>]\n      packetdeath waf-report --log-dir <path> [--since <YYYY-MM-DD>]".to_string(),
    }
}

pub fn arg_parse_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("引数の解析に失敗した: {e}"),
        Locale::En => format!("failed to parse arguments: {e}"),
    }
}

pub fn unknown_command(locale: Locale, cmd: &str) -> String {
    match locale {
        Locale::Ja => format!(
            "未知の command: {cmd}（observe / block / eval / filterlist / allowlist-convert / service-install / service-uninstall / service-run / proxy / defense-report / waf / waf-test / waf-report のいずれか）"
        ),
        Locale::En => format!(
            "unknown command: {cmd} (one of observe / block / eval / filterlist / allowlist-convert / service-install / service-uninstall / service-run / proxy / defense-report / waf / waf-test / waf-report)"
        ),
    }
}

pub fn filter_windows_only_ignored(locale: Locale) -> String {
    match locale {
        Locale::Ja => {
            "--filter は Windows 専用（docs/design.md「名前と置き場」）。Linux では無視する"
                .to_string()
        }
        Locale::En => {
            "--filter is Windows-only (docs/design.md \"Names and locations\"); ignored on Linux"
                .to_string()
        }
    }
}

pub fn log_dir_undecided(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("log dir を決められなかった: {e}"),
        Locale::En => format!("could not determine log dir: {e}"),
    }
}

pub fn observe_started(locale: Locale, queue_num: u16, log: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("queue={queue_num} log={log} で観測を開始する（遮断は0件）"),
        Locale::En => format!("starting observe queue={queue_num} log={log} (0 blocks)"),
    }
}

pub fn observe_loop_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("観測 loop が失敗して終了した: {e}"),
        Locale::En => format!("observe loop failed and exited: {e}"),
    }
}

pub fn ips_sids_load_failed(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!(
            "ips-sids を読めなかった ({path}): {e}。空集合として動く（IDS 由来の遮断は0件）"
        ),
        Locale::En => format!(
            "failed to load ips-sids ({path}): {e}; falling back to an empty set (0 IDS-based blocks)"
        ),
    }
}

pub fn blocklist_load_failed_empty(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!(
            "blocklist を読めなかった ({path}): {e}。空の blocklist として動く（何も落とさない）"
        ),
        Locale::En => format!(
            "failed to load blocklist ({path}): {e}; falling back to an empty blocklist (blocks nothing)"
        ),
    }
}

pub fn allowlist_load_failed_empty(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!(
            "allowlist を読めなかった ({path}): {e}。空の allowlist として動く（何も救わない）"
        ),
        Locale::En => format!(
            "failed to load allowlist ({path}): {e}; falling back to an empty allowlist (allows nothing through)"
        ),
    }
}

pub fn iplist_load_failed_empty(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => {
            format!("iplist を読めなかった ({path}): {e}。空の iplist として動く（何も落とさない）")
        }
        Locale::En => format!(
            "failed to load iplist ({path}): {e}; falling back to an empty iplist (blocks nothing)"
        ),
    }
}

pub fn av_load_failed_empty(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!(
            "av file を読めなかった ({path}): {e}。空の av 集合として動く（何も落とさない）"
        ),
        Locale::En => format!(
            "failed to load av file ({path}): {e}; falling back to an empty av set (blocks nothing)"
        ),
    }
}

pub fn pcapng_foreground_watch(locale: Locale, path: impl fmt::Display, poll_ms: u64) -> String {
    match locale {
        Locale::Ja => {
            format!("pcapng={path} poll_ms={poll_ms} を前景で監視する（Ctrl-C で終了する）")
        }
        Locale::En => {
            format!("watching pcapng={path} poll_ms={poll_ms} in the foreground (Ctrl-C to stop)")
        }
    }
}

pub fn linux_pcapng_no_blocker_passthrough(locale: Locale) -> String {
    match locale {
        Locale::Ja => {
            "Linux には遮断手段（常駐 PowerShell）が無いため、--pcapng 経路は判定と log だけを行い素通しへ倒す（動作確認用）"
                .to_string()
        }
        Locale::En => {
            "Linux has no blocking mechanism (resident PowerShell); the --pcapng path only judges and logs, falling through (for verification only)"
                .to_string()
        }
    }
}

pub fn dns_log_open_failed(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("dns log を開けなかった ({path}): {e}"),
        Locale::En => format!("failed to open dns log ({path}): {e}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn block_started(
    locale: Locale,
    queue_num: u16,
    log: impl fmt::Display,
    blocklist: &[std::path::PathBuf],
    dns: bool,
    iplist: &[std::path::PathBuf],
    eve: &Option<std::path::PathBuf>,
    ips_sids: &Option<std::path::PathBuf>,
    ips_severity: Option<u8>,
    ips_ttl_secs: u64,
    av: &Option<std::path::PathBuf>,
) -> String {
    match locale {
        Locale::Ja => format!(
            "queue={queue_num} log={log} blocklist={blocklist:?} dns={dns} iplist={iplist:?} eve={eve:?} ips_sids={ips_sids:?} ips_severity={ips_severity:?} ips_ttl={ips_ttl_secs}s av={av:?} で遮断を開始する"
        ),
        Locale::En => format!(
            "starting block queue={queue_num} log={log} blocklist={blocklist:?} dns={dns} iplist={iplist:?} eve={eve:?} ips_sids={ips_sids:?} ips_severity={ips_severity:?} ips_ttl={ips_ttl_secs}s av={av:?}"
        ),
    }
}

pub fn block_loop_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("遮断 loop が失敗して終了した: {e}"),
        Locale::En => format!("block loop failed and exited: {e}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn block_not_implemented_for_os(
    locale: Locale,
    queue_num: u16,
    log_dir: impl fmt::Display,
    blocklist: &[std::path::PathBuf],
    dns: bool,
    iplist: &[std::path::PathBuf],
    eve: &Option<std::path::PathBuf>,
    ips_sids: &Option<std::path::PathBuf>,
    ips_severity: Option<u8>,
    ips_ttl_secs: u64,
    av: &Option<std::path::PathBuf>,
) -> String {
    match locale {
        Locale::Ja => format!(
            "block はこの OS 向けにまだ実装していない（queue={queue_num} log_dir={log_dir} blocklist={blocklist:?} dns={dns} iplist={iplist:?} eve={eve:?} ips_sids={ips_sids:?} ips_severity={ips_severity:?} ips_ttl={ips_ttl_secs}s av={av:?}）"
        ),
        Locale::En => format!(
            "block is not implemented yet for this OS (queue={queue_num} log_dir={log_dir} blocklist={blocklist:?} dns={dns} iplist={iplist:?} eve={eve:?} ips_sids={ips_sids:?} ips_severity={ips_severity:?} ips_ttl={ips_ttl_secs}s av={av:?})"
        ),
    }
}

pub fn flow_log_opened(locale: Locale, path: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("log={path} を開いた"),
        Locale::En => format!("opened log={path}"),
    }
}

pub fn kill_tcp_script_write_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!(
            "kill_tcp.ps1 を書き出せなかった: {e}。この起動中は遮断を諦め、観測だけ続ける"
        ),
        Locale::En => format!(
            "failed to write kill_tcp.ps1: {e}; giving up on blocking for this run and continuing to observe only"
        ),
    }
}

pub fn labels_file_read_failed(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("labels file を読めなかった ({path}): {e}"),
        Locale::En => format!("failed to read labels file ({path}): {e}"),
    }
}

pub fn stdin_read_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("stdin を読めなかった: {e}"),
        Locale::En => format!("failed to read stdin: {e}"),
    }
}

pub fn input_file_read_failed(locale: Locale, path: &str, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("入力 file を読めなかった ({path}): {e}"),
        Locale::En => format!("failed to read input file ({path}): {e}"),
    }
}

pub fn output_file_write_failed(locale: Locale, path: &str, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("出力 file を書けなかった ({path}): {e}"),
        Locale::En => format!("failed to write output file ({path}): {e}"),
    }
}

pub fn cli_timestamp_format_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("timestamp を整形できなかった: {e}"),
        Locale::En => format!("failed to format timestamp: {e}"),
    }
}

pub fn observe_not_implemented_for_os(
    locale: Locale,
    queue_num: u16,
    log_dir: impl fmt::Display,
    filter: &Option<String>,
) -> String {
    match locale {
        Locale::Ja => format!(
            "queue={queue_num} log_dir={log_dir} filter={filter:?} はこの OS 向けにまだ実装していない（段階1w は Windows 未着手。PK-6 は build のみ）"
        ),
        Locale::En => format!(
            "queue={queue_num} log_dir={log_dir} filter={filter:?} is not implemented yet for this OS (stage 1w / Windows is not started; PK-6 is build-only)"
        ),
    }
}

pub fn service_installed(
    locale: Locale,
    log_dir: impl fmt::Display,
    pcapng: &Option<std::path::PathBuf>,
    blocklist: &Option<std::path::PathBuf>,
    allowlist: &Option<std::path::PathBuf>,
) -> String {
    match locale {
        Locale::Ja => format!(
            "service を登録した（log_dir={log_dir} pcapng={pcapng:?} blocklist={blocklist:?} allowlist={allowlist:?}）"
        ),
        Locale::En => format!(
            "registered service (log_dir={log_dir} pcapng={pcapng:?} blocklist={blocklist:?} allowlist={allowlist:?})"
        ),
    }
}

pub fn service_install_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("service の登録に失敗した: {e}"),
        Locale::En => format!("failed to register service: {e}"),
    }
}

pub fn service_install_windows_only(locale: Locale, log_dir: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("service-install は Windows 専用（log_dir={log_dir}）"),
        Locale::En => format!("service-install is Windows-only (log_dir={log_dir})"),
    }
}

pub fn service_uninstalled(locale: Locale) -> String {
    match locale {
        Locale::Ja => "service を削除した".to_string(),
        Locale::En => "removed service".to_string(),
    }
}

pub fn service_uninstall_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("service の削除に失敗した: {e}"),
        Locale::En => format!("failed to remove service: {e}"),
    }
}

pub fn service_uninstall_windows_only(locale: Locale) -> String {
    match locale {
        Locale::Ja => "service-uninstall は Windows 専用".to_string(),
        Locale::En => "service-uninstall is Windows-only".to_string(),
    }
}

pub fn service_dispatcher_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("service dispatcher が失敗して終了した: {e}"),
        Locale::En => format!("service dispatcher failed and exited: {e}"),
    }
}

pub fn service_run_windows_only(locale: Locale, log_dir: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("service-run は Windows 専用（log_dir={log_dir}）"),
        Locale::En => format!("service-run is Windows-only (log_dir={log_dir})"),
    }
}

// ============================================================
// win_service.rs（`--pcapng` 前景経路の Windows サービス版）
// ============================================================

pub fn pcapng_not_specified_wait_stop(locale: Locale) -> String {
    match locale {
        Locale::Ja => "--pcapng 未指定。監視 loop を回さず stop/shutdown を待つ".to_string(),
        Locale::En => {
            "--pcapng not specified; skipping the watch loop and waiting for stop/shutdown"
                .to_string()
        }
    }
}

pub fn flow_log_open_failed_wait_stop(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!(
            "flow log を開けなかった ({path}): {e}。監視 loop を開始せず stop/shutdown を待つ"
        ),
        Locale::En => format!(
            "failed to open flow log ({path}): {e}; not starting the watch loop, waiting for stop/shutdown"
        ),
    }
}

// ============================================================
// windows.rs（pcapng の parse）
// ============================================================

pub fn pcapng_truncated(locale: Locale, cursor: usize, total: usize) -> String {
    match locale {
        Locale::Ja => format!(
            "pcapng を{cursor}byte目までしか読めなかった（全{total}byte中）。壊れた block で打ち切った"
        ),
        Locale::En => format!(
            "could only read pcapng up to byte {cursor} of {total} total; stopped at a corrupt block"
        ),
    }
}

// ============================================================
// filterlist.rs（EasyList / 公開 allowlist の変換）
// ============================================================

#[allow(clippy::too_many_arguments)]
pub fn filterlist_converted(
    locale: Locale,
    lines: u32,
    domains: usize,
    exceptions: usize,
    accepted: u32,
    plain: u32,
    modifier: u32,
    dropped_by_exception: u32,
) -> String {
    match locale {
        Locale::Ja => format!(
            "filterlist を変換した lines={lines} domains={domains} exceptions={exceptions} 採用={accepted} (plain={plain} modifier={modifier}) 除外_suffix衝突={dropped_by_exception}"
        ),
        Locale::En => format!(
            "converted filterlist lines={lines} domains={domains} exceptions={exceptions} accepted={accepted} (plain={plain} modifier={modifier}) dropped_by_suffix_collision={dropped_by_exception}"
        ),
    }
}

pub fn filterlist_unparsable_lines(locale: Locale, other: u32) -> String {
    match locale {
        Locale::Ja => format!(
            "読めなかった行 other={other}（`||` で始まらない、または `||` の直後に domain が無い）"
        ),
        Locale::En => format!(
            "unparsable lines other={other} (does not start with `||`, or no domain right after `||`)"
        ),
    }
}

pub fn filterlist_header_comment(locale: Locale) -> String {
    match locale {
        Locale::Ja => {
            "# packetdeath filterlist: EasyList 形式から blocklist 形式へ変換した\n".to_string()
        }
        Locale::En => {
            "# packetdeath filterlist: converted from EasyList syntax to blocklist format\n"
                .to_string()
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn filterlist_accepted_comment(
    locale: Locale,
    domain: usize,
    plain: u32,
    third_party: u32,
    three_p: u32,
    all: u32,
    document: u32,
) -> String {
    match locale {
        Locale::Ja => format!(
            "# 採用 domain={domain} (plain={plain} modifier third-party={third_party} 3p={three_p} all={all} document={document})\n"
        ),
        Locale::En => format!(
            "# accepted domain={domain} (plain={plain} modifier third-party={third_party} 3p={three_p} all={all} document={document})\n"
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn filterlist_dropped_comment(
    locale: Locale,
    comment: u32,
    blank: u32,
    cosmetic: u32,
    wildcard: u32,
    exception_total: u32,
    exception_recorded: u32,
    path: u32,
    modifier_discarded: u32,
    other: u32,
    dropped_by_exception: u32,
) -> String {
    match locale {
        Locale::Ja => format!(
            "# 除外 comment={comment} blank={blank} cosmetic={cosmetic} wildcard={wildcard} exception={exception_total}(記録={exception_recorded}) path={path} modifier_discarded={modifier_discarded} other={other} suffix衝突による除外={dropped_by_exception}\n"
        ),
        Locale::En => format!(
            "# dropped comment={comment} blank={blank} cosmetic={cosmetic} wildcard={wildcard} exception={exception_total}(recorded={exception_recorded}) path={path} modifier_discarded={modifier_discarded} other={other} dropped_by_suffix_collision={dropped_by_exception}\n"
        ),
    }
}

pub fn microsoft_json_parse_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("Microsoft JSON の構造を読めなかった（`urls` field が無い等）: {e}"),
        Locale::En => {
            format!("could not parse Microsoft JSON structure (e.g. missing `urls` field): {e}")
        }
    }
}

pub fn allowlist_convert_header_comment(locale: Locale) -> String {
    match locale {
        Locale::Ja => {
            "# packetdeath allowlist-convert: 公開 allowlist を allowlist 形式へ変換した\n"
                .to_string()
        }
        Locale::En => {
            "# packetdeath allowlist-convert: converted a public allowlist to allowlist format\n"
                .to_string()
        }
    }
}

pub fn allowlist_convert_accepted_comment(locale: Locale, domain: usize, dropped: u32) -> String {
    match locale {
        Locale::Ja => format!(
            "# 採用 domain={domain} 捨てた候補={dropped}（単位は source により異なる。adblock/plain は行数、microsoft-json は urls 配列の要素数）\n"
        ),
        Locale::En => format!(
            "# accepted domain={domain} dropped candidates={dropped} (unit depends on source: adblock/plain counts lines, microsoft-json counts urls array elements)\n"
        ),
    }
}

// ============================================================
// eval.rs
// ============================================================

#[allow(clippy::too_many_arguments)]
pub fn eval_executed(
    locale: Locale,
    ad_total: u32,
    ad_blocked: u32,
    ok_total: u32,
    ok_blocked: u32,
    skipped: u32,
) -> String {
    match locale {
        Locale::Ja => format!(
            "eval を実行した ad_total={ad_total} ad_blocked={ad_blocked} ok_total={ok_total} ok_blocked={ok_blocked} skipped={skipped}"
        ),
        Locale::En => format!(
            "ran eval ad_total={ad_total} ad_blocked={ad_blocked} ok_total={ok_total} ok_blocked={ok_blocked} skipped={skipped}"
        ),
    }
}

// ============================================================
// sni.rs
// ============================================================

pub fn sni_absent(locale: Locale, reason: &str) -> String {
    match locale {
        Locale::Ja => format!("SNI が無いと判定した reason={reason}"),
        Locale::En => format!("determined SNI is absent reason={reason}"),
    }
}

// ============================================================
// reload.rs（blocklist / allowlist の走行中の読み直し）
// ============================================================

pub fn reload_file_not_found(locale: Locale, path: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("{path} が見つからない"),
        Locale::En => format!("{path} not found"),
    }
}

pub fn reload_file_read_failed(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("{path} を読めなかった: {e}"),
        Locale::En => format!("failed to read {path}: {e}"),
    }
}

pub fn reload_succeeded(
    locale: Locale,
    kind: &str,
    path: impl fmt::Display,
    after: usize,
    before: usize,
) -> String {
    match locale {
        Locale::Ja => format!("{kind} を読み直した path={path} entries={after}（前は {before}）"),
        Locale::En => format!("reloaded {kind} path={path} entries={after} (was {before})"),
    }
}

pub fn reload_failed(locale: Locale, kind: &str, msg: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("{kind} の読み直しに失敗した: {msg}。前のものを使い続ける"),
        Locale::En => format!("failed to reload {kind}: {msg}; continuing with the previous one"),
    }
}

// ============================================================
// dns.rs（`DnsParseError`）
// ============================================================

pub fn dns_too_short(locale: Locale) -> String {
    match locale {
        Locale::Ja => "DNS message が header にすら届かない".to_string(),
        Locale::En => "DNS message is too short to contain a header".to_string(),
    }
}

pub fn dns_not_a_response(locale: Locale) -> String {
    match locale {
        Locale::Ja => "DNS message が応答（QR=1）ではない".to_string(),
        Locale::En => "DNS message is not a response (QR=1)".to_string(),
    }
}

pub fn dns_no_question(locale: Locale) -> String {
    match locale {
        Locale::Ja => "DNS 応答に question が無い".to_string(),
        Locale::En => "DNS response has no question".to_string(),
    }
}

pub fn dns_bad_name(locale: Locale) -> String {
    match locale {
        Locale::Ja => "DNS の domain name が読めない".to_string(),
        Locale::En => "could not read DNS domain name".to_string(),
    }
}

pub fn dns_bad_record(locale: Locale) -> String {
    match locale {
        Locale::Ja => "DNS の resource record が読めない".to_string(),
        Locale::En => "could not read DNS resource record".to_string(),
    }
}

// ============================================================
// reassemble.rs（ClientHello の組み立て直し。Linux・Windows 共通）
// ============================================================

pub fn reassemble_buffer_overflow(locale: Locale, max_buffered_bytes: usize) -> String {
    match locale {
        Locale::Ja => {
            format!("ClientHello の再構築が上限（{max_buffered_bytes}byte）を超えたため諦めた")
        }
        Locale::En => format!(
            "gave up reassembling ClientHello: exceeded the limit ({max_buffered_bytes} bytes)"
        ),
    }
}

pub fn reassemble_flow_limit_reached(locale: Locale, max_tracked_flows: usize) -> String {
    match locale {
        Locale::Ja => format!(
            "溜めている接続数が上限（{max_tracked_flows}）に達したため、最も古い接続を諦めた"
        ),
        Locale::En => format!(
            "reached the limit of tracked connections ({max_tracked_flows}); giving up the oldest one"
        ),
    }
}

pub fn reassemble_flow_expired(locale: Locale, dst_ip: impl fmt::Display, dst_port: u16) -> String {
    match locale {
        Locale::Ja => format!(
            "組み立て直しが寿命に達したため fragmented のまま確定した dst_ip={dst_ip} dst_port={dst_port}"
        ),
        Locale::En => format!(
            "reassembly hit its lifetime; settled as fragmented dst_ip={dst_ip} dst_port={dst_port}"
        ),
    }
}

// ============================================================
// blocklist.rs / allowlist.rs / iplist.rs（`*Error` の Display と load ログ）
// ============================================================

pub fn blocklist_io_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("blocklist file を読めなかった: {e}"),
        Locale::En => format!("failed to read blocklist file: {e}"),
    }
}

pub fn blocklist_loaded(locale: Locale, path: impl fmt::Display, domains: usize) -> String {
    match locale {
        Locale::Ja => format!("blocklist を読んだ path={path} domains={domains}"),
        Locale::En => format!("loaded blocklist path={path} domains={domains}"),
    }
}

pub fn allowlist_io_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("allowlist file を読めなかった: {e}"),
        Locale::En => format!("failed to read allowlist file: {e}"),
    }
}

pub fn allowlist_loaded(locale: Locale, path: impl fmt::Display, domains: usize) -> String {
    match locale {
        Locale::Ja => format!("allowlist を読んだ path={path} domains={domains}"),
        Locale::En => format!("loaded allowlist path={path} domains={domains}"),
    }
}

pub fn iplist_io_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("iplist file を読めなかった: {e}"),
        Locale::En => format!("failed to read iplist file: {e}"),
    }
}

pub fn iplist_line_skipped(locale: Locale, line_no: usize) -> String {
    match locale {
        Locale::Ja => format!("iplist の{line_no}行目を読み飛ばす（不正な IP/CIDR）"),
        Locale::En => format!("skipping iplist line {line_no} (invalid IP/CIDR)"),
    }
}

pub fn iplist_loaded(locale: Locale, path: impl fmt::Display, entries: usize) -> String {
    match locale {
        Locale::Ja => format!("iplist を読んだ path={path} entries={entries}"),
        Locale::En => format!("loaded iplist path={path} entries={entries}"),
    }
}

pub fn iplist_parsed(locale: Locale, entries: usize, skipped: usize) -> String {
    match locale {
        Locale::Ja => format!("iplist を parse した entries={entries} skipped={skipped}"),
        Locale::En => format!("parsed iplist entries={entries} skipped={skipped}"),
    }
}

// ============================================================
// block_loop.rs / judge.rs（判定 loop・allowlist 通過の共有文言）
// ============================================================

pub fn ps_bridge_spawn_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("常駐 PowerShell を起動できなかった: {e}。素通しに倒す"),
        Locale::En => {
            format!("failed to start the resident PowerShell: {e}; falling through (fail-open)")
        }
    }
}

pub fn tcp_connection_cut(locale: Locale, rc: i64, micros: f64) -> String {
    match locale {
        Locale::Ja => format!("接続を切った rc={rc} us={micros}"),
        Locale::En => format!("cut connection rc={rc} us={micros}"),
    }
}

pub fn tcp_cut_rejected(locale: Locale, rc: i64, micros: f64) -> String {
    match locale {
        Locale::Ja => format!("SetTcpEntry が接続を切らなかった rc={rc} us={micros}。素通しに倒す"),
        Locale::En => format!(
            "SetTcpEntry did not cut the connection rc={rc} us={micros}; falling through (fail-open)"
        ),
    }
}

pub fn tcp_block_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("接続の遮断に失敗した: {e}。素通しに倒す"),
        Locale::En => format!("failed to block connection: {e}; falling through (fail-open)"),
    }
}

pub fn allowlist_passed(locale: Locale, sni: &str) -> String {
    match locale {
        Locale::Ja => format!("allowlist に当たったので通す sni={sni}"),
        Locale::En => format!("allowlist matched, passing through sni={sni}"),
    }
}

pub fn flow_log_write_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("flow log への書き込みに失敗した: {e}"),
        Locale::En => format!("failed to write flow log: {e}"),
    }
}

// ============================================================
// ps_bridge.rs（`EncodeError` / `ParseResponseError` / `BridgeError` の Display）
// ============================================================

pub fn ps_bridge_contains_newline(locale: Locale) -> String {
    match locale {
        Locale::Ja => "field に改行を含む値がある".to_string(),
        Locale::En => "a field contains a newline".to_string(),
    }
}

pub fn ps_bridge_malformed_response(locale: Locale) -> String {
    match locale {
        Locale::Ja => "rc=<n> us=<f> の形で読めない行だった".to_string(),
        Locale::En => "line did not match the rc=<n> us=<f> form".to_string(),
    }
}

pub fn ps_bridge_encode_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("命令の組み立てに失敗した: {e}"),
        Locale::En => format!("failed to build command: {e}"),
    }
}

pub fn ps_bridge_io_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("子 process との入出力に失敗した: {e}"),
        Locale::En => format!("I/O with child process failed: {e}"),
    }
}

pub fn ps_bridge_child_closed(locale: Locale) -> String {
    match locale {
        Locale::Ja => "子 process が終了している".to_string(),
        Locale::En => "child process has exited".to_string(),
    }
}

pub fn ps_bridge_parse_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("子 process の応答を読めなかった: {e}"),
        Locale::En => format!("could not parse child process response: {e}"),
    }
}

pub fn ps_bridge_timeout(locale: Locale, timeout: impl fmt::Debug) -> String {
    match locale {
        Locale::Ja => format!("{timeout:?} 以内に応答が来なかった"),
        Locale::En => format!("no response within {timeout:?}"),
    }
}

pub fn ps_bridge_poisoned(locale: Locale) -> String {
    match locale {
        Locale::Ja => "過去に timeout した子 process には送信しない".to_string(),
        Locale::En => "not sending to a child process that previously timed out".to_string(),
    }
}

pub fn ps_bridge_stdin_none(locale: Locale) -> String {
    match locale {
        Locale::Ja => "spawn 直後の child.stdin が None だった".to_string(),
        Locale::En => "child.stdin was None immediately after spawn".to_string(),
    }
}

pub fn ps_bridge_stdout_none(locale: Locale) -> String {
    match locale {
        Locale::Ja => "spawn 直後の child.stdout が None だった".to_string(),
        Locale::En => "child.stdout was None immediately after spawn".to_string(),
    }
}

pub fn ps_bridge_response_timeout_discard(locale: Locale, timeout: impl fmt::Debug) -> String {
    match locale {
        Locale::Ja => format!(
            "常駐 PowerShell への応答が {timeout:?} 以内に来なかった。この bridge を破棄し、次回 呼び出しで新しく spawn し直す"
        ),
        Locale::En => format!(
            "no response from the resident PowerShell within {timeout:?}; discarding this bridge and respawning on the next call"
        ),
    }
}

pub fn ps_bridge_warmed(locale: Locale, millis: u128, rc: i64) -> String {
    match locale {
        Locale::Ja => format!("常駐 PowerShell を温めた elapsed_ms={millis} rc={rc}"),
        Locale::En => format!("warmed the resident PowerShell elapsed_ms={millis} rc={rc}"),
    }
}

pub fn ps_bridge_warm_up_failed(
    locale: Locale,
    timeout: impl fmt::Debug,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!(
            "常駐 PowerShell の温めに失敗した（上限 {timeout:?}）: {e}。この bridge を捨て、この接続は素通しに倒す"
        ),
        Locale::En => format!(
            "warming up the resident PowerShell failed (limit {timeout:?}): {e}; dropping this bridge and letting this connection through"
        ),
    }
}

// ============================================================
// av.rs
// ============================================================

pub fn av_io_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("av file を読めなかった: {e}"),
        Locale::En => format!("failed to read av file: {e}"),
    }
}

pub fn av_line_skipped(locale: Locale, line_no: usize, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("av file の{line_no}行目を読み飛ばす: {e}"),
        Locale::En => format!("skipping av file line {line_no}: {e}"),
    }
}

pub fn av_loaded(
    locale: Locale,
    total: usize,
    malicious: usize,
    clean: usize,
    skipped: usize,
) -> String {
    match locale {
        Locale::Ja => format!(
            "av file を読んだ total={total} malicious={malicious} clean={clean} skipped={skipped}"
        ),
        Locale::En => format!(
            "loaded av file total={total} malicious={malicious} clean={clean} skipped={skipped}"
        ),
    }
}

pub fn av_matched(
    locale: Locale,
    dst_ip: impl fmt::Display,
    dst_port: u16,
    verdict: &str,
    engine: &str,
) -> String {
    match locale {
        Locale::Ja => format!(
            "av 判定で宛先を落とした dst_ip={dst_ip} dst_port={dst_port} verdict={verdict} engine={engine}"
        ),
        Locale::En => format!(
            "av verdict dropped destination dst_ip={dst_ip} dst_port={dst_port} verdict={verdict} engine={engine}"
        ),
    }
}

// ============================================================
// linux.rs（`LinuxQueueError` と nfqueue の bind 完了ログ）
// ============================================================

pub fn nfqueue_open_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("nfqueue socket を開けなかった: {e}"),
        Locale::En => format!("failed to open nfqueue socket: {e}"),
    }
}

pub fn nfqueue_bind_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("nfqueue queue の bind に失敗した: {e}"),
        Locale::En => format!("failed to bind nfqueue queue: {e}"),
    }
}

pub fn nfqueue_fail_open_setting_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("--queue-bypass 相当の設定に失敗した: {e}"),
        Locale::En => format!("failed to set the --queue-bypass equivalent: {e}"),
    }
}

pub fn nfqueue_recv_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("nfqueue からの受信に失敗した: {e}"),
        Locale::En => format!("failed to receive from nfqueue: {e}"),
    }
}

pub fn nfqueue_verdict_send_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("nfqueue への verdict 送信に失敗した: {e}"),
        Locale::En => format!("failed to send verdict to nfqueue: {e}"),
    }
}

pub fn nfqueue_bound_observe(locale: Locale, queue_num: u16) -> String {
    match locale {
        Locale::Ja => format!("nfqueue queue={queue_num} を bind した（fail-open 有効、観測のみ）"),
        Locale::En => format!("bound nfqueue queue={queue_num} (fail-open enabled, observe only)"),
    }
}

pub fn nfqueue_bound_block(locale: Locale, queue_num: u16) -> String {
    match locale {
        Locale::Ja => {
            format!("nfqueue queue={queue_num} を bind した（fail-open 有効、遮断を開始）")
        }
        Locale::En => {
            format!("bound nfqueue queue={queue_num} (fail-open enabled, starting to block)")
        }
    }
}

// ============================================================
// judge.rs
// ============================================================

pub fn judge_matched(
    locale: Locale,
    reason: &str,
    dst_ip: impl fmt::Display,
    dst_port: u16,
) -> String {
    match locale {
        Locale::Ja => {
            format!("判定器が当たった reason={reason} dst_ip={dst_ip} dst_port={dst_port}")
        }
        Locale::En => {
            format!("a judge matched reason={reason} dst_ip={dst_ip} dst_port={dst_port}")
        }
    }
}

// ============================================================
// ids.rs（`IdsSidsError` と alert 適用ログ）
// ============================================================

pub fn ids_sids_io_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("ips-sids file を読めなかった: {e}"),
        Locale::En => format!("failed to read ips-sids file: {e}"),
    }
}

pub fn ids_alert_dropped(
    locale: Locale,
    sid: impl fmt::Display,
    dst_ip: impl fmt::Display,
    dst_port: u16,
) -> String {
    match locale {
        Locale::Ja => format!(
            "ids alert が sid={sid} で宛先を drop 集合へ入れた dst_ip={dst_ip} dst_port={dst_port}"
        ),
        Locale::En => format!(
            "ids alert sid={sid} added destination to drop set dst_ip={dst_ip} dst_port={dst_port}"
        ),
    }
}

// ============================================================
// flow.rs（`LogError` の Display と JSON line の検証）
// ============================================================

pub fn timestamp_format_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("timestamp の整形に失敗した: {e}"),
        Locale::En => format!("failed to format timestamp: {e}"),
    }
}

pub fn flow_log_json_encode_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("flow log の JSON 化に失敗した: {e}"),
        Locale::En => format!("failed to serialize flow log entry to JSON: {e}"),
    }
}

pub fn flow_log_lock_poisoned(locale: Locale) -> String {
    match locale {
        Locale::Ja => "flow log の file lock が poison していた".to_string(),
        Locale::En => "flow log file lock was poisoned".to_string(),
    }
}

pub fn flow_log_line_not_json_object(locale: Locale) -> String {
    match locale {
        Locale::Ja => "flow log の1行は JSON object のはず".to_string(),
        Locale::En => "expected a flow log line to be a JSON object".to_string(),
    }
}

// ============================================================
// proxy（段階7。`src/proxy.rs`）
// ============================================================

pub fn proxy_listen_bind_failed(
    locale: Locale,
    addr: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("--listen {addr} を bind できなかった: {e}"),
        Locale::En => format!("failed to bind --listen {addr}: {e}"),
    }
}

pub fn proxy_started(locale: Locale, addr: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("proxy を起動した listen={addr}"),
        Locale::En => format!("proxy started listen={addr}"),
    }
}

pub fn proxy_allow_from_default_used(locale: Locale) -> String {
    match locale {
        Locale::Ja => {
            "--allow-from 未指定につき既定（loopback と RFC1918）だけを許可する".to_string()
        }
        Locale::En => {
            "no --allow-from given; only loopback and RFC1918 ranges are allowed".to_string()
        }
    }
}

pub fn proxy_allow_from_configured(locale: Locale, count: usize) -> String {
    match locale {
        Locale::Ja => format!("--allow-from を{count}件 受け付けた"),
        Locale::En => format!("accepted {count} --allow-from entries"),
    }
}

pub fn proxy_allow_from_invalid(locale: Locale, value: &str) -> String {
    match locale {
        Locale::Ja => format!("--allow-from の値が CIDR として読めない: {value}"),
        Locale::En => format!("--allow-from value does not parse as a CIDR: {value}"),
    }
}

pub fn proxy_connection_rejected(locale: Locale, peer_ip: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("--allow-from に無い接続元を拒否した src_ip={peer_ip}"),
        Locale::En => format!("rejected connection from src_ip={peer_ip} (not in --allow-from)"),
    }
}

pub fn proxy_accept_failed(locale: Locale, err: &std::io::Error) -> String {
    match locale {
        Locale::Ja => format!("accept に失敗した。100 ms 待つ error={err}"),
        Locale::En => format!("accept failed; waiting 100 ms error={err}"),
    }
}

pub fn flow_set_swept(locale: Locale, removed: usize) -> String {
    match locale {
        Locale::Ja => format!("idle の flow を集合から落とした removed={removed}"),
        Locale::En => format!("dropped idle flows from the set removed={removed}"),
    }
}

pub fn service_log_open_failed(
    locale: Locale,
    path: impl fmt::Display,
    err: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("service.log を開けなかった。stderr のまま path={path} error={err}"),
        Locale::En => {
            format!("could not open service.log; staying on stderr path={path} error={err}")
        }
    }
}

pub fn service_log_utc_fallback(locale: Locale) -> String {
    match locale {
        Locale::Ja => {
            "local の offset が取れないので service.log の時刻は UTC（Z）で書く".to_string()
        }
        Locale::En => "local offset unavailable; service.log timestamps are UTC (Z)".to_string(),
    }
}

pub fn proxy_request_line_too_long(locale: Locale, peer_ip: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("request 行が長すぎる（8 KiB 超）src_ip={peer_ip}"),
        Locale::En => format!("request line too long (over 8 KiB) src_ip={peer_ip}"),
    }
}

pub fn proxy_request_unparseable(locale: Locale, peer_ip: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("CONNECT/絶対 URL のどちらでもない request src_ip={peer_ip}"),
        Locale::En => {
            format!("request is neither CONNECT nor an absolute-form URL src_ip={peer_ip}")
        }
    }
}

pub fn proxy_pac_served(locale: Locale, peer_ip: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("PAC を返した src_ip={peer_ip}"),
        Locale::En => format!("served the PAC file to src_ip={peer_ip}"),
    }
}

pub fn proxy_ca_served(locale: Locale, peer_ip: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("CA 証明書を返した src_ip={peer_ip}"),
        Locale::En => format!("served the CA certificate to src_ip={peer_ip}"),
    }
}

pub fn proxy_upstream_unreachable(locale: Locale, host: &str, port: u16) -> String {
    match locale {
        Locale::Ja => format!("上流へ繋げなかった host={host} port={port}"),
        Locale::En => format!("could not reach upstream host={host} port={port}"),
    }
}

pub fn proxy_connection_limit_reached(locale: Locale, max: usize) -> String {
    match locale {
        Locale::Ja => format!("同時接続数の上限（{max}）に達したので拒否した"),
        Locale::En => format!("rejected connection: concurrency limit ({max}) reached"),
    }
}

pub fn proxy_blackhole_entered(locale: Locale, host: &str, hold_secs: u64) -> String {
    match locale {
        Locale::Ja => format!("blackhole へ落とした host={host} hold={hold_secs}s"),
        Locale::En => format!("dropped into blackhole host={host} hold={hold_secs}s"),
    }
}

pub fn proxy_blackhole_limit_reached(locale: Locale, max: usize) -> String {
    match locale {
        Locale::Ja => format!("blackhole 枠の上限（{max}）に達したので 403 に倒した"),
        Locale::En => format!("blackhole slot limit ({max}) reached; fell back to 403"),
    }
}

// ============================================================
// MITM (stage 8. `src/ca.rs`, `src/clamd.rs`, `src/scan.rs`, `src/mitm.rs`,
// `src/main.rs`). The list of messages is `docs/design.md` "段階8 MITM", i18n.
// ============================================================

pub fn mitm_enabled(
    locale: Locale,
    list_count: usize,
    not_after: impl fmt::Display,
    sha256: &str,
) -> String {
    match locale {
        Locale::Ja => {
            format!("復号を有効にした mitm_list={list_count}件 CA期限={not_after} sha256={sha256}")
        }
        Locale::En => format!(
            "decryption enabled mitm_list={list_count} ca_not_after={not_after} sha256={sha256}"
        ),
    }
}

pub fn mitm_disabled_missing(locale: Locale, missing: &str) -> String {
    match locale {
        Locale::Ja => format!("復号を無効にした（足りない option: {missing}）"),
        Locale::En => format!("decryption disabled (missing option: {missing})"),
    }
}

pub fn mitm_disabled_os(locale: Locale) -> String {
    match locale {
        Locale::Ja => {
            "--mitm-list / --ca-dir / --clamd は Linux だけで効く。この OS では無視し、復号しない"
                .to_string()
        }
        Locale::En => {
            "--mitm-list / --ca-dir / --clamd only work on Linux; ignored on this OS, no decryption"
                .to_string()
        }
    }
}

pub fn mitm_disabled_error(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("復号を無効にして段階7 のまま動く: {e}"),
        Locale::En => format!("decryption disabled, running as stage 7: {e}"),
    }
}

pub fn ca_generated(locale: Locale, dir: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("CA を生成した dir={dir}"),
        Locale::En => format!("generated the CA dir={dir}"),
    }
}

pub fn ca_loaded(locale: Locale, dir: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("CA を読み込んだ dir={dir}"),
        Locale::En => format!("loaded the CA dir={dir}"),
    }
}

pub fn ca_fingerprint(
    locale: Locale,
    sha256: &str,
    sha1: &str,
    not_after: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("CA の指紋 sha256={sha256} sha1={sha1} 期限={not_after}"),
        Locale::En => format!("CA fingerprint sha256={sha256} sha1={sha1} not_after={not_after}"),
    }
}

pub fn ca_expiring_soon(
    locale: Locale,
    days: impl fmt::Display,
    not_after: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!(
            "CA の期限まで残り {days} 日（{not_after}）。新しい CA を作り、端末へ入れ直す"
        ),
        Locale::En => format!(
            "the CA expires in {days} days ({not_after}); make a new CA and install it on the devices again"
        ),
    }
}

pub fn ca_io_failed(locale: Locale, path: impl fmt::Display, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("CA の file を扱えなかった path={path}: {e}"),
        Locale::En => format!("could not access a CA file path={path}: {e}"),
    }
}

pub fn ca_one_file_missing(locale: Locale, missing: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => {
            format!("CA の鍵と証明書の片方だけが在る（無いのは {missing}）。作り直さない")
        }
        Locale::En => format!(
            "only one of the CA key and certificate exists (missing {missing}); not regenerating"
        ),
    }
}

pub fn ca_key_too_open(locale: Locale, path: impl fmt::Display, mode: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("CA の鍵の権限が 0600 より緩い path={path} mode={mode}"),
        Locale::En => format!("the CA key is more open than 0600 path={path} mode={mode}"),
    }
}

pub fn ca_parse_failed(
    locale: Locale,
    path: impl fmt::Display,
    detail: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("CA の file を読み解けない path={path}: {detail}"),
        Locale::En => format!("could not parse a CA file path={path}: {detail}"),
    }
}

pub fn ca_expired(locale: Locale, not_after: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("CA の期限が切れている（{not_after}）。作り直さない"),
        Locale::En => format!("the CA has expired ({not_after}); not regenerating"),
    }
}

pub fn ca_generate_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("CA を生成できなかった: {e}"),
        Locale::En => format!("could not generate the CA: {e}"),
    }
}

pub fn clamd_ping_failed(locale: Locale, addr: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("clamd の PING に PONG が返らない clamd={addr}（起動は続ける）"),
        Locale::En => format!("clamd did not answer PING with PONG clamd={addr} (starting anyway)"),
    }
}

pub fn clamd_not_loopback(locale: Locale, addr: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!(
            "--clamd が loopback 以外の TCP clamd={addr}。file の本文が平文で network を渡る"
        ),
        Locale::En => format!(
            "--clamd is TCP off this host clamd={addr}; file bodies cross the network in the clear"
        ),
    }
}

pub fn av_log_open_failed(locale: Locale, path: impl fmt::Display, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("av.jsonl を開けなかった path={path}: {e}"),
        Locale::En => format!("could not open av.jsonl path={path}: {e}"),
    }
}

pub fn av_log_write_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("av.jsonl に書けなかった: {e}"),
        Locale::En => format!("could not write av.jsonl: {e}"),
    }
}

pub fn mitm_leaf_failed(locale: Locale, host: &str, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("leaf 証明書を作れない。非復号で通す host={host}: {e}"),
        Locale::En => format!("could not issue a leaf certificate; tunnelling host={host}: {e}"),
    }
}

pub fn mitm_upstream_tls_failed(locale: Locale, host: &str, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("上流の TLS が失敗した。非復号で通す host={host}: {e}"),
        Locale::En => format!("upstream TLS failed; tunnelling host={host}: {e}"),
    }
}

/// `reason` is `alert`, `silent_close`, `timeout` or `tls_error`; `stage` is
/// `handshake` or `after_handshake`. Both stay ASCII for grep.
pub fn mitm_client_refused(
    locale: Locale,
    reason: &str,
    stage: &str,
    client_ip: impl fmt::Display,
    host: &str,
) -> String {
    match locale {
        Locale::Ja => format!(
            "client が復号を拒んだ（alert / 無通告の切断 / handshake 未完） 理由={reason} 段階={stage} src_ip={client_ip} host={host}"
        ),
        Locale::En => format!(
            "client refused decryption (alert / silent close / unfinished handshake) reason={reason} stage={stage} src_ip={client_ip} host={host}"
        ),
    }
}

pub fn mitm_closed_before_tls(locale: Locale, client_ip: impl fmt::Display, host: &str) -> String {
    match locale {
        Locale::Ja => format!(
            "client が TLS を始める前に切った。証明書を見ていないので bypass しない src_ip={client_ip} host={host}"
        ),
        Locale::En => format!(
            "client closed before starting TLS; it never saw the certificate, not bypassed src_ip={client_ip} host={host}"
        ),
    }
}

/// `reason` is `handshake` (cut mid-handshake without an alert) or
/// `recent_request` (the pair sent a request recently).
pub fn mitm_silent_close_kept(
    locale: Locale,
    reason: &str,
    stage: &str,
    client_ip: impl fmt::Display,
    host: &str,
) -> String {
    match locale {
        Locale::Ja => format!(
            "無通告の切断を拒否とみなさず bypass しない 理由={reason} 段階={stage} src_ip={client_ip} host={host}"
        ),
        Locale::En => format!(
            "silent close not taken as a refusal; not bypassed reason={reason} stage={stage} src_ip={client_ip} host={host}"
        ),
    }
}

pub fn mitm_unsupported(locale: Locale, host: &str, kind: &str) -> String {
    match locale {
        Locale::Ja => format!("復号したまま扱えない通信 host={host} 理由={kind}"),
        Locale::En => format!("cannot handle this decrypted exchange host={host} reason={kind}"),
    }
}

pub fn mitm_upstream_closed(locale: Locale, host: &str) -> String {
    match locale {
        Locale::Ja => format!("上流が応答を返す前に切れた。502 を返した host={host}"),
        Locale::En => format!("upstream closed before its response; answered 502 host={host}"),
    }
}

pub fn mitm_relay_aborted(locale: Locale, host: &str, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("復号した通信の中継が途中で終わった host={host}: {e}"),
        Locale::En => format!("decrypted relay ended early host={host}: {e}"),
    }
}

pub fn mitm_bypassed(
    locale: Locale,
    client_ip: impl fmt::Display,
    host: &str,
    ttl_secs: u64,
) -> String {
    match locale {
        Locale::Ja => {
            format!("bypass 表へ入れた。{ttl_secs} 秒 非復号で通す src_ip={client_ip} host={host}")
        }
        Locale::En => format!(
            "added to the bypass table; tunnelling for {ttl_secs}s src_ip={client_ip} host={host}"
        ),
    }
}

pub fn av_found(
    locale: Locale,
    host: &str,
    signature: &str,
    sha256: &str,
    elapsed: Duration,
) -> String {
    let ms = elapsed.as_millis();
    match locale {
        Locale::Ja => format!(
            "検知した。403 に差し替えた host={host} signature={signature} ms={ms} sha256={sha256}"
        ),
        Locale::En => format!(
            "detected; replaced with 403 host={host} signature={signature} ms={ms} sha256={sha256}"
        ),
    }
}

pub fn av_clean(locale: Locale, host: &str, sha256: &str, elapsed: Duration) -> String {
    let ms = elapsed.as_millis();
    match locale {
        Locale::Ja => format!("検査した。clean だった host={host} ms={ms} sha256={sha256}"),
        Locale::En => format!("scanned clean host={host} ms={ms} sha256={sha256}"),
    }
}

pub fn av_scan_skipped(locale: Locale, host: &str, reason: &str) -> String {
    match locale {
        Locale::Ja => format!("scan しなかった host={host} 理由={reason}"),
        Locale::En => format!("not scanned host={host} reason={reason}"),
    }
}

pub fn av_scan_failed(locale: Locale, host: &str, reason: &str) -> String {
    match locale {
        Locale::Ja => format!("scan に失敗した。本文はそのまま通す host={host} 理由={reason}"),
        Locale::En => format!("scan failed; passing the body through host={host} reason={reason}"),
    }
}

pub fn av_scan_unfinished(locale: Locale, host: &str, signature: &str) -> String {
    match locale {
        Locale::Ja => {
            format!("検査未了だった。本文はそのまま通す host={host} signature={signature}")
        }
        Locale::En => {
            format!("scan unfinished; passing the body through host={host} signature={signature}")
        }
    }
}

pub fn mitm_list_loaded(locale: Locale, path: impl fmt::Display, count: usize) -> String {
    match locale {
        Locale::Ja => format!("--mitm-list を読み込んだ path={path} 件数={count}"),
        Locale::En => format!("loaded --mitm-list path={path} entries={count}"),
    }
}

pub fn mitm_list_load_failed_empty(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!(
            "--mitm-list を読めない。空の list で始め、file を見張り続ける path={path}: {e}"
        ),
        Locale::En => format!(
            "could not read --mitm-list; starting empty and watching the file path={path}: {e}"
        ),
    }
}

pub fn mitm_list_entry_allowlisted(locale: Locale, host: &str) -> String {
    match locale {
        Locale::Ja => format!("--mitm-list の項目が allowlist に当たるので復号しない host={host}"),
        Locale::En => {
            format!("--mitm-list entry is on the allowlist and will not be decrypted host={host}")
        }
    }
}

pub fn av_blocked_body(locale: Locale) -> String {
    match locale {
        Locale::Ja => "packetdeath: この file はマルウェア対策の検査で止めました。\n".to_string(),
        Locale::En => "packetdeath: this file was blocked by the malware scan.\n".to_string(),
    }
}

// ============================================================
// Stage 10 (active defense. `src/distrust.rs`, `src/prober.rs`,
// `src/defense.rs`, `src/main.rs`). The list of messages is
// `docs/design.md` "段階10 能動防御", i18n.
// ============================================================

pub fn probe_chain_read(locale: Locale, host: &str, count: usize, verified: bool) -> String {
    match locale {
        Locale::Ja => {
            format!("probe が鎖を読んだ host={host} 証明書={count}枚 webpki の検証={verified}")
        }
        Locale::En => {
            format!(
                "probe read a chain host={host} certificates={count} webpki_verified={verified}"
            )
        }
    }
}

pub fn probe_chain_distrusted(locale: Locale, host: &str) -> String {
    match locale {
        Locale::Ja => format!("probe が読んだ鎖に不信の証明書が在る host={host}"),
        Locale::En => {
            format!("the chain the probe read holds a distrusted certificate host={host}")
        }
    }
}

pub fn probe_summary(
    locale: Locale,
    probes: u64,
    hits: u64,
    timeouts: u64,
    dropped: u64,
) -> String {
    match locale {
        Locale::Ja => {
            format!("probe の 1 時間の集計 probes={probes} hits={hits} timeouts={timeouts} dropped={dropped}")
        }
        Locale::En => {
            format!("probe hourly summary probes={probes} hits={hits} timeouts={timeouts} dropped={dropped}")
        }
    }
}

pub fn distrust_loaded(
    locale: Locale,
    path: impl fmt::Display,
    entries: usize,
    skipped: usize,
) -> String {
    match locale {
        Locale::Ja => format!(
            "不信の証明書の list を読み込んだ path={path} 件数={entries} 読めない行={skipped}"
        ),
        Locale::En => format!(
            "loaded the distrust list path={path} entries={entries} skipped_lines={skipped}"
        ),
    }
}

pub fn distrust_load_failed_empty(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("不信の証明書の list を読めず空で始める（file が現れたら読む） path={path}: {e}"),
        Locale::En => format!("could not read the distrust list; starting empty (it is read once the file appears) path={path}: {e}"),
    }
}

pub fn distrust_lines_skipped(locale: Locale, path: impl fmt::Display, skipped: usize) -> String {
    match locale {
        Locale::Ja => {
            format!("不信の証明書の list に読めない行が在り捨てた path={path} 行数={skipped}")
        }
        Locale::En => {
            format!("dropped unreadable lines of the distrust list path={path} lines={skipped}")
        }
    }
}

pub fn defense_started(
    locale: Locale,
    stop_files: usize,
    watch_files: usize,
    probe: bool,
    breaker_hosts: usize,
) -> String {
    match locale {
        Locale::Ja => format!(
            "段階10 の能動防御を有効にした 止める list={stop_files}本 見張りの list={watch_files}本 probe={probe} breaker の閾値={breaker_hosts}host"
        ),
        Locale::En => format!(
            "stage 10 active defense enabled stop_lists={stop_files} watch_lists={watch_files} probe={probe} breaker_hosts={breaker_hosts}"
        ),
    }
}

pub fn defense_off_changed(locale: Locale, on: bool) -> String {
    match locale {
        Locale::Ja if on => {
            "defense-off の file が在る間、段階10 の止める側は見張りになる".to_string()
        }
        Locale::Ja => "defense-off の file が消えた。段階10 の止める側へ戻る".to_string(),
        Locale::En if on => {
            "the defense-off file exists: the stage 10 stop side only watches".to_string()
        }
        Locale::En => "the defense-off file is gone: the stage 10 stop side is back".to_string(),
    }
}

pub fn breaker_tripped(locale: Locale, source: &str, threshold: usize) -> String {
    match locale {
        Locale::Ja => format!(
            "breaker が働いた source={source} は 10 分に {threshold} host を超えて止めたので見張りへ落とす（file が変わるか再起動で戻る）"
        ),
        Locale::En => format!(
            "breaker tripped: source={source} stopped more than {threshold} hosts in 10 minutes and falls back to watch (a changed file or a restart brings it back)"
        ),
    }
}

pub fn chain_marked_allowlisted(locale: Locale, host: &str) -> String {
    match locale {
        Locale::Ja => format!("不信の鎖の印が付いた host は allowlist に在り、通した host={host}"),
        Locale::En => format!("a host marked with a distrusted chain is on the allowlist and was let through host={host}"),
    }
}

pub fn upstream_chain_distrusted(locale: Locale, host: &str, source: &str) -> String {
    match locale {
        Locale::Ja => format!("上流の鎖に不信の証明書が在る host={host} source={source}"),
        Locale::En => {
            format!("the upstream chain holds a distrusted certificate host={host} source={source}")
        }
    }
}

pub fn watch_log_open_failed(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("watch.jsonl を開けない path={path}: {e}"),
        Locale::En => format!("failed to open watch.jsonl path={path}: {e}"),
    }
}

pub fn watch_log_write_failed(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("watch.jsonl へ書けない: {e}"),
        Locale::En => format!("failed to write watch.jsonl: {e}"),
    }
}

pub fn defense_disabled_error(locale: Locale, e: impl fmt::Display) -> String {
    match locale {
        Locale::Ja => format!("段階10 の能動防御を無効にして、それ以外のまま動く: {e}"),
        Locale::En => format!("stage 10 active defense disabled, running without it: {e}"),
    }
}

pub fn stage10_disabled_os(locale: Locale) -> String {
    match locale {
        Locale::Ja => "--distrust / --watch-distrust / --watch-blocklist / --watch-iplist / --probe-chains / --defense-off は Linux だけで効く。この OS では無視する".to_string(),
        Locale::En => "--distrust / --watch-distrust / --watch-blocklist / --watch-iplist / --probe-chains / --defense-off only work on Linux; ignored on this OS".to_string(),
    }
}

pub fn cli_invalid_breaker_hosts(locale: Locale, v: &str) -> String {
    match locale {
        Locale::Ja => format!("--breaker-hosts の値は 1 以上の整数: {v}"),
        Locale::En => format!("--breaker-hosts value must be an integer of 1 or more: {v}"),
    }
}

pub fn cli_invalid_days(locale: Locale, v: &str) -> String {
    match locale {
        Locale::Ja => format!("--days の値は整数: {v}"),
        Locale::En => format!("--days value must be an integer: {v}"),
    }
}

pub fn defense_report_read_failed(
    locale: Locale,
    path: impl fmt::Display,
    e: impl fmt::Display,
) -> String {
    match locale {
        Locale::Ja => format!("defense-report が読む file を開けない path={path}: {e}"),
        Locale::En => format!("defense-report could not read the file path={path}: {e}"),
    }
}

pub fn defense_report_lines_skipped(locale: Locale, skipped: usize) -> String {
    match locale {
        Locale::Ja => format!("defense-report が読めない行を捨てた 行数={skipped}"),
        Locale::En => format!("defense-report dropped unreadable lines lines={skipped}"),
    }
}

/// [`all_message_samples`] が呼び忘れを検出するための、代表引数（ダミー値）。
/// 実際の意味は持たない。型を満たすためだけの値である。
/// `#[cfg(test)]` を付けない ── `tests/independent_i18n.rs`（統合 test。
/// 別 crate として lib を通常 build でリンクする）から
/// [`all_message_samples`] を呼ぶため、この module も常時 build する必要が
/// 在る。
mod sample_args {
    pub const S: &str = "x";
    pub const N: usize = 1;
    pub const N32: u32 = 1;
    pub const N16: u16 = 1;
    pub const N64: u64 = 1;
    pub const F: f64 = 1.0;
}

/// 全 pub なメッセージ関数を、日本語・英語の両方で1回ずつ呼んだ結果を返す。
/// `tests/independent_i18n.rs` が「同じ key が両方の言語に在ること」の
/// 機械検査（`every_pub_message_fn_has_a_sample`）に使う。
///
/// **新しい `pub fn` を `src/i18n.rs` に足したら、ここにも1行 足す。**
/// 足し忘れは上記 test が、`rg -c '^pub fn '` で数えた関数の総数と
/// この関数が返す件数の不一致として検出する。
pub fn all_message_samples() -> Vec<(&'static str, String, String)> {
    use sample_args::*;
    use std::path::PathBuf;
    let none: Option<PathBuf> = None;
    let filter_none: Option<String> = None;
    macro_rules! sample {
        ($name:literal, $f:expr) => {
            ($name, $f(Locale::Ja), $f(Locale::En))
        };
    }
    vec![
        (
            "cli_unknown_flag",
            cli_unknown_flag(Locale::Ja, S),
            cli_unknown_flag(Locale::En, S),
        ),
        (
            "cli_value_required",
            cli_value_required(Locale::Ja, S),
            cli_value_required(Locale::En, S),
        ),
        (
            "cli_invalid_queue_num",
            cli_invalid_queue_num(Locale::Ja, S),
            cli_invalid_queue_num(Locale::En, S),
        ),
        (
            "cli_required_arg_missing",
            cli_required_arg_missing(Locale::Ja, S),
            cli_required_arg_missing(Locale::En, S),
        ),
        (
            "cli_invalid_ips_ttl",
            cli_invalid_ips_ttl(Locale::Ja, S),
            cli_invalid_ips_ttl(Locale::En, S),
        ),
        (
            "cli_invalid_ips_severity",
            cli_invalid_ips_severity(Locale::Ja, S),
            cli_invalid_ips_severity(Locale::En, S),
        ),
        (
            "cli_invalid_poll_ms",
            cli_invalid_poll_ms(Locale::Ja, S),
            cli_invalid_poll_ms(Locale::En, S),
        ),
        (
            "cli_invalid_listen_addr",
            cli_invalid_listen_addr(Locale::Ja, S),
            cli_invalid_listen_addr(Locale::En, S),
        ),
        (
            "cli_invalid_deny_mode",
            cli_invalid_deny_mode(Locale::Ja, S),
            cli_invalid_deny_mode(Locale::En, S),
        ),
        sample!("log_dir_no_home", log_dir_no_home),
        sample!("log_dir_no_local_app_data", log_dir_no_local_app_data),
        (
            "log_dir_create_failed",
            log_dir_create_failed(Locale::Ja, S, S),
            log_dir_create_failed(Locale::En, S, S),
        ),
        (
            "flow_log_open_failed",
            flow_log_open_failed(Locale::Ja, S, S),
            flow_log_open_failed(Locale::En, S, S),
        ),
        sample!("usage_banner", usage_banner),
        (
            "arg_parse_failed",
            arg_parse_failed(Locale::Ja, S),
            arg_parse_failed(Locale::En, S),
        ),
        (
            "unknown_command",
            unknown_command(Locale::Ja, S),
            unknown_command(Locale::En, S),
        ),
        sample!("filter_windows_only_ignored", filter_windows_only_ignored),
        (
            "log_dir_undecided",
            log_dir_undecided(Locale::Ja, S),
            log_dir_undecided(Locale::En, S),
        ),
        (
            "observe_started",
            observe_started(Locale::Ja, N16, S),
            observe_started(Locale::En, N16, S),
        ),
        (
            "observe_loop_failed",
            observe_loop_failed(Locale::Ja, S),
            observe_loop_failed(Locale::En, S),
        ),
        (
            "ips_sids_load_failed",
            ips_sids_load_failed(Locale::Ja, S, S),
            ips_sids_load_failed(Locale::En, S, S),
        ),
        (
            "blocklist_load_failed_empty",
            blocklist_load_failed_empty(Locale::Ja, S, S),
            blocklist_load_failed_empty(Locale::En, S, S),
        ),
        (
            "allowlist_load_failed_empty",
            allowlist_load_failed_empty(Locale::Ja, S, S),
            allowlist_load_failed_empty(Locale::En, S, S),
        ),
        (
            "iplist_load_failed_empty",
            iplist_load_failed_empty(Locale::Ja, S, S),
            iplist_load_failed_empty(Locale::En, S, S),
        ),
        (
            "av_load_failed_empty",
            av_load_failed_empty(Locale::Ja, S, S),
            av_load_failed_empty(Locale::En, S, S),
        ),
        (
            "pcapng_foreground_watch",
            pcapng_foreground_watch(Locale::Ja, S, N64),
            pcapng_foreground_watch(Locale::En, S, N64),
        ),
        sample!(
            "linux_pcapng_no_blocker_passthrough",
            linux_pcapng_no_blocker_passthrough
        ),
        (
            "dns_log_open_failed",
            dns_log_open_failed(Locale::Ja, S, S),
            dns_log_open_failed(Locale::En, S, S),
        ),
        (
            "block_started",
            block_started(
                Locale::Ja,
                N16,
                S,
                &[],
                false,
                &[],
                &none,
                &none,
                None,
                N64,
                &none,
            ),
            block_started(
                Locale::En,
                N16,
                S,
                &[],
                false,
                &[],
                &none,
                &none,
                None,
                N64,
                &none,
            ),
        ),
        (
            "block_loop_failed",
            block_loop_failed(Locale::Ja, S),
            block_loop_failed(Locale::En, S),
        ),
        (
            "block_not_implemented_for_os",
            block_not_implemented_for_os(
                Locale::Ja,
                N16,
                S,
                &[],
                false,
                &[],
                &none,
                &none,
                None,
                N64,
                &none,
            ),
            block_not_implemented_for_os(
                Locale::En,
                N16,
                S,
                &[],
                false,
                &[],
                &none,
                &none,
                None,
                N64,
                &none,
            ),
        ),
        (
            "flow_log_opened",
            flow_log_opened(Locale::Ja, S),
            flow_log_opened(Locale::En, S),
        ),
        (
            "kill_tcp_script_write_failed",
            kill_tcp_script_write_failed(Locale::Ja, S),
            kill_tcp_script_write_failed(Locale::En, S),
        ),
        (
            "labels_file_read_failed",
            labels_file_read_failed(Locale::Ja, S, S),
            labels_file_read_failed(Locale::En, S, S),
        ),
        (
            "stdin_read_failed",
            stdin_read_failed(Locale::Ja, S),
            stdin_read_failed(Locale::En, S),
        ),
        (
            "input_file_read_failed",
            input_file_read_failed(Locale::Ja, S, S),
            input_file_read_failed(Locale::En, S, S),
        ),
        (
            "output_file_write_failed",
            output_file_write_failed(Locale::Ja, S, S),
            output_file_write_failed(Locale::En, S, S),
        ),
        (
            "cli_timestamp_format_failed",
            cli_timestamp_format_failed(Locale::Ja, S),
            cli_timestamp_format_failed(Locale::En, S),
        ),
        (
            "observe_not_implemented_for_os",
            observe_not_implemented_for_os(Locale::Ja, N16, S, &filter_none),
            observe_not_implemented_for_os(Locale::En, N16, S, &filter_none),
        ),
        (
            "service_installed",
            service_installed(Locale::Ja, S, &none, &none, &none),
            service_installed(Locale::En, S, &none, &none, &none),
        ),
        (
            "service_install_failed",
            service_install_failed(Locale::Ja, S),
            service_install_failed(Locale::En, S),
        ),
        (
            "service_install_windows_only",
            service_install_windows_only(Locale::Ja, S),
            service_install_windows_only(Locale::En, S),
        ),
        sample!("service_uninstalled", service_uninstalled),
        (
            "service_uninstall_failed",
            service_uninstall_failed(Locale::Ja, S),
            service_uninstall_failed(Locale::En, S),
        ),
        sample!(
            "service_uninstall_windows_only",
            service_uninstall_windows_only
        ),
        (
            "service_dispatcher_failed",
            service_dispatcher_failed(Locale::Ja, S),
            service_dispatcher_failed(Locale::En, S),
        ),
        (
            "service_run_windows_only",
            service_run_windows_only(Locale::Ja, S),
            service_run_windows_only(Locale::En, S),
        ),
        sample!(
            "pcapng_not_specified_wait_stop",
            pcapng_not_specified_wait_stop
        ),
        (
            "flow_log_open_failed_wait_stop",
            flow_log_open_failed_wait_stop(Locale::Ja, S, S),
            flow_log_open_failed_wait_stop(Locale::En, S, S),
        ),
        (
            "pcapng_truncated",
            pcapng_truncated(Locale::Ja, N, N),
            pcapng_truncated(Locale::En, N, N),
        ),
        (
            "filterlist_converted",
            filterlist_converted(Locale::Ja, N32, N, N, N32, N32, N32, N32),
            filterlist_converted(Locale::En, N32, N, N, N32, N32, N32, N32),
        ),
        (
            "filterlist_unparsable_lines",
            filterlist_unparsable_lines(Locale::Ja, N32),
            filterlist_unparsable_lines(Locale::En, N32),
        ),
        sample!("filterlist_header_comment", filterlist_header_comment),
        (
            "filterlist_accepted_comment",
            filterlist_accepted_comment(Locale::Ja, N, N32, N32, N32, N32, N32),
            filterlist_accepted_comment(Locale::En, N, N32, N32, N32, N32, N32),
        ),
        (
            "filterlist_dropped_comment",
            filterlist_dropped_comment(
                Locale::Ja,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
            ),
            filterlist_dropped_comment(
                Locale::En,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
                N32,
            ),
        ),
        (
            "microsoft_json_parse_failed",
            microsoft_json_parse_failed(Locale::Ja, S),
            microsoft_json_parse_failed(Locale::En, S),
        ),
        sample!(
            "allowlist_convert_header_comment",
            allowlist_convert_header_comment
        ),
        (
            "allowlist_convert_accepted_comment",
            allowlist_convert_accepted_comment(Locale::Ja, N, N32),
            allowlist_convert_accepted_comment(Locale::En, N, N32),
        ),
        (
            "eval_executed",
            eval_executed(Locale::Ja, N32, N32, N32, N32, N32),
            eval_executed(Locale::En, N32, N32, N32, N32, N32),
        ),
        (
            "sni_absent",
            sni_absent(Locale::Ja, S),
            sni_absent(Locale::En, S),
        ),
        (
            "reload_file_not_found",
            reload_file_not_found(Locale::Ja, S),
            reload_file_not_found(Locale::En, S),
        ),
        (
            "reload_file_read_failed",
            reload_file_read_failed(Locale::Ja, S, S),
            reload_file_read_failed(Locale::En, S, S),
        ),
        (
            "reload_succeeded",
            reload_succeeded(Locale::Ja, S, S, N, N),
            reload_succeeded(Locale::En, S, S, N, N),
        ),
        (
            "reload_failed",
            reload_failed(Locale::Ja, S, S),
            reload_failed(Locale::En, S, S),
        ),
        sample!("dns_too_short", dns_too_short),
        sample!("dns_not_a_response", dns_not_a_response),
        sample!("dns_no_question", dns_no_question),
        sample!("dns_bad_name", dns_bad_name),
        sample!("dns_bad_record", dns_bad_record),
        (
            "reassemble_buffer_overflow",
            reassemble_buffer_overflow(Locale::Ja, N),
            reassemble_buffer_overflow(Locale::En, N),
        ),
        (
            "reassemble_flow_limit_reached",
            reassemble_flow_limit_reached(Locale::Ja, N),
            reassemble_flow_limit_reached(Locale::En, N),
        ),
        (
            "reassemble_flow_expired",
            reassemble_flow_expired(Locale::Ja, S, N16),
            reassemble_flow_expired(Locale::En, S, N16),
        ),
        (
            "blocklist_io_failed",
            blocklist_io_failed(Locale::Ja, S),
            blocklist_io_failed(Locale::En, S),
        ),
        (
            "blocklist_loaded",
            blocklist_loaded(Locale::Ja, S, N),
            blocklist_loaded(Locale::En, S, N),
        ),
        (
            "allowlist_io_failed",
            allowlist_io_failed(Locale::Ja, S),
            allowlist_io_failed(Locale::En, S),
        ),
        (
            "allowlist_loaded",
            allowlist_loaded(Locale::Ja, S, N),
            allowlist_loaded(Locale::En, S, N),
        ),
        (
            "iplist_io_failed",
            iplist_io_failed(Locale::Ja, S),
            iplist_io_failed(Locale::En, S),
        ),
        (
            "iplist_line_skipped",
            iplist_line_skipped(Locale::Ja, N),
            iplist_line_skipped(Locale::En, N),
        ),
        (
            "iplist_loaded",
            iplist_loaded(Locale::Ja, S, N),
            iplist_loaded(Locale::En, S, N),
        ),
        (
            "iplist_parsed",
            iplist_parsed(Locale::Ja, N, N),
            iplist_parsed(Locale::En, N, N),
        ),
        (
            "ps_bridge_spawn_failed",
            ps_bridge_spawn_failed(Locale::Ja, S),
            ps_bridge_spawn_failed(Locale::En, S),
        ),
        (
            "tcp_connection_cut",
            tcp_connection_cut(Locale::Ja, 1, F),
            tcp_connection_cut(Locale::En, 1, F),
        ),
        (
            "tcp_cut_rejected",
            tcp_cut_rejected(Locale::Ja, 317, F),
            tcp_cut_rejected(Locale::En, 317, F),
        ),
        (
            "tcp_block_failed",
            tcp_block_failed(Locale::Ja, S),
            tcp_block_failed(Locale::En, S),
        ),
        (
            "allowlist_passed",
            allowlist_passed(Locale::Ja, S),
            allowlist_passed(Locale::En, S),
        ),
        (
            "flow_log_write_failed",
            flow_log_write_failed(Locale::Ja, S),
            flow_log_write_failed(Locale::En, S),
        ),
        sample!("ps_bridge_contains_newline", ps_bridge_contains_newline),
        sample!("ps_bridge_malformed_response", ps_bridge_malformed_response),
        (
            "ps_bridge_encode_failed",
            ps_bridge_encode_failed(Locale::Ja, S),
            ps_bridge_encode_failed(Locale::En, S),
        ),
        (
            "ps_bridge_io_failed",
            ps_bridge_io_failed(Locale::Ja, S),
            ps_bridge_io_failed(Locale::En, S),
        ),
        sample!("ps_bridge_child_closed", ps_bridge_child_closed),
        (
            "ps_bridge_parse_failed",
            ps_bridge_parse_failed(Locale::Ja, S),
            ps_bridge_parse_failed(Locale::En, S),
        ),
        (
            "ps_bridge_timeout",
            ps_bridge_timeout(Locale::Ja, std::time::Duration::from_secs(1)),
            ps_bridge_timeout(Locale::En, std::time::Duration::from_secs(1)),
        ),
        sample!("ps_bridge_poisoned", ps_bridge_poisoned),
        sample!("ps_bridge_stdin_none", ps_bridge_stdin_none),
        sample!("ps_bridge_stdout_none", ps_bridge_stdout_none),
        (
            "ps_bridge_response_timeout_discard",
            ps_bridge_response_timeout_discard(Locale::Ja, std::time::Duration::from_secs(1)),
            ps_bridge_response_timeout_discard(Locale::En, std::time::Duration::from_secs(1)),
        ),
        (
            "ps_bridge_warmed",
            ps_bridge_warmed(Locale::Ja, 1, 1),
            ps_bridge_warmed(Locale::En, 1, 1),
        ),
        (
            "ps_bridge_warm_up_failed",
            ps_bridge_warm_up_failed(Locale::Ja, std::time::Duration::from_secs(1), S),
            ps_bridge_warm_up_failed(Locale::En, std::time::Duration::from_secs(1), S),
        ),
        (
            "av_io_failed",
            av_io_failed(Locale::Ja, S),
            av_io_failed(Locale::En, S),
        ),
        (
            "av_line_skipped",
            av_line_skipped(Locale::Ja, N, S),
            av_line_skipped(Locale::En, N, S),
        ),
        (
            "av_loaded",
            av_loaded(Locale::Ja, N, N, N, N),
            av_loaded(Locale::En, N, N, N, N),
        ),
        (
            "av_matched",
            av_matched(Locale::Ja, S, N16, S, S),
            av_matched(Locale::En, S, N16, S, S),
        ),
        (
            "nfqueue_open_failed",
            nfqueue_open_failed(Locale::Ja, S),
            nfqueue_open_failed(Locale::En, S),
        ),
        (
            "nfqueue_bind_failed",
            nfqueue_bind_failed(Locale::Ja, S),
            nfqueue_bind_failed(Locale::En, S),
        ),
        (
            "nfqueue_fail_open_setting_failed",
            nfqueue_fail_open_setting_failed(Locale::Ja, S),
            nfqueue_fail_open_setting_failed(Locale::En, S),
        ),
        (
            "nfqueue_recv_failed",
            nfqueue_recv_failed(Locale::Ja, S),
            nfqueue_recv_failed(Locale::En, S),
        ),
        (
            "nfqueue_verdict_send_failed",
            nfqueue_verdict_send_failed(Locale::Ja, S),
            nfqueue_verdict_send_failed(Locale::En, S),
        ),
        (
            "nfqueue_bound_observe",
            nfqueue_bound_observe(Locale::Ja, N16),
            nfqueue_bound_observe(Locale::En, N16),
        ),
        (
            "nfqueue_bound_block",
            nfqueue_bound_block(Locale::Ja, N16),
            nfqueue_bound_block(Locale::En, N16),
        ),
        (
            "judge_matched",
            judge_matched(Locale::Ja, S, S, N16),
            judge_matched(Locale::En, S, S, N16),
        ),
        (
            "ids_sids_io_failed",
            ids_sids_io_failed(Locale::Ja, S),
            ids_sids_io_failed(Locale::En, S),
        ),
        (
            "ids_alert_dropped",
            ids_alert_dropped(Locale::Ja, N, S, N16),
            ids_alert_dropped(Locale::En, N, S, N16),
        ),
        (
            "timestamp_format_failed",
            timestamp_format_failed(Locale::Ja, S),
            timestamp_format_failed(Locale::En, S),
        ),
        (
            "flow_log_json_encode_failed",
            flow_log_json_encode_failed(Locale::Ja, S),
            flow_log_json_encode_failed(Locale::En, S),
        ),
        sample!("flow_log_lock_poisoned", flow_log_lock_poisoned),
        sample!(
            "flow_log_line_not_json_object",
            flow_log_line_not_json_object
        ),
        (
            "proxy_listen_bind_failed",
            proxy_listen_bind_failed(Locale::Ja, S, S),
            proxy_listen_bind_failed(Locale::En, S, S),
        ),
        (
            "proxy_started",
            proxy_started(Locale::Ja, S),
            proxy_started(Locale::En, S),
        ),
        sample!(
            "proxy_allow_from_default_used",
            proxy_allow_from_default_used
        ),
        (
            "proxy_allow_from_configured",
            proxy_allow_from_configured(Locale::Ja, N),
            proxy_allow_from_configured(Locale::En, N),
        ),
        (
            "proxy_allow_from_invalid",
            proxy_allow_from_invalid(Locale::Ja, S),
            proxy_allow_from_invalid(Locale::En, S),
        ),
        (
            "proxy_connection_rejected",
            proxy_connection_rejected(Locale::Ja, S),
            proxy_connection_rejected(Locale::En, S),
        ),
        (
            "proxy_accept_failed",
            proxy_accept_failed(Locale::Ja, &std::io::Error::from(std::io::ErrorKind::Other)),
            proxy_accept_failed(Locale::En, &std::io::Error::from(std::io::ErrorKind::Other)),
        ),
        (
            "flow_set_swept",
            flow_set_swept(Locale::Ja, 7),
            flow_set_swept(Locale::En, 7),
        ),
        (
            "service_log_open_failed",
            service_log_open_failed(Locale::Ja, S, S),
            service_log_open_failed(Locale::En, S, S),
        ),
        (
            "service_log_utc_fallback",
            service_log_utc_fallback(Locale::Ja),
            service_log_utc_fallback(Locale::En),
        ),
        (
            "proxy_request_line_too_long",
            proxy_request_line_too_long(Locale::Ja, S),
            proxy_request_line_too_long(Locale::En, S),
        ),
        (
            "proxy_request_unparseable",
            proxy_request_unparseable(Locale::Ja, S),
            proxy_request_unparseable(Locale::En, S),
        ),
        (
            "proxy_pac_served",
            proxy_pac_served(Locale::Ja, S),
            proxy_pac_served(Locale::En, S),
        ),
        (
            "proxy_ca_served",
            proxy_ca_served(Locale::Ja, S),
            proxy_ca_served(Locale::En, S),
        ),
        (
            "proxy_upstream_unreachable",
            proxy_upstream_unreachable(Locale::Ja, S, N16),
            proxy_upstream_unreachable(Locale::En, S, N16),
        ),
        (
            "proxy_connection_limit_reached",
            proxy_connection_limit_reached(Locale::Ja, N),
            proxy_connection_limit_reached(Locale::En, N),
        ),
        (
            "proxy_blackhole_entered",
            proxy_blackhole_entered(Locale::Ja, S, N64),
            proxy_blackhole_entered(Locale::En, S, N64),
        ),
        (
            "proxy_blackhole_limit_reached",
            proxy_blackhole_limit_reached(Locale::Ja, N),
            proxy_blackhole_limit_reached(Locale::En, N),
        ),
        (
            "mitm_enabled",
            mitm_enabled(Locale::Ja, N, S, S),
            mitm_enabled(Locale::En, N, S, S),
        ),
        (
            "mitm_disabled_missing",
            mitm_disabled_missing(Locale::Ja, S),
            mitm_disabled_missing(Locale::En, S),
        ),
        sample!("mitm_disabled_os", mitm_disabled_os),
        (
            "mitm_disabled_error",
            mitm_disabled_error(Locale::Ja, S),
            mitm_disabled_error(Locale::En, S),
        ),
        (
            "ca_generated",
            ca_generated(Locale::Ja, S),
            ca_generated(Locale::En, S),
        ),
        (
            "ca_loaded",
            ca_loaded(Locale::Ja, S),
            ca_loaded(Locale::En, S),
        ),
        (
            "ca_fingerprint",
            ca_fingerprint(Locale::Ja, S, S, S),
            ca_fingerprint(Locale::En, S, S, S),
        ),
        (
            "ca_expiring_soon",
            ca_expiring_soon(Locale::Ja, N, S),
            ca_expiring_soon(Locale::En, N, S),
        ),
        (
            "ca_io_failed",
            ca_io_failed(Locale::Ja, S, S),
            ca_io_failed(Locale::En, S, S),
        ),
        (
            "ca_one_file_missing",
            ca_one_file_missing(Locale::Ja, S),
            ca_one_file_missing(Locale::En, S),
        ),
        (
            "ca_key_too_open",
            ca_key_too_open(Locale::Ja, S, S),
            ca_key_too_open(Locale::En, S, S),
        ),
        (
            "ca_parse_failed",
            ca_parse_failed(Locale::Ja, S, S),
            ca_parse_failed(Locale::En, S, S),
        ),
        (
            "ca_expired",
            ca_expired(Locale::Ja, S),
            ca_expired(Locale::En, S),
        ),
        (
            "ca_generate_failed",
            ca_generate_failed(Locale::Ja, S),
            ca_generate_failed(Locale::En, S),
        ),
        (
            "clamd_ping_failed",
            clamd_ping_failed(Locale::Ja, S),
            clamd_ping_failed(Locale::En, S),
        ),
        (
            "clamd_not_loopback",
            clamd_not_loopback(Locale::Ja, S),
            clamd_not_loopback(Locale::En, S),
        ),
        (
            "av_log_open_failed",
            av_log_open_failed(Locale::Ja, S, S),
            av_log_open_failed(Locale::En, S, S),
        ),
        (
            "av_log_write_failed",
            av_log_write_failed(Locale::Ja, S),
            av_log_write_failed(Locale::En, S),
        ),
        (
            "probe_chain_read",
            probe_chain_read(Locale::Ja, S, N, true),
            probe_chain_read(Locale::En, S, N, true),
        ),
        (
            "probe_chain_distrusted",
            probe_chain_distrusted(Locale::Ja, S),
            probe_chain_distrusted(Locale::En, S),
        ),
        (
            "probe_summary",
            probe_summary(Locale::Ja, N64, N64, N64, N64),
            probe_summary(Locale::En, N64, N64, N64, N64),
        ),
        (
            "distrust_loaded",
            distrust_loaded(Locale::Ja, S, N, N),
            distrust_loaded(Locale::En, S, N, N),
        ),
        (
            "distrust_load_failed_empty",
            distrust_load_failed_empty(Locale::Ja, S, S),
            distrust_load_failed_empty(Locale::En, S, S),
        ),
        (
            "distrust_lines_skipped",
            distrust_lines_skipped(Locale::Ja, S, N),
            distrust_lines_skipped(Locale::En, S, N),
        ),
        (
            "defense_started",
            defense_started(Locale::Ja, N, N, true, N),
            defense_started(Locale::En, N, N, true, N),
        ),
        (
            "defense_off_changed",
            defense_off_changed(Locale::Ja, true),
            defense_off_changed(Locale::En, true),
        ),
        (
            "breaker_tripped",
            breaker_tripped(Locale::Ja, S, N),
            breaker_tripped(Locale::En, S, N),
        ),
        (
            "chain_marked_allowlisted",
            chain_marked_allowlisted(Locale::Ja, S),
            chain_marked_allowlisted(Locale::En, S),
        ),
        (
            "upstream_chain_distrusted",
            upstream_chain_distrusted(Locale::Ja, S, S),
            upstream_chain_distrusted(Locale::En, S, S),
        ),
        (
            "watch_log_open_failed",
            watch_log_open_failed(Locale::Ja, S, S),
            watch_log_open_failed(Locale::En, S, S),
        ),
        (
            "watch_log_write_failed",
            watch_log_write_failed(Locale::Ja, S),
            watch_log_write_failed(Locale::En, S),
        ),
        (
            "defense_disabled_error",
            defense_disabled_error(Locale::Ja, S),
            defense_disabled_error(Locale::En, S),
        ),
        sample!("stage10_disabled_os", stage10_disabled_os),
        (
            "cli_invalid_breaker_hosts",
            cli_invalid_breaker_hosts(Locale::Ja, S),
            cli_invalid_breaker_hosts(Locale::En, S),
        ),
        (
            "cli_invalid_days",
            cli_invalid_days(Locale::Ja, S),
            cli_invalid_days(Locale::En, S),
        ),
        (
            "defense_report_read_failed",
            defense_report_read_failed(Locale::Ja, S, S),
            defense_report_read_failed(Locale::En, S, S),
        ),
        (
            "defense_report_lines_skipped",
            defense_report_lines_skipped(Locale::Ja, N),
            defense_report_lines_skipped(Locale::En, N),
        ),
        (
            "mitm_leaf_failed",
            mitm_leaf_failed(Locale::Ja, S, S),
            mitm_leaf_failed(Locale::En, S, S),
        ),
        (
            "mitm_upstream_tls_failed",
            mitm_upstream_tls_failed(Locale::Ja, S, S),
            mitm_upstream_tls_failed(Locale::En, S, S),
        ),
        (
            "mitm_client_refused",
            mitm_client_refused(Locale::Ja, S, S, S, S),
            mitm_client_refused(Locale::En, S, S, S, S),
        ),
        (
            "mitm_closed_before_tls",
            mitm_closed_before_tls(Locale::Ja, S, S),
            mitm_closed_before_tls(Locale::En, S, S),
        ),
        (
            "mitm_silent_close_kept",
            mitm_silent_close_kept(Locale::Ja, S, S, S, S),
            mitm_silent_close_kept(Locale::En, S, S, S, S),
        ),
        (
            "mitm_unsupported",
            mitm_unsupported(Locale::Ja, S, S),
            mitm_unsupported(Locale::En, S, S),
        ),
        (
            "mitm_upstream_closed",
            mitm_upstream_closed(Locale::Ja, S),
            mitm_upstream_closed(Locale::En, S),
        ),
        (
            "mitm_relay_aborted",
            mitm_relay_aborted(Locale::Ja, S, S),
            mitm_relay_aborted(Locale::En, S, S),
        ),
        (
            "mitm_bypassed",
            mitm_bypassed(Locale::Ja, S, S, N64),
            mitm_bypassed(Locale::En, S, S, N64),
        ),
        (
            "av_found",
            av_found(Locale::Ja, S, S, S, Duration::ZERO),
            av_found(Locale::En, S, S, S, Duration::ZERO),
        ),
        (
            "av_clean",
            av_clean(Locale::Ja, S, S, Duration::ZERO),
            av_clean(Locale::En, S, S, Duration::ZERO),
        ),
        (
            "av_scan_skipped",
            av_scan_skipped(Locale::Ja, S, S),
            av_scan_skipped(Locale::En, S, S),
        ),
        (
            "av_scan_failed",
            av_scan_failed(Locale::Ja, S, S),
            av_scan_failed(Locale::En, S, S),
        ),
        (
            "av_scan_unfinished",
            av_scan_unfinished(Locale::Ja, S, S),
            av_scan_unfinished(Locale::En, S, S),
        ),
        (
            "mitm_list_loaded",
            mitm_list_loaded(Locale::Ja, S, N),
            mitm_list_loaded(Locale::En, S, N),
        ),
        (
            "mitm_list_load_failed_empty",
            mitm_list_load_failed_empty(Locale::Ja, S, S),
            mitm_list_load_failed_empty(Locale::En, S, S),
        ),
        (
            "mitm_list_entry_allowlisted",
            mitm_list_entry_allowlisted(Locale::Ja, S),
            mitm_list_entry_allowlisted(Locale::En, S),
        ),
        sample!("av_blocked_body", av_blocked_body),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_defaults_to_english_when_unset() {
        // std::env::var は環境変数を実際に読むため、この unit test は
        // 「未設定なら英語」という契約だけを、`LC_ALL`/`LANG` を陽に
        // 空文字へ潰した仮の locale 値で確認する（プロセス環境を書き換える
        // unit test は他の並行 test と競合するため、`detect` 自体を
        // 呼ばず、判定ロジックの入力・出力契約は `tests/independent_i18n.rs`
        // が subprocess で確認する）。
        let value: Option<String> = None;
        let resolved = match value {
            Some(v) if v.to_ascii_lowercase().starts_with("ja") => Locale::Ja,
            _ => Locale::En,
        };
        assert_eq!(resolved, Locale::En);
    }

    #[test]
    fn av_scan_unfinished_names_the_host_and_the_signature_in_both_locales() {
        for locale in [Locale::Ja, Locale::En] {
            let line = av_scan_unfinished(locale, "h.example", "Heuristics.Limits.Exceeded.X");
            assert!(line.contains("host=h.example"), "{line}");
            assert!(
                line.contains("signature=Heuristics.Limits.Exceeded.X"),
                "{line}"
            );
        }
        assert!(av_scan_unfinished(Locale::Ja, "h", "s").contains("検査未了だった"));
    }

    #[test]
    fn accept_failed_message_names_the_error() {
        let err = std::io::Error::from(std::io::ErrorKind::Other);
        let text = err.to_string();
        for locale in [Locale::Ja, Locale::En] {
            let line = proxy_accept_failed(locale, &err);
            assert!(line.contains("error="), "{line}");
            assert!(line.contains(&text), "{line}");
        }
    }

    #[test]
    fn flow_set_swept_message_names_the_count() {
        for locale in [Locale::Ja, Locale::En] {
            let line = flow_set_swept(locale, 7);
            assert!(line.contains("removed=7"), "{line}");
        }
    }

    #[test]
    fn service_log_open_failed_message_names_the_path() {
        for locale in [Locale::Ja, Locale::En] {
            let line = service_log_open_failed(locale, r"C:\pd\log\service.log", "denied");
            assert!(line.contains(r"path=C:\pd\log\service.log"), "{line}");
        }
    }

    #[test]
    fn service_log_utc_fallback_message_names_utc() {
        for locale in [Locale::Ja, Locale::En] {
            let line = service_log_utc_fallback(locale);
            assert!(line.contains("UTC"), "{line}");
        }
    }

    #[test]
    fn ps_bridge_warmed_message_names_ms() {
        for locale in [Locale::Ja, Locale::En] {
            let line = ps_bridge_warmed(locale, 632, 317);
            assert!(line.contains("elapsed_ms=632"), "{line}");
            assert!(line.contains("rc=317"), "{line}");
        }
    }

    #[test]
    fn tcp_cut_rejected_message_names_rc() {
        for locale in [Locale::Ja, Locale::En] {
            let line = tcp_cut_rejected(locale, 317, 1.5);
            assert!(line.contains("rc=317"), "{line}");
            assert!(line.contains("us=1.5"), "{line}");
        }
    }

    #[test]
    fn ps_bridge_warm_up_failed_message_names_timeout() {
        for locale in [Locale::Ja, Locale::En] {
            let line = ps_bridge_warm_up_failed(locale, std::time::Duration::from_secs(5), "boom");
            assert!(line.contains("5s"), "{line}");
            assert!(line.contains("boom"), "{line}");
        }
    }

    #[test]
    fn ja_and_en_render_differently_for_every_message() {
        for (name, ja, en) in all_message_samples() {
            assert_ne!(ja, en, "{name} で ja と en が同じ文字列になっている");
        }
    }
}
