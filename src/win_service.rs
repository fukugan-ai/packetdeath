//! packetdeath を Windows サービスとして常駐させる層。
//! `packetdeath service-install` / `service-uninstall` / `service-run` の実体。
//!
//! # `unsafe` を書かない
//!
//! `windows-service` crate 自身は内部で Win32 API（`SetServiceStatus` 等）を
//! `unsafe` で呼ぶが、この crate（packetdeath）はそれを safe な公開 API
//! （`ServiceManager` / `Service` / `service_control_handler` のメソッド）
//! 経由でしか呼ばない。`Cargo.toml` の `unsafe_code = "forbid"` は
//! packetdeath 自身の code に対する制約であり、依存 crate 内部の unsafe には
//! 及ばない（`Cargo.toml` の該当 comment が正本）。
//!
//! # なぜサービスにするか
//!
//! 起動時遅延ありのサービスとして登録する。タスクスケジューラは自動再起動を
//! 持たないため採らない。
//!
//! # 実際の遮断 loop（`block_loop.rs` への配線）
//!
//! pktmon の運用（`etl2pcap` を何秒ごとに回すか）は利用者が行う（`windows.rs`
//! 冒頭コメント）。[`run_service`] は SCM の stop/shutdown 要求に応答しつつ、
//! [`ServiceRuntimeConfig::pcapng_path`] が指定されていれば
//! `block_loop::run_watch_loop` を回して pcapng を監視し、blocklist に当たる
//! SNI の接続を常駐 PowerShell 経由で切る。`pcapng_path` が未指定（`--pcapng`
//! を渡さずに起動した）ときは、従来どおり stop/shutdown を待つだけの骨格
//! 動作にフォールバックする。
//!
//! # `service_main_entry` へ設定を渡す経路（判断）
//!
//! `windows_service::define_windows_service!` が生成する `service_main_entry`
//! は SCM が直接 呼ぶ静的関数で、closure の capture ができない。そのため
//! `service-run` の CLI 引数から作った [`ServiceRuntimeConfig`] を
//! `SERVICE_CONFIG`（`OnceLock`。`unsafe` を使わない安全な static）へ積み、
//! `run_service` 側で読み出す。`OnceLock::set` の2回目以降の呼び出しは
//! 失敗するが、1 process につき `run_service_dispatcher` は1回しか呼ばれない
//! 契約（SCM が1 process に対して1回だけ entry point を起動する）なので
//! 実害は無い。

use crate::allowlist::Allowlist;
use crate::av::AvList;
use crate::block_loop::{self, NoopBlocker, RespawningPsBridge, TcpBlocker, WatchInputs};
use crate::blocklist::Blocklist;
use crate::flow::FlowLogSink;
use crate::iplist::IpList;
use crate::ps_bridge;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

/// pcapng を監視する間隔。`win_service.rs` 冒頭の SCM stop poll と同じ
/// 1秒にし、体感遅延と CPU 負荷のどちらも実務上 無視できる値にする
/// （`block_loop.rs`「pcapng file をどう監視するか」の判断と対になる値）。
/// pcapng を読み直す間隔。
///
/// 実測 ── 広告のやり取りは 0.05〜0.32 秒 で完結する
/// （実機の cap.pcapng を parse した結果。8 flow 中 7 flow が 1000 byte 超を
/// 受信済みで、全部 0.32 秒 以内に終わっていた）。
/// 一方 pktmon の rotate 周期は 中央 11 秒 だった（pktmon-rotate.log 19 区間）。
/// **遅れの支配項は rotate 側であり、poll は 1 秒 でも足を引っ張らない。**
/// ただし rotate を 3 秒 へ詰めたので、poll も 300 ms へ下げて
/// 「pcapng が更新されてから読むまで」の待ちを削る。
///
/// 🔴 下げすぎると、更新途中の pcapng を読む回数が増える。
/// `block_loop::run_watch_loop` は読めない回を skip して次へ進む（fail-open）ので
/// 壊れはしないが、無駄な読み直しが増える。300 ms は rotate 3 秒 の 1/10 である。
const PCAPNG_POLL_INTERVAL: Duration = Duration::from_millis(300);

/// `service-run` の CLI 引数から作る、`run_service` が実際に使う設定。
/// `service_main_entry` は引数を受け取れないため `SERVICE_CONFIG` 経由で渡す。
pub struct ServiceRuntimeConfig {
    pub log_dir: PathBuf,
    /// 利用者が `pktmon etl2pcap` で作る pcapng の path。`None` なら
    /// 監視 loop を回さず、SCM の stop/shutdown 待ちだけの骨格動作にする。
    pub pcapng_path: Option<PathBuf>,
    /// blocklist の path。`None`（または読めない）なら空の blocklist
    /// （何も落とさない）として動く（`blocklist.rs` の既定判断と同じ）。
    pub blocklist_path: Option<PathBuf>,
    /// 「当たっても通す」allowlist の path。`None`（または読めない）なら
    /// 空の allowlist（何も救わない＝従来どおりの挙動）として動く
    /// （`allowlist.rs` の既定判断と同じ）。
    pub allowlist_path: Option<PathBuf>,
}

static SERVICE_CONFIG: OnceLock<ServiceRuntimeConfig> = OnceLock::new();

/// SCM に登録するサービス名・表示名。
pub const SERVICE_NAME: &str = "packetdeath";
const SERVICE_DISPLAY_NAME: &str = "packetdeath";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main_entry);

/// `service-run` から呼ぶ。`config` を `SERVICE_CONFIG` へ積んでから、
/// SCM が `ffi_service_main` を起動するまでこのスレッドをブロックする
/// （`windows_service::service_dispatcher::start` の契約）。
///
/// `SERVICE_CONFIG.set` が2回目以降 失敗しても無視する（モジュール冒頭
/// 「`service_main_entry` へ設定を渡す経路」の判断どおり、1 process につき
/// 1回しか呼ばれない契約のため実害が無い）。
pub fn run_service_dispatcher(config: ServiceRuntimeConfig) -> windows_service::Result<()> {
    let _ = SERVICE_CONFIG.set(config);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// SCM が背景 thread で呼ぶ実際の entry point。戻り値を返せないため、
/// 失敗はここで飲み込む以外に報告先が無い（SCM へは exit code で伝える）。
fn service_main_entry(_arguments: Vec<OsString>) {
    let _ = run_service();
}

fn running_status() -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn stopped_status() -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn run_service() -> windows_service::Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // 受信側が既に無くなっていても（二重送信等）失敗を無視する。
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status_handle.set_service_status(running_status())?;

    match SERVICE_CONFIG.get() {
        Some(config) => run_block_loop_until_stop(config, &stop_rx),
        // `--pcapng` を渡さずに起動した（または test 経路で config 未設定）。
        // stop/shutdown が来るまで待つだけの骨格動作。
        None => while stop_rx.recv_timeout(Duration::from_secs(1)).is_err() {},
    }

    status_handle.set_service_status(stopped_status())?;
    Ok(())
}

/// `config.pcapng_path` が指定されていれば `block_loop::run_watch_loop` を
/// 回し、指定されていなければ stop/shutdown を待つだけの骨格動作にする。
///
/// blocklist・flow log・常駐 PowerShell のいずれかが開けない／spawn できない
/// 場合も、サービス自体は落とさず fail-open へ倒す
/// （遮断できないときに通信を止めない、と同じ精神を起動時の失敗にも適用する）。
/// **flow log だけは例外**：`<log_dir>/flows.jsonl` が開けないのは
/// `--log-dir` の権限設定ミス等、運用上 見過ごせない致命的な状態なので、
/// stop/shutdown 待ちの骨格へ倒して早期に `service-run` を終わらせ、
/// `install_service` が設定した自動再起動（Restart 3件）に委ねる。
fn run_block_loop_until_stop(config: &ServiceRuntimeConfig, stop_rx: &mpsc::Receiver<()>) {
    let locale = crate::i18n::locale();
    let Some(pcapng_path) = config.pcapng_path.as_deref() else {
        crate::flow::service_log(&format!(
            "packetdeath: [info] {}",
            crate::i18n::pcapng_not_specified_wait_stop(locale)
        ));
        while stop_rx.recv_timeout(Duration::from_secs(1)).is_err() {}
        return;
    };

    let blocklist = match config.blocklist_path.as_deref() {
        Some(path) => Blocklist::load(path).unwrap_or_else(|e| {
            crate::flow::service_log(&format!(
                "packetdeath: [warn] {}",
                crate::i18n::blocklist_load_failed_empty(locale, path.display(), e)
            ));
            Blocklist::empty()
        }),
        None => Blocklist::empty(),
    };

    // 「当たっても通す」allowlist。blocklist / iplist / av のどれよりも
    // 先に効く（`docs/design.md`「判定を差し込む口」。`block_loop::judge_and_log`
    // が先頭でチェックする）。
    let allowlist = match config.allowlist_path.as_deref() {
        Some(path) => Allowlist::load(path).unwrap_or_else(|e| {
            crate::flow::service_log(&format!(
                "packetdeath: [warn] {}",
                crate::i18n::allowlist_load_failed_empty(locale, path.display(), e)
            ));
            Allowlist::empty()
        }),
        None => Allowlist::empty(),
    };

    let flows_path = config.log_dir.join("flows.jsonl");
    let log = match FlowLogSink::open(&flows_path) {
        Ok(sink) => sink,
        Err(e) => {
            crate::flow::service_log(&format!(
                "packetdeath: [error] {}",
                crate::i18n::flow_log_open_failed_wait_stop(locale, flows_path.display(), e)
            ));
            while stop_rx.recv_timeout(Duration::from_secs(1)).is_err() {}
            return;
        }
    };

    let mut noop = NoopBlocker;
    let mut respawning;
    let blocker: &mut dyn TcpBlocker = match ps_bridge::write_script(&config.log_dir) {
        Ok(script_path) => {
            respawning = RespawningPsBridge::new(script_path);
            respawning.prepare();
            &mut respawning
        }
        Err(e) => {
            crate::flow::service_log(&format!(
                "packetdeath: [error] {}",
                crate::i18n::kill_tcp_script_write_failed(locale, e)
            ));
            &mut noop
        }
    };

    // 段階5「宛先 IP list」の Windows CLI 公開（`ServiceRuntimeConfig` への
    // `--iplist` 追加）は範囲外（実機は範囲外、`docs/design.md` に
    // Windows 向けの iplist 受入 ID が無い）。`run_watch_loop` は
    // `linux.rs::run_block` と共に IpJudge を使える core であることだけを
    // 満たし、常に空の iplist（何も落とさない）で動かす。

    // 段階6「外部 scanner の verdict 取り込み」の Windows CLI 公開
    // （`ServiceRuntimeConfig` への `--av` 追加）も同じ理由で範囲外
    // （`docs/design.md` に Windows 向けの av 受入 ID が無い）。iplist と
    // 同じ扱いで、常に空の av 集合（何も落とさない）で動かす。
    let av = AvList::empty();

    // blocklist / allowlist は走行中に読み直す（再起動なしで編集を反映する）。
    // `WatchInputs` が path を覚え、`run_watch_loop` が poll ごとに変化を確かめる
    // （`block_loop.rs`「走行中の blocklist / allowlist 読み直し」の判断）。
    let blocklist_files = match config.blocklist_path.clone() {
        Some(path) => vec![(path, blocklist)],
        None => Vec::new(),
    };
    let mut inputs = WatchInputs::new(
        Blocklist::empty(),
        allowlist,
        config.allowlist_path.clone(),
        IpList::empty(),
        &av,
    )
    .with_blocklist_files(blocklist_files);
    block_loop::run_watch_loop(
        pcapng_path,
        PCAPNG_POLL_INTERVAL,
        &mut inputs,
        blocker,
        &log,
        stop_rx,
    );
}

/// `service-install` が SCM へ渡す起動引数（`service-run --log-dir <log_dir>
/// [--pcapng <path>] [--blocklist <path>]`）を組み立てる。`windows-service` の
/// 型に依存しない純粋関数として切り出し、Linux 側の `cargo test` でも
/// 検証できるようにする。
///
/// `pcapng_path` / `blocklist_path` / `allowlist_path` が `None` なら、その
/// 引数を一切 載せない（今までどおり `--log-dir` だけの起動引数になる。既存の
/// test が守る契約）。`service-run` 側は既にこの3つを parse できる
/// （`main.rs` の `parse_service_args`）ので、載せる側だけを直す。
pub fn service_launch_arguments(
    log_dir: &Path,
    pcapng_path: Option<&Path>,
    blocklist_path: Option<&Path>,
    allowlist_path: Option<&Path>,
) -> Vec<String> {
    let mut args = vec![
        "service-run".to_string(),
        "--log-dir".to_string(),
        log_dir.display().to_string(),
    ];
    if let Some(path) = pcapng_path {
        args.push("--pcapng".to_string());
        args.push(path.display().to_string());
    }
    if let Some(path) = blocklist_path {
        args.push("--blocklist".to_string());
        args.push(path.display().to_string());
    }
    if let Some(path) = allowlist_path {
        args.push("--allowlist".to_string());
        args.push(path.display().to_string());
    }
    args
}

/// `sc create` 相当。
///
/// 設定する内容：
/// - 起動種別：`AutoStart` + [`Service::set_delayed_auto_start`] で
///   delayed-auto にする（起動時遅延あり）。
/// - 失敗時の動作：[`Service::update_failure_actions`] で1回目・2回目・
///   3回目以降のすべてを `Restart` にし、`reset_period` を1日にする
///   （タスクスケジューラに無い自動再起動）。
///   `set_failure_actions_on_non_crash_failures(true)` も併せて設定し、
///   クラッシュでない終了（設定 error 等）でも再起動対象にする。
pub fn install_service(
    log_dir: &Path,
    pcapng_path: Option<&Path>,
    blocklist_path: Option<&Path>,
    allowlist_path: Option<&Path>,
) -> windows_service::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let executable_path = std::env::current_exe().map_err(windows_service::Error::Winapi)?;

    let launch_arguments =
        service_launch_arguments(log_dir, pcapng_path, blocklist_path, allowlist_path)
            .into_iter()
            .map(OsString::from)
            .collect();

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments,
        dependencies: vec![],
        // `None` は LocalSystem。SYSTEM で走ると `%LOCALAPPDATA%` が変わる
        // ため `--log-dir` を必須にしている（main.rs）。
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    service.set_delayed_auto_start(true)?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(60),
            },
        ]),
    })?;
    Ok(())
}

/// `sc delete` 相当。
pub fn uninstall_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn service_launch_arguments_includes_log_dir_flag() {
        // `--pcapng` / `--blocklist` / `--allowlist` を渡さなければ、今までどおり
        // `--log-dir` だけの起動引数になる（穴を塞ぐ前の契約を保つ）。
        let args = service_launch_arguments(
            &PathBuf::from(r"C:\ProgramData\packetdeath"),
            None,
            None,
            None,
        );
        assert_eq!(
            args,
            vec![
                "service-run".to_string(),
                "--log-dir".to_string(),
                r"C:\ProgramData\packetdeath".to_string(),
            ]
        );
    }

    #[test]
    fn service_launch_arguments_starts_with_service_run() {
        let args = service_launch_arguments(&PathBuf::from("."), None, None, None);
        assert_eq!(args.first().map(String::as_str), Some("service-run"));
    }

    #[test]
    fn service_launch_arguments_includes_pcapng_and_blocklist_when_given() {
        // service-install で登録したサービスが遮断しない穴を塞ぐ。`--pcapng` / `--blocklist` を渡したら、この順で起動引数へ載る。
        let args = service_launch_arguments(
            &PathBuf::from(r"C:\ProgramData\packetdeath"),
            Some(&PathBuf::from(r"C:\capture.pcapng")),
            Some(&PathBuf::from(r"C:\blocklist.txt")),
            None,
        );
        assert_eq!(
            args,
            vec![
                "service-run".to_string(),
                "--log-dir".to_string(),
                r"C:\ProgramData\packetdeath".to_string(),
                "--pcapng".to_string(),
                r"C:\capture.pcapng".to_string(),
                "--blocklist".to_string(),
                r"C:\blocklist.txt".to_string(),
            ]
        );
    }

    #[test]
    fn service_launch_arguments_includes_allowlist_when_given() {
        // --allowlist を渡したら起動引数の末尾へ載る。
        let args = service_launch_arguments(
            &PathBuf::from(r"C:\ProgramData\packetdeath"),
            None,
            None,
            Some(&PathBuf::from(r"C:\allowlist.txt")),
        );
        assert_eq!(
            args,
            vec![
                "service-run".to_string(),
                "--log-dir".to_string(),
                r"C:\ProgramData\packetdeath".to_string(),
                "--allowlist".to_string(),
                r"C:\allowlist.txt".to_string(),
            ]
        );
    }
}
