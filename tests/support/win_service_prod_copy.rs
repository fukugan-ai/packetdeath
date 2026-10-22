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
//! 及ばない（`Cargo.toml` の該当 comment、実測②が正本）。
//!
//! # なぜサービスにするか
//!
//! 起動時遅延ありのサービス登録を採る。サービスは設定の信頼性が高く、
//! タスクスケジューラは自動再起動を持たないため採らない
//! （設計の「採らない手段」表）。
//!
//! # 実際の遮断 loop はここに無い
//!
//! pktmon の運用（`etl2pcap` を何秒ごとに回すか）は `windows.rs` 冒頭コメント
//! の通り `未確認`／範囲外（別途進める）。[`run_service`] は SCM の
//! stop/shutdown 要求に応答する骨格だけを持ち、その中身（pcapng 読み取り→
//! `judge_sni`→`ps_bridge::PsBridge`）の統合はこのファイルの範囲外。

use std::ffi::OsString;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

/// SCM に登録するサービス名・表示名。
pub const SERVICE_NAME: &str = "packetdeath";
const SERVICE_DISPLAY_NAME: &str = "packetdeath";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main_entry);

/// `service-run` から呼ぶ。SCM が `ffi_service_main` を起動するまで
/// このスレッドをブロックする（`windows_service::service_dispatcher::start`
/// の契約）。
pub fn run_service_dispatcher() -> windows_service::Result<()> {
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

    // stop/shutdown が来るまで待つ骨格。実際の遮断 loop の統合は範囲外
    // （本 module 冒頭コメント）。
    while stop_rx.recv_timeout(Duration::from_secs(1)).is_err() {}

    status_handle.set_service_status(stopped_status())?;
    Ok(())
}

/// `service-install` / `service-uninstall` が SCM へ渡す起動引数
/// （`service-run --log-dir <log_dir>`）を組み立てる。`windows-service` の
/// 型に依存しない純粋関数として切り出し、Linux 側の `cargo test` でも
/// 検証できるようにする。
pub fn service_launch_arguments(log_dir: &Path) -> Vec<String> {
    vec![
        "service-run".to_string(),
        "--log-dir".to_string(),
        log_dir.display().to_string(),
    ]
}

/// `sc create` 相当。実装するだけで、test からは呼ばない。
///
/// 設定する内容：
/// - 起動種別：`AutoStart` + [`Service::set_delayed_auto_start`] で
///   delayed-auto にする（起動時遅延あり）。
/// - 失敗時の動作：[`Service::update_failure_actions`] で1回目・2回目・
///   3回目以降のすべてを `Restart` にし、`reset_period` を1日にする
///   （タスクスケジューラに無い自動再起動）。
///   `set_failure_actions_on_non_crash_failures(true)` も併せて設定し、
///   クラッシュでない終了（設定 error 等）でも再起動対象にする。
pub fn install_service(log_dir: &Path) -> windows_service::Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let executable_path = std::env::current_exe().map_err(windows_service::Error::Winapi)?;

    let launch_arguments = service_launch_arguments(log_dir)
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

/// `sc delete` 相当。実装するだけで、test からは呼ばない。
pub fn uninstall_service() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()
}

