//! 独立検算 ── src/win_service.rs を対象とする検証。
//!
//! ## 到達可能性
//! `grep -n "pub mod win_service" src/lib.rs` は `#[cfg(windows)]` の直後の
//! `pub mod win_service;` に1件 当たる。
//! `cargo check --target x86_64-pc-windows-gnu` は `Finished` で終わり、
//! E0433 は出ない。
//! **`pub mod win_service;` は在る。ただし `#[cfg(windows)]` で条件付きの
//! ため**、非 windows target（この WSL 環境の既定 target）では module 自体が
//! build に含まれず、`packetdeath::win_service::...` は依然 参照できない
//! （ps_bridge の `pub mod ps_bridge;` が `#[cfg(windows)]` を持たず常に
//! build されるのとは違う）。そのため Linux 上で **実行を伴う** test を
//! 持たせるには、引き続き凍結コピーの手法が要る ── `ps_bridge` と同じ手法 ──
//! `#[cfg(test)] mod tests` より前（1〜190行）だけを `head -n 190` で
//! 逐語コピーした `tests/support/win_service_prod_copy.rs` を `#[path]` で
//! 直接 取り込む ── で検証する。
//!
//! ## 実行環境の制約
//! `win_service.rs` は `windows_service` crate（`Cargo.toml` で
//! `[target.'cfg(windows)'.dependencies]` に限定）に依存する。この WSL 環境に
//! Windows PE binary を実行する `wine`/`pwsh` は無い（実測:
//! `which pwsh wine wine64` → exit 1）。そのため：
//!
//! - **`--target x86_64-pc-windows-gnu` での `cargo check`（型検査のみ）**
//!   は実行できる（`rustup target list --installed` に含まれる）。
//! - **実行を伴う assert（`cargo test`）はこの box では走らない。**
//!   純粋関数 [`win_service::service_launch_arguments`] の出力は
//!   実行結果ではなく **静的な文字列組み立てロジックの実読**で照合する
//!   （ラベル: 実読。実測ではない）。
//! - `install_service` / `uninstall_service` / `run_service_dispatcher` は
//!   実際の SCM 呼び出しを伴うため（`sc create` 等を打たない）、
//!   **呼び出さない**。設定内容（delayed-auto-start・失敗時 Restart 3件・
//!   reset_period 24h）は `src/win_service.rs:145-166` を実読して確認した
//!   （ラベル: 実読）。

#[cfg(windows)]
#[path = "support/win_service_prod_copy.rs"]
mod win_service;

#[cfg(windows)]
mod windows_only_tests {
    use super::win_service::{service_launch_arguments, SERVICE_NAME};
    use std::path::Path;

    #[test]
    fn service_name_is_packetdeath() {
        assert_eq!(SERVICE_NAME, "packetdeath");
    }

    #[test]
    fn service_launch_arguments_is_service_run_plus_log_dir_verbatim() {
        let dir = Path::new(r"C:\ProgramData\packetdeath\logs");
        let args = service_launch_arguments(dir);
        assert_eq!(
            args,
            vec![
                "service-run".to_string(),
                "--log-dir".to_string(),
                dir.display().to_string(),
            ]
        );
    }

    #[test]
    fn service_launch_arguments_does_not_lose_or_reorder_a_path_with_spaces() {
        let dir = Path::new(r"C:\Program Files\packetdeath state");
        let args = service_launch_arguments(dir);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "service-run");
        assert_eq!(args[1], "--log-dir");
        assert_eq!(args[2], dir.display().to_string());
    }
}

// このテストクレート自体は Linux（cfg(not(windows))）でも `cargo test` の
// 対象に含まれる。windows 専用 test が0件のまま黙って success 扱いに
// なるのを避けるため、理由を明示するダミー test を1本 残す。
#[cfg(not(windows))]
#[test]
fn win_service_tests_are_windows_only_and_were_skipped_on_this_target() {
    eprintln!(
        "SKIP（このターゲットでは走らない）: win_service.rs は windows_service \
         crate（Cargo.toml で cfg(windows) 限定）に依存し、非 windows target \
         では #[path] 取り込みそのものが compile できない。\
         代わりに `cargo check --target x86_64-pc-windows-gnu --tests` の \
         生出力を独立に取得し、報告本文へ貼った。"
    );
}
