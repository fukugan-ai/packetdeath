//! 独立検算 ── `--log-dir` が本当に必須かを、
//! 実際にビルドした `packetdeath` binary を subprocess として起動して
//! 黒箱で確かめる。
//!
//! `src/main.rs` を実読して確認した事実（`main.rs:175-190, 291-300`）：
//! `parse_service_args` は `#[cfg(windows)]` を持たない OS 非依存の関数で、
//! `service-install` / `service-run` の両方でディスパッチ前に呼ばれる。
//! つまりこの検証は Linux 上で行っても、Windows 実機での挙動の代わりになる
//! （同じ code path。cfg で分岐していない）。

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_packetdeath"))
}

#[test]
fn service_run_without_log_dir_fails_fast_with_missing_required_arg() -> std::io::Result<()> {
    let output = Command::new(bin()).arg("service-run").output()?;
    assert!(
        !output.status.success(),
        "--log-dir 無しで service-run が成功してしまった（PS-4 違反）: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--log-dir"),
        "エラーメッセージに --log-dir への言及が無い: {stderr:?}"
    );
    eprintln!("[PS-4] --log-dir 無し service-run → 失敗(PASS)。stderr={stderr:?}");
    Ok(())
}

#[test]
fn service_install_without_log_dir_fails_fast_with_missing_required_arg() -> std::io::Result<()> {
    let output = Command::new(bin()).arg("service-install").output()?;
    assert!(
        !output.status.success(),
        "--log-dir 無しで service-install が成功してしまった（PS-4 違反）: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--log-dir"),
        "エラーメッセージに --log-dir への言及が無い: {stderr:?}"
    );
    eprintln!("[PS-4] --log-dir 無し service-install → 失敗(PASS)。stderr={stderr:?}");
    Ok(())
}

#[test]
fn service_run_with_log_dir_passes_arg_parsing_stage() -> std::io::Result<()> {
    // Linux 上では「Windows 専用」で FAILURE になるのが正しい仕様
    // （main.rs の #[cfg(not(windows))] 分岐）。ここで確かめたいのは
    // 「--log-dir を渡した場合に MissingRequiredArg では失敗しない」ことだけ。
    let output = Command::new(bin())
        .args(["service-run", "--log-dir", "/tmp/pd-independent-test-logdir"])
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("MissingRequiredArg") && !stderr.contains("--log-dir を明示"),
        "--log-dir を渡したのに引数不足として拒否された: {stderr:?}"
    );
    eprintln!(
        "[PS-4] --log-dir 有り service-run → 引数解析段階は通過。\
         (この機械では Windows 専用として failure になるのが仕様通り) stderr={stderr:?}"
    );
    Ok(())
}
