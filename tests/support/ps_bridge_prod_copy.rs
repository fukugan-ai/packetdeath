//! 常駐 PowerShell へ `SetTcpEntry` 呼び出しを依頼するパイプ層。
//!
//! `SetTcpEntry`（`iphlpapi.dll`）は `windows` crate で `pub unsafe fn` として
//! 公開されている。この crate は `Cargo.toml` に `unsafe_code = "forbid"` を
//! 持つため、Rust から直接 呼ばない（`windows.rs` 冒頭コメントが同じ判断の
//! 正本）。代わりに
//! `SetTcpEntry` を P/Invoke で呼ぶ常駐 PowerShell（[`KILL_TCP_SCRIPT`]）を
//! 子 process として起動し、標準入出力で1行1命令をやり取りする。
//!
//! 実測①：常駐させた PowerShell への
//! 2回目以降の呼び出しは 0.03ms 前後。毎回 `powershell.exe` を起動すると
//! 200ms 級のコストが乗るため、常駐させる。
//!
//! # このファイルを `target_os` で絞らない理由
//!
//! `windows.rs` と同じ判断（`lib.rs` のコメントが正本）。`powershell.exe` の
//! 起動そのものは Windows でしか成功しないが、行の組み立て・parse・
//! 子 process の生死検知は OS 非依存の byte/文字列処理であり、Linux 側の
//! `cargo test` でも PS-0〜PS-3 を検証できるようにするため、常に build する。

use crate::windows::TcpRowSpec;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// `SetTcpEntry` を呼ぶ常駐 PowerShell script の中身。単一 exe で配布し、
/// 実行時に `--log-dir` 配下へ書き出す。
///
/// **判断（`.ps1` を配布物へ同梱せず埋め込む理由）**：SYSTEM で走ると
/// `%LOCALAPPDATA%` が `C:\WINDOWS\system32\config\systemprofile\...` に
/// 変わる（実測③）ため、既定の user temp や配布 zip の相対 path に
/// 依存すると、サービス起動時に script が見つからない事故が起きる。
/// `include_str!` で exe に埋め込み、呼び出し側が確実に書ける
/// `--log-dir` 配下へ毎回 書き出せば、script の欠落・取り違えが起きない。
pub const KILL_TCP_SCRIPT: &str = include_str!("kill_tcp.ps1");

/// [`KILL_TCP_SCRIPT`] を `dir` 配下（`kill_tcp.ps1`）へ書き出す。
/// version 更新時に古い script が残らないよう、既存 file があれば上書きする。
pub fn write_script(dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("kill_tcp.ps1");
    std::fs::write(&path, KILL_TCP_SCRIPT)?;
    Ok(path)
}

/// 子 process へ渡す1行の組み立てに失敗した理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// field に改行（`\n` / `\r`）を含む値が混ざっていた。行プロトコルは
    /// 1行 = 1命令なので、改行を許すと後続の行が別の命令として誤読される
    /// （改行を含む値が来たら命令注入になる）。
    ContainsNewline,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContainsNewline => write!(f, "field に改行を含む値がある"),
        }
    }
}

/// `fields` をカンマ区切りの1行へ組み立てる。どれか1つでも `\n` / `\r` を
/// 含むなら **1 byte も書かず** `Err` を返す（PS-0）。
///
/// 現在の唯一の呼び出し元（[`encode_tcp_row_line`]）は `u32` を文字列化した
/// 値しか渡さないため実際には改行を含み得ないが、この検証は行の組み立て
/// そのものを守る汎用境界として置く。将来 SNI や生 IP 文字列を直接 渡す
/// 変更が入っても、この関数を経由する限り注入は起きない。
fn join_line_fields(fields: &[String]) -> Result<String, EncodeError> {
    if fields.iter().any(|f| f.contains(['\n', '\r'])) {
        return Err(EncodeError::ContainsNewline);
    }
    Ok(fields.join(","))
}

/// `TcpRowSpec` を `la,lp,ra,rp` の1行へ組み立てる。byte order の変換
/// 自体は `build_tcp_row_spec`（`windows.rs`）が既に済ませている
/// （PS-1 は同 module の `pw3_*` test が検証する）。ここでは文字列化と
/// 命令注入の検証だけを担う。
pub fn encode_tcp_row_line(row: &TcpRowSpec) -> Result<String, EncodeError> {
    join_line_fields(&[
        row.local_addr.to_string(),
        row.local_port.to_string(),
        row.remote_addr.to_string(),
        row.remote_port.to_string(),
    ])
}

/// 子 process から受けた1行の parse に失敗した理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseResponseError {
    /// `rc=<n> us=<f>` の形（field 数・prefix・数値表現のいずれか）に
    /// 一致しなかった。
    Malformed,
}

impl std::fmt::Display for ParseResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "rc=<n> us=<f> の形で読めない行だった"),
        }
    }
}

/// 常駐 PowerShell の応答（`rc=<n> us=<f>`）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsResponse {
    /// `SetTcpEntry` の戻り値。`0` は成功、`317` は該当接続が無い
    /// （実測①）等、Win32 error code がそのまま入る。
    pub rc: i64,
    /// script 側で計測した所要時間（マイクロ秒）。
    pub micros: f64,
}

/// `rc=<n> us=<f>` の1行を parse する。壊れた行・空行・巨大な行でも
/// panic せず `Err` を返す（PS-2）。
pub fn parse_response_line(line: &str) -> Result<PsResponse, ParseResponseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut fields = line.split_whitespace();
    let rc_field = fields.next().ok_or(ParseResponseError::Malformed)?;
    let us_field = fields.next().ok_or(ParseResponseError::Malformed)?;
    if fields.next().is_some() {
        return Err(ParseResponseError::Malformed);
    }

    let rc_str = rc_field
        .strip_prefix("rc=")
        .ok_or(ParseResponseError::Malformed)?;
    let us_str = us_field
        .strip_prefix("us=")
        .ok_or(ParseResponseError::Malformed)?;

    let rc = rc_str.parse().map_err(|_| ParseResponseError::Malformed)?;
    let micros = us_str.parse().map_err(|_| ParseResponseError::Malformed)?;
    Ok(PsResponse { rc, micros })
}

/// 子 process との入出力に失敗した理由。呼び出し側はこれを受け取ったら
/// **遮断を諦めて素通しに倒す**（PS-3）。通信そのものは止めない。
#[derive(Debug)]
pub enum BridgeError {
    Encode(EncodeError),
    /// 子 process への書き込み、または子 process からの読み取りに失敗した。
    Io(std::io::Error),
    /// stdout が EOF を返した。子 process が終了している。
    ChildClosed,
    Parse(ParseResponseError),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "命令の組み立てに失敗した: {e}"),
            Self::Io(e) => write!(f, "子 process との入出力に失敗した: {e}"),
            Self::ChildClosed => write!(f, "子 process が終了している"),
            Self::Parse(e) => write!(f, "子 process の応答を読めなかった: {e}"),
        }
    }
}

/// 常駐 PowerShell（または test 用の代替 process）へ1行1命令を送るパイプ。
pub struct PsBridge {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl PsBridge {
    /// `program` を `args` で起動し、stdin/stdout を握った状態で返す。
    pub fn spawn(program: &str, args: &[&str]) -> std::io::Result<Self> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        // `Stdio::piped()` を指定しているので通常ここは必ず `Some` だが、
        // `expect()` は使わず（`Cargo.toml` の `expect_used = "deny"`）
        // `io::Error` へ変換して呼び出し側へ伝播する。
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("spawn 直後の child.stdin が None だった"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("spawn 直後の child.stdout が None だった"))?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    /// `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script_path>`
    /// を起動する。`script_path` は [`write_script`] が返した path。
    pub fn spawn_powershell(script_path: &Path) -> std::io::Result<Self> {
        Self::spawn(
            "powershell.exe",
            &[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                &script_path.to_string_lossy(),
            ],
        )
    }

    /// `row` を子 process へ渡し、応答を1行 受ける。
    ///
    /// 子 process が既に終了している／入出力に失敗した場合は `Err` を返す。
    /// **呼び出し側はこれを遮断の失敗として扱い、通信は止めない**（PS-3）。
    pub fn send_tcp_row(&mut self, row: &TcpRowSpec) -> Result<PsResponse, BridgeError> {
        let line = encode_tcp_row_line(row).map_err(BridgeError::Encode)?;
        writeln!(self.stdin, "{line}").map_err(BridgeError::Io)?;
        self.stdin.flush().map_err(BridgeError::Io)?;

        let mut response_line = String::new();
        let bytes_read = self
            .stdout
            .read_line(&mut response_line)
            .map_err(BridgeError::Io)?;
        if bytes_read == 0 {
            return Err(BridgeError::ChildClosed);
        }
        parse_response_line(&response_line).map_err(BridgeError::Parse)
    }

    /// 子 process がまだ生きているか。`wait` と異なりブロックしない。
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for PsBridge {
    fn drop(&mut self) {
        // 子 process を明示的に kill してから wait し、defunct/zombie を
        // 残さない（`wait` を呼ばない spawn は罠になる）。終了直前の
        // kill/wait 失敗は握り潰す以外に報告先が無いため無視する。
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

