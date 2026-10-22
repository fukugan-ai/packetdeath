//! 常駐 PowerShell へ `SetTcpEntry` 呼び出しを依頼するパイプ層。
//!
//! `SetTcpEntry`（`iphlpapi.dll`）は `windows` crate で `pub unsafe fn` として
//! 公開されている。この crate は `Cargo.toml` に `unsafe_code = "forbid"` を
//! 持つため、Rust から直接 呼ばない（`unsafe` を使わない方針。`windows.rs` 冒頭
//! コメントが同じ判断の正本）。代わりに
//! `SetTcpEntry` を P/Invoke で呼ぶ常駐 PowerShell（[`KILL_TCP_SCRIPT`]）を
//! 子 process として起動し、標準入出力で1行1命令をやり取りする。
//!
//! 実測：常駐させた PowerShell への
//! 2回目以降の呼び出しは 0.03ms 前後。毎回 `powershell.exe` を起動すると
//! 200ms 級のコストが乗るため、常駐させる。
//!
//! # このファイルを `target_os` で絞らない理由
//!
//! `windows.rs` と同じ判断（`lib.rs` のコメントが正本）。`powershell.exe` の
//! 起動そのものは Windows でしか成功しないが、行の組み立て・parse・
//! 子 process の生死検知・timeout 処理は OS 非依存の byte/文字列処理であり、
//! Linux 側の `cargo test` でも PS-0〜PS-4 を検証できるようにするため、
//! 常に build する。
//!
//! # 応答が返らないとき（PS-4）
//!
//! [`PsBridge::send_tcp_row`] は子 process の標準出力を専用の読み取り
//! thread（[`spawn_reader`]）に任せ、本体は [`RESPONSE_TIMEOUT`] を上限に
//! `mpsc::Receiver::recv_timeout` で待つ。子 process が生きたまま応答を
//! 返さなくても、この上限で `Err(BridgeError::Timeout)` へ倒れる
//! （呼び出し側はこれを遮断の失敗として扱い、通信は止めない）。
//!
//! **timeout した [`PsBridge`] は使い回さない。**一度 timeout すると
//! `poisoned` を立てて以降の [`PsBridge::send_tcp_row`] を即 `Err` にする。
//! 読み取り thread は行単位で pipe を読み続けているため、timeout の後に
//! 子 process が遅れて応答を書いてきた場合、その行は「次の呼び出しへの
//! 応答」と誤認識されてしまう（1行1命令のプロトコルが応答1個ぶんだけ
//! ずれる）。これを避けるため、timeout 後は呼び出し側が
//! [`PsBridge`] を（`Drop` で子 process を kill させて）捨て、次の要求では
//! 新しい [`PsBridge`] を spawn し直す設計にする。

use crate::windows::TcpRowSpec;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// [`PsBridge::send_tcp_row`] が応答を待つ上限。
///
/// 実測 ── 常駐 PowerShell への呼び出しは
/// 温まった後 27〜32 マイクロ秒、1回目は JIT 込みで 92 ミリ秒。92ms の
/// 5倍強の余裕を見て 500ms とする。これより短いと、初回呼び出しや一時的な
/// CPU 競合（antivirus のスキャン等）を誤ってハングと判定し、正常な接続
/// まで fail-open で見送ってしまう。これより長いと、実際にハングした
/// ときの1接続あたりの遅延が伸びる。
const RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// How long [`PsBridge::warm_up`] waits for the first response after spawn.
///
/// The first line pays for the `powershell.exe` start and the `Add-Type` at the
/// top of the script, so it takes far longer than a line sent to a warmed
/// child. Lines after the warm-up are still bounded by [`RESPONSE_TIMEOUT`].
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The warm-up line: a 4-tuple that matches no connection.
const WARM_UP_LINE: &str = "0,0,0,0";

/// `SetTcpEntry` を呼ぶ常駐 PowerShell script の中身。単一 exe で配布し、
/// 実行時に `--log-dir` 配下へ書き出す。
///
/// **判断（`.ps1` を配布物へ同梱せず埋め込む理由）**：SYSTEM で走ると
/// `%LOCALAPPDATA%` が `C:\WINDOWS\system32\config\systemprofile\...` に
/// 変わるため、既定の user temp や配布 zip の相対 path に
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
    /// （改行を含む値は命令注入になる）。
    ContainsNewline,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContainsNewline => {
                write!(
                    f,
                    "{}",
                    crate::i18n::ps_bridge_contains_newline(crate::i18n::locale())
                )
            }
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
            Self::Malformed => {
                write!(
                    f,
                    "{}",
                    crate::i18n::ps_bridge_malformed_response(crate::i18n::locale())
                )
            }
        }
    }
}

/// 常駐 PowerShell の応答（`rc=<n> us=<f>`）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsResponse {
    /// `SetTcpEntry` の戻り値。`0` は成功、`317` は該当接続が無い
    /// 等、Win32 error code がそのまま入る。
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
    /// [`RESPONSE_TIMEOUT`] 以内に応答が来なかった。この [`PsBridge`] は
    /// 以降 [`BridgeError::Poisoned`] を返し続ける（モジュール冒頭の
    /// 「応答が返らないとき」参照）。
    Timeout,
    /// 過去に一度 [`BridgeError::Timeout`] になった [`PsBridge`] へ、
    /// さらに送信しようとした。呼び出し側は捨てて spawn し直す。
    Poisoned,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locale = crate::i18n::locale();
        let s = match self {
            Self::Encode(e) => crate::i18n::ps_bridge_encode_failed(locale, e),
            Self::Io(e) => crate::i18n::ps_bridge_io_failed(locale, e),
            Self::ChildClosed => crate::i18n::ps_bridge_child_closed(locale),
            Self::Parse(e) => crate::i18n::ps_bridge_parse_failed(locale, e),
            Self::Timeout => crate::i18n::ps_bridge_timeout(locale, RESPONSE_TIMEOUT),
            Self::Poisoned => crate::i18n::ps_bridge_poisoned(locale),
        };
        write!(f, "{s}")
    }
}

/// 読み取り thread（[`spawn_reader`]）が本体へ送る1件。
enum ReaderMsg {
    /// 1行 読めた（改行込み。[`parse_response_line`] が末尾の改行を剥がす）。
    Line(String),
    /// `read_line` が `Ok(0)`（EOF）を返した。子 process が終了している。
    ChildClosed,
    /// `read_line` が `Err` を返した。
    Io(std::io::Error),
}

/// `stdout` を専用 thread に持たせ、1行 読むたびに `tx` へ送る。
///
/// **本体（[`PsBridge::send_tcp_row`]）が `recv_timeout` で待つ間も、この
/// thread は `read_line` で block したままでよい。**timeout 後に子 process が
/// 遅れて書いてきた行は、`tx` の送信先（[`PsBridge`] が持つ `Receiver`）が
/// 既に無くなっていれば `send` が `Err` を返すので、その時点で thread は
/// 静かに終了する（モジュール冒頭「応答が返らないとき」参照）。
fn spawn_reader(
    mut stdout: BufReader<ChildStdout>,
    tx: mpsc::Sender<ReaderMsg>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        let mut line = String::new();
        let msg = match stdout.read_line(&mut line) {
            Ok(0) => {
                let _ = tx.send(ReaderMsg::ChildClosed);
                return;
            }
            Ok(_) => ReaderMsg::Line(line),
            Err(e) => {
                let _ = tx.send(ReaderMsg::Io(e));
                return;
            }
        };
        if tx.send(msg).is_err() {
            // 受信側（PsBridge）が既に drop 済み。これ以上 読んでも渡す先が
            // 無いので thread を終える。
            return;
        }
    })
}

/// 常駐 PowerShell（または test 用の代替 process）へ1行1命令を送るパイプ。
pub struct PsBridge {
    child: Child,
    stdin: ChildStdin,
    response_rx: mpsc::Receiver<ReaderMsg>,
    /// 一度 [`BridgeError::Timeout`] になったら `true`。以降の
    /// [`PsBridge::send_tcp_row`] はプロトコルのずれを避けるため即 `Err` を
    /// 返す（モジュール冒頭「応答が返らないとき」参照）。
    poisoned: bool,
}

impl PsBridge {
    /// `program` を `args` で起動し、stdin を握り、stdout は専用 thread に
    /// 読ませた状態で返す。
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
        let stdin = child.stdin.take().ok_or_else(|| {
            std::io::Error::other(crate::i18n::ps_bridge_stdin_none(crate::i18n::locale()))
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::other(crate::i18n::ps_bridge_stdout_none(crate::i18n::locale()))
        })?;

        let (tx, response_rx) = mpsc::channel();
        // JoinHandle は保持しない（fire-and-forget）。この thread は
        // `PsBridge` が drop されて `response_rx` が閉じるか、子 process が
        // 終了して `read_line` が抜けるかのどちらかで必ず終わる。
        let _ = spawn_reader(BufReader::new(stdout), tx);

        Ok(Self {
            child,
            stdin,
            response_rx,
            poisoned: false,
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
    /// [`RESPONSE_TIMEOUT`] 以内に応答が来なければ `Err(BridgeError::Timeout)`
    /// を返し、この `PsBridge` を以降 使えなくする。
    /// **呼び出し側はこれを遮断の失敗として扱い、通信は止めない**（PS-3・
    /// PS-4）。
    pub fn send_tcp_row(&mut self, row: &TcpRowSpec) -> Result<PsResponse, BridgeError> {
        if self.poisoned {
            return Err(BridgeError::Poisoned);
        }

        let line = encode_tcp_row_line(row).map_err(BridgeError::Encode)?;
        self.exchange(&line, RESPONSE_TIMEOUT)
    }

    /// Sends [`WARM_UP_LINE`] and waits up to `timeout` for the first response
    /// of a freshly spawned child.
    ///
    /// Any readable response counts as warmed; the caller reads `rc` from the
    /// returned [`PsResponse`]. A timeout poisons this bridge like
    /// [`PsBridge::send_tcp_row`] does, so the caller drops it.
    pub fn warm_up(&mut self, timeout: Duration) -> Result<PsResponse, BridgeError> {
        if self.poisoned {
            return Err(BridgeError::Poisoned);
        }
        self.exchange(WARM_UP_LINE, timeout)
    }

    /// Writes one line to the child and waits up to `timeout` for one response.
    fn exchange(&mut self, line: &str, timeout: Duration) -> Result<PsResponse, BridgeError> {
        writeln!(self.stdin, "{line}").map_err(BridgeError::Io)?;
        self.stdin.flush().map_err(BridgeError::Io)?;

        match self.response_rx.recv_timeout(timeout) {
            Ok(ReaderMsg::Line(response_line)) => {
                parse_response_line(&response_line).map_err(BridgeError::Parse)
            }
            Ok(ReaderMsg::ChildClosed) => Err(BridgeError::ChildClosed),
            Ok(ReaderMsg::Io(e)) => Err(BridgeError::Io(e)),
            // 読み取り thread が既に終了して送信側 (`Sender`) が drop 済み。
            // 子 process が終了したときと同じ扱いにする。
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(BridgeError::ChildClosed),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.poisoned = true;
                crate::flow::service_log(&format!(
                    "packetdeath: [warn] {}",
                    crate::i18n::ps_bridge_response_timeout_discard(crate::i18n::locale(), timeout)
                ));
                Err(BridgeError::Timeout)
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowKey, Proto};
    use crate::windows::build_tcp_row_spec;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    /// テストだけが使う「すぐ終了する process」の名前。Unix と Windows で
    /// 標準に存在するコマンドが違うため OS ごとに分ける。
    #[cfg(unix)]
    const EXIT_IMMEDIATELY: (&str, &[&str]) = ("true", &[]);
    #[cfg(windows)]
    const EXIT_IMMEDIATELY: (&str, &[&str]) = ("cmd.exe", &["/C", "exit"]);

    /// テストだけが使う「生きたまま応答を返さない process」の名前
    /// （PS-4：timeout の検証用）。
    #[cfg(unix)]
    const HANGS_FOREVER: (&str, &[&str]) = ("sleep", &["30"]);
    #[cfg(windows)]
    const HANGS_FOREVER: (&str, &[&str]) = (
        "powershell.exe",
        &["-NoProfile", "-Command", "Start-Sleep -Seconds 30"],
    );

    fn sample_row() -> Result<TcpRowSpec, String> {
        let key = FlowKey {
            proto: Proto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 200, 20)),
            src_port: 59012,
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 66, 147, 243)),
            dst_port: 443,
        };
        build_tcp_row_spec(&key)
            .ok_or_else(|| "proto=Tcp かつ IPv4 の key は必ず組める".to_string())
    }

    #[test]
    fn ps0_negative_control_rejects_field_with_newline() {
        let result = join_line_fields(&["bad\nvalue".to_string()]);
        assert_eq!(result, Err(EncodeError::ContainsNewline));
    }

    #[test]
    fn ps0_rejects_field_with_carriage_return() {
        let result = join_line_fields(&["bad\rvalue".to_string()]);
        assert_eq!(result, Err(EncodeError::ContainsNewline));
    }

    #[test]
    fn ps0_accepts_normal_fields_and_joins_with_comma() -> Result<(), String> {
        let line =
            join_line_fields(&["1".to_string(), "2".to_string()]).map_err(|e| e.to_string())?;
        assert_eq!(line, "1,2");
        Ok(())
    }

    #[test]
    fn ps1_encode_tcp_row_line_uses_network_byte_order_port() -> Result<(), String> {
        // PW-3（windows.rs）と同じ 443 -> 0xBB01（= 47873）を、行の中でも確認する。
        let row = sample_row()?;
        let line = encode_tcp_row_line(&row).map_err(|e| e.to_string())?;
        let fields: Vec<&str> = line.split(',').collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[3], "47873");
        Ok(())
    }

    #[test]
    fn ps2_parses_normal_response_line() -> Result<(), String> {
        let resp = parse_response_line("rc=317 us=31.6\n").map_err(|e| e.to_string())?;
        assert_eq!(resp.rc, 317);
        assert!((resp.micros - 31.6).abs() < 1e-9);
        Ok(())
    }

    #[test]
    fn ps2_rejects_empty_line_without_panic() {
        assert_eq!(parse_response_line(""), Err(ParseResponseError::Malformed));
    }

    #[test]
    fn ps2_rejects_line_missing_us_field_without_panic() {
        assert_eq!(
            parse_response_line("rc=317"),
            Err(ParseResponseError::Malformed)
        );
    }

    #[test]
    fn ps2_rejects_garbage_line_without_panic() {
        assert_eq!(
            parse_response_line("not a response at all"),
            Err(ParseResponseError::Malformed)
        );
    }

    #[test]
    fn ps2_rejects_huge_line_without_panic() {
        // 巨大な数値 field は i64::parse に失敗するので Err になる。
        let huge = format!("rc={} us=1.0", "9".repeat(10_000));
        assert_eq!(
            parse_response_line(&huge),
            Err(ParseResponseError::Malformed)
        );
    }

    #[test]
    fn ps2_rejects_extra_trailing_field_without_panic() {
        assert_eq!(
            parse_response_line("rc=317 us=31.6 extra"),
            Err(ParseResponseError::Malformed)
        );
    }

    #[test]
    fn ps3_falls_open_when_child_has_already_exited() -> Result<(), String> {
        let (program, args) = EXIT_IMMEDIATELY;
        let mut bridge = PsBridge::spawn(program, args).map_err(|e| e.to_string())?;

        // 子 process が実際に終了するまで待つ（`try_wait` はブロックしない
        // ので polling する）。
        for _ in 0..200 {
            if !bridge.is_alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !bridge.is_alive(),
            "test 前提: 子 process は既に終了している"
        );

        let row = sample_row()?;
        let result = bridge.send_tcp_row(&row);
        assert!(
            matches!(
                result,
                Err(BridgeError::Io(_)) | Err(BridgeError::ChildClosed)
            ),
            "死んだ子 process への送信は Err で返るべき（PS-3）: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn ps4_hung_child_fails_open_within_timeout_not_forever() -> Result<(), String> {
        let (program, args) = HANGS_FOREVER;
        let mut bridge = PsBridge::spawn(program, args).map_err(|e| e.to_string())?;
        assert!(bridge.is_alive(), "test 前提: 子 process はまだ生きている");

        let row = sample_row()?;
        let started = std::time::Instant::now();
        let result = bridge.send_tcp_row(&row);
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(BridgeError::Timeout)),
            "生きたまま応答しない子への送信は Timeout で返るべき（PS-4）: {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(RESPONSE_TIMEOUT.as_secs() + 4),
            "RESPONSE_TIMEOUT（{RESPONSE_TIMEOUT:?}）を大幅に超えて {elapsed:?} かかった"
        );

        // timeout 後は poisoned になり、以降 即 Err（プロトコルのずれを防ぐ）。
        let second = bridge.send_tcp_row(&row);
        assert!(
            matches!(second, Err(BridgeError::Poisoned)),
            "timeout 後の再送信は Poisoned であるべき: {second:?}"
        );
        Ok(())
    }

    /// The first response takes 700 ms, longer than `RESPONSE_TIMEOUT`, so
    /// waiting for it with the row limit would time out.
    #[cfg(unix)]
    #[test]
    fn warm_up_accepts_a_slow_first_response_within_startup_timeout() -> Result<(), String> {
        let mut bridge = PsBridge::spawn(
            "sh",
            &[
                "-c",
                "read l; sleep 0.7; echo 'rc=317 us=1.0'; cat >/dev/null",
            ],
        )
        .map_err(|e| e.to_string())?;

        let resp = bridge
            .warm_up(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        assert_eq!(resp.rc, 317);
        Ok(())
    }

    #[test]
    fn warm_up_times_out_when_no_response_within_startup_timeout() -> Result<(), String> {
        let (program, args) = HANGS_FOREVER;
        let mut bridge = PsBridge::spawn(program, args).map_err(|e| e.to_string())?;
        let limit = Duration::from_millis(300);

        let started = std::time::Instant::now();
        let result = bridge.warm_up(limit);
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(BridgeError::Timeout)),
            "a child that never answers must time out the warm-up: {result:?}"
        );
        assert!(
            elapsed < limit + Duration::from_secs(4),
            "warm-up took {elapsed:?} against a limit of {limit:?}"
        );

        let second = bridge.send_tcp_row(&sample_row()?);
        assert!(
            matches!(second, Err(BridgeError::Poisoned)),
            "a bridge whose warm-up timed out must stay poisoned: {second:?}"
        );
        Ok(())
    }

    /// After a successful warm-up the per-row limit is still `RESPONSE_TIMEOUT`.
    #[cfg(unix)]
    #[test]
    fn a_warmed_bridge_keeps_the_row_timeout() -> Result<(), String> {
        let mut bridge = PsBridge::spawn("sh", &["-c", "read l; echo 'rc=317 us=1.0'; sleep 30"])
            .map_err(|e| e.to_string())?;
        bridge
            .warm_up(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;

        let started = std::time::Instant::now();
        let result = bridge.send_tcp_row(&sample_row()?);
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(BridgeError::Timeout)),
            "the row after the warm-up gets no answer and must time out: {result:?}"
        );
        assert!(
            elapsed < RESPONSE_TIMEOUT + Duration::from_secs(4),
            "the row waited {elapsed:?}; the warm-up limit leaked into the row limit"
        );
        Ok(())
    }

    #[test]
    fn spawn_returns_err_when_program_does_not_exist() {
        let result = PsBridge::spawn("packetdeath-nonexistent-binary-xyz", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn spawn_powershell_returns_err_when_powershell_missing() {
        // この環境（Linux）には powershell.exe が無いため、必ず Err になる。
        // 起動失敗を静かに握り潰さないことの確認（陽性対照）。
        let result = PsBridge::spawn_powershell(Path::new("/nonexistent/kill_tcp.ps1"));
        assert!(result.is_err());
    }

    #[test]
    fn write_script_writes_readable_content() -> Result<(), String> {
        let dir =
            std::env::temp_dir().join(format!("packetdeath-ps-bridge-test-{}", std::process::id()));
        let path = write_script(&dir).map_err(|e| e.to_string())?;
        let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        assert_eq!(content, KILL_TCP_SCRIPT);
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(())
    }
}
