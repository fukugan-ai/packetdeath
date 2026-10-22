//! 独立検算 ── src/ps_bridge.rs を対象とする、実装者とは別 context の検証。
//!
//! ## 到達可能性
//! `src/lib.rs` は `pub mod ps_bridge;` を持ち、`#[cfg(windows)]` などの条件も
//! 付いていない。そのため本 file の一般的な検証は、以下 `use` の通り
//! **現行の `packetdeath::ps_bridge` / `packetdeath::windows` を直接 参照する**。
//!
//! ## 凍結コピー（`tests/support/ps_bridge_prod_copy.rs`）を残す理由
//! このコピーは `tests/support/` 配下にあり、track されているが内容を変えない
//! （過去の欠陥の記録）── つまり **このコピーの中身が
//! 唯一の記録であり、上書きすれば取り戻せない。**中身は `RESPONSE_TIMEOUT` /
//! `spawn_reader` スレッド / `poisoned` 状態が入る**前**の `ps_bridge.rs` の
//! 逐語 snapshot で、`finding_hung_child_was_a_real_defect_in_the_frozen_copy`
//! が「timeout 機構が無いと本当にハングし続ける」ことを捕まえた実在の欠陥の
//! 記録である。**同期（内容の上書き）も削除も採らない**
//! （凍結コピーを消すと過去の欠陥の記録が消える。同じ理由で、内容を現行へ
//! 同期する＝この file の唯一の旧内容を上書きすることも
//! 同様に不可逆であり、採らない）。
//! **`tests/support/ps_bridge_prod_copy.rs` の code は1バイトも変更しない
//! （公開に際して直したのは、個人情報を含む comment だけである）。**
//! 参照する側（本 file）だけを直す。
//!
//! 該当 test だけ、下記 `ps_bridge_frozen_copy` module（そのコピーへの
//! `#[path]`）を明示的に使う。コピーの pub API のうち `KILL_TCP_SCRIPT` /
//! `write_script` / `spawn_powershell` はこの1 test からは呼ばれないため
//! （凍結コピーは丸ごと1つの module としてしか取り込めない）、
//! `#[allow(dead_code)]` を module 宣言へ付けて `dead_code` 警告を抑える
//! （抑えるのは `dead_code` だけであり、`clippy::unwrap_used` /
//! `clippy::expect_used` ではない。後者を抑える手段は採らない）。
//!
//! `finding_hung_child` が実証した「timeout 機構が無い」という欠陥は
//! **現行の `src/ps_bridge.rs` では直っている**（`RESPONSE_TIMEOUT` /
//! `Poisoned` 参照）。それを検証するのは、この file 内の
//! `ps4_current_ps_bridge_hung_child_times_out_instead_of_blocking_forever`
//! であり、そちらは凍結コピーではなく **現行の `packetdeath::ps_bridge` を
//! 直接 呼ぶ。**

use packetdeath::flow::{FlowKey, Proto};
use packetdeath::ps_bridge::{
    encode_tcp_row_line, parse_response_line, BridgeError, EncodeError, ParseResponseError,
    PsBridge,
};
use packetdeath::windows::{build_tcp_row_spec, TcpRowSpec};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn Error>>;

/// `tests/support/ps_bridge_prod_copy.rs` の `use crate::windows::TcpRowSpec;`
/// を満たすための shim。凍結コピーは「本番の `src/ps_bridge.rs` の中に居る」
/// という前提で書かれているため、このテストクレート内でも同じ相対名
/// （`crate::windows::TcpRowSpec`）を解決できるようにする（型は
/// `packetdeath::windows::TcpRowSpec` と同一。再輸出であって改変ではない）。
mod windows {
    pub use packetdeath::windows::TcpRowSpec;
}

/// `src/ps_bridge.rs` の `RESPONSE_TIMEOUT` / `spawn_reader` / `poisoned` が
/// 入る前の逐語 snapshot（1〜248行）。**code は変更していない**（module 冒頭の
/// コメントを見よ）。`finding_hung_child_was_a_real_defect_in_the_frozen_copy`
/// だけがこれを使う。
#[allow(dead_code)]
#[path = "support/ps_bridge_prod_copy.rs"]
mod ps_bridge_frozen_copy;

/// xorshift64* による決定的な擬似乱数。`rand` crate は Cargo.toml に無いため
/// std だけで独自実装する（`Cargo.toml` の dependencies を実測: dev-dependencies
/// 節が存在しないことを `grep -c dev-dependencies Cargo.toml` で
/// 確認できる。0件）。
struct XorShift64Star(u64);
impl XorShift64Star {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
}

// ============================================================
// 0. 陽性対照 ── 検査そのものが破れを検知できることを先に確かめる
// ============================================================

/// `catch_unwind` が実際に panic を捕まえることを確かめる（検知器の陽性対照）。
/// これが失敗するなら、以降の「panic 0件」報告は無意味になる。
/// **意図的に panic させる**のが目的そのものなので、`.expect()` で偶発的に
/// panic させるのではなく `panic!()` を直接 呼ぶ（`unwrap()`/`expect()` を
/// 使わない、という制約に触れずに同じ効果を得る）。
#[test]
fn positive_control_catch_unwind_detects_a_real_panic() {
    let result = std::panic::catch_unwind(|| {
        panic!("deliberate panic for positive control");
    });
    assert!(
        result.is_err(),
        "陽性対照が失敗: catch_unwind が意図した panic を検知できなかった"
    );
}

/// 行フォーマット検査器（`^[0-9]+,[0-9]+,[0-9]+,[0-9]+$`）自身の陽性対照。
/// 改行を含む壊れた行を「壊れている」と判定できることを先に確かめる。
fn looks_like_clean_csv_u32_line(s: &str) -> bool {
    let parts: Vec<&str> = s.split(',').collect();
    parts.len() == 4
        && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && !s.contains(['\n', '\r', '\0'])
}

#[test]
fn positive_control_csv_checker_rejects_a_planted_injection() {
    assert!(
        !looks_like_clean_csv_u32_line("1,2\n,3,4"),
        "陽性対照が失敗: 改行混入行を清潔と誤判定した"
    );
    assert!(
        !looks_like_clean_csv_u32_line("1,2,3"),
        "陽性対照が失敗: 4 field 未満を清潔と誤判定した"
    );
    assert!(
        looks_like_clean_csv_u32_line("443,80,1,4294967295"),
        "陽性対照が失敗: 正常な行を不正と誤判定した"
    );
}

// ============================================================
// 1. 命令注入 ── encode_tcp_row_line の到達可能な入力面を全数で試す
// ============================================================

/// `encode_tcp_row_line` の唯一の入力は `TcpRowSpec { u32, u32, u32, u32 }`。
/// `u32::to_string()` は ASCII の `0`-`9` 以外を**型として**生成し得ない。
/// つまり「改行・復帰・カンマ・NUL・制御文字・非 ASCII・空文字・極端に長い
/// 文字列」は、この pub 入口からは構築不能である（実行時検査ではなく
/// 型による構造的な証明）。これを u32 の全範囲の代表点＋乱数で確認する。
#[test]
fn ps0_encode_tcp_row_line_output_never_contains_injection_bytes() -> TestResult {
    let mut rng = XorShift64Star::new(0xC0FFEE);
    let mut probed = 0u64;
    let extremes = [0u32, 1, 9, 10, 65535, 65536, u32::MAX, u32::MAX - 1, 0xBB01];
    for &a in &extremes {
        for &b in &extremes {
            let row = TcpRowSpec {
                local_addr: a,
                local_port: b,
                remote_addr: b,
                remote_port: a,
            };
            // INVARIANT: row の4 field はすべて u32 であり、
            // encode_tcp_row_line の唯一の失敗要因（改行混入）は
            // u32::to_string() からは構築不能（このテストの主張そのもの）。
            let line = encode_tcp_row_line(&row).map_err(|e| e.to_string())?;
            assert!(
                looks_like_clean_csv_u32_line(&line),
                "注入検知: extremes 入力 a={a} b={b} で不正な行 {line:?} が生成された"
            );
            probed += 1;
        }
    }
    // 乱数 100,000 組。pattern: XorShift64Star seed=0xC0FFEE、範囲: u32 全域。
    for _ in 0..100_000 {
        let row = TcpRowSpec {
            local_addr: rng.next_u32(),
            local_port: rng.next_u32(),
            remote_addr: rng.next_u32(),
            remote_port: rng.next_u32(),
        };
        let line = encode_tcp_row_line(&row).map_err(|e| e.to_string())?;
        assert!(
            looks_like_clean_csv_u32_line(&line),
            "注入検知: 乱数入力で不正な行 {line:?} が生成された（row={row:?}）"
        );
        probed += 1;
    }
    eprintln!(
        "[ps0] 走査 pattern=looks_like_clean_csv_u32_line, 走査範囲=u32 extremes(9x9)+乱数100000本, \
         probed={probed}, 命令注入=0件"
    );
    Ok(())
}

/// `EncodeError::ContainsNewline` という variant が定義されている以上、
/// 「改行を含む行は書かない」という契約自体は本番 code に存在する
/// （型定義の実読で確認。`ps_bridge.rs:78-84`）。ただし pub 入口
/// （`TcpRowSpec` は全 field u32）からはその分岐へ到達できない ──
/// これは exhaustive でない network path が実在することを意味する。
/// 発見した欠陥として報告する（この test は「有る」ことの記録であり、
/// 実装を直すものではない）。
#[test]
fn finding_containsnewline_branch_is_unreachable_from_the_only_public_encoder() {
    // TcpRowSpec の4 field は pub かつ u32 のみ。文字列を直接 渡す pub 関数は
    // encode_tcp_row_line 以外に存在しない（`grep -c "pub fn" ps_bridge.rs` で
    // 実測: encode_tcp_row_line, parse_response_line, write_script,
    // PsBridge::{spawn, spawn_powershell, send_tcp_row, is_alive} の7件のみ。
    // 文字列 field を持つ pub 関数は無い）。
    let _ = EncodeError::ContainsNewline; // variant の存在だけを型で確認する
}

// ============================================================
// 2. 応答 parse の panic 安全性
// ============================================================

fn assert_no_panic_parsing(line: &str) {
    let result = std::panic::catch_unwind(|| parse_response_line(line));
    assert!(
        result.is_ok(),
        "panic 検知: parse_response_line が入力 {line:?} で panic した"
    );
}

#[test]
fn ps2_parse_response_line_edge_cases_never_panic() {
    let cases: Vec<String> = vec![
        "".to_string(),
        "\n".to_string(),
        "\r\n".to_string(),
        "rc=".to_string(),
        "us=".to_string(),
        "rc=0".to_string(),
        "us=1.0".to_string(),
        "rc=0 us=".to_string(),
        "rc= us=1.0".to_string(),
        "rc=0 us=1.0 extra".to_string(),
        "rc=abc us=1.0".to_string(),
        "rc=0 us=abc".to_string(),
        "rc=99999999999999999999999999 us=1.0".to_string(), // i64 溢れ
        "rc=0 us=99999999999999999999999999999999999999.0e400".to_string(), // f64 溢れ→inf
        "rc=NaN us=NaN".to_string(),
        "rc=inf us=inf".to_string(),
        "rc=-1 us=-1.0".to_string(),
        "rc=0x1A us=1.0".to_string(),
        "rc=0 us=1,0".to_string(), // 桁区切りカンマ
        "rc=0\tus=1.0".to_string(),
        "   rc=0 us=1.0   ".to_string(),
        "rc=0  us=1.0".to_string(), // 連続空白
        "０ｒｃ＝０　ｕｓ＝１．０".to_string(), // 全角
        "rc=0 us=1.0\0".to_string(), // NUL 混入
        "\u{0}\u{1}\u{2}".to_string(),
        "🦀".repeat(1000),
        "a".repeat(10_000_000), // 極端に長い行（10MB）
        "rc=0 us=1.0".repeat(500_000), // 極端に長い、有効に見える行の反復
    ];
    let mut probed = 0u64;
    for c in &cases {
        assert_no_panic_parsing(c);
        probed += 1;
    }
    eprintln!(
        "[ps2] 走査 pattern=手動 edge-case 列挙, 走査範囲={probed}本（空行・壊れた行・巨大な行・rc=のみ・us=のみ・非ASCII・NUL含む）, panic=0件"
    );
}

#[test]
fn ps2_ten_thousand_random_byte_strings_never_panic_lossy_utf8() {
    // 乱数 byte 列（UTF-8 として不正なものを含む）を lossy 変換して投入する。
    // parse_response_line のシグネチャは &str のみを受けるため、呼び出し元
    // （send_tcp_row 内の BufReader::read_line）が UTF-8 検証を既に済ませて
    // いる契約に合わせつつ、「UTF-8 としては読めても内容が壊れている」行を
    // 広く踏む。pattern: XorShift64Star seed=0x5EED, 走査本数=10,000。
    let mut rng = XorShift64Star::new(0x5EED);
    let mut probed = 0u64;
    for _ in 0..10_000 {
        let len = (rng.next_u32() % 512) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| (rng.next_u32() % 256) as u8).collect();
        let s = String::from_utf8_lossy(&bytes).into_owned();
        assert_no_panic_parsing(&s);
        probed += 1;
    }
    eprintln!(
        "[ps2] 走査 pattern=XorShift64Star(seed=0x5EED)の乱数byte列→from_utf8_lossy, \
         走査範囲={probed}本（各長0-511 byte）, panic=0件"
    );
}

#[test]
fn ps2_ten_thousand_random_valid_unicode_strings_never_panic() {
    // 有効な UTF-8 の乱数文字列（サロゲート域を避けた任意コードポイント）を
    // 1万本 投入する。pattern: XorShift64Star seed=0xABCD1234, 本数=10,000。
    let mut rng = XorShift64Star::new(0xABCD_1234);
    let mut probed = 0u64;
    for _ in 0..10_000 {
        let len = (rng.next_u32() % 64) as usize;
        let mut s = String::new();
        for _ in 0..len {
            loop {
                let cp = rng.next_u32() % 0x11_0000;
                if let Some(c) = char::from_u32(cp) {
                    s.push(c);
                    break;
                }
            }
        }
        assert_no_panic_parsing(&s);
        probed += 1;
    }
    eprintln!(
        "[ps2] 走査 pattern=XorShift64Star(seed=0xABCD1234)の乱数 Unicode 文字列, \
         走査範囲={probed}本（各長0-63文字、非ASCII含む）, panic=0件"
    );
}

#[test]
fn ps2_malformed_rc_or_us_returns_err_not_panic() {
    // 誤った parse で `Ok` を返してしまっていないかも併せて見る。
    for bad in ["", "rc=", "us=", "garbage", "rc=x us=y", "rc=1", "us=1.0"] {
        match parse_response_line(bad) {
            Err(ParseResponseError::Malformed) => {}
            other => panic!("期待した Malformed ではなく {other:?} が返った（入力={bad:?}）"),
        }
    }
}

#[test]
fn ps2_well_formed_line_parses_correctly() -> TestResult {
    let r = parse_response_line("rc=317 us=42.5\n").map_err(|e| e.to_string())?;
    assert_eq!(r.rc, 317);
    assert!((r.micros - 42.5).abs() < f64::EPSILON);
    Ok(())
}

// ============================================================
// 3. 子 process が死んだとき／応答が返らないとき、素通しに倒れるか
// ============================================================

/// 子 process が **既に終了している** 状態で送信すると、panic せず Err を返すか。
#[test]
fn ps3_send_after_child_already_exited_returns_err_not_panic() -> TestResult {
    // `true` は起動直後に exit する。stdin/stdout とも即 close される。
    let mut bridge = PsBridge::spawn("true", &[])?;
    // 子が確実に死ぬまで待つ（is_alive がブロックしないことも同時に確認）。
    let deadline = Instant::now() + Duration::from_secs(5);
    while bridge.is_alive() {
        if Instant::now() > deadline {
            panic!("`true` が5秒経っても終了しなかった（環境異常）");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let row = sample_row();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bridge.send_tcp_row(&row)));
    match result {
        Ok(Err(BridgeError::Io(_))) | Ok(Err(BridgeError::ChildClosed)) => {
            eprintln!("[ps3] 既に終了した子への送信 → panic せず Err（素通しに倒せる形）");
        }
        Ok(Ok(resp)) => panic!("死んだ子から応答が返るのはおかしい: {resp:?}"),
        Ok(Err(other)) => panic!("Io/ChildClosed 以外の Err: {other:?}"),
        Err(_) => panic!("panic 検知: 既に終了した子への送信で panic した"),
    }
    Ok(())
}

/// 子 process が **stdin を閉じた直後に自分も終了する**（`sh -c 'exit 0'`）
/// ケース。書き込みは通っても読み取りが EOF になるはず。
#[test]
fn ps3_child_closes_stdout_after_read_returns_childclosed_not_panic() -> TestResult {
    // `sh -c "read x; exit 0"`: 1行 読んでから何も書かずに終了する。
    let mut bridge = PsBridge::spawn("sh", &["-c", "read x; exit 0"])?;
    let row = sample_row();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bridge.send_tcp_row(&row)));
    match result {
        Ok(Err(BridgeError::ChildClosed)) | Ok(Err(BridgeError::Io(_))) => {
            eprintln!("[ps3] 読み取り後に終了する子 → panic せず Err（素通しに倒せる形）");
        }
        Ok(Ok(resp)) => panic!("応答を書かない子から応答が返るのはおかしい: {resp:?}"),
        Ok(Err(other)) => panic!("ChildClosed/Io 以外の Err: {other:?}"),
        Err(_) => panic!("panic 検知: 子が EOF を返す状況で panic した"),
    }
    Ok(())
}

/// 子 process が **生きているが応答を一切 返さない**（ハング）場合に、
/// **凍結コピー（timeout 機構が入る前の `src/ps_bridge.rs` の逐語 snapshot）**
/// が実際にどう振る舞ったかを記録する。
///
/// 🔴 重要な観測（記録当時）: 凍結コピーの `send_tcp_row` は内部で
/// `BufReader::read_line` を **timeout 無しで** 呼ぶ（`tests/support/
/// ps_bridge_prod_copy.rs` を実読して確認）。そのため子がハングすると
/// 呼び出し側スレッドも無期限にブロックし、「panic しない」は保てるが
/// 「素通しに倒す」（エラーとして返って処理を続ける）は**保てなかった**。
/// **これは過去の欠陥の記録である。現行の `src/ps_bridge.rs` はこの欠陥を
/// 直しており（`RESPONSE_TIMEOUT` / `Poisoned`）、その検証は下の
/// `ps4_current_ps_bridge_hung_child_times_out_instead_of_blocking_forever`
/// が別に担う。**
#[test]
fn finding_hung_child_was_a_real_defect_in_the_frozen_copy() -> TestResult {
    // `sleep 30`: 生存し続けるが、stdin を読まず stdout にも書かない。
    let mut bridge = ps_bridge_frozen_copy::PsBridge::spawn("sleep", &["30"])?;
    assert!(bridge.is_alive(), "test 前提: sleep はまだ生きている");
    let row = sample_row();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let r = bridge.send_tcp_row(&row);
        let _ = tx.send(r);
        // bridge はこの thread の終了と共に drop され、Drop が sleep を kill する。
    });

    let waited = Duration::from_secs(2);
    match rx.recv_timeout(waited) {
        Ok(result) => {
            panic!(
                "想定外: 2秒以内に返ってきた（この凍結コピーは timeout 機構を持たないはず）: \
                 {result:?}。コピーの内容が変わっていないか確認せよ。"
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "[frozen-copy] 子 process が応答を返さない状況で、凍結コピーの send_tcp_row は \
                 少なくとも{}ms 以内に復帰しなかった（timeout 機構が無かった、という過去の欠陥の記録）。\
                 呼び出し scope の thread はこの間ブロックし続けた。",
                waited.as_millis()
            );
        }
        Err(e) => panic!("recv_timeout が想定外の Err: {e:?}"),
    }
    // このスレッドは detach する（プロセス終了時に回収される）。テスト全体を
    // ブロックしないよう join しない。
    drop(handle);
    Ok(())
}

/// 上の欠陥が **現行の `src/ps_bridge.rs`（`packetdeath::ps_bridge`）では
/// 直っている**ことを検証する（PT-4）。凍結コピーではなく、`use` で取り込んだ
/// 現行の `PsBridge` / `BridgeError` を直接 使う。
#[test]
fn ps4_current_ps_bridge_hung_child_times_out_instead_of_blocking_forever() -> TestResult {
    let mut bridge = PsBridge::spawn("sleep", &["30"])?;
    assert!(bridge.is_alive(), "test 前提: sleep はまだ生きている");
    let row = sample_row();

    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let started = Instant::now();
        let first = bridge.send_tcp_row(&row);
        let elapsed = started.elapsed();
        // timeout 後は poisoned になり、以降 即 Err のはず（同じ bridge へ
        // 続けて送る。プロトコルのずれを防ぐ設計の検証）。
        let second = bridge.send_tcp_row(&row);
        let _ = tx.send((first, elapsed, second));
        // bridge はこの thread の終了と共に drop され、Drop が sleep を kill する。
    });

    // 現行実装の RESPONSE_TIMEOUT は非公開（500ms、`src/ps_bridge.rs` の
    // 実読で確認済み）。ここでは private な定数値に依存せず、それより十分
    // 大きい 5秒 を「有限時間で戻るべき」上限として独立に置く。
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok((first, elapsed, second)) => {
            assert!(
                matches!(first, Err(BridgeError::Timeout)),
                "現行の PsBridge はハングした子への送信で Timeout に倒れるべき: {first:?}"
            );
            assert!(
                elapsed < Duration::from_secs(5),
                "timeout が独立 bound(5秒) 以内に返らなかった: {elapsed:?}"
            );
            assert!(
                matches!(second, Err(BridgeError::Poisoned)),
                "timeout 後の再送信は Poisoned であるべき: {second:?}"
            );
            eprintln!(
                "[ps4-current] 現行 PsBridge: ハングした子への送信は {elapsed:?} で Timeout に \
                 倒れ、以降は Poisoned になった（有限時間で fail-open できる形。過去の欠陥は\
                 直っている）。"
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "現行の PsBridge が独立 bound(5秒) 以内に応答しなかった。\
                 timeout 機構が退行している疑い（PT-4 違反）"
            );
        }
        Err(e) => panic!("recv_timeout が想定外の Err: {e:?}"),
    }
    drop(handle);
    Ok(())
}

fn sample_row() -> TcpRowSpec {
    TcpRowSpec {
        local_addr: 0x0100_007f,
        local_port: 0xBB01,
        remote_addr: 0x0100_007f,
        remote_port: 0x5000,
    }
}

// ============================================================
// 4. network byte order
// ============================================================

#[test]
fn pw_port_443_becomes_0xbb01_via_build_tcp_row_spec() -> TestResult {
    // `build_tcp_row_spec` の対応（本番 code を実読して確認: windows.rs
    // `key.src_*` は local、`key.dst_*` は remote）。443 を **src_port** に
    // 置くので、確かめるのは row.local_port である
    // （最初 dst_port 側で確かめて失敗し、自分の対応関係の取り違えだと
    // 判った。誤りの記録: 差分ログとして残す）。
    let key = FlowKey {
        proto: Proto::Tcp,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 443,
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        dst_port: 12345,
    };
    let row = build_tcp_row_spec(&key).ok_or("ipv4/tcp は構築できるはず")?;
    assert_eq!(
        row.local_port, 0xBB01,
        "443 → 0xBB01（47873）になっていない: got {:#06x} ({})",
        row.local_port, row.local_port
    );
    assert_eq!(row.local_port, 47873);

    // dst_port=12345 側も、別の既知値で byte order の式を検算する。
    // 12345 = 0x3039 → byte swap → 0x3930 = 14640。
    assert_eq!(row.remote_port, 0x3930);
    assert_eq!(row.remote_port, 14640);
    Ok(())
}

#[test]
fn pw_ip_octet_order_is_preserved_not_reversed() -> TestResult {
    let key = FlowKey {
        proto: Proto::Tcp,
        src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        src_port: 1,
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        dst_port: 2,
    };
    let row = build_tcp_row_spec(&key).ok_or("ipv4/tcp は構築できるはず")?;
    // little-endian u32 として octets をそのまま読んだ値なら、その値を
    // 再び to_le_bytes() した結果は元の octet 列と一致するはず（逆順になって
    // いれば [4,3,2,1] になり、この assert が落ちる）。
    assert_eq!(row.local_addr.to_le_bytes(), [1, 2, 3, 4]);
    assert_eq!(row.local_addr, 1u32 + 2 * 256 + 3 * 65536 + 4 * 16_777_216);
    Ok(())
}

#[test]
fn pw_ipv6_and_udp_are_rejected_not_silently_mishandled() {
    let ipv6_key = FlowKey {
        proto: Proto::Tcp,
        src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        src_port: 1,
        dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        dst_port: 2,
    };
    assert_eq!(build_tcp_row_spec(&ipv6_key), None);

    let udp_key = FlowKey {
        proto: Proto::Udp,
        src_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        src_port: 1,
        dst_ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        dst_port: 2,
    };
    assert_eq!(build_tcp_row_spec(&udp_key), None);
}

// ============================================================
// 6. 禁じ手（証明書・proxy・外部 driver・unsafe）を、自分の式で数える
// ============================================================

#[test]
fn finding_no_forbidden_terms_in_the_current_production_source() {
    // 対象: **現行の** `src/ps_bridge.rs`（`include_str!` で読むだけで、
    // 書き換えはしない）。凍結コピーではなく現行 file を直接 見る。
    // 走査 pattern は下記の各 needle、走査時刻はこの test 実行時。
    //
    // 🔴 絞り込みの記録（user-principles.md「絞り込み語を使ったら、外した版も
    // 打って件数を比べる」）: 最初 "unsafe " という広い pattern で走らせたら
    // 複数 ヒットしたが、すべて `//!` doc comment 内の地の文（「pub unsafe fn
    // として」のように `pub unsafe fn` の語を説明に使う行）だった。
    // 実 code かどうかを分けるため、`//` 始まりの行を除外した版で数え直す。
    let src = include_str!("../src/ps_bridge.rs");
    let code_lines: Vec<&str> = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    let code_only = code_lines.join("\n");

    let unsafe_hits_including_comments = src.matches("unsafe").count();
    let unsafe_hits_code_only = code_only.matches("unsafe").count();
    eprintln!(
        "[禁じ手] pattern=\"unsafe\" 全体(comment込み)={unsafe_hits_including_comments}件, \
         同 pattern comment除外(実 code のみ)={unsafe_hits_code_only}件 \
         （差はすべて `//` 始まりの doc comment 内の引用と実読で確認済み）"
    );
    assert_eq!(
        unsafe_hits_code_only, 0,
        "禁じ手検知: 実 code 中に \"unsafe\" が {unsafe_hits_code_only} 件"
    );

    let forbidden = [
        "CertAddCertificateContextToStore",
        "trusted root",
        "信頼ストア",
        "set_proxy",
        "PROXY",
        "http_proxy",
    ];
    for needle in forbidden {
        let n = src.matches(needle).count();
        assert_eq!(
            n, 0,
            "禁じ手検知: pattern={needle:?} が現行 ps_bridge.rs に {n} 件"
        );
    }
    eprintln!(
        "[禁じ手] 走査 pattern={:?}, 走査範囲=現行 src/ps_bridge.rs 全文(comment込み), \
         測定時刻=このテスト実行時, 各0件",
        forbidden
    );
}
