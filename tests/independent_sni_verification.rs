//! 独立検算。`src/sni.rs` の `#[cfg(test)] mod tests` は開かずに書いた
//! （唯一の例外 ── sed 範囲の誤りで 226〜300 行目の一部を偶然 見てしまった。
//! 詳細は検証報告に書く）。
//!
//! ここの ClientHello builder は `src/sni.rs` の `build_client_hello` を見ずに、
//! TLS の wire format（RFC 8446 4.1.2 / RFC 6066 3）から自分で組んだ。
//! 構成（関数分割・引数の取り方）も独立に設計した。
//!
//! `rustls` は `cargo tree` に存在しないため使えない
//! （Cargo.toml は書き換え禁止）。代わりに `/usr/bin/openssl`（外部 binary。
//! `openssl version` = `OpenSSL 3.5.5`）で本物の ClientHello を生成し、
//! 生成経路を実装と独立にする。

use packetdeath::sni::{extract_sni, SniState};
use std::error::Error;
use std::io::Read;
use std::net::TcpListener;
use std::panic::{self, AssertUnwindSafe};
use std::process::{Command, Stdio};
use std::time::Duration;

type TestResult = Result<(), Box<dyn Error>>;

// ------------------------------------------------------------------
// 1. 本物の TLS ClientHello（openssl 生成）
// ------------------------------------------------------------------

/// `openssl s_client` を接続させ、最初に届いた byte 列（ClientHello を含む
/// 1 TLS record）をそのまま返す。ServerHello は返さないので相手はいずれ
/// 諦めるが、こちらは ClientHello を受け取った時点で `kill` して切る。
fn capture_real_client_hello(sni: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-servername",
            sni,
            "-quiet",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // set_ttl（listener が使える状態かの軽い自己確認）
    listener.set_ttl(64)?;
    let (mut conn, _addr) = listener.accept()?;
    conn.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut data = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(_) => break, // timeout（もう来ない）
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    Ok(data)
}

#[test]
fn real_openssl_clienthello_yields_expected_sni() -> TestResult {
    let sni = "probe-independent-1.example";
    let bytes = capture_real_client_hello(sni)?;
    assert!(
        bytes.len() > 100,
        "openssl から ClientHello が取れていない（{} bytes）。\
         この機の openssl または loopback 経路を疑う",
        bytes.len()
    );
    // 陽性対照：この byte 列に SNI の平文が実在することを、parser を介さず先に確認する。
    assert!(
        String::from_utf8_lossy(&bytes).contains(sni),
        "捕まえた byte 列に平文 SNI '{sni}' が無い。捕獲そのものが壊れている"
    );

    let state = extract_sni(&bytes);
    assert_eq!(state, SniState::Ok(sni.to_string()));
    Ok(())
}

#[test]
fn real_openssl_clienthello_without_sni_flag_has_no_sni() -> TestResult {
    // openssl は `-noservername` で SNI 拡張自体を送らない。
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-noservername",
            "-quiet",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let (mut conn, _) = listener.accept()?;
    conn.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut data = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => data.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(data.len() > 50, "ClientHello が取れていない（{} bytes）", data.len());
    let state = extract_sni(&data);
    assert_eq!(
        state,
        SniState::None,
        "-noservername の本物 ClientHello なのに SNI が出た。誤検出"
    );
    Ok(())
}

// ------------------------------------------------------------------
// 2. 自作 ClientHello builder（構造 fuzz 用。実装の build_client_hello は
//    見ずに、TLS wire format の仕様から独立に組んだ）
// ------------------------------------------------------------------

fn u16_be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}
fn u24_be(v: u32) -> [u8; 3] {
    let b = v.to_be_bytes();
    [b[1], b[2], b[3]]
}

/// server_name extension の中身（ServerNameList）を組む。
/// `entries` は (name_type, name_bytes) の並び。空なら「SNI が0個」になる。
fn encode_server_name_list(entries: &[(u8, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (name_type, name) in entries {
        list.push(*name_type);
        list.extend_from_slice(&u16_be(name.len() as u16));
        list.extend_from_slice(name);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&u16_be(list.len() as u16));
    out.extend_from_slice(&list);
    out
}

/// 1つの extension（type + length + data）を組む。
fn encode_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u16_be(ext_type));
    out.extend_from_slice(&u16_be(data.len() as u16));
    out.extend_from_slice(data);
    out
}

struct HelloSpec<'a> {
    /// None なら extensions block 自体を持たない ClientHello（TLS 1.2 以前互換）。
    extensions: Option<Vec<u8>>,
    session_id_len: usize,
    cipher_suites: &'a [u8],
    compression_methods: &'a [u8],
}

impl<'a> Default for HelloSpec<'a> {
    fn default() -> Self {
        Self {
            extensions: Some(Vec::new()),
            session_id_len: 0,
            cipher_suites: &[0x00, 0x2f],
            compression_methods: &[0x00],
        }
    }
}

/// ClientHello を含む1つの TLS record（RECORD > HANDSHAKE > BODY）を組む。
fn encode_record(spec: &HelloSpec) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version
    body.extend_from_slice(&[0x42u8; 32]); // random（値は何でもよい）
    body.push(spec.session_id_len as u8);
    body.extend(std::iter::repeat_n(0u8, spec.session_id_len));
    body.extend_from_slice(&u16_be(spec.cipher_suites.len() as u16));
    body.extend_from_slice(spec.cipher_suites);
    body.push(spec.compression_methods.len() as u8);
    body.extend_from_slice(spec.compression_methods);
    if let Some(ext) = &spec.extensions {
        body.extend_from_slice(&u16_be(ext.len() as u16));
        body.extend_from_slice(ext);
    }

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    handshake.extend_from_slice(&u24_be(body.len() as u32));
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16); // Handshake content type
    record.extend_from_slice(&[0x03, 0x01]); // record version
    record.extend_from_slice(&u16_be(handshake.len() as u16));
    record.extend_from_slice(&handshake);
    record
}

fn hello_with_extensions(extensions: Vec<u8>) -> Vec<u8> {
    encode_record(&HelloSpec {
        extensions: Some(extensions),
        ..HelloSpec::default()
    })
}

// ------------------------------------------------------------------
// 構造 fuzz：SNI 0個 / 複数 / extension 0個 / extensions block 無し
// ------------------------------------------------------------------

#[test]
fn zero_sni_entries_in_server_name_list_yields_none() {
    // extension は在るが ServerNameList の中身が空（SNI が0個）。
    let sni_ext = encode_extension(0x0000, &encode_server_name_list(&[]));
    let packet = hello_with_extensions(sni_ext);
    assert_eq!(extract_sni(&packet), SniState::None);
}

#[test]
fn multiple_sni_entries_returns_first_host_name_without_panic() {
    // ServerNameList に host_name を2つ入れる（本来は禁止だが、外から来た
    // byte を信じない前提の検証なので、あえて壊れた形にする）。
    let list = encode_server_name_list(&[(0x00, b"first.example"), (0x00, b"second.example")]);
    let sni_ext = encode_extension(0x0000, &list);
    let packet = hello_with_extensions(sni_ext);
    let result = panic::catch_unwind(|| extract_sni(&packet));
    // 最初の1件を返す実装（先頭一致）であることを、自分の期待として立てて確認する。
    match result {
        Ok(state) => assert_eq!(state, SniState::Ok("first.example".to_string())),
        Err(_) => panic!("SNI 複数で panic した"),
    }
}

#[test]
fn zero_extensions_yields_none() {
    // extensions block はあるが中身が空（extension が0個）。
    let packet = hello_with_extensions(Vec::new());
    assert_eq!(extract_sni(&packet), SniState::None);
}

#[test]
fn no_extensions_block_at_all_yields_none() {
    // TLS 1.2 以前互換：ClientHello が compression_methods で終わり、
    // extensions block 自体を持たない。
    let packet = encode_record(&HelloSpec {
        extensions: None,
        ..HelloSpec::default()
    });
    assert_eq!(extract_sni(&packet), SniState::None);
}

#[test]
fn single_sni_round_trips_through_own_builder() {
    // 陽性対照：自作 builder が正しい ClientHello を作れていることを、
    // 素直な1件の SNI で先に確認する（0件系の判定の土台）。
    let list = encode_server_name_list(&[(0x00, b"builder-check.example")]);
    let sni_ext = encode_extension(0x0000, &list);
    let packet = hello_with_extensions(sni_ext);
    assert_eq!(
        extract_sni(&packet),
        SniState::Ok("builder-check.example".to_string())
    );
}

// ------------------------------------------------------------------
// 3. panic しないことの検証
// ------------------------------------------------------------------

/// xorshift64* による決定的な擬似乱数（`rand` crate を追加できないため std だけで実装）。
struct Xorshift64(u64);
impl Xorshift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let word = self.next_u64().to_le_bytes();
            let n = (buf.len() - i).min(8);
            buf[i..i + n].copy_from_slice(&word[..n]);
            i += n;
        }
    }
}

fn try_extract(bytes: &[u8]) -> Result<SniState, String> {
    match panic::catch_unwind(AssertUnwindSafe(|| extract_sni(bytes))) {
        Ok(state) => Ok(state),
        Err(payload) => {
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "panic payload は文字列でない".to_string()
            };
            Err(msg)
        }
    }
}

#[test]
fn ten_thousand_random_byte_strings_never_panic() {
    let mut rng = Xorshift64(0x9E3779B97F4A7C15);
    let mut panics: Vec<(usize, usize, String)> = Vec::new();
    const N: usize = 12_000;
    for i in 0..N {
        // 長さは 0〜4096 を満遍なく踏む（0・1byte・巨大 も含める）。
        let len = match i % 20 {
            0 => 0,
            1 => 1,
            2 => 2,
            18 => 65536,     // 巨大
            19 => 131072,    // さらに巨大
            _ => (rng.next_u64() % 4096) as usize,
        };
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        if let Err(msg) = try_extract(&buf) {
            panics.push((i, len, msg));
        }
    }
    assert!(
        panics.is_empty(),
        "乱数 byte 列で panic が {} 件（先頭5件: {:?}）",
        panics.len(),
        &panics[..panics.len().min(5)]
    );
    eprintln!("乱数 byte 列 {N} 本、panic {} 件", panics.len());
}

#[test]
fn corrupted_length_fields_never_panic() {
    // 良品 ClientHello を土台に、5箇所の長さ欄（record / handshake /
    // extensions / server_name_list / name）それぞれを壊す。
    let list = encode_server_name_list(&[(0x00, b"corrupt-target.example")]);
    let sni_ext = encode_extension(0x0000, &list);
    let good = hello_with_extensions(sni_ext);

    // record length は byte[3..5]、handshake length は byte[5..8] の u24、
    // 以降は good の構造から機械的に位置を出す（byte 列は自分の builder が作った物なので
    // 位置は既知）。
    let record_len_at = 3usize;
    let handshake_len_at = 5 + 1; // handshake type の直後
    let extensions_len_at = good.len() - sni_ext_total_len(&good); // 後述 helper
    let _ = extensions_len_at; // 使わない経路もあるので警告避け

    let corrupt_values_u16: [u16; 6] = [0, 1, 0xFFFF, 0x7FFF, 3, 9999];
    let mut panics = 0usize;
    let mut tried = 0usize;

    // record length（u16, big-endian, offset 3）を総当たりで壊す。
    for &v in &corrupt_values_u16 {
        let mut p = good.clone();
        p[record_len_at..record_len_at + 2].copy_from_slice(&v.to_be_bytes());
        tried += 1;
        if try_extract(&p).is_err() {
            panics += 1;
        }
    }

    // handshake length（u24, offset 6..9）を壊す。
    for &v in &[0u32, 1, 0xFFFFFF, 3, 9999] {
        let mut p = good.clone();
        let b = v.to_be_bytes();
        p[handshake_len_at..handshake_len_at + 3].copy_from_slice(&[b[1], b[2], b[3]]);
        tried += 1;
        if try_extract(&p).is_err() {
            panics += 1;
        }
    }

    // 深く入れ子にした長さ欄：extensions_len と server_name_list_len と
    // name_len を同時に矛盾させる（extensions_len だけ極端に大きく、
    // 内側の list/name len はそのまま）。
    for &v in &corrupt_values_u16 {
        // extensions_len は body 末尾から2byte 前。良品の構造を辿って探す。
        if let Some(pos) = find_extensions_len_offset(&good) {
            let mut p = good.clone();
            p[pos..pos + 2].copy_from_slice(&v.to_be_bytes());
            tried += 1;
            if try_extract(&p).is_err() {
                panics += 1;
            }
        }
    }

    // 全 byte を 0 に潰した同じ長さの列（長さ欄がすべて0という「入れ子の底」）。
    {
        let p = vec![0u8; good.len()];
        tried += 1;
        if try_extract(&p).is_err() {
            panics += 1;
        }
    }

    assert_eq!(panics, 0, "長さ欄破壊 {tried} 件中 {panics} 件で panic");
    eprintln!("長さ欄破壊 ClientHello {tried} 件、panic {panics} 件");
}

/// `good`（`hello_with_extensions` が作った byte 列）の中で extensions_len
/// （2 byte, extensions block 直前）が始まる offset を、構造を辿って求める。
fn find_extensions_len_offset(good: &[u8]) -> Option<usize> {
    // record header 5 byte + handshake header 4 byte = 9 byte 目から body。
    let body_start = 5 + 4;
    let client_version_random = 2 + 32;
    let session_id_len = *good.get(body_start + client_version_random)? as usize;
    let mut cursor = body_start + client_version_random + 1 + session_id_len;
    let cipher_len =
        u16::from_be_bytes([*good.get(cursor)?, *good.get(cursor + 1)?]) as usize;
    cursor += 2 + cipher_len;
    let compression_len = *good.get(cursor)? as usize;
    cursor += 1 + compression_len;
    Some(cursor)
}

/// `good` の extensions block（server_name 拡張1個ぶん）の総 byte 数。
/// extensions_len offset の逆算に使う。
fn sni_ext_total_len(good: &[u8]) -> usize {
    if let Some(pos) = find_extensions_len_offset(good) {
        good.len() - pos
    } else {
        0
    }
}

#[test]
fn truncated_at_every_prefix_length_never_panics() {
    let list = encode_server_name_list(&[(0x00, b"truncate-target.example")]);
    let sni_ext = encode_extension(0x0000, &list);
    let good = hello_with_extensions(sni_ext);

    let mut panics = Vec::new();
    for cut in 0..=good.len() {
        let slice = &good[..cut];
        if let Err(msg) = try_extract(slice) {
            panics.push((cut, msg));
        }
    }
    assert!(
        panics.is_empty(),
        "切り詰め {} 通り中 {} 件で panic（先頭3件: {:?}）",
        good.len() + 1,
        panics.len(),
        &panics[..panics.len().min(3)]
    );
    eprintln!(
        "切り詰め ClientHello {} 通り（0byte〜満尺）、panic {} 件",
        good.len() + 1,
        panics.len()
    );
}

#[test]
fn edge_case_inputs_never_panic() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("空", vec![]),
        ("1byte(0x16)", vec![0x16]),
        ("1byte(0x00)", vec![0x00]),
        ("NUL 埋め64byte", vec![0u8; 64]),
        ("0xFF 埋め64byte", vec![0xFFu8; 64]),
        ("非ASCII SNI", {
            let list = encode_server_name_list(&[(0x00, &[0xE3, 0x81, 0x82, 0xFF, 0x00, 0xC3])]);
            let ext = encode_extension(0x0000, &list);
            hello_with_extensions(ext)
        }),
        ("巨大(1MiB, 先頭は正規record header)", {
            let mut v = vec![0u8; 1024 * 1024];
            v[0] = 0x16;
            v[1] = 0x03;
            v[2] = 0x03;
            v[3] = 0xFF;
            v[4] = 0xFF;
            v
        }),
    ];

    let mut panics = Vec::new();
    for (name, bytes) in &cases {
        if let Err(msg) = try_extract(bytes) {
            panics.push((*name, msg));
        }
    }
    assert!(panics.is_empty(), "edge case で panic: {:?}", panics);
    eprintln!("edge case {} 件、panic {} 件", cases.len(), panics.len());
}
