//! 独立検算。`flows.jsonl` が「1 flow 1行の JSON Lines」であることの検証。
//! `src/flow.rs` の本番 code（`FlowKey` / `FlowLogEntry` / `FlowLogSink`。
//! いずれも `#[cfg(test)]` より前の公開 API）だけを使う。
//! `flow.rs` の test module は開いていない（`grep -n cfg(test) src/flow.rs` は
//! 171 行目。ここで使うのは1〜170 行目の公開 API のみ）。
//!
//! # `unwrap()` / `expect()` を使わない
//! 各 test は `Result<(), Box<dyn std::error::Error>>` を返し、`?` で伝播する。
//! 失敗時は従来の `panic!` メッセージの代わりに `Err` の `Debug` 出力が
//! test harness に出るが、**落ちる条件そのものは変えていない**
//! （PT-8 対応表は報告本文）。

use packetdeath::flow::{FlowKey, FlowLogEntry, FlowLogSink, Proto};
use packetdeath::sni::SniState;
use std::error::Error;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

fn make_key(dst_port: u16) -> Result<FlowKey, Box<dyn Error>> {
    Ok(FlowKey {
        proto: Proto::Tcp,
        src_ip: "10.0.0.1".parse::<IpAddr>()?,
        src_port: 55555,
        dst_ip: "93.184.216.34".parse::<IpAddr>()?,
        dst_port,
    })
}

/// `tests/` 配下だけに書く一時 file（要求範囲内）。
fn scratch_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/tmp-independent-log");
    fs::create_dir_all(&dir)?;
    Ok(dir.join(name))
}

#[test]
fn positive_control_serialization_contains_expected_fields() -> TestResult {
    // 陽性対照：素直な SNI で、期待する field がまず出ることを先に確認する。
    let key = make_key(443)?;
    let state = SniState::Ok("example.com".to_string());
    let entry = FlowLogEntry::new(key, &state)?;
    let line = serde_json::to_string(&entry)?;

    for needle in [
        "\"proto\":\"tcp\"",
        "\"dst_ip\":\"93.184.216.34\"",
        "\"dst_port\":443",
        "\"sni\":\"example.com\"",
        "\"sni_state\":\"ok\"",
        "\"decision\":\"observe\"",
        "\"reason\":null",
    ] {
        assert!(
            line.contains(needle),
            "陽性対照で '{needle}' が出ない。line={line}"
        );
    }
    assert_eq!(line.lines().count(), 1, "1行のはずが複数行: {line:?}");
    Ok(())
}

#[test]
fn sni_with_newline_and_control_chars_stays_one_json_line() -> TestResult {
    // SNI に改行・タブ・NUL・二重引用符・バックスラッシュを混ぜる。
    // TLS の仕様上ホスト名にこれらは出ないはずだが、`SniState::Ok` は
    // 生の `String` を保持するだけなので、上流の parser が壊れていれば
    // ここへ届き得る。log 側がそれでも壊れないかを見る。
    let malicious = "evil\n.example\r\ncom\t\0\"\\{\"injected\":true}";
    let key = make_key(443)?;
    let state = SniState::Ok(malicious.to_string());
    let entry = FlowLogEntry::new(key, &state)?;
    let line = serde_json::to_string(&entry)?;

    assert_eq!(
        line.lines().count(),
        1,
        "制御文字入り SNI で行が割れた: {line:?}"
    );
    assert!(
        !line.contains('\n') && !line.contains('\r'),
        "生の改行/CR が JSON 文字列の中に残っている（エスケープ漏れ）: {line:?}"
    );

    // round trip：json として正しくパースでき、元の文字列が復元できるか。
    let value: serde_json::Value = serde_json::from_str(&line)?;
    let sni = value["sni"].as_str().ok_or("sni is not a string")?;
    assert_eq!(sni, malicious, "round trip で SNI の中身が変わった");
    Ok(())
}

#[test]
fn multiple_flows_via_sink_produce_one_line_each() -> TestResult {
    // FlowLogSink 経由で3 flow 書き、file の行数がちょうど3になることを見る
    // （1 flow 1行の実地検証。stdout への複製は別経路なので見ない）。
    let path = scratch_path("flows_multi.jsonl")?;
    let _ = fs::remove_file(&path);

    let sink = FlowLogSink::open(&path)?;
    let states = [
        SniState::Ok("a.example".to_string()),
        SniState::None,
        SniState::Ok("evil\nb.example".to_string()),
    ];
    for (i, state) in states.iter().enumerate() {
        let key = make_key(1000 + i as u16)?;
        let entry = FlowLogEntry::new(key, state)?;
        sink.write(&entry)?;
    }

    let content = fs::read_to_string(&path)?;
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "3 flow 書いたのに file の行数が {}: {content:?}",
        lines.len()
    );
    for (i, line) in lines.iter().enumerate() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(parsed.is_ok(), "{i} 行目が JSON として壊れている: {line}");
    }

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn sni_none_and_fragmented_serialize_null_sni() -> TestResult {
    let key = make_key(443)?;
    for state in [SniState::None, SniState::Fragmented] {
        let entry = FlowLogEntry::new(key, &state)?;
        let line = serde_json::to_string(&entry)?;
        assert!(
            line.contains("\"sni\":null"),
            "{:?} で sni が null になっていない: {line}",
            state
        );
        assert_eq!(line.lines().count(), 1);
    }
    Ok(())
}
