//! 独立検算。`blocklists/telemetry-windows.txt` が Windows / Office / MSN の
//! 診断データ送信 host を落とし、Defender / Windows Update / 配信最適化 /
//! Store の host を落とさないことの検証。`src/blocklist.rs` の
//! `Blocklist::load` / `Blocklist::matches`（いずれも `#[cfg(test)]` より前の
//! 公開 API）だけを使う。
//!
//! この test は、6行 blocklist の判定結果を報告からそのまま転記せず、
//! `Blocklist::matches` を直接 呼んで確かめる（出所は `blocklists/README.md`）。
//!
//! # `unwrap()` / `expect()` を使わない
//! 各 test は `Result<(), Box<dyn std::error::Error>>` を返し、`?` で伝播する。

use packetdeath::blocklist::Blocklist;
use std::error::Error;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

fn load_telemetry_blocklist() -> Result<Blocklist, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("blocklists/telemetry-windows.txt");
    Ok(Blocklist::load(&path)?)
}

/// 実機（`flows.jsonl` 3776行）で観測した
/// 診断データ送信の host。`blocklists/README.md`「何を止めるか」と対応する。
const DIAGNOSTIC_HOSTS: &[&str] = &[
    "settings-win.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "mobile.events.data.microsoft.com",
    "self.events.data.microsoft.com",
    "ecs.office.com",
    "browser.events.data.msn.com",
    "tsfe.trafficshaping.dsp.mp.microsoft.com",
];

/// 実機の log に出たが、止めると Defender / Windows Update / 配信最適化 /
/// Store が壊れる host の7件（`www.yahoo.co.jp` は無関係な
/// domain の陰性対照）。`blocklists/README.md`「絶対に入れないもの」と対応する。
const MUST_NOT_BLOCK_HOSTS: &[&str] = &[
    // 🔴 入れると実機で2件 落ちる host。
    //    MSN のウィジェットや Edge の新しいタブの中身を配る経路であり、
    //    止めると表示が壊れる。診断データ送信ではない。
    //    EasyList には入っていない（rg -c '^assets\.msn\.com$' el-blocklist.txt → rc=1）。
    "assets.msn.com",
    "wdcp.microsoft.com",
    "fe2cr.update.microsoft.com",
    "fe3cr.delivery.mp.microsoft.com",
    "storeedge.microsoft.com",
    "array611.prod.do.dsp.mp.microsoft.com",
    "kv601.prod.do.dsp.mp.microsoft.com",
    "www.yahoo.co.jp",
];

#[test]
fn diagnostic_hosts_are_blocked() -> TestResult {
    // 陽性：実機に出た診断 host は全部 当たる。
    let bl = load_telemetry_blocklist()?;
    for host in DIAGNOSTIC_HOSTS {
        assert!(bl.matches(host), "診断 host が当たらない: {host}");
    }
    Ok(())
}

#[test]
fn defender_update_delivery_store_hosts_are_not_blocked() -> TestResult {
    // 陰性：Defender・Windows Update・配信最適化・Store・無関係 domain は
    // 1つも当たらない。将来 誰かが1行 足して巻き込んだら、この test が落ちる。
    let bl = load_telemetry_blocklist()?;
    for host in MUST_NOT_BLOCK_HOSTS {
        assert!(
            !bl.matches(host),
            "落としてはいけない host が当たった: {host}"
        );
    }
    Ok(())
}

#[test]
fn onedrive_personal_content_host_is_not_blocked() -> TestResult {
    // OneDrive 個人コンテンツ配信の host。用途は判明している（`検索`。
    // Azure Front Door 経由の OneDrive 個人ファイルダウンロード API）が、
    // 「診断データ送信」ではなく実データ配信なので telemetry blocklist には
    // 入れない（`blocklists/README.md`「判断を保留した host」）。将来 誤って
    // 足されたら、この test が検知する。
    let bl = load_telemetry_blocklist()?;
    assert!(
        !bl.matches("my.microsoftpersonalcontent.com"),
        "OneDrive の個人コンテンツ host が blocklist に入ってしまっている"
    );
    Ok(())
}
