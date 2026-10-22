//! 独立検算。「当たっても通す」allowlist が blocklist より先に効くこと、
//! 実際に取得した公開 allowlist（`allowlists/microsoft-required.txt` /
//! `allowlists/pihole-common.txt`）が利用者の名指しした経路を救うこと、
//! 広告 domain は allowlist に入らず落ちることを検証する。
//! `Allowlist::load` / `Allowlist::matches` / `judge::run_judges_with_allowlist`
//! （いずれも公開 API）だけを使う。
//!
//! # `unwrap()` / `expect()` を使わない
//! 各 test は `Result<(), Box<dyn std::error::Error>>` を返し、`?` で伝播する。

use packetdeath::allowlist::Allowlist;
use packetdeath::blocklist::Blocklist;
use packetdeath::judge::{run_judges_with_allowlist, Judge, JudgeInput, Reason, SniJudge};
use packetdeath::sni::SniState;
use std::collections::HashSet;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

fn dummy_dst_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
}

fn load_repo_allowlist(name: &str) -> Result<Allowlist, Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
    Ok(Allowlist::load(&path)?)
}

/// SNI 判定を1つだけ持つ最小構成で `run_judges_with_allowlist` を呼ぶ。
fn judge_with_allowlist_and_blocklist(
    allowlist: &Allowlist,
    blocklist: &Blocklist,
    sni: &str,
) -> Option<Reason> {
    let sni_judge = SniJudge { blocklist };
    let judges: Vec<&dyn Judge> = vec![&sni_judge];
    let sni_state = SniState::Ok(sni.to_string());
    let matches = HashSet::new();
    let input = JudgeInput {
        sni_state: &sni_state,
        cname_matched_qnames: &matches,
        dst_ip: dummy_dst_ip(),
        dst_port: 443,
    };
    run_judges_with_allowlist(allowlist, &judges, &input)
}

#[test]
fn allowlist_passes_even_when_the_same_domain_is_blocklisted() -> TestResult {
    // allowlist と blocklist の両方に同じ domain が在っても、
    // allowlist が先に効いて通る（何があっても通す）。
    let allowlist = Allowlist::parse("ads.example\n");
    let blocklist = Blocklist::parse("ads.example\n");
    assert_eq!(
        judge_with_allowlist_and_blocklist(&allowlist, &blocklist, "ads.example"),
        None,
        "allowlist と blocklist の両方に当たる domain が block されてしまった"
    );
    Ok(())
}

#[test]
fn allowlist_passes_subdomain_of_blocklisted_domain() -> TestResult {
    // allowlist・blocklist とも `Blocklist::matches` と同じサフィックス一致
    // （`example.org` は `*.example.org` にも当たる）。
    let allowlist = Allowlist::parse("ads.example\n");
    let blocklist = Blocklist::parse("ads.example\n");
    assert_eq!(
        judge_with_allowlist_and_blocklist(&allowlist, &blocklist, "sub.ads.example"),
        None
    );
    Ok(())
}

#[test]
fn domain_not_in_allowlist_still_blocked() -> TestResult {
    // allowlist に当たらない domain は、従来どおり blocklist で落ちる
    // （allowlist を差し込んでも既存の遮断が壊れていないことの回帰）。
    let allowlist = Allowlist::parse("other.example\n");
    let blocklist = Blocklist::parse("ads.example\n");
    assert_eq!(
        judge_with_allowlist_and_blocklist(&allowlist, &blocklist, "ads.example"),
        Some(Reason::Sni)
    );
    Ok(())
}

/// 利用者が名指しした経路のうち、取得した2つの公開 allowlist に実際に
/// 含まれている5件。`Allowlist::matches` は `Blocklist::matches` と同じ
/// サフィックス一致なので、`chromesyncpasswords.googleapis.com` は
/// `pihole-common.txt` の裸の `googleapis.com`（サフィックス一致）で救われる。
const REAL_ALLOWLIST_HOSTS: &[(&str, &str)] = &[
    ("pihole-common.txt", "1drv.com"),
    ("pihole-common.txt", "clients4.google.com"),
    ("pihole-common.txt", "chromesyncpasswords.googleapis.com"),
    ("microsoft-required.txt", "login.live.com"),
    ("microsoft-required.txt", "login.microsoftonline.com"),
];

#[test]
fn real_allowlists_save_the_hosts_the_user_named() -> TestResult {
    for (file, host) in REAL_ALLOWLIST_HOSTS {
        let allowlist = load_repo_allowlist(&format!("allowlists/{file}"))?;
        assert!(
            allowlist.matches(host),
            "{host} が allowlists/{file} で救われない"
        );
    }
    Ok(())
}

#[test]
fn real_allowlists_save_the_named_hosts_even_against_a_matching_blocklist() -> TestResult {
    // `run_judges_with_allowlist` を通しても、実ファイルの allowlist で
    // 名指しされた経路が救われることを確認する（同じ domain を blocklist にも
    // 入れて、allowlist が先に勝つことを示す）。
    for (file, host) in REAL_ALLOWLIST_HOSTS {
        let allowlist = load_repo_allowlist(&format!("allowlists/{file}"))?;
        let blocklist = Blocklist::parse(host);
        assert_eq!(
            judge_with_allowlist_and_blocklist(&allowlist, &blocklist, host),
            None,
            "{host} が blocklist と衝突したときに救われない"
        );
    }
    Ok(())
}

/// `my.microsoftpersonalcontent.com`（OneDrive）は、取得した
/// Microsoft 公式 API（`ms-endpoints.json`）にも
/// anudeepND/whitelist にも含まれていない（`実測`。
/// `grep -rn my.microsoftpersonalcontent.com allowlists/` が0件）。
/// Microsoft 公式 API は Microsoft 365 の Worldwide エンドポイント一覧であり、
/// OneDrive 個人向け（consumer）の配信 CDN までは載らないためと見られる
/// （`推測`）。
///
/// **この domain は検証した広告 blocklist（EasyList 由来 47,160件）にも
/// そもそも当たらない**ので、allowlist が無くても
/// 現状は素通し（`pass`）のままであり、壊れてはいない。取得した2つの
/// 公開 allowlist だけでは「当たっても通す」効果を持たない、という限界を
/// この test で明示する（隠さない）。
#[test]
fn onedrive_personal_content_host_is_not_in_either_fetched_allowlist() -> TestResult {
    let ms = load_repo_allowlist("allowlists/microsoft-required.txt")?;
    let pihole = load_repo_allowlist("allowlists/pihole-common.txt")?;
    let host = "my.microsoftpersonalcontent.com";
    assert!(
        !ms.matches(host) && !pihole.matches(host),
        "取得した2つの公開 allowlist のどちらかに {host} が含まれていた（想定外）"
    );
    Ok(())
}

/// 陰性：広告 domain は allowlist に入っておらず、blocklist で落ちる。
const AD_HOSTS: &[&str] = &[
    "pagead2.googlesyndication.com",
    "ads.ad.doubleclick.net",
    "ep1.adtrafficquality.google",
    "tpsc-ae1.doubleverify.com",
];

#[test]
fn ad_hosts_are_not_in_real_allowlists_and_still_blocked() -> TestResult {
    let ms = load_repo_allowlist("allowlists/microsoft-required.txt")?;
    let pihole = load_repo_allowlist("allowlists/pihole-common.txt")?;
    for host in AD_HOSTS {
        assert!(
            !ms.matches(host),
            "{host} が microsoft-required.txt に誤って入っている"
        );
        assert!(
            !pihole.matches(host),
            "{host} が pihole-common.txt に誤って入っている"
        );

        // blocklist に当たった状態で、real allowlist が誤って救ってしまわ
        // ないことも確認する（allowlist は「両方に当たった domain」しか
        // 通さない。当たらない domain は blocklist の判定がそのまま効く）。
        let blocklist = Blocklist::parse(host);
        let reason_with_ms = judge_with_allowlist_and_blocklist(&ms, &blocklist, host);
        assert_eq!(
            reason_with_ms,
            Some(Reason::Sni),
            "{host} が誤って通ってしまった"
        );
        let reason_with_pihole = judge_with_allowlist_and_blocklist(&pihole, &blocklist, host);
        assert_eq!(
            reason_with_pihole,
            Some(Reason::Sni),
            "{host} が誤って通ってしまった"
        );
    }
    Ok(())
}

#[test]
fn empty_allowlist_saves_nothing() -> TestResult {
    // `--allowlist` 未指定（空の allowlist）は従来どおりの挙動（何も救わない）。
    let allowlist = Allowlist::empty();
    let blocklist = Blocklist::parse("ads.example\n");
    assert_eq!(
        judge_with_allowlist_and_blocklist(&allowlist, &blocklist, "ads.example"),
        Some(Reason::Sni)
    );
    Ok(())
}
