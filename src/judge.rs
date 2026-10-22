//! 同期判定の口。`docs/design.md`「判定を差し込む口」節が正本。
//!
//! 判定は「packet を受け取った瞬間に答える同期判定」と「別 process が後から
//! 出す結果を drop 集合へ流し込む非同期判定」に分かれる。この module が持つ
//! のは同期判定の口（`Judge` trait）だけである。段階4「IPS 化」の非同期判定
//! （`eve.json` の alert を溜める `IdsDropSet`）は `ids.rs` が持つ。`tail`
//! する別 thread が挿入し、`IdsJudge` は参照するだけで I/O をしない。
//! 段階6の `--av`（`av.rs`）は `eve.json` の reader とは独立に、起動時読み込み
//! の同期判定器（`AvJudge`）として実装している
//! （`docs/design.md`「段階5 以降と受入 ID の予約」節の受入 ID PK-60〜63が
//! `--av` 単体で完結し、`--eve` / `--ips-sids` / `--ips-ttl` を要らないため）。
//!
//! 判定器は段階の番号順に並べ、最初に `Some` を返した判定器の `Reason` を
//! log の `reason` に書く。全部 `None` なら `pass`。
//! **判定器の中で I/O をしない。**file の読み込みは起動時（`Blocklist::load`）
//! と、DNS 応答を読む別経路（`crate::dns`）、`eve.json` を tail する別 thread
//! （`crate::ids::watch_eve_file`）だけで行う。

use crate::allowlist::Allowlist;
use crate::av::AvList;
use crate::blocklist::Blocklist;
use crate::ids::IdsDropSet;
use crate::iplist::IpList;
use crate::sni::SniState;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

/// **add-only な列挙。**既存の値を改名しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// SNI が blocklist に当たった（段階2）。
    Sni,
    /// DNS 応答の CNAME チェーンが blocklist に当たった（段階3）。
    Cname,
    /// 宛先 IP が `--iplist` に当たった（段階5）。`sni_state` と proto を
    /// 問わない。SNI を持たない接続に届く唯一の材料である
    /// （`docs/design.md`「段階5 以降と受入 ID の予約」）。
    Iplist,
    /// 宛先の `(dst_ip, dst_port)` の組が `--av` の `malicious` 集合に
    /// 当たった（段階6。`docs/design.md`「段階5 以降と受入 ID の予約」）。
    Av,
    /// `--eve` の alert が `--ips-sids` に当たり、以後の同じ宛先
    /// `(dst_ip, dst_port)` を落とした（段階4「IPS 化」）。add-only の
    /// 末尾へ足す（既存4値の並びは変えない）。値は `docs/design.md`
    /// 「名前と置き場」150行目の reason 一覧と、受入 ID PK-30〜32 の
    /// `grep -c '"reason":"ids"'`（205〜206行目）に一致させる。
    Ids,
    /// Stage 10: a certificate in the chain of this host is on a `--distrust`
    /// list. The chain comes from stage 8's upstream handshake or from the
    /// prober (`docs/design.md` "段階10 能動防御"). Added at the end; the log
    /// value is `chain`.
    Chain,
}

impl Reason {
    /// `flows.jsonl` の `reason` field に書く値。
    /// `docs/design.md`「名前と置き場」および段階5・段階6の一覧と一致する。
    pub fn as_log_str(self) -> &'static str {
        match self {
            Self::Sni => "sni",
            Self::Cname => "cname",
            Self::Iplist => "iplist",
            Self::Av => "av",
            Self::Ids => "ids",
            Self::Chain => "chain",
        }
    }
}

/// 判定材料を1つにまとめた入力。`FlowKey` は呼び出し側が既に持っているので
/// 全体は含めないが、`dst_ip` は `IpJudge`（段階5）が要るのでここに持つ。
pub struct JudgeInput<'a> {
    pub sni_state: &'a SniState,
    /// 段階3：CNAME チェーンの途中が blocklist に当たった `qname` の集合
    /// （小文字化済み）。`--dns` 無しでは常に空。
    pub cname_matched_qnames: &'a HashSet<String>,
    /// 段階5：判定対象 flow の宛先 IP。
    pub dst_ip: IpAddr,
    /// 段階6：`AvJudge` が要る宛先 port。`av` は `dst_ip` 単独では落とさず
    /// `dst_ip` と `dst_port` の組で判定する（CDN の共有 IP 対策）。
    pub dst_port: u16,
}

/// 同期判定の口。実装は `FlowKey` と起動時に読んだ local file だけで、
/// 1 flow あたり定数時間で答える。
pub trait Judge {
    fn judge(&self, input: &JudgeInput) -> Option<Reason>;
}

/// 段階2：SNI が blocklist に当たるかを見る判定器。
pub struct SniJudge<'a> {
    pub blocklist: &'a Blocklist,
}

impl Judge for SniJudge<'_> {
    fn judge(&self, input: &JudgeInput) -> Option<Reason> {
        let sni = input.sni_state.sni()?;
        self.blocklist.matches(sni).then_some(Reason::Sni)
    }
}

/// 段階3：SNI が、CNAME チェーンで blocklist に当たった `qname` と一致するかを
/// 見る判定器。SNI と DNS の `qname` は同じホスト名であるという対応に基づく。
pub struct CnameJudge;

impl Judge for CnameJudge {
    fn judge(&self, input: &JudgeInput) -> Option<Reason> {
        let sni = input.sni_state.sni()?;
        input
            .cname_matched_qnames
            .contains(&sni.to_ascii_lowercase())
            .then_some(Reason::Cname)
    }
}

/// 段階5：宛先 IP が `--iplist` に当たるかを見る判定器。`sni_state` を見ない
/// ので、SNI を持たない接続（`SniState::None`）にも届く。
pub struct IpJudge<'a> {
    pub iplist: &'a IpList,
}

impl Judge for IpJudge<'_> {
    fn judge(&self, input: &JudgeInput) -> Option<Reason> {
        self.iplist
            .contains(&input.dst_ip)
            .then_some(Reason::Iplist)
    }
}

/// 段階6：宛先の `(dst_ip, dst_port)` の組が `--av` の `malicious` 集合に
/// 当たるかを見る判定器。`av.rs` の reader（起動時に一括で読む local file）
/// だけを見るので、`Judge` の「1 flow あたり定数時間」契約を満たす。
pub struct AvJudge<'a> {
    pub av: &'a AvList,
}

impl Judge for AvJudge<'_> {
    fn judge(&self, input: &JudgeInput) -> Option<Reason> {
        self.av
            .contains(&input.dst_ip, input.dst_port)
            .then_some(Reason::Av)
    }
}

/// 段階4：`--eve` の alert が `--ips-sids` に当たり、drop 集合
/// （`ids::IdsDropSet`。別 thread が `eve.json` を tail して更新する共有
/// state）に入った `(dst_ip, dst_port)` かどうかを見る判定器。`contains` の
/// 参照だけで I/O をしないので、`Judge` の「1 flow あたり定数時間」契約を
/// 満たす。
pub struct IdsJudge<'a> {
    pub drop_set: &'a IdsDropSet,
}

impl Judge for IdsJudge<'_> {
    fn judge(&self, input: &JudgeInput) -> Option<Reason> {
        self.drop_set
            .contains(&input.dst_ip, input.dst_port, Instant::now())
            .then_some(Reason::Ids)
    }
}

/// 判定器を段階順に並べて実行し、最初に `Some` を返した `Reason` を返す。
/// 全部 `None` なら `pass`（`None` を返す）。
///
/// 個々の `Judge::judge` の中では I/O をしない契約だが、この関数自体は
/// `Judge` 実装ではなく呼び出し側の orchestrator なので、当たったときだけ
/// `[debug]` を出す（判定の途中経過は結果が変わった時だけ出す。
/// 当たらない大多数の flow では出さないので、広告を見るだけで log が
/// 爆発することはない）。
pub fn run_judges(judges: &[&dyn Judge], input: &JudgeInput) -> Option<Reason> {
    let reason = judges.iter().find_map(|judge| judge.judge(input));
    if let Some(reason) = reason {
        crate::flow::service_log(&format!(
            "packetdeath: [debug] {}",
            crate::i18n::judge_matched(
                crate::i18n::locale(),
                reason.as_log_str(),
                input.dst_ip,
                input.dst_port
            )
        ));
    }
    reason
}

/// **allowlist が判定の列の先頭で効く** orchestrator
/// （`docs/design.md`「判定を差し込む口」）。SNI が `allowlist` に当たれば、
/// `judges` を1つも評価せず即座に `pass`（`None`）を返す ──
/// blocklist・CNAME・宛先 IP・IDS・av のどれに当たっていても、allowlist が
/// 先に勝つ。`flows.jsonl` の `decision` は `pass`、`reason` は `null` の
/// ままにする（`docs/design.md`「名前と置き場」の `Reason` を増やさない）。
/// 当たったことは `[debug]` の log に出す。
///
/// SNI を持たない flow（`SniState::None` / `Fragmented`）は allowlist の
/// 対象にできない（domain 名が無い）ので、そのまま `run_judges` へ委譲する。
pub fn run_judges_with_allowlist(
    allowlist: &Allowlist,
    judges: &[&dyn Judge],
    input: &JudgeInput,
) -> Option<Reason> {
    if let Some(sni) = input.sni_state.sni() {
        if allowlist.matches(sni) {
            crate::flow::service_log(&format!(
                "packetdeath: [debug] {}",
                crate::i18n::allowlist_passed(crate::i18n::locale(), sni)
            ));
            return None;
        }
    }
    run_judges(judges, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn empty_matches() -> HashSet<String> {
        HashSet::new()
    }

    /// 既存の SNI / CNAME 判定器の test は宛先 IP を見ないので、iplist に
    /// 当たらないダミー値で埋める。
    fn dummy_dst_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }

    /// 既存の SNI / CNAME / IP 判定器の test は宛先 port を見ないので、
    /// av に当たらないダミー値で埋める。
    fn dummy_dst_port() -> u16 {
        443
    }

    #[test]
    fn sni_judge_returns_none_for_empty_blocklist() {
        // テスト項目1。
        let blocklist = Blocklist::empty();
        let judge = SniJudge {
            blocklist: &blocklist,
        };
        let sni_state = SniState::Ok("example.org".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), None);
    }

    #[test]
    fn sni_judge_matches_blocklisted_sni() {
        // テスト項目3。
        let blocklist = Blocklist::parse("example.org\n");
        let judge = SniJudge {
            blocklist: &blocklist,
        };
        let sni_state = SniState::Ok("example.org".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), Some(Reason::Sni));
    }

    #[test]
    fn sni_judge_does_not_match_fragmented_state() {
        // テスト項目6。fragmented は判定材料にしない（fail-open）。
        let blocklist = Blocklist::parse("example.org\n");
        let judge = SniJudge {
            blocklist: &blocklist,
        };
        let sni_state = SniState::Fragmented;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), None);
    }

    #[test]
    fn cname_judge_matches_when_sni_is_in_matched_qnames() {
        // テスト項目9。
        let judge = CnameJudge;
        let sni_state = SniState::Ok("first-party.example".to_string());
        let mut matches = HashSet::new();
        matches.insert("first-party.example".to_string());
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), Some(Reason::Cname));
    }

    #[test]
    fn cname_judge_returns_none_when_not_matched() {
        let judge = CnameJudge;
        let sni_state = SniState::Ok("first-party.example".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), None);
    }

    #[test]
    fn run_judges_returns_first_matching_reason_in_order() {
        let blocklist = Blocklist::parse("example.org\n");
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let cname_judge = CnameJudge;
        let sni_state = SniState::Ok("example.org".to_string());
        let mut matches = HashSet::new();
        matches.insert("example.org".to_string()); // 両方 当たる状況でも SNI が先
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge, &cname_judge];
        assert_eq!(run_judges(&judges, &input), Some(Reason::Sni));
    }

    #[test]
    fn run_judges_returns_none_when_all_judges_pass() {
        let blocklist = Blocklist::empty();
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let cname_judge = CnameJudge;
        let sni_state = SniState::Ok("example.com".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge, &cname_judge];
        assert_eq!(run_judges(&judges, &input), None);
    }

    #[test]
    fn ip_judge_returns_none_for_empty_iplist() {
        // PK-50 相当。--iplist 無しでは IP で落ちない。
        let iplist = IpList::empty();
        let judge = IpJudge { iplist: &iplist };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), None);
    }

    #[test]
    fn ip_judge_matches_listed_destination() {
        // PK-51 相当。
        let iplist = IpList::parse("93.184.216.34\n");
        let judge = IpJudge { iplist: &iplist };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), Some(Reason::Iplist));
    }

    #[test]
    fn ip_judge_matches_even_without_sni() {
        // PK-52 相当。SNI を持たない flow（`SniState::None`）も IP で落ちる。
        let iplist = IpList::parse("93.184.216.34\n");
        let judge = IpJudge { iplist: &iplist };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), Some(Reason::Iplist));
    }

    #[test]
    fn run_judges_tries_ip_last_after_sni_and_cname() {
        // PK-53 相当の回帰：SNI が先に当たれば IP 判定器まで進まない。
        let blocklist = Blocklist::parse("example.org\n");
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let cname_judge = CnameJudge;
        let iplist = IpList::parse("93.184.216.34\n");
        let ip_judge = IpJudge { iplist: &iplist };
        let sni_state = SniState::Ok("example.org".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge, &cname_judge, &ip_judge];
        assert_eq!(run_judges(&judges, &input), Some(Reason::Sni));
    }

    #[test]
    fn run_judges_falls_through_to_ip_when_sni_and_cname_pass() {
        let blocklist = Blocklist::empty();
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let cname_judge = CnameJudge;
        let iplist = IpList::parse("93.184.216.34\n");
        let ip_judge = IpJudge { iplist: &iplist };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge, &cname_judge, &ip_judge];
        assert_eq!(run_judges(&judges, &input), Some(Reason::Iplist));
    }

    #[test]
    fn av_judge_returns_none_for_empty_av_list() {
        // PK-60 相当。--av 無しでは malicious が在っても落ちない。
        let av = AvList::empty();
        let judge = AvJudge { av: &av };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), None);
    }

    #[test]
    fn av_judge_matches_malicious_destination() {
        // PK-61 相当。
        let av = AvList::parse(
            r#"{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"93.184.216.34","dst_port":443,"sha256":null,"verdict":"malicious","engine":"manual"}"#,
        );
        let judge = AvJudge { av: &av };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), Some(Reason::Av));
    }

    #[test]
    fn av_judge_requires_port_match_not_ip_alone() {
        // 正本「段階5 以降と受入 ID の予約」節：av は ids と違い dst_ip 単独
        // では落とさず dst_ip と dst_port の組で判定する。
        let av = AvList::parse(
            r#"{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"93.184.216.34","dst_port":443,"sha256":null,"verdict":"malicious","engine":"manual"}"#,
        );
        let judge = AvJudge { av: &av };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: 8443,
        };
        assert_eq!(judge.judge(&input), None);
    }

    #[test]
    fn run_judges_tries_av_last_after_sni_cname_and_ip() {
        // PK-67 相当の回帰：SNI が先に当たれば av 判定器まで進まない。
        let blocklist = Blocklist::parse("example.org\n");
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let cname_judge = CnameJudge;
        let iplist = IpList::empty();
        let ip_judge = IpJudge { iplist: &iplist };
        let av = AvList::parse(
            r#"{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"93.184.216.34","dst_port":443,"sha256":null,"verdict":"malicious","engine":"manual"}"#,
        );
        let av_judge = AvJudge { av: &av };
        let sni_state = SniState::Ok("example.org".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge, &cname_judge, &ip_judge, &av_judge];
        assert_eq!(run_judges(&judges, &input), Some(Reason::Sni));
    }

    #[test]
    fn run_judges_falls_through_to_av_when_others_pass() {
        let blocklist = Blocklist::empty();
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let cname_judge = CnameJudge;
        let iplist = IpList::empty();
        let ip_judge = IpJudge { iplist: &iplist };
        let av = AvList::parse(
            r#"{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"93.184.216.34","dst_port":443,"sha256":null,"verdict":"malicious","engine":"manual"}"#,
        );
        let av_judge = AvJudge { av: &av };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge, &cname_judge, &ip_judge, &av_judge];
        assert_eq!(run_judges(&judges, &input), Some(Reason::Av));
    }

    #[test]
    fn ids_judge_returns_none_for_empty_drop_set() {
        // PK-30 相当。--eve / --ips-sids 無しでは drop 集合が空のまま。
        let drop_set = IdsDropSet::new();
        let judge = IdsJudge {
            drop_set: &drop_set,
        };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), None);
    }

    #[test]
    fn ids_judge_matches_dropped_destination() {
        // PK-31 相当。
        let drop_set = IdsDropSet::new();
        drop_set.insert(
            dummy_dst_ip(),
            dummy_dst_port(),
            Instant::now(),
            std::time::Duration::from_secs(300),
        );
        let judge = IdsJudge {
            drop_set: &drop_set,
        };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        assert_eq!(judge.judge(&input), Some(Reason::Ids));
    }

    #[test]
    fn run_judges_tries_ids_after_sni_and_cname_but_before_ip_and_av() {
        // 段階の番号順（sni=2, cname=3, ids=4, iplist=5, av=6）で並べる
        // （`docs/design.md`「判定を差し込む口」節）。SNI が先に当たれば
        // ids 判定器まで進まない。
        let blocklist = Blocklist::parse("example.org\n");
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let cname_judge = CnameJudge;
        let drop_set = IdsDropSet::new();
        drop_set.insert(
            dummy_dst_ip(),
            dummy_dst_port(),
            Instant::now(),
            std::time::Duration::from_secs(300),
        );
        let ids_judge = IdsJudge {
            drop_set: &drop_set,
        };
        let sni_state = SniState::Ok("example.org".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge, &cname_judge, &ids_judge];
        assert_eq!(run_judges(&judges, &input), Some(Reason::Sni));
    }

    #[test]
    fn run_judges_falls_through_to_ids_when_sni_and_cname_pass() {
        let blocklist = Blocklist::empty();
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let cname_judge = CnameJudge;
        let drop_set = IdsDropSet::new();
        drop_set.insert(
            dummy_dst_ip(),
            dummy_dst_port(),
            Instant::now(),
            std::time::Duration::from_secs(300),
        );
        let ids_judge = IdsJudge {
            drop_set: &drop_set,
        };
        let sni_state = SniState::None;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge, &cname_judge, &ids_judge];
        assert_eq!(run_judges(&judges, &input), Some(Reason::Ids));
    }

    #[test]
    fn run_judges_with_allowlist_passes_even_when_same_domain_is_blocklisted() {
        // allowlist と blocklist の両方に同じ domain が在っても、
        // allowlist が先に効いて通る。
        let allowlist = Allowlist::parse("example.org\n");
        let blocklist = Blocklist::parse("example.org\n");
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let sni_state = SniState::Ok("example.org".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge];
        assert_eq!(run_judges_with_allowlist(&allowlist, &judges, &input), None);
    }

    #[test]
    fn run_judges_with_allowlist_still_blocks_when_not_allowlisted() {
        // allowlist に当たらない domain は、従来どおり blocklist で落ちる。
        let allowlist = Allowlist::parse("other.example\n");
        let blocklist = Blocklist::parse("example.org\n");
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let sni_state = SniState::Ok("example.org".to_string());
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge];
        assert_eq!(
            run_judges_with_allowlist(&allowlist, &judges, &input),
            Some(Reason::Sni)
        );
    }

    #[test]
    fn run_judges_with_allowlist_falls_through_when_sni_has_no_host() {
        // SNI を持たない flow（fragmented）は allowlist の対象にできず、
        // 既存の run_judges の挙動（fail-open）へそのまま委譲する。
        let allowlist = Allowlist::parse("example.org\n");
        let blocklist = Blocklist::empty();
        let sni_judge = SniJudge {
            blocklist: &blocklist,
        };
        let sni_state = SniState::Fragmented;
        let matches = empty_matches();
        let input = JudgeInput {
            sni_state: &sni_state,
            cname_matched_qnames: &matches,
            dst_ip: dummy_dst_ip(),
            dst_port: dummy_dst_port(),
        };
        let judges: Vec<&dyn Judge> = vec![&sni_judge];
        assert_eq!(run_judges_with_allowlist(&allowlist, &judges, &input), None);
    }
}
