//! 段階6「外部 scanner の verdict 取り込み」の `--av`。`docs/design.md`
//! 「段階5 以降と受入 ID の予約」節（586行目付近の表の直後）が正本。
//!
//! 形式は JSON Lines。1行1 verdict。field は `ts`、`proto`、`dst_ip`、
//! `dst_port`、`sha256`（無ければ `null`）、`verdict`（`malicious` か
//! `clean`）、`engine`。`verdict` が `malicious` の行だけが効き、drop 集合へ
//! 入るのは `dst_ip` と `dst_port` の組である。`ids`（段階4）と違い `dst_ip`
//! 単独では落とさない。CDN の共有 IP を丸ごと落とすと、同じ IP の別の site が
//! 巻き込まれるため（正本、同節）。
//! `ts` は記録するだけで判定には使わない（同節）ので、この module は読みも
//! しない。`engine` は判定には使わないが、`AvJudge` が当たったときの log
//! （`log_match`。`AvJudge` が当たったとき engine 名まで出す）に
//! 使うため保持する。
//!
//! **外部が更新する av file を、動作の gate にしない。**file が読めなくても
//! `AvList::empty()` へ倒して素通しのまま動き続ける（呼び出し側の責務。
//! `IpList::load` と同じ形。`iplist.rs` を踏襲）。
//!
//! 個々の行の parse に失敗しても（壊れた JSON、field 欠落、型違反、途中で
//! 切れた行等）panic せず、その行だけを読み飛ばして stderr に出す
//! （正本「読めない行は捨てて stderr に出す」。PK-64, PK-65）。file は外部の
//! 橋渡し program が追記し続けるので、末尾の1行が壊れていても、そこまでの
//! 行は効く。読み終えた行数・`malicious` / `clean` / 読み飛ばした件数は
//! `AvList::parse` が info log として出す（PK-6D）。

use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

/// `verdict` がこの文字列の行だけが drop 集合へ入る。
const VERDICT_MALICIOUS: &str = "malicious";

/// `av.jsonl` の1行。判定に使うのは `dst_ip` / `dst_port` / `verdict` の3つ、
/// log に出すのに `engine` を使う。`ts` / `proto` / `sha256` は記録用の
/// field でこの module は読まないが、`#[serde(deny_unknown_fields)]` は
/// 付けない ── 橋渡し program が将来 field を足しても、この reader を
/// 壊さないため。
#[derive(Debug, Deserialize)]
struct AvLine {
    dst_ip: IpAddr,
    dst_port: u16,
    verdict: String,
    engine: String,
}

/// `--av` に当たる `malicious` な宛先（`dst_ip` と `dst_port` の組）の集合。
/// 値は判定した `engine` 名（log 用。`AvJudge` が当たったとき、通信の中身
/// ではなく engine 名を log に出すため保持する）。
#[derive(Debug, Default)]
pub struct AvList {
    malicious: HashMap<(IpAddr, u16), String>,
}

#[derive(Debug)]
pub enum AvListError {
    Io(std::io::Error),
}

impl fmt::Display for AvListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{}", crate::i18n::av_io_failed(crate::i18n::locale(), e)),
        }
    }
}

impl std::error::Error for AvListError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for AvListError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// 1行を parse した結果。`parse` が件数を集計する材料にする。
enum LineOutcome {
    /// `verdict` が `malicious`。
    Malicious {
        dst_ip: IpAddr,
        dst_port: u16,
        engine: String,
    },
    /// `verdict` が `malicious` 以外（`clean` 等）。
    Clean,
    /// 壊れた JSON、field 欠落、型違反。呼び出し側が stderr へ出す。
    Skipped(serde_json::Error),
}

impl AvList {
    /// 何にも当たらない空の av 集合（PK-60 の陰性対照）。
    pub fn empty() -> Self {
        Self {
            malicious: HashMap::new(),
        }
    }

    /// `path` から av file を読む。
    pub fn load(path: &Path) -> Result<Self, AvListError> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    /// JSON Lines を読む。空行は無視する。壊れた行と `verdict` が
    /// `malicious` でない行は読み飛ばし、panic しない（PK-64, PK-65）。
    ///
    /// 読み終えたら、読んだ行数・`malicious` / `clean` / 読み飛ばした行数を
    /// 1行の info log に出す（PK-6D）。個々の読み飛ばした行は、その場で
    /// warn log に出す（行番号と理由つき）。
    pub fn parse(content: &str) -> Self {
        let mut malicious = HashMap::new();
        let mut clean_count = 0usize;
        let mut skipped_count = 0usize;
        let mut total_count = 0usize;

        for (i, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            total_count += 1;
            match Self::parse_line(line) {
                LineOutcome::Malicious {
                    dst_ip,
                    dst_port,
                    engine,
                } => {
                    malicious.insert((dst_ip, dst_port), engine);
                }
                LineOutcome::Clean => clean_count += 1,
                LineOutcome::Skipped(e) => {
                    skipped_count += 1;
                    eprintln!(
                        "packetdeath: [warn] {}",
                        crate::i18n::av_line_skipped(crate::i18n::locale(), i + 1, e)
                    );
                }
            }
        }

        eprintln!(
            "packetdeath: [info] {}",
            crate::i18n::av_loaded(
                crate::i18n::locale(),
                total_count,
                malicious.len(),
                clean_count,
                skipped_count
            )
        );

        Self { malicious }
    }

    /// 1行を parse する。空行は呼び出し側（`parse`）が既に除いている前提。
    fn parse_line(line: &str) -> LineOutcome {
        match serde_json::from_str::<AvLine>(line) {
            Ok(entry) if entry.verdict == VERDICT_MALICIOUS => LineOutcome::Malicious {
                dst_ip: entry.dst_ip,
                dst_port: entry.dst_port,
                engine: entry.engine,
            },
            Ok(_) => LineOutcome::Clean,
            Err(e) => LineOutcome::Skipped(e),
        }
    }

    /// `(dst_ip, dst_port)` の組が `malicious` として届いているか。
    pub fn contains(&self, dst_ip: &IpAddr, dst_port: u16) -> bool {
        self.malicious.contains_key(&(*dst_ip, dst_port))
    }

    /// `(dst_ip, dst_port)` が `malicious` として届いていれば、その
    /// `engine` 名を返す。`AvJudge` が当たったときの log 用
    /// （宛先と verdict と engine 名までにし、通信の中身は出さない）。
    pub fn engine_of(&self, dst_ip: &IpAddr, dst_port: u16) -> Option<&str> {
        self.malicious.get(&(*dst_ip, dst_port)).map(String::as_str)
    }
}

/// `AvJudge`（`judge.rs`）が当たった宛先を debug log に出す。`av` は
/// 当たったときだけ出し、当たらなければ何もしない。
///
/// `Judge` の中で I/O をしない設計（`judge.rs` 冒頭 doc comment）に沿い、
/// この関数は `Judge::judge` の中ではなく、判定結果を受け取った呼び出し側
/// （`linux::run_block` / `block_loop::process_pcapng_snapshot`）が
/// `Reason::Av` を見たときにだけ呼ぶ。
///
/// log に出すのは宛先と verdict と engine 名までで、通信の中身は出さない
/// （PK-6E）。
pub fn log_match(av: &AvList, dst_ip: &IpAddr, dst_port: u16) {
    if let Some(engine) = av.engine_of(dst_ip, dst_port) {
        eprintln!(
            "packetdeath: [debug] {}",
            crate::i18n::av_matched(
                crate::i18n::locale(),
                dst_ip,
                dst_port,
                VERDICT_MALICIOUS,
                engine
            )
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }

    fn malicious_line(ip: &str, port: u16) -> String {
        format!(
            r#"{{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"{ip}","dst_port":{port},"sha256":null,"verdict":"malicious","engine":"manual"}}"#
        )
    }

    #[test]
    fn empty_av_list_matches_nothing() {
        // PK-60 相当。
        let list = AvList::empty();
        assert!(!list.contains(&sample_ip(), 443));
    }

    #[test]
    fn parse_matches_malicious_destination() {
        // PK-61 相当。
        let content = malicious_line("93.184.216.34", 443);
        let list = AvList::parse(&content);
        assert!(list.contains(&sample_ip(), 443));
    }

    #[test]
    fn clean_verdict_does_not_match() {
        let content = r#"{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"93.184.216.34","dst_port":443,"sha256":null,"verdict":"clean","engine":"manual"}"#;
        let list = AvList::parse(content);
        assert!(!list.contains(&sample_ip(), 443));
    }

    #[test]
    fn port_must_match_exactly() {
        // dst_ip が同じでも dst_port が違えば当たらない（CDN の共有 IP 対策。
        // 正本「段階5 以降と受入 ID の予約」節）。
        let content = malicious_line("93.184.216.34", 443);
        let list = AvList::parse(&content);
        assert!(!list.contains(&sample_ip(), 8443));
    }

    #[test]
    fn malformed_lines_are_skipped_without_panicking() {
        // PK-64: 空、不正な JSON、途中で切れた行、巨大な行、非 ASCII、
        // field 不足、型違いのいずれも panic せず、正常な行だけが効く
        // （PK-65）。
        let huge_line = "x".repeat(1_000_000);
        let content = format!(
            "\n\nnot-json\n{{\"dst_ip\":\"not-an-ip\",\"dst_port\":443,\"verdict\":\"malicious\"}}\n{{\"dst_ip\":\"93.184.216.34\",\"dst_port\":\"not-a-port\",\"verdict\":\"malicious\"}}\n{{\"dst_ip\":\"93.184.216.34\"\n{huge_line}\n日本語\n{{\"dst_ip\":\"93.184.216.34\",\"dst_port\":99999,\"verdict\":\"malicious\"}}\n{}\n",
            malicious_line("198.51.100.7", 80)
        );
        let list = AvList::parse(&content);
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 80));
        assert!(!list.contains(&sample_ip(), 443));
    }

    #[test]
    fn missing_fields_are_skipped_without_panicking() {
        // field が足りない行（`dst_port` 欠落）は読み飛ばす。
        let content = "{\"dst_ip\":\"93.184.216.34\",\"verdict\":\"malicious\"}\n";
        let list = AvList::parse(content);
        assert!(!list.contains(&sample_ip(), 443));
    }

    #[test]
    fn load_missing_file_returns_err() {
        let path = Path::new("/nonexistent/packetdeath-av-test.jsonl");
        assert!(AvList::load(path).is_err());
    }

    #[test]
    fn engine_of_returns_none_for_empty_av_list() {
        let list = AvList::empty();
        assert_eq!(list.engine_of(&sample_ip(), 443), None);
    }

    #[test]
    fn engine_of_returns_engine_name_for_malicious_destination() {
        // PK-6E 相当：`AvJudge` が当たったとき、log に出す engine 名が引ける。
        let content = r#"{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"93.184.216.34","dst_port":443,"sha256":null,"verdict":"malicious","engine":"clamav"}"#;
        let list = AvList::parse(content);
        assert_eq!(list.engine_of(&sample_ip(), 443), Some("clamav"));
    }

    #[test]
    fn engine_of_returns_none_for_clean_verdict() {
        let content = r#"{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"93.184.216.34","dst_port":443,"sha256":null,"verdict":"clean","engine":"clamav"}"#;
        let list = AvList::parse(content);
        assert_eq!(list.engine_of(&sample_ip(), 443), None);
    }

    #[test]
    fn log_match_does_not_panic_for_matching_and_non_matching_destinations() {
        // PK-6E：log の副作用自体は assert できないが、当たる場合・当たらない
        // 場合の両方で panic しないことを確かめる（宛先と verdict と engine
        // 名までしか使わないので、通信の中身に依存しない）。
        let content = malicious_line("93.184.216.34", 443);
        let list = AvList::parse(&content);
        log_match(&list, &sample_ip(), 443);
        log_match(&list, &sample_ip(), 8443);
    }
}
