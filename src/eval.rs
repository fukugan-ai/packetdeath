//! `packetdeath eval --labels <tsv>` の遮断率・誤遮断率の計算。
//! `docs/design.md`「受入 ID」PK-13 が正本。OS 非依存（file を読むだけ）。

use serde::Deserialize;
use std::collections::HashMap;

/// labels.tsv の1行が持つラベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Ad,
    Ok,
}

/// `host<TAB>ad` / `host<TAB>ok` 形式の labels.tsv を読む。
/// 形式に合わない行（列が無い・ラベルが `ad`/`ok` 以外）は無視する
/// （labels.tsv は利用者が書く外部入力であり、壊れた行で `panic` しない）。
pub fn parse_labels(content: &str) -> HashMap<String, Label> {
    content
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, '\t');
            let host = parts.next()?.trim();
            let label = parts.next()?.trim();
            if host.is_empty() {
                return None;
            }
            match label {
                "ad" => Some((host.to_string(), Label::Ad)),
                "ok" => Some((host.to_string(), Label::Ok)),
                _ => None,
            }
        })
        .collect()
}

/// `flows.jsonl` の1行から eval に要る field だけを読む。`FlowLogEntry` は
/// `&'static str` を持つため deserialize できないので、別の view を使う。
#[derive(Debug, Deserialize)]
struct FlowRecordView {
    sni: Option<String>,
    decision: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Counts {
    pub total: u32,
    pub blocked: u32,
}

impl Counts {
    /// `total` が0のときは0.0を返す（0除算で `NaN` を出さない）。
    fn rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            f64::from(self.blocked) / f64::from(self.total)
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct EvalReport {
    pub ad: Counts,
    pub ok: Counts,
    pub skipped: u32,
}

impl EvalReport {
    pub fn ad_line(&self) -> String {
        format!(
            "ad total={} blocked={} block_rate={:.4}",
            self.ad.total,
            self.ad.blocked,
            self.ad.rate()
        )
    }

    pub fn ok_line(&self) -> String {
        format!(
            "ok total={} blocked={} false_block_rate={:.4}",
            self.ok.total,
            self.ok.blocked,
            self.ok.rate()
        )
    }

    /// ラベル無し行が1件以上あるときだけ `Some`。
    pub fn skipped_line(&self) -> Option<String> {
        (self.skipped > 0).then(|| format!("skipped={}", self.skipped))
    }
}

/// `flows_jsonl` を1行ずつ `labels` と突き合わせ、遮断率・誤遮断率を数える。
/// JSON として壊れた行、`sni` が無い行、`labels` に無い `sni` の行は
/// `skipped` に数える。`flows_jsonl` が空なら全カウント0（PK-13 の陰性対照）。
pub fn evaluate(labels: &HashMap<String, Label>, flows_jsonl: &str) -> EvalReport {
    let mut report = EvalReport::default();

    for line in flows_jsonl.lines() {
        let Ok(record) = serde_json::from_str::<FlowRecordView>(line) else {
            report.skipped += 1;
            continue;
        };
        let Some(sni) = &record.sni else {
            report.skipped += 1;
            continue;
        };
        let is_blocked = record.decision == "block";
        match labels.get(sni) {
            Some(Label::Ad) => {
                report.ad.total += 1;
                if is_blocked {
                    report.ad.blocked += 1;
                }
            }
            Some(Label::Ok) => {
                report.ok.total += 1;
                if is_blocked {
                    report.ok.blocked += 1;
                }
            }
            None => report.skipped += 1,
        }
    }

    eprintln!(
        "packetdeath: [info] {}",
        crate::i18n::eval_executed(
            crate::i18n::locale(),
            report.ad.total,
            report.ad.blocked,
            report.ok.total,
            report.ok.blocked,
            report.skipped
        )
    );

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_labels_reads_ad_and_ok_rows() {
        let labels = parse_labels("ads.example\tad\nfirst-party.example\tok\n");
        assert_eq!(labels.get("ads.example"), Some(&Label::Ad));
        assert_eq!(labels.get("first-party.example"), Some(&Label::Ok));
    }

    #[test]
    fn parse_labels_ignores_malformed_rows() {
        let labels = parse_labels("no-tab-here\nhost\tunknown-label\n");
        assert!(labels.is_empty());
    }

    #[test]
    fn evaluate_reports_zero_totals_for_empty_log() {
        // テスト項目10：log が空のとき total=0 と言う。
        let labels = parse_labels("ads.example\tad\n");
        let report = evaluate(&labels, "");
        assert_eq!(report.ad.total, 0);
        assert_eq!(report.ok.total, 0);
        assert!(report.ad_line().contains("total=0"));
    }

    #[test]
    fn evaluate_counts_blocked_ad_and_unblocked_ok() {
        let labels = parse_labels("ads.example\tad\nfirst-party.example\tok\n");
        let flows = concat!(
            r#"{"sni":"ads.example","decision":"block"}"#,
            "\n",
            r#"{"sni":"first-party.example","decision":"pass"}"#,
            "\n",
        );
        let report = evaluate(&labels, flows);
        assert_eq!(
            report.ad,
            Counts {
                total: 1,
                blocked: 1
            }
        );
        assert_eq!(
            report.ok,
            Counts {
                total: 1,
                blocked: 0
            }
        );
        assert_eq!(report.skipped, 0);
    }

    #[test]
    fn evaluate_counts_false_block_when_ok_host_is_blocked() {
        let labels = parse_labels("first-party.example\tok\n");
        let flows = concat!(r#"{"sni":"first-party.example","decision":"block"}"#, "\n");
        let report = evaluate(&labels, flows);
        assert_eq!(
            report.ok,
            Counts {
                total: 1,
                blocked: 1
            }
        );
    }

    #[test]
    fn evaluate_skips_rows_without_label() {
        let labels = parse_labels("ads.example\tad\n");
        let flows = concat!(r#"{"sni":"unlabeled.example","decision":"pass"}"#, "\n");
        let report = evaluate(&labels, flows);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.skipped_line(), Some("skipped=1".to_string()));
    }

    #[test]
    fn evaluate_skips_rows_with_null_sni() {
        let labels = parse_labels("ads.example\tad\n");
        let flows = concat!(r#"{"sni":null,"decision":"pass"}"#, "\n");
        let report = evaluate(&labels, flows);
        assert_eq!(report.skipped, 1);
    }

    #[test]
    fn skipped_line_is_none_when_nothing_skipped() {
        let report = EvalReport::default();
        assert_eq!(report.skipped_line(), None);
    }
}
