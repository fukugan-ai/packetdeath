//! Stage 12: `packetdeath ips-report`, a summary of `ips.jsonl`.
//!
//! `docs/design.md` "段階12 IDS/IPS の業務水準化" 報告. It answers: how many of
//! each event, which signatures acted most, which signatures only ever
//! observed (the candidates to turn into a drop), which destinations were
//! protected (a sign of a policy aimed at the network itself), and how many
//! drops each day.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

pub use crate::waf::report::{parse_report_args, ReportArgs};

/// How many rows each top list shows.
const TOP: usize = 10;

/// What the log says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub lines: usize,
    pub unreadable: usize,
    pub events: BTreeMap<String, usize>,
    pub acting_sids: Vec<(u64, usize)>,
    pub observed_only: Vec<(u64, usize)>,
    pub protected: Vec<(String, usize)>,
    pub daily_drops: BTreeMap<String, usize>,
}

fn top<K: Ord + Clone>(counts: BTreeMap<K, usize>) -> Vec<(K, usize)> {
    let mut rows: Vec<(K, usize)> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(TOP);
    rows
}

/// Count `text` (the lines of `ips.jsonl`), leaving out lines before `since`.
pub fn summarize(text: &str, since: Option<&str>) -> Summary {
    let mut out = Summary::default();
    let mut acting: BTreeMap<u64, usize> = BTreeMap::new();
    let mut observed: BTreeMap<u64, usize> = BTreeMap::new();
    let mut dropped_sids: BTreeSet<u64> = BTreeSet::new();
    let mut protected: BTreeMap<String, usize> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(row) = serde_json::from_str::<Value>(line) else {
            out.unreadable += 1;
            continue;
        };
        let (Some(ts), Some(event)) = (row["ts"].as_str(), row["event"].as_str()) else {
            out.unreadable += 1;
            continue;
        };
        if since.is_some_and(|s| ts.get(..10).is_some_and(|day| day < s)) {
            continue;
        }
        out.lines += 1;
        *out.events.entry(event.to_owned()).or_insert(0) += 1;
        let sid = row["sid"].as_u64();
        match (event, sid) {
            ("drop" | "escalated", Some(sid)) => {
                *acting.entry(sid).or_insert(0) += 1;
                dropped_sids.insert(sid);
                if let Some(day) = ts.get(..10) {
                    *out.daily_drops.entry(day.to_owned()).or_insert(0) += 1;
                }
            }
            ("observed", Some(sid)) => *observed.entry(sid).or_insert(0) += 1,
            ("protected", _) => {
                if let Some(dst) = row["dst_ip"].as_str() {
                    *protected.entry(dst.to_owned()).or_insert(0) += 1;
                }
            }
            _ => {}
        }
    }
    observed.retain(|sid, _| !dropped_sids.contains(sid));
    out.acting_sids = top(acting);
    out.observed_only = top(observed);
    out.protected = top(protected);
    out
}

/// The report as lines of text.
pub fn render(summary: &Summary) -> Vec<String> {
    let mut rows = vec![format!("lines {}  unreadable {}", summary.lines, summary.unreadable)];
    rows.push(String::from("events"));
    for (event, count) in &summary.events {
        rows.push(format!("  {event:<10} {count}"));
    }
    rows.push(String::from("signatures that dropped"));
    for (sid, count) in &summary.acting_sids {
        rows.push(format!("  sid {sid}  {count}"));
    }
    rows.push(String::from("signatures that only observed (candidates for a drop rule)"));
    for (sid, count) in &summary.observed_only {
        rows.push(format!("  sid {sid}  {count}"));
    }
    rows.push(String::from("protected destinations (a policy aimed at the network itself?)"));
    for (dst, count) in &summary.protected {
        rows.push(format!("  {dst}  {count}"));
    }
    rows.push(String::from("drops per day"));
    for (day, count) in &summary.daily_drops {
        rows.push(format!("  {day}  {count}"));
    }
    rows
}

/// Run `ips-report`. Prints the report; returns the exit code.
pub fn run(args: &ReportArgs) -> i32 {
    let path = args.log_dir.join("ips.jsonl");
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            for row in render(&summarize(&text, args.since.as_deref())) {
                println!("{row}");
            }
            0
        }
        Err(why) => {
            eprintln!("packetdeath: [error] ips-report: {}: {why}", path.display());
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ts: &str, event: &str, sid: u64, dst: &str) -> String {
        format!("{{\"ts\":\"{ts}\",\"event\":\"{event}\",\"sid\":{sid},\"dst_ip\":\"{dst}\"}}")
    }

    fn log(rows: &[String]) -> String {
        rows.join("\n")
    }

    #[test]
    fn events_acting_sids_and_daily_drops_are_counted() {
        let text = log(&[
            row("2026-10-27T01:00:00Z", "drop", 7, "203.0.113.1"),
            row("2026-10-28T01:00:00Z", "drop", 7, "203.0.113.2"),
            row("2026-10-28T02:00:00Z", "escalated", 8, "203.0.113.3"),
            row("2026-10-28T03:00:00Z", "observed", 9, "203.0.113.4"),
        ]);
        let s = summarize(&text, None);
        assert_eq!((s.lines, s.events.get("drop").copied()), (4, Some(2)));
        assert_eq!(s.acting_sids, vec![(7, 2), (8, 1)]);
        assert_eq!(s.daily_drops.get("2026-10-28").copied(), Some(2));
    }

    #[test]
    fn a_signature_that_also_dropped_is_not_observed_only() {
        let text = log(&[
            row("2026-10-28T01:00:00Z", "observed", 9, "203.0.113.1"),
            row("2026-10-28T01:00:01Z", "observed", 9, "203.0.113.1"),
            row("2026-10-28T01:00:02Z", "observed", 5, "203.0.113.1"),
            row("2026-10-28T01:00:03Z", "drop", 5, "203.0.113.1"),
        ]);
        assert_eq!(summarize(&text, None).observed_only, vec![(9, 2)]);
    }

    #[test]
    fn protected_destinations_and_since_and_unreadable_lines() {
        let text = log(&[
            row("2026-10-20T01:00:00Z", "protected", 1, "192.168.1.1"),
            row("2026-10-28T01:00:00Z", "protected", 1, "192.168.1.1"),
            String::from("garbage"),
            String::from("{\"event\":\"drop\"}"),
        ]);
        let s = summarize(&text, Some("2026-10-27"));
        assert_eq!((s.lines, s.unreadable), (1, 2));
        assert_eq!(s.protected, vec![(String::from("192.168.1.1"), 1)]);
    }

    #[test]
    fn an_empty_log_reports_zero_and_every_section_is_rendered() {
        let rows = render(&summarize("", None));
        assert_eq!(rows[0], "lines 0  unreadable 0");
        for head in ["events", "signatures that dropped", "signatures that only observed", "protected destinations", "drops per day"] {
            assert!(rows.iter().any(|r| r.starts_with(head)), "{head}");
        }
    }

    #[test]
    fn a_missing_log_is_exit_2() {
        let args = ReportArgs { log_dir: std::path::PathBuf::from("/nonexistent-ips-log-7b2e"), since: None };
        assert_eq!(run(&args), 2);
    }
}
