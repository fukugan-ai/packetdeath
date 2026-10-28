//! Stage 11: `packetdeath waf-report`, a summary of `waf.jsonl`.
//!
//! `docs/design.md` "段階11 WAF" 報告. It answers four questions: what was done
//! with the requests, which rules fired most, which sources sent the most, and
//! which rules look like false positives (the same rule on the same path for
//! several different sources, which is what ordinary users doing an ordinary
//! thing look like).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

/// How many rows each top list shows.
const TOP: usize = 10;
/// A rule on a path is suspected after this many hits...
const SUSPECT_HITS: usize = 5;
/// ...from at least this many different sources.
const SUSPECT_SOURCES: usize = 2;

/// Options of `packetdeath waf-report`.
#[derive(Debug, PartialEq, Eq)]
pub struct ReportArgs {
    pub log_dir: PathBuf,
    /// `YYYY-MM-DD`; lines before it are left out.
    pub since: Option<String>,
}

fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
}

/// Read `waf-report` options.
pub fn parse_report_args(args: &[String]) -> Result<ReportArgs, String> {
    let mut log_dir = None;
    let mut since = None;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut next = |name: &str| iter.next().ok_or_else(|| format!("{name} needs a value"));
        match flag.as_str() {
            "--log-dir" => log_dir = Some(PathBuf::from(next("--log-dir")?)),
            "--since" => {
                let text = next("--since")?;
                if !is_date(text) {
                    return Err(format!("--since {text:?} is not YYYY-MM-DD"));
                }
                since = Some(text.clone());
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    let log_dir = log_dir.ok_or_else(|| String::from("--log-dir is required"))?;
    Ok(ReportArgs { log_dir, since })
}

/// A rule that hits the same path for several sources.
#[derive(Debug, PartialEq, Eq)]
pub struct Suspect {
    pub rule: String,
    pub path: String,
    pub hits: usize,
    pub sources: usize,
}

/// What the log says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub total: usize,
    pub unreadable: usize,
    pub by_action: BTreeMap<String, usize>,
    pub top_rules: Vec<(String, usize)>,
    pub top_sources: Vec<(String, usize)>,
    pub suspects: Vec<Suspect>,
}

fn text_of<'a>(line: &'a Value, key: &str) -> Option<&'a str> {
    line.get(key).and_then(Value::as_str)
}

fn top(counts: BTreeMap<String, usize>) -> Vec<(String, usize)> {
    let mut rows: Vec<(String, usize)> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(TOP);
    rows
}

/// Tally of one `(rule, path)` pair.
#[derive(Default)]
struct Pair {
    hits: usize,
    sources: BTreeSet<String>,
}

/// Summarize the text of a `waf.jsonl`.
pub fn summarize(text: &str, since: Option<&str>) -> Summary {
    let mut summary = Summary::default();
    let mut rules: BTreeMap<String, usize> = BTreeMap::new();
    let mut sources: BTreeMap<String, usize> = BTreeMap::new();
    let mut pairs: BTreeMap<(String, String), Pair> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            summary.unreadable += 1;
            continue;
        };
        let (Some(ts), Some(action), Some(ip)) = (
            text_of(&value, "ts"),
            text_of(&value, "action"),
            text_of(&value, "ip"),
        ) else {
            summary.unreadable += 1;
            continue;
        };
        if since.is_some_and(|date| ts < date) {
            continue;
        }
        summary.total += 1;
        *summary.by_action.entry(action.to_owned()).or_insert(0) += 1;
        *sources.entry(ip.to_owned()).or_insert(0) += 1;
        let path = text_of(&value, "path").map(str::to_owned);
        let labels = value.get("rules").and_then(Value::as_array);
        for label in labels.into_iter().flatten().filter_map(Value::as_str) {
            let rule = label.split(':').next().map(str::to_owned);
            let (Some(rule), Some(path)) = (rule, path.clone()) else {
                continue;
            };
            *rules.entry(rule.clone()).or_insert(0) += 1;
            let pair = pairs.entry((rule, path)).or_default();
            pair.hits += 1;
            pair.sources.insert(ip.to_owned());
        }
    }
    summary.top_rules = top(rules);
    summary.top_sources = top(sources);
    summary.suspects = pairs
        .into_iter()
        .filter(|(_, p)| p.hits >= SUSPECT_HITS && p.sources.len() >= SUSPECT_SOURCES)
        .map(|((rule, path), p)| Suspect {
            rule,
            path,
            hits: p.hits,
            sources: p.sources.len(),
        })
        .collect();
    summary
        .suspects
        .sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.rule.cmp(&b.rule)));
    summary
}

/// The share of requests that were blocked, as `12.3%`.
fn block_share(summary: &Summary) -> String {
    let blocked = summary.by_action.get("block").copied();
    let Some(blocked) = blocked.filter(|_| summary.total > 0) else {
        return String::from("0.0%");
    };
    let tenths = blocked * 1000 / summary.total;
    format!("{}.{}%", tenths / 10, tenths % 10)
}

/// The report as lines of text.
pub fn render(summary: &Summary) -> Vec<String> {
    let mut out = vec![format!(
        "requests {}  unreadable {}  blocked {}",
        summary.total,
        summary.unreadable,
        block_share(summary)
    )];
    out.push(String::from("actions:"));
    for (action, count) in &summary.by_action {
        out.push(format!("  {action:<10} {count}"));
    }
    out.push(String::from("top rules:"));
    for (rule, count) in &summary.top_rules {
        out.push(format!("  {rule:<10} {count}"));
    }
    out.push(String::from("top sources:"));
    for (ip, count) in &summary.top_sources {
        out.push(format!("  {ip:<40} {count}"));
    }
    out.push(String::from("possible false positives (same rule, same path, several sources):"));
    for s in &summary.suspects {
        out.push(format!(
            "  rule {} on {}  {} hits from {} sources",
            s.rule, s.path, s.hits, s.sources
        ));
    }
    out
}

/// Run `waf-report`. Returns the exit code.
pub fn run(args: &ReportArgs) -> i32 {
    let path = args.log_dir.join("waf.jsonl");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("packetdeath: [error] waf-report: {}: {e}", path.display());
            return 2;
        }
    };
    for line in render(&summarize(&text, args.since.as_deref())) {
        println!("{line}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(ts: &str, ip: &str, action: &str, path: &str, rules: &[&str]) -> String {
        let labels: Vec<String> = rules.iter().map(|r| format!("\"{r}\"")).collect();
        format!(
            "{{\"ts\":\"{ts}\",\"ip\":\"{ip}\",\"action\":\"{action}\",\"path\":\"{path}\",\"rules\":[{}]}}",
            labels.join(",")
        )
    }

    fn log(lines: &[String]) -> String {
        lines.join("\n")
    }

    #[test]
    fn actions_rules_and_sources_are_counted() {
        let text = log(&[
            line("2026-10-28T01:00:00Z", "203.0.113.5", "pass", "/", &[]),
            line("2026-10-28T01:00:01Z", "203.0.113.5", "block", "/a", &["942100:query"]),
            line("2026-10-28T01:00:02Z", "198.51.100.7", "block", "/b", &["942100:query", "941100:body"]),
            line("2026-10-28T01:00:03Z", "198.51.100.7", "detect", "/c", &["941100:query"]),
        ]);
        let s = summarize(&text, None);
        assert_eq!(s.total, 4);
        assert_eq!(s.by_action.get("block"), Some(&2));
        assert_eq!(s.top_rules[0], ("941100".to_owned(), 2));
        assert_eq!(s.top_rules[1], ("942100".to_owned(), 2));
        assert_eq!(s.top_sources[0].1, 2);
        assert_eq!(block_share(&s), "50.0%");
    }

    #[test]
    fn the_same_rule_on_the_same_path_for_several_sources_is_a_suspect() {
        let mut lines = Vec::new();
        for n in 0..6 {
            let ip = format!("203.0.113.{n}");
            lines.push(line("2026-10-28T01:00:00Z", &ip, "detect", "/api/search", &["942170:query"]));
        }
        let s = summarize(&log(&lines), None);
        assert_eq!(
            s.suspects,
            vec![Suspect { rule: "942170".into(), path: "/api/search".into(), hits: 6, sources: 6 }]
        );
    }

    #[test]
    fn one_source_repeating_itself_is_an_attacker_not_a_suspect() {
        let mut lines = Vec::new();
        for _ in 0..10 {
            lines.push(line("2026-10-28T01:00:00Z", "203.0.113.5", "block", "/login", &["942100:query"]));
        }
        assert!(summarize(&log(&lines), None).suspects.is_empty());
    }

    #[test]
    fn four_hits_are_not_enough_for_a_suspect() {
        let mut lines = Vec::new();
        for n in 0..4 {
            let ip = format!("203.0.113.{n}");
            lines.push(line("2026-10-28T01:00:00Z", &ip, "detect", "/x", &["942170:query"]));
        }
        assert!(summarize(&log(&lines), None).suspects.is_empty());
    }

    #[test]
    fn since_leaves_out_older_lines() {
        let text = log(&[
            line("2026-10-27T23:59:59Z", "203.0.113.5", "pass", "/", &[]),
            line("2026-10-28T00:00:00Z", "203.0.113.5", "pass", "/", &[]),
        ]);
        assert_eq!(summarize(&text, Some("2026-10-28")).total, 1);
        assert_eq!(summarize(&text, Some("2026-10-27")).total, 2);
    }

    #[test]
    fn unreadable_lines_are_counted_not_fatal() {
        let text = format!("garbage\n{{\"x\":1}}\n{}\n", line("2026-10-28T00:00:00Z", "203.0.113.5", "pass", "/", &[]));
        let s = summarize(&text, None);
        assert_eq!((s.total, s.unreadable), (1, 2));
    }

    #[test]
    fn an_empty_log_reports_zero() {
        let s = summarize("", None);
        assert_eq!(s.total, 0);
        assert_eq!(block_share(&s), "0.0%");
        assert!(render(&s)[0].starts_with("requests 0"));
    }

    #[test]
    fn the_rendering_has_every_section() {
        let rows = render(&summarize("", None)).join("\n");
        for heading in ["actions:", "top rules:", "top sources:", "possible false positives"] {
            assert!(rows.contains(heading), "{heading}");
        }
    }

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn options_are_read_and_checked() {
        let got = parse_report_args(&args("--log-dir d --since 2026-10-01"));
        assert_eq!(
            got,
            Ok(ReportArgs { log_dir: PathBuf::from("d"), since: Some("2026-10-01".into()) })
        );
        for bad in ["", "--log-dir", "--log-dir d --since yesterday", "--log-dir d --since 2026-1-01", "--what"] {
            assert!(parse_report_args(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_missing_log_is_exit_2() {
        let a = ReportArgs { log_dir: PathBuf::from("/nonexistent-waf-log-4f9a"), since: None };
        assert_eq!(run(&a), 2);
    }
}
