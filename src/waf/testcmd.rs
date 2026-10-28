//! Stage 11: `packetdeath waf-test`, the judge run over a corpus without a socket.
//!
//! `docs/design.md` "段階11 WAF" 検査用. One JSON object per line:
//!
//! ```text
//! {"method":"GET","path":"/","query":"q=1","headers":{"X-A":"b"},"body":"...","expect":"block"}
//! ```
//!
//! `method` and `path` are required; `query`, `headers` and `body` may be left
//! out; `expect` is `pass` or `block`; `note` is for the reader. A line whose
//! outcome is not the expected one is reported with its line number, and the
//! command exits 1.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

use super::config::{load_exclusions, ExclusionError};
use super::engine::{inspect, Exclusion, Policy, Request};
use super::rules::{load_jsonl, RuleSet};

/// What a corpus line expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Pass,
    Block,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    method: String,
    path: String,
    query: Option<String>,
    headers: Option<BTreeMap<String, String>>,
    body: Option<String>,
    expect: String,
    #[allow(dead_code)]
    note: Option<String>,
}

/// A line whose outcome was not the expected one.
#[derive(Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub line: usize,
    pub expected: Expect,
    pub score: u32,
    pub rules: Vec<u32>,
}

/// The result of a corpus run.
#[derive(Debug, Default)]
pub struct Report {
    pub total: usize,
    pub mismatches: Vec<Mismatch>,
    /// Lines that are not corpus lines (1-based line, why). These fail the run.
    pub bad_lines: Vec<(usize, String)>,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.mismatches.is_empty() && self.bad_lines.is_empty()
    }
}

fn expectation(text: &str) -> Option<Expect> {
    match text {
        "pass" => Some(Expect::Pass),
        "block" => Some(Expect::Block),
        _ => None,
    }
}

/// Build the request a corpus line describes. `Host` is added when absent so
/// that a line is not blamed for something it did not mean to test.
fn request_of(line: Line) -> Request {
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(given) = line.headers {
        headers.extend(given);
    }
    if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
        headers.push(("Host".to_owned(), "corpus.test".to_owned()));
    }
    let mut query = String::new();
    if let Some(found) = line.query {
        query = found;
    }
    let mut body = Vec::new();
    if let Some(found) = line.body {
        body = found.into_bytes();
    }
    Request {
        method: line.method,
        path: line.path,
        query,
        headers,
        body,
        body_truncated: false,
        http11: true,
    }
}

fn read_line(text: &str) -> Result<(Request, Expect), String> {
    let parsed: Line = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let Some(expect) = expectation(&parsed.expect) else {
        return Err(format!("expect {:?} is not pass or block", parsed.expect));
    };
    Ok((request_of(parsed), expect))
}

/// Run every line of `corpus`.
pub fn run_corpus(
    corpus: &str,
    set: &RuleSet,
    policy: Policy,
    exclusions: &[Exclusion],
) -> Report {
    let mut report = Report::default();
    for (index, text) in corpus.lines().enumerate() {
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let (request, expect) = match read_line(trimmed) {
            Ok(found) => found,
            Err(why) => {
                report.bad_lines.push((number, why));
                continue;
            }
        };
        report.total += 1;
        let verdict = inspect(&request, set, policy, exclusions);
        let got = if verdict.over_threshold { Expect::Block } else { Expect::Pass };
        if got != expect {
            report.mismatches.push(Mismatch {
                line: number,
                expected: expect,
                score: verdict.score,
                rules: verdict.hits.iter().map(|h| h.id).collect(),
            });
        }
    }
    report
}

/// Options of `packetdeath waf-test`.
#[derive(Debug, PartialEq, Eq)]
pub struct TestArgs {
    pub corpus: PathBuf,
    pub rules: Option<PathBuf>,
    pub exclusions: Option<PathBuf>,
    pub paranoia: u8,
    pub threshold: u32,
}

/// Read `waf-test` options.
pub fn parse_test_args(args: &[String]) -> Result<TestArgs, String> {
    let mut corpus = None;
    let mut rules = None;
    let mut exclusions = None;
    let mut paranoia: u8 = 1;
    let mut threshold: u32 = 5;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut next = |name: &str| iter.next().ok_or_else(|| format!("{name} needs a value"));
        match flag.as_str() {
            "--corpus" => corpus = Some(PathBuf::from(next("--corpus")?)),
            "--rules" => rules = Some(PathBuf::from(next("--rules")?)),
            "--exclusions" => exclusions = Some(PathBuf::from(next("--exclusions")?)),
            "--paranoia" => {
                let text = next("--paranoia")?;
                paranoia = text.parse().map_err(|_| format!("--paranoia {text:?}"))?;
                if !(1..=4).contains(&paranoia) {
                    return Err(format!("--paranoia {text:?} is not 1..4"));
                }
            }
            "--threshold" => {
                let text = next("--threshold")?;
                threshold = text.parse().map_err(|_| format!("--threshold {text:?}"))?;
            }
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    let corpus = corpus.ok_or_else(|| String::from("--corpus is required"))?;
    Ok(TestArgs {
        corpus,
        rules,
        exclusions,
        paranoia,
        threshold,
    })
}

fn read(path: &PathBuf) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn describe(why: &ExclusionError) -> String {
    why.to_string()
}

/// Run `waf-test`. Prints the mismatches; returns the exit code.
pub fn run(args: &TestArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(why) => {
            eprintln!("packetdeath: [error] waf-test: {why}");
            2
        }
    }
}

fn run_inner(args: &TestArgs) -> Result<i32, String> {
    let mut extra = Vec::new();
    if let Some(path) = &args.rules {
        let loaded = load_jsonl(&read(path)?);
        for (line, why) in &loaded.bad {
            eprintln!("packetdeath: [warn] rules line {line}: {why}");
        }
        extra = loaded.rules;
    }
    let set = RuleSet::with_extra(extra).map_err(|e| e.to_string())?;
    let mut exclusions = Vec::new();
    if let Some(path) = &args.exclusions {
        let loaded = load_exclusions(&read(path)?);
        for (line, why) in &loaded.bad {
            eprintln!("packetdeath: [warn] exclusions line {line}: {}", describe(why));
        }
        exclusions = loaded.exclusions;
    }
    let policy = Policy {
        paranoia: args.paranoia,
        threshold: args.threshold,
    };
    let report = run_corpus(&read(&args.corpus)?, &set, policy, &exclusions);
    print_report(args, &report);
    Ok(if report.passed() { 0 } else { 1 })
}

fn print_report(args: &TestArgs, report: &Report) {
    let file = args.corpus.display();
    for m in &report.mismatches {
        println!(
            "{file}:{}: expected {:?}, score {}, rules {:?}",
            m.line, m.expected, m.score, m.rules
        );
    }
    for (line, why) in &report.bad_lines {
        println!("{file}:{line}: not a corpus line: {why}");
    }
    println!(
        "{} lines, {} mismatches, {} unreadable",
        report.total,
        report.mismatches.len(),
        report.bad_lines.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const POLICY: Policy = Policy {
        paranoia: 1,
        threshold: 5,
    };

    fn run_text(text: &str) -> Result<Report, Box<dyn std::error::Error>> {
        Ok(run_corpus(text, &RuleSet::builtin_only()?, POLICY, &[]))
    }

    #[test]
    fn matching_lines_pass_the_run() -> TestResult {
        let text = concat!(
            "{\"method\":\"GET\",\"path\":\"/\",\"query\":\"q=blue+shoes\",\"expect\":\"pass\"}\n",
            "{\"method\":\"GET\",\"path\":\"/\",\"query\":\"q=1+union+select+2\",\"expect\":\"block\"}\n",
        );
        let report = run_text(text)?;
        assert_eq!(report.total, 2);
        assert!(report.passed());
        Ok(())
    }

    #[test]
    fn a_mismatch_names_its_line_and_the_rules_that_fired() -> TestResult {
        let text = concat!(
            "# a comment\n",
            "\n",
            "{\"method\":\"GET\",\"path\":\"/\",\"query\":\"q=1+union+select+2\",\"expect\":\"pass\"}\n",
        );
        let report = run_text(text)?;
        assert_eq!(report.mismatches.len(), 1);
        assert_eq!(report.mismatches[0].line, 3);
        assert_eq!(report.mismatches[0].expected, Expect::Pass);
        assert!(report.mismatches[0].rules.contains(&942_100));
        assert!(!report.passed());
        Ok(())
    }

    #[test]
    fn headers_and_body_are_judged() -> TestResult {
        let text = concat!(
            "{\"method\":\"POST\",\"path\":\"/\",\"headers\":{\"Content-Type\":\"application/json\"},",
            "\"body\":\"{\\\"a\\\":\\\"<script>x</script>\\\"}\",\"expect\":\"block\"}\n",
            "{\"method\":\"GET\",\"path\":\"/\",\"headers\":{\"X-A\":\"${jndi:ldap://e/a}\"},\"expect\":\"block\"}\n",
        );
        assert!(run_text(text)?.passed());
        Ok(())
    }

    #[test]
    fn unreadable_lines_fail_the_run_and_are_named() -> TestResult {
        let text = concat!(
            "not json\n",
            "{\"method\":\"GET\",\"path\":\"/\",\"expect\":\"maybe\"}\n",
            "{\"method\":\"GET\",\"path\":\"/\",\"expect\":\"pass\",\"extra\":1}\n",
        );
        let report = run_text(text)?;
        let lines: Vec<usize> = report.bad_lines.iter().map(|b| b.0).collect();
        assert_eq!(lines, vec![1, 2, 3]);
        assert!(!report.passed());
        assert_eq!(report.total, 0);
        Ok(())
    }

    #[test]
    fn an_empty_corpus_passes_with_zero_lines() -> TestResult {
        let report = run_text("")?;
        assert_eq!((report.total, report.passed()), (0, true));
        Ok(())
    }

    #[test]
    fn host_is_added_so_a_line_is_not_blamed_for_its_absence() -> TestResult {
        let text = "{\"method\":\"GET\",\"path\":\"/\",\"expect\":\"pass\"}\n";
        assert!(run_text(text)?.passed());
        Ok(())
    }

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn options_are_read() -> TestResult {
        let got = parse_test_args(&args("--corpus c.jsonl --rules r --exclusions e --paranoia 2 --threshold 7"))?;
        assert_eq!(got.corpus, PathBuf::from("c.jsonl"));
        assert_eq!(got.rules, Some(PathBuf::from("r")));
        assert_eq!((got.paranoia, got.threshold), (2, 7));
        let plain = parse_test_args(&args("--corpus c.jsonl"))?;
        assert_eq!((plain.paranoia, plain.threshold), (1, 5));
        Ok(())
    }

    #[test]
    fn bad_options_are_refused() {
        for line in ["", "--corpus", "--corpus c --paranoia 9", "--corpus c --threshold x", "--corpus c --what"] {
            assert!(parse_test_args(&args(line)).is_err(), "{line:?}");
        }
    }

    #[test]
    fn a_missing_corpus_file_is_exit_2() {
        let a = TestArgs {
            corpus: PathBuf::from("/nonexistent-corpus-4f9a.jsonl"),
            rules: None,
            exclusions: None,
            paranoia: 1,
            threshold: 5,
        };
        assert_eq!(run(&a), 2);
    }
}
