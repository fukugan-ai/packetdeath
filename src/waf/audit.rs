//! Stage 11: the audit log, `<log-dir>/waf.jsonl`, one line per request.
//!
//! `docs/design.md` "段階11 WAF". The line carries what is needed to find a
//! request again and to see why it was judged as it was: who, what route, what
//! was decided, which rules. It never carries a query value, a header value, a
//! cookie or a body; the path is cut at [`PATH_BYTES`].

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::engine::{Hit, Verdict};

/// Longest path written.
pub const PATH_BYTES: usize = 256;
/// Longest `Host` written.
pub const HOST_BYTES: usize = 128;

/// What was done with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Pass,
    /// Over the threshold, but the mode is `detect`.
    Detect,
    Block,
    DenyIp,
    RateLimit,
    Ban,
    /// Refused as malformed HTTP before any rule ran.
    Protocol,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Pass => "pass",
            Action::Detect => "detect",
            Action::Block => "block",
            Action::DenyIp => "deny-ip",
            Action::RateLimit => "ratelimit",
            Action::Ban => "ban",
            Action::Protocol => "protocol",
        }
    }
}

/// One audit line.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub ts: String,
    pub id: String,
    pub ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub query_len: usize,
    pub body_len: u64,
    pub status: u16,
    pub action: &'static str,
    pub score: u32,
    pub rules: Vec<String>,
    pub mode: &'static str,
    pub upstream_ms: Option<u64>,
    pub flags: Vec<&'static str>,
}

static NEXT: AtomicU64 = AtomicU64::new(1);

/// A request id, unique within this process and across restarts (the start
/// second and the process id are in it).
pub fn request_id(started_secs: u64) -> String {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{started_secs:x}-{:x}-{n:x}", std::process::id())
}

/// Cut `text` to at most `max` bytes without splitting a character, and drop
/// control characters (a log line stays one line).
pub fn clip(text: &str, max: usize) -> String {
    let mut out = String::new();
    for c in text.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

/// `942100:query` for each hit.
pub fn rule_labels(hits: &[Hit]) -> Vec<String> {
    hits.iter()
        .map(|h| format!("{}:{}", h.id, h.at.name()))
        .collect()
}

/// Everything the server knows about a request when it writes the line.
pub struct Facts<'a> {
    pub id: String,
    pub ip: &'a str,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub query_len: usize,
    pub body_len: u64,
    pub status: u16,
    pub action: Action,
    pub mode: &'static str,
    pub upstream_ms: Option<u64>,
}

/// Why a line could not be built or written.
#[derive(Debug)]
pub enum AuditError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Time(time::error::Format),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Io(e) => write!(out, "audit log: {e}"),
            AuditError::Json(e) => write!(out, "audit line: {e}"),
            AuditError::Time(e) => write!(out, "audit time: {e}"),
        }
    }
}

impl std::error::Error for AuditError {}

/// Build the record for a judged request.
pub fn record(
    facts: Facts<'_>,
    verdict: &Verdict,
    extra_flags: &[&'static str],
) -> Result<Record, AuditError> {
    let mut flags = verdict.flags.clone();
    for flag in extra_flags {
        if !flags.contains(flag) {
            flags.push(flag);
        }
    }
    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(AuditError::Time)?;
    Ok(Record {
        ts,
        id: facts.id,
        ip: facts.ip.to_owned(),
        host: clip(facts.host, HOST_BYTES),
        method: clip(facts.method, 16),
        path: clip(facts.path, PATH_BYTES),
        query_len: facts.query_len,
        body_len: facts.body_len,
        status: facts.status,
        action: facts.action.as_str(),
        score: verdict.score,
        rules: rule_labels(&verdict.hits),
        mode: facts.mode,
        upstream_ms: facts.upstream_ms,
        flags,
    })
}

/// The open `waf.jsonl`.
pub struct AuditLog {
    file: Mutex<File>,
}

impl AuditLog {
    /// Open (or create) `<dir>/waf.jsonl` for appending.
    pub fn open(dir: &Path) -> Result<AuditLog, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("waf.jsonl"))
            .map_err(AuditError::Io)?;
        Ok(AuditLog {
            file: Mutex::new(file),
        })
    }

    /// Append one record as one line, in one `write_all`.
    pub fn write(&self, record: &Record) -> Result<(), AuditError> {
        let mut line = serde_json::to_string(record).map_err(AuditError::Json)?;
        line.push('\n');
        let mut file = match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        file.write_all(line.as_bytes()).map_err(AuditError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::rules::{Location, Severity};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn scratch(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("waf-audit-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn facts(path: &str) -> Facts<'_> {
        Facts {
            id: request_id(1),
            ip: "203.0.113.5",
            host: "example.test",
            method: "GET",
            path,
            query_len: 12,
            body_len: 0,
            status: 200,
            action: Action::Pass,
            mode: "detect",
            upstream_ms: Some(3),
        }
    }

    fn verdict_with_hit() -> Verdict {
        Verdict {
            score: 5,
            hits: vec![Hit {
                id: 942_100,
                at: Location::Query,
                severity: Severity::Critical,
            }],
            flags: vec!["body_truncated"],
            over_threshold: true,
        }
    }

    #[test]
    fn a_path_is_cut_on_a_character_boundary() {
        let long = "あ".repeat(200);
        let cut = clip(&long, PATH_BYTES);
        assert!(cut.len() <= PATH_BYTES);
        assert!(cut.chars().all(|c| c == 'あ'));
        assert_eq!(clip("", 10), "");
        assert_eq!(clip("abc", 3), "abc");
        assert_eq!(clip("abcd", 3), "abc");
    }

    #[test]
    fn control_characters_cannot_split_a_line() {
        assert_eq!(clip("a\nb\r\tc\u{0}d", 64), "abcd");
    }

    #[test]
    fn request_ids_are_unique() {
        let ids: Vec<String> = (0..1000).map(|_| request_id(7)).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn actions_have_the_names_the_design_gives() {
        let names: Vec<&str> = [
            Action::Pass,
            Action::Detect,
            Action::Block,
            Action::DenyIp,
            Action::RateLimit,
            Action::Ban,
            Action::Protocol,
        ]
        .iter()
        .map(|a| a.as_str())
        .collect();
        assert_eq!(
            names,
            ["pass", "detect", "block", "deny-ip", "ratelimit", "ban", "protocol"]
        );
    }

    #[test]
    fn the_record_names_rules_and_flags_but_no_values() -> TestResult {
        let r = record(facts("/search"), &verdict_with_hit(), &["engine_error"])?;
        assert_eq!(r.rules, vec!["942100:query"]);
        assert_eq!(r.flags, vec!["body_truncated", "engine_error"]);
        let text = serde_json::to_string(&r)?;
        for key in [
            "ts", "id", "ip", "host", "method", "path", "query_len", "body_len", "status",
            "action", "score", "rules", "mode", "upstream_ms", "flags",
        ] {
            assert!(text.contains(&format!("\"{key}\"")), "{key}");
        }
        assert!(!text.contains("\"query\":"));
        Ok(())
    }

    #[test]
    fn a_line_is_written_per_request_and_is_json() -> TestResult {
        let dir = scratch("write")?;
        let log = AuditLog::open(&dir)?;
        for n in 0..3 {
            log.write(&record(
                facts(&format!("/p{n}")),
                &Verdict::default(),
                &[],
            )?)?;
        }
        let text = std::fs::read_to_string(dir.join("waf.jsonl"))?;
        assert_eq!(text.lines().count(), 3);
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line)?;
            assert_eq!(v["action"], "pass");
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn opening_in_a_missing_directory_is_an_error() {
        let missing = std::path::Path::new("/nonexistent-waf-dir-4f9a");
        assert!(matches!(AuditLog::open(missing), Err(AuditError::Io(_))));
    }

    #[test]
    fn a_secret_in_the_query_never_reaches_the_line() -> TestResult {
        let r = record(facts("/login"), &Verdict::default(), &[])?;
        let text = serde_json::to_string(&r)?;
        assert!(!text.contains("SECRETVALUE"));
        Ok(())
    }
}
