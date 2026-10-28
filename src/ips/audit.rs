//! Stage 12: the IPS audit log, `<log-dir>/ips.jsonl`, one line per event.
//!
//! `docs/design.md` "段階12 IDS/IPS の業務水準化". The line carries the
//! endpoints of the flow (the tool's own business data) and the signature id,
//! never the signature text or anything from the traffic. A value that does not
//! apply is `null`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Longest `classtype` written.
pub const CLASSTYPE_BYTES: usize = 64;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Drop,
    Observed,
    Ignored,
    Protected,
    Escalated,
    Expired,
    Evicted,
    Restored,
    Stale,
    Recovered,
    /// Lines skipped by the reader (too long, not UTF-8).
    Skipped,
}

impl Event {
    pub fn as_str(self) -> &'static str {
        match self {
            Event::Drop => "drop",
            Event::Observed => "observed",
            Event::Ignored => "ignored",
            Event::Protected => "protected",
            Event::Escalated => "escalated",
            Event::Expired => "expired",
            Event::Evicted => "evicted",
            Event::Restored => "restored",
            Event::Stale => "stale",
            Event::Recovered => "recovered",
            Event::Skipped => "skipped",
        }
    }
}

/// One audit line.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub ts: String,
    pub event: &'static str,
    pub sid: Option<u64>,
    pub severity: Option<u8>,
    pub classtype: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub src_ip: Option<String>,
    pub ttl: Option<u64>,
    /// Line of the policy rule that decided.
    pub rule: Option<usize>,
    /// A count that belongs to the event (restored, evicted, skipped).
    pub count: Option<u64>,
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
            AuditError::Io(e) => write!(out, "ips audit log: {e}"),
            AuditError::Json(e) => write!(out, "ips audit line: {e}"),
            AuditError::Time(e) => write!(out, "ips audit time: {e}"),
        }
    }
}

impl std::error::Error for AuditError {}

fn clip(text: &str, max: usize) -> String {
    let mut out = String::new();
    for c in text.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out
}

impl Record {
    /// A line for `event` with every other field `null`.
    pub fn new(event: Event) -> Result<Self, AuditError> {
        let ts = OffsetDateTime::now_utc().format(&Rfc3339).map_err(AuditError::Time)?;
        Ok(Self {
            ts,
            event: event.as_str(),
            sid: None,
            severity: None,
            classtype: None,
            dst_ip: None,
            dst_port: None,
            src_ip: None,
            ttl: None,
            rule: None,
            count: None,
        })
    }

    pub fn alert(mut self, sid: u64, severity: Option<u8>, classtype: Option<&str>) -> Self {
        self.sid = Some(sid);
        self.severity = severity;
        self.classtype = classtype.map(|c| clip(c, CLASSTYPE_BYTES));
        self
    }

    pub fn flow(mut self, src: Option<IpAddr>, dst: IpAddr, port: u16) -> Self {
        self.src_ip = src.map(|ip| ip.to_string());
        self.dst_ip = Some(dst.to_string());
        self.dst_port = Some(port);
        self
    }

    pub fn deciding(mut self, rule: Option<usize>, ttl: Option<u64>) -> Self {
        self.rule = rule;
        self.ttl = ttl;
        self
    }

    pub fn counted(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }
}

/// The open `ips.jsonl`.
pub struct IpsLog {
    file: Mutex<File>,
}

impl IpsLog {
    /// Open (or create) `<dir>/ips.jsonl` for appending.
    pub fn open(dir: &Path) -> Result<Self, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("ips.jsonl"))
            .map_err(AuditError::Io)?;
        Ok(Self { file: Mutex::new(file) })
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
    use std::net::Ipv4Addr;

    fn dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("ips-test")
            .join(format!("audit-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn a_line_has_every_field_and_nulls_for_what_does_not_apply() -> Result<(), Box<dyn std::error::Error>> {
        let d = dir("shape")?;
        let log = IpsLog::open(&d)?;
        log.write(&Record::new(Event::Stale)?)?;
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let r = Record::new(Event::Drop)?.alert(9000001, Some(1), Some("trojan")).flow(None, dst, 443).deciding(Some(3), Some(60));
        log.write(&r)?;
        let text = std::fs::read_to_string(d.join("ips.jsonl"))?;
        let rows: Vec<serde_json::Value> = text.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].as_object().map(|o| o.len()), Some(11));
        assert!(rows[0]["sid"].is_null() && rows[0]["event"] == "stale");
        assert_eq!((rows[1]["dst_ip"].as_str(), rows[1]["rule"].as_u64()), (Some("203.0.113.9"), Some(3)));
        Ok(())
    }

    #[test]
    fn nothing_from_the_signature_text_can_reach_the_line() -> Result<(), Box<dyn std::error::Error>> {
        let d = dir("secret")?;
        let log = IpsLog::open(&d)?;
        let dst = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let r = Record::new(Event::Observed)?.alert(1, None, Some("ok")).flow(None, dst, 80);
        log.write(&r)?;
        let text = std::fs::read_to_string(d.join("ips.jsonl"))?;
        assert!(!text.contains("SECRETSIGNATURE") && text.matches('\n').count() == 1);
        Ok(())
    }

    #[test]
    fn a_long_classtype_is_cut_and_control_characters_are_dropped() -> Result<(), Box<dyn std::error::Error>> {
        let r = Record::new(Event::Drop)?.alert(1, None, Some(&format!("a\nb{}", "x".repeat(200))));
        let Some(c) = r.classtype else {
            return Err("the classtype was lost".into());
        };
        assert!(c.len() <= CLASSTYPE_BYTES && !c.contains('\n') && c.starts_with("ab"));
        Ok(())
    }
}
