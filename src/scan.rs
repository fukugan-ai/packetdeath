//! Stage 8: which decrypted responses go to clamd, how many body bytes scans
//! may hold at once, and the `av.jsonl` record. `docs/design.md` "段階8 MITM",
//! subsection "scan", is the source of truth.
//!
//! The rule lists what is **not** scanned, so a response that omits its
//! headers is scanned rather than waved through. Nothing here touches HTTP
//! framing or TLS: the inputs are already-parsed header values, so the same
//! rules survive a later move of the HTTP layer.

use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Largest body that is held and scanned (8191 MiB). Exactly this many bytes
/// is scanned; one more is not. Same constant as clamd's `StreamMaxLength`
/// and `MaxFileSize` (8191M); change both or neither.
pub const DEFAULT_MAX_SCAN_BYTES: usize = 8191 * 1024 * 1024;

/// Bytes of body that all scans together may hold at once (8 GiB).
pub const DEFAULT_SCAN_BUDGET_BYTES: usize = 8 * 1024 * 1024 * 1024;

/// What the response looked like, as far as the scan rule cares.
#[derive(Debug, Clone, Copy)]
pub struct ResponseFacts<'a> {
    pub method: &'a str,
    pub status: u16,
    pub content_type: Option<&'a str>,
    pub content_disposition: Option<&'a str>,
    pub content_encoding: Option<&'a str>,
    pub content_length: Option<u64>,
}

/// Why a response was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Not a `GET` `200`, a page part / media / API type, or an empty body.
    NotEligible,
    /// A `Content-Encoding` other than `identity`.
    Encoded,
    /// Larger than the scan limit (declared, or found while holding it).
    TooLarge,
    /// The scan budget had no room for the body.
    SlotFull,
}

impl SkipReason {
    /// The reason word written to the log.
    pub fn as_log_str(self) -> &'static str {
        match self {
            Self::NotEligible => "not_eligible",
            Self::Encoded => "encoded",
            Self::TooLarge => "too_large",
            Self::SlotFull => "slot_full",
        }
    }
}

/// The decision taken from the response head alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eligibility {
    Scan,
    Skip(SkipReason),
}

/// Media types that are page parts, media or API responses. `application/*+json`
/// is matched by suffix in `is_not_scanned_type`.
const NOT_SCANNED_EXACT: [&str; 11] = [
    "text/html",
    "text/css",
    "text/xml",
    "text/event-stream",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
];

/// Top-level types that are never scanned.
const NOT_SCANNED_TOP: [&str; 4] = ["image/", "video/", "audio/", "font/"];

/// The media type of a `Content-Type` value: before any parameter, trimmed,
/// lower case.
fn media_type(content_type: &str) -> String {
    let essence = match content_type.split_once(';') {
        Some((essence, _)) => essence,
        None => content_type,
    };
    essence.trim().to_ascii_lowercase()
}

fn is_not_scanned_type(media: &str) -> bool {
    NOT_SCANNED_EXACT.contains(&media)
        || NOT_SCANNED_TOP.iter().any(|top| media.starts_with(top))
        || (media.starts_with("application/") && media.ends_with("+json"))
}

/// `Content-Disposition: attachment` (with or without parameters).
fn is_attachment(disposition: &str) -> bool {
    let kind = match disposition.split_once(';') {
        Some((kind, _)) => kind,
        None => disposition,
    };
    kind.trim().eq_ignore_ascii_case("attachment")
}

/// Applies the scan rule to a response head. A missing `Content-Length` is
/// scanned here; the caller gives up if the body outgrows `max_bytes`.
pub fn eligibility(facts: &ResponseFacts<'_>, max_bytes: usize) -> Eligibility {
    if facts.method != "GET" || facts.status != 200 {
        return Eligibility::Skip(SkipReason::NotEligible);
    }
    let attachment = facts.content_disposition.is_some_and(is_attachment);
    let excluded = facts
        .content_type
        .is_some_and(|ct| is_not_scanned_type(&media_type(ct)));
    if excluded && !attachment {
        return Eligibility::Skip(SkipReason::NotEligible);
    }
    if let Some(encoding) = facts.content_encoding {
        if !encoding.trim().eq_ignore_ascii_case("identity") {
            return Eligibility::Skip(SkipReason::Encoded);
        }
    }
    match facts.content_length {
        Some(0) => Eligibility::Skip(SkipReason::NotEligible),
        Some(len) if len > max_bytes as u64 => Eligibility::Skip(SkipReason::TooLarge),
        _ => Eligibility::Scan,
    }
}

/// A budget of body bytes shared by every connection thread.
pub struct ScanBudget {
    held: AtomicUsize,
    max: usize,
}

/// Bytes taken from the budget. Dropping it gives them back.
pub struct ScanLease<'a> {
    held: &'a AtomicUsize,
    bytes: usize,
}

impl Drop for ScanLease<'_> {
    fn drop(&mut self) {
        self.held.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl ScanBudget {
    pub fn new(max: usize) -> Self {
        Self {
            held: AtomicUsize::new(0),
            max,
        }
    }

    /// Takes `bytes`, or `None` when they do not fit (the caller passes the
    /// body through unscanned).
    pub fn try_acquire(&self, bytes: usize) -> Option<ScanLease<'_>> {
        let before = self.held.fetch_add(bytes, Ordering::AcqRel);
        if before.saturating_add(bytes) > self.max {
            self.held.fetch_sub(bytes, Ordering::AcqRel);
            return None;
        }
        Some(ScanLease {
            held: &self.held,
            bytes,
        })
    }
}

/// The SHA-256 of `body`, lower-case hex.
pub fn sha256_hex(body: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, body);
    hex(digest.as_ref())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// What clamd said, in `av.jsonl` terms. Errors are never written: the
/// stage 6 reader counts anything but `malicious` as clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvVerdict<'a> {
    Malicious { signature: &'a str },
    Clean,
}

/// One `av.jsonl` line, in the stage 6 shape with no extra field.
#[derive(Debug, Serialize)]
struct AvRecord<'a> {
    ts: String,
    proto: &'static str,
    dst_ip: IpAddr,
    dst_port: u16,
    sha256: &'a str,
    verdict: &'static str,
    engine: String,
}

/// Builds one `av.jsonl` line (without the trailing newline).
pub fn av_line(
    dst_ip: IpAddr,
    dst_port: u16,
    sha256: &str,
    verdict: AvVerdict<'_>,
) -> Result<String, AvLogError> {
    let (verdict, engine) = match verdict {
        AvVerdict::Malicious { signature } => ("malicious", format!("clamav:{signature}")),
        AvVerdict::Clean => ("clean", String::from("clamav")),
    };
    let record = AvRecord {
        ts: OffsetDateTime::now_utc().format(&Rfc3339)?,
        proto: "tcp",
        dst_ip,
        dst_port,
        sha256,
        verdict,
        engine,
    };
    Ok(serde_json::to_string(&record)?)
}

#[derive(Debug)]
pub enum AvLogError {
    Timestamp(time::error::Format),
    Json(serde_json::Error),
    Io(io::Error),
    Lock,
}

impl std::fmt::Display for AvLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locale = crate::i18n::locale();
        let s = match self {
            Self::Timestamp(e) => crate::i18n::timestamp_format_failed(locale, e),
            Self::Json(e) => crate::i18n::flow_log_json_encode_failed(locale, e),
            Self::Io(e) => crate::i18n::flow_log_write_failed(locale, e),
            Self::Lock => crate::i18n::flow_log_lock_poisoned(locale),
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for AvLogError {}

impl From<time::error::Format> for AvLogError {
    fn from(e: time::error::Format) -> Self {
        Self::Timestamp(e)
    }
}

impl From<serde_json::Error> for AvLogError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<io::Error> for AvLogError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// `<log dir>/av.jsonl`, opened for append only while stage 8 is enabled.
pub struct AvLog {
    file: Mutex<File>,
}

impl AvLog {
    pub fn open(path: &Path) -> Result<Self, io::Error> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Appends one verdict. One `write_all` per line keeps lines whole.
    pub fn write(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        sha256: &str,
        verdict: AvVerdict<'_>,
    ) -> Result<(), AvLogError> {
        let mut line = av_line(dst_ip, dst_port, sha256, verdict)?;
        line.push('\n');
        let mut file = self.file.lock().map_err(|_| AvLogError::Lock)?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::av::AvList;
    use std::net::Ipv4Addr;

    fn get_200<'a>(content_type: Option<&'a str>) -> ResponseFacts<'a> {
        ResponseFacts {
            method: "GET",
            status: 200,
            content_type,
            content_disposition: None,
            content_encoding: None,
            content_length: Some(10),
        }
    }

    fn decide(facts: &ResponseFacts<'_>) -> Eligibility {
        eligibility(facts, DEFAULT_MAX_SCAN_BYTES)
    }

    const SKIP: Eligibility = Eligibility::Skip(SkipReason::NotEligible);

    #[test]
    fn exactly_the_limit_is_scanned() {
        let facts = ResponseFacts {
            content_length: Some(8_588_886_016),
            ..get_200(None)
        };
        assert_eq!(decide(&facts), Eligibility::Scan);
    }

    #[test]
    fn one_byte_over_the_limit_is_not_scanned() {
        let facts = ResponseFacts {
            content_length: Some(8_588_886_017),
            ..get_200(None)
        };
        assert_eq!(decide(&facts), Eligibility::Skip(SkipReason::TooLarge));
    }

    #[test]
    fn an_empty_body_is_not_scanned() {
        let facts = ResponseFacts {
            content_length: Some(0),
            ..get_200(None)
        };
        assert_eq!(decide(&facts), SKIP);
    }

    #[test]
    fn a_missing_length_is_scanned_until_it_outgrows_the_limit() {
        let facts = ResponseFacts {
            content_length: None,
            ..get_200(Some("application/zip"))
        };
        assert_eq!(decide(&facts), Eligibility::Scan);
    }

    #[test]
    fn downloads_are_scanned() {
        assert_eq!(decide(&get_200(Some("application/zip"))), Eligibility::Scan);
        assert_eq!(
            decide(&get_200(Some("application/octet-stream"))),
            Eligibility::Scan
        );
    }

    #[test]
    fn api_and_script_types_are_not_scanned() {
        for ct in [
            "application/json",
            "application/javascript",
            "application/vnd.api+json",
            "text/xml",
            "text/event-stream",
        ] {
            assert_eq!(decide(&get_200(Some(ct))), SKIP, "{ct}");
        }
    }

    #[test]
    fn page_parts_and_media_are_not_scanned() {
        for ct in [
            "text/html",
            "image/png",
            "font/woff2",
            "video/mp4",
            "audio/ogg",
        ] {
            assert_eq!(decide(&get_200(Some(ct))), SKIP, "{ct}");
        }
    }

    #[test]
    fn an_attachment_is_scanned_whatever_its_type() {
        let facts = ResponseFacts {
            content_disposition: Some("attachment; filename=\"a.png\""),
            ..get_200(Some("image/png"))
        };
        assert_eq!(decide(&facts), Eligibility::Scan);
        let inline = ResponseFacts {
            content_disposition: Some("inline"),
            ..get_200(Some("image/png"))
        };
        assert_eq!(decide(&inline), SKIP);
    }

    #[test]
    fn plain_text_and_no_type_are_scanned() {
        assert_eq!(decide(&get_200(Some("text/plain"))), Eligibility::Scan);
        assert_eq!(decide(&get_200(None)), Eligibility::Scan);
    }

    #[test]
    fn media_type_reads_case_and_parameters() {
        assert_eq!(
            decide(&get_200(Some("Application/ZIP; x=y"))),
            Eligibility::Scan
        );
        assert_eq!(decide(&get_200(Some(" Text/HTML ; charset=UTF-8"))), SKIP);
        assert_eq!(media_type("Application/ZIP; x=y"), "application/zip");
    }

    #[test]
    fn only_get_200_is_scanned() {
        for (method, status) in [("GET", 206), ("GET", 304), ("HEAD", 200), ("POST", 200)] {
            let facts = ResponseFacts {
                method,
                status,
                ..get_200(None)
            };
            assert_eq!(decide(&facts), SKIP, "{method} {status}");
        }
    }

    #[test]
    fn identity_or_no_encoding_is_scanned() {
        for encoding in [None, Some("identity"), Some(" Identity ")] {
            let facts = ResponseFacts {
                content_encoding: encoding,
                ..get_200(None)
            };
            assert_eq!(decide(&facts), Eligibility::Scan, "{encoding:?}");
        }
    }

    #[test]
    fn compressed_bodies_are_not_scanned() {
        for encoding in ["gzip", "br"] {
            let facts = ResponseFacts {
                content_encoding: Some(encoding),
                ..get_200(None)
            };
            assert_eq!(
                decide(&facts),
                Eligibility::Skip(SkipReason::Encoded),
                "{encoding}"
            );
        }
    }

    #[test]
    fn skip_reason_words_are_stable() {
        assert_eq!(SkipReason::NotEligible.as_log_str(), "not_eligible");
        assert_eq!(SkipReason::Encoded.as_log_str(), "encoded");
        assert_eq!(SkipReason::TooLarge.as_log_str(), "too_large");
        assert_eq!(SkipReason::SlotFull.as_log_str(), "slot_full");
    }

    #[test]
    fn budget_runs_out_and_comes_back() {
        let budget = ScanBudget::new(10);
        let first = budget.try_acquire(6);
        assert!(first.is_some());
        assert!(budget.try_acquire(5).is_none());
        let second = budget.try_acquire(4);
        assert!(second.is_some());
        drop(first);
        assert!(budget.try_acquire(6).is_some());
    }

    #[test]
    fn zero_budget_never_scans() {
        assert!(ScanBudget::new(0).try_acquire(1).is_none());
    }

    #[test]
    fn sha256_of_empty_is_the_known_value() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    fn sample_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }

    #[test]
    fn av_line_has_exactly_the_stage_6_fields() -> Result<(), Box<dyn std::error::Error>> {
        let sha = sha256_hex(b"x");
        let line = av_line(sample_ip(), 443, &sha, AvVerdict::Clean)?;
        let value: serde_json::Value = serde_json::from_str(&line)?;
        let object = value.as_object().ok_or("not an object")?;
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["dst_ip", "dst_port", "engine", "proto", "sha256", "ts", "verdict"]
        );
        assert_eq!(object.get("proto"), Some(&serde_json::json!("tcp")));
        assert_eq!(object.get("dst_port"), Some(&serde_json::json!(443)));
        assert_eq!(object.get("engine"), Some(&serde_json::json!("clamav")));
        assert_eq!(object.get("sha256"), Some(&serde_json::json!(sha)));
        assert!(!line.contains('\n'));
        Ok(())
    }

    #[test]
    fn av_lines_round_trip_through_the_stage_6_reader() -> Result<(), Box<dyn std::error::Error>> {
        let bad = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let malicious = av_line(
            bad,
            443,
            &sha256_hex(b"m"),
            AvVerdict::Malicious {
                signature: "Eicar-Test-Signature",
            },
        )?;
        let clean = av_line(sample_ip(), 443, &sha256_hex(b"c"), AvVerdict::Clean)?;
        let malicious_value: serde_json::Value = serde_json::from_str(&malicious)?;
        assert_eq!(
            malicious_value.get("engine"),
            Some(&serde_json::json!("clamav:Eicar-Test-Signature"))
        );
        let list = AvList::parse(&format!("{malicious}\n{clean}\n"));
        assert!(list.contains(&bad, 443));
        assert_eq!(
            list.engine_of(&bad, 443),
            Some("clamav:Eicar-Test-Signature")
        );
        // The clean line is read and does not land in the drop set.
        assert!(!list.contains(&sample_ip(), 443));
        Ok(())
    }
}
