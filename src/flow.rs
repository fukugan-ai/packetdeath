//! `<log dir>/flows.jsonl` への1 flow 1行 の JSON Lines ログ。
//! field は `ts`, `proto`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `sni`, `sni_state`,
//! `decision`, `reason` の10個（`docs/design.md`「名前と置き場」が正本）。
//!
//! **log に通信の中身を書かない。**SNI と宛先までにする。
//! 段階1は観測だけなので `decision` は常に `"observe"`、`reason` は常に `null`。

use crate::sni::SniState;
use serde::Serialize;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// 段階1は観測のみなので、遮断の実装が無いことを型でも表す。
pub const DECISION_OBSERVE: &str = "observe";
/// 段階2以降：判定できたが blocklist に当たらず通した flow。
pub const DECISION_PASS: &str = "pass";
/// 段階2以降：判定材料が blocklist（または CNAME チェーン）に当たり落とした flow。
pub const DECISION_BLOCK: &str = "block";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_log_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// TCP/UDP flow を一意に定める 5-tuple。ログにも全項目を出す。送信元も含めた全項目が
/// 「1 flow 1回」の重複排除にも要る。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: Proto,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowLogEntry {
    pub ts: String,
    pub proto: &'static str,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub sni: Option<String>,
    pub sni_state: &'static str,
    pub decision: &'static str,
    pub reason: Option<&'static str>,
}

impl FlowLogEntry {
    /// `key` と `sni_state` から、現在時刻を `ts` に埋めた 1 flow 分の log entry を作る。
    /// 段階1は観測のみなので `decision` は常に `observe`、`reason` は常に `null`。
    pub fn new(key: FlowKey, sni_state: &SniState) -> Result<Self, time::error::Format> {
        Self::with_verdict(key, sni_state, DECISION_OBSERVE, None)
    }

    /// 段階2以降：判定結果（`decision` / `reason`）を明示して log entry を作る。
    /// `decision` は `pass` か `block`、`reason` は `block` のときだけ `Some`。
    pub fn with_verdict(
        key: FlowKey,
        sni_state: &SniState,
        decision: &'static str,
        reason: Option<&'static str>,
    ) -> Result<Self, time::error::Format> {
        Ok(Self {
            ts: OffsetDateTime::now_utc().format(&Rfc3339)?,
            proto: key.proto.as_log_str(),
            src_ip: key.src_ip,
            src_port: key.src_port,
            dst_ip: key.dst_ip,
            dst_port: key.dst_port,
            sni: sni_state.sni().map(str::to_string),
            sni_state: sni_state.as_log_str(),
            decision,
            reason,
        })
    }
}

#[derive(Debug)]
pub enum LogError {
    Timestamp(time::error::Format),
    Json(serde_json::Error),
    Io(std::io::Error),
    /// 書き込みを直列化する mutex が poison していた。
    Lock,
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Timestamp(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Lock => None,
        }
    }
}

impl From<time::error::Format> for LogError {
    fn from(e: time::error::Format) -> Self {
        Self::Timestamp(e)
    }
}

impl From<serde_json::Error> for LogError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<std::io::Error> for LogError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// `<log dir>/flows.jsonl` への追記と、開発中の stdout 複製を担う。
pub struct FlowLogSink {
    file: Mutex<File>,
}

impl FlowLogSink {
    /// `path` は `<log dir>/flows.jsonl` の絶対 path。親 directory は
    /// 呼び出し側（`main.rs`）が用意する。
    pub fn open(path: &Path) -> Result<Self, LogError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Write one flow as one JSON line to the file and echo the same line to stdout.
    pub fn write(&self, entry: &FlowLogEntry) -> Result<(), LogError> {
        let line = serde_json::to_string(entry)?;
        println!("{line}");

        let mut file = self.file.lock().map_err(|_| LogError::Lock)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

/// Appends timestamped `[info]` / `[warn]` / `[error]` lines to `<log dir>/service.log`.
pub struct ServiceLog {
    file: Mutex<File>,
    offset: Option<UtcOffset>,
}

impl ServiceLog {
    /// `path` is `<log dir>/service.log`; the directory is not created.
    /// `offset` is applied to every timestamp as given (`None` writes UTC).
    pub fn open(path: &Path, offset: Option<UtcOffset>) -> Result<Self, LogError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            offset,
        })
    }

    /// Write `<RFC 3339 timestamp> <line>\n` with a single `write_all`, so lines
    /// from other writers never interleave with it. A poisoned lock is recovered.
    pub fn write_line(&self, line: &str) -> Result<(), LogError> {
        let now = OffsetDateTime::now_utc();
        let now = match self.offset {
            Some(offset) => now.to_offset(offset),
            None => now,
        };
        let text = format!("{} {line}\n", now.format(&Rfc3339)?);
        let mut file = match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        file.write_all(text.as_bytes())?;
        Ok(())
    }
}

static SERVICE_LOG: OnceLock<ServiceLog> = OnceLock::new();

const SERVICE_LOG_DEBUG_PREFIX: &str = "packetdeath: [debug]";

/// Send every later `service_log` line to `log`. Only the first call takes effect;
/// returns whether this call was the one.
pub fn redirect_service_log(log: ServiceLog) -> bool {
    SERVICE_LOG.set(log).is_ok()
}

/// Falls back to stderr until `redirect_service_log` is called, and for a line the
/// file refused. Debug lines are dropped once redirected: they scale with
/// packets x snapshot re-reads, not with flows.
pub fn service_log(line: &str) {
    match SERVICE_LOG.get() {
        Some(_) if line.starts_with(SERVICE_LOG_DEBUG_PREFIX) => {}
        Some(log) => {
            if log.write_line(line).is_err() {
                eprintln!("{line}");
            }
        }
        None => eprintln!("{line}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A fresh path under `tests/tmp-unit-<pid>/`. The directory is shared by
    /// parallel tests, so only the file itself is removed.
    fn service_log_scratch(name: &str) -> Result<std::path::PathBuf, String> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(format!("tmp-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
        Ok(path)
    }

    fn sample_key() -> FlowKey {
        FlowKey {
            proto: Proto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            src_port: 51234,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
        }
    }

    #[test]
    fn entry_carries_decision_observe_and_null_reason_in_stage1() -> Result<(), String> {
        let sni_state = SniState::Ok("example.com".to_string());
        let entry = FlowLogEntry::new(sample_key(), &sni_state).map_err(|e| e.to_string())?;
        assert_eq!(entry.decision, DECISION_OBSERVE);
        assert_eq!(entry.reason, None);
        Ok(())
    }

    #[test]
    fn entry_serializes_as_single_line_json() -> Result<(), String> {
        // テスト項目7。1 flow 1行の JSON Lines になっている。
        let sni_state = SniState::None;
        let entry = FlowLogEntry::new(sample_key(), &sni_state)
            .map_err(|e: time::error::Format| e.to_string())?;
        let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
        assert!(!line.contains('\n'));
        assert!(line.contains("\"decision\":\"observe\""));
        assert!(line.contains("\"sni\":null"));
        assert!(line.contains("\"sni_state\":\"none\""));
        assert!(line.contains("\"reason\":null"));
        assert!(line.contains("\"proto\":\"tcp\""));
        Ok(())
    }

    #[test]
    /// `docs/design.md`「名前と置き場」の flow log 節が宣言する10 field
    /// （`src_ip` / `src_port` を含む）を `FlowLogEntry` が持つ。
    ///
    /// この test は key の**集合**を検査する。`entry_serializes_as_single_line_json`
    /// のような `line.contains(...)` は部分文字列一致でしかなく、key が1つ
    /// 増えても減っても落ちない。この test は `serde_json::Value` として
    /// 読み直し、key の集合が10 field と過不足なく一致することを
    /// assert するので、field の増減を検出できる。値は
    /// `entry_carries_the_source_of_the_key` が見る。
    fn entry_json_keys_match_current_ten_field_contract() -> Result<(), String> {
        let sni_state = SniState::Ok("example.com".to_string());
        let entry = FlowLogEntry::new(sample_key(), &sni_state).map_err(|e| e.to_string())?;
        let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
        let value: serde_json::Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        let object = value
            .as_object()
            .ok_or_else(|| "flow log の1行は JSON object のはず".to_string())?;

        let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected = vec![
            "ts",
            "proto",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "sni",
            "sni_state",
            "decision",
            "reason",
        ];
        expected.sort_unstable();
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn entry_carries_the_source_of_the_key() -> Result<(), String> {
        // Values, not just key names: `src_ip: key.dst_ip` would pass a key-set check.
        let sni_state = SniState::Ok("example.com".to_string());
        let entry = FlowLogEntry::new(sample_key(), &sni_state).map_err(|e| e.to_string())?;
        let line = serde_json::to_string(&entry).map_err(|e| e.to_string())?;
        let value: serde_json::Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        assert_eq!(value["src_ip"], "192.0.2.10");
        assert_eq!(value["src_port"], 51234);
        assert_eq!(value["dst_ip"], "93.184.216.34");
        Ok(())
    }

    #[test]
    fn with_verdict_carries_block_decision_and_reason() -> Result<(), String> {
        let sni_state = SniState::Ok("ads.example".to_string());
        let entry =
            FlowLogEntry::with_verdict(sample_key(), &sni_state, DECISION_BLOCK, Some("sni"))
                .map_err(|e| e.to_string())?;
        assert_eq!(entry.decision, DECISION_BLOCK);
        assert_eq!(entry.reason, Some("sni"));
        Ok(())
    }

    #[test]
    fn with_verdict_carries_pass_decision_and_null_reason() -> Result<(), String> {
        let sni_state = SniState::Ok("example.com".to_string());
        let entry = FlowLogEntry::with_verdict(sample_key(), &sni_state, DECISION_PASS, None)
            .map_err(|e| e.to_string())?;
        assert_eq!(entry.decision, DECISION_PASS);
        assert_eq!(entry.reason, None);
        Ok(())
    }

    #[test]
    fn fragmented_state_serializes_null_sni() -> Result<(), String> {
        let sni_state = SniState::Fragmented;
        let entry = FlowLogEntry::new(sample_key(), &sni_state).map_err(|e| e.to_string())?;
        assert_eq!(entry.sni, None);
        assert_eq!(entry.sni_state, "fragmented");
        Ok(())
    }

    #[test]
    fn write_appends_one_line_per_call() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("packetdeath-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("flows.jsonl");
        let sink = FlowLogSink::open(&path).map_err(|e| e.to_string())?;

        let sni_state = SniState::Ok("example.com".to_string());
        let entry = FlowLogEntry::new(sample_key(), &sni_state).map_err(|e| e.to_string())?;
        sink.write(&entry).map_err(|e| e.to_string())?;
        sink.write(&entry).map_err(|e| e.to_string())?;

        let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let line_count = content.lines().count();
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
        assert_eq!(line_count, 2);
        Ok(())
    }

    #[test]
    fn service_log_writes_one_timestamped_line_per_call() -> Result<(), String> {
        let path = service_log_scratch("service-log-two-lines.log")?;
        let log = ServiceLog::open(&path, None).map_err(|e| e.to_string())?;
        let sent = ["packetdeath: [info] one", "packetdeath: [warn] two"];
        for line in sent {
            log.write_line(line).map_err(|e| e.to_string())?;
        }

        let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        assert_eq!(content.lines().count(), 2);
        assert!(content.ends_with('\n'));
        for (written, expected) in content.lines().zip(sent) {
            let (ts, body) = written
                .split_once(' ')
                .ok_or_else(|| format!("no space in {written:?}"))?;
            assert!(ts.len() >= 20 && ts.ends_with('Z'), "{ts}");
            assert_eq!(ts.as_bytes().get(4), Some(&b'-'), "{ts}");
            assert_eq!(ts.as_bytes().get(10), Some(&b'T'), "{ts}");
            assert_eq!(body, expected);
        }
        Ok(())
    }

    #[test]
    fn service_log_writes_the_given_offset() -> Result<(), String> {
        let path = service_log_scratch("service-log-offset.log")?;
        let plus_nine = UtcOffset::from_hms(9, 0, 0).map_err(|e| e.to_string())?;
        let log = ServiceLog::open(&path, Some(plus_nine)).map_err(|e| e.to_string())?;
        log.write_line("packetdeath: [info] offset")
            .map_err(|e| e.to_string())?;

        let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let (ts, _) = content
            .split_once(' ')
            .ok_or_else(|| format!("no space in {content:?}"))?;
        assert!(ts.ends_with("+09:00"), "{ts}");
        assert!(!ts.contains('Z'), "{ts}");
        Ok(())
    }

    #[test]
    fn service_log_reopen_appends_instead_of_truncating() -> Result<(), String> {
        let path = service_log_scratch("service-log-reopen.log")?;
        let first = ServiceLog::open(&path, None).map_err(|e| e.to_string())?;
        first
            .write_line("packetdeath: [info] first")
            .map_err(|e| e.to_string())?;
        drop(first);
        let second = ServiceLog::open(&path, None).map_err(|e| e.to_string())?;
        second
            .write_line("packetdeath: [info] second")
            .map_err(|e| e.to_string())?;

        let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        assert_eq!(content.lines().count(), 2);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn write_line_on_a_full_device_returns_err() -> Result<(), String> {
        let log = ServiceLog::open(Path::new("/dev/full"), None).map_err(|e| e.to_string())?;
        assert!(log.write_line("packetdeath: [warn] full").is_err());
        Ok(())
    }

    #[test]
    fn write_line_survives_a_poisoned_lock() -> Result<(), String> {
        let path = service_log_scratch("service-log-poison.log")?;
        let log = std::sync::Arc::new(ServiceLog::open(&path, None).map_err(|e| e.to_string())?);

        let holder = std::sync::Arc::clone(&log);
        let handle = std::thread::spawn(move || {
            let _guard = holder.file.lock();
            panic!("poison the lock on purpose");
        });
        assert!(handle.join().is_err());
        assert!(log.file.is_poisoned());

        log.write_line("packetdeath: [info] after poison")
            .map_err(|e| e.to_string())?;
        let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        assert_eq!(content.lines().count(), 1);
        Ok(())
    }
}
