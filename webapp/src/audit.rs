//! The console's audit log, `<log-dir>/webapp.jsonl`. `docs/design.md`
//! "段階13 WebApp" 設定の書き方.
//!
//! One line per sign-in, user change and settings save: who, what, when, and
//! for a settings save the digests of the file before and after. It never holds
//! a password, a session token, the content of a setting or an address.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Longest value kept in a field.
pub const FIELD_BYTES: usize = 64;

/// One audit line.
#[derive(Debug, Serialize)]
pub struct Line {
    pub ts: String,
    pub user: String,
    pub action: &'static str,
    pub target: String,
    pub ok: bool,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// The SHA-256 of `bytes`, in lowercase hex.
pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Keep a client-supplied value short and on one line.
pub fn clip(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > FIELD_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// The open `webapp.jsonl`.
pub struct Audit {
    file: Mutex<File>,
}

impl Audit {
    /// Open (or create) `<dir>/webapp.jsonl` for appending.
    pub fn open(dir: &Path) -> Result<Self, String> {
        let path = dir.join("webapp.jsonl");
        let file = OpenOptions::new().create(true).append(true).open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Self { file: Mutex::new(file) })
    }

    /// Append one line. `before` and `after` are digests, never content.
    pub fn record(&self, user: &str, action: &'static str, target: &str, ok: bool, digests: (Option<String>, Option<String>)) -> Result<(), String> {
        let ts = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|e| e.to_string())?;
        let (before, after) = digests;
        let line = Line { ts, user: clip(user), action, target: clip(target), ok, before, after };
        let mut text = serde_json::to_string(&line).map_err(|e| e.to_string())?;
        text.push('\n');
        let mut file = match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        file.write_all(text.as_bytes()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("audit-test").join(format!("{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn the_digest_is_sha256_hex() {
        assert_eq!(digest(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(digest(b"").len(), 64);
    }

    #[test]
    fn a_line_is_one_json_object_with_digests_and_without_content() -> Result<(), Box<dyn std::error::Error>> {
        let d = dir("line")?;
        let audit = Audit::open(&d)?;
        audit.record("alice", "setting_save", "ips-policy", true, (Some(digest(b"old")), Some(digest(b"new"))))?;
        audit.record("bob\nx", "login", "bob", false, (None, None))?;
        let text = std::fs::read_to_string(d.join("webapp.jsonl"))?;
        let rows: Vec<serde_json::Value> = text.lines().map(serde_json::from_str).collect::<Result<_, _>>()?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["before"], digest(b"old"));
        assert!(rows[1]["before"].is_null() && rows[1]["ok"] == false);
        assert_eq!(rows[1]["user"], "bobx");
        Ok(())
    }

    #[test]
    fn a_long_value_is_cut() {
        assert_eq!(clip(&"x".repeat(500)).len(), FIELD_BYTES);
    }
}
