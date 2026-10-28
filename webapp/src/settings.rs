//! The settings the console edits. `docs/design.md` "段階13 WebApp" 設定の書き方.
//!
//! Every setting is a file that the packet tool already reads. A save checks the
//! whole text with the parser the tool reads it with, keeps the file it
//! replaces, writes the new text next to the file and renames it over, so the
//! tool sees the old file or the new one and never half of either.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use packetdeath::iplist;
use packetdeath::ips::policy;
use packetdeath::waf::{config, rules};

use crate::audit::digest;

/// A setting larger than this is refused.
pub const MAX_BYTES: usize = 1 << 20;
/// Older versions kept per setting.
pub const KEEP: usize = 20;

/// The lines a text has that its parser cannot read: line number and reason.
type Problems = Vec<(usize, String)>;

/// One editable file.
pub struct Kind {
    pub id: &'static str,
    /// The part of the tool it belongs to: `ips`, `ids`, `waf` or `av`.
    pub part: &'static str,
    pub file: &'static str,
    /// Whether the running tool rereads it by itself.
    pub hot: bool,
    check: fn(&str) -> Problems,
}

fn ip_lines(text: &str) -> Problems {
    iplist::check(text).into_iter().map(|n| (n, String::from("not an address or CIDR"))).collect()
}

fn policy_lines(text: &str) -> Problems {
    let mut bad = policy::check(text);
    if bad.is_empty() && policy::Policy::parse(text).0.is_empty() {
        bad.push((0, String::from("the policy has no rule")));
    }
    bad
}

fn sid_lines(text: &str) -> Problems {
    let numbered = text.lines().enumerate();
    let mut bad = Vec::new();
    for (index, line) in numbered.map(|(i, l)| (i + 1, l.trim())) {
        if !line.is_empty() && !line.starts_with('#') && line.parse::<u64>().is_err() {
            bad.push((index, String::from("not a signature id")));
        }
    }
    bad
}

fn host_lines(text: &str) -> Problems {
    let mut bad = Vec::new();
    for (index, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l.trim())) {
        let ok = line.len() <= 253 && line.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*'));
        if !line.is_empty() && !line.starts_with('#') && !ok {
            bad.push((index, String::from("not a host name")));
        }
    }
    bad
}

fn rule_lines(text: &str) -> Problems {
    rules::load_jsonl(text).bad.into_iter().map(|(n, why)| (n, why.to_string())).collect()
}

fn exclusion_lines(text: &str) -> Problems {
    config::load_exclusions(text).bad.into_iter().map(|(n, why)| (n, why.to_string())).collect()
}

/// Every setting the console edits.
pub static KINDS: [Kind; 12] = [
    Kind { id: "ips-policy", part: "ips", file: "ips-policy.jsonl", hot: true, check: policy_lines },
    Kind { id: "ips-never", part: "ips", file: "ips-never.txt", hot: true, check: ip_lines },
    Kind { id: "ids-sids", part: "ids", file: "ids-sids.txt", hot: false, check: sid_lines },
    Kind { id: "waf-rules", part: "waf", file: "waf-rules.jsonl", hot: true, check: rule_lines },
    Kind { id: "waf-exclusions", part: "waf", file: "waf-exclusions.jsonl", hot: true, check: exclusion_lines },
    Kind { id: "waf-allow-ip", part: "waf", file: "waf-allow-ip.txt", hot: true, check: ip_lines },
    Kind { id: "waf-deny-ip", part: "waf", file: "waf-deny-ip.txt", hot: true, check: ip_lines },
    Kind { id: "waf-trusted", part: "waf", file: "waf-trusted.txt", hot: true, check: ip_lines },
    Kind { id: "blocklist", part: "ids", file: "blocklist.txt", hot: true, check: host_lines },
    Kind { id: "allowlist", part: "ids", file: "allowlist.txt", hot: true, check: host_lines },
    Kind { id: "iplist", part: "ids", file: "iplist.txt", hot: true, check: ip_lines },
    Kind { id: "mitm-list", part: "av", file: "mitm-list.txt", hot: false, check: host_lines },
];

/// Why a read or a save failed.
#[derive(Debug, PartialEq, Eq)]
pub enum SettingError {
    Unknown,
    TooLarge,
    Invalid(Problems),
    Io(String),
}

impl std::fmt::Display for SettingError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettingError::Unknown => write!(out, "no such setting"),
            SettingError::TooLarge => write!(out, "the setting is larger than {MAX_BYTES} bytes"),
            SettingError::Invalid(lines) => write!(out, "{} line(s) cannot be read", lines.len()),
            SettingError::Io(why) => write!(out, "{why}"),
        }
    }
}

impl std::error::Error for SettingError {}

/// What a save did.
#[derive(Debug, PartialEq, Eq)]
pub struct Saved {
    pub before: Option<String>,
    pub after: String,
    /// The file name of the kept old version, when there was one.
    pub kept: Option<String>,
}

/// The folder the settings live in, and the folder their old versions go to.
pub struct Store {
    dir: PathBuf,
    backups: PathBuf,
    /// Set by a test: stop after the temporary file is written, as a crash would.
    #[doc(hidden)]
    pub crash_before_rename: AtomicBool,
}

fn kind(id: &str) -> Result<&'static Kind, SettingError> {
    KINDS.iter().find(|k| k.id == id).ok_or(SettingError::Unknown)
}

fn io(path: &Path, why: std::io::Error) -> SettingError {
    SettingError::Io(format!("{}: {why}", path.display()))
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self, SettingError> {
        let backups = dir.join("backups");
        std::fs::create_dir_all(&backups).map_err(|e| io(&backups, e))?;
        Ok(Self { dir: dir.to_path_buf(), backups, crash_before_rename: AtomicBool::new(false) })
    }

    /// The current text. A file that does not exist yet reads as empty.
    pub fn read(&self, id: &str) -> Result<String, SettingError> {
        let path = self.dir.join(kind(id)?.file);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(io(&path, e)),
        }
    }

    /// Check `text`, keep the old file, and replace it atomically.
    pub fn save(&self, id: &str, text: &str, now: u64) -> Result<Saved, SettingError> {
        let kind = kind(id)?;
        if text.len() > MAX_BYTES {
            return Err(SettingError::TooLarge);
        }
        let problems = (kind.check)(text);
        if !problems.is_empty() {
            return Err(SettingError::Invalid(problems));
        }
        let path = self.dir.join(kind.file);
        let old = std::fs::read(&path).ok();
        let kept = match &old {
            Some(bytes) => Some(self.keep(id, bytes, now)?),
            None => None,
        };
        let mut tmp = path.clone();
        tmp.set_extension("tmp");
        std::fs::write(&tmp, text).map_err(|e| io(&tmp, e))?;
        if self.crash_before_rename.load(Ordering::SeqCst) {
            return Err(SettingError::Io(String::from("stopped before the rename")));
        }
        std::fs::rename(&tmp, &path).map_err(|e| io(&path, e))?;
        Ok(Saved { before: old.map(|b| digest(&b)), after: digest(text.as_bytes()), kept })
    }

    fn keep(&self, id: &str, bytes: &[u8], now: u64) -> Result<String, SettingError> {
        let name = format!("{id}.{now}.bak");
        let path = self.backups.join(&name);
        std::fs::write(&path, bytes).map_err(|e| io(&path, e))?;
        let prefix = format!("{id}.");
        let mut mine: Vec<String> = std::fs::read_dir(&self.backups)
            .map_err(|e| io(&self.backups, e))?
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with(&prefix) && n.ends_with(".bak") && n[prefix.len()..n.len() - 4].chars().all(|c| c.is_ascii_digit()))
            .collect();
        mine.sort_by_key(|n| n[prefix.len()..n.len() - 4].parse::<u64>().ok());
        while mine.len() > KEEP {
            let oldest = mine.remove(0);
            std::fs::remove_file(self.backups.join(&oldest)).map_err(|e| io(&self.backups, e))?;
        }
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> Result<Store, Box<dyn std::error::Error>> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("settings-test").join(format!("{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Store::open(&dir)?)
    }

    #[test]
    fn the_catalog_has_unique_ids_and_files() {
        let mut ids: Vec<&str> = KINDS.iter().map(|k| k.id).collect();
        let mut files: Vec<&str> = KINDS.iter().map(|k| k.file).collect();
        ids.sort();
        files.sort();
        ids.dedup();
        files.dedup();
        assert_eq!((ids.len(), files.len()), (KINDS.len(), KINDS.len()));
        assert!(KINDS.iter().all(|k| matches!(k.part, "ips" | "ids" | "waf" | "av")));
    }

    #[test]
    fn a_bad_line_is_named_and_nothing_is_written() -> Result<(), Box<dyn std::error::Error>> {
        let s = store("bad")?;
        let saved = s.save("ips-policy", "{\"action\":\"alert\"}\n", 1)?;
        assert!(saved.before.is_none());
        let refused = s.save("ips-policy", "{\"action\":\"alert\"}\nnot json\n{\"action\":\"explode\"}\n", 2);
        assert!(matches!(&refused, Err(SettingError::Invalid(lines)) if lines.iter().map(|l| l.0).collect::<Vec<_>>() == vec![2, 3]));
        assert_eq!(s.read("ips-policy")?, "{\"action\":\"alert\"}\n");
        assert!(matches!(s.save("ips-policy", "# only a comment\n", 3), Err(SettingError::Invalid(_))));
        Ok(())
    }

    #[test]
    fn a_good_save_replaces_the_file_and_keeps_the_old_one() -> Result<(), Box<dyn std::error::Error>> {
        let s = store("keep")?;
        s.save("waf-allow-ip", "192.0.2.1\n", 10)?;
        let saved = s.save("waf-allow-ip", "192.0.2.0/24\n", 20)?;
        assert_eq!(s.read("waf-allow-ip")?, "192.0.2.0/24\n");
        assert_eq!(saved.kept.as_deref(), Some("waf-allow-ip.20.bak"));
        assert_eq!(saved.before, Some(digest(b"192.0.2.1\n")));
        assert_eq!(saved.after, digest(b"192.0.2.0/24\n"));
        Ok(())
    }

    #[test]
    fn only_twenty_old_versions_are_kept() -> Result<(), Box<dyn std::error::Error>> {
        let s = store("rotate")?;
        for n in 1..=30_u64 {
            s.save("iplist", &format!("192.0.2.{n}\n"), n)?;
        }
        let count = std::fs::read_dir(s.backups.clone())?.filter(|e| e.as_ref().is_ok_and(|e| e.file_name().to_string_lossy().starts_with("iplist."))).count();
        assert_eq!(count, KEEP);
        Ok(())
    }

    #[test]
    fn a_crash_after_the_temporary_file_leaves_the_original_untouched() -> Result<(), Box<dyn std::error::Error>> {
        let s = store("crash")?;
        s.save("ids-sids", "9000001\n", 1)?;
        s.crash_before_rename.store(true, Ordering::SeqCst);
        assert!(matches!(s.save("ids-sids", "9000002\n", 2), Err(SettingError::Io(_))));
        assert_eq!(s.read("ids-sids")?, "9000001\n");
        Ok(())
    }

    #[test]
    fn unknown_ids_and_big_texts_are_refused_and_a_missing_file_reads_empty() -> Result<(), Box<dyn std::error::Error>> {
        let s = store("misc")?;
        assert_eq!(s.read("nope"), Err(SettingError::Unknown));
        assert_eq!(s.save("nope", "x", 0), Err(SettingError::Unknown));
        assert_eq!(s.save("iplist", &"1.1.1.1\n".repeat(MAX_BYTES), 0), Err(SettingError::TooLarge));
        assert_eq!(s.read("blocklist")?, "");
        Ok(())
    }

    #[test]
    fn each_kind_rejects_what_its_tool_would_drop() {
        assert!((KINDS[2].check)("12\nabc\n") == vec![(2, String::from("not a signature id"))]);
        assert!(!(KINDS[8].check)("good.example\nbad host!\n").is_empty());
        assert!(!(KINDS[3].check)("not json\n").is_empty());
        assert!(!(KINDS[4].check)("not json\n").is_empty());
        assert!(!(KINDS[1].check)("999.1.1.1\n").is_empty());
    }
}
