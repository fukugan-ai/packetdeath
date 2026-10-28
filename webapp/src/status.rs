//! The status page's numbers. `webapp/docs/design.ja.md`.
//!
//! They come from the same functions as `waf-report` and `ips-report`, so the
//! page and the command line cannot disagree. A log that does not exist yet is
//! reported as absent, not as zero: no traffic and no log are different facts.

use std::path::Path;

use packetdeath::ips::report as ips;
use packetdeath::waf::report as waf;
use serde_json::{json, Value};

fn waf_part(text: &str) -> Value {
    let s = waf::summarize(text, None);
    let pairs = |rows: &[(String, usize)]| rows.iter().map(|(k, n)| json!({"key": k, "count": n})).collect::<Vec<_>>();
    let suspects: Vec<Value> = s
        .suspects
        .iter()
        .map(|x| json!({"rule": x.rule, "path": x.path, "hits": x.hits, "sources": x.sources}))
        .collect();
    json!({
        "present": true,
        "total": s.total,
        "unreadable": s.unreadable,
        "by_action": s.by_action,
        "top_rules": pairs(&s.top_rules),
        "top_sources": pairs(&s.top_sources),
        "suspects": suspects,
    })
}

fn ips_part(text: &str) -> Value {
    let s = ips::summarize(text, None);
    let sids = |rows: &[(u64, usize)]| rows.iter().map(|(sid, n)| json!({"sid": sid, "count": n})).collect::<Vec<_>>();
    let protected: Vec<Value> = s.protected.iter().map(|(dst, n)| json!({"dst": dst, "count": n})).collect();
    // An absent count is smaller than a present one, so this is "more stale than recovered".
    let stale = s.events.get("stale") > s.events.get("recovered");
    json!({
        "present": true,
        "lines": s.lines,
        "unreadable": s.unreadable,
        "events": s.events,
        "acting_sids": sids(&s.acting_sids),
        "observed_only": sids(&s.observed_only),
        "protected": protected,
        "daily_drops": s.daily_drops,
        "stale": stale,
    })
}

fn part(dir: &Path, file: &str, build: fn(&str) -> Value) -> Result<Value, String> {
    let path = dir.join(file);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(build(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({"present": false})),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The WAF and IPS summaries of the logs in `dir`.
pub fn read(dir: &Path) -> Result<Value, String> {
    Ok(json!({"waf": part(dir, "waf.jsonl", waf_part)?, "ips": part(dir, "ips.jsonl", ips_part)?}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("status-test").join(format!("{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn a_missing_log_is_absent_not_zero() -> Result<(), Box<dyn std::error::Error>> {
        let v = read(&dir("none")?)?;
        assert_eq!(v["waf"]["present"], false);
        assert_eq!(v["ips"]["present"], false);
        Ok(())
    }

    #[test]
    fn the_numbers_equal_the_command_line_reports() -> Result<(), Box<dyn std::error::Error>> {
        let d = dir("same")?;
        let waf_text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/waf/fixture-log/waf.jsonl"))?;
        let ips_text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/ids/fixture-log/ips.jsonl"))?;
        std::fs::write(d.join("waf.jsonl"), &waf_text)?;
        std::fs::write(d.join("ips.jsonl"), &ips_text)?;
        let v = read(&d)?;
        assert_eq!(v["waf"]["total"], waf::summarize(&waf_text, None).total);
        assert_eq!(v["ips"]["lines"], ips::summarize(&ips_text, None).lines);
        assert_eq!(v["waf"]["total"], 10);
        assert_eq!(v["ips"]["events"]["drop"], 2);
        assert_eq!(v["ips"]["observed_only"][0]["sid"], 2013504);
        assert_eq!(v["ips"]["stale"], false);
        Ok(())
    }

    #[test]
    fn a_stale_event_without_a_recovery_is_marked_stale() -> Result<(), Box<dyn std::error::Error>> {
        let d = dir("stale")?;
        std::fs::write(d.join("ips.jsonl"), "{\"ts\":\"2026-10-28T01:00:00Z\",\"event\":\"stale\"}\n")?;
        assert_eq!(read(&d)?["ips"]["stale"], true);
        Ok(())
    }

    #[test]
    fn an_unreadable_log_is_an_error() -> Result<(), Box<dyn std::error::Error>> {
        let d = dir("dirlog")?;
        std::fs::create_dir_all(d.join("waf.jsonl"))?;
        assert!(read(&d).is_err());
        Ok(())
    }
}
