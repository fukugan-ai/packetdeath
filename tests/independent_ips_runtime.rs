//! Stage 12 acceptance PK-172..179 through `ips::runtime`, with time passed in.
//! `docs/design.md` "段階12 IDS/IPS の業務水準化" 受入 ID.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use packetdeath::ids::IdsDropSet;
use packetdeath::ips::policy::Action;
use packetdeath::ips::runtime::{Config, Runtime};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("ips-rt-{}-{name}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn epoch() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// The options every test starts from; the files are not touched.
fn base(dir: &Path) -> Config {
    Config {
        eve: dir.join("eve.json"),
        policy: dir.join("policy.jsonl"),
        never: None,
        allow_private: false,
        default_action: Action::Alert,
        default_ttl: 600,
        log_dir: Some(dir.to_path_buf()),
        state: Some(dir.join("state.jsonl")),
        max_entries: 8,
        max_read: 1 << 20,
        stale_after: 900,
    }
}

/// Write the policy and an empty `eve.json`, and return the options.
fn config(dir: &Path, policy: &str) -> Result<Config, std::io::Error> {
    std::fs::write(dir.join("policy.jsonl"), policy)?;
    std::fs::write(dir.join("eve.json"), "")?;
    Ok(base(dir))
}

fn alert(sid: u64, dst: &str) -> String {
    format!("{{\"event_type\":\"alert\",\"src_ip\":\"192.168.1.20\",\"dest_ip\":\"{dst}\",\"dest_port\":443,\"proto\":\"TCP\",\"alert\":{{\"signature_id\":{sid},\"severity\":1,\"signature\":\"SECRETSIGNATURE\",\"category\":\"Trojan\"}}}}\n")
}

fn append(dir: &Path, text: &str) -> Result<(), std::io::Error> {
    let mut file = std::fs::OpenOptions::new().append(true).open(dir.join("eve.json"))?;
    file.write_all(text.as_bytes())
}

fn blocked(sink: &IdsDropSet, ip: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(sink.contains(&ip.parse::<IpAddr>()?, 443, Instant::now()))
}

fn events(dir: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(dir.join("ips.jsonl"))?;
    let mut found = Vec::new();
    for line in text.lines() {
        let row: serde_json::Value = serde_json::from_str(line)?;
        found.push(row["event"].as_str().map(str::to_owned).ok_or("no event")?);
    }
    Ok(found)
}

fn count(found: &[String], event: &str) -> usize {
    found.iter().filter(|e| *e == event).count()
}

#[test]
fn pk172_pk178_a_drop_reaches_the_judge_set_and_the_audit_without_the_signature() -> TestResult {
    let dir = scratch("drop")?;
    let sink = Arc::new(IdsDropSet::new());
    let mut rt = Runtime::start(config(&dir, "{\"sid\":1,\"action\":\"drop\",\"ttl\":60}\n")?, Arc::clone(&sink))?;
    append(&dir, &(alert(1, "203.0.113.9") + &alert(2, "203.0.113.10")))?;
    rt.tick(epoch()?);
    assert!(blocked(&sink, "203.0.113.9")?);
    assert!(!blocked(&sink, "203.0.113.10")?);
    assert_eq!(events(&dir)?, vec!["drop", "observed"]);
    let log = std::fs::read_to_string(dir.join("ips.jsonl"))?;
    assert!(!log.contains("SECRETSIGNATURE"));
    Ok(())
}

#[test]
fn pk173_a_protected_destination_stays_open_whatever_the_policy_says() -> TestResult {
    let dir = scratch("never")?;
    let sink = Arc::new(IdsDropSet::new());
    let mut rt = Runtime::start(config(&dir, "{\"action\":\"drop\"}\n")?, Arc::clone(&sink))?;
    append(&dir, &(alert(1, "127.0.0.1") + &alert(1, "192.168.1.1")))?;
    rt.tick(epoch()?);
    assert!(!blocked(&sink, "127.0.0.1")? && !blocked(&sink, "192.168.1.1")?);
    assert_eq!(events(&dir)?, vec!["protected", "protected"]);
    Ok(())
}

#[test]
fn pk175_a_restart_restores_what_is_still_in_force() -> TestResult {
    let dir = scratch("restore")?;
    let mut rt = Runtime::start(config(&dir, "{\"action\":\"drop\",\"ttl\":3000}\n")?, Arc::new(IdsDropSet::new()))?;
    append(&dir, &alert(1, "203.0.113.9"))?;
    rt.tick(epoch()?);
    drop(rt);
    let again = Arc::new(IdsDropSet::new());
    let _rt = Runtime::start(base(&dir), Arc::clone(&again))?;
    assert!(blocked(&again, "203.0.113.9")?);
    assert!(events(&dir)?.contains(&String::from("restored")));
    Ok(())
}

#[test]
fn pk175_a_broken_state_file_starts_empty() -> TestResult {
    let dir = scratch("broken-state")?;
    let cfg = config(&dir, "{\"action\":\"drop\"}\n")?;
    std::fs::write(dir.join("state.jsonl"), "not json\n")?;
    let sink = Arc::new(IdsDropSet::new());
    let mut rt = Runtime::start(cfg, Arc::clone(&sink))?;
    assert!(!blocked(&sink, "203.0.113.9")?);
    append(&dir, &alert(1, "203.0.113.9"))?;
    rt.tick(epoch()?);
    assert!(blocked(&sink, "203.0.113.9")?);
    Ok(())
}

#[test]
fn pk177_a_silent_eve_file_goes_stale_once_and_recovers_when_it_grows() -> TestResult {
    let dir = scratch("stale")?;
    let mut rt = Runtime::start(config(&dir, "{\"action\":\"alert\"}\n")?, Arc::new(IdsDropSet::new()))?;
    let base_time = epoch()?;
    rt.tick(base_time + 100);
    rt.tick(base_time + 1000);
    rt.tick(base_time + 1100);
    append(&dir, &alert(1, "203.0.113.9"))?;
    rt.tick(base_time + 1200);
    let found = events(&dir)?;
    assert_eq!((count(&found, "stale"), count(&found, "recovered")), (1, 1));
    Ok(())
}

#[test]
fn pk179_a_rewritten_policy_takes_effect_and_a_broken_one_is_ignored() -> TestResult {
    let dir = scratch("reload")?;
    let sink = Arc::new(IdsDropSet::new());
    let mut rt = Runtime::start(config(&dir, "{\"action\":\"alert\"}\n")?, Arc::clone(&sink))?;
    append(&dir, &alert(1, "203.0.113.9"))?;
    rt.tick(epoch()?);
    assert!(!blocked(&sink, "203.0.113.9")?);
    std::fs::write(dir.join("policy.jsonl"), "{\"action\":\"drop\",\"ttl\":60}\n# changed\n")?;
    append(&dir, &alert(1, "203.0.113.9"))?;
    rt.tick(epoch()?);
    assert!(blocked(&sink, "203.0.113.9")?);
    std::fs::write(dir.join("policy.jsonl"), "garbage garbage garbage garbage\n")?;
    append(&dir, &alert(1, "203.0.113.11"))?;
    rt.tick(epoch()?);
    assert!(blocked(&sink, "203.0.113.11")?);
    Ok(())
}

#[test]
fn an_unreadable_or_empty_policy_stops_the_start() -> TestResult {
    let dir = scratch("nopolicy")?;
    let garbage = config(&dir, "garbage\n")?;
    assert!(Runtime::start(garbage, Arc::new(IdsDropSet::new())).is_err());
    let mut absent = config(&dir, "{\"action\":\"alert\"}\n")?;
    absent.policy = dir.join("absent.jsonl");
    assert!(Runtime::start(absent, Arc::new(IdsDropSet::new())).is_err());
    Ok(())
}

#[test]
fn pk174_a_flood_of_distinct_destinations_stays_inside_the_cap() -> TestResult {
    let dir = scratch("flood")?;
    let sink = Arc::new(IdsDropSet::new());
    let mut rt = Runtime::start(config(&dir, "{\"action\":\"drop\",\"ttl\":3000}\n")?, Arc::clone(&sink))?;
    let mut flood = String::new();
    for n in 1..=100 {
        flood.push_str(&alert(1, &format!("203.0.113.{n}")));
    }
    append(&dir, &flood)?;
    rt.tick(epoch()?);
    let mut held = 0;
    for n in 1..=100 {
        if blocked(&sink, &format!("203.0.113.{n}"))? {
            held += 1;
        }
    }
    assert_eq!(held, 8);
    assert_eq!(count(&events(&dir)?, "evicted"), 92);
    Ok(())
}
