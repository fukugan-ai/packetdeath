//! 段階4「IPS 化」の `--eve` / `--ips-sids` / `--ips-ttl`。`docs/design.md`
//! 「段階」節・「採る方式」節・受入 ID PK-30〜32 が正本。
//!
//! Suricata が IDS モードで並走し、検知した alert を `eve.json`
//! （JSON Lines）へ追記し続ける。この module は `event_type` が `alert` の
//! 行だけを拾い、`--ips-sids` に列挙された `signature_id` に当たれば、
//! `dest_ip` / `dest_port` の組を [`IdsDropSet`] へ `--ips-ttl` の期限付きで
//! 入れる。drop 集合の照合は `judge::IdsJudge` として同期判定の列に並ぶ
//! （`docs/design.md`「判定を差し込む口」節）。
//!
//! **`alert` 以外の `event_type`（`flow` / `tls` / `http` / `fileinfo` /
//! `stats`）は読まない（PK-35）。**通信の中身（`tls.sni` や `http` の
//! フィールド等）を log へ持ち出さない制約に沿い、`EveLine` は
//! `alert` の判定に要る5 field（`event_type` / `dest_ip` / `dest_port` /
//! `alert.signature_id` / `alert.severity`）しか持たない。
//!
//! An alert is dropped when its `signature_id` is listed in `--ips-sids`, or
//! when its `severity` is at most `--ips-severity` (Suricata numbers severity
//! from 1, the most severe). [`IpsRule`] holds both conditions; with neither
//! given it matches nothing.
//!
//! **外部が更新する `eve.json` を、動作の gate にしない。**file が無い・
//! 読めない・個々の行が壊れていても panic せず、その poll / その行だけを
//! 読み飛ばして起動を続ける（PK-33, PK-34）。

use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const EVENT_TYPE_ALERT: &str = "alert";

#[derive(Debug)]
pub enum IdsSidsError {
    Io(std::io::Error),
}

impl fmt::Display for IdsSidsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(
                f,
                "{}",
                crate::i18n::ids_sids_io_failed(crate::i18n::locale(), e)
            ),
        }
    }
}

impl std::error::Error for IdsSidsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for IdsSidsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// `--ips-sids` の1行1 `sid` 形式を読む。数値として読めない行は読み飛ばす
/// （panic しない）。空集合を渡せば、後段の `IdsDropSet` は何にも当たらない
/// （PK-30 の陰性対照。「この file に無い sid では落とさない」）。
pub fn parse_ips_sids(content: &str) -> HashSet<u64> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.parse::<u64>().ok())
        .collect()
}

/// `path` から `--ips-sids` file を読む。
pub fn load_ips_sids(path: &Path) -> Result<HashSet<u64>, IdsSidsError> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_ips_sids(&content))
}

/// `eve.json` の1行のうち、alert 判定に要る field だけを持つ。
/// `dest_ip` / `dest_port` / `alert` は `event_type` が `alert` 以外の行
/// （`flow` / `tls` / `http` / `fileinfo` / `stats`）では持たない、または
/// 判定に使わないので `Option` で受ける。`#[serde(deny_unknown_fields)]` は
/// 付けない ── Suricata が実物に持つ他の field（`tls` / `http` の中身等）を
/// この reader が拒否しないため（`av.rs` / `iplist.rs` と同じ判断）。
#[derive(Debug, Deserialize)]
struct EveLine {
    event_type: String,
    #[serde(default)]
    dest_ip: Option<IpAddr>,
    #[serde(default)]
    dest_port: Option<u16>,
    #[serde(default)]
    alert: Option<EveAlertBody>,
}

#[derive(Debug, Deserialize)]
struct EveAlertBody {
    signature_id: u64,
    /// Absent in a hand-made line; such an alert never matches `--ips-severity`.
    #[serde(default)]
    severity: Option<u8>,
}

/// The fields of one `alert` line that the drop decision reads.
#[derive(Debug, PartialEq)]
struct Alert {
    dest_ip: IpAddr,
    dest_port: u16,
    signature_id: u64,
    severity: Option<u8>,
}

/// 1行を parse し、`event_type` が `alert` であれば [`Alert`] を返す。
/// それ以外（壊れた JSON、`alert` 以外の `event_type`、field 欠落、型違反）は
/// `None`（PK-33, PK-35）。
fn parse_alert_line(line: &str) -> Option<Alert> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let entry: EveLine = serde_json::from_str(line).ok()?;
    if entry.event_type != EVENT_TYPE_ALERT {
        return None;
    }
    let body = entry.alert?;
    Some(Alert {
        dest_ip: entry.dest_ip?,
        dest_port: entry.dest_port?,
        signature_id: body.signature_id,
        severity: body.severity,
    })
}

/// Which alerts are dropped: a listed `signature_id`, or a `severity` at or
/// below `max_severity`. The default drops nothing.
#[derive(Debug, Default)]
pub struct IpsRule {
    pub sids: HashSet<u64>,
    pub max_severity: Option<u8>,
}

impl IpsRule {
    fn matches(&self, alert: &Alert) -> bool {
        self.sids.contains(&alert.signature_id)
            || matches!(
                (self.max_severity, alert.severity),
                (Some(max), Some(severity)) if severity <= max
            )
    }
}

/// `--eve` の alert が `--ips-sids` に当たった宛先 `(dst_ip, dst_port)` の
/// drop 集合。`--ips-ttl` を過ぎた entry は参照時に無効と判定する。
///
/// 挿入のたびに期限切れの古い entry を掃除する。alert を tail する thread
/// だけが挿入するので、別 timer / 別 thread を持たずに GC を1箇所へ
/// 閉じ込められる。
#[derive(Debug, Default)]
pub struct IdsDropSet {
    entries: Mutex<HashMap<(IpAddr, u16), Instant>>,
}

impl IdsDropSet {
    /// 何にも当たらない空の drop 集合（`--eve` 未指定、または起動直後）。
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// `dst_ip`:`dst_port` を `now` から `ttl` の間 drop 対象にする。
    /// `now` を明示引数にするのは、`--ips-ttl` の期限切れ（PK-37）を
    /// test から実際に sleep せず注入できるようにするため
    /// （呼び出し側は本番では `Instant::now()` を渡す）。
    pub fn insert(&self, dst_ip: IpAddr, dst_port: u16, now: Instant, ttl: Duration) {
        // SAFETY 不要: `unsafe` は使わない。mutex が poison した場合は
        // 挿入を諦めて fail-open に倒す（この thread は tail 専用で、他の
        // panic に巻き込まれる想定は無いが、念のため unwrap しない）。
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.retain(|_, expires_at| *expires_at > now);
        entries.insert((dst_ip, dst_port), now + ttl);
    }

    /// 集合の中身を `entries` ちょうどに入れ替える（段階12の `ips::runtime` が
    /// 上限つきの集合と揃えるために使う）。mutex が poison していれば何もしない。
    pub fn replace(&self, entries: Vec<((IpAddr, u16), Instant)>) {
        let Ok(mut held) = self.entries.lock() else {
            return;
        };
        *held = entries.into_iter().collect();
    }

    /// `(dst_ip, dst_port)` がいま drop 対象か。期限切れ、または一度も
    /// 挿入されていなければ `false`。
    pub fn contains(&self, dst_ip: &IpAddr, dst_port: u16, now: Instant) -> bool {
        let Ok(entries) = self.entries.lock() else {
            return false;
        };
        entries
            .get(&(*dst_ip, dst_port))
            .is_some_and(|expires_at| *expires_at > now)
    }
}

/// `path`（`eve.json`）を `poll_interval` ごとに監視し、新しく追記された
/// `alert` 行のうち `rule` に当たるものを `drop_set` へ `ttl` の期限で
/// 積む。`stop_rx` に何か届くか、送信側が drop されたら（`Disconnected`）
/// 戻る。
///
/// 🔴 **file が無い・読めない・途中で消えても落ちない。**その poll を
/// skip して次回へ進む（fail-open。`block_loop::run_watch_loop` と同じ形）。
pub fn watch_eve_file(
    path: &Path,
    rule: &IpsRule,
    drop_set: &IdsDropSet,
    ttl: Duration,
    poll_interval: Duration,
    stop_rx: &mpsc::Receiver<()>,
) {
    let mut offset: u64 = 0;
    loop {
        match stop_rx.recv_timeout(poll_interval) {
            Ok(()) => return,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        offset = poll_eve_file_once(path, offset, rule, drop_set, ttl);
    }
}

/// `watch_eve_file` の1 poll 分。新しく追記された byte を読み、完全な行
/// （末尾が `\n`）だけを処理して、次回 読み始める offset を返す。
/// 追記の途中で切れた最終行は消費せず、次回の poll へ持ち越す。
///
/// file が開けない・metadata が取れない・読めない・縮んでいる（ローテーション
/// 等）ときは、安全な offset （変更なし、または 0 からの読み直し）を返す。
fn poll_eve_file_once(
    path: &Path,
    offset: u64,
    rule: &IpsRule,
    drop_set: &IdsDropSet,
    ttl: Duration,
) -> u64 {
    let Ok(mut file) = File::open(path) else {
        return offset;
    };
    let Ok(metadata) = file.metadata() else {
        return offset;
    };
    let len = metadata.len();
    // file が前回より縮んでいたら（ローテーション等）先頭から読み直す。
    let start = if len < offset { 0 } else { offset };
    if file.seek(SeekFrom::Start(start)).is_err() {
        return offset;
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return start;
    }

    let mut consumed: usize = 0;
    for line_bytes in buf.split_inclusive(|&b| b == b'\n') {
        if line_bytes.last() != Some(&b'\n') {
            // 追記の途中で切れた最終行。次回の poll で読み直す。
            break;
        }
        consumed += line_bytes.len();
        let line = String::from_utf8_lossy(line_bytes);
        if let Some(alert) = parse_alert_line(&line).filter(|alert| rule.matches(alert)) {
            eprintln!(
                "packetdeath: [debug] {}",
                crate::i18n::ids_alert_dropped(
                    crate::i18n::locale(),
                    alert.signature_id,
                    alert.dest_ip,
                    alert.dest_port
                )
            );
            drop_set.insert(alert.dest_ip, alert.dest_port, Instant::now(), ttl);
        }
    }
    start + consumed as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(172, 66, 147, 243))
    }

    /// 実物の `eve.json` alert 行を模した1行（severity は 3）。
    fn alert_line(dest_ip: &str, dest_port: u16, sid: u64) -> String {
        alert_line_with_severity(dest_ip, dest_port, sid, 3)
    }

    fn alert_line_with_severity(dest_ip: &str, dest_port: u16, sid: u64, severity: u8) -> String {
        format!(
            r#"{{"timestamp":"2026-09-11T05:31:06.544371+0900","flow_id":837226380193816,"in_iface":"eth0","event_type":"alert","src_ip":"192.0.2.20","src_port":52727,"dest_ip":"{dest_ip}","dest_port":{dest_port},"proto":"TCP","alert":{{"action":"allowed","gid":1,"signature_id":{sid},"rev":1,"signature":"packetdeath probe: tls sni","category":"","severity":{severity}}}}}"#
        )
    }

    /// A rule that drops by the listed sids only.
    fn sid_rule(sids: &[u64]) -> IpsRule {
        IpsRule {
            sids: sids.iter().copied().collect(),
            max_severity: None,
        }
    }

    /// A rule that drops by severity only.
    fn severity_rule(max_severity: u8) -> IpsRule {
        IpsRule {
            sids: HashSet::new(),
            max_severity: Some(max_severity),
        }
    }

    fn alert_of(sid: u64, severity: Option<u8>) -> Alert {
        Alert {
            dest_ip: sample_ip(),
            dest_port: 443,
            signature_id: sid,
            severity,
        }
    }

    fn non_alert_line(event_type: &str) -> String {
        format!(r#"{{"event_type":"{event_type}","src_ip":"1.2.3.4","dest_ip":"5.6.7.8"}}"#)
    }

    #[test]
    fn parse_ips_sids_reads_one_sid_per_line() {
        let sids = parse_ips_sids("9000002\n\n  9000001  \n");
        assert!(sids.contains(&9000002));
        assert!(sids.contains(&9000001));
        assert_eq!(sids.len(), 2);
    }

    #[test]
    fn parse_ips_sids_skips_non_numeric_lines_without_panicking() {
        let sids = parse_ips_sids("not-a-number\n9000002\n\n日本語\n");
        assert_eq!(sids.len(), 1);
        assert!(sids.contains(&9000002));
    }

    #[test]
    fn load_missing_file_returns_err() {
        let path = Path::new("/nonexistent/packetdeath-ips-sids-test.txt");
        assert!(load_ips_sids(path).is_err());
    }

    #[test]
    fn parse_alert_line_extracts_dest_and_sid() -> Result<(), String> {
        // 実物の alert 行と同じ形。
        let line = alert_line("172.66.147.243", 443, 9000002);
        let alert =
            parse_alert_line(&line).ok_or_else(|| "alert 行は parse できるはず".to_string())?;
        assert_eq!(alert, alert_of(9000002, Some(3)));
        Ok(())
    }

    #[test]
    fn parse_alert_line_reads_severity_and_tolerates_its_absence() -> Result<(), String> {
        let line = alert_line_with_severity("172.66.147.243", 443, 1, 1);
        let alert =
            parse_alert_line(&line).ok_or_else(|| "alert 行は parse できるはず".to_string())?;
        assert_eq!(alert.severity, Some(1));
        let no_severity = r#"{"event_type":"alert","dest_ip":"172.66.147.243","dest_port":443,"alert":{"signature_id":1}}"#;
        let alert = parse_alert_line(no_severity)
            .ok_or_else(|| "severity 無しでも parse できるはず".to_string())?;
        assert_eq!(alert.severity, None);
        Ok(())
    }

    #[test]
    fn ips_rule_drops_severity_at_or_below_the_limit() {
        // PK-36a: severity 1 は `--ips-severity 1` で落とし、2 は落とさない。
        let rule = severity_rule(1);
        assert!(rule.matches(&alert_of(1, Some(1))));
        assert!(!rule.matches(&alert_of(1, Some(2))));
        assert!(!rule.matches(&alert_of(1, Some(3))));
        assert!(severity_rule(2).matches(&alert_of(1, Some(2))));
        assert!(!severity_rule(2).matches(&alert_of(1, Some(3))));
    }

    #[test]
    fn ips_rule_without_severity_limit_drops_no_severity_1_alert() {
        // PK-36a 陰性対照：`--ips-severity` も sid も無ければ severity 1 でも落とさない。
        assert!(!IpsRule::default().matches(&alert_of(1, Some(1))));
    }

    #[test]
    fn ips_rule_never_drops_an_alert_without_severity_by_severity() {
        assert!(!severity_rule(3).matches(&alert_of(1, None)));
    }

    #[test]
    fn ips_rule_drops_on_either_listed_sid_or_severity() {
        let rule = IpsRule {
            sids: HashSet::from([9000002]),
            max_severity: Some(1),
        };
        assert!(rule.matches(&alert_of(9000002, Some(3))));
        assert!(rule.matches(&alert_of(7, Some(1))));
        assert!(!rule.matches(&alert_of(7, Some(3))));
    }

    #[test]
    fn poll_eve_file_once_drops_by_severity_only_for_severe_alerts() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!(
            "packetdeath-ids-test-severity-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("eve.json");
        let content = format!(
            "{}\n{}\n",
            alert_line_with_severity("172.66.147.243", 443, 1, 1),
            alert_line_with_severity("198.51.100.7", 80, 2, 2),
        );
        std::fs::write(&path, content).map_err(|e| e.to_string())?;

        let drop_set = IdsDropSet::new();
        poll_eve_file_once(
            &path,
            0,
            &severity_rule(1),
            &drop_set,
            Duration::from_secs(300),
        );
        assert!(drop_set.contains(&sample_ip(), 443, Instant::now()));
        let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        assert!(!drop_set.contains(&other, 80, Instant::now()));
        Ok(())
    }

    #[test]
    fn parse_alert_line_ignores_non_alert_event_types() {
        // PK-35: flow / tls / http / fileinfo / stats は読まない。
        for event_type in ["flow", "tls", "http", "fileinfo", "stats"] {
            assert_eq!(parse_alert_line(&non_alert_line(event_type)), None);
        }
    }

    #[test]
    fn parse_alert_line_handles_broken_input_without_panicking() {
        // PK-33: 空、不正な JSON、途中で切れた行、巨大な行、非 ASCII、
        // field 不足、型違い、alert 無しのいずれも panic せず None になる。
        let huge = "x".repeat(1_000_000);
        let cases = [
            "".to_string(),
            "not-json".to_string(),
            r#"{"event_type":"alert""#.to_string(), // 途中で切れた JSON
            huge,
            "日本語だけの行".to_string(),
            r#"{"event_type":"alert","dest_port":443}"#.to_string(), // dest_ip 欠落
            r#"{"event_type":"alert","dest_ip":"not-an-ip","dest_port":443,"alert":{"signature_id":1}}"#.to_string(),
            r#"{"event_type":"alert","dest_ip":"1.2.3.4","dest_port":"not-a-port","alert":{"signature_id":1}}"#.to_string(),
            r#"{"event_type":"alert","dest_ip":"1.2.3.4","dest_port":443}"#.to_string(), // alert 無し
        ];
        for case in cases {
            assert_eq!(parse_alert_line(&case), None, "case={case}");
        }
    }

    #[test]
    fn ids_drop_set_matches_only_after_insert() {
        let drop_set = IdsDropSet::new();
        let now = Instant::now();
        assert!(!drop_set.contains(&sample_ip(), 443, now));
        drop_set.insert(sample_ip(), 443, now, Duration::from_secs(300));
        assert!(drop_set.contains(&sample_ip(), 443, now));
    }

    #[test]
    fn ids_drop_set_does_not_match_different_port() {
        let drop_set = IdsDropSet::new();
        let now = Instant::now();
        drop_set.insert(sample_ip(), 443, now, Duration::from_secs(300));
        assert!(!drop_set.contains(&sample_ip(), 80, now));
    }

    #[test]
    fn ids_drop_set_expires_after_ttl() {
        // PK-32 相当。時刻を test から注入し、実際に sleep しない。
        let drop_set = IdsDropSet::new();
        let now = Instant::now();
        drop_set.insert(sample_ip(), 443, now, Duration::from_secs(5));
        assert!(drop_set.contains(&sample_ip(), 443, now + Duration::from_secs(4)));
        assert!(!drop_set.contains(&sample_ip(), 443, now + Duration::from_secs(6)));
    }

    #[test]
    fn poll_eve_file_once_ignores_non_alert_and_out_of_list_sid() -> Result<(), String> {
        // PK-30 / PK-35 相当。--ips-sids に無い sid、alert 以外の event_type は
        // drop 集合を増やさない。
        let dir = std::env::temp_dir().join(format!(
            "packetdeath-ids-test-{}-{}",
            "negative",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("eve.json");
        let content = format!(
            "{}\n{}\n",
            non_alert_line("flow"),
            alert_line("172.66.147.243", 443, 9000002)
        );
        std::fs::write(&path, content).map_err(|e| e.to_string())?;

        let drop_set = IdsDropSet::new();
        let next_offset = poll_eve_file_once(
            &path,
            0,
            &IpsRule::default(),
            &drop_set,
            Duration::from_secs(300),
        );
        assert!(next_offset > 0);
        assert!(!drop_set.contains(&sample_ip(), 443, Instant::now()));
        Ok(())
    }

    #[test]
    fn poll_eve_file_once_applies_matching_sid() -> Result<(), String> {
        // PK-31 相当。
        let dir = std::env::temp_dir().join(format!(
            "packetdeath-ids-test-{}-{}",
            "positive",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("eve.json");
        std::fs::write(
            &path,
            format!("{}\n", alert_line("172.66.147.243", 443, 9000002)),
        )
        .map_err(|e| e.to_string())?;

        let drop_set = IdsDropSet::new();
        let rule = sid_rule(&[9000002]);
        poll_eve_file_once(&path, 0, &rule, &drop_set, Duration::from_secs(300));
        assert!(drop_set.contains(&sample_ip(), 443, Instant::now()));
        Ok(())
    }

    #[test]
    fn poll_eve_file_once_reads_valid_lines_even_when_mixed_with_broken_lines() -> Result<(), String>
    {
        // PK-34: 1行が壊れていても他の行は読める。壊れた JSON 行を
        // 正常な alert 行の前後に挟む。
        let dir = std::env::temp_dir().join(format!(
            "packetdeath-ids-test-{}-{}",
            "mixed",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("eve.json");
        let content = format!(
            "not-json\n{}\n{{\"event_type\":\"alert\"\n{}\n日本語だけの壊れた行\n",
            alert_line("172.66.147.243", 443, 9000002),
            alert_line("198.51.100.7", 80, 9000001),
        );
        std::fs::write(&path, content).map_err(|e| e.to_string())?;

        let drop_set = IdsDropSet::new();
        let rule = sid_rule(&[9000002, 9000001]);
        poll_eve_file_once(&path, 0, &rule, &drop_set, Duration::from_secs(300));
        assert!(drop_set.contains(&sample_ip(), 443, Instant::now()));
        assert!(drop_set.contains(
            &IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            80,
            Instant::now()
        ));
        Ok(())
    }

    #[test]
    fn poll_eve_file_once_leaves_incomplete_trailing_line_for_next_poll() -> Result<(), String> {
        // eve.json は追記され続ける前提。改行の無い末尾行は
        // 次回の poll へ持ち越し、offset を進めない。
        let dir = std::env::temp_dir().join(format!(
            "packetdeath-ids-test-{}-{}",
            "incomplete",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("eve.json");
        let partial_line = alert_line("172.66.147.243", 443, 9000002);
        // 末尾の改行を落として「書き込み中」を模す。
        std::fs::write(&path, &partial_line).map_err(|e| e.to_string())?;

        let drop_set = IdsDropSet::new();
        let rule = sid_rule(&[9000002]);
        let next_offset = poll_eve_file_once(&path, 0, &rule, &drop_set, Duration::from_secs(300));
        assert_eq!(next_offset, 0, "改行が無い行は消費しない");
        assert!(!drop_set.contains(&sample_ip(), 443, Instant::now()));

        // 改行を足して追記が完了した想定で、続きから読み直す。
        std::fs::write(&path, format!("{partial_line}\n")).map_err(|e| e.to_string())?;
        let next_offset = poll_eve_file_once(
            &path,
            next_offset,
            &rule,
            &drop_set,
            Duration::from_secs(300),
        );
        assert!(next_offset > 0);
        assert!(drop_set.contains(&sample_ip(), 443, Instant::now()));
        Ok(())
    }

    #[test]
    fn watch_eve_file_returns_promptly_on_stop_signal_for_missing_file() -> Result<(), String> {
        // file が最初から存在しない path を渡し、run_watch_loop 相当が panic
        // せず、stop 通知で確実に戻ることを確かめる
        // （`block_loop::pi3_missing_pcapng_file_falls_open_and_watch_loop_returns_on_stop`
        // と同じ形）。
        let drop_set = IdsDropSet::new();
        let rule = IpsRule::default();
        let missing_path = std::env::temp_dir().join("packetdeath-does-not-exist-eve.json");
        let (stop_tx, stop_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            watch_eve_file(
                &missing_path,
                &rule,
                &drop_set,
                Duration::from_secs(300),
                Duration::from_millis(10),
                &stop_rx,
            );
        });
        std::thread::sleep(Duration::from_millis(50));
        stop_tx.send(()).map_err(|e| e.to_string())?;
        handle
            .join()
            .map_err(|e| format!("watch_eve_file の thread が panic した: {e:?}"))?;
        Ok(())
    }
}
