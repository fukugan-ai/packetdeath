//! Stage 12: an `eve.json` line to the fields a policy tests.
//!
//! Only `event_type == "alert"` lines count. Suricata prints the
//! classification description in `alert.category`; a policy's `classtype` and
//! `category` conditions both read that field. The signature text is never
//! read, so it cannot reach a log.

use std::net::IpAddr;

use serde::Deserialize;

use super::policy::AlertInfo;

#[derive(Deserialize)]
struct Line {
    event_type: String,
    src_ip: Option<IpAddr>,
    dest_ip: Option<IpAddr>,
    dest_port: Option<u16>,
    proto: Option<String>,
    alert: Option<Body>,
}

#[derive(Deserialize)]
struct Body {
    signature_id: u64,
    severity: Option<u8>,
    category: Option<String>,
}

/// The alert in `line`, or `None` for anything that is not a complete alert.
pub fn alert_of(line: &str) -> Option<AlertInfo> {
    let parsed: Line = serde_json::from_str(line.trim()).ok()?;
    if parsed.event_type != "alert" {
        return None;
    }
    let body = parsed.alert?;
    Some(AlertInfo {
        sid: body.signature_id,
        severity: body.severity,
        classtype: body.category.clone(),
        category: body.category,
        src_ip: parsed.src_ip,
        dst_ip: parsed.dest_ip?,
        dst_port: parsed.dest_port?,
        proto: parsed.proto,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"{"timestamp":"2026-10-28T10:00:00+0900","event_type":"alert","src_ip":"192.168.1.20","src_port":5555,"dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":1,"signature":"SECRETSIGNATURE","category":"A Network Trojan was detected","severity":1}}"#;

    #[test]
    fn a_full_alert_line_gives_every_field() {
        let a = alert_of(FULL);
        assert_eq!(a.as_ref().map(|a| a.sid), Some(2001219));
        assert_eq!(a.as_ref().and_then(|a| a.severity), Some(1));
        assert_eq!(a.as_ref().map(|a| a.dst_port), Some(443));
        assert_eq!(a.and_then(|a| a.classtype).as_deref(), Some("A Network Trojan was detected"));
    }

    #[test]
    fn lines_that_are_not_complete_alerts_give_nothing() {
        for line in [
            "",
            "not json",
            r#"{"event_type":"flow","dest_ip":"1.2.3.4","dest_port":80}"#,
            r#"{"event_type":"alert","dest_port":80,"alert":{"signature_id":1}}"#,
            r#"{"event_type":"alert","dest_ip":"1.2.3.4","alert":{"signature_id":1}}"#,
            r#"{"event_type":"alert","dest_ip":"1.2.3.4","dest_port":80}"#,
            r#"{"event_type":"alert","dest_ip":"nope","dest_port":80,"alert":{"signature_id":1}}"#,
        ] {
            assert_eq!(alert_of(line), None, "{line}");
        }
    }
}
