//! Stage 12: the IPS policy file. `docs/design.md` "段階12 IDS/IPS の業務水準化".
//!
//! One JSON object per line, evaluated in order; the first rule whose
//! conditions all hold decides. A line that cannot be read is dropped and
//! counted, so a typo never turns a policy into "drop everything".

use std::net::IpAddr;

use serde::Deserialize;

use crate::iplist::{parse_line, Cidr};

/// What the policy says to do with an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Drop the destination for `ttl` seconds (`None`: the command-line TTL).
    Drop { ttl: Option<u64> },
    /// Record the alert as observed and drop nothing.
    Alert,
    /// Say nothing about this alert (a false positive that is switched off).
    Ignore,
    /// Drop once `count` alerts of one (src, dst, sid) arrive inside `window`.
    Escalate { count: u32, window: u64, ttl: u64 },
}

/// The fields of one alert that a rule can test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertInfo {
    pub sid: u64,
    pub severity: Option<u8>,
    pub classtype: Option<String>,
    pub category: Option<String>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub proto: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SidSpec {
    One(u64),
    Range(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    sid: Option<SidSpec>,
    classtype: Option<String>,
    severity_max: Option<u8>,
    category: Option<String>,
    src: Option<String>,
    dst: Option<String>,
    proto: Option<String>,
    dst_port: Option<u16>,
    action: String,
    ttl: Option<u64>,
    count: Option<u32>,
    window: Option<u64>,
}

#[derive(Debug)]
struct Rule {
    line: usize,
    sid: Option<(u64, u64)>,
    classtype: Option<String>,
    severity_max: Option<u8>,
    category: Option<String>,
    src: Option<Cidr>,
    dst: Option<Cidr>,
    proto: Option<String>,
    dst_port: Option<u16>,
    action: Action,
}

/// The rules of a policy file, in file order.
#[derive(Debug, Default)]
pub struct Policy {
    rules: Vec<Rule>,
}

/// The rule that decided, and what it says.
#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    /// 1-based line of the rule in the policy file.
    pub line: usize,
    pub action: Action,
}

fn sid_range(spec: SidSpec) -> Result<(u64, u64), String> {
    let text = match spec {
        SidSpec::One(sid) => return Ok((sid, sid)),
        SidSpec::Range(text) => text,
    };
    let Some((low, high)) = text.split_once('-') else {
        return Err(format!("sid range {text:?} is not low-high"));
    };
    let low: u64 = low.trim().parse().map_err(|_| format!("sid {low:?}"))?;
    let high: u64 = high.trim().parse().map_err(|_| format!("sid {high:?}"))?;
    if low > high {
        return Err(format!("sid range {low}-{high} is reversed"));
    }
    Ok((low, high))
}

fn cidr_of(text: Option<String>, what: &str) -> Result<Option<Cidr>, String> {
    let Some(text) = text else {
        return Ok(None);
    };
    match parse_line(&text) {
        Some(cidr) => Ok(Some(cidr)),
        None => Err(format!("{what} {text:?} is not an address or CIDR")),
    }
}

fn action_of(raw: &RawRule) -> Result<Action, String> {
    match raw.action.as_str() {
        "drop" => Ok(Action::Drop { ttl: raw.ttl }),
        "alert" => Ok(Action::Alert),
        "ignore" => Ok(Action::Ignore),
        "escalate" => {
            let (Some(count), Some(window), Some(ttl)) = (raw.count, raw.window, raw.ttl) else {
                return Err(String::from("escalate needs count, window and ttl"));
            };
            if count == 0 || window == 0 || ttl == 0 {
                return Err(String::from("escalate count, window and ttl must be above 0"));
            }
            Ok(Action::Escalate { count, window, ttl })
        }
        other => Err(format!("unknown action {other:?}")),
    }
}

fn rule_of(line: usize, text: &str) -> Result<Rule, String> {
    let raw: RawRule = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let action = action_of(&raw)?;
    let sid = match raw.sid {
        Some(spec) => Some(sid_range(spec)?),
        None => None,
    };
    Ok(Rule {
        line,
        sid,
        classtype: raw.classtype,
        severity_max: raw.severity_max,
        category: raw.category,
        src: cidr_of(raw.src, "src")?,
        dst: cidr_of(raw.dst, "dst")?,
        proto: raw.proto,
        dst_port: raw.dst_port,
        action,
    })
}

impl Rule {
    fn matches(&self, a: &AlertInfo) -> bool {
        self.sid.is_none_or(|(low, high)| (low..=high).contains(&a.sid))
            && self.classtype.as_ref().is_none_or(|c| a.classtype.as_ref() == Some(c))
            && self.severity_max.is_none_or(|max| a.severity.is_some_and(|s| s <= max))
            && self.category.as_ref().is_none_or(|c| {
                a.category.as_ref().is_some_and(|text| text.contains(c.as_str()))
            })
            && self.src.is_none_or(|c| a.src_ip.is_some_and(|ip| c.contains(&ip)))
            && self.dst.is_none_or(|c| c.contains(&a.dst_ip))
            && self.proto.as_ref().is_none_or(|p| {
                a.proto.as_ref().is_some_and(|q| q.eq_ignore_ascii_case(p))
            })
            && self.dst_port.is_none_or(|port| port == a.dst_port)
    }
}

impl Policy {
    /// Read a policy. Returns the rules and how many lines were dropped.
    pub fn parse(content: &str) -> (Self, usize) {
        let mut rules = Vec::new();
        let mut dropped = 0_usize;
        for (index, text) in content.lines().enumerate() {
            let text = text.trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            match rule_of(index + 1, text) {
                Ok(rule) => rules.push(rule),
                Err(_) => dropped += 1,
            }
        }
        (Self { rules }, dropped)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The first rule that holds for `alert`, or `None` when none does.
    pub fn decide(&self, alert: &AlertInfo) -> Option<Decision> {
        self.rules.iter().find(|r| r.matches(alert)).map(|r| Decision {
            line: r.line,
            action: r.action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn alert(sid: u64) -> AlertInfo {
        AlertInfo {
            sid,
            severity: Some(2),
            classtype: Some(String::from("trojan-activity")),
            category: Some(String::from("A Network Trojan was detected")),
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            dst_port: 443,
            proto: Some(String::from("TCP")),
        }
    }

    #[test]
    fn an_empty_policy_decides_nothing() {
        let (policy, dropped) = Policy::parse("");
        assert!(policy.is_empty());
        assert_eq!((dropped, policy.decide(&alert(1))), (0, None));
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let text = "{\"sid\":5,\"action\":\"ignore\"}\n{\"sid\":\"1-9\",\"action\":\"drop\"}\n";
        let (policy, _) = Policy::parse(text);
        assert_eq!(policy.decide(&alert(5)).map(|d| d.line), Some(1));
        assert_eq!(policy.decide(&alert(6)).map(|d| d.line), Some(2));
        assert_eq!(policy.decide(&alert(10)), None);
    }

    #[test]
    fn range_edges_are_inclusive() {
        let (policy, _) = Policy::parse("{\"sid\":\"10-20\",\"action\":\"alert\"}");
        assert!(policy.decide(&alert(10)).is_some() && policy.decide(&alert(20)).is_some());
        assert!(policy.decide(&alert(9)).is_none() && policy.decide(&alert(21)).is_none());
    }

    #[test]
    fn every_condition_must_hold() {
        let text = "{\"classtype\":\"trojan-activity\",\"dst\":\"203.0.113.0/24\",\"dst_port\":443,\"severity_max\":2,\"proto\":\"tcp\",\"src\":\"192.168.0.0/16\",\"category\":\"Trojan\",\"action\":\"drop\",\"ttl\":60}";
        let (policy, dropped) = Policy::parse(text);
        assert_eq!(dropped, 0);
        let hit = policy.decide(&alert(1));
        assert_eq!(hit.map(|d| d.action), Some(Action::Drop { ttl: Some(60) }));
        let mut other = alert(1);
        other.dst_port = 80;
        assert_eq!(policy.decide(&other), None);
        other = alert(1);
        other.severity = Some(3);
        assert_eq!(policy.decide(&other), None);
    }

    #[test]
    fn broken_lines_are_dropped_and_counted() {
        let text = "not json\n{\"action\":\"explode\"}\n{\"sid\":\"9-1\",\"action\":\"drop\"}\n{\"action\":\"escalate\"}\n{\"dst\":\"nope\",\"action\":\"drop\"}\n{\"extra\":1,\"action\":\"drop\"}\n# note\n{\"action\":\"alert\"}\n";
        let (policy, dropped) = Policy::parse(text);
        assert_eq!((policy.len(), dropped), (1, 6));
    }

    #[test]
    fn escalate_needs_count_window_and_ttl() {
        let ok = "{\"action\":\"escalate\",\"count\":5,\"window\":60,\"ttl\":900}";
        let (policy, dropped) = Policy::parse(ok);
        assert_eq!(dropped, 0);
        let want = Action::Escalate { count: 5, window: 60, ttl: 900 };
        assert_eq!(policy.decide(&alert(1)).map(|d| d.action), Some(want));
        let (_, zero) = Policy::parse("{\"action\":\"escalate\",\"count\":0,\"window\":60,\"ttl\":9}");
        assert_eq!(zero, 1);
    }
}
