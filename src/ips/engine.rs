//! Stage 12: the decision for one alert. `docs/design.md`
//! "段階12 IDS/IPS の業務水準化".
//!
//! Policy says what to do, never-block can veto a drop, escalation counts
//! before it drops, and the drop set remembers. The engine holds no clock and
//! no file: the caller passes `now` and writes the audit line.

use super::audit::Event;
use super::dropset::DropSet;
use super::escalate::Escalator;
use super::never::{Protected, Why};
use super::policy::{Action, AlertInfo, Policy};

/// What was decided for one alert.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub event: Event,
    /// Line of the deciding policy rule (`None`: no rule matched).
    pub rule: Option<usize>,
    /// Seconds the destination is dropped, for `Drop` and `Escalated`.
    pub ttl: Option<u64>,
    /// Entries that left the drop set to make room.
    pub evicted: usize,
    /// Why the destination was protected.
    pub why: Option<Why>,
}

/// The pieces of one IPS.
pub struct Engine {
    pub policy: Policy,
    pub never: Protected,
    pub escalator: Escalator,
    pub drops: DropSet,
    /// What an alert no rule matched gets.
    pub default_action: Action,
    /// TTL of a drop whose rule gives none.
    pub default_ttl: u64,
}

impl Engine {
    /// Decide one alert at `now` (seconds since the epoch) and record a drop.
    pub fn handle(&mut self, alert: &AlertInfo, now: u64) -> Outcome {
        let decision = self.policy.decide(alert);
        let rule = decision.as_ref().map(|d| d.line);
        let action = match decision {
            Some(d) => d.action,
            None => self.default_action,
        };
        match action {
            Action::Ignore => self.outcome(Event::Ignored, rule, None),
            Action::Alert => self.outcome(Event::Observed, rule, None),
            Action::Drop { ttl } => self.drop(alert, now, rule, ttl, Event::Drop),
            Action::Escalate { count, window, ttl } => {
                let key = (alert.src_ip, alert.dst_ip, alert.sid);
                if self.escalator.record(key, now, count, window) {
                    self.drop(alert, now, rule, Some(ttl), Event::Escalated)
                } else {
                    self.outcome(Event::Observed, rule, None)
                }
            }
        }
    }

    fn outcome(&self, event: Event, rule: Option<usize>, ttl: Option<u64>) -> Outcome {
        Outcome { event, rule, ttl, evicted: 0, why: None }
    }

    fn drop(&mut self, alert: &AlertInfo, now: u64, rule: Option<usize>, ttl: Option<u64>, event: Event) -> Outcome {
        if let Some(why) = self.never.why(&alert.dst_ip) {
            return Outcome { event: Event::Protected, rule, ttl: None, evicted: 0, why: Some(why) };
        }
        let seconds = match ttl {
            Some(own) => own,
            None => self.default_ttl,
        };
        let inserted = self.drops.insert(alert.dst_ip, alert.dst_port, now, seconds);
        Outcome { event, rule, ttl: Some(seconds), evicted: inserted.evicted, why: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn alert(sid: u64, dst: IpAddr) -> AlertInfo {
        AlertInfo {
            sid,
            severity: Some(1),
            classtype: None,
            category: None,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))),
            dst_ip: dst,
            dst_port: 443,
            proto: None,
        }
    }

    fn public() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
    }

    fn engine(policy: &str, default_action: Action) -> Engine {
        Engine {
            policy: Policy::parse(policy).0,
            never: Protected::new(false, Vec::new()),
            escalator: Escalator::new(64),
            drops: DropSet::new(64),
            default_action,
            default_ttl: 600,
        }
    }

    #[test]
    fn an_alert_no_rule_matches_gets_the_default_and_a_default_alert_drops_nothing() {
        let mut e = engine("", Action::Alert);
        let o = e.handle(&alert(1, public()), 100);
        assert_eq!((o.event, o.rule), (Event::Observed, None));
        assert!(e.drops.is_empty());
    }

    #[test]
    fn drop_uses_the_rule_ttl_or_the_default_and_the_set_remembers() {
        let mut e = engine("{\"sid\":1,\"action\":\"drop\",\"ttl\":60}\n{\"sid\":2,\"action\":\"drop\"}", Action::Alert);
        assert_eq!(e.handle(&alert(1, public()), 100).ttl, Some(60));
        assert!(e.drops.contains(&public(), 443, 159) && !e.drops.contains(&public(), 443, 160));
        assert_eq!(e.handle(&alert(2, public()), 100).ttl, Some(600));
    }

    #[test]
    fn ignore_leaves_no_trace_and_alert_only_observes() {
        let mut e = engine("{\"sid\":1,\"action\":\"ignore\"}\n{\"sid\":2,\"action\":\"alert\"}", Action::Drop { ttl: None });
        assert_eq!(e.handle(&alert(1, public()), 0).event, Event::Ignored);
        assert_eq!(e.handle(&alert(2, public()), 0).event, Event::Observed);
        assert!(e.drops.is_empty());
        assert_eq!(e.handle(&alert(3, public()), 0).event, Event::Drop);
    }

    #[test]
    fn a_protected_destination_is_never_dropped_whatever_the_rule_says() {
        let mut e = engine("{\"action\":\"drop\"}", Action::Alert);
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let o = e.handle(&alert(1, lan), 0);
        assert_eq!((o.event, o.why), (Event::Protected, Some(Why::Private)));
        let lo = e.handle(&alert(1, IpAddr::V4(Ipv4Addr::LOCALHOST)), 0);
        assert_eq!(lo.why, Some(Why::Special));
        assert!(e.drops.is_empty());
    }

    #[test]
    fn escalate_observes_until_the_count_then_drops_with_its_ttl() {
        let mut e = engine("{\"action\":\"escalate\",\"count\":3,\"window\":60,\"ttl\":900}", Action::Alert);
        let kinds: Vec<Event> = (0..3).map(|i| e.handle(&alert(1, public()), 10 + i).event).collect();
        assert_eq!(kinds, vec![Event::Observed, Event::Observed, Event::Escalated]);
        assert!(e.drops.contains(&public(), 443, 100));
    }

    #[test]
    fn a_full_drop_set_reports_what_it_evicted() {
        let mut e = engine("{\"action\":\"drop\"}", Action::Alert);
        e.drops = DropSet::new(2);
        let at = |n: u8| IpAddr::V4(Ipv4Addr::new(203, 0, 113, n));
        e.handle(&alert(1, at(1)), 0);
        e.handle(&alert(1, at(2)), 0);
        assert_eq!(e.handle(&alert(1, at(3)), 0).evicted, 1);
    }
}
