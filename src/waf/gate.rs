//! Stage 11: what the source-address rules say about a request.
//!
//! `docs/design.md` "段階11 WAF" source IP の制御. Order: the allow list (no
//! judgment, no rate limit), the deny list, the ban table, the rate limit.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use super::audit::Action;
use super::limits::{Limiter, Take};
use super::live::Inputs;

/// The decision for one source address.
#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    /// Judge the request.
    Inspect,
    /// On the allow list: forward without judging.
    Skip,
    /// Answer without carrying the request.
    Refuse {
        action: Action,
        status: u16,
        extra: Vec<(String, String)>,
    },
}

fn lock(limiter: &Mutex<Limiter>) -> std::sync::MutexGuard<'_, Limiter> {
    match limiter.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn refuse(action: Action, status: u16) -> Gate {
    Gate::Refuse {
        action,
        status,
        extra: Vec::new(),
    }
}

/// Decide for `ip`. `clock` is the server's start; the limiter counts time from it.
pub fn decide(limiter: &Mutex<Limiter>, clock: &Instant, inputs: &Inputs, ip: IpAddr) -> Gate {
    if inputs.allow.contains(&ip) {
        return Gate::Skip;
    }
    if inputs.deny.contains(&ip) {
        return refuse(Action::DenyIp, 403);
    }
    let now_ms = clock.elapsed().as_millis() as u64;
    let mut limiter = lock(limiter);
    if limiter.is_banned(ip, now_ms) {
        return refuse(Action::Ban, 403);
    }
    match limiter.take(ip, now_ms) {
        Take::Allowed => Gate::Inspect,
        Take::Limited { retry_after_secs } => Gate::Refuse {
            action: Action::RateLimit,
            status: 429,
            extra: vec![("Retry-After".to_owned(), retry_after_secs.to_string())],
        },
    }
}

/// Count one block against `ip`; true when it earned a ban.
pub fn note_block(limiter: &Mutex<Limiter>, clock: &Instant, ip: IpAddr) -> bool {
    let now_ms = clock.elapsed().as_millis() as u64;
    lock(limiter).record_block(ip, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iplist::IpList;
    use crate::waf::limits::{LimitConfig, RateSpec};
    use crate::waf::rules::RuleSet;
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn inputs(allow: &str, deny: &str) -> Result<Inputs, Box<dyn std::error::Error>> {
        Ok(Inputs {
            rules: Arc::new(RuleSet::builtin_only()?),
            exclusions: Arc::new(Vec::new()),
            allow: Arc::new(IpList::parse(allow)),
            deny: Arc::new(IpList::parse(deny)),
            trust: Arc::new(IpList::empty()),
        })
    }

    fn limiter(rate: Option<RateSpec>, ban_after: u32) -> Mutex<Limiter> {
        Mutex::new(Limiter::new(LimitConfig {
            rate,
            ban_after,
            ban_window_ms: 60_000,
            ban_ttl_ms: 60_000,
            cap: 64,
        }))
    }

    #[test]
    fn an_ordinary_source_is_inspected() -> TestResult {
        let g = decide(&limiter(None, 0), &Instant::now(), &inputs("", "")?, "203.0.113.5".parse()?);
        assert_eq!(g, Gate::Inspect);
        Ok(())
    }

    #[test]
    fn an_allowed_source_skips_judgment_and_the_rate_limit() -> TestResult {
        let lim = limiter(Some(RateSpec { count: 1, per_ms: 60_000 }), 0);
        let inp = inputs("203.0.113.0/24\n", "")?;
        let clock = Instant::now();
        for _ in 0..5 {
            assert_eq!(decide(&lim, &clock, &inp, "203.0.113.5".parse()?), Gate::Skip);
        }
        Ok(())
    }

    #[test]
    fn the_allow_list_wins_over_the_deny_list() -> TestResult {
        let inp = inputs("203.0.113.5\n", "203.0.113.0/24\n")?;
        let g = decide(&limiter(None, 0), &Instant::now(), &inp, "203.0.113.5".parse()?);
        assert_eq!(g, Gate::Skip);
        Ok(())
    }

    #[test]
    fn a_denied_source_is_refused_with_403() -> TestResult {
        let inp = inputs("", "198.51.100.0/24\n")?;
        let g = decide(&limiter(None, 0), &Instant::now(), &inp, "198.51.100.9".parse()?);
        assert_eq!(g, Gate::Refuse { action: Action::DenyIp, status: 403, extra: Vec::new() });
        Ok(())
    }

    #[test]
    fn the_sixth_request_in_a_second_is_429_with_retry_after() -> TestResult {
        let lim = limiter(Some(RateSpec { count: 5, per_ms: 1000 }), 0);
        let inp = inputs("", "")?;
        let clock = Instant::now();
        let ip = "203.0.113.5".parse()?;
        for _ in 0..5 {
            assert_eq!(decide(&lim, &clock, &inp, ip), Gate::Inspect);
        }
        let g = decide(&lim, &clock, &inp, ip);
        assert_eq!(
            g,
            Gate::Refuse {
                action: Action::RateLimit,
                status: 429,
                extra: vec![("Retry-After".into(), "1".into())],
            }
        );
        Ok(())
    }

    #[test]
    fn three_blocks_make_a_ban_and_the_next_request_is_refused() -> TestResult {
        let lim = limiter(None, 3);
        let clock = Instant::now();
        let ip = "203.0.113.5".parse()?;
        assert!(!note_block(&lim, &clock, ip));
        assert!(!note_block(&lim, &clock, ip));
        assert!(note_block(&lim, &clock, ip));
        let g = decide(&lim, &clock, &inputs("", "")?, ip);
        assert_eq!(g, Gate::Refuse { action: Action::Ban, status: 403, extra: Vec::new() });
        Ok(())
    }
}
