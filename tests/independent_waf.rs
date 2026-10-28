//! Stage 11 acceptance over real sockets: PK-150, 151, 155, 156, 157.
//! `docs/design.md` "段階11 WAF" 受入 ID. The rest are in `independent_waf_more.rs`.

mod waf_support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use waf_support::{audit_lines, exchange, get, scratch, serial, upstream, waf, TestResult};

const ATTACK: &str = "/?q=1%27%20union%20select%20password%20from%20users--";

#[test]
fn pk150_detect_lets_an_attack_through_and_logs_it() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk150")?);
    let running = waf(up.port, &dir, "--mode detect")?;
    let reply = get(running.addr, ATTACK)?;
    assert_eq!(reply.status, 200);
    assert_eq!(up.seen.load(Ordering::SeqCst), 1);
    let lines = audit_lines(&dir, 1)?;
    assert_eq!(lines[0]["action"], "detect");
    let rules = lines[0]["rules"].to_string();
    assert!(rules.contains("9421"), "{rules}");
    running.stop();
    Ok(())
}

#[test]
fn pk150_negative_control_a_plain_request_is_a_pass() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk150n")?);
    let running = waf(up.port, &dir, "--mode block")?;
    assert_eq!(get(running.addr, "/shop?q=blue+shoes")?.status, 200);
    assert_eq!(audit_lines(&dir, 1)?[0]["action"], "pass");
    running.stop();
    Ok(())
}

#[test]
fn pk151_block_answers_403_and_the_upstream_sees_nothing() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk151")?);
    let running = waf(up.port, &dir, "--mode block")?;
    let reply = get(running.addr, ATTACK)?;
    assert_eq!(reply.status, 403);
    assert!(reply.text.contains("X-Request-Id:"));
    assert_eq!(up.seen.load(Ordering::SeqCst), 0);
    assert_eq!(audit_lines(&dir, 1)?[0]["action"], "block");
    running.stop();
    Ok(())
}

#[test]
fn the_upstream_gets_the_request_id_and_the_forwarded_chain() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("headers")?);
    let running = waf(up.port, &dir, "")?;
    let raw = "GET / HTTP/1.1\r\nHost: t.test\r\nX-Request-Id: forged\r\nConnection: close\r\n\r\n";
    assert_eq!(exchange(running.addr, raw.as_bytes())?.status, 200);
    let head = up.last_head.lock().map_err(|_| "lock")?.clone();
    assert!(head.contains("X-Forwarded-For: 127.0.0.1"), "{head}");
    assert!(!head.contains("forged"), "{head}");
    assert_eq!(head.matches("X-Request-Id").count(), 1);
    running.stop();
    Ok(())
}

#[test]
fn pk155_content_length_with_transfer_encoding_is_400_and_never_forwarded() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk155a")?);
    let running = waf(up.port, &dir, "")?;
    let raw = "POST / HTTP/1.1\r\nHost: t.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    assert_eq!(exchange(running.addr, raw.as_bytes())?.status, 400);
    let twice = "POST / HTTP/1.1\r\nHost: t.test\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nabcd";
    assert_eq!(exchange(running.addr, twice.as_bytes())?.status, 400);
    assert_eq!(up.seen.load(Ordering::SeqCst), 0);
    assert_eq!(audit_lines(&dir, 2)?[0]["action"], "protocol");
    running.stop();
    Ok(())
}

#[test]
fn pk155_a_head_over_16_kib_is_431_and_a_body_over_the_limit_is_413() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk155b")?);
    let running = waf(up.port, &dir, "--max-body 1000")?;
    let big = format!("GET / HTTP/1.1\r\nHost: t.test\r\nX-Pad: {}\r\n\r\n", "a".repeat(17_000));
    assert_eq!(exchange(running.addr, big.as_bytes())?.status, 431);
    let long = "POST / HTTP/1.1\r\nHost: t.test\r\nContent-Length: 5000\r\n\r\n";
    assert_eq!(exchange(running.addr, long.as_bytes())?.status, 413);
    assert_eq!(up.seen.load(Ordering::SeqCst), 0);
    running.stop();
    Ok(())
}

#[test]
fn pk155_a_bare_lf_and_an_unknown_version_are_refused() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk155c")?);
    let running = waf(up.port, &dir, "")?;
    assert_eq!(exchange(running.addr, b"GET / HTTP/1.1\nHost: t.test\n\n")?.status, 400);
    assert_eq!(exchange(running.addr, b"GET / HTTP/2.0\r\nHost: t.test\r\n\r\n")?.status, 505);
    assert_eq!(up.seen.load(Ordering::SeqCst), 0);
    running.stop();
    Ok(())
}

#[test]
fn pk156_the_sixth_request_in_a_second_is_429_and_it_recovers() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk156a")?);
    let running = waf(up.port, &dir, "--rate 5/1")?;
    for _ in 0..5 {
        assert_eq!(get(running.addr, "/")?.status, 200);
    }
    let limited = get(running.addr, "/")?;
    assert_eq!(limited.status, 429);
    assert!(limited.text.contains("Retry-After: 1"), "{}", limited.text);
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(get(running.addr, "/")?.status, 200);
    running.stop();
    Ok(())
}

#[test]
fn pk156_three_blocks_ban_the_source_until_the_ttl_ends() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk156b")?);
    let running = waf(up.port, &dir, "--mode block --ban-after 3 --ban-ttl 2")?;
    for _ in 0..3 {
        assert_eq!(get(running.addr, ATTACK)?.status, 403);
    }
    assert_eq!(get(running.addr, "/")?.status, 403);
    let lines = audit_lines(&dir, 4)?;
    assert_eq!(lines[3]["action"], "ban");
    std::thread::sleep(Duration::from_millis(2200));
    assert_eq!(get(running.addr, "/")?.status, 200);
    running.stop();
    Ok(())
}

#[test]
fn pk157_an_allowed_source_passes_an_attack_and_a_denied_one_is_refused() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk157")?);
    let allow = dir.join("allow.txt");
    let deny = dir.join("deny.txt");
    std::fs::write(&allow, "127.0.0.1\n")?;
    std::fs::write(&deny, "10.9.9.9\n")?;
    let extra = format!("--mode block --allow-ip {} --deny-ip {}", allow.display(), deny.display());
    let running = waf(up.port, &dir, &extra)?;
    assert_eq!(get(running.addr, ATTACK)?.status, 200);
    running.stop();

    std::fs::write(&allow, "")?;
    std::fs::write(&deny, "127.0.0.1\n")?;
    let (up2, dir2) = (upstream()?, scratch("pk157b")?);
    let extra = format!("--allow-ip {} --deny-ip {}", allow.display(), deny.display());
    let running = waf(up2.port, &dir2, &extra)?;
    assert_eq!(get(running.addr, "/")?.status, 403);
    assert_eq!(up2.seen.load(Ordering::SeqCst), 0);
    assert_eq!(audit_lines(&dir2, 1)?[0]["action"], "deny-ip");
    running.stop();
    Ok(())
}
