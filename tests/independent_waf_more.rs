//! Stage 11 acceptance over real sockets: PK-154, 158, 159, 160, 162.
//! `docs/design.md` "段階11 WAF" 受入 ID. The rest are in `independent_waf.rs`.

mod waf_support;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use packetdeath::waf::server::PANIC_NEXT;
use waf_support::{audit_lines, exchange, get, scratch, serial, upstream, waf, Reply, TestResult};

fn post(addr: SocketAddr, kind: &str, body: &[u8]) -> Result<Reply, Box<dyn std::error::Error>> {
    let head = format!(
        "POST /submit HTTP/1.1\r\nHost: t.test\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut raw = head.into_bytes();
    raw.extend_from_slice(body);
    exchange(addr, &raw)
}

#[test]
fn pk154_attacks_in_urlencoded_json_and_multipart_bodies_are_blocked() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk154a")?);
    let running = waf(up.port, &dir, "--mode block")?;
    let addr = running.addr;
    let form = b"user=a&pw=%27+or+1%3D1";
    assert_eq!(post(addr, "application/x-www-form-urlencoded", form)?.status, 403);
    let json = br#"{"a":{"b":[1,{"c":"<script>alert(1)</script>"}]}}"#;
    assert_eq!(post(addr, "application/json", json)?.status, 403);
    let multi = "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\nxx\r\n--B--\r\n";
    assert_eq!(post(addr, "multipart/form-data; boundary=B", multi.as_bytes())?.status, 403);
    let benign = r#"{"name":"Tanaka","note":"日本語の本文です"}"#;
    assert_eq!(post(addr, "application/json", benign.as_bytes())?.status, 200);
    assert_eq!(up.seen.load(Ordering::SeqCst), 1);
    running.stop();
    Ok(())
}

#[test]
fn pk154_an_attack_past_the_inspected_prefix_passes_and_says_so() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk154b")?);
    let running = waf(up.port, &dir, "--mode block --max-body-inspect 1024")?;
    let attack = "<script>alert(1)</script>";
    let early = format!("{attack}{}", "a".repeat(3000));
    assert_eq!(post(running.addr, "text/plain", early.as_bytes())?.status, 403);
    let late = format!("{}{attack}", "a".repeat(70_000));
    assert_eq!(post(running.addr, "text/plain", late.as_bytes())?.status, 200);
    let lines = audit_lines(&dir, 2)?;
    let flags = lines[1]["flags"].to_string();
    assert!(flags.contains("body_truncated"), "{flags}");
    running.stop();
    Ok(())
}

fn wait_for_status(addr: SocketAddr, target: &str, want: u16) -> Result<bool, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_millis(2500);
    while Instant::now() < deadline {
        if get(addr, target)?.status == want {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(false)
}

#[test]
fn pk158_rewriting_the_rules_and_exclusions_changes_the_answer_within_a_second_or_two() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk158")?);
    let rules = dir.join("rules.jsonl");
    let exclusions = dir.join("exclusions.jsonl");
    std::fs::write(&rules, "")?;
    std::fs::write(&exclusions, "")?;
    let extra = format!("--mode block --rules {} --exclusions {}", rules.display(), exclusions.display());
    let running = waf(up.port, &dir, &extra)?;
    let word = "/?q=forbidden-word";
    assert_eq!(get(running.addr, word)?.status, 200);

    let rule = r#"{"id":990001,"target":"query","pattern":"forbidden-word","severity":"critical","paranoia":1,"message":"mine"}"#;
    std::fs::write(&rules, format!("{rule}\n"))?;
    assert!(wait_for_status(running.addr, word, 403)?, "the new rule never took effect");

    let skip = r#"{"rule":990001,"path_prefix":"/"}"#;
    std::fs::write(&exclusions, format!("{skip}\n"))?;
    assert!(wait_for_status(running.addr, word, 200)?, "the exclusion never took effect");

    std::fs::write(&exclusions, "")?;
    assert!(wait_for_status(running.addr, word, 403)?, "emptying the exclusions did not restore the rule");
    std::fs::remove_file(&rules)?;
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(get(running.addr, word)?.status, 403, "a vanished file must leave the old rules in use");
    running.stop();
    Ok(())
}

fn closed_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

#[test]
fn pk159_a_dead_upstream_is_502_and_the_waf_keeps_serving() -> TestResult {
    let _held = serial();
    let dir = scratch("pk159a")?;
    let running = waf(closed_port()?, &dir, "")?;
    assert_eq!(get(running.addr, "/")?.status, 502);
    assert_eq!(get(running.addr, "/")?.status, 502);
    let lines = audit_lines(&dir, 2)?;
    assert!(lines[0]["flags"].to_string().contains("upstream_unreachable"));
    running.stop();
    Ok(())
}

#[test]
fn pk159_a_panic_in_the_judge_lets_the_request_through_with_engine_error() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk159b")?);
    let running = waf(up.port, &dir, "--mode block")?;
    PANIC_NEXT.store(true, Ordering::SeqCst);
    let attack = "/?q=1%27%20union%20select%20password%20from%20users--";
    assert_eq!(get(running.addr, attack)?.status, 200);
    let lines = audit_lines(&dir, 1)?;
    assert!(lines[0]["flags"].to_string().contains("engine_error"));
    assert_eq!(get(running.addr, attack)?.status, 403, "the next request is judged again");
    running.stop();
    Ok(())
}

#[test]
fn pk160_the_audit_has_one_unique_line_per_request_and_no_secret() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk160")?);
    let running = waf(up.port, &dir, "--mode block")?;
    for n in 0..200 {
        let raw = format!(
            "POST /a/{n}?token=SECRETVALUE&q=1%27%20or%201%3D1 HTTP/1.1\r\nHost: t.test\r\nCookie: sid=SECRETVALUE\r\nAuthorization: Bearer SECRETVALUE\r\nContent-Length: 18\r\nConnection: close\r\n\r\npw=SECRETVALUE&x=1"
        );
        exchange(running.addr, raw.as_bytes())?;
    }
    let lines = audit_lines(&dir, 200)?;
    assert_eq!(lines.len(), 200);
    let ids: HashSet<String> = lines.iter().map(|l| l["id"].to_string()).collect();
    assert_eq!(ids.len(), 200);
    let text = std::fs::read_to_string(dir.join("waf.jsonl"))?;
    assert_eq!(text.matches("SECRETVALUE").count(), 0);
    assert!(lines.iter().all(|l| l["action"] == "block"));
    running.stop();
    Ok(())
}

#[test]
fn pk162_the_fifth_connection_over_max_conns_4_is_503() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk162a")?);
    let running = waf(up.port, &dir, "--max-conns 4")?;
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(TcpStream::connect(running.addr)?);
    }
    std::thread::sleep(Duration::from_millis(300));
    let mut fifth = TcpStream::connect(running.addr)?;
    fifth.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut data = Vec::new();
    // The WAF closes the turned-away connection after its 503.
    let _ = fifth.read_to_end(&mut data);
    let text = String::from_utf8_lossy(&data);
    assert!(text.starts_with("HTTP/1.1 503"), "{text}");
    drop(held);
    running.stop();
    Ok(())
}

#[test]
fn pk162_a_head_sent_one_byte_a_second_is_cut_at_about_ten_seconds() -> TestResult {
    let _held = serial();
    let (up, dir) = (upstream()?, scratch("pk162b")?);
    let running = waf(up.port, &dir, "")?;
    let mut slow = TcpStream::connect(running.addr)?;
    slow.set_read_timeout(Some(Duration::from_millis(200)))?;
    let started = Instant::now();
    let mut said = Vec::new();
    let line = b"GET / HTTP/1.1\r\nHost: slow.test\r\nX-Slow: yes-this-takes-a-while";
    for byte in line.iter().cycle() {
        if started.elapsed() > Duration::from_secs(14) {
            break;
        }
        if slow.write_all(&[*byte]).is_err() {
            break;
        }
        let mut chunk = [0u8; 256];
        match slow.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                said.extend_from_slice(&chunk[..n]);
                break;
            }
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(800));
    }
    let took = started.elapsed();
    let text = String::from_utf8_lossy(&said);
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(took >= Duration::from_secs(9) && took < Duration::from_secs(13), "{took:?}");
    assert_eq!(up.seen.load(Ordering::SeqCst), 0);
    running.stop();
    Ok(())
}
