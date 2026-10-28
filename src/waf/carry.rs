//! Stage 11: one request whose head has been read, from the source-address
//! rules to the answer. See `server.rs` for the connection around it.

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;

use crate::flow::service_log;

use super::audit::{record, request_id, Action, Facts};
use super::config::Mode;
use super::engine::{inspect, Policy, Request, Verdict};
use super::forward::{forward, respond, Carry, Forwarded};
use super::gate::{decide, note_block, Gate};
use super::http::{Body, Framing, Head, RequestLine, Version};
use super::limits::client_ip;
use super::live::Inputs;
use super::request::{client_keep_alive, read_prefix, target_parts};
use super::server::{Next, Reader, Shared, PANIC_NEXT};

/// What one request looks like to the log, apart from the verdict.
pub struct Seen<'a> {
    pub id: &'a str,
    pub ip: IpAddr,
    pub head: &'a Head,
    pub line: &'a RequestLine,
    pub path: &'a str,
    pub query_len: usize,
    pub body_len: u64,
}

/// Append one audit line; a failure to write is said, not fatal.
pub fn write_audit(
    shared: &Shared,
    seen: &Seen<'_>,
    status: u16,
    action: Action,
    upstream_ms: Option<u64>,
    verdict: &Verdict,
    flags: &[&'static str],
) {
    let ip_text = seen.ip.to_string();
    let mut host = "";
    if let Some(found) = seen.head.first_value("host") {
        host = found;
    }
    let facts = Facts {
        id: seen.id.to_owned(),
        ip: &ip_text,
        host,
        method: &seen.line.method,
        path: seen.path,
        query_len: seen.query_len,
        body_len: seen.body_len,
        status,
        action,
        mode: shared.settings.mode.as_str(),
        upstream_ms,
    };
    let written = record(facts, verdict, flags).and_then(|r| shared.audit.write(&r));
    if let Err(e) = written {
        service_log(&format!("packetdeath: [warn] waf {e}"));
    }
}

/// Judge a request. A panic in the judge lets the request through.
fn judge(shared: &Shared, inputs: &Inputs, request: &Request) -> (Verdict, Vec<&'static str>) {
    let policy = Policy {
        paranoia: shared.settings.paranoia,
        threshold: shared.settings.threshold,
    };
    let judged = catch_unwind(AssertUnwindSafe(|| {
        if PANIC_NEXT.swap(false, Ordering::SeqCst) {
            panic!("injected judge panic");
        }
        inspect(request, &inputs.rules, policy, &inputs.exclusions)
    }));
    match judged {
        Ok(verdict) => (verdict, Vec::new()),
        Err(_) => {
            service_log("packetdeath: [error] waf judge panicked; the request is let through");
            (Verdict::default(), vec!["engine_error"])
        }
    }
}

/// Answer a head the WAF will not carry, and log it.
pub fn refuse_head(
    shared: &Shared,
    writer: &mut TcpStream,
    peer: SocketAddr,
    status: u16,
    flag: &'static str,
) {
    let id = request_id(shared.started_secs);
    let bare = Head::default();
    let line = RequestLine {
        method: String::from("-"),
        target: String::from("-"),
        version: Version::Http11,
    };
    let seen = Seen {
        id: &id,
        ip: peer.ip(),
        head: &bare,
        line: &line,
        path: "",
        query_len: 0,
        body_len: 0,
    };
    // The peer may already be gone; the audit line is what matters.
    let _ = respond(writer, status, &id, &[], false);
    let none = Verdict::default();
    write_audit(shared, &seen, status, Action::Protocol, None, &none, &[flag]);
}

fn read_failure_status(error: &io::Error) -> u16 {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        408
    } else {
        400
    }
}

/// Audit and answer according to how forwarding ended.
fn finish(
    shared: &Shared,
    writer: &mut TcpStream,
    seen: &Seen<'_>,
    action: Action,
    verdict: &Verdict,
    flags: &mut Vec<&'static str>,
    sent: Forwarded,
) -> Next {
    let (status, upstream_ms, next, flag) = match sent {
        Forwarded::Done {
            status,
            upstream_ms,
            keep_alive,
        } => {
            let next = if keep_alive { Next::KeepAlive } else { Next::Close };
            (status, Some(upstream_ms), next, None)
        }
        Forwarded::BadGateway => (502, None, Next::Close, Some("upstream_unreachable")),
        Forwarded::GatewayTimeout => (504, None, Next::Close, Some("upstream_timeout")),
        Forwarded::BodyTooLarge => (413, None, Next::Close, Some("body_too_large")),
        Forwarded::Broken => (502, None, Next::Close, Some("broken")),
    };
    let mut logged = action;
    if let Some(flag) = flag {
        flags.push(flag);
        logged = Action::Pass;
        if flag != "broken" {
            // The answer had not started, so there is room for a status.
            let _ = respond(writer, status, seen.id, &[], false);
        }
    }
    write_audit(shared, seen, status, logged, upstream_ms, verdict, flags);
    next
}

/// What is known about a request once its head is read.
pub struct Parsed<'a> {
    pub head: &'a Head,
    pub line: &'a RequestLine,
    pub framing: Framing,
}

/// Carry one request: gate, read the inspected body, judge, forward.
pub fn carry_request(
    shared: &Shared,
    reader: &mut Reader,
    writer: &mut TcpStream,
    peer: SocketAddr,
    parsed: &Parsed<'_>,
) -> Next {
    let (head, line, framing) = (parsed.head, parsed.line, parsed.framing);
    let inputs = shared.live.snapshot();
    let id = request_id(shared.started_secs);
    let (path, query) = target_parts(&line.target);
    let ip = client_ip(peer.ip(), head.first_value("x-forwarded-for"), &inputs.trust);
    let mut seen = Seen {
        id: &id,
        ip,
        head,
        line,
        path: &path,
        query_len: query.len(),
        body_len: 0,
    };
    let none = Verdict::default();
    let skip = match decide(&shared.limiter, &shared.clock, &inputs, ip) {
        Gate::Refuse { action, status, extra } => {
            // The unread body makes this connection unusable for another request.
            let _ = respond(writer, status, &id, &extra, false);
            write_audit(shared, &seen, status, action, None, &none, &[]);
            return Next::Close;
        }
        Gate::Skip => true,
        Gate::Inspect => false,
    };
    let wants_continue = head
        .values("expect")
        .any(|v| v.eq_ignore_ascii_case("100-continue"));
    if wants_continue && writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").is_err() {
        return Next::Close;
    }
    let mut body = Body::new(reader, framing);
    let cap = shared.settings.max_body_inspect;
    let prefix = match read_prefix(&mut body, cap) {
        Ok(prefix) => prefix,
        Err(e) => {
            let status = read_failure_status(&e);
            let _ = respond(writer, status, &id, &[], false);
            write_audit(shared, &seen, status, Action::Protocol, None, &none, &["body_read"]);
            return Next::Close;
        }
    };
    seen.body_len = prefix.len() as u64;
    let request = Request {
        method: line.method.clone(),
        path: path.clone(),
        query: query.clone(),
        headers: head.headers.clone(),
        body: prefix[..prefix.len().min(cap)].to_vec(),
        body_truncated: prefix.len() > cap || !body.is_finished(),
        http11: line.version == Version::Http11,
    };
    let (verdict, mut flags) = if skip || shared.settings.mode == Mode::Off {
        (Verdict::default(), Vec::new())
    } else {
        judge(shared, &inputs, &request)
    };
    if verdict.over_threshold && shared.settings.mode == Mode::Block {
        if note_block(&shared.limiter, &shared.clock, ip) {
            service_log(&format!("packetdeath: [info] waf ban {ip}"));
        }
        let _ = respond(writer, 403, &id, &[], false);
        write_audit(shared, &seen, 403, Action::Block, None, &verdict, &flags);
        return Next::Close;
    }
    let action = if verdict.over_threshold { Action::Detect } else { Action::Pass };
    let peer_text = peer.ip().to_string();
    let carry = Carry {
        head,
        line,
        framing,
        prefix: &prefix,
        max_body: shared.settings.max_body,
        request_id: &id,
        peer: &peer_text,
        client_keep_alive: client_keep_alive(head, line),
    };
    let sent = forward(&carry, &shared.settings.upstream, &mut body, writer);
    finish(shared, writer, &seen, action, &verdict, &mut flags, sent)
}
