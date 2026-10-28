//! Stage 11: carrying one request to the upstream and its answer back.
//!
//! `docs/design.md` "段階11 WAF" 上流. The WAF re-writes the request instead of
//! relaying bytes: it writes only the headers it understood, with its own
//! framing, so a request that is read one way here cannot be read another way
//! by the upstream. The upstream gets `Connection: close` and one request per
//! connection; the client side keeps its connection open when it can.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use super::config::{CONNECT_TIMEOUT, UPSTREAM_IDLE};
use super::http::{
    is_hop_by_hop, parse_status_line, read_head, response_framing, write_chunk, write_head,
    write_last_chunk, Body, Framing, Head, HeadError, RequestLine,
};

/// Longest time a write to either side may take.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// What came of forwarding one request.
#[derive(Debug)]
pub enum Forwarded {
    /// The answer was sent. `keep_alive` says whether the client connection
    /// may carry another request.
    Done {
        status: u16,
        upstream_ms: u64,
        keep_alive: bool,
    },
    /// The upstream could not be reached or sent nothing usable (502).
    BadGateway,
    /// The upstream did not answer in time (504).
    GatewayTimeout,
    /// A chunked request body outgrew `--max-body` after forwarding began.
    BodyTooLarge,
    /// A connection broke after the answer had started; nothing more can be said.
    Broken,
}

/// The reason phrase for the statuses the WAF itself sends.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        408 => "Request Timeout",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

/// Send a short answer of the WAF's own and say the connection closes (or not).
pub fn respond<W: Write>(
    out: &mut W,
    status: u16,
    request_id: &str,
    extra: &[(String, String)],
    keep_alive: bool,
) -> io::Result<()> {
    let body = format!("{} {}\n", status, reason(status));
    let mut headers = vec![
        ("Content-Type".to_owned(), "text/plain; charset=utf-8".to_owned()),
        ("Content-Length".to_owned(), body.len().to_string()),
        ("X-Request-Id".to_owned(), request_id.to_owned()),
    ];
    if !keep_alive {
        headers.push(("Connection".to_owned(), "close".to_owned()));
    }
    headers.extend_from_slice(extra);
    write_head(out, &format!("HTTP/1.1 {status} {}", reason(status)), &headers)?;
    out.write_all(body.as_bytes())?;
    out.flush()
}

/// Open the upstream, trying every address `upstream` resolves to.
pub fn connect(upstream: &str) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "upstream resolves to nothing");
    for addr in upstream.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(UPSTREAM_IDLE))?;
                stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The headers the upstream is sent: what the WAF understood, minus the
/// hop-by-hop ones, plus its own.
pub fn upstream_headers(
    head: &Head,
    framing: Framing,
    request_id: &str,
    peer: &str,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(head.headers.len() + 4);
    let mut forwarded = String::new();
    for (name, value) in &head.headers {
        if name.eq_ignore_ascii_case("x-forwarded-for") {
            if !forwarded.is_empty() {
                forwarded.push_str(", ");
            }
            forwarded.push_str(value);
        } else if !is_hop_by_hop(name)
            && !name.eq_ignore_ascii_case("expect")
            && !name.eq_ignore_ascii_case("x-request-id")
        {
            out.push((name.clone(), value.clone()));
        }
    }
    if !forwarded.is_empty() {
        forwarded.push_str(", ");
    }
    forwarded.push_str(peer);
    out.push(("X-Forwarded-For".to_owned(), forwarded));
    out.push(("X-Request-Id".to_owned(), request_id.to_owned()));
    match framing {
        Framing::Length(n) => out.push(("Content-Length".to_owned(), n.to_string())),
        Framing::Chunked => out.push(("Transfer-Encoding".to_owned(), "chunked".to_owned())),
        Framing::None | Framing::UntilClose => {}
    }
    out.push(("Connection".to_owned(), "close".to_owned()));
    out
}

/// The headers the client is sent: the upstream's, minus the hop-by-hop ones
/// (the framing is written again below), plus the request id.
fn client_headers(
    head: &Head,
    framing: Framing,
    keep_head_length: bool,
    request_id: &str,
    keep_alive: bool,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(head.headers.len() + 3);
    for (name, value) in &head.headers {
        let keep = keep_head_length && name.eq_ignore_ascii_case("content-length");
        if keep || (!is_hop_by_hop(name) && !name.eq_ignore_ascii_case("x-request-id")) {
            out.push((name.clone(), value.clone()));
        }
    }
    match framing {
        Framing::Length(n) if !keep_head_length => {
            out.push(("Content-Length".to_owned(), n.to_string()));
        }
        Framing::Chunked => out.push(("Transfer-Encoding".to_owned(), "chunked".to_owned())),
        _ => {}
    }
    out.push(("X-Request-Id".to_owned(), request_id.to_owned()));
    if !keep_alive {
        out.push(("Connection".to_owned(), "close".to_owned()));
    }
    out
}

/// Copy the rest of a request body to the upstream. `sent` is what has gone
/// out already; the total may not pass `max_body`.
fn send_body<R: BufRead, W: Write>(
    body: &mut Body<'_, R>,
    out: &mut W,
    framing: Framing,
    mut sent: u64,
    max_body: u64,
) -> Result<(), Forwarded> {
    let mut piece = Vec::new();
    loop {
        match body.next_piece(&mut piece) {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => return Err(Forwarded::Broken),
        }
        sent += piece.len() as u64;
        if sent > max_body {
            return Err(Forwarded::BodyTooLarge);
        }
        let wrote = match framing {
            Framing::Chunked => write_chunk(out, &piece),
            _ => out.write_all(&piece),
        };
        if wrote.is_err() {
            return Err(Forwarded::Broken);
        }
    }
    if framing == Framing::Chunked && write_last_chunk(out).is_err() {
        return Err(Forwarded::Broken);
    }
    out.flush().map_err(|_| Forwarded::Broken)
}

/// Write the head and the part of the body already read.
fn send_request_start<W: Write>(
    out: &mut W,
    line: &RequestLine,
    headers: &[(String, String)],
    framing: Framing,
    prefix: &[u8],
) -> io::Result<()> {
    write_head(
        out,
        &format!("{} {} HTTP/1.1", line.method, line.target),
        headers,
    )?;
    if prefix.is_empty() {
        return Ok(());
    }
    match framing {
        Framing::Chunked => write_chunk(out, prefix),
        _ => out.write_all(prefix),
    }
}

/// Read the upstream's answer head, skipping interim `1xx` heads.
fn read_answer_head<R: BufRead>(input: &mut R) -> Result<(Head, u16), Forwarded> {
    loop {
        let head = match read_head(input) {
            Ok(head) => head,
            Err(HeadError::Timeout) => return Err(Forwarded::GatewayTimeout),
            Err(_) => return Err(Forwarded::BadGateway),
        };
        let Some(status) = parse_status_line(&head.first) else {
            return Err(Forwarded::BadGateway);
        };
        if status == 101 {
            return Err(Forwarded::BadGateway);
        }
        if !(100..200).contains(&status) {
            return Ok((head, status));
        }
    }
}

/// Stream the upstream's body to the client in the framing chosen for it.
fn relay_body<R: BufRead, W: Write>(
    answer: &mut Body<'_, R>,
    client: &mut W,
    framing: Framing,
) -> Result<(), Forwarded> {
    let mut piece = Vec::new();
    loop {
        match answer.next_piece(&mut piece) {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => return Err(Forwarded::Broken),
        }
        let wrote = match framing {
            Framing::Chunked => write_chunk(client, &piece),
            _ => client.write_all(&piece),
        };
        if wrote.is_err() {
            return Err(Forwarded::Broken);
        }
    }
    if framing == Framing::Chunked && write_last_chunk(client).is_err() {
        return Err(Forwarded::Broken);
    }
    client.flush().map_err(|_| Forwarded::Broken)
}

/// What the WAF knows about the request it is carrying.
pub struct Carry<'a> {
    pub head: &'a Head,
    pub line: &'a RequestLine,
    pub framing: Framing,
    /// Body bytes already read from the client (the inspected part).
    pub prefix: &'a [u8],
    pub max_body: u64,
    pub request_id: &'a str,
    pub peer: &'a str,
    /// The client connection may stay open after this answer.
    pub client_keep_alive: bool,
}

/// Send the request upstream and the answer back.
pub fn forward<R: BufRead, W: Write>(
    carry: &Carry<'_>,
    upstream: &str,
    request_body: &mut Body<'_, R>,
    client: &mut W,
) -> Forwarded {
    let started = Instant::now();
    let Ok(mut stream) = connect(upstream) else {
        return Forwarded::BadGateway;
    };
    let headers = upstream_headers(carry.head, carry.framing, carry.request_id, carry.peer);
    let start = send_request_start(&mut stream, carry.line, &headers, carry.framing, carry.prefix);
    if start.is_err() {
        return Forwarded::BadGateway;
    }
    let prefix_len = carry.prefix.len() as u64;
    if let Err(failed) = send_body(request_body, &mut stream, carry.framing, prefix_len, carry.max_body)
    {
        return failed;
    }
    let Ok(read_half) = stream.try_clone() else {
        return Forwarded::BadGateway;
    };
    let mut reader = BufReader::new(read_half);
    let (answer_head, status) = match read_answer_head(&mut reader) {
        Ok(found) => found,
        Err(failed) => return failed,
    };
    let upstream_ms = started.elapsed().as_millis() as u64;
    let head_request = carry.line.method == "HEAD";
    let framing = response_framing(&answer_head, status, head_request);
    let keep_alive = carry.client_keep_alive && framing != Framing::UntilClose;
    let out_headers = client_headers(&answer_head, framing, head_request, carry.request_id, keep_alive);
    if write_head(client, &answer_head.first, &out_headers).is_err() {
        return Forwarded::Broken;
    }
    let mut answer = Body::new(&mut reader, framing);
    let out_framing = if framing == Framing::UntilClose { Framing::None } else { framing };
    if let Err(failed) = relay_body(&mut answer, client, out_framing) {
        return failed;
    }
    Forwarded::Done {
        status,
        upstream_ms,
        keep_alive,
    }
}

/// A reader that gives up when a deadline passes, however slowly the peer
/// sends: each read is allowed only the time that is left.
pub struct DeadlineReader<R: Read> {
    inner: R,
    deadline: Option<Instant>,
    set_timeout: fn(&R, Option<Duration>) -> io::Result<()>,
}

impl<R: Read> DeadlineReader<R> {
    pub fn new(inner: R, set_timeout: fn(&R, Option<Duration>) -> io::Result<()>) -> Self {
        Self {
            inner,
            deadline: None,
            set_timeout,
        }
    }

    /// The whole message head must arrive before `deadline`.
    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "head deadline"));
            }
            (self.set_timeout)(&self.inner, Some(deadline - now))?;
        }
        self.inner.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::http::{parse_request_line, Version};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn head(lines: &[(&str, &str)]) -> Head {
        Head {
            first: "GET / HTTP/1.1".into(),
            headers: lines
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn names(headers: &[(String, String)]) -> Vec<String> {
        headers.iter().map(|(n, _)| n.to_ascii_lowercase()).collect()
    }

    #[test]
    fn the_upstream_gets_only_understood_headers_and_its_own_framing() {
        let h = head(&[
            ("Host", "a.test"),
            ("Connection", "keep-alive"),
            ("Transfer-Encoding", "chunked"),
            ("Content-Length", "5"),
            ("Expect", "100-continue"),
            ("X-Request-Id", "forged"),
            ("Accept", "*/*"),
        ]);
        let out = upstream_headers(&h, Framing::Length(5), "rid-1", "203.0.113.5");
        let n = names(&out);
        assert!(n.contains(&"host".into()) && n.contains(&"accept".into()));
        assert!(!n.contains(&"expect".into()) && !n.contains(&"transfer-encoding".into()));
        assert_eq!(n.iter().filter(|x| *x == "content-length").count(), 1);
        assert_eq!(n.iter().filter(|x| *x == "x-request-id").count(), 1);
        assert!(out.contains(&("X-Request-Id".into(), "rid-1".into())));
        assert!(out.contains(&("Connection".into(), "close".into())));
    }

    #[test]
    fn x_forwarded_for_keeps_the_chain_and_adds_the_peer() {
        let h = head(&[("X-Forwarded-For", "1.2.3.4"), ("x-forwarded-for", "5.6.7.8")]);
        let out = upstream_headers(&h, Framing::None, "r", "203.0.113.5");
        let found: Vec<&(String, String)> = out
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("x-forwarded-for"))
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, "1.2.3.4, 5.6.7.8, 203.0.113.5");
        let none = upstream_headers(&head(&[]), Framing::None, "r", "203.0.113.5");
        assert!(none.contains(&("X-Forwarded-For".into(), "203.0.113.5".into())));
    }

    #[test]
    fn a_chunked_request_is_sent_chunked() {
        let out = upstream_headers(&head(&[]), Framing::Chunked, "r", "1.1.1.1");
        assert!(out.contains(&("Transfer-Encoding".into(), "chunked".into())));
        assert!(!names(&out).contains(&"content-length".into()));
    }

    #[test]
    fn the_answer_to_the_client_is_re_framed() {
        let h = head(&[("Content-Length", "9"), ("Connection", "close"), ("X-A", "b")]);
        let out = client_headers(&h, Framing::Length(9), false, "r", true);
        assert_eq!(names(&out).iter().filter(|x| *x == "content-length").count(), 1);
        assert!(!names(&out).contains(&"connection".into()));
        let closing = client_headers(&h, Framing::Length(9), false, "r", false);
        assert!(closing.contains(&("Connection".into(), "close".into())));
    }

    #[test]
    fn a_head_answer_keeps_the_upstreams_content_length() {
        let h = head(&[("Content-Length", "1234")]);
        let out = client_headers(&h, Framing::None, true, "r", true);
        assert!(out.contains(&("Content-Length".into(), "1234".into())));
    }

    #[test]
    fn reasons_exist_for_every_status_the_waf_sends() {
        for status in [400, 403, 408, 413, 429, 431, 502, 503, 504, 505] {
            assert_ne!(reason(status), "Error", "{status}");
        }
    }

    #[test]
    fn an_own_answer_is_a_complete_http_message() -> TestResult {
        let mut out = Vec::new();
        respond(&mut out, 403, "rid", &[("Retry-After".into(), "1".into())], false)?;
        let text = String::from_utf8(out)?;
        assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(text.contains("Content-Length: 14\r\n"));
        assert!(text.contains("X-Request-Id: rid\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.contains("Retry-After: 1\r\n"));
        assert!(text.ends_with("\r\n\r\n403 Forbidden\n"));
        Ok(())
    }

    #[test]
    fn a_dead_upstream_is_a_bad_gateway() -> TestResult {
        let line = parse_request_line("GET / HTTP/1.1").map_err(|_| "request line")?;
        assert_eq!(line.version, Version::Http11);
        let h = head(&[("Host", "a.test")]);
        let carry = Carry {
            head: &h,
            line: &line,
            framing: Framing::None,
            prefix: b"",
            max_body: 100,
            request_id: "r",
            peer: "1.1.1.1",
            client_keep_alive: true,
        };
        let mut empty = io::Cursor::new(Vec::new());
        let mut body = Body::new(&mut empty, Framing::None);
        let mut client = Vec::new();
        // Port 1 on loopback has no listener.
        let result = forward(&carry, "127.0.0.1:1", &mut body, &mut client);
        assert!(matches!(result, Forwarded::BadGateway), "{result:?}");
        assert!(client.is_empty());
        Ok(())
    }

    #[test]
    fn the_deadline_reader_refuses_a_read_after_the_deadline() -> TestResult {
        fn noop(_: &io::Cursor<Vec<u8>>, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        let mut reader = DeadlineReader::new(io::Cursor::new(b"abc".to_vec()), noop);
        let mut buf = [0u8; 2];
        assert_eq!(reader.read(&mut buf)?, 2);
        reader.set_deadline(Some(Instant::now()));
        let said = reader.read(&mut buf).err().map(|e| e.kind());
        assert_eq!(said, Some(io::ErrorKind::TimedOut));
        reader.set_deadline(None);
        assert_eq!(reader.read(&mut buf)?, 1);
        assert_eq!(reader.get_ref().position(), 3);
        Ok(())
    }
}
