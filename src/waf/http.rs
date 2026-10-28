//! Stage 11: the HTTP/1.1 reading and writing the WAF needs.
//!
//! `docs/design.md` "段階11 WAF" is the source of truth. This module is strict
//! on purpose: the WAF builds the request it sends upstream from what it
//! parsed here, so a request the WAF reads one way and the upstream reads
//! another (request smuggling) cannot exist. Anything ambiguous is a
//! `ProtocolError` that ends the connection with an error status, and the
//! upstream never sees it.
//!
//! Refused here: a bare `\n` as a line end, a NUL or other control byte in a
//! line, an obsolete folded header, a name that is not a token, a space before
//! the colon, `Transfer-Encoding` beside `Content-Length`, more than one
//! `Content-Length`, a `Transfer-Encoding` other than a single `chunked`, a
//! `Content-Length` that is not plain digits.

use std::io::{self, BufRead, Write};

/// The whole head (request line and headers) may not be longer than this.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// One line of the head may not be longer than this.
pub const MAX_LINE_BYTES: usize = 8 * 1024;
/// Header lines per message.
pub const MAX_HEADERS: usize = 100;
/// The size of one piece of body that is moved at a time.
pub const PIECE_BYTES: usize = 64 * 1024;
/// A chunk-size line (hex digits and an optional extension) may not be longer
/// than this.
const MAX_CHUNK_LINE: usize = 256;
/// Trailer lines after the last chunk that are read and thrown away.
const MAX_TRAILER_LINES: usize = 32;

/// What went wrong while reading a head.
#[derive(Debug)]
pub enum HeadError {
    /// The peer closed before sending a byte of this message.
    Closed,
    /// The read timed out before the head was complete.
    Timeout,
    /// The head, a line or the header count is over its limit (431).
    TooLarge,
    /// The head is not valid HTTP/1.x (400). The text is the flag recorded in
    /// the audit log.
    Malformed(&'static str),
    /// The version is not HTTP/1.0 or HTTP/1.1 (505).
    Version,
    /// Any other I/O failure.
    Io(io::Error),
}

impl From<io::Error> for HeadError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(e),
        }
    }
}

/// A request or response head: the first line and the header fields in the
/// order they arrived. Field values are trimmed of surrounding spaces and tabs.
#[derive(Debug, Clone, Default)]
pub struct Head {
    pub first: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// Every value of the named header (case-insensitive), in order.
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The first value of the named header.
    pub fn first_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether any header of this name is present.
    pub fn has(&self, name: &str) -> bool {
        self.first_value(name).is_some()
    }
}

/// HTTP version of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
}

/// A parsed request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    pub method: String,
    pub target: String,
    pub version: Version,
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    None,
    Length(u64),
    Chunked,
    /// Ends when the sender closes (responses only).
    UntilClose,
}

/// A request the WAF refuses before the upstream sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolError {
    pub status: u16,
    pub flag: &'static str,
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_token_byte)
}

/// Read one line ending in `\n`, at most `cap` bytes including the line end.
/// `Ok(None)` is a clean end of input before the first byte.
fn read_line_capped<R: BufRead>(input: &mut R, cap: usize) -> Result<Option<Vec<u8>>, HeadError> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let (consumed, found) = {
            let available = match input.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if available.is_empty() {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Err(HeadError::Malformed("truncated"))
                };
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    line.extend_from_slice(&available[..=i]);
                    (i + 1, true)
                }
                None => {
                    line.extend_from_slice(available);
                    (available.len(), false)
                }
            }
        };
        input.consume(consumed);
        if line.len() > cap {
            return Err(HeadError::TooLarge);
        }
        if found {
            return Ok(Some(line));
        }
    }
}

/// Strip the `\r\n` of a line. A bare `\n` is refused.
fn strip_crlf(line: &[u8]) -> Result<&[u8], HeadError> {
    match line {
        [rest @ .., b'\r', b'\n'] => Ok(rest),
        _ => Err(HeadError::Malformed("bare-lf")),
    }
}

fn has_forbidden_control(line: &[u8]) -> bool {
    line.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// Read a head. `Ok` always carries a complete head; `Err(Closed)` is a clean
/// close before any byte.
pub fn read_head<R: BufRead>(input: &mut R) -> Result<Head, HeadError> {
    let mut head = Head::default();
    let mut total = 0usize;
    let mut skipped = 0usize;
    // The first line. Up to two empty lines before it are ignored, as a client
    // that ends a body with a spare CRLF is common.
    loop {
        let Some(line) = read_line_capped(input, MAX_LINE_BYTES)? else {
            return Err(HeadError::Closed);
        };
        total += line.len();
        let text = strip_crlf(&line)?;
        if text.is_empty() {
            skipped += 1;
            if skipped > 2 {
                return Err(HeadError::Malformed("empty-request"));
            }
            continue;
        }
        if has_forbidden_control(text) {
            return Err(HeadError::Malformed("control-byte"));
        }
        head.first = String::from_utf8_lossy(text).into_owned();
        break;
    }
    loop {
        let Some(line) = read_line_capped(input, MAX_LINE_BYTES)? else {
            return Err(HeadError::Malformed("truncated"));
        };
        total += line.len();
        if total > MAX_HEAD_BYTES {
            return Err(HeadError::TooLarge);
        }
        let text = strip_crlf(&line)?;
        if text.is_empty() {
            return Ok(head);
        }
        if has_forbidden_control(text) {
            return Err(HeadError::Malformed("control-byte"));
        }
        if matches!(text.first(), Some(b' ' | b'\t')) {
            return Err(HeadError::Malformed("obs-fold"));
        }
        if head.headers.len() >= MAX_HEADERS {
            return Err(HeadError::TooLarge);
        }
        let Some(colon) = text.iter().position(|&b| b == b':') else {
            return Err(HeadError::Malformed("header-no-colon"));
        };
        let (name, rest) = text.split_at(colon);
        let Ok(name) = std::str::from_utf8(name) else {
            return Err(HeadError::Malformed("header-name"));
        };
        if !is_token(name) {
            return Err(HeadError::Malformed("header-name"));
        }
        let value = String::from_utf8_lossy(&rest[1..]);
        let value = value.trim_matches([' ', '\t']);
        head.headers.push((name.to_string(), value.to_string()));
    }
}

/// Parse `METHOD SP target SP HTTP/1.x`.
pub fn parse_request_line(first: &str) -> Result<RequestLine, HeadError> {
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HeadError::Malformed("request-line"));
    };
    if !is_token(method) {
        return Err(HeadError::Malformed("method"));
    }
    if target.is_empty() {
        return Err(HeadError::Malformed("target"));
    }
    let version = match version {
        "HTTP/1.1" => Version::Http11,
        "HTTP/1.0" => Version::Http10,
        v if v.starts_with("HTTP/") => return Err(HeadError::Version),
        _ => return Err(HeadError::Malformed("version")),
    };
    Ok(RequestLine {
        method: method.to_string(),
        target: target.to_string(),
        version,
    })
}

/// The status code of `HTTP/1.x NNN reason`.
pub fn parse_status_line(first: &str) -> Option<u16> {
    let mut parts = first.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse().ok()
}

fn parse_length(value: &str) -> Option<u64> {
    if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn is_single_chunked(head: &Head) -> Result<bool, ProtocolError> {
    let values: Vec<&str> = head.values("transfer-encoding").collect();
    match values.as_slice() {
        [] => Ok(false),
        [only] if only.eq_ignore_ascii_case("chunked") => Ok(true),
        _ => Err(ProtocolError {
            status: 400,
            flag: "transfer-encoding",
        }),
    }
}

/// How the body of a request is delimited. `max_body` is the largest
/// `Content-Length` accepted (413 above it).
pub fn request_framing(head: &Head, max_body: u64) -> Result<Framing, ProtocolError> {
    let chunked = is_single_chunked(head)?;
    let lengths: Vec<&str> = head.values("content-length").collect();
    if chunked && !lengths.is_empty() {
        return Err(ProtocolError {
            status: 400,
            flag: "cl-and-te",
        });
    }
    if chunked {
        return Ok(Framing::Chunked);
    }
    match lengths.as_slice() {
        [] => Ok(Framing::None),
        [one] => match parse_length(one) {
            Some(0) => Ok(Framing::None),
            Some(n) if n > max_body => Err(ProtocolError {
                status: 413,
                flag: "body-too-large",
            }),
            Some(n) => Ok(Framing::Length(n)),
            None => Err(ProtocolError {
                status: 400,
                flag: "content-length",
            }),
        },
        _ => Err(ProtocolError {
            status: 400,
            flag: "multiple-content-length",
        }),
    }
}

/// How the body of a response is delimited. `head_request` is true for a
/// reply to `HEAD`.
pub fn response_framing(head: &Head, status: u16, head_request: bool) -> Framing {
    if head_request || (100..200).contains(&status) || status == 204 || status == 304 {
        return Framing::None;
    }
    let last_coding_is_chunked = |v: &str| {
        v.rsplit(',')
            .next()
            .is_some_and(|c| c.trim().eq_ignore_ascii_case("chunked"))
    };
    if head.values("transfer-encoding").any(last_coding_is_chunked) {
        return Framing::Chunked;
    }
    let lengths: Vec<&str> = head.values("content-length").collect();
    match lengths.as_slice() {
        [one] => match parse_length(one) {
            Some(0) => Framing::None,
            Some(n) => Framing::Length(n),
            None => Framing::UntilClose,
        },
        _ => Framing::UntilClose,
    }
}

#[derive(Debug, Clone, Copy)]
enum ChunkState {
    Size,
    Data(u64),
    DataEnd,
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Length(u64),
    Chunked(ChunkState),
    UntilClose,
    Finished,
}

/// A message body read a piece at a time. The chunk framing of a chunked body
/// is decoded: the pieces are the data only.
pub struct Body<'a, R: BufRead> {
    input: &'a mut R,
    kind: Kind,
}

impl<'a, R: BufRead> Body<'a, R> {
    pub fn new(input: &'a mut R, framing: Framing) -> Self {
        let kind = match framing {
            Framing::None | Framing::Length(0) => Kind::Finished,
            Framing::Length(n) => Kind::Length(n),
            Framing::Chunked => Kind::Chunked(ChunkState::Size),
            Framing::UntilClose => Kind::UntilClose,
        };
        Self { input, kind }
    }

    /// Whether the whole body has been read.
    pub fn is_finished(&self) -> bool {
        matches!(self.kind, Kind::Finished)
    }

    /// Read the next piece (at most [`PIECE_BYTES`]) into `out`, which is
    /// cleared first. `Ok(false)` is the end of the body.
    pub fn next_piece(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        out.clear();
        match self.kind {
            Kind::Finished => Ok(false),
            Kind::Length(remaining) => {
                let take = remaining.min(PIECE_BYTES as u64) as usize;
                self.read_exact_into(out, take)?;
                let left = remaining - take as u64;
                self.kind = if left == 0 {
                    Kind::Finished
                } else {
                    Kind::Length(left)
                };
                Ok(true)
            }
            Kind::UntilClose => {
                let available = self.input.fill_buf()?;
                if available.is_empty() {
                    self.kind = Kind::Finished;
                    return Ok(false);
                }
                let n = available.len().min(PIECE_BYTES);
                out.extend_from_slice(&available[..n]);
                self.input.consume(n);
                Ok(true)
            }
            Kind::Chunked(state) => self.next_chunk_piece(state, out),
        }
    }

    fn read_exact_into(&mut self, out: &mut Vec<u8>, n: usize) -> io::Result<()> {
        while out.len() < n {
            let available = self.input.fill_buf()?;
            if available.is_empty() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            let take = available.len().min(n - out.len());
            out.extend_from_slice(&available[..take]);
            self.input.consume(take);
        }
        Ok(())
    }

    fn next_chunk_piece(&mut self, mut state: ChunkState, out: &mut Vec<u8>) -> io::Result<bool> {
        loop {
            match state {
                ChunkState::Size => {
                    let size = self.read_chunk_size()?;
                    if size == 0 {
                        self.read_trailers()?;
                        self.kind = Kind::Finished;
                        return Ok(false);
                    }
                    state = ChunkState::Data(size);
                }
                ChunkState::Data(remaining) => {
                    let take = remaining.min(PIECE_BYTES as u64) as usize;
                    self.read_exact_into(out, take)?;
                    let left = remaining - take as u64;
                    let next = if left == 0 {
                        ChunkState::DataEnd
                    } else {
                        ChunkState::Data(left)
                    };
                    self.kind = Kind::Chunked(next);
                    return Ok(true);
                }
                ChunkState::DataEnd => {
                    let mut crlf = Vec::with_capacity(2);
                    self.read_exact_into(&mut crlf, 2)?;
                    if crlf != b"\r\n" {
                        return Err(invalid("chunk-terminator"));
                    }
                    state = ChunkState::Size;
                }
            }
        }
    }

    fn read_chunk_size(&mut self) -> io::Result<u64> {
        let line = self.read_framing_line(MAX_CHUNK_LINE, "chunk-size-line")?;
        let text = strip_crlf(&line).map_err(|_| invalid("chunk-size-line"))?;
        let Ok(text) = std::str::from_utf8(text) else {
            return Err(invalid("chunk-size-line"));
        };
        let Some(digits) = text.split(';').next() else {
            return Err(invalid("chunk-size"));
        };
        let digits = digits.trim_end_matches([' ', '\t']);
        if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(invalid("chunk-size"));
        }
        u64::from_str_radix(digits, 16).map_err(|_| invalid("chunk-size"))
    }

    fn read_trailers(&mut self) -> io::Result<()> {
        for _ in 0..MAX_TRAILER_LINES {
            let line = self.read_framing_line(MAX_LINE_BYTES, "trailer")?;
            let text = strip_crlf(&line).map_err(|_| invalid("trailer"))?;
            if text.is_empty() {
                return Ok(());
            }
        }
        Err(invalid("trailer-count"))
    }

    fn read_framing_line(&mut self, cap: usize, what: &'static str) -> io::Result<Vec<u8>> {
        match read_line_capped(self.input, cap) {
            Ok(Some(l)) => Ok(l),
            Ok(None) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Err(HeadError::Io(e)) => Err(e),
            Err(HeadError::Timeout) => Err(io::Error::from(io::ErrorKind::TimedOut)),
            Err(_) => Err(invalid(what)),
        }
    }
}

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// Write a head: the first line and the headers, then the blank line.
pub fn write_head<W: Write>(
    out: &mut W,
    first: &str,
    headers: &[(String, String)],
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(first.as_bytes());
    buf.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    out.write_all(&buf)
}

/// Write one chunk. An empty `data` writes nothing (it would end the body).
pub fn write_chunk<W: Write>(out: &mut W, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    write!(out, "{:x}\r\n", data.len())?;
    out.write_all(data)?;
    out.write_all(b"\r\n")
}

/// Write the last chunk and the empty trailer.
pub fn write_last_chunk<W: Write>(out: &mut W) -> io::Result<()> {
    out.write_all(b"0\r\n\r\n")
}

/// Whether a header is hop-by-hop and so is not forwarded as it came.
pub fn is_hop_by_hop(name: &str) -> bool {
    const NAMES: [&str; 10] = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    ];
    NAMES.iter().any(|n| name.eq_ignore_ascii_case(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// What a head read came to, in a form tests can compare.
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Ok,
        Closed,
        Timeout,
        TooLarge,
        Version,
        Io,
        Malformed(&'static str),
    }

    fn outcome(result: &Result<Head, HeadError>) -> Outcome {
        match result {
            Ok(_) => Outcome::Ok,
            Err(HeadError::Closed) => Outcome::Closed,
            Err(HeadError::Timeout) => Outcome::Timeout,
            Err(HeadError::TooLarge) => Outcome::TooLarge,
            Err(HeadError::Version) => Outcome::Version,
            Err(HeadError::Io(_)) => Outcome::Io,
            Err(HeadError::Malformed(f)) => Outcome::Malformed(f),
        }
    }

    fn head_of(raw: &str) -> Result<Head, HeadError> {
        read_head(&mut Cursor::new(raw.as_bytes().to_vec()))
    }

    fn outcome_of(raw: &str) -> Outcome {
        outcome(&head_of(raw))
    }

    #[test]
    fn a_plain_request_head_is_read() {
        let Ok(head) = head_of("GET /a?b=1 HTTP/1.1\r\nHost: example.org\r\nX-A:  v \r\n\r\n")
        else {
            panic!("a plain head was refused");
        };
        assert_eq!(head.first, "GET /a?b=1 HTTP/1.1");
        assert_eq!(head.first_value("host"), Some("example.org"));
        assert_eq!(head.first_value("X-A"), Some("v"));
    }

    #[test]
    fn a_bare_lf_is_refused() {
        assert_eq!(
            outcome_of("GET / HTTP/1.1\nHost: a\r\n\r\n"),
            Outcome::Malformed("bare-lf")
        );
        assert_eq!(
            outcome_of("GET / HTTP/1.1\r\nHost: a\n\r\n"),
            Outcome::Malformed("bare-lf")
        );
    }

    #[test]
    fn a_nul_or_control_byte_is_refused() {
        assert_eq!(
            outcome_of("GET / HTTP/1.1\r\nHost: a\0b\r\n\r\n"),
            Outcome::Malformed("control-byte")
        );
        assert_eq!(
            outcome_of("GET /\x01 HTTP/1.1\r\nHost: a\r\n\r\n"),
            Outcome::Malformed("control-byte")
        );
    }

    #[test]
    fn an_obsolete_fold_is_refused() {
        assert_eq!(
            outcome_of("GET / HTTP/1.1\r\nHost: a\r\n b\r\n\r\n"),
            Outcome::Malformed("obs-fold")
        );
    }

    #[test]
    fn a_space_before_the_colon_is_refused() {
        assert_eq!(
            outcome_of("GET / HTTP/1.1\r\nHost : a\r\n\r\n"),
            Outcome::Malformed("header-name")
        );
        assert_eq!(
            outcome_of("GET / HTTP/1.1\r\nHost\r\n\r\n"),
            Outcome::Malformed("header-no-colon")
        );
    }

    #[test]
    fn a_head_over_the_limits_is_too_large() {
        let long = format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "a".repeat(MAX_LINE_BYTES));
        assert_eq!(outcome_of(&long), Outcome::TooLarge);
        let mut many = String::from("GET / HTTP/1.1\r\n");
        for i in 0..=MAX_HEADERS {
            many.push_str(&format!("H{i}: v\r\n"));
        }
        many.push_str("\r\n");
        assert_eq!(outcome_of(&many), Outcome::TooLarge);
        let mut big = String::from("GET / HTTP/1.1\r\n");
        for i in 0..40 {
            big.push_str(&format!("H{i}: {}\r\n", "x".repeat(600)));
        }
        big.push_str("\r\n");
        assert_eq!(outcome_of(&big), Outcome::TooLarge);
    }

    #[test]
    fn a_clean_close_and_a_truncated_head_differ() {
        assert_eq!(outcome_of(""), Outcome::Closed);
        assert_eq!(
            outcome_of("GET / HTTP/1.1\r\nHost: a"),
            Outcome::Malformed("truncated")
        );
    }

    #[test]
    fn leading_empty_lines_are_skipped_up_to_two() {
        assert_eq!(outcome_of("\r\nGET / HTTP/1.1\r\n\r\n"), Outcome::Ok);
        assert_eq!(
            outcome_of("\r\n\r\n\r\nGET / HTTP/1.1\r\n\r\n"),
            Outcome::Malformed("empty-request")
        );
    }

    #[test]
    fn the_request_line_is_checked() {
        assert!(parse_request_line("GET / HTTP/1.1").is_ok());
        assert!(matches!(
            parse_request_line("GET / HTTP/2.0"),
            Err(HeadError::Version)
        ));
        assert!(matches!(
            parse_request_line("GET /"),
            Err(HeadError::Malformed(_))
        ));
        assert!(matches!(
            parse_request_line("GET  / HTTP/1.1"),
            Err(HeadError::Malformed(_))
        ));
        assert!(matches!(
            parse_request_line("G\u{e9}T / HTTP/1.1"),
            Err(HeadError::Malformed(_))
        ));
    }

    fn framing_of(raw: &str, max: u64) -> Result<Framing, ProtocolError> {
        let Ok(head) = head_of(raw) else {
            panic!("head refused: {raw:?}");
        };
        request_framing(&head, max)
    }

    fn refusal(status: u16, flag: &'static str) -> Result<Framing, ProtocolError> {
        Err(ProtocolError { status, flag })
    }

    #[test]
    fn content_length_and_transfer_encoding_together_are_refused() {
        let r = framing_of(
            "POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            100,
        );
        assert_eq!(r, refusal(400, "cl-and-te"));
    }

    #[test]
    fn two_content_lengths_are_refused_even_when_equal() {
        let r = framing_of(
            "POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
            100,
        );
        assert_eq!(r, refusal(400, "multiple-content-length"));
    }

    #[test]
    fn a_content_length_that_is_not_digits_is_refused() {
        for bad in ["+3", "-1", "3 4", "0x3", "3.0", ""] {
            let raw = format!("POST / HTTP/1.1\r\nContent-Length: {bad}\r\n\r\n");
            assert_eq!(framing_of(&raw, 100), refusal(400, "content-length"), "{bad:?}");
        }
    }

    #[test]
    fn a_body_over_the_limit_is_413() {
        let r = framing_of("POST / HTTP/1.1\r\nContent-Length: 101\r\n\r\n", 100);
        assert_eq!(r, refusal(413, "body-too-large"));
        let at = framing_of("POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n", 100);
        assert_eq!(at, Ok(Framing::Length(100)));
        let none = framing_of("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 100);
        assert_eq!(none, Ok(Framing::None));
    }

    #[test]
    fn only_a_single_chunked_coding_is_accepted() {
        for bad in ["gzip, chunked", "chunked, gzip", "identity", "xchunked"] {
            let raw = format!("POST / HTTP/1.1\r\nTransfer-Encoding: {bad}\r\n\r\n");
            assert_eq!(framing_of(&raw, 100), refusal(400, "transfer-encoding"), "{bad:?}");
        }
        let ok = framing_of("POST / HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n", 100);
        assert_eq!(ok, Ok(Framing::Chunked));
    }

    #[test]
    fn two_transfer_encoding_headers_are_refused() {
        let r = framing_of(
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            100,
        );
        assert_eq!(r, refusal(400, "transfer-encoding"));
    }

    #[test]
    fn a_response_has_no_body_for_head_204_304_and_1xx() {
        let h = Head {
            first: "HTTP/1.1 200 OK".into(),
            headers: vec![("Content-Length".into(), "5".into())],
        };
        assert_eq!(response_framing(&h, 200, true), Framing::None);
        assert_eq!(response_framing(&h, 204, false), Framing::None);
        assert_eq!(response_framing(&h, 304, false), Framing::None);
        assert_eq!(response_framing(&h, 101, false), Framing::None);
        assert_eq!(response_framing(&h, 200, false), Framing::Length(5));
        let none = Head::default();
        assert_eq!(response_framing(&none, 200, false), Framing::UntilClose);
    }

    #[test]
    fn a_status_line_is_read() {
        assert_eq!(parse_status_line("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_line("HTTP/1.0 404"), Some(404));
        assert_eq!(parse_status_line("HTTP/2 200"), None);
        assert_eq!(parse_status_line("HTTP/1.1 20 OK"), None);
        assert_eq!(parse_status_line("HTTP/1.1 abc OK"), None);
    }

    fn read_all(framing: Framing, raw: &[u8]) -> io::Result<Vec<u8>> {
        let mut input = Cursor::new(raw.to_vec());
        let mut body = Body::new(&mut input, framing);
        let mut all = Vec::new();
        let mut piece = Vec::new();
        while body.next_piece(&mut piece)? {
            all.extend_from_slice(&piece);
        }
        Ok(all)
    }

    #[test]
    fn a_length_body_is_read_exactly() {
        let all = read_all(Framing::Length(5), b"helloEXTRA");
        assert_eq!(all.ok(), Some(b"hello".to_vec()));
        let short = read_all(Framing::Length(10), b"hello");
        assert!(short.is_err());
    }

    #[test]
    fn a_chunked_body_is_decoded() {
        let raw = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n";
        let all = read_all(Framing::Chunked, raw);
        assert_eq!(all.ok(), Some(b"hello world".to_vec()));
    }

    #[test]
    fn a_malformed_chunked_body_is_an_error() {
        for raw in [
            &b"zz\r\nhello\r\n0\r\n\r\n"[..],
            b"5\r\nhelloXX0\r\n\r\n",
            b"5\r\nhel",
            b"5\nhello\r\n0\r\n\r\n",
            b"ffffffffffffffffff\r\n",
            b"\r\n",
        ] {
            assert!(read_all(Framing::Chunked, raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn an_until_close_body_reads_to_the_end() {
        let all = read_all(Framing::UntilClose, b"to the end");
        assert_eq!(all.ok(), Some(b"to the end".to_vec()));
    }

    #[test]
    fn a_big_length_body_comes_in_pieces() {
        let raw = vec![b'a'; PIECE_BYTES * 2 + 10];
        let mut input = Cursor::new(raw.clone());
        let mut body = Body::new(&mut input, Framing::Length(raw.len() as u64));
        let mut sizes = Vec::new();
        let mut piece = Vec::new();
        loop {
            match body.next_piece(&mut piece) {
                Ok(true) => sizes.push(piece.len()),
                Ok(false) => break,
                Err(e) => panic!("read failed: {e}"),
            }
        }
        assert_eq!(sizes, vec![PIECE_BYTES, PIECE_BYTES, 10]);
        assert!(body.is_finished());
    }

    #[test]
    fn written_heads_and_chunks_have_the_wire_form() {
        let mut out = Vec::new();
        let headers = vec![("Host".to_string(), "a".to_string())];
        assert!(write_head(&mut out, "GET / HTTP/1.1", &headers).is_ok());
        assert_eq!(out, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let mut chunks = Vec::new();
        assert!(write_chunk(&mut chunks, b"hello").is_ok());
        assert!(write_chunk(&mut chunks, b"").is_ok());
        assert!(write_last_chunk(&mut chunks).is_ok());
        assert_eq!(chunks, b"5\r\nhello\r\n0\r\n\r\n");
    }

    #[test]
    fn hop_by_hop_headers_are_named() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("Content-Type"));
    }

    #[test]
    fn a_timeout_kind_maps_to_timeout_and_the_rest_to_io() {
        assert!(matches!(
            HeadError::from(io::Error::from(io::ErrorKind::WouldBlock)),
            HeadError::Timeout
        ));
        assert!(matches!(
            HeadError::from(io::Error::from(io::ErrorKind::ConnectionReset)),
            HeadError::Io(_)
        ));
    }
}
