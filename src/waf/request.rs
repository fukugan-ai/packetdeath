//! Stage 11: small pieces of reading one request that the server shares.

use std::io::{self, BufRead};

use super::http::{Body, Head, HeadError, RequestLine, Version};

/// What a head that could not be read is answered with: a status and the flag
/// recorded in the audit log. `None` means the connection is closed silently.
pub fn head_failure(error: &HeadError, first: bool) -> Option<(u16, &'static str)> {
    match error {
        HeadError::Closed | HeadError::Io(_) => None,
        HeadError::Timeout if first => Some((408, "head_timeout")),
        HeadError::Timeout => None,
        HeadError::TooLarge => Some((431, "head_too_large")),
        HeadError::Malformed(flag) => Some((400, flag)),
        HeadError::Version => Some((505, "http_version")),
    }
}

/// The origin form of a request target: `http://host/p?q` becomes `/p?q`.
fn origin_form(target: &str) -> &str {
    let Some(at) = target.find("://") else {
        return target;
    };
    if target.starts_with('/') {
        return target;
    }
    let rest = &target[at + 3..];
    // DEFAULT: an absolute-form target with no path means the root path (RFC 9112 section 3.2.2).
    let mut origin = "/";
    if let Some(slash) = rest.find('/') {
        origin = &rest[slash..];
    }
    origin
}

/// Split a request target into its path and its query (without the `?`).
pub fn target_parts(target: &str) -> (String, String) {
    let origin = origin_form(target);
    match origin.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (origin.to_owned(), String::new()),
    }
}

/// Read the part of the body that is judged: pieces until `cap` bytes are held
/// or the body ends. The rest stays unread.
pub fn read_prefix<R: BufRead>(body: &mut Body<'_, R>, cap: usize) -> io::Result<Vec<u8>> {
    let mut prefix = Vec::new();
    let mut piece = Vec::new();
    while prefix.len() < cap {
        if !body.next_piece(&mut piece)? {
            break;
        }
        prefix.extend_from_slice(&piece);
    }
    Ok(prefix)
}

/// Whether the client connection may carry another request after this one.
pub fn client_keep_alive(head: &Head, line: &RequestLine) -> bool {
    line.version == Version::Http11
        && !head
            .values("connection")
            .any(|v| v.to_ascii_lowercase().contains("close"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::http::Framing;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_target_is_split_into_path_and_query() {
        assert_eq!(target_parts("/a/b?x=1&y=2"), ("/a/b".into(), "x=1&y=2".into()));
        assert_eq!(target_parts("/a/b"), ("/a/b".into(), String::new()));
        assert_eq!(target_parts("/?"), ("/".into(), String::new()));
        assert_eq!(target_parts("*"), ("*".into(), String::new()));
    }

    #[test]
    fn an_absolute_form_target_loses_its_scheme_and_host() {
        assert_eq!(
            target_parts("http://example.test/p?q=1"),
            ("/p".into(), "q=1".into())
        );
        assert_eq!(target_parts("http://example.test"), ("/".into(), String::new()));
        assert_eq!(
            target_parts("/redirect?to=http://x/y"),
            ("/redirect".into(), "to=http://x/y".into())
        );
    }

    #[test]
    fn head_failures_map_to_the_statuses_the_design_gives() {
        assert_eq!(head_failure(&HeadError::TooLarge, true), Some((431, "head_too_large")));
        assert_eq!(
            head_failure(&HeadError::Malformed("bare_lf"), true),
            Some((400, "bare_lf"))
        );
        assert_eq!(head_failure(&HeadError::Version, true), Some((505, "http_version")));
        assert_eq!(head_failure(&HeadError::Timeout, true), Some((408, "head_timeout")));
        assert_eq!(head_failure(&HeadError::Timeout, false), None);
        assert_eq!(head_failure(&HeadError::Closed, true), None);
    }

    #[test]
    fn keep_alive_needs_http11_and_no_close() {
        let line = |version| RequestLine {
            method: "GET".into(),
            target: "/".into(),
            version,
        };
        let plain = Head::default();
        let closing = Head {
            first: String::new(),
            headers: vec![("Connection".into(), "Close".into())],
        };
        assert!(client_keep_alive(&plain, &line(Version::Http11)));
        assert!(!client_keep_alive(&closing, &line(Version::Http11)));
        assert!(!client_keep_alive(&plain, &line(Version::Http10)));
    }

    #[test]
    fn the_prefix_stops_at_the_cap_and_the_rest_stays_unread() -> TestResult {
        let mut input = io::Cursor::new(vec![b'a'; 200_000]);
        let mut body = Body::new(&mut input, Framing::Length(200_000));
        let prefix = read_prefix(&mut body, 1000)?;
        assert!(prefix.len() >= 1000 && prefix.len() < 200_000);
        assert!(!body.is_finished());
        Ok(())
    }

    #[test]
    fn a_small_body_is_read_whole_and_finishes() -> TestResult {
        let mut input = io::Cursor::new(b"hello".to_vec());
        let mut body = Body::new(&mut input, Framing::Length(5));
        assert_eq!(read_prefix(&mut body, 1000)?, b"hello");
        assert!(body.is_finished());
        Ok(())
    }

    #[test]
    fn an_empty_body_gives_an_empty_prefix() -> TestResult {
        let mut input = io::Cursor::new(Vec::new());
        let mut body = Body::new(&mut input, Framing::None);
        assert!(read_prefix(&mut body, 1000)?.is_empty());
        Ok(())
    }
}
