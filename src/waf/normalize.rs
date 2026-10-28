//! Stage 11: turning one request value into the text the rules read.
//!
//! `docs/design.md` "段階11 WAF" is the source of truth. A rule is written
//! against the plain form of a value, so an attacker's encoding must not be
//! able to hide a payload from it. The steps, in order:
//!
//! 1. `+` becomes a space (query and urlencoded bodies only);
//! 2. percent-decoding, `%XX` and the IIS form `%uXXXX`, at most
//!    [`MAX_DECODE_PASSES`] times; a value that still decodes after that is an
//!    `overflow` (the rules report it, the value is not decoded further);
//! 3. NUL bytes are removed and counted;
//! 4. the bytes become text; bytes that are not UTF-8 are replaced and counted;
//! 5. full-width ASCII (U+FF01..U+FF5E) becomes ASCII;
//! 6. the common HTML entities and numeric references are decoded once;
//! 7. SQL comments are replaced by a space, and the MySQL version comment
//!    `/*!12345 ... */` is opened so what is inside is read;
//! 8. letters are lowercased, white space and control characters collapse to
//!    a single space, and the ends are trimmed.

/// How many times percent-decoding is applied to one value.
pub const MAX_DECODE_PASSES: usize = 3;

/// A value after the steps above, with what was found on the way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Normalized {
    pub text: String,
    /// Decoding passes that changed the value.
    pub passes: usize,
    /// The value still had a percent sequence after [`MAX_DECODE_PASSES`].
    pub overflow: bool,
    /// The value carried a NUL byte (decoded or literal).
    pub nul: bool,
    /// The value was not valid UTF-8.
    pub bad_utf8: bool,
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
    Some(hex_value(hi)? * 16 + hex_value(lo)?)
}

fn hex_unit(digits: &[u8]) -> Option<u32> {
    let [a, b, c, d] = digits else {
        return None;
    };
    let hi = u32::from(hex_byte(*a, *b)?);
    let lo = u32::from(hex_byte(*c, *d)?);
    Some(hi * 256 + lo)
}

/// One percent-decoding pass. Returns the result and whether any sequence was
/// decoded.
fn decode_pass(input: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b != b'%' {
            out.push(b);
            i += 1;
            continue;
        }
        if input.get(i + 1) == Some(&b'u') || input.get(i + 1) == Some(&b'U') {
            if let Some(unit) = input.get(i + 2..i + 6).and_then(hex_unit) {
                if let Some(c) = char::from_u32(unit) {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    changed = true;
                    i += 6;
                    continue;
                }
            }
        }
        if let (Some(&hi), Some(&lo)) = (input.get(i + 1), input.get(i + 2)) {
            if let Some(byte) = hex_byte(hi, lo) {
                out.push(byte);
                changed = true;
                i += 3;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    (out, changed)
}

fn fullwidth_to_ascii(c: char) -> char {
    let code = u32::from(c);
    if (0xFF01..=0xFF5E).contains(&code) {
        if let Some(ascii) = char::from_u32(code - 0xFEE0) {
            return ascii;
        }
    }
    if code == 0x3000 {
        return ' ';
    }
    c
}

/// Decode `&lt;` `&gt;` `&amp;` `&quot;` `&apos;` `&#NN;` `&#xHH;` once.
fn decode_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        match entity_at(tail) {
            Some((c, used)) => {
                out.push(c);
                rest = &tail[used..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The character an entity at the start of `tail` stands for, and its length.
fn entity_at(tail: &str) -> Option<(char, usize)> {
    let end = tail.find(';')?;
    if end > 10 {
        return None;
    }
    let name = &tail[1..end];
    let c = match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        _ => {
            let digits = name.strip_prefix('#')?;
            let code = match digits.strip_prefix(['x', 'X']) {
                Some(h) => u32::from_str_radix(h, 16).ok()?,
                None => digits.parse::<u32>().ok()?,
            };
            char::from_u32(code)?
        }
    };
    Some((c, end + 1))
}

/// Replace `/* ... */` by a space. `/*!12345` (the MySQL version comment) is
/// opened instead, so the SQL inside it stays visible to the rules.
fn strip_sql_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut conditional_depth = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            if bytes.get(i + 2) == Some(&b'!') {
                let mut j = i + 3;
                while bytes.get(j).is_some_and(u8::is_ascii_digit) {
                    j += 1;
                }
                out.push(' ');
                conditional_depth += 1;
                i = j;
                continue;
            }
            match input[i + 2..].find("*/") {
                Some(close) => {
                    out.push(' ');
                    i += 2 + close + 2;
                }
                None => {
                    out.push(' ');
                    return out;
                }
            }
            continue;
        }
        if conditional_depth > 0 && bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
            out.push(' ');
            conditional_depth -= 1;
            i += 2;
            continue;
        }
        // The next whole character, so a multi-byte one is not cut.
        let Some(c) = input[i..].chars().next() else {
            break;
        };
        out.push(c);
        i += c.len_utf8();
    }
    out
}

fn collapse_white_space(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_space = true;
    for c in input.chars() {
        if c.is_whitespace() || c.is_control() {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(c);
            in_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Normalize one value. `plus_as_space` is true for query strings and
/// urlencoded bodies, where `+` is a space.
pub fn normalize_value(raw: &[u8], plus_as_space: bool) -> Normalized {
    let mut current: Vec<u8> = if plus_as_space {
        raw.iter().map(|&b| if b == b'+' { b' ' } else { b }).collect()
    } else {
        raw.to_vec()
    };
    let mut passes = 0usize;
    let mut overflow = false;
    for pass in 0..=MAX_DECODE_PASSES {
        let (next, changed) = decode_pass(&current);
        if !changed {
            break;
        }
        if pass == MAX_DECODE_PASSES {
            overflow = true;
            break;
        }
        current = next;
        passes += 1;
    }
    let nul = current.contains(&0);
    if nul {
        current.retain(|&b| b != 0);
    }
    let (text, bad_utf8) = match String::from_utf8(current) {
        Ok(text) => (text, false),
        Err(e) => (String::from_utf8_lossy(e.as_bytes()).into_owned(), true),
    };
    let ascii: String = text.chars().map(fullwidth_to_ascii).collect();
    let decoded = decode_entities(&ascii);
    let uncommented = strip_sql_comments(&decoded);
    let lowered = uncommented.to_lowercase();
    Normalized {
        text: collapse_white_space(&lowered),
        passes,
        overflow,
        nul,
        bad_utf8,
    }
}

/// Resolve `.` and `..` segments and repeated slashes of a decoded path, and
/// turn `\` into `/`. A `..` that climbs above the root is dropped.
pub fn clean_path(path: &str) -> String {
    let unified = path.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for part in unified.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    if unified.ends_with('/') && out.len() > 1 {
        out.push('/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(raw: &str, plus: bool) -> String {
        normalize_value(raw.as_bytes(), plus).text
    }

    #[test]
    fn a_plain_value_is_lowercased_and_trimmed() {
        assert_eq!(text_of("  Hello   WORLD ", false), "hello world");
        assert_eq!(text_of("", false), "");
    }

    #[test]
    fn plus_is_a_space_only_when_asked() {
        assert_eq!(text_of("a+b", true), "a b");
        assert_eq!(text_of("a+b", false), "a+b");
    }

    #[test]
    fn percent_sequences_are_decoded() {
        assert_eq!(text_of("%27%20OR%201%3D1", false), "' or 1=1");
        assert_eq!(text_of("%u0027", false), "'");
        assert_eq!(text_of("%U003Cscript%u003E", false), "<script>");
    }

    #[test]
    fn a_bad_percent_sequence_is_kept_as_it_is() {
        assert_eq!(text_of("100%", false), "100%");
        assert_eq!(text_of("%zz%2", false), "%zz%2");
    }

    #[test]
    fn double_and_triple_encoding_are_unwrapped_and_counted() {
        let n = normalize_value(b"%2527", false);
        assert_eq!(n.text, "'");
        assert_eq!(n.passes, 2);
        assert!(!n.overflow);
        let three = normalize_value(b"%252527", false);
        assert_eq!(three.text, "'");
        assert_eq!(three.passes, 3);
        assert!(!three.overflow);
    }

    #[test]
    fn a_fourth_layer_of_encoding_is_an_overflow() {
        let n = normalize_value(b"%25252527", false);
        assert!(n.overflow);
        assert_eq!(n.passes, MAX_DECODE_PASSES);
        assert_eq!(n.text, "%27");
    }

    #[test]
    fn nul_bytes_are_removed_and_counted() {
        let n = normalize_value(b"ab%00c\0d", false);
        assert_eq!(n.text, "abcd");
        assert!(n.nul);
        assert!(!normalize_value(b"abcd", false).nul);
    }

    #[test]
    fn bytes_that_are_not_utf8_are_counted() {
        let n = normalize_value(&[b'a', 0xff, b'b'], false);
        assert!(n.bad_utf8);
        assert!(n.text.starts_with('a') && n.text.ends_with('b'));
        assert!(!normalize_value("日本語".as_bytes(), false).bad_utf8);
    }

    #[test]
    fn full_width_ascii_becomes_ascii() {
        assert_eq!(text_of("ＵＮＩＯＮ　ＳＥＬＥＣＴ", false), "union select");
    }

    #[test]
    fn html_entities_are_decoded_once() {
        assert_eq!(text_of("&lt;script&gt;", false), "<script>");
        assert_eq!(text_of("&#60;b&#x3e;", false), "<b>");
        assert_eq!(text_of("a &amp; b", false), "a & b");
        assert_eq!(text_of("&amp;lt;", false), "&lt;");
        assert_eq!(text_of("fish & chips; salt", false), "fish & chips; salt");
    }

    #[test]
    fn sql_comments_become_a_space() {
        assert_eq!(text_of("UN/**/ION SE/*x*/LECT", false), "un ion se lect");
        assert_eq!(text_of("a /* never closed", false), "a");
    }

    #[test]
    fn a_mysql_version_comment_is_opened() {
        assert_eq!(text_of("/*!50000union*/ select", false), "union select");
        assert_eq!(text_of("/*!union*/ /*!select*/ 1", false), "union select 1");
    }

    #[test]
    fn white_space_and_control_characters_collapse() {
        assert_eq!(text_of("a\t\n\r  b\u{b}c", false), "a b c");
    }

    #[test]
    fn a_multi_byte_character_survives_comment_stripping() {
        assert_eq!(text_of("日本/**/語", false), "日本 語");
    }

    #[test]
    fn dot_segments_and_repeated_slashes_are_resolved() {
        assert_eq!(clean_path("/a/b/../c"), "/a/c");
        assert_eq!(clean_path("//a///b/./c"), "/a/b/c");
        assert_eq!(clean_path("/a\\b\\..\\c"), "/a/c");
        assert_eq!(clean_path("/../../etc/passwd"), "/etc/passwd");
        assert_eq!(clean_path("/"), "/");
        assert_eq!(clean_path("/dir/"), "/dir/");
        assert_eq!(clean_path(""), "/");
    }
}
