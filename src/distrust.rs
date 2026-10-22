//! Stage 10: the distrust list and the check of a certificate chain against it.
//! `docs/design.md` "段階10 能動防御（PC を守る見張りと遮断）", policy 1 and 2,
//! is the source of truth.
//!
//! A list line is one of
//!
//! ```text
//! spki-sha256 <base64>                      SHA-256 of a certificate's SubjectPublicKeyInfo
//! issuer-serial <base64 DER> <base64 serial> issuer name (DER) and serial number
//! cert-sha1 <hex>                           SHA-1 of the whole certificate
//! ```
//!
//! `#` lines and blank lines are ignored. A line that cannot be read is
//! dropped and counted: one bad line never discards the list.
//!
//! A chain is checked as every certificate the server sent plus the one trust
//! anchor whose subject is the issuer of the top certificate. Servers usually
//! leave the root out, so without the anchor a distrusted root could never
//! match.

use aws_lc_rs::digest;
use rustls::pki_types::{CertificateDer, TrustAnchor};
use std::collections::HashSet;
use x509_parser::parse_x509_certificate;

/// What a list can match on, for one certificate. A trust anchor carries only
/// its public key, so its SHA-1 and its issuer and serial are absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPrints {
    pub spki_sha256: [u8; 32],
    pub sha1: Option<[u8; 20]>,
    /// Issuer name (whole DER) and serial number without leading zero bytes.
    pub issuer_serial: Option<(Vec<u8>, Vec<u8>)>,
}

fn sha256(data: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(digest::digest(&digest::SHA256, data).as_ref()).ok()
}

fn sha1(data: &[u8]) -> Option<[u8; 20]> {
    <[u8; 20]>::try_from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref()).ok()
}

fn trim_serial(serial: &[u8]) -> &[u8] {
    match serial.iter().position(|byte| *byte != 0) {
        Some(first) => &serial[first..],
        None => &[],
    }
}

/// The prints of one DER certificate; `None` when it does not parse.
pub fn prints_of(der: &[u8]) -> Option<CertPrints> {
    let (_, cert) = parse_x509_certificate(der).ok()?;
    Some(CertPrints {
        spki_sha256: sha256(cert.public_key().raw)?,
        sha1: sha1(der),
        issuer_serial: Some((
            cert.issuer().as_raw().to_vec(),
            trim_serial(cert.raw_serial()).to_vec(),
        )),
    })
}

/// The content of one DER element (tag and length removed). `None` unless the
/// element fills `der` exactly.
fn der_content(der: &[u8]) -> Option<&[u8]> {
    let (_tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (len_bytes, rest) = rest.split_at(count);
        let len = len_bytes
            .iter()
            .fold(0_usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (len, rest)
    };
    (rest.len() == len).then_some(rest)
}

/// `content` wrapped as a DER SEQUENCE.
fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 10);
    out.push(0x30);
    let bytes = content.len().to_be_bytes();
    if content.len() < 0x80 {
        out.push(bytes[bytes.len() - 1]);
    } else {
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        let used = &bytes[skip..];
        let count: u8 = used.iter().map(|_| 1_u8).sum();
        out.push(0x80 | count);
        out.extend_from_slice(used);
    }
    out.extend_from_slice(content);
    out
}

/// webpki-roots keeps the content of the subject and of the SPKI without the
/// outer SEQUENCE; a certificate's own SPKI hash is taken over the whole
/// structure, so the SEQUENCE is put back before hashing.
fn anchor_prints(anchor: &TrustAnchor<'_>) -> Option<CertPrints> {
    let spki = der_sequence(anchor.subject_public_key_info.as_ref());
    Some(CertPrints {
        spki_sha256: sha256(&spki)?,
        sha1: None,
        issuer_serial: None,
    })
}

/// The anchor whose subject is the issuer of `top`.
fn root_for(top: &CertPrints, anchors: &[TrustAnchor<'_>]) -> Option<CertPrints> {
    let (issuer, _) = top.issuer_serial.as_ref()?;
    let wanted = der_content(issuer)?;
    anchors
        .iter()
        .find(|anchor| anchor.subject.as_ref() == wanted)
        .and_then(anchor_prints)
}

/// Every certificate the server sent, then the matching trust anchor if any.
/// A certificate that does not parse is left out: it cannot be matched.
pub fn chain_prints(chain: &[CertificateDer<'_>], anchors: &[TrustAnchor<'_>]) -> Vec<CertPrints> {
    let mut prints: Vec<CertPrints> = chain
        .iter()
        .filter_map(|der| prints_of(der.as_ref()))
        .collect();
    if let Some(root) = prints.last().and_then(|top| root_for(top, anchors)) {
        prints.push(root);
    }
    prints
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text.trim_end_matches('=').bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn hex_decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    if !text.is_ascii() || text.len() != N * 2 {
        return None;
    }
    let mut out = [0_u8; N];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// A parsed distrust list.
#[derive(Debug, Default)]
pub struct DistrustList {
    spki: HashSet<[u8; 32]>,
    sha1: HashSet<[u8; 20]>,
    issuer_serial: HashSet<(Vec<u8>, Vec<u8>)>,
    skipped: usize,
}

impl DistrustList {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn parse(content: &str) -> Self {
        let mut list = Self::default();
        let lines = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        for line in lines {
            if list.add_line(line).is_none() {
                list.skipped += 1;
            }
        }
        list
    }

    fn add_line(&mut self, line: &str) -> Option<()> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["spki-sha256", key] => {
                let hash = <[u8; 32]>::try_from(base64_decode(key)?.as_slice()).ok()?;
                self.spki.insert(hash);
            }
            ["cert-sha1", key] => {
                self.sha1.insert(hex_decode::<20>(key)?);
            }
            ["issuer-serial", issuer, serial] => {
                let serial = base64_decode(serial)?;
                self.issuer_serial
                    .insert((base64_decode(issuer)?, trim_serial(&serial).to_vec()));
            }
            _ => return None,
        }
        Some(())
    }

    /// Entries read.
    pub fn len(&self) -> usize {
        self.spki.len() + self.sha1.len() + self.issuer_serial.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lines that could not be read.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    fn matches(&self, prints: &CertPrints) -> bool {
        self.spki.contains(&prints.spki_sha256)
            || prints.sha1.is_some_and(|hash| self.sha1.contains(&hash))
            || prints
                .issuer_serial
                .as_ref()
                .is_some_and(|key| self.issuer_serial.contains(key))
    }

    pub fn matches_chain(&self, chain: &[CertPrints]) -> bool {
        chain.iter().any(|prints| self.matches(prints))
    }

    /// How many `spki-sha256` entries are a public trust anchor. One such line
    /// stops every host whose chain ends at that root.
    pub fn root_entries(&self, anchors: &[TrustAnchor<'_>]) -> usize {
        anchors
            .iter()
            .filter_map(anchor_prints)
            .filter(|prints| self.spki.contains(&prints.spki_sha256))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, PublicKeyData};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn b64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let word = chunk.iter().enumerate().fold(0_u32, |acc, (i, byte)| {
                acc | (u32::from(*byte) << (16 - 8 * i))
            });
            for i in 0..=chunk.len() {
                let index = ((word >> (18 - 6 * i)) & 63) as usize;
                out.push(char::from(ALPHABET[index]));
            }
            for _ in chunk.len()..3 {
                out.push('=');
            }
        }
        out
    }

    fn self_signed() -> Result<(KeyPair, CertificateDer<'static>), Box<dyn std::error::Error>> {
        let key = KeyPair::generate()?;
        let cert = CertificateParams::new(vec!["probe.test".to_owned()])?.self_signed(&key)?;
        Ok((key, cert.der().clone()))
    }

    #[test]
    fn distrust_list_reads_spki_issuer_serial_and_cert_sha1_lines() {
        let spki = b64(&[7_u8; 32]);
        let sha1_hex = "ab".repeat(20);
        let text = format!(
            "# comment\n\nspki-sha256 {spki}\ncert-sha1 {sha1_hex}\nissuer-serial MDwx AIAJ\n\
             spki-sha256 not-base64!\ncert-sha1 abcd\nunknown-kind x\nspki-sha256\n"
        );
        let list = DistrustList::parse(&text);
        assert_eq!(list.len(), 3);
        assert_eq!(list.skipped(), 4);
    }

    #[test]
    fn an_empty_text_gives_an_empty_list() {
        let list = DistrustList::parse("");
        assert!(list.is_empty());
        assert_eq!(list.skipped(), 0);
        assert!(!list.matches_chain(&[]));
    }

    #[test]
    fn a_certificate_is_matched_by_each_of_the_three_line_forms() -> TestResult {
        let (key, der) = self_signed()?;
        let prints = prints_of(der.as_ref()).ok_or("self-signed certificate did not parse")?;
        // The expected values come from rcgen and a plain digest, not from `prints_of`.
        let spki = digest::digest(&digest::SHA256, &key.subject_public_key_info());
        assert_eq!(prints.spki_sha256.as_slice(), spki.as_ref());
        let sha1_hex: String = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, der.as_ref())
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let (issuer, serial) = prints.issuer_serial.clone().ok_or("no issuer and serial")?;
        let lines = [
            format!("spki-sha256 {}", b64(spki.as_ref())),
            format!("cert-sha1 {sha1_hex}"),
            format!("issuer-serial {} {}", b64(&issuer), b64(&serial)),
        ];
        for line in &lines {
            let list = DistrustList::parse(line);
            assert_eq!(list.len(), 1, "{line}");
            assert!(list.matches_chain(std::slice::from_ref(&prints)), "{line}");
        }
        // The control: another certificate matches none of them.
        let (_, other) = self_signed()?;
        let other = prints_of(other.as_ref()).ok_or("other certificate did not parse")?;
        for line in &lines {
            assert!(
                !DistrustList::parse(line).matches_chain(std::slice::from_ref(&other)),
                "{line}"
            );
        }
        Ok(())
    }

    #[test]
    fn leading_zero_bytes_of_a_serial_do_not_change_the_match() {
        let prints = CertPrints {
            spki_sha256: [0; 32],
            sha1: None,
            issuer_serial: Some((vec![0x30, 0x00], vec![0x80, 0x09])),
        };
        let padded = format!(
            "issuer-serial {} {}",
            b64(&[0x30, 0x00]),
            b64(&[0x00, 0x80, 0x09])
        );
        assert!(DistrustList::parse(&padded).matches_chain(&[prints]));
    }

    #[test]
    fn base64_and_hex_reject_what_they_cannot_read() {
        assert_eq!(base64_decode("AIAJ"), Some(vec![0x00, 0x80, 0x09]));
        assert_eq!(base64_decode("AA=="), Some(vec![0]));
        assert_eq!(base64_decode("A$"), None);
        assert_eq!(hex_decode::<2>("0aFf"), Some([0x0a, 0xff]));
        assert_eq!(hex_decode::<2>("0aF"), None);
        assert_eq!(hex_decode::<2>("0aGg"), None);
        assert_eq!(hex_decode::<1>("é"), None);
    }

    #[test]
    fn der_helpers_agree_on_short_and_long_lengths() {
        for len in [0_usize, 1, 127, 128, 255, 256, 70_000] {
            let content = vec![0xab; len];
            let wrapped = der_sequence(&content);
            assert_eq!(der_content(&wrapped), Some(content.as_slice()), "len {len}");
        }
        assert_eq!(der_content(&[0x30, 0x05, 1]), None);
        assert_eq!(der_content(&[0x30]), None);
        assert_eq!(der_content(&[0x30, 0x80]), None);
        assert_eq!(der_content(&[]), None);
    }

    #[test]
    fn every_public_anchor_spki_is_valid_der_once_wrapped() {
        use x509_parser::prelude::FromDer;
        use x509_parser::x509::SubjectPublicKeyInfo;
        let anchors = webpki_roots::TLS_SERVER_ROOTS;
        assert!(anchors.len() > 100, "{}", anchors.len());
        for anchor in anchors {
            let wrapped = der_sequence(anchor.subject_public_key_info.as_ref());
            let parsed = SubjectPublicKeyInfo::from_der(&wrapped);
            assert!(matches!(parsed, Ok((rest, _)) if rest.is_empty()));
        }
    }

    #[test]
    fn the_root_of_a_chain_is_the_anchor_named_by_the_top_issuer() -> TestResult {
        let anchors = webpki_roots::TLS_SERVER_ROOTS;
        let anchor = anchors.first().ok_or("no anchors")?;
        let top = CertPrints {
            spki_sha256: [0; 32],
            sha1: None,
            issuer_serial: Some((der_sequence(anchor.subject.as_ref()), vec![1])),
        };
        let root = root_for(&top, anchors).ok_or("the anchor was not found")?;
        let line = format!("spki-sha256 {}", b64(&root.spki_sha256));
        let list = DistrustList::parse(&line);
        assert_eq!(list.root_entries(anchors), 1);
        assert!(list.matches_chain(&[root]));
        // The control: an issuer no anchor has finds nothing.
        let unknown = CertPrints {
            issuer_serial: Some((der_sequence(b"no such name"), vec![1])),
            ..top
        };
        assert_eq!(root_for(&unknown, anchors), None);
        Ok(())
    }
}
