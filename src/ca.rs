//! Stage 8: the CA that signs the per-host leaf certificates. `docs/design.md`
//! "段階8 MITM", subsection "CA", is the source of truth.
//!
//! ECDSA P-256, CN `packetdeath CA <YYYY-MM-DD>` so generations can be told
//! apart on a device, 730 days from a notBefore one day in the past, CA with
//! pathlen 0, keyCertSign and cRLSign.
//!
//! **Nothing is ever overwritten.** The key is created with mode `0600` at
//! open time (never chmod-ed after writing), both files are created with
//! `create_new`, and if `ca.crt` cannot be written the `ca.key` this run made
//! is removed. On startup a half pair, a key readable by others, a file that
//! does not parse, or an expired certificate disables decryption instead of
//! regenerating: silently replacing a key cannot be undone, and every device
//! that trusts the old CA would break.
//!
//! Leaves live in memory only: one per host, 7 days valid, issued again after
//! a day, at most 256 hosts.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::fmt;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

pub const CA_KEY_FILE: &str = "ca.key";
pub const CA_CERT_FILE: &str = "ca.crt";

const CA_VALIDITY: time::Duration = time::Duration::days(730);
/// notBefore is set this far back to tolerate device clocks that run behind.
const BACKDATE: time::Duration = time::Duration::days(1);
const LEAF_VALIDITY: time::Duration = time::Duration::days(7);
/// X.509 caps a common name at 64 characters; longer hosts get no CN.
const MAX_COMMON_NAME: usize = 64;

/// Warn at startup when the CA has fewer days than this left.
pub const EXPIRY_WARNING_DAYS: i64 = 30;
/// A cached leaf older than this is issued again.
pub const LEAF_REFRESH: Duration = Duration::from_secs(24 * 60 * 60);
/// Hosts kept in the leaf cache.
pub const LEAF_CACHE_CAPACITY: usize = 256;

#[derive(Debug)]
pub enum CaError {
    CreateDir(PathBuf, io::Error),
    /// Exactly one of `ca.key` / `ca.crt` exists; the path is the missing one.
    OneFileMissing(PathBuf),
    /// `ca.key` grants access beyond its owner (looser than `0600`).
    KeyTooOpen(PathBuf, u32),
    Read(PathBuf, io::Error),
    Parse(PathBuf, String),
    Expired(OffsetDateTime),
    Generate(rcgen::Error),
    Write(PathBuf, io::Error),
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let locale = crate::i18n::locale();
        let s = match self {
            Self::CreateDir(path, e) | Self::Read(path, e) | Self::Write(path, e) => {
                crate::i18n::ca_io_failed(locale, path.display(), e)
            }
            Self::OneFileMissing(path) => crate::i18n::ca_one_file_missing(locale, path.display()),
            Self::KeyTooOpen(path, mode) => {
                crate::i18n::ca_key_too_open(locale, path.display(), format!("{mode:o}"))
            }
            Self::Parse(path, detail) => {
                crate::i18n::ca_parse_failed(locale, path.display(), detail)
            }
            Self::Expired(not_after) => crate::i18n::ca_expired(locale, utc_text(*not_after)),
            Self::Generate(e) => crate::i18n::ca_generate_failed(locale, e),
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for CaError {}

/// Why a leaf could not be issued. Both carry the library's own message.
#[derive(Debug)]
pub enum LeafError {
    Rcgen(rcgen::Error),
    Rustls(rustls::Error),
}

impl fmt::Display for LeafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rcgen(e) => write!(f, "{e}"),
            Self::Rustls(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LeafError {}

impl From<rcgen::Error> for LeafError {
    fn from(e: rcgen::Error) -> Self {
        Self::Rcgen(e)
    }
}

impl From<rustls::Error> for LeafError {
    fn from(e: rustls::Error) -> Self {
        Self::Rustls(e)
    }
}

/// Whether this start made the CA or found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaOrigin {
    Generated,
    Loaded,
}

/// The loaded or generated CA.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
    /// `ca.crt` exactly as it is on disk, kept so serving it never reads disk.
    pem: Vec<u8>,
    not_after: OffsetDateTime,
    provider: Arc<CryptoProvider>,
}

fn common_name(text: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    if text.len() <= MAX_COMMON_NAME {
        name.push(DnType::CommonName, text);
    }
    name
}

/// `YYYY-MM-DDTHH:MM:SSZ` in UTC, the form the logs print validity in.
pub fn utc_text(moment: OffsetDateTime) -> String {
    let utc = moment.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// `packetdeath CA <YYYY-MM-DD>` for the day `now` falls on (UTC).
pub fn ca_common_name(now: OffsetDateTime) -> String {
    let date = now.date();
    format!(
        "packetdeath CA {:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

fn ca_params(now: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = common_name(&ca_common_name(now));
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = now - BACKDATE;
    params.not_after = now + CA_VALIDITY;
    params
}

/// Creates `path` holding `contents`, never replacing an existing file. A
/// file this call created but could not fill is removed again.
fn write_new(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    if let Err(e) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

impl Ca {
    /// Loads the CA from `dir`, or generates it when neither file exists.
    /// `dir` is created with mode `0700` when missing.
    pub fn load_or_create(
        dir: &Path,
        provider: Arc<CryptoProvider>,
        now: OffsetDateTime,
    ) -> Result<(Self, CaOrigin), CaError> {
        if !dir.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| CaError::CreateDir(dir.to_path_buf(), e))?;
        }
        let key_path = dir.join(CA_KEY_FILE);
        let cert_path = dir.join(CA_CERT_FILE);
        match (key_path.exists(), cert_path.exists()) {
            (false, false) => Self::generate(&key_path, &cert_path, provider, now)
                .map(|ca| (ca, CaOrigin::Generated)),
            (true, false) => Err(CaError::OneFileMissing(cert_path)),
            (false, true) => Err(CaError::OneFileMissing(key_path)),
            (true, true) => {
                Self::load(&key_path, &cert_path, provider, now).map(|ca| (ca, CaOrigin::Loaded))
            }
        }
    }

    fn generate(
        key_path: &Path,
        cert_path: &Path,
        provider: Arc<CryptoProvider>,
        now: OffsetDateTime,
    ) -> Result<Self, CaError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(CaError::Generate)?;
        let params = ca_params(now);
        let cert = params.self_signed(&key).map_err(CaError::Generate)?;
        write_new(key_path, key.serialize_pem().as_bytes(), 0o600)
            .map_err(|e| CaError::Write(key_path.to_path_buf(), e))?;
        let pem = cert.pem().into_bytes();
        if let Err(e) = write_new(cert_path, &pem, 0o644) {
            // The key alone would block every later start (a half pair).
            let _ = std::fs::remove_file(key_path);
            return Err(CaError::Write(cert_path.to_path_buf(), e));
        }
        let not_after = params.not_after;
        Ok(Self {
            der: cert.der().clone(),
            pem,
            issuer: Issuer::new(params, key),
            not_after,
            provider,
        })
    }

    fn load(
        key_path: &Path,
        cert_path: &Path,
        provider: Arc<CryptoProvider>,
        now: OffsetDateTime,
    ) -> Result<Self, CaError> {
        let mode = std::fs::metadata(key_path)
            .map_err(|e| CaError::Read(key_path.to_path_buf(), e))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(CaError::KeyTooOpen(key_path.to_path_buf(), mode));
        }
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| CaError::Read(key_path.to_path_buf(), e))?;
        let cert_pem =
            std::fs::read(cert_path).map_err(|e| CaError::Read(cert_path.to_path_buf(), e))?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(|e| CaError::Parse(key_path.to_path_buf(), e.to_string()))?;
        let der = CertificateDer::from_pem_slice(&cert_pem)
            .map_err(|e| CaError::Parse(cert_path.to_path_buf(), e.to_string()))?;
        // The key has to be the one the certificate carries.
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        CertifiedKey::from_der(vec![der.clone()], key_der, &provider)
            .map_err(|e| CaError::Parse(cert_path.to_path_buf(), e.to_string()))?;
        let Some((_, not_after)) = validity(&der) else {
            return Err(CaError::Parse(
                cert_path.to_path_buf(),
                String::from("notAfter"),
            ));
        };
        if now > not_after {
            return Err(CaError::Expired(not_after));
        }
        let issuer = Issuer::from_ca_cert_der(&der, key)
            .map_err(|e| CaError::Parse(cert_path.to_path_buf(), e.to_string()))?;
        Ok(Self {
            issuer,
            der,
            pem: cert_pem,
            not_after,
            provider,
        })
    }

    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// `ca.crt` as a PEM file, byte for byte. This is what `/ca.crt` serves.
    pub fn pem(&self) -> &[u8] {
        &self.pem
    }

    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// Whole days until the CA expires.
    pub fn days_left(&self, now: OffsetDateTime) -> i64 {
        (self.not_after - now).whole_days()
    }

    /// SHA-256 of `ca.crt`, colon-separated upper-case hex (what a device shows).
    pub fn sha256_fingerprint(&self) -> String {
        fingerprint(&aws_lc_rs::digest::SHA256, &self.der)
    }

    /// SHA-1 of `ca.crt`, for devices that only show this one.
    pub fn sha1_fingerprint(&self) -> String {
        fingerprint(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &self.der)
    }

    /// Issues a leaf for `host`: SAN `host`, serverAuth, P-256, 7 days.
    pub fn issue_leaf(
        &self,
        host: &str,
        now: OffsetDateTime,
    ) -> Result<Arc<CertifiedKey>, LeafError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name = common_name(host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - BACKDATE;
        params.not_after = now + LEAF_VALIDITY;
        let cert = params.signed_by(&key, &self.issuer)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = self.provider.key_provider.load_private_key(key_der)?;
        Ok(Arc::new(CertifiedKey::new(
            vec![cert.der().clone()],
            signing_key,
        )))
    }
}

fn fingerprint(algorithm: &'static aws_lc_rs::digest::Algorithm, der: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(algorithm, der);
    let mut out = String::with_capacity(digest.as_ref().len() * 3);
    for (i, b) in digest.as_ref().iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// Per-host leaves, memory only.
pub struct LeafCache {
    entries: HashMap<String, (Instant, Arc<CertifiedKey>)>,
    capacity: usize,
    refresh: Duration,
}

impl LeafCache {
    pub fn new(capacity: usize, refresh: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            refresh,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The cached leaf for `host` if younger than the refresh age, else a new
    /// one. A full cache drops its oldest host first.
    pub fn get_or_issue(
        &mut self,
        ca: &Ca,
        host: &str,
        now: Instant,
        wall: OffsetDateTime,
    ) -> Result<Arc<CertifiedKey>, LeafError> {
        if let Some((made, leaf)) = self.entries.get(host) {
            if now.saturating_duration_since(*made) < self.refresh {
                return Ok(Arc::clone(leaf));
            }
        }
        let leaf = ca.issue_leaf(host, wall)?;
        if !self.entries.contains_key(host) && self.entries.len() >= self.capacity {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, (made, _))| *made)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries
            .insert(host.to_owned(), (now, Arc::clone(&leaf)));
        Ok(leaf)
    }
}

// ------------------------------------------------------------------
// A minimal DER walk to the certificate's validity. rcgen does not expose a
// parsed validity and no X.509 crate is a direct dependency (the design
// allows four), so the two times are read here.
// ------------------------------------------------------------------

/// One TLV: tag, contents, and what follows it.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, &rest[count..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

fn digits(text: &[u8]) -> Option<u32> {
    text.iter().try_fold(0u32, |acc, &b| {
        b.is_ascii_digit().then(|| acc * 10 + u32::from(b - b'0'))
    })
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`).
fn parse_time(tag: u8, text: &[u8]) -> Option<OffsetDateTime> {
    let (year, rest) = match tag {
        0x17 if text.len() == 13 => {
            let yy = i32::try_from(digits(&text[..2])?).ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        0x18 if text.len() == 15 => (i32::try_from(digits(&text[..4])?).ok()?, &text[4..]),
        _ => return None,
    };
    if rest.last() != Some(&b'Z') {
        return None;
    }
    let field = |i: usize| digits(&rest[i..i + 2]).and_then(|v| u8::try_from(v).ok());
    let month = Month::try_from(field(0)?).ok()?;
    let date = Date::from_calendar_date(year, month, field(2)?).ok()?;
    let time = Time::from_hms(field(4)?, field(6)?, field(8)?).ok()?;
    Some(PrimitiveDateTime::new(date, time).assume_utc())
}

/// `(notBefore, notAfter)` of a DER certificate.
pub fn validity(der: &[u8]) -> Option<(OffsetDateTime, OffsetDateTime)> {
    let (0x30, certificate, _) = tlv(der)? else {
        return None;
    };
    let (0x30, tbs, _) = tlv(certificate)? else {
        return None;
    };
    let (tag, _, mut rest) = tlv(tbs)?;
    if tag == 0xa0 {
        // [0] version; the serial number follows.
        (_, _, rest) = tlv(rest)?;
    }
    let (_, _, rest) = tlv(rest)?; // signature algorithm
    let (_, _, rest) = tlv(rest)?; // issuer
    let (0x30, times, _) = tlv(rest)? else {
        return None;
    };
    let (before_tag, before, rest) = tlv(times)?;
    let (after_tag, after, _) = tlv(rest)?;
    Some((
        parse_time(before_tag, before)?,
        parse_time(after_tag, after)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::RootCertStore;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    /// A fresh directory in a per-process directory inside the repository, so
    /// two test processes never share a path. Stale directories of dead
    /// processes are swept first.
    fn fresh_dir(name: &str) -> Result<PathBuf, io::Error> {
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let own = std::process::id();
        for entry in std::fs::read_dir(&tests)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(pid) = file_name
                .to_str()
                .and_then(|n| n.strip_prefix("tmp-unit-"))
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if pid != own && !Path::new(&format!("/proc/{pid}")).exists() {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        let dir = tests.join(format!("tmp-unit-{own}")).join(name);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(dir)
    }

    fn mode_of(path: &Path) -> Result<u32, io::Error> {
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn generated_ca_has_the_designed_shape() -> TestResult {
        let dir = fresh_dir("ca-generate")?.join("nested");
        let now = OffsetDateTime::now_utc();
        let (ca, origin) = Ca::load_or_create(&dir, provider(), now)?;
        assert_eq!(origin, CaOrigin::Generated);
        assert_eq!(mode_of(&dir.join(CA_KEY_FILE))?, 0o600);
        assert_eq!(mode_of(&dir)?, 0o700);
        assert!(contains(ca.der(), ca_common_name(now).as_bytes()));
        assert!(ca_common_name(now).starts_with("packetdeath CA 20"));
        // basicConstraints: cA TRUE, pathLenConstraint 0.
        assert!(contains(
            ca.der(),
            &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00]
        ));
        let (not_before, not_after) = validity(ca.der()).ok_or("no validity")?;
        let whole = |d: time::Duration| d.whole_seconds();
        assert!((whole(not_after - now) - whole(CA_VALIDITY)).abs() <= 2);
        assert!((whole(now - not_before) - whole(BACKDATE)).abs() <= 2);
        assert_eq!(ca.days_left(now), 730);
        Ok(())
    }

    #[test]
    fn the_pem_is_the_file_and_the_certificate_whether_made_or_loaded() -> TestResult {
        let dir = fresh_dir("ca-pem")?;
        let now = OffsetDateTime::now_utc();
        let (made, _) = Ca::load_or_create(&dir, provider(), now)?;
        let (loaded, origin) = Ca::load_or_create(&dir, provider(), now)?;
        assert_eq!(origin, CaOrigin::Loaded);
        let on_disk = std::fs::read(dir.join(CA_CERT_FILE))?;
        assert!(made.pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert_eq!(made.pem(), on_disk);
        assert_eq!(loaded.pem(), on_disk);
        assert_eq!(&CertificateDer::from_pem_slice(made.pem())?, made.der());
        Ok(())
    }

    #[test]
    fn a_second_start_loads_the_same_ca() -> TestResult {
        let dir = fresh_dir("ca-reload")?;
        let now = OffsetDateTime::now_utc();
        let (first, _) = Ca::load_or_create(&dir, provider(), now)?;
        let key_before = std::fs::read(dir.join(CA_KEY_FILE))?;
        let (second, origin) = Ca::load_or_create(&dir, provider(), now)?;
        assert_eq!(origin, CaOrigin::Loaded);
        assert_eq!(first.der(), second.der());
        assert_eq!(std::fs::read(dir.join(CA_KEY_FILE))?, key_before);
        Ok(())
    }

    #[test]
    fn a_half_pair_is_refused_and_left_alone() -> TestResult {
        let dir = fresh_dir("ca-half")?;
        let now = OffsetDateTime::now_utc();
        Ca::load_or_create(&dir, provider(), now)?;
        std::fs::remove_file(dir.join(CA_CERT_FILE))?;
        let key_before = std::fs::read(dir.join(CA_KEY_FILE))?;
        let result = Ca::load_or_create(&dir, provider(), now);
        assert!(matches!(result, Err(CaError::OneFileMissing(_))));
        assert!(!dir.join(CA_CERT_FILE).exists());
        assert_eq!(std::fs::read(dir.join(CA_KEY_FILE))?, key_before);
        Ok(())
    }

    #[test]
    fn a_readable_key_is_refused_and_left_alone() -> TestResult {
        let dir = fresh_dir("ca-0644")?;
        let now = OffsetDateTime::now_utc();
        Ca::load_or_create(&dir, provider(), now)?;
        let key_path = dir.join(CA_KEY_FILE);
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))?;
        let cert_before = std::fs::read(dir.join(CA_CERT_FILE))?;
        let result = Ca::load_or_create(&dir, provider(), now);
        assert!(matches!(result, Err(CaError::KeyTooOpen(_, 0o644))));
        assert_eq!(mode_of(&key_path)?, 0o644);
        assert_eq!(std::fs::read(dir.join(CA_CERT_FILE))?, cert_before);
        Ok(())
    }

    #[test]
    fn an_expired_ca_is_refused_and_left_alone() -> TestResult {
        let dir = fresh_dir("ca-expired")?;
        let three_years_ago = OffsetDateTime::now_utc() - time::Duration::days(3 * 365);
        Ca::load_or_create(&dir, provider(), three_years_ago)?;
        let cert_before = std::fs::read(dir.join(CA_CERT_FILE))?;
        let result = Ca::load_or_create(&dir, provider(), OffsetDateTime::now_utc());
        assert!(matches!(result, Err(CaError::Expired(_))));
        assert_eq!(std::fs::read(dir.join(CA_CERT_FILE))?, cert_before);
        Ok(())
    }

    #[test]
    fn garbage_files_are_refused() -> TestResult {
        let dir = fresh_dir("ca-garbage")?;
        std::fs::create_dir_all(&dir)?;
        write_new(&dir.join(CA_KEY_FILE), b"not a key", 0o600)?;
        write_new(&dir.join(CA_CERT_FILE), b"not a cert", 0o644)?;
        let result = Ca::load_or_create(&dir, provider(), OffsetDateTime::now_utc());
        assert!(matches!(result, Err(CaError::Parse(_, _))));
        assert_eq!(std::fs::read(dir.join(CA_KEY_FILE))?, b"not a key");
        Ok(())
    }

    #[test]
    fn write_new_never_replaces_a_file() -> TestResult {
        let dir = fresh_dir("ca-write-new")?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("x");
        write_new(&path, b"first", 0o600)?;
        assert!(write_new(&path, b"second", 0o600).is_err());
        assert_eq!(std::fs::read(&path)?, b"first");
        Ok(())
    }

    fn verifier(ca: &Ca) -> Result<Arc<WebPkiServerVerifier>, Box<dyn std::error::Error>> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone())?;
        Ok(WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider()).build()?)
    }

    fn at(moment: OffsetDateTime) -> Result<UnixTime, Box<dyn std::error::Error>> {
        let secs = u64::try_from(moment.unix_timestamp())?;
        Ok(UnixTime::since_unix_epoch(Duration::from_secs(secs)))
    }

    #[test]
    fn a_leaf_is_valid_for_its_host_for_seven_days() -> TestResult {
        let dir = fresh_dir("ca-leaf")?;
        let now = OffsetDateTime::now_utc();
        let (ca, _) = Ca::load_or_create(&dir, provider(), now)?;
        let leaf = ca.issue_leaf("download.example", now)?;
        let end_entity = leaf.end_entity_cert()?;
        let verifier = verifier(&ca)?;
        let name = ServerName::try_from("download.example")?;
        verifier.verify_server_cert(end_entity, &[], &name, &[], at(now)?)?;
        let six_days = now + time::Duration::days(6);
        verifier.verify_server_cert(end_entity, &[], &name, &[], at(six_days)?)?;
        let eight_days = now + time::Duration::days(8);
        assert!(verifier
            .verify_server_cert(end_entity, &[], &name, &[], at(eight_days)?)
            .is_err());
        let other = ServerName::try_from("other.example")?;
        assert!(verifier
            .verify_server_cert(end_entity, &[], &other, &[], at(now)?)
            .is_err());
        // id-kp-serverAuth (1.3.6.1.5.5.7.3.1).
        let server_auth = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        assert!(contains(end_entity, &server_auth));
        Ok(())
    }

    #[test]
    fn the_cache_reuses_a_leaf_for_a_day_then_reissues() -> TestResult {
        let dir = fresh_dir("ca-cache")?;
        let wall = OffsetDateTime::now_utc();
        let (ca, _) = Ca::load_or_create(&dir, provider(), wall)?;
        let mut cache = LeafCache::new(LEAF_CACHE_CAPACITY, LEAF_REFRESH);
        let t0 = Instant::now();
        let first = cache.get_or_issue(&ca, "a.example", t0, wall)?;
        let again = cache.get_or_issue(&ca, "a.example", t0 + Duration::from_secs(3600), wall)?;
        assert!(Arc::ptr_eq(&first, &again));
        let later = t0 + LEAF_REFRESH + Duration::from_secs(1);
        let renewed = cache.get_or_issue(&ca, "a.example", later, wall)?;
        assert!(!Arc::ptr_eq(&first, &renewed));
        assert_eq!(cache.len(), 1);
        Ok(())
    }

    #[test]
    fn a_full_cache_drops_its_oldest_host() -> TestResult {
        let dir = fresh_dir("ca-cache-cap")?;
        let wall = OffsetDateTime::now_utc();
        let (ca, _) = Ca::load_or_create(&dir, provider(), wall)?;
        let mut cache = LeafCache::new(2, LEAF_REFRESH);
        let t0 = Instant::now();
        let a = cache.get_or_issue(&ca, "a.example", t0, wall)?;
        cache.get_or_issue(&ca, "b.example", t0 + Duration::from_secs(1), wall)?;
        cache.get_or_issue(&ca, "c.example", t0 + Duration::from_secs(2), wall)?;
        assert_eq!(cache.len(), 2);
        let a_again = cache.get_or_issue(&ca, "a.example", t0 + Duration::from_secs(3), wall)?;
        assert!(
            !Arc::ptr_eq(&a, &a_again),
            "the oldest host was not dropped"
        );
        Ok(())
    }

    #[test]
    fn fingerprints_are_colon_separated_hex() -> TestResult {
        let dir = fresh_dir("ca-fingerprint")?;
        let (ca, _) = Ca::load_or_create(&dir, provider(), OffsetDateTime::now_utc())?;
        let sha256 = ca.sha256_fingerprint();
        assert_eq!(sha256.len(), 32 * 3 - 1);
        assert_eq!(sha256.matches(':').count(), 31);
        assert_eq!(ca.sha1_fingerprint().len(), 20 * 3 - 1);
        assert!(sha256.chars().all(|c| c == ':' || c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn both_time_forms_are_read() -> TestResult {
        let utc = parse_time(0x17, b"491231235959Z").ok_or("utc 2049")?;
        assert_eq!(utc.year(), 2049);
        let old = parse_time(0x17, b"500101000000Z").ok_or("utc 1950")?;
        assert_eq!(old.year(), 1950);
        let general = parse_time(0x18, b"20510102030405Z").ok_or("generalized")?;
        assert_eq!((general.year(), general.second()), (2051, 5));
        assert!(parse_time(0x17, b"491231235959").is_none());
        assert!(parse_time(0x18, b"2051010203040xZ").is_none());
        assert!(parse_time(0x04, b"491231235959Z").is_none());
        Ok(())
    }

    #[test]
    fn truncated_der_has_no_validity() {
        assert!(validity(&[]).is_none());
        assert!(validity(&[0x30, 0x82, 0xff]).is_none());
        assert!(validity(&[0x04, 0x00]).is_none());
    }
}
