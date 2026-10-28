//! RFC 6238 time-based one-time passwords: HMAC-SHA1, 6 digits, 30 second step.
//! `webapp/docs/design.ja.md` stage 14.
//!
//! A code is accepted for the step before, the current step and the step after
//! (clock drift), and never twice: the caller keeps the last step it accepted.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub const STEP_SECONDS: u64 = 30;
pub const SECRET_BYTES: usize = 20;
const DIGITS: u32 = 6;

#[derive(Debug, PartialEq, Eq)]
pub enum TotpError {
    BadSecret,
    Random(String),
}

type HmacSha1 = Hmac<Sha1>;

/// The 6-digit code of `secret` for step `counter`.
pub fn code_at(secret: &[u8], counter: u64) -> Result<u32, TotpError> {
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| TotpError::BadSecret)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let Some(last) = digest.last() else {
        return Err(TotpError::BadSecret);
    };
    let offset = usize::from(last & 0x0f);
    let Some(window) = digest.get(offset..offset + 4) else {
        return Err(TotpError::BadSecret);
    };
    let mut word = [0_u8; 4];
    word.copy_from_slice(window);
    Ok((u32::from_be_bytes(word) & 0x7fff_ffff) % 10_u32.pow(DIGITS))
}

/// A new random secret.
pub fn new_secret() -> Result<Vec<u8>, TotpError> {
    let mut bytes = vec![0_u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| TotpError::Random(e.to_string()))?;
    Ok(bytes)
}

/// The secret as the base32 text an authenticator app reads.
pub fn secret_text(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

/// The secret back from its base32 text.
pub fn secret_from_text(text: &str) -> Result<Vec<u8>, TotpError> {
    BASE32_NOPAD.decode(text.as_bytes()).map_err(|_| TotpError::BadSecret)
}

/// The `otpauth://` address a QR code or an app carries.
pub fn uri(account: &str, issuer: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}",
        secret_text(secret)
    )
}

fn same_digits(left: u32, typed: &str) -> bool {
    let want = format!("{left:0width$}", width = DIGITS as usize);
    want.as_bytes().ct_eq(typed.as_bytes()).into()
}

/// The step `typed` is a valid code for, when it is later than `last_step`.
pub fn verify(secret: &[u8], typed: &str, now: u64, last_step: Option<u64>) -> Result<Option<u64>, TotpError> {
    if typed.len() != DIGITS as usize || !typed.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let here = now / STEP_SECONDS;
    let mut found = None;
    for step in here.saturating_sub(1)..=here + 1 {
        if same_digits(code_at(secret, step)?, typed) && last_step.is_none_or(|last| step > last) {
            found = Some(step);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1, secret "12345678901234567890", last 6 of the 8-digit values.
    const KEY: &[u8] = b"12345678901234567890";

    #[test]
    fn the_rfc_6238_vectors_match() -> Result<(), TotpError> {
        for (time, want) in [(59_u64, 287_082_u32), (1_111_111_109, 81_804), (1_111_111_111, 50_471), (1_234_567_890, 5_924), (2_000_000_000, 279_037)] {
            assert_eq!(code_at(KEY, time / STEP_SECONDS)?, want, "time {time}");
        }
        Ok(())
    }

    #[test]
    fn a_code_is_taken_once_and_only_near_its_step() -> Result<(), TotpError> {
        let now = 1_111_111_109_u64;
        let typed = "081804";
        let step = verify(KEY, typed, now, None)?;
        assert_eq!(step, Some(now / STEP_SECONDS));
        assert_eq!(verify(KEY, typed, now, step)?, None, "the same code twice");
        assert_eq!(verify(KEY, typed, now + STEP_SECONDS, None)?, step, "one step late");
        assert_eq!(verify(KEY, typed, now + 3 * STEP_SECONDS, None)?, None, "three steps late");
        Ok(())
    }

    #[test]
    fn a_malformed_code_is_refused_without_error() -> Result<(), TotpError> {
        for typed in ["", "12345", "1234567", "12345a", "０８１８０４", " 81804"] {
            assert_eq!(verify(KEY, typed, 1_111_111_109, None)?, None, "{typed:?}");
        }
        Ok(())
    }

    #[test]
    fn a_secret_survives_its_text() -> Result<(), TotpError> {
        let secret = new_secret()?;
        assert_eq!(secret.len(), SECRET_BYTES);
        assert_eq!(secret_from_text(&secret_text(&secret))?, secret);
        assert_eq!(secret_from_text("not base32 !"), Err(TotpError::BadSecret));
        Ok(())
    }
}
