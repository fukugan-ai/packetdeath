//! A random password of the minimum length, drawn in the browser. `webapp/docs/design.ja.md`, the sign-in screen.
//!
//! The browser's own suggestion is about 15 characters, below the console's minimum, so
//! the screen draws one itself from `crypto.getRandomValues`. Bytes at or above the
//! largest multiple of the alphabet are thrown away so every character is equally likely.

use js_sys::{Function, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};

/// Letters, digits and symbols that every keyboard layout and password field accepts.
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&*+-=?@^_";

/// The length drawn: the console's minimum (`webapp/src/users.rs` `PASSWORD_MIN`).
pub const LENGTH: usize = 128;

/// Bytes below this map evenly onto the alphabet.
const FAIR_BELOW: u8 = 225;

fn random_bytes() -> Result<Vec<u8>, String> {
    let global = js_sys::global();
    let crypto = Reflect::get(&global, &JsValue::from_str("crypto")).map_err(|e| format!("{e:?}"))?;
    if crypto.is_undefined() || crypto.is_null() {
        return Err(String::from("crypto is not available in this browser"));
    }
    let fill: Function = Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .map_err(|e| format!("{e:?}"))?
        .dyn_into()
        .map_err(|_| String::from("crypto.getRandomValues is missing"))?;
    let buffer = Uint8Array::new_with_length(256);
    fill.call1(&crypto, &buffer).map_err(|e| format!("{e:?}"))?;
    Ok(buffer.to_vec())
}

/// Keep the bytes that map evenly and turn them into alphabet characters.
fn letters(bytes: &[u8]) -> Vec<char> {
    let mut kept = Vec::new();
    for byte in bytes {
        if *byte < FAIR_BELOW {
            kept.push(char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]));
        }
    }
    kept
}

/// A random password of [`LENGTH`] characters.
pub fn password() -> Result<String, String> {
    let mut out: Vec<char> = Vec::with_capacity(LENGTH);
    while out.len() < LENGTH {
        out.extend(letters(&random_bytes()?));
    }
    out.truncate(LENGTH);
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_at_the_limit_is_thrown_away() {
        assert!(letters(&[FAIR_BELOW]).is_empty());
        assert_eq!(letters(&[FAIR_BELOW - 1]).len(), 1);
    }

    #[test]
    fn the_alphabet_divides_the_fair_range_evenly() {
        assert_eq!(usize::from(FAIR_BELOW) % ALPHABET.len(), 0);
    }

    #[test]
    fn the_first_and_last_fair_bytes_are_inside_the_alphabet() {
        assert_eq!(letters(&[0]), vec!['A']);
        assert_eq!(letters(&[FAIR_BELOW - 1]), vec!['_']);
    }
}
